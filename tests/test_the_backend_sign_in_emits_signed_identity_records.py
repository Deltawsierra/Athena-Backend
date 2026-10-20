"""This backend's own sign-in and role promotions emit the signed records #138 verifies.

Authority chain short 2 (the owner's decision 10, 20 Oct). On master (cf14de0) #138
takes in signed sign-in and delegation records and reads an authority chain's person
hops from them, but nothing in production emits one: a successful sign-in at
``/api/token/`` and a promotion leave no record, and a chain that starts at a person
whose account signed in here reads ``authenticated_as`` unproven
(``no_authentication_record``) whatever happened.

* A successful sign-in emits a signed ``mythos.authentication/v1`` record on every
  deployment, taken in through #138's own intake and in force under the keyring; a
  failed or refused one emits nothing.
* A promotion that names its granter emits a signed ``mythos.delegation/v1`` record of
  the grant; one naming nobody emits nothing, and so do a demotion, a deactivation and
  a removal.
* No password, token or key is in any record, or in what the emitter logs.
* A burst of successful sign-ins by one account -- which no attempt budget counts --
  adds one record and one decision refresh per deployment per interval, not one per
  sign-in: each refresh recomputes under the row lock a pause takes.
* A record that cannot be signed or recorded never refuses the sign-in or the
  promotion: fail-open for the act, while the hop it would prove reads unproven.
* Nothing here is reached on a stop: a pause by the failsafe service token and by an
  operator, a demotion, a deactivation, a removal and the token refresh are served
  with the emitter made to fail, and it is never called.
* A chain whose person hop is proven by an emitted record reads proven end to end; a
  dispatch that presented the emitted assertion is proven by that record alone.

What this change adds is imported where it is used, so on a tree without it each test
fails on its own assertion or import rather than the file failing to collect.
"""

from __future__ import annotations

import base64
import json
import logging
from datetime import datetime, timedelta, timezone as dt_timezone

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from assurance import identity_evidence, observed_outcomes
from assurance.decision import decision_support
from assurance.models import Deployment, IdentityEvidence, IdentityEvidenceRewriteRefused
from tests import signed_chains
from tests.test_spine_authority_chain import WF, _base, _chain_body, _fresh, _post, _world

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()

PASSWORD = "emitter-test-password-0123456789"  # pragma: allowlist secret
#: The variables and signers the emitter reads and signs as, spelled here so a tree
#: without the emitter still runs these tests (and fails them).
SIGN_IN_KEY_ENV = "ATHENA_SIGNIN_RECORD_KEY_FILE"
GRANT_KEY_ENV = "ATHENA_GRANT_RECORD_KEY_FILE"
SIGN_IN_SIGNER = "mythos-signin-collector"
GRANT_SIGNER = "mythos-grant-collector"
SERVICE_TOKEN = "svc-" + "fedcba9876543210" * 3  # pragma: allowlist secret


def _pem(key) -> bytes:
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


@pytest.fixture
def emitter(tmp_path, monkeypatch):
    """Both signing keys configured: the identity signers' keys the test keyring trusts."""
    paths = {}
    for env, signer in ((SIGN_IN_KEY_ENV, SIGN_IN_SIGNER), (GRANT_KEY_ENV, GRANT_SIGNER)):
        path = tmp_path / f"{signer}.pem"
        path.write_bytes(_pem(signed_chains.ENGINE_KEYS[signer]))
        monkeypatch.setenv(env, str(path))
        paths[env] = path
    return paths


def _deployment():
    owner = User.objects.create_user(username=f"owner{User.objects.count()}", password="x")
    return Deployment.objects.create(name=f"emitted{Deployment.objects.count()}", owner=owner)


def _account(username, role=None):
    return User.objects.create_user(username=username, password=PASSWORD, role=role or User.Roles.VIEWER)


def _admin(username="granter"):
    user = _account(username, User.Roles.ADMIN)
    client = APIClient()
    client.force_authenticate(user=user)
    return user, client


def _sign_in(username, password=PASSWORD):
    return APIClient().post("/api/token/", {"username": username, "password": password}, format="json")


def _set_role(client, user, role):
    return client.patch(f"/api/accounts/users/{user.pk}/set_role/", {"role": role}, format="json")


def _records(kind):
    return list(IdentityEvidence.objects.filter(kind=kind).order_by("deployment_id", "id"))


def _stamp(epoch_or_instant) -> str:
    instant = (
        datetime.fromtimestamp(epoch_or_instant, dt_timezone.utc)
        if isinstance(epoch_or_instant, int)
        else epoch_or_instant
    )
    return instant.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _claims(token):
    from rest_framework_simplejwt.tokens import RefreshToken

    return RefreshToken(token, verify=False).payload


def _later(monkeypatch):
    """Move the emitter's clock past the interval an account's sign-in is recorded in
    at most once, so the next sign-in is recorded."""
    from assurance import identity_emitter

    real = identity_emitter._now
    step = timedelta(seconds=identity_emitter.SIGN_IN_RECORD_INTERVAL_SECONDS + 1)
    monkeypatch.setattr(identity_emitter, "_now", lambda: real() + step)


# ------------------------------------------------------------- what is emitted


def test_a_successful_sign_in_emits_a_signed_sign_in_record_on_every_deployment(
    emitter, django_capture_on_commit_callbacks
):
    from assurance import identity_emitter

    deps = [_deployment(), _deployment()]
    _account("support-user")
    with django_capture_on_commit_callbacks(execute=True):
        answer = _sign_in("support-user")
    assert answer.status_code == 200, answer.content
    refresh = answer.json()["refresh"]
    claims = _claims(refresh)

    rows = _records("authentication")
    assert [r.deployment_id for r in rows] == [d.pk for d in deps]
    keyring = observed_outcomes.load_keyring()
    for dep, row in zip(deps, rows, strict=True):
        document = identity_evidence.in_force(row, keyring, str(dep.uuid))
        assert document is not None, "the emitted record does not verify as #138 reads it"
        assert (row.observer_engine, row.witness, row.principal) == (
            SIGN_IN_SIGNER, "mythos", "athena-backend:support-user"
        )
        assert document == {
            "schema": "mythos.authentication/v1",
            "deployment": str(dep.uuid),
            "person": "athena-backend:support-user",
            "principal": "athena-backend:support-user",
            "identity_provider": {"issuer": "athena-backend", "protocol": "password"},
            "assertion_digest": identity_emitter.assertion_digest(str(dep.uuid), refresh),
            "authenticated_at": _stamp(claims["iat"]),
            "expires_at": _stamp(claims["exp"]),
            "witness": "mythos",
            "observed_at": document["observed_at"],
        }
    # One sign-in, one record per deployment: the digest binds the deployment, so the
    # record on one is no replay of the record on the other.
    assert len({r.document["assertion_digest"] for r in rows}) == len(deps)


def test_a_failed_or_refused_sign_in_emits_nothing(emitter, django_capture_on_commit_callbacks):
    _deployment()
    _account("support-user")
    with django_capture_on_commit_callbacks(execute=True):
        assert _sign_in("support-user", "not-the-password").status_code == 401
        assert APIClient().post("/api/token/", {"username": "support-user"}, format="json").status_code == 400
        assert _sign_in("nobody-by-that-name").status_code == 401
    assert IdentityEvidence.objects.count() == 0


def test_each_sign_in_adds_records_and_none_is_ever_rewritten(
    emitter, django_capture_on_commit_callbacks, monkeypatch
):
    _deployment()
    _account("support-user")
    with django_capture_on_commit_callbacks(execute=True):
        assert _sign_in("support-user").status_code == 200
    first = _records("authentication")
    _later(monkeypatch)
    with django_capture_on_commit_callbacks(execute=True):
        assert _sign_in("support-user").status_code == 200
    rows = _records("authentication")
    assert len(rows) == 2 and rows[0].pk == first[0].pk and rows[0].document == first[0].document
    with pytest.raises(IdentityEvidenceRewriteRefused):
        rows[0].save()
    with pytest.raises(IdentityEvidenceRewriteRefused):
        rows[0].delete()


def test_a_promotion_naming_its_granter_emits_a_signed_grant_record(emitter, django_capture_on_commit_callbacks):
    from accounts.models import RoleGrant
    from assurance import identity_emitter

    deps = [_deployment(), _deployment()]
    with django_capture_on_commit_callbacks(execute=True):
        # Made an admin as it was created, by nobody: no one delegated it, no record.
        granter, client = _admin()
        target = _account("support-agent")
    assert _records("delegation") == []

    with django_capture_on_commit_callbacks(execute=True):
        assert _set_role(client, target, "analyst").status_code == 200
    grant = RoleGrant.objects.get(account_pk=target.pk)
    rows = _records("delegation")
    assert [r.deployment_id for r in rows] == [d.pk for d in deps]
    keyring = observed_outcomes.load_keyring()
    for dep, row in zip(deps, rows, strict=True):
        document = identity_evidence.in_force(row, keyring, str(dep.uuid))
        assert document is not None, "the emitted record does not verify as #138 reads it"
        assert (row.observer_engine, row.witness, row.principal) == (
            GRANT_SIGNER, "mythos", "athena-backend:granter"
        )
        body = {
            "grant_id": f"role-grant-{grant.pk}",
            "principal": {"kind": "user", "ref": "athena-backend:granter"},
            "agent": "athena-backend:support-agent",
            "scope": {"actions": ["athena-backend:role:analyst"]},
            "not_before": _stamp(grant.granted_at),
            "not_after": "9999-12-31T23:59:59.999999Z",
        }
        assert document["grant"] == body
        assert document["grant_digest"] == identity_evidence.grant_digest(str(dep.uuid), body)
        assert document["revocation"] == {"state": "active", "revoked_at": None}
    assert identity_emitter.role_scope("viewer", True) == ["athena-backend:role:superuser", "athena-backend:role:viewer"]


@pytest.mark.parametrize("change", ["demote", "deactivate", "remove", "create_unnamed"])
def test_no_revoke_and_no_unnamed_grant_emits_a_record(emitter, django_capture_on_commit_callbacks, change):
    from accounts import views as account_views

    _deployment()
    with django_capture_on_commit_callbacks(execute=True):
        _admin_user, client = _admin()
        target = _account("support-agent", User.Roles.ANALYST)
    with django_capture_on_commit_callbacks(execute=True):
        if change == "demote":
            assert _set_role(client, target, "viewer").status_code == 200
        elif change == "deactivate":
            account_views._deactivate_and_revoke(target)
        elif change == "remove":
            assert client.delete(f"/api/accounts/users/{target.pk}/").status_code == 204
        else:
            User.objects.create_superuser(username="root", password=PASSWORD, email="root@example.test")
    assert IdentityEvidence.objects.count() == 0


# --------------------------------------------------------- nothing secret leaves


def test_no_password_token_or_key_enters_a_record_or_the_log(emitter, django_capture_on_commit_callbacks, caplog):
    _deployment()
    _account("support-user")
    granter, client = _admin()
    caplog.set_level(logging.DEBUG)
    with django_capture_on_commit_callbacks(execute=True):
        answer = _sign_in("support-user")
        assert _set_role(client, User.objects.get(username="support-user"), "analyst").status_code == 200
    assert answer.status_code == 200
    tokens = answer.json()
    secrets = {"password": PASSWORD, "access": tokens["access"], "refresh": tokens["refresh"]}
    secrets["jti"] = _claims(tokens["refresh"])["jti"]
    for signer in (SIGN_IN_SIGNER, GRANT_SIGNER):
        key = signed_chains.ENGINE_KEYS[signer]
        raw = key.private_bytes(
            serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
        )
        secrets[f"{signer} pem"] = _pem(key).decode().splitlines()[1]
        secrets[f"{signer} hex"] = raw.hex()
        secrets[f"{signer} b64"] = base64.b64encode(raw).decode()
    rows = list(IdentityEvidence.objects.all())
    assert {r.kind for r in rows} == {"authentication", "delegation"}
    for row in rows:
        payload = base64.b64decode(row.envelope["payload"]).decode()
        columns = json.dumps({f.attname: str(getattr(row, f.attname)) for f in row._meta.concrete_fields})
        for blob in (json.dumps(row.document), json.dumps(row.envelope), payload, columns):
            for name, secret in secrets.items():
                assert secret not in blob, f"the {name} is in a {row.kind} record"
    logged = "\n".join(r.getMessage() for r in caplog.records)
    for name, secret in secrets.items():
        assert secret not in logged, f"the {name} is in the log"


# ------------------------------------------------ fail-open for the act, closed for proof


def _broken(fault, tmp_path, monkeypatch):
    """Make the sign-in record impossible to emit, one way."""
    path = tmp_path / "broken.pem"
    if fault == "unset":
        monkeypatch.delenv(SIGN_IN_KEY_ENV)
        monkeypatch.delenv(GRANT_KEY_ENV)
        return
    if fault == "unreadable":
        path = tmp_path / "missing.pem"
    elif fault == "not_a_key":
        # A PEM frame around "not a key": no key at all.
        path.write_bytes(b"-----BEGIN PRIVATE KEY-----\nbm90IGEga2V5\n-----END PRIVATE KEY-----\n")  # pragma: allowlist secret
    elif fault == "not_ed25519":
        path.write_bytes(_pem(ec.generate_private_key(ec.SECP256R1())))
    elif fault == "untrusted":
        path.write_bytes(_pem(Ed25519PrivateKey.generate()))
    elif fault == "no_keyring":
        monkeypatch.delenv(observed_outcomes.KEYRING_ENV)
        return
    elif fault == "intake_raises":

        def raises(*args, **kwargs):
            raise RuntimeError("the intake failed")

        monkeypatch.setattr(identity_evidence, "ingest", raises)
        return
    monkeypatch.setenv(SIGN_IN_KEY_ENV, str(path))
    monkeypatch.setenv(GRANT_KEY_ENV, str(path))


FAULTS = ["unset", "unreadable", "not_a_key", "not_ed25519", "untrusted", "no_keyring", "intake_raises"]


@pytest.mark.parametrize("fault", FAULTS)
def test_a_record_that_cannot_be_made_never_refuses_the_sign_in(
    emitter, django_capture_on_commit_callbacks, tmp_path, monkeypatch, caplog, fault
):
    from assurance import identity_emitter

    _deployment()
    _account("support-user")
    _broken(fault, tmp_path, monkeypatch)
    caplog.set_level(logging.INFO, logger=identity_emitter.__name__)
    with django_capture_on_commit_callbacks(execute=True):
        answer = _sign_in("support-user")
    assert answer.status_code == 200, answer.content
    assert set(answer.json()) == {"access", "refresh"}
    assert IdentityEvidence.objects.count() == 0
    # Said, never silent: an unset key is the emitter switched off (INFO); every
    # other fault is an ERROR naming why.
    emitted = [r for r in caplog.records if r.name == identity_emitter.__name__]
    assert emitted, "the missing record was not logged"
    expected = logging.INFO if fault == "unset" else logging.ERROR
    assert max(r.levelno for r in emitted) == expected, [(r.levelname, r.getMessage()) for r in emitted]


@pytest.mark.parametrize("fault", FAULTS)
def test_a_record_that_cannot_be_made_never_refuses_the_promotion(
    emitter, django_capture_on_commit_callbacks, tmp_path, monkeypatch, fault
):
    from accounts.models import RoleGrant

    _deployment()
    with django_capture_on_commit_callbacks(execute=True):
        _granter, client = _admin()
        target = _account("support-agent")
    _broken(fault, tmp_path, monkeypatch)
    with django_capture_on_commit_callbacks(execute=True):
        assert _set_role(client, target, "admin").status_code == 200
    assert User.objects.get(pk=target.pk).role == "admin"
    assert RoleGrant.objects.filter(account_pk=target.pk).count() == 1
    assert IdentityEvidence.objects.count() == 0


def test_an_emitter_that_raises_never_refuses_the_sign_in(emitter, django_capture_on_commit_callbacks, monkeypatch):
    """Belt and braces: even an emitter whose own guard is gone is held off the sign-in."""
    from assurance import identity_emitter

    def raises(*args, **kwargs):
        raise RuntimeError("the emitter failed")

    _deployment()
    _account("support-user")
    monkeypatch.setattr(identity_emitter, "emit_sign_in", raises)
    with django_capture_on_commit_callbacks(execute=True):
        assert _sign_in("support-user").status_code == 200
    monkeypatch.setattr(identity_emitter, "after_commit", raises)
    with django_capture_on_commit_callbacks(execute=True):
        assert _sign_in("support-user").status_code == 200
    assert IdentityEvidence.objects.count() == 0


# ------------------------------------------------------------- nothing on a stop


def test_a_burst_of_sign_ins_adds_one_record_and_one_refresh_per_deployment(
    emitter, django_capture_on_commit_callbacks, monkeypatch, caplog
):
    """A successful sign-in is counted against no attempt budget, and every record
    schedules its deployment's decision refresh -- which recomputes under the row lock
    a pause takes. So a burst of them by one account is recorded on each deployment
    once in the interval: one record and one refresh each, however long it lasts."""
    from assurance import decision, identity_emitter

    with django_capture_on_commit_callbacks(execute=True):
        deps = [_deployment(), _deployment(), _deployment()]
        _account("support-user")
    refreshed = []
    real = decision.refresh_stored_decisions

    def counted(ids):
        refreshed.extend(ids)
        return real(ids)

    monkeypatch.setattr(decision, "refresh_stored_decisions", counted)
    caplog.set_level(logging.INFO, logger=identity_emitter.__name__)
    for _ in range(12):
        with django_capture_on_commit_callbacks(execute=True):
            assert _sign_in("support-user").status_code == 200
    assert [r.deployment_id for r in _records("authentication")] == [d.pk for d in deps]
    assert sorted(refreshed) == sorted(d.pk for d in deps)
    passed_over = [r for r in caplog.records if "less than 60 s ago" in r.getMessage()]
    assert len(passed_over) == 11 * len(deps)
    # Past the interval, the account's next sign-in is recorded again.
    _later(monkeypatch)
    with django_capture_on_commit_callbacks(execute=True):
        assert _sign_in("support-user").status_code == 200
    assert len(_records("authentication")) == 2 * len(deps)


def test_no_stop_or_token_refresh_reaches_the_emitter(emitter, django_capture_on_commit_callbacks, monkeypatch, settings):
    """A pause made with the failsafe service token and by an operator, a demotion, a
    deactivation, a removal and the token refresh: each served as before with every
    entry to the emitter made to fail, and none of them reaches it."""
    from accounts import views as account_views
    from assurance import identity_emitter

    dep = _deployment()
    with django_capture_on_commit_callbacks(execute=True):
        _operator, client = _admin("operator")
        service = _account("failsafe-svc", User.Roles.ADMIN)
        demoted = _account("to-demote", User.Roles.ADMIN)
        removed = _account("to-remove", User.Roles.ANALYST)
        deactivated = _account("to-deactivate", User.Roles.ANALYST)
        _account("support-user")
    monkeypatch.delenv(SIGN_IN_KEY_ENV)
    refresh = _sign_in("support-user").json()["refresh"]
    monkeypatch.setenv(SIGN_IN_KEY_ENV, str(emitter[SIGN_IN_KEY_ENV]))
    settings.FAILSAFE_SERVICE_TOKEN = SERVICE_TOKEN
    settings.FAILSAFE_SERVICE_USER = service.username

    reached = []

    def tripwire(*args, **kwargs):
        reached.append(args)
        raise AssertionError("a stop reached the identity emitter")

    for name in ("after_commit", "emit_sign_in", "emit_role_grant", "_emit", "sign", "signing_key"):
        monkeypatch.setattr(identity_emitter, name, tripwire)
    by_token = APIClient()
    by_token.credentials(HTTP_X_FAILSAFE_SERVICE_TOKEN=SERVICE_TOKEN)
    with django_capture_on_commit_callbacks(execute=True):
        assert by_token.post(_base(dep) + "recompute/", {"paused": True}, format="json").status_code == 200
        assert client.post(_base(dep) + "recompute/", {"paused": True}, format="json").status_code == 200
        assert _set_role(client, demoted, "viewer").status_code == 200
        assert client.delete(f"/api/accounts/users/{removed.pk}/").status_code == 204
        account_views._deactivate_and_revoke(deactivated)
        assert APIClient().post("/api/token/refresh/", {"refresh": refresh}, format="json").status_code == 200
    assert reached == []
    assert _fresh(dep).decision == Deployment.Decision.PAUSED
    assert IdentityEvidence.objects.count() == 0


def test_the_emitter_signs_as_the_identity_signers_and_reads_its_keys_by_name():
    from assurance import composition, identity_emitter

    assert (identity_emitter.SIGN_IN_KEY_ENV, identity_emitter.GRANT_KEY_ENV) == (SIGN_IN_KEY_ENV, GRANT_KEY_ENV)
    assert identity_emitter.SIGNERS == {"authentication": SIGN_IN_SIGNER, "delegation": GRANT_SIGNER}
    for kind, signer in identity_emitter.SIGNERS.items():
        assert composition.signer_evidence(signer) == kind
        assert identity_evidence.SIGNER_WITNESS[signer] == "mythos"


# --------------------------------------------------- the chain, proven end to end


def _hops(chain):
    return {h["relation"]: h for h in chain["hops"]}


def _codes(hop):
    return [r["code"] for r in (hop["proven_by"] if hop["verdict"] == "proven" else hop["reasons"])]


#: How this backend's records name the support user's account (and the person, whom
#: it knows only by the account they proved they hold).
ACCOUNT = "athena-backend:support-user"


def _signed_in_world(django_capture_on_commit_callbacks, *, emit=True, monkeypatch=None):
    """#138's person-started world, with its person signing in HERE: the support user's
    account signs in at /api/token/, then the effect is dispatched and observed, and the
    grant collector records the user's delegation to the agent (a delegation record
    where one exists: this backend delegates nothing to an agent)."""
    dep, client, permit, _ = _world()
    _account("support-user")
    if not emit:
        monkeypatch.delenv(SIGN_IN_KEY_ENV)
    with django_capture_on_commit_callbacks(execute=True):
        answer = _sign_in("support-user")
    assert answer.status_code == 200, answer.content
    effect_at = datetime.now(dt_timezone.utc)
    signed_chains.record_identity(
        dep,
        "delegation",
        *signed_chains.delegation(
            dep, effect_at - timedelta(hours=1), effect_at + timedelta(days=1), principal=("user", ACCOUNT)
        ),
    )
    return dep, client, permit, effect_at, answer.json()["refresh"]


def _person_chain(client, dep, permit, effect):
    body = _chain_body(client, dep, permit, person=True)
    body["hops"][0]["from"]["ref"] = body["hops"][0]["to"]["ref"] = body["hops"][1]["from"]["ref"] = ACCOUNT
    body["effect_outcome_id"] = effect.outcome_id
    answer = _post(client, dep, body)
    assert answer.status_code == 201, answer.content
    return [c for c in client.get(_base(dep) + "authority-chains/").json()["chains"] if c["standing"]][0]


def test_an_effect_whose_person_signed_in_here_reads_proven_end_to_end(emitter, django_capture_on_commit_callbacks):
    dep, client, permit, effect_at, _refresh = _signed_in_world(django_capture_on_commit_callbacks)
    effect = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, effect_at)
    chain = _person_chain(client, dep, permit, effect)
    hops = _hops(chain)
    assert chain["verdict"] == "proven", {r: _codes(h) for r, h in hops.items() if h["verdict"] != "proven"}
    assert {r: _codes(h) for r, h in hops.items()} == {
        "authenticated_as": ["authentication"],
        "delegates_to": ["delegation"],
        "under_policy": ["approval_in_force_at_dispatch"],
        "invokes": ["contract_in_force_at_dispatch", "route_at_dispatch", "reach_in_force_at_dispatch"],
        "through_identity": ["identity_in_force_at_dispatch"],
        "performs": ["action_in_force_at_dispatch", "within_approval_at_dispatch", "gate_permit"],
        "produces": ["observed_effect"],
    }
    detail = hops["authenticated_as"]["proven_by"][0]["detail"]
    assert "athena-backend (password)" in detail and "witnessed by mythos" in detail
    support = decision_support(_fresh(dep))
    assert support["claims"]["authority_chains_unproven"] == support["claims"]["authority_chains_missing"] == []
    assert support["claim_cap"] is None


def test_without_the_emitted_record_the_person_hop_reads_unproven(
    emitter, django_capture_on_commit_callbacks, monkeypatch
):
    dep, client, permit, effect_at, _refresh = _signed_in_world(
        django_capture_on_commit_callbacks, emit=False, monkeypatch=monkeypatch
    )
    effect = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, effect_at)
    chain = _person_chain(client, dep, permit, effect)
    assert chain["verdict"] == "unproven"
    assert _codes(_hops(chain)["authenticated_as"]) == ["no_authentication_record"]
    assert _hops(chain)["delegates_to"]["verdict"] == "proven"


@pytest.mark.parametrize(
    "presented, code",
    [
        ("first", "authentication"),
        ("second", "authentication"),
        ("second_as_another_deployment_names_it", "authentication_not_dispatched"),
        ("a_session_never_issued", "authentication_not_dispatched"),
    ],
)
def test_a_dispatch_is_proven_only_by_the_sign_in_it_presented(
    emitter, django_capture_on_commit_callbacks, monkeypatch, presented, code
):
    """The gate presents the assertion of the session the dispatch was made in: only
    the record of that sign-in, on that deployment, proves the hop."""
    from assurance import identity_emitter

    dep, client, permit, _effect_at, first = _signed_in_world(django_capture_on_commit_callbacks)
    other = _deployment()
    _later(monkeypatch)
    with django_capture_on_commit_callbacks(execute=True):
        second = _sign_in("support-user").json()["refresh"]
    effect_at = datetime.now(dt_timezone.utc)
    on = identity_emitter.assertion_digest
    digest = {
        "first": on(str(dep.uuid), first),
        "second": on(str(dep.uuid), second),
        # The second sign-in's record on the other deployment: on record, but not here.
        "second_as_another_deployment_names_it": on(str(other.uuid), second),
        "a_session_never_issued": on(str(dep.uuid), first + "-never-issued"),
    }[presented]
    effect = signed_chains.record_observed_effect(
        dep, WF, permit.outcome_id, effect_at, presented=signed_chains.live_presented(dep, WF, assertion=digest)
    )
    hops = _hops(_person_chain(client, dep, permit, effect))
    assert _codes(hops["authenticated_as"]) == [code]


def test_a_role_grant_record_never_stands_in_for_an_action_grant(emitter, django_capture_on_commit_callbacks):
    """A promotion's record delegates a role of this backend's, not an action: a chain
    whose user "delegated" the agent through a promotion alone reads that hop
    unproven, out of scope -- never proven by the role."""
    dep, client, permit, _ = _world()
    with django_capture_on_commit_callbacks(execute=True):
        granter, admin_client = _admin()
        agent = _account("support-agent")
    with django_capture_on_commit_callbacks(execute=True):
        assert _set_role(admin_client, agent, "analyst").status_code == 200
    effect = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, datetime.now(dt_timezone.utc))
    body = _chain_body(client, dep, permit, person=True)
    body["hops"][0]["to"]["ref"] = body["hops"][1]["from"]["ref"] = f"athena-backend:{granter.username}"
    for hop in body["hops"]:
        for end in ("from", "to"):
            if hop[end]["kind"] == "agent":
                hop[end]["ref"] = f"athena-backend:{agent.username}"
    body["effect_outcome_id"] = effect.outcome_id
    assert _post(client, dep, body).status_code == 201
    chain = [c for c in client.get(_base(dep) + "authority-chains/").json()["chains"] if c["standing"]][0]
    delegated = _hops(chain)["delegates_to"]
    assert delegated["verdict"] != "proven"
    assert "delegation_out_of_scope" in _codes(delegated), _codes(delegated)
