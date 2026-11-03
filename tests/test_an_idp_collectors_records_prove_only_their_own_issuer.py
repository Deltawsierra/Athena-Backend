"""A customer-run identity collector's records prove only its own issuer's subjects.

Identity slice 1 of 4 (IDP design, section 8): the backend's trust model for a
collector the customer runs at its relying party, before any collector exists. On
master (ff1e8e6) the only identity signers are the Mythos-run ``mythos-*`` names, and
a key may sign a record naming any subject: the chain rule matches a hop's refs to a
record's and never compares issuers, so a key the backend trusts for its own sign-ins
could prove a sign-in at a customer's identity provider, and the other way round.

* ``customer-signin-collector`` and ``customer-grant-collector`` sign their kinds,
  customer-witnessed: a customer-signed sign-in for its bound issuer is recorded and
  proves ``authenticated_as`` end to end, labelled ``witness: customer``.
* A keyring entry binds a key to the issuers it speaks for (``"issuers"``). A bound
  key's record names ``oidc:<issuer>#<subject>`` refs of those issuers alone, and
  ``realms/a`` is never a prefix of ``realms/ab``. Checked at intake and on every
  read: withdrawing the issuer unproves what is recorded, and the stored decision
  follows.
* A customer key with no binding, or a malformed one, vouches for nothing -- and
  nothing else in the keyring is touched by it. A Mythos-run key with no binding
  reads exactly as before (#181's own file runs unchanged).
* A verifier from before this change refuses a customer record at intake and reads a
  recorded one unproven, never proven.
* No session may be claimed longer than the chain's window plus the longest token
  lifetime: a 100-year session is refused.
* The witness table, the issuer-bound signers, the subject scheme and the token
  lifetime are policy: each moves the pin.
* SAFETY RULE: no stop reaches the identity evidence module, and both intake routes
  stay classified as starting and stopping nothing.
"""

from __future__ import annotations

import base64
import inspect
import json
import logging
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from mythos_core import outcome as oc
from rest_framework.test import APIClient

from assurance.decision import current_decision, decision_support
from tests import signed_chains
from tests.test_spine_authority_chain import _base, _chain_body, _fresh, _post, _world

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()

SIGNIN = "customer-signin-collector"
GRANT = "customer-grant-collector"
#: The customer's identity provider, as its ID tokens sign it, and another one.
ISSUER = "https://kc.example.test/realms/acme"
OTHER_ISSUER = "https://kc.example.test/realms/other"
CUSTOMER_KEYS = {SIGNIN: Ed25519PrivateKey.generate(), GRANT: Ed25519PrivateKey.generate()}
TOKENS = {
    "authentication": "customer-sign-in-collector-token-for-tests-0123",  # pragma: allowlist secret
    "delegation": "customer-grant-collector-token-for-tests-0123456",  # pragma: allowlist secret
}
#: How the chain names the person and the account they signed in as: the customer's
#: identity provider's subjects.
PERSON = f"oidc:{ISSUER}#employee"
USER = f"oidc:{ISSUER}#support-user"
UNSET = object()
VECTORS = Path(__file__).resolve().parent / "vectors" / "identity-evidence-v1.json"


def _subject(name, issuer=ISSUER):
    return f"oidc:{issuer}#{name}"


def _write_keyring(path, bindings=None, *, mythos=None):
    """The test keyring: every engine key of :mod:`tests.signed_chains`, and the two
    customer keys, each bound as ``bindings`` says (default: both to :data:`ISSUER`;
    :data:`UNSET` leaves ``issuers`` out). ``mythos`` binds the Mythos-run keys too."""
    bindings = {SIGNIN: [ISSUER], GRANT: [ISSUER], **(bindings or {}), **(mythos or {})}
    entries = []
    for engine, key in {**signed_chains.ENGINE_KEYS, **CUSTOMER_KEYS}.items():
        entry = {"engine": engine, "public_key": base64.b64encode(oc.raw_public_key(key)).decode()}
        binding = bindings.get(engine, UNSET)
        if binding is not UNSET:
            entry["issuers"] = binding
        entries.append(entry)
    path.write_text(json.dumps(entries))


@pytest.fixture(autouse=True)
def bound_keyring(engine_keyring):
    _write_keyring(engine_keyring)
    return engine_keyring


@pytest.fixture
def collectors(monkeypatch):
    """Both identity services' credentials, and the account each authenticates as."""
    from assurance import identity_evidence

    clients = {}
    for kind, token in TOKENS.items():
        service = {"authentication": identity_evidence.AUTHENTICATION_SERVICE, "delegation": identity_evidence.DELEGATION_SERVICE}[kind]
        User.objects.create_user(username=f"{kind}-collector", password="x")
        monkeypatch.setenv(service.token_env, token)
        monkeypatch.setenv(service.user_env, f"{kind}-collector")
        client = APIClient()
        client.credentials(**{service.meta: token})
        clients[kind] = client
    return clients


def _stamp(instant):
    return instant.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _now(minutes=0):
    return datetime.now(dt_timezone.utc) - timedelta(minutes=minutes)


def _sign_in(dep, effect_at, *, person=PERSON, principal=USER, issuer=ISSUER, protocol="oidc", engine=SIGNIN,
             witness="customer", key=None, authenticated_at=None, expires_at=None):
    """``(envelope, evidence)``: what the customer's sign-in collector posts for a
    verified ID token -- a ``mythos.authentication/v1`` document, signed."""
    import uuid

    signed_in = authenticated_at or effect_at - timedelta(minutes=30)
    evidence = {
        "schema": "mythos.authentication/v1",
        "deployment": str(dep.uuid),
        "person": person,
        "principal": principal,
        "identity_provider": {"issuer": issuer, "protocol": protocol},
        "assertion_digest": "sha256:" + uuid.uuid4().hex * 2,
        "authenticated_at": _stamp(signed_in),
        "expires_at": _stamp(expires_at or signed_in + timedelta(hours=1)),
        "witness": witness,
        "observed_at": _stamp(signed_in),
    }
    keys = {**signed_chains.ENGINE_KEYS, **CUSTOMER_KEYS}
    envelope = signed_chains._sign_record(dep, "authentication", evidence, signed_in, engine=engine, key=key or keys[engine])
    return envelope, evidence


def _grant(dep, effect_at, *, principal=("user", USER), agent=None, engine=GRANT, witness="customer"):
    keys = {**signed_chains.ENGINE_KEYS, **CUSTOMER_KEYS}
    return signed_chains.delegation(
        dep, effect_at - timedelta(hours=1), effect_at + timedelta(days=1), principal=principal,
        agent=agent or _subject("support-bot"), engine=engine, witness=witness, key=keys[engine],
    )


def _send(client, dep, kind, envelope, evidence):
    return client.post(_base(dep) + f"{kind}s/", {"envelope": envelope, "evidence": evidence}, format="json")


def _refused(answer, says="", *, recorded=0):
    """A 400, with nothing recorded: ``recorded`` rows stand, as before the post."""
    from assurance.models import IdentityEvidence

    assert answer.status_code == 400, answer.content
    assert IdentityEvidence.objects.count() == recorded
    if says:
        body = answer.json()
        reason = body["refused"][0]["reason"] if "refused" in body else json.dumps(body)
        assert says in reason, body
    return answer


def _hops(chain):
    return {h["relation"]: h for h in chain["hops"]}


def _codes(hop):
    return [r["code"] for r in (hop["proven_by"] if hop["verdict"] == "proven" else hop["reasons"])]


def _chains(client, dep):
    return [c for c in client.get(_base(dep) + "authority-chains/").json()["chains"] if c["standing"]]


def _customer_chain(client, dep, permit, effect):
    """The roadmap's chain, started at a person the customer's identity provider names:
    ``oidc:<issuer>#employee`` signed in as ``oidc:<issuer>#support-user``, who
    delegated to the support agent."""
    body = _chain_body(client, dep, permit, person=True)
    body["hops"][0]["from"]["ref"] = PERSON
    body["hops"][0]["to"]["ref"] = USER
    body["hops"][1]["from"]["ref"] = USER
    body["effect_outcome_id"] = effect.outcome_id
    answer = _post(client, dep, body)
    assert answer.status_code == 201, answer.content
    return answer.json()["chains"][0]


def _proven_world(collectors):
    """A chain whose person hops are proven: the customer's sign-in record for its bound
    issuer, and a Mythos-run grant (unbound, as today) from that account to the agent."""
    dep, client, permit, _ = _world()
    effect_at = _now(1)
    effect = signed_chains.record_observed_effect(dep, "support-update", permit.outcome_id, effect_at)
    signed_in = _send(collectors["authentication"], dep, "authentication", *_sign_in(dep, effect_at))
    assert signed_in.status_code == 201, signed_in.content
    granted = _send(
        collectors["delegation"], dep, "delegation",
        *signed_chains.delegation(dep, effect_at - timedelta(hours=1), effect_at + timedelta(days=1), principal=("user", USER)),
    )
    assert granted.status_code == 201, granted.content
    chain = _customer_chain(client, dep, permit, effect)
    return dep, client, chain, signed_in.json(), effect_at


# ------------------------------------------------- proven, customer-witnessed


def test_a_customer_witnessed_sign_in_for_its_bound_issuer_proves_the_hop_end_to_end(collectors):
    dep, client, chain, recorded, _ = _proven_world(collectors)

    assert recorded["witness"] == "customer" and recorded["kind"] == "authentication"
    assert recorded["principal"] == USER
    hops = _hops(chain)
    assert chain["verdict"] == "proven", {r: _codes(h) for r, h in hops.items() if h["verdict"] != "proven"}
    assert _codes(hops["authenticated_as"]) == ["authentication"]
    assert "witnessed by customer" in hops["authenticated_as"]["proven_by"][0]["detail"]
    assert "witnessed by mythos" in hops["delegates_to"]["proven_by"][0]["detail"]
    support = decision_support(_fresh(dep))
    assert support["claims"]["authority_chains_unproven"] == support["claims"]["authority_chains_missing"] == []
    assert support["claim_cap"] is None


def test_a_customer_grant_between_its_own_subjects_is_recorded_customer_witnessed(collectors):
    dep, _, _, _ = _world()
    answer = _send(collectors["delegation"], dep, "delegation", *_grant(dep, _now()))
    assert answer.status_code == 201, answer.content
    assert answer.json()["witness"] == "customer" and answer.json()["principal"] == USER


def test_the_customer_signers_are_their_kinds_and_customer_witnessed():
    from assurance import composition as comp
    from assurance import identity_evidence

    assert comp.signer_evidence(SIGNIN) == "authentication"
    assert comp.signer_evidence(GRANT) == "delegation"
    assert identity_evidence.SIGNER_WITNESS == {
        "mythos-signin-collector": "mythos",
        "mythos-grant-collector": "mythos",
        SIGNIN: "customer",
        GRANT: "customer",
    }
    assert identity_evidence.ISSUER_BOUND_SIGNERS == {SIGNIN, GRANT}
    for near in ("customer_signin_collector", "Customer-signin-collector", "customer-signin-collectors"):
        assert comp.signer_evidence(near) == comp.EVIDENCE_UNCLASSIFIED


@pytest.mark.parametrize("kind", ["authentication", "delegation"])
def test_a_customer_key_cannot_claim_mythos_witnessed_it(collectors, kind):
    dep, _, _, _ = _world()
    build = _sign_in if kind == "authentication" else _grant
    _refused(_send(collectors[kind], dep, kind, *build(dep, _now(), witness="mythos")), "witnessed by 'mythos'")


# ---------------------------------------------------------- refused at intake


@pytest.mark.parametrize(
    ("change", "says"),
    [
        ({"issuer": OTHER_ISSUER, "person": _subject("employee", OTHER_ISSUER), "principal": _subject("u", OTHER_ISSUER)},
         "speaks only for"),
        ({"person": "employee"}, "person 'employee' is not oidc:<issuer>#<subject>"),
        ({"principal": "support-user"}, "principal 'support-user' is not"),
        ({"principal": _subject("support-user", OTHER_ISSUER)}, "principal "),
        ({"person": f"oidc:{ISSUER}#"}, "person "),
        ({"person": f"oidc:{ISSUER}employee"}, "person "),
        ({"protocol": "saml"}, "protocol 'saml'"),
    ],
    ids=["another-issuer", "unprefixed-person", "unprefixed-principal", "principal-of-another-issuer",
         "empty-subject", "no-separator", "another-protocol"],
)
def test_a_sign_in_naming_another_issuer_or_unprefixed_refs_is_refused(collectors, change, says):
    dep, _, _, _ = _world()
    _refused(_send(collectors["authentication"], dep, "authentication", *_sign_in(dep, _now(), **change)), says)


@pytest.mark.parametrize(
    ("change", "says"),
    [
        ({"agent": "support-agent"}, "grant.agent 'support-agent' is not"),
        ({"principal": ("user", "support-user")}, "grant.principal.ref 'support-user' is not"),
        ({"principal": ("user", _subject("support-user", OTHER_ISSUER))}, "grant.principal.ref "),
        ({"agent": _subject("bot", OTHER_ISSUER)}, "grant.agent "),
    ],
    ids=["unprefixed-agent", "unprefixed-principal", "principal-of-another-issuer", "agent-of-another-issuer"],
)
def test_a_grant_naming_another_issuers_subjects_is_refused(collectors, change, says):
    dep, _, _, _ = _world()
    _refused(_send(collectors["delegation"], dep, "delegation", *_grant(dep, _now(), **change)), says)


def test_a_key_bound_to_one_realm_never_speaks_for_a_realm_its_name_begins(collectors, bound_keyring):
    """``.../realms/a`` is the start of ``.../realms/ab``: the ``#`` in the prefix is
    what keeps the second realm's subjects from reading as the first's."""
    realm_a, realm_ab = "https://kc.example.test/realms/a", "https://kc.example.test/realms/ab"
    _write_keyring(bound_keyring, {SIGNIN: [realm_a], GRANT: [realm_a]})
    dep, _, _, _ = _world()
    _refused(
        _send(collectors["authentication"], dep, "authentication",
              *_sign_in(dep, _now(), issuer=realm_a, person=_subject("alice", realm_ab), principal=_subject("alice", realm_ab))),
        "person ",
    )
    _refused(
        _send(collectors["delegation"], dep, "delegation",
              *_grant(dep, _now(), principal=("user", _subject("alice", realm_a)), agent=_subject("bot", realm_ab))),
        "grant.agent ",
    )
    # Its own realm's subjects it does speak for.
    answer = _send(collectors["authentication"], dep, "authentication",
                   *_sign_in(dep, _now(), issuer=realm_a, person=_subject("alice", realm_a), principal=_subject("alice", realm_a)))
    assert answer.status_code == 201, answer.content


def test_a_key_bound_to_two_issuers_speaks_for_each_and_a_sign_in_for_its_own(collectors, bound_keyring):
    _write_keyring(bound_keyring, {SIGNIN: [ISSUER, OTHER_ISSUER], GRANT: [ISSUER, OTHER_ISSUER]})
    dep, _, _, _ = _world()
    answer = _send(collectors["delegation"], dep, "delegation",
                   *_grant(dep, _now(), principal=("user", USER), agent=_subject("bot", OTHER_ISSUER)))
    assert answer.status_code == 201, answer.content
    # A sign-in's subjects are its own provider's, even where the key speaks for both.
    _refused(
        _send(collectors["authentication"], dep, "authentication",
              *_sign_in(dep, _now(), issuer=OTHER_ISSUER, person=_subject("employee", OTHER_ISSUER))),
        "principal ",
        recorded=1,
    )


# -------------------------------------------- read again on every read


@pytest.mark.parametrize("binding", [[OTHER_ISSUER], UNSET], ids=["bound-elsewhere", "binding-removed"])
def test_withdrawing_the_issuer_from_the_binding_unproves_the_stored_row(collectors, bound_keyring, binding):
    from assurance import identity_evidence, observed_outcomes
    from assurance.models import IdentityEvidence

    dep, client, chain, _, _ = _proven_world(collectors)
    assert chain["verdict"] == "proven"
    proven = _fresh(dep).decision
    row = IdentityEvidence.objects.get(kind="authentication")
    before = observed_outcomes.keyring_fingerprint()

    _write_keyring(bound_keyring, {SIGNIN: binding})

    assert identity_evidence.in_force(row, observed_outcomes.trusted_keyring(), str(dep.uuid)) is None
    hop = _hops(_chains(client, dep)[0])["authenticated_as"]
    assert hop["verdict"] == "unproven" and _codes(hop) == ["no_authentication_record"]
    # The binding is part of what the stored decision was computed under: withdrawn, the
    # keyring reads as rotated, and the decision is recomputed.
    assert observed_outcomes.keyring_fingerprint() != before
    support = decision_support(_fresh(dep))
    assert support["claim_cap"] == "needs_more_evidence"
    # The first publishing read after the change recomputes the stored decision.
    assert proven != "needs_more_evidence"
    assert current_decision(_fresh(dep)) == "needs_more_evidence"
    assert _fresh(dep).decision == "needs_more_evidence"


def test_a_keyring_that_binds_nothing_keeps_the_fingerprint_it_had(bound_keyring):
    import hashlib

    from assurance import observed_outcomes

    signed_chains.write_keyring(bound_keyring)
    plain = observed_outcomes._parse_keyring(bound_keyring.read_bytes())
    pairs = sorted((key_id, key.engine) for key_id, key in plain.items())
    assert observed_outcomes.keyring_fingerprint(plain) == hashlib.sha256(json.dumps(pairs).encode()).hexdigest()


# ------------------------------------------ no binding, or a malformed one


@pytest.mark.parametrize(
    "binding",
    [UNSET, [], ISSUER, [""], ["https://kc.example.test/realms/acme#x"], [ISSUER, ISSUER], [5], ["with space"], None],
    ids=["absent", "empty", "not-a-list", "empty-issuer", "fragment", "repeated", "not-text", "whitespace", "null"],
)
def test_a_customer_key_with_no_or_a_malformed_binding_vouches_for_nothing_and_touches_nothing_else(
    collectors, bound_keyring, binding, caplog
):
    from assurance import observed_outcomes

    _write_keyring(bound_keyring, {SIGNIN: binding})
    dep, _, permit, _ = _world()
    with caplog.at_level(logging.WARNING, logger="assurance.observed_outcomes"):
        keyring = observed_outcomes.load_keyring()
        trusted = observed_outcomes.trusted_keyring()

    customer_id = oc.key_id_for(oc.raw_public_key(CUSTOMER_KEYS[SIGNIN]))
    if binding is UNSET:
        assert customer_id in keyring and observed_outcomes.issuers_of(keyring, customer_id) is None
    else:
        # A malformed binding: that key alone is left out, said at ERROR.
        assert customer_id not in keyring and customer_id not in trusted
        assert any(
            r.name == "assurance.observed_outcomes" and r.levelno == logging.ERROR and SIGNIN in r.getMessage()
            for r in caplog.records
        )
    # Everything else in the same file still verifies: Achilles' gate decision, Athena,
    # the observed-effect key, the other customer key, and the Mythos-run signers.
    assert trusted is not None
    for engine in ("achilles", "athena", "achilles-effect", "mythos-signin-collector", GRANT):
        key_id = oc.key_id_for(oc.raw_public_key({**signed_chains.ENGINE_KEYS, **CUSTOMER_KEYS}[engine]))
        assert key_id in keyring and key_id in trusted, engine
    verdict = oc.verify_outcome(permit.envelope, keyring)
    assert verdict.verdict == oc.AUTHENTIC and verdict.outcome["observer"]["engine"] == "achilles"

    _refused(_send(collectors["authentication"], dep, "authentication", *_sign_in(dep, _now())))


def test_a_customer_key_recorded_under_one_binding_proves_nothing_once_it_has_none(collectors, bound_keyring):
    from assurance import identity_evidence, observed_outcomes
    from assurance.models import IdentityEvidence

    dep, _, _, _ = _world()
    assert _send(collectors["authentication"], dep, "authentication", *_sign_in(dep, _now())).status_code == 201
    row = IdentityEvidence.objects.get()
    for binding in (UNSET, "not a list", []):
        _write_keyring(bound_keyring, {SIGNIN: binding})
        assert identity_evidence.in_force(row, observed_outcomes.trusted_keyring(), str(dep.uuid)) is None, binding


def test_one_key_listed_twice_with_two_bindings_vouches_for_nothing(bound_keyring):
    from assurance import observed_outcomes

    raw = base64.b64encode(oc.raw_public_key(CUSTOMER_KEYS[SIGNIN])).decode()
    entries = json.loads(bound_keyring.read_text())
    entries.append({"engine": SIGNIN, "public_key": raw, "issuers": [OTHER_ISSUER]})
    bound_keyring.write_text(json.dumps(entries))
    keyring = observed_outcomes.load_keyring()
    assert oc.key_id_for(oc.raw_public_key(CUSTOMER_KEYS[SIGNIN])) not in keyring
    assert oc.key_id_for(oc.raw_public_key(CUSTOMER_KEYS[GRANT])) in keyring


def test_one_key_is_still_never_two_engines_whatever_its_binding(bound_keyring):
    from assurance import observed_outcomes

    raw = base64.b64encode(oc.raw_public_key(CUSTOMER_KEYS[SIGNIN])).decode()
    entries = json.loads(bound_keyring.read_text())
    entries.append({"engine": GRANT, "public_key": raw, "issuers": "malformed"})
    bound_keyring.write_text(json.dumps(entries))
    with pytest.raises(observed_outcomes.KeyringUnavailable, match="one key has one engine"):
        observed_outcomes.load_keyring()


# ------------------------------------------- the Mythos-run signers, as before


def test_a_mythos_key_without_a_binding_reads_exactly_as_before(collectors, caplog):
    """Unbound, the Mythos-run sign-in key still records any subject (#181's records
    name ``athena-backend:<username>``), and the load says so once, at WARNING."""
    from assurance import observed_outcomes

    dep, _, _, _ = _world()
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="assurance.observed_outcomes"):
        observed_outcomes.load_keyring()
    warned = [r for r in caplog.records if r.name == "assurance.observed_outcomes" and r.levelno == logging.WARNING]
    assert len(warned) == 1 and "mythos-signin-collector" in warned[0].getMessage()
    envelope, evidence = signed_chains.authentication(dep, _now(30), person="athena-backend:alice",
                                                      principal="athena-backend:alice")
    assert _send(collectors["authentication"], dep, "authentication", envelope, evidence).status_code == 201


def test_a_mythos_key_with_a_binding_is_held_to_it(collectors, bound_keyring):
    _write_keyring(bound_keyring, mythos={"mythos-signin-collector": [ISSUER]})
    dep, _, _, _ = _world()
    envelope, evidence = signed_chains.authentication(dep, _now(30), person="athena-backend:alice",
                                                      principal="athena-backend:alice")
    _refused(_send(collectors["authentication"], dep, "authentication", envelope, evidence), "speaks only for")


# ---------------------------------------------------- an old verifier


def test_an_old_verifier_refuses_a_customer_record_and_reads_a_recorded_one_unproven(collectors, monkeypatch):
    """Rolled back to a release without the customer signers: their records are
    unclassified at intake (400, nothing recorded) and not in force on a read --
    unproven, never proven."""
    from assurance import composition, identity_evidence
    from assurance.models import IdentityEvidence

    dep, client, chain, _, effect_at = _proven_world(collectors)
    assert chain["verdict"] == "proven"
    for table in (composition.SIGNER_EVIDENCE, identity_evidence.SIGNER_WITNESS):
        for signer in (SIGNIN, GRANT):
            monkeypatch.delitem(table, signer)
    monkeypatch.setattr(identity_evidence, "ISSUER_BOUND_SIGNERS", frozenset())

    count = IdentityEvidence.objects.count()
    answer = _send(collectors["authentication"], dep, "authentication", *_sign_in(dep, effect_at))
    assert answer.status_code == 400, answer.content
    assert "unclassified, not authentication" in answer.json()["refused"][0]["reason"]
    assert IdentityEvidence.objects.count() == count
    hop = _hops(_chains(client, dep)[0])["authenticated_as"]
    assert hop["verdict"] == "unproven" and _codes(hop) == ["no_authentication_record"]


# ------------------------------------------------------- the session cap


def test_a_hundred_year_session_is_refused(collectors):
    from assurance import identity_evidence

    dep, _, _, _ = _world()
    at = _now(30)
    envelope, evidence = _sign_in(dep, at, authenticated_at=at, expires_at=at + timedelta(days=365 * 100))
    with pytest.raises(identity_evidence.EvidenceRefused, match="expires_at is at most 172800 s after"):
        identity_evidence.validate_authentication(evidence)
    _refused(_send(collectors["authentication"], dep, "authentication", envelope, evidence), "expires_at is at most")
    # The same from a Mythos-run signer.
    envelope, evidence = signed_chains.authentication(dep, at, expires_at=at + timedelta(days=365 * 100))
    _refused(_send(collectors["authentication"], dep, "authentication", envelope, evidence), "expires_at is at most")


def test_a_session_is_capped_at_the_window_plus_the_longest_token():
    from assurance import authority_chain as ac
    from assurance import identity_evidence

    cap = timedelta(seconds=ac.AUTHENTICATION_WINDOW_SECONDS + identity_evidence.MAX_TOKEN_LIFETIME_SECONDS)
    assert cap == timedelta(hours=48)
    opened = datetime(2026, 11, 3, 9, 0, tzinfo=dt_timezone.utc)
    document = {
        "schema": "mythos.authentication/v1", "deployment": "d", "person": "p", "principal": "p",
        "identity_provider": {"issuer": ISSUER, "protocol": "oidc"}, "assertion_digest": "sha256:" + "ab" * 32,
        "authenticated_at": _stamp(opened), "expires_at": _stamp(opened + cap), "witness": "customer",
        "observed_at": _stamp(opened),
    }
    assert identity_evidence.validate_authentication(document) is document
    with pytest.raises(identity_evidence.EvidenceRefused, match="expires_at is at most"):
        identity_evidence.validate_authentication({**document, "expires_at": _stamp(opened + cap + timedelta(microseconds=1))})


def test_no_session_this_backend_or_the_vectors_record_passes_the_cap():
    """The cap moves nothing already recorded: this backend's own sign-in session is its
    refresh token's lifetime (#181), read off a token it issues, and the conformance
    vectors' and the test helpers' sessions are 8 hours."""
    from assurance import authority_chain as ac
    from assurance import identity_evidence
    from rest_framework_simplejwt.tokens import RefreshToken

    cap = ac.AUTHENTICATION_WINDOW_SECONDS + identity_evidence.MAX_TOKEN_LIFETIME_SECONDS
    user = User.objects.create_user(username="session-probe", password="x")
    payload = RefreshToken.for_user(user).payload
    assert 0 < payload["exp"] - payload["iat"] <= cap
    vectors = json.loads(VECTORS.read_text(encoding="utf-8"))
    for case in vectors["valid"] + vectors["invalid"]:
        evidence = case.get("evidence")
        if isinstance(evidence, dict) and "expires_at" in evidence:
            span = identity_evidence.instant(evidence["expires_at"]) - identity_evidence.instant(evidence["authenticated_at"])
            assert span <= timedelta(seconds=cap), case["name"]


# ------------------------------------------------------------- the pin


def _document_keys(document, found=None):
    found = {} if found is None else found
    for key, value in document.items():
        found[key] = value
        if isinstance(value, dict):
            _document_keys(value, found)
    return found


def test_the_policy_document_names_each_identity_rule():
    from assurance import identity_evidence
    from assurance.policy import _policy_document

    found = _document_keys(_policy_document())
    assert found["identity_signer_witness"] == identity_evidence.SIGNER_WITNESS
    assert found["issuer_bound_signers"] == [GRANT, SIGNIN]
    assert found["identity_subject_scheme"] == "oidc:{issuer}#"
    assert found["identity_max_token_lifetime_seconds"] == 24 * 60 * 60
    assert found["signer_evidence"][SIGNIN] == "authentication" and found["signer_evidence"][GRANT] == "delegation"


@pytest.mark.parametrize(
    ("name", "key", "value"),
    [
        ("SIGNER_WITNESS", SIGNIN, "mythos"),
        ("SIGNER_WITNESS", GRANT, "mythos"),
        ("SIGNER_WITNESS", "mythos-signin-collector", "customer"),
        ("ISSUER_BOUND_SIGNERS", None, frozenset({SIGNIN})),
        ("SUBJECT_SCHEME", None, "oidc:{issuer}"),
        ("MAX_TOKEN_LIFETIME_SECONDS", None, 100 * 365 * 24 * 60 * 60),
    ],
)
def test_the_pin_moves_with_each_identity_rule(monkeypatch, name, key, value):
    from assurance import identity_evidence
    from assurance.policy import policy_pin

    before = policy_pin()
    if key is None:
        monkeypatch.setattr(identity_evidence, name, value)
    else:
        monkeypatch.setitem(getattr(identity_evidence, name), key, value)
    assert policy_pin() != before


# ------------------------------------------------------------ SAFETY RULE


def test_both_intake_routes_still_start_and_stop_nothing():
    from safety import stops

    assert stops.NOT_STOPS["deployment-authentications"] == {
        "POST": "the sign-in collector records a signed sign-in as evidence for an authority chain; it starts "
        "and stops nothing"
    }
    assert stops.NOT_STOPS["deployment-delegations"] == {
        "POST": "the grant collector records a signed delegation grant or revocation as evidence for an "
        "authority chain; it starts and stops nothing"
    }
    for name in ("deployment-authentications", "deployment-delegations"):
        assert name not in stops.STOP_ROUTES and name not in stops.EXEMPT_ROUTES


def test_no_stop_reaches_the_identity_evidence_module(django_capture_on_commit_callbacks, monkeypatch, settings,
                                                      bound_keyring):
    """A pause by the failsafe service token and by an operator, a demotion, a removal,
    a deactivation, the token refresh and a sign-out, with every function of
    :mod:`assurance.identity_evidence` made to fail and a keyring that holds a malformed
    binding: each is served as before, and none reaches the module."""
    from accounts import views as account_views
    from assurance import identity_evidence
    from assurance.models import Deployment
    from tests.test_the_backend_sign_in_emits_signed_identity_records import (
        SERVICE_TOKEN,
        _account,
        _admin,
        _deployment,
        _set_role,
        _sign_in as _password_sign_in,
    )

    _write_keyring(bound_keyring, {SIGNIN: "malformed", GRANT: UNSET})
    dep = _deployment()
    with django_capture_on_commit_callbacks(execute=True):
        _operator, client = _admin("operator")
        service = _account("failsafe-svc", User.Roles.ADMIN)
        demoted = _account("to-demote", User.Roles.ADMIN)
        removed = _account("to-remove", User.Roles.ANALYST)
        deactivated = _account("to-deactivate", User.Roles.ANALYST)
        _account("support-user")
    refresh = _password_sign_in("support-user").json()["refresh"]
    signed_out = _password_sign_in("support-user").json()["refresh"]
    settings.FAILSAFE_SERVICE_TOKEN = SERVICE_TOKEN
    settings.FAILSAFE_SERVICE_USER = service.username

    reached = []

    def tripwire(*args, **kwargs):
        reached.append(args)
        raise AssertionError("a stop reached assurance.identity_evidence")

    functions = [
        name for name, value in vars(identity_evidence).items()
        if inspect.isfunction(value) and value.__module__ == identity_evidence.__name__
    ]
    assert {"ingest", "examine", "in_force", "records_for", "binding_refusal", "validate_authentication"} <= set(functions)
    for name in functions:
        monkeypatch.setattr(identity_evidence, name, tripwire)
    by_token = APIClient()
    by_token.credentials(HTTP_X_FAILSAFE_SERVICE_TOKEN=SERVICE_TOKEN)
    with django_capture_on_commit_callbacks(execute=True):
        assert by_token.post(_base(dep) + "recompute/", {"paused": True}, format="json").status_code == 200
        assert client.post(_base(dep) + "recompute/", {"paused": True}, format="json").status_code == 200
        assert _set_role(client, demoted, "viewer").status_code == 200
        assert client.delete(f"/api/accounts/users/{removed.pk}/").status_code == 204
        account_views._deactivate_and_revoke(deactivated)
        assert APIClient().post("/api/token/refresh/", {"refresh": refresh}, format="json").status_code == 200
        assert APIClient().post("/api/token/revoke/", {"refresh": signed_out}, format="json").status_code in (200, 204, 205)
    assert reached == []
    assert _fresh(dep).decision == Deployment.Decision.PAUSED
