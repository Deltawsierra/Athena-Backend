"""A demoted operator's role grant stops proving (AB-GRANT-LEASE).

On master (ff1e8e6) the backend's own identity emitter (#181) signs each promotion of an
operator as a ``mythos.delegation/v1`` record whose window has no end (``not_after``
9999-12-31), and a demotion, a deactivation or a removal emits no revocation. So once
an operator's role is taken away, the record of its grant still reads ``proven`` in
the authority chain for every later effect, for ever: a false proof of authority
(IDP-DESIGN, suggestion 3).

* A withdrawal -- a demotion, a narrowing, a removal, a deactivation, the superuser
  flag taken away -- signs a revocation of the grant at the instant of the withdrawal,
  so a later effect reads ``delegation_revoked``, and an effect before it stays proven.
* Every role grant's record carries a lease of 24 h, and a periodic reconcile
  (``manage.py reconcile_role_grants``) re-asserts it only while the role is still
  held. With the reconcile not run, or failing -- no key, an unreadable key, no
  keyring, an account that cannot be read, an intake that fails -- the lease lapses
  and the hop reads ``delegation_expired``: a failure never extends a lease.
* The reconcile revokes a withdrawal nothing announced (a role changed by a path that
  sends no signal) at the instant it sees it.
* The open-ended records signed before leases were read to one lease from when they
  opened.
* Stops always go: the module that serves a demotion or a removal imports nothing of
  the identity code, no stop handler does, and a withdrawal's revocation is signed
  only after the stop is answered; with every identity entry made to fail, every stop
  is answered as before.

What this change adds is imported where it is used, so on a tree without it each test
fails on its own assertion or import rather than the file failing to collect.
"""

from __future__ import annotations

import ast
import inspect
import textwrap
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from assurance import identity_evidence, observed_outcomes
from assurance.models import Asset, IdentityEvidence
from tests import signed_chains
from tests.test_spine_authority_chain import WF, _base, _chain_body, _post, _world
from tests.test_the_backend_sign_in_emits_signed_identity_records import (  # noqa: F401 - the fixture
    GRANT_KEY_ENV,
    emitter,
)

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()

PASSWORD = "lease-test-password-0123456789"  # pragma: allowlist secret
ROOT = Path(__file__).resolve().parent.parent
#: The lease, spelled here so a tree without it still runs these tests (and fails them).
LEASE = timedelta(hours=24)
OPEN_ENDED = "9999-12-31T23:59:59.999999Z"


def _now():
    return datetime.now(dt_timezone.utc)


def _account(username, role=None, **extra):
    return User.objects.create_user(username=username, password=PASSWORD, role=role or User.Roles.VIEWER, **extra)


def _client_for(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _set_role(client, user, role):
    return client.patch(f"/api/accounts/users/{user.pk}/set_role/", {"role": role}, format="json")


def _codes(hop):
    return [r["code"] for r in (hop["proven_by"] if hop["verdict"] == "proven" else hop["reasons"])]


def _role_hop(client, dep, permit, granter, agent_username, role, effect_at):
    """The ``delegates_to`` hop of a chain in which ``granter`` delegated the operator
    account ``agent_username`` the action ``athena-backend:role:<role>``, for an effect
    observed at ``effect_at``: what a role grant's record alone can prove."""
    ref = f"athena-backend:{agent_username}"
    if not Asset.objects.filter(deployment=dep, identifier=ref).exists():
        Asset.objects.create(
            deployment=dep, kind="agent", name=ref, identifier=ref, classification=Asset.Classification.APPROVED,
            metadata={}, assessed_at=_now(),
        )
    effect = signed_chains.record_observed_effect(dep, WF, permit.outcome_id, effect_at)
    body = _chain_body(client, dep, permit, person=True)
    body["hops"][0]["to"]["ref"] = body["hops"][1]["from"]["ref"] = f"athena-backend:{granter.username}"
    for hop in body["hops"]:
        for end in ("from", "to"):
            if hop[end]["kind"] == "agent":
                hop[end]["ref"] = ref
            elif hop[end]["kind"] == "action":
                hop[end]["ref"] = f"athena-backend:role:{role}"
    body["effect_outcome_id"] = effect.outcome_id
    answer = _post(client, dep, body)
    assert answer.status_code == 201, answer.content
    return effect.outcome_id


def _hop(client, dep, effect_outcome_id):
    """The ``delegates_to`` hop of the chain citing that effect, read now (standing or
    superseded by a later chain of the same workflow: each is verified on every read)."""
    chains = client.get(_base(dep) + "authority-chains/").json()["chains"]
    (chain,) = [c for c in chains if c["effect_outcome_id"] == effect_outcome_id]
    return {h["relation"]: h for h in chain["hops"]}["delegates_to"]


def _promoted(django_capture_on_commit_callbacks, role="analyst", *, superuser=False):
    """A world, an admin who grants, and an operator account the admin promotes to
    ``role`` through the API: the grant's record emitted as it commits."""
    dep, client, permit, _ = _world()
    with django_capture_on_commit_callbacks(execute=True):
        granter = _account("granter", User.Roles.ADMIN)
        agent = _account("support-agent")
    admin = _client_for(granter)
    with django_capture_on_commit_callbacks(execute=True):
        assert _set_role(admin, agent, role).status_code == 200
        if superuser:
            from accounts.models import RoleGrant

            User.objects.filter(pk=agent.pk).update(is_superuser=True)
            RoleGrant.record(User.objects.get(pk=agent.pk), granter)
    return dep, client, permit, granter, agent, admin


def _active_role_records():
    return [
        r for r in IdentityEvidence.objects.filter(kind="delegation").order_by("id")
        if r.document["revocation"]["state"] == "active"
    ]


def _revocations():
    return [
        r for r in IdentityEvidence.objects.filter(kind="delegation").order_by("id")
        if r.document["revocation"]["state"] == "revoked"
    ]


# ------------------------------------------------------- a withdrawal revokes at once


WITHDRAWALS = ["demoted", "narrowed", "removed", "deactivated", "superuser_taken"]


def _withdraw(change, admin, agent, granter):
    from accounts import views as account_views

    if change == "demoted":
        assert _set_role(admin, agent, "viewer").status_code == 200
    elif change == "narrowed":
        assert _set_role(admin, agent, "analyst").status_code == 200
    elif change == "removed":
        assert admin.delete(f"/api/accounts/users/{agent.pk}/").status_code == 204
    elif change == "deactivated":
        account_views._deactivate_and_revoke(agent)
    else:
        from types import SimpleNamespace

        from django.contrib.admin.sites import site
        from django.test import RequestFactory

        account = User.objects.get(pk=agent.pk)
        form = SimpleNamespace(initial={"role": account.role, "is_superuser": True, "is_active": True})
        account.is_superuser = False
        request = RequestFactory().post("/admin/")
        request.user = granter
        site._registry[User].save_model(request, account, form, True)


@pytest.mark.parametrize("change", WITHDRAWALS)
def test_a_withdrawn_role_s_grant_reads_unproven_for_a_later_effect(
    emitter, django_capture_on_commit_callbacks, change  # noqa: F811
):
    """STEP 1's gap, closed: on master every case reads ``proven`` after the
    withdrawal (the record is open-ended and nothing revokes it)."""
    role = {"narrowed": "admin", "superuser_taken": "admin"}.get(change, "analyst")
    dep, client, permit, granter, agent, admin = _promoted(
        django_capture_on_commit_callbacks, role, superuser=change == "superuser_taken"
    )
    before = _role_hop(client, dep, permit, granter, agent.username, role, _now())
    assert _hop(client, dep, before)["verdict"] == "proven", _codes(_hop(client, dep, before))

    with django_capture_on_commit_callbacks(execute=True):
        _withdraw(change, admin, agent, granter)
    after = _role_hop(client, dep, permit, granter, agent.username, role, _now())

    hop = _hop(client, dep, after)
    assert hop["verdict"] == "unproven", f"the {change} operator's old grant still proves a later effect: {hop}"
    assert _codes(hop) == ["delegation_revoked"]
    # Revocation is read at the effect's instant: what was done under the grant before
    # it was withdrawn stays proven.
    assert _hop(client, dep, before)["verdict"] == "proven"
    revoked = _revocations()
    assert revoked and all(r.observer_engine == "mythos-grant-collector" for r in revoked)
    keyring = observed_outcomes.load_keyring()
    for row in revoked:
        assert identity_evidence.in_force(row, keyring, str(dep.uuid)) is not None


def test_a_promotion_s_record_carries_one_lease(emitter, django_capture_on_commit_callbacks):  # noqa: F811
    from accounts.models import RoleGrant

    _promoted(django_capture_on_commit_callbacks)
    (row,) = _active_role_records()
    grant = row.document["grant"]
    opened = identity_evidence.instant(grant["not_before"])
    assert grant["grant_id"] == f"role-grant-{RoleGrant.objects.get(role='analyst').pk}"
    assert grant["not_after"] != OPEN_ENDED
    assert identity_evidence.instant(grant["not_after"]) - opened == LEASE


# ------------------------------------------------------------- the lease, and its reconcile


def _granted_long_ago(django_capture_on_commit_callbacks, ago=timedelta(hours=30)):
    """An operator promoted ``ago`` (its RoleGrant recorded then, its record emitted
    now), and still holding the role: its first lease has run out unless re-asserted."""
    from accounts.models import RoleGrant

    dep, client, permit, _ = _world()
    with django_capture_on_commit_callbacks(execute=True):
        granter = _account("granter", User.Roles.ADMIN)
        agent = _account("support-agent")
    from assurance import identity_emitter

    User.objects.filter(pk=agent.pk).update(role="analyst")
    # Recorded then; its commit is never run here, so its record is the one emitted now.
    grant = RoleGrant.objects.create(
        account_pk=agent.pk, account_username=agent.username, role="analyst", granted_by_pk=granter.pk,
        granted_by_username=granter.username, granted_at=_now() - ago,
    )
    with django_capture_on_commit_callbacks(execute=True):
        assert identity_emitter.emit_role_grant(grant.pk) == 1
    assert len(_active_role_records()) == 1
    return dep, client, permit, granter, agent


def _fault(fault, tmp_path, monkeypatch):
    """Make the reconcile unable to run, one way (``monkeypatch``: a context of its own,
    so undoing it leaves the keyring and the keys the test runs under)."""
    from assurance import identity_emitter

    if fault == "unset":
        monkeypatch.delenv(GRANT_KEY_ENV)
    elif fault == "unreadable":
        monkeypatch.setenv(GRANT_KEY_ENV, str(tmp_path / "missing.pem"))
    elif fault == "no_keyring":
        monkeypatch.delenv(observed_outcomes.KEYRING_ENV)
    elif fault == "account_unreadable":

        def raises(*args, **kwargs):
            raise RuntimeError("the database is down")

        monkeypatch.setattr(identity_emitter, "held_grant", raises)
    elif fault == "intake_raises":

        def raises(*args, **kwargs):
            raise RuntimeError("the intake failed")

        monkeypatch.setattr(identity_evidence, "ingest", raises)


RECONCILE_FAULTS = ["not_run", "unset", "unreadable", "no_keyring", "account_unreadable", "intake_raises"]


@pytest.mark.parametrize("fault", RECONCILE_FAULTS)
def test_with_the_reconcile_disabled_a_lease_lapses_to_unproven(
    emitter, django_capture_on_commit_callbacks, tmp_path, monkeypatch, fault  # noqa: F811
):
    dep, client, permit, granter, agent = _granted_long_ago(django_capture_on_commit_callbacks)
    if fault != "not_run":
        from assurance import identity_emitter

        with pytest.MonkeyPatch.context() as broken:
            _fault(fault, tmp_path, broken)
            with django_capture_on_commit_callbacks(execute=True):
                done = identity_emitter.reconcile()
        assert done.reasserted == 0
    # Never extended on a failure: still the one record, its lease long over.
    assert len(_active_role_records()) == 1
    effect = _role_hop(client, dep, permit, granter, agent.username, "analyst", _now())
    hop = _hop(client, dep, effect)
    assert hop["verdict"] == "unproven", hop
    assert _codes(hop) == ["delegation_expired"]


def test_a_held_role_is_reasserted_and_stays_proven(emitter, django_capture_on_commit_callbacks):  # noqa: F811
    from assurance import identity_emitter

    dep, client, permit, granter, agent = _granted_long_ago(django_capture_on_commit_callbacks)
    with django_capture_on_commit_callbacks(execute=True):
        done = identity_emitter.reconcile()
    assert (done.ran, done.reasserted, done.revoked, done.unknown) == (True, 1, 0, 0)
    first, again = _active_role_records()
    assert first.document["grant"]["grant_id"] == again.document["grant"]["grant_id"]
    assert first.document["grant_digest"] != again.document["grant_digest"]
    renewed = again.document["grant"]
    assert identity_evidence.instant(renewed["not_after"]) - identity_evidence.instant(renewed["not_before"]) == LEASE
    effect = _role_hop(client, dep, permit, granter, agent.username, "analyst", _now())
    assert _hop(client, dep, effect)["verdict"] == "proven", _codes(_hop(client, dep, effect))
    # Not due again until half a lease is left: a second run signs nothing.
    with django_capture_on_commit_callbacks(execute=True):
        done = identity_emitter.reconcile()
    assert (done.reasserted, done.revoked) == (0, 0)
    assert len(_active_role_records()) == 2


def test_the_reconcile_revokes_a_withdrawal_nothing_announced(
    emitter, django_capture_on_commit_callbacks  # noqa: F811
):
    from assurance import identity_emitter

    dep, client, permit, granter, agent, _admin = _promoted(django_capture_on_commit_callbacks)
    # A role changed by a path that sends no signal (a bulk update, a shell).
    User.objects.filter(pk=agent.pk).update(role="viewer")
    with django_capture_on_commit_callbacks(execute=True):
        done = identity_emitter.reconcile()
    assert (done.reasserted, done.revoked) == (0, 1)
    effect = _role_hop(client, dep, permit, granter, agent.username, "analyst", _now())
    assert _codes(_hop(client, dep, effect)) == ["delegation_revoked"]


def test_the_reconcile_command_says_what_it_did_and_fails_loudly(
    emitter, django_capture_on_commit_callbacks, monkeypatch, tmp_path  # noqa: F811
):
    from io import StringIO

    from django.core.management import call_command
    from django.core.management.base import CommandError

    _granted_long_ago(django_capture_on_commit_callbacks)
    out = StringIO()
    with django_capture_on_commit_callbacks(execute=True):
        call_command("reconcile_role_grants", stdout=out)
    assert "re-asserted: 1" in out.getvalue() and "revoked: 0" in out.getvalue()
    monkeypatch.setenv(GRANT_KEY_ENV, str(tmp_path / "missing.pem"))
    with pytest.raises(CommandError, match="lapses at the end of its lease"):
        call_command("reconcile_role_grants", stdout=StringIO())
    monkeypatch.delenv(GRANT_KEY_ENV)
    out = StringIO()
    call_command("reconcile_role_grants", stdout=out)
    assert "is off" in out.getvalue()


# ------------------------------------------------------- the records signed before leases


def test_an_open_ended_record_signed_before_leases_proves_for_one_lease(
    emitter, django_capture_on_commit_callbacks  # noqa: F811
):
    """#181's records are append-only and say 9999-12-31: each is read to one lease
    from when it opened -- stricter than one lease from the deploy -- and the first
    reconcile re-asserts the grant if the role is still held."""
    from accounts.models import RoleGrant
    from assurance import identity_emitter

    dep, client, permit, _ = _world()
    with django_capture_on_commit_callbacks(execute=True):
        granter = _account("granter", User.Roles.ADMIN)
        agent = _account("support-agent")
    User.objects.filter(pk=agent.pk).update(role="analyst")
    opened = _now() - timedelta(days=2)
    # Recorded before leases were: its record is the open-ended one below, not one the
    # emitter signs now (its commit is never run here).
    grant = RoleGrant.objects.create(
        account_pk=agent.pk, account_username=agent.username, role="analyst", granted_by_pk=granter.pk,
        granted_by_username=granter.username, granted_at=opened,
    )
    body = {
        "grant_id": f"role-grant-{grant.pk}",
        "principal": {"kind": "user", "ref": f"athena-backend:{granter.username}"},
        "agent": f"athena-backend:{agent.username}",
        "scope": {"actions": ["athena-backend:role:analyst"]},
        "not_before": signed_chains._stamp(opened),
        "not_after": OPEN_ENDED,
    }
    document = {
        "schema": "mythos.delegation/v1",
        "deployment": str(dep.uuid),
        "grant": body,
        "grant_digest": identity_evidence.grant_digest(str(dep.uuid), body),
        "revocation": {"state": "active", "revoked_at": None},
        "witness": "mythos",
        "observed_at": signed_chains._stamp(opened),
    }
    envelope = identity_emitter.sign("delegation", document, identity_emitter.signing_key("delegation"), "legacy")
    signed_chains.record_identity(dep, "delegation", envelope, document)

    within = _role_hop(client, dep, permit, granter, agent.username, "analyst", opened + timedelta(hours=12))
    beyond = _role_hop(client, dep, permit, granter, agent.username, "analyst", _now())
    assert _hop(client, dep, within)["verdict"] == "proven", _codes(_hop(client, dep, within))
    assert _codes(_hop(client, dep, beyond)) == ["delegation_expired"]

    with django_capture_on_commit_callbacks(execute=True):
        assert identity_emitter.reconcile().reasserted == 1
    later = _role_hop(client, dep, permit, granter, agent.username, "analyst", _now())
    assert _hop(client, dep, later)["verdict"] == "proven", _codes(_hop(client, dep, later))


def test_the_lease_moves_the_policy_pin(monkeypatch):
    from assurance import role_grant_lease
    from assurance.policy import policy_pin

    before = policy_pin()
    with pytest.MonkeyPatch.context() as changed:
        changed.setattr(role_grant_lease, "ROLE_GRANT_LEASE_SECONDS", role_grant_lease.ROLE_GRANT_LEASE_SECONDS + 1)
        assert policy_pin() != before
    with pytest.MonkeyPatch.context() as changed:
        changed.setattr(role_grant_lease, "ROLE_SCOPE_PREFIX", "athena-backend:rank:")
        assert policy_pin() != before
    assert policy_pin() == before


# -------------------------------------------------------------------- stops always go


IDENTITY_MODULES = {"identity_emitter", "identity_evidence", "role_grant_lease"}


def _imported(path: Path) -> set[str]:
    """Every module name any import statement in ``path`` names, at any depth."""
    names = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            names.update(part for alias in node.names for part in alias.name.split("."))
        elif isinstance(node, ast.ImportFrom):
            names.update((node.module or "").split("."))
            names.update(alias.name for alias in node.names)
    return names


def _stop_handlers():
    """URL name -> the view callable of every stop and stop-access route."""
    from django.urls import URLPattern, URLResolver, get_resolver

    from safety.stops import STOP_ACCESS_ROUTES, STOP_ROUTES

    found = {}

    def walk(patterns, namespace=""):
        for pattern in patterns:
            if isinstance(pattern, URLResolver):
                walk(pattern.url_patterns, f"{namespace}{pattern.namespace}:" if pattern.namespace else namespace)
            elif isinstance(pattern, URLPattern) and pattern.name:
                found.setdefault(namespace + pattern.name, pattern.callback)

    walk(get_resolver().url_patterns)
    wanted = {**STOP_ROUTES, **STOP_ACCESS_ROUTES}
    assert set(wanted) <= set(found), sorted(set(wanted) - set(found))
    return {name: (found[name], methods) for name, methods in wanted.items()}


def test_no_stop_handler_imports_the_identity_code():
    """The tripwire: no module that serves a stop imports the identity emitter, the
    identity evidence or the lease -- anywhere in it, a function's own import included
    -- and the accounts app, which serves the demotion and the removal, imports none of
    them at all. ``assurance.views`` also serves the identity intake routes, so there
    each stop handler's own code is read instead: none of them names one."""
    handlers = _stop_handlers()
    modules = {callback.__module__ for callback, _methods in handlers.values()}
    assert "accounts.views" in modules and "safety.revoke" in modules
    files = {ROOT / Path(*m.split(".")).with_suffix(".py") for m in modules if m != "assurance.views"}
    files |= {p for p in (ROOT / "accounts").glob("*.py")}
    for path in sorted(files):
        assert not (_imported(path) & IDENTITY_MODULES), f"{path.relative_to(ROOT)} imports identity code"
    for name, (callback, methods) in handlers.items():
        if callback.__module__ != "assurance.views":
            continue
        cls = getattr(callback, "cls", None)
        for method in methods:
            handler = getattr(cls, callback.actions[method.lower()])
            tree = ast.parse(textwrap.dedent(inspect.getsource(handler)))
            named = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
            named |= {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
            assert not (named & IDENTITY_MODULES), f"{name} {method} names identity code"


STOPS = ["demote", "remove", "deactivate_on_remove", "token_revoke", "pause"]


def _stop(kind, admin, agent, dep, refresh):
    if kind == "demote":
        return _set_role(admin, agent, "viewer"), (200,)
    if kind in ("remove", "deactivate_on_remove"):
        return admin.delete(f"/api/accounts/users/{agent.pk}/"), (200, 204)
    if kind == "token_revoke":
        return APIClient().post("/api/token/revoke/", {"refresh": refresh}, format="json"), (200, 204, 205)
    return admin.post(_base(dep) + "recompute/", {"paused": True}, format="json"), (200,)


@pytest.mark.parametrize("kind", STOPS)
def test_every_stop_is_answered_before_any_identity_work_runs(
    emitter, django_capture_on_commit_callbacks, monkeypatch, kind  # noqa: F811
):
    """Each entry to the identity code is watched: on a stop, none of it runs until the
    stop's view has answered (the revocation runs after, once the response is closed)."""
    from accounts import views as account_views
    from assurance import identity_emitter

    dep, client, permit, granter, agent, admin = _promoted(django_capture_on_commit_callbacks)
    if kind == "deactivate_on_remove":
        from django.db.models import ProtectedError

        def protected(self, instance):
            raise ProtectedError("a decision they made", set())

        monkeypatch.setattr(account_views.UserViewSet, "perform_destroy", protected)
    refresh = None
    if kind == "token_revoke":
        refresh = APIClient().post(
            "/api/token/", {"username": agent.username, "password": PASSWORD}, format="json"
        ).json()["refresh"]

    events = []
    for cls, name in (
        (account_views.UserViewSet, "set_role"), (account_views.UserViewSet, "destroy"),
    ):
        real = getattr(cls, name)

        def answered(self, *args, _real=real, **kwargs):
            response = _real(self, *args, **kwargs)
            events.append("answered")
            return response

        monkeypatch.setattr(cls, name, answered)

    def watch(module, name):
        real = getattr(module, name)

        def watched(*args, **kwargs):
            events.append(name)
            return real(*args, **kwargs)

        monkeypatch.setattr(module, name, watched)

    for name in ("emit_revocations", "emit_role_grant", "emit_sign_in", "reconcile", "_emit_documents", "sign",
                 "signing_key", "live_leases", "held_grant"):
        watch(identity_emitter, name)
    for name in ("in_force", "ingest", "records_for"):
        watch(identity_evidence, name)

    answer, statuses = _stop(kind, client if kind == "pause" else admin, agent, dep, refresh)
    assert answer.status_code in statuses, answer.content
    if kind in ("demote", "remove", "deactivate_on_remove"):
        assert events[0] == "answered", events
        assert "emit_revocations" in events and "sign" in events, events
        assert _revocations(), "the withdrawal was answered but its revocation never signed"
    else:
        assert events == [], events


@pytest.mark.parametrize("kind", ["demote", "remove", "deactivate_on_remove"])
@pytest.mark.parametrize("entry", ["emit_revocations", "after_the_answer", "_now", "send_robust"])
def test_a_withdrawal_stands_when_every_identity_entry_fails(
    emitter, django_capture_on_commit_callbacks, monkeypatch, kind, entry  # noqa: F811
):
    from accounts import models as account_models
    from accounts import views as account_views
    from assurance import identity_emitter

    dep, client, permit, granter, agent, admin = _promoted(django_capture_on_commit_callbacks)
    if kind == "deactivate_on_remove":
        from django.db.models import ProtectedError

        def protected(self, instance):
            raise ProtectedError("a decision they made", set())

        monkeypatch.setattr(account_views.UserViewSet, "perform_destroy", protected)

    def raises(*args, **kwargs):
        raise RuntimeError(f"{entry} failed")

    if entry == "send_robust":
        monkeypatch.setattr(account_models.role_withdrawn, "send_robust", raises)
    else:
        monkeypatch.setattr(identity_emitter, entry, raises)
    with django_capture_on_commit_callbacks(execute=True):
        answer, statuses = _stop(kind, admin, agent, dep, None)
    assert answer.status_code in statuses, answer.content
    account = User.objects.filter(pk=agent.pk).first()
    if kind == "demote":
        assert account.role == "viewer"
    elif kind == "remove":
        assert account is None
    else:
        assert account.is_active is False
