"""Athena Phase 2.3 — the human-reviewed remediation workflow.

Proves the workflow layer does what it claims and, just as importantly, what it
must *not* do:

- assignment records who does the remediation work (distinct from ``owner``);
- a legal transition succeeds and writes an attributed ``RemediationEvent``;
- an illegal jump is rejected with a clean 400, not silently coerced;
- a workflow move never changes the security ``status`` or the deployment
  decision — the two axes stay orthogonal;
- every mutating action is admin-only (a non-admin gets 403).

The migration applying is implicit: the test database is built from it.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.decision import recompute_decision
from assurance.models import Deployment, Finding, RemediationEvent
from assurance.remediation import (
    IllegalTransition,
    apply_transition,
    assign,
    can_transition,
)
from assurance.views import FindingViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()

State = Finding.RemediationState


def _user(name, role=User.Roles.ANALYST):
    return User.objects.create_user(username=name, password="x", role=role)


def _finding(dep, *, fingerprint="fp", **kwargs):
    defaults = dict(
        deployment=dep,
        fingerprint=fingerprint,
        finding_type="t",
        title="T",
        severity="high",
        status=Finding.Status.OPEN,
    )
    defaults.update(kwargs)
    return Finding.objects.create(**defaults)


def _transition_view():
    return FindingViewSet.as_view({"post": "remediation_transition"})


def _assign_view():
    return FindingViewSet.as_view({"post": "remediation_assign"})


def _assignable_view():
    return FindingViewSet.as_view({"get": "assignable"})


# ---------------------------------------------------------------------------
# The state machine, in isolation
# ---------------------------------------------------------------------------


def test_legal_transition_moves_state_and_writes_attributed_event():
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep, fingerprint="a")
    assert f.remediation_state == State.NEW

    event = apply_transition(f, State.TRIAGED, actor=admin, note="looks real")

    f.refresh_from_db()
    assert f.remediation_state == State.TRIAGED
    assert event.from_state == State.NEW
    assert event.to_state == State.TRIAGED
    assert event.actor == admin  # attributed
    assert event.note == "looks real"
    assert list(f.remediation_events.all()) == [event]


def test_illegal_transition_is_rejected_not_coerced():
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep, fingerprint="b")

    # NEW cannot jump straight to RESOLVED (must go through the workflow).
    with pytest.raises(IllegalTransition):
        apply_transition(f, State.RESOLVED, actor=admin)

    f.refresh_from_db()
    assert f.remediation_state == State.NEW  # unchanged
    assert f.remediation_events.count() == 0  # nothing recorded


def test_self_transition_is_illegal():
    assert not can_transition(State.NEW, State.NEW)


def test_full_forward_path_is_legal():
    assert can_transition(State.NEW, State.TRIAGED)
    assert can_transition(State.TRIAGED, State.IN_PROGRESS)
    assert can_transition(State.IN_PROGRESS, State.IN_REVIEW)
    assert can_transition(State.IN_REVIEW, State.RESOLVED)
    # review can bounce back; a resolved finding can reopen on regression
    assert can_transition(State.IN_REVIEW, State.IN_PROGRESS)
    assert can_transition(State.RESOLVED, State.IN_PROGRESS)


# ---------------------------------------------------------------------------
# Orthogonality: the workflow never moves the security disposition or decision
# ---------------------------------------------------------------------------


def test_workflow_transition_does_not_change_status_or_decision():
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep, fingerprint="c", severity="critical")

    # Establish the baseline decision from the live (OPEN, critical) finding.
    before = recompute_decision(dep)
    assert before == Deployment.Decision.NOT_RECOMMENDED
    assert f.status == Finding.Status.OPEN

    # Walk the workflow all the way to RESOLVED.
    apply_transition(f, State.TRIAGED, actor=admin)
    apply_transition(f, State.IN_PROGRESS, actor=admin)
    apply_transition(f, State.IN_REVIEW, actor=admin)
    apply_transition(f, State.RESOLVED, actor=admin)

    f.refresh_from_db()
    dep.refresh_from_db()
    # remediation_state=RESOLVED is a process claim only.
    assert f.remediation_state == State.RESOLVED
    # The security disposition is untouched...
    assert f.status == Finding.Status.OPEN
    # ...and so is the standing decision (still a live critical finding).
    assert dep.decision == Deployment.Decision.NOT_RECOMMENDED
    assert recompute_decision(dep) == Deployment.Decision.NOT_RECOMMENDED


# ---------------------------------------------------------------------------
# The API: admin-gated transitions and assignment
# ---------------------------------------------------------------------------


def test_transition_api_admin_only():
    admin = _user("boss", role=User.Roles.ADMIN)
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep, fingerprint="d")
    factory = APIRequestFactory()
    view = _transition_view()

    # Non-admin is refused (403), nothing recorded.
    denied = factory.post(
        f"/api/assurance/findings/{f.uuid}/remediation/transition/",
        {"to_state": "triaged"}, format="json",
    )
    force_authenticate(denied, user=analyst)
    assert view(denied, uuid=str(f.uuid)).status_code == 403
    f.refresh_from_db()
    assert f.remediation_state == State.NEW
    assert f.remediation_events.count() == 0

    # Admin succeeds.
    ok = factory.post(
        f"/api/assurance/findings/{f.uuid}/remediation/transition/",
        {"to_state": "triaged", "note": "confirmed"}, format="json",
    )
    force_authenticate(ok, user=admin)
    resp = view(ok, uuid=str(f.uuid))
    assert resp.status_code == 200
    assert resp.data["remediation_state"] == "triaged"
    f.refresh_from_db()
    assert f.remediation_state == State.TRIAGED
    event = f.remediation_events.get()
    assert event.actor == admin and event.note == "confirmed"


def test_transition_api_rejects_illegal_and_unknown_states():
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep, fingerprint="e")
    factory = APIRequestFactory()
    view = _transition_view()

    # Illegal jump → 400, state unchanged.
    illegal = factory.post("/x/", {"to_state": "resolved"}, format="json")
    force_authenticate(illegal, user=admin)
    resp = view(illegal, uuid=str(f.uuid))
    assert resp.status_code == 400
    f.refresh_from_db()
    assert f.remediation_state == State.NEW

    # Unknown state → 400, not a 500.
    unknown = factory.post("/x/", {"to_state": "banana"}, format="json")
    force_authenticate(unknown, user=admin)
    assert view(unknown, uuid=str(f.uuid)).status_code == 400
    assert f.remediation_events.count() == 0


def test_assign_api_sets_assignee_distinct_from_owner_and_is_attributed():
    admin = _user("boss", role=User.Roles.ADMIN)
    owner = _user("owner")
    worker = _user("worker")
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep, fingerprint="f", owner=owner)
    factory = APIRequestFactory()
    view = _assign_view()

    # Non-admin refused.
    analyst = _user("ana", role=User.Roles.ANALYST)
    denied = factory.post("/x/", {"assignee": "worker"}, format="json")
    force_authenticate(denied, user=analyst)
    assert view(denied, uuid=str(f.uuid)).status_code == 403

    # Admin assigns the remediation work to a user distinct from the owner.
    ok = factory.post("/x/", {"assignee": "worker"}, format="json")
    force_authenticate(ok, user=admin)
    resp = view(ok, uuid=str(f.uuid))
    assert resp.status_code == 200
    assert resp.data["assignee"] == "worker"

    f.refresh_from_db()
    assert f.assignee == worker
    assert f.owner == owner  # owner axis untouched
    # The assignment is attributed and recorded (from_state == to_state == NEW).
    event = f.remediation_events.get()
    assert event.actor == admin
    assert event.from_state == State.NEW and event.to_state == State.NEW


def test_assign_api_unknown_user_is_400():
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep, fingerprint="g")
    factory = APIRequestFactory()
    view = _assign_view()
    req = factory.post("/x/", {"assignee": "ghost"}, format="json")
    force_authenticate(req, user=admin)
    assert view(req, uuid=str(f.uuid)).status_code == 400
    assert RemediationEvent.objects.count() == 0


def test_remediation_read_is_open_and_returns_history():
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep, fingerprint="h")
    apply_transition(f, State.TRIAGED, actor=admin, note="triaged it")

    factory = APIRequestFactory()
    view = FindingViewSet.as_view({"get": "remediation"})
    # A privileged reader (analyst) can read the workflow without admin rights.
    analyst = _user("ana", role=User.Roles.ANALYST)
    req = factory.get(f"/api/assurance/findings/{f.uuid}/remediation/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(f.uuid))
    assert resp.status_code == 200
    assert resp.data["remediation_state"] == "triaged"
    assert len(resp.data["events"]) == 1
    assert resp.data["events"][0]["actor"] == "boss"


def test_remediation_state_is_not_writable_via_patch():
    """The workflow state moves only through the attributed transition action; a
    raw PATCH must not be able to set it (that would bypass the state machine)."""
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep, fingerprint="i")
    factory = APIRequestFactory()
    view = FindingViewSet.as_view({"patch": "partial_update"})
    req = factory.patch("/x/", {"remediation_state": "resolved"}, format="json")
    force_authenticate(req, user=admin)
    resp = view(req, uuid=str(f.uuid))
    assert resp.status_code == 200
    f.refresh_from_db()
    # PATCH silently ignores the read-only field; state stays NEW.
    assert f.remediation_state == State.NEW


# ---------------------------------------------------------------------------
# Assignee-mapping polish (Phase 2.3): active-user scoping, a uniform error that
# leaks nothing, idempotent re-assign, and the scoped assignable-users picker.
# ---------------------------------------------------------------------------

UNIFORM_ASSIGN_ERROR = "assignee is not an assignable user"


def test_assign_unknown_and_inactive_return_the_same_uniform_400():
    """An unknown username and an inactive (real but not assignable) user must
    return the SAME 400 message, so the response is not a user-enumeration
    oracle — it never reveals which usernames exist."""
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep, fingerprint="ua")
    inactive = _user("dormant")
    inactive.is_active = False
    inactive.save(update_fields=["is_active"])
    factory = APIRequestFactory()
    view = _assign_view()

    unknown = factory.post("/x/", {"assignee": "ghost"}, format="json")
    force_authenticate(unknown, user=admin)
    r_unknown = view(unknown, uuid=str(f.uuid))

    inactive_req = factory.post("/x/", {"assignee": "dormant"}, format="json")
    force_authenticate(inactive_req, user=admin)
    r_inactive = view(inactive_req, uuid=str(f.uuid))

    assert r_unknown.status_code == 400
    assert r_inactive.status_code == 400
    # Same wording either way — nothing distinguishes "no such user" from
    # "inactive", so nothing leaks.
    assert r_unknown.data["detail"] == UNIFORM_ASSIGN_ERROR
    assert r_inactive.data["detail"] == UNIFORM_ASSIGN_ERROR
    # Neither attempt assigned anyone or recorded an event.
    f.refresh_from_db()
    assert f.assignee_id is None
    assert RemediationEvent.objects.count() == 0


def test_assign_active_user_writes_exactly_one_event():
    admin = _user("boss", role=User.Roles.ADMIN)
    worker = _user("worker")
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep, fingerprint="aa")
    factory = APIRequestFactory()
    view = _assign_view()

    # Surrounding whitespace is stripped before lookup (usernames are NOT
    # lowercased — Django usernames are case-sensitive).
    req = factory.post("/x/", {"assignee": "  worker  "}, format="json")
    force_authenticate(req, user=admin)
    resp = view(req, uuid=str(f.uuid))
    assert resp.status_code == 200
    assert resp.data["assignee"] == "worker"
    f.refresh_from_db()
    assert f.assignee == worker
    assert f.remediation_events.count() == 1


def test_reassign_same_user_is_idempotent_no_duplicate_event():
    admin = _user("boss", role=User.Roles.ADMIN)
    worker = _user("worker")
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep, fingerprint="ai")
    factory = APIRequestFactory()
    view = _assign_view()

    first = factory.post("/x/", {"assignee": "worker"}, format="json")
    force_authenticate(first, user=admin)
    assert view(first, uuid=str(f.uuid)).status_code == 200
    assert f.remediation_events.count() == 1

    # Re-assigning the same user is a no-op: still 200, but NO duplicate event.
    again = factory.post("/x/", {"assignee": "worker"}, format="json")
    force_authenticate(again, user=admin)
    resp = view(again, uuid=str(f.uuid))
    assert resp.status_code == 200
    assert resp.data["assignee"] == "worker"
    assert resp.data["event"] is None  # nothing new recorded
    f.refresh_from_db()
    assert f.assignee == worker
    assert f.remediation_events.count() == 1  # unchanged


def test_unassign_null_still_clears_and_records():
    admin = _user("boss", role=User.Roles.ADMIN)
    worker = _user("worker")
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep, fingerprint="an", assignee=worker)
    factory = APIRequestFactory()
    view = _assign_view()

    req = factory.post("/x/", {"assignee": None}, format="json")
    force_authenticate(req, user=admin)
    resp = view(req, uuid=str(f.uuid))
    assert resp.status_code == 200
    assert resp.data["assignee"] is None
    f.refresh_from_db()
    assert f.assignee_id is None
    # Clearing a real assignment is a change, so it records one event...
    assert f.remediation_events.count() == 1

    # ...but clearing an already-unassigned finding is idempotent (no event).
    ev = assign(f, None, actor=admin)
    assert ev is None
    f.refresh_from_db()
    assert f.remediation_events.count() == 1


def test_assignable_endpoint_lists_active_excludes_inactive_and_is_admin_only():
    admin = _user("boss", role=User.Roles.ADMIN)
    worker = _user("worker")
    worker.first_name = "Work"
    worker.last_name = "Er"
    worker.save(update_fields=["first_name", "last_name"])
    inactive = _user("dormant")
    inactive.is_active = False
    inactive.save(update_fields=["is_active"])
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep, fingerprint="ap", assignee=worker)
    factory = APIRequestFactory()
    view = _assignable_view()

    # Admin-only: a non-admin analyst is refused (same guard as assign).
    analyst = _user("ana", role=User.Roles.ANALYST)
    denied = factory.get(f"/api/assurance/findings/{f.uuid}/assignable/")
    force_authenticate(denied, user=analyst)
    assert view(denied, uuid=str(f.uuid)).status_code == 403

    ok = factory.get(f"/api/assurance/findings/{f.uuid}/assignable/")
    force_authenticate(ok, user=admin)
    resp = view(ok, uuid=str(f.uuid))
    assert resp.status_code == 200
    usernames = [row["username"] for row in resp.data["assignable"]]
    assert "worker" in usernames and "boss" in usernames and "ana" in usernames
    assert "dormant" not in usernames  # inactive excluded
    assert usernames == sorted(usernames)  # ordered by username
    # display is the full name when set, the username otherwise.
    by_name = {row["username"]: row["display"] for row in resp.data["assignable"]}
    assert by_name["worker"] == "Work Er"
    assert by_name["boss"] == "boss"
    # The current assignee is reported.
    assert resp.data["current"] == "worker"
