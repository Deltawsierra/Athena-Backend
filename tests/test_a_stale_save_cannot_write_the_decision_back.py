"""A Deployment instance held across a refresh cannot write the decision back.

The stored decision has one writer: the refresh (`revision.accept_transition`, and
the keyring stamp `decision.recompute_decision` writes beside it). A plain
``Deployment.save()`` wrote every column from the instance, and an instance held
across a refresh holds the decision from BEFORE it. The ordinary shell sequence --
hold a READY deployment, record a critical finding (the backstop refreshes a
DIFFERENT instance: NOT_RECOMMENDED at revision N+1, transition recorded), rename
the deployment and save it -- wrote READY at revision N back over the row. The
receipt published READY over an open critical finding, and every recompute after it
computed revision N+1 again, collided with the transition already recorded there,
and failed, so nothing could repair it.

Three defences, each pinned here on its own:

- ``Deployment.save`` never writes the decision columns over a stored row, and
  refuses a save that names one;
- ``accept_transition`` takes the next revision after both the row and its
  transition log, and repairs -- loudly, once -- a row that is behind the log,
  keeping the operator's pause as the LOG records it, not as the stale row does;
- the after-commit backstop logs a refresh that fails at ERROR, naming the
  deployment, rather than letting it pass unseen.

And the one writer is held to by reading the source of every first-party package
for the writes the model cannot see.
"""

from __future__ import annotations

import ast
import io
import logging
import os
import re
import textwrap
import tokenize
from collections import Counter
from datetime import timedelta
from itertools import product
from pathlib import Path

import pytest
from django.apps import apps as django_apps
from django.apps.registry import Apps
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.db import DatabaseError, IntegrityError, connection, transaction
from django.test import RequestFactory
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from assurance import signals
from assurance.admin import DeploymentAdmin
from assurance.decision import decision_support, recompute_decision
from assurance.models import (
    DECISION_OWNED_FIELDS,
    DecisionColumnWriteRefused,
    DecisionTransition,
    Deployment,
    Finding,
)
from assurance.revision import (
    StaleDecisionRead,
    accept_transition,
    decision_in_force,
    read_decision,
)
from tests.decision_surfaces import one_decision

pytestmark = pytest.mark.django_db

User = get_user_model()
D = Deployment.Decision
_REPO = Path(__file__).resolve().parent.parent


def _owner():
    return User.objects.create_user(
        username=f"o{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )


def _scanned_ready():
    dep = Deployment.objects.create(name="d", owner=_owner())
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    dep.refresh_from_db()
    recompute_decision(dep)
    dep.refresh_from_db()
    assert dep.decision == D.READY
    return dep


def _critical(dep):
    return Finding.objects.create(
        deployment=dep, fingerprint="fp", finding_type="t", title="T", severity="critical"
    )


def _client(dep):
    client = APIClient()
    client.force_authenticate(user=dep.owner)
    client.raise_request_exception = False
    return client


def _log(dep):
    return list(
        DecisionTransition.objects.filter(deployment=dep)
        .order_by("revision")
        .values_list("revision", "from_decision", "to_decision")
    )


# ---------------------------------------------------------------------------
# The sequence that wedged a deployment
# ---------------------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_a_shell_writers_stale_full_save_leaves_the_decision_where_the_backstop_put_it(caplog):
    """Autocommit, as a shell or a management command runs: every write commits on
    its own, so the backstop refreshes as soon as the finding lands -- on an
    instance of its own, not the writer's."""
    dep = _scanned_ready()
    before = dep.decision_revision

    _critical(dep)
    assert Deployment.objects.get(pk=dep.pk).decision == D.NOT_RECOMMENDED
    assert dep.decision == D.READY, "the writer's instance really is stale"

    dep.name = "renamed"
    with caplog.at_level(logging.ERROR):
        dep.save()

    stored = Deployment.objects.get(pk=dep.pk)
    assert stored.name == "renamed", "the save still writes what the writer changed"
    assert (stored.decision, stored.decision_revision) == (D.NOT_RECOMMENDED, before + 1)
    assert _log(dep) == [
        (before, "", D.READY),
        (before + 1, D.READY, D.NOT_RECOMMENDED),
    ], "the row and its transition log agree"
    assert decision_support(stored)["decision"] == D.NOT_RECOMMENDED
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []

    client = _client(dep)
    assert one_decision(dep, client) == D.NOT_RECOMMENDED
    response = client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {}, format="json")
    assert response.status_code == 200, response.content
    assert response.json()["decision"] == D.NOT_RECOMMENDED
    assert one_decision(dep, client) == D.NOT_RECOMMENDED
    assert read_decision(dep) == {"decision": D.NOT_RECOMMENDED, "revision": before + 1}


# ---------------------------------------------------------------------------
# Deployment.save never writes the decision columns over a stored row
# ---------------------------------------------------------------------------


def _moved_under(stale):
    """Move the stored decision on ANOTHER instance, as a refresh does, and stamp a
    keyring, so all three owned columns differ from what ``stale`` holds."""
    accept_transition(Deployment.objects.get(pk=stale.pk), to_decision=D.NOT_RECOMMENDED)
    Deployment.objects.filter(pk=stale.pk).update(decision_keyring="stamped")
    return Deployment.objects.values(*sorted(DECISION_OWNED_FIELDS)).get(pk=stale.pk)


def _owned(dep):
    return Deployment.objects.values(*sorted(DECISION_OWNED_FIELDS)).get(pk=dep.pk)


def test_a_full_save_of_a_stale_instance_writes_everything_but_the_decision():
    dep = Deployment.objects.create(name="d", owner=_owner())
    stale = Deployment.objects.get(pk=dep.pk)
    moved = _moved_under(stale)
    assert (stale.decision, stale.decision_revision, stale.decision_keyring) == (None, 0, None)

    stale.description = "edited"
    stale.evidence_incomplete = True
    stale.save()

    assert _owned(dep) == moved
    row = Deployment.objects.get(pk=dep.pk)
    assert row.description == "edited", "every other column is still written"
    assert row.evidence_incomplete is True, "including the inputs the backstop refreshes on"


def test_a_full_save_of_a_deferred_stale_instance_writes_no_decision_either():
    dep = Deployment.objects.create(name="d", owner=_owner())
    stale = Deployment.objects.defer("description").get(pk=dep.pk)
    moved = _moved_under(stale)

    stale.name = "renamed"
    stale.save()

    assert _owned(dep) == moved
    assert Deployment.objects.get(pk=dep.pk).name == "renamed"


def test_an_instance_built_with_a_stored_pk_does_not_write_its_defaults_over_the_decision():
    """Django saves ``Deployment(pk=7, ...)`` as an UPDATE of row 7 before it falls
    back to an INSERT -- every column, the unset decision included."""
    dep = Deployment.objects.create(name="d", owner=_owner())
    moved = _moved_under(dep)

    # The shape a script restoring rows from a dump with `Deployment(**row).save()`
    # takes -- its dumped decision is exactly the stale one.
    Deployment(
        pk=dep.pk, uuid=dep.uuid, name="rebuilt", owner=dep.owner, created_at=dep.created_at
    ).save()

    assert _owned(dep) == moved
    assert Deployment.objects.get(pk=dep.pk).name == "rebuilt"


def test_an_instance_built_with_a_pk_no_row_holds_is_inserted():
    """The existence check is what tells the two apart: with no stored row 4242,
    ``Deployment(pk=4242, ...)`` is a new deployment, inserted with what it was
    given -- not an UPDATE of a row that is not there, which fails."""
    owner = _owner()
    Deployment(pk=4242, name="restored", owner=owner, decision=D.NEEDS_REMEDIATION).save()

    assert Deployment.objects.filter(pk=4242, name="restored").exists()
    assert Deployment.objects.get(pk=4242).decision == D.NEEDS_REMEDIATION


def test_a_deferred_instance_writes_only_what_it_loaded(django_assert_num_queries):
    """As Django's own save does for a deferred instance. Naming every column would
    make each deferred one a query to fetch the value it then writes back."""
    dep = Deployment.objects.create(name="d", owner=_owner())
    handle = Deployment.objects.only("name").get(pk=dep.pk)
    handle.name = "renamed"

    with django_assert_num_queries(1):
        handle.save()
    assert Deployment.objects.get(pk=dep.pk).name == "renamed"


@pytest.mark.parametrize("column", sorted(DECISION_OWNED_FIELDS))
def test_a_save_that_names_a_decision_column_is_refused(column):
    """Refused, not dropped: a caller that asked for the decision to be written and
    got a save that wrote nothing would go on believing it had set it."""
    dep = Deployment.objects.create(name="d", owner=_owner())
    moved = _moved_under(dep)
    dep.decision, dep.decision_revision, dep.decision_keyring = D.READY, 0, "forged"

    with pytest.raises(DecisionColumnWriteRefused):
        dep.save(update_fields=[column, "name"])
    with pytest.raises(DecisionColumnWriteRefused):
        Deployment.objects.update_or_create(pk=dep.pk, defaults={column: getattr(dep, column)})

    assert _owned(dep) == moved


def test_a_new_row_is_still_inserted_with_the_decision_it_was_given():
    """An INSERT has no transition log to fall behind; the backstop refreshes its
    decision once the transaction commits. Fixtures create rows this way."""
    dep = Deployment.objects.create(name="d", owner=_owner(), decision=D.NEEDS_REMEDIATION)
    assert Deployment.objects.get(pk=dep.pk).decision == D.NEEDS_REMEDIATION

    fresh = Deployment(name="e", owner=dep.owner, decision=D.READY)
    fresh.save()
    assert Deployment.objects.get(pk=fresh.pk).decision == D.READY


def test_a_stale_instance_of_a_deleted_deployment_is_not_resurrected():
    """Django's plain save re-inserts a deleted row. This one would come back with
    the decision its deleted findings and transition log supported."""
    dep = Deployment.objects.create(name="d", owner=_owner())
    accept_transition(dep, to_decision=D.READY)
    Deployment.objects.filter(pk=dep.pk).delete()

    # In a savepoint: the failed save marks the enclosing transaction for rollback.
    with pytest.raises(DatabaseError), transaction.atomic():
        dep.save()
    assert not Deployment.objects.filter(pk=dep.pk).exists()


def test_the_admin_saving_an_instance_loaded_before_a_refresh_leaves_the_decision():
    """The change form's ``save_model`` is a plain save of the instance the admin
    loaded; a refresh committed between the load and the save used to be undone."""
    dep = Deployment.objects.create(name="d", owner=_owner())
    stale = Deployment.objects.get(pk=dep.pk)
    moved = _moved_under(stale)

    stale.name = "admin-edited"
    request = RequestFactory().post("/admin/")
    DeploymentAdmin(Deployment, admin.site).save_model(request, stale, form=None, change=True)

    assert _owned(dep) == moved
    assert Deployment.objects.get(pk=dep.pk).name == "admin-edited"


# ---------------------------------------------------------------------------
# accept_transition repairs a row behind its transition log
# ---------------------------------------------------------------------------


def _behind_its_log():
    """READY at 1, then NOT_RECOMMENDED at 2 -- and the row written back to READY at
    1 beneath the log, the state the stale save left before the model refused it.
    Planted with a QuerySet update, which the model cannot see."""
    dep = Deployment.objects.create(name="d", owner=_owner())
    accept_transition(dep, to_decision=D.READY)
    accept_transition(dep, to_decision=D.NOT_RECOMMENDED)
    Deployment.objects.filter(pk=dep.pk).update(decision=D.READY, decision_revision=1)
    return dep


def _repair_logged(caplog, dep):
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1, [r.getMessage() for r in errors]
    assert errors[0].name == "assurance.revision"
    message = errors[0].getMessage()
    assert f"deployment {dep.pk}:" in message and "behind its transition log" in message


def test_a_move_from_a_row_behind_its_log_takes_the_revision_after_the_log(caplog):
    dep = _behind_its_log()

    with caplog.at_level(logging.ERROR):
        out = accept_transition(dep, to_decision=D.NEEDS_REMEDIATION)

    assert out == {"decision": D.NEEDS_REMEDIATION, "revision": 3, "changed": True}
    assert read_decision(dep) == {"decision": D.NEEDS_REMEDIATION, "revision": 3}
    # FROM what the log last recorded, so the sequence consumers drained stays whole.
    assert _log(dep)[-1] == (3, D.NOT_RECOMMENDED, D.NEEDS_REMEDIATION)
    _repair_logged(caplog, dep)


def test_a_row_behind_a_log_that_already_records_the_decision_is_brought_up_to_it(caplog):
    dep = _behind_its_log()

    with caplog.at_level(logging.ERROR):
        out = accept_transition(dep, to_decision=D.NOT_RECOMMENDED)

    assert out == {"decision": D.NOT_RECOMMENDED, "revision": 2, "changed": True}
    assert read_decision(dep) == {"decision": D.NOT_RECOMMENDED, "revision": 2}
    assert (dep.decision, dep.decision_revision) == (D.NOT_RECOMMENDED, 2)
    assert len(_log(dep)) == 2, "the move was recorded when it happened; nothing new"
    _repair_logged(caplog, dep)


def test_a_row_behind_its_log_holding_the_decision_computed_is_not_a_no_op(caplog):
    """The stale row already says READY and READY is what was computed -- but the
    log says the decision in force is NOT_RECOMMENDED, and that is what every
    consumer was told. Returning "unchanged" would leave the row beneath its log
    for good; the move back to READY is a real one and gets its own revision."""
    dep = _behind_its_log()

    with caplog.at_level(logging.ERROR):
        out = accept_transition(dep, to_decision=D.READY)

    assert out == {"decision": D.READY, "revision": 3, "changed": True}
    assert read_decision(dep) == {"decision": D.READY, "revision": 3}
    assert _log(dep)[-1] == (3, D.NOT_RECOMMENDED, D.READY)
    _repair_logged(caplog, dep)


def test_a_row_behind_a_log_that_records_no_decision_is_brought_up_to_it(caplog):
    """The log stores an unassessed decision as ``""``; the decision is ``None``.
    Read as ``""``, a recompute to ``None`` was a move, and recorded a transition
    from nothing to nothing."""
    dep = Deployment.objects.create(name="d", owner=_owner())
    accept_transition(dep, to_decision=D.READY)
    accept_transition(dep, to_decision=None)
    assert _log(dep)[-1] == (2, D.READY, "")
    Deployment.objects.filter(pk=dep.pk).update(decision=D.READY, decision_revision=1)

    with caplog.at_level(logging.ERROR):
        out = accept_transition(Deployment.objects.get(pk=dep.pk), to_decision=None)

    assert out == {"decision": None, "revision": 2, "changed": True}
    assert read_decision(dep) == {"decision": None, "revision": 2}
    assert len(_log(dep)) == 2
    _repair_logged(caplog, dep)


def test_the_callers_own_instance_is_brought_up_by_a_repair_that_records_nothing():
    """The instance handed in is the stale one -- not one that already holds the
    values the repair writes."""
    dep = _behind_its_log()
    fresh = Deployment.objects.get(pk=dep.pk)
    assert (fresh.decision, fresh.decision_revision) == (D.READY, 1)

    accept_transition(fresh, to_decision=D.NOT_RECOMMENDED)

    assert (fresh.decision, fresh.decision_revision) == (D.NOT_RECOMMENDED, 2)


def test_a_row_ahead_of_its_log_is_trusted_and_not_reported(caplog):
    """A row with a revision and no transitions behind it (a deployment decided
    before the log existed) is not corruption: the next revision follows the row."""
    dep = Deployment.objects.create(name="d", owner=_owner())
    Deployment.objects.filter(pk=dep.pk).update(decision=D.READY, decision_revision=5)

    with caplog.at_level(logging.ERROR):
        out = accept_transition(dep, to_decision=D.NOT_RECOMMENDED)

    assert out == {"decision": D.NOT_RECOMMENDED, "revision": 6, "changed": True}
    assert _log(dep) == [(6, D.READY, D.NOT_RECOMMENDED)]
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []


def test_a_wedged_deployment_is_repaired_by_the_next_recompute(caplog):
    """The state the stale save produced before the model refused it: stored READY
    at a revision the log has moved past, with a critical finding open. The recompute
    route answered 500 on it for ever; it now repairs it."""
    dep = _scanned_ready()
    _critical(dep)
    recompute_decision(dep)
    top = dep.decision_revision
    Deployment.objects.filter(pk=dep.pk).update(decision=D.READY, decision_revision=top - 1)

    client = _client(dep)
    with caplog.at_level(logging.ERROR):
        response = client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {}, format="json")

    assert response.status_code == 200, response.content
    assert response.json()["decision"] == D.NOT_RECOMMENDED
    assert read_decision(dep) == {"decision": D.NOT_RECOMMENDED, "revision": top}
    assert one_decision(dep, client) == D.NOT_RECOMMENDED
    _repair_logged(caplog, dep)


# ---------------------------------------------------------------------------
# The operator's pause is read from the decision in force, not the stale row
# ---------------------------------------------------------------------------


def _pause_through_the_route(dep):
    """An operator pauses a READY deployment through the route: PAUSED at N+1, with
    the transition recorded. Returns N+1."""
    response = _client(dep).post(
        f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json"
    )
    assert response.status_code == 200 and response.json()["decision"] == D.PAUSED
    paused_at = dep.decision_revision + 1
    assert _log(dep)[-1] == (paused_at, D.READY, D.PAUSED)
    return paused_at


def _write_back(dep, decision, revision):
    """The row written back beneath its log -- what an admin form loaded before the
    pause and saved after it did, before the model refused the decision columns.
    Planted with a QuerySet update, which the model cannot see."""
    Deployment.objects.filter(pk=dep.pk).update(decision=decision, decision_revision=revision)


def _refresh_by_recompute(dep):
    recompute_decision(Deployment.objects.get(pk=dep.pk))


def _refresh_by_route(dep):
    response = _client(dep).post(
        f"/api/assurance/deployments/{dep.uuid}/recompute/", {}, format="json"
    )
    assert response.status_code == 200, response.content


@pytest.mark.parametrize("refresh", [_refresh_by_recompute, _refresh_by_route])
def test_a_repair_keeps_the_pause_the_log_records(caplog, refresh):
    """The refresh that repairs the row keeps "the pause" as the LOG records it. It
    read it from the row it was repairing, and recorded PAUSED -> READY: every
    consumer draining the transitions was told to resume a deployment its operator
    had paused, and no operator had lifted anything."""
    dep = _scanned_ready()
    paused_at = _pause_through_the_route(dep)
    _write_back(dep, D.READY, paused_at - 1)
    log = _log(dep)

    with caplog.at_level(logging.ERROR):
        refresh(dep)

    assert read_decision(dep) == {"decision": D.PAUSED, "revision": paused_at}
    assert _log(dep) == log, "the pause was recorded when it was made; nothing new"
    _repair_logged(caplog, dep)


def test_a_repair_by_the_backstop_keeps_the_pause_over_a_new_critical_finding(
    caplog, django_capture_on_commit_callbacks
):
    """The refresh an input write schedules is the commonest one to meet a wedged
    row. Computed without the pause, the finding recorded PAUSED -> NOT_RECOMMENDED."""
    # Committed, so no refresh from the setup is still pending to stand for the
    # finding's own.
    with django_capture_on_commit_callbacks(execute=True):
        dep = _scanned_ready()
        paused_at = _pause_through_the_route(dep)
    _write_back(dep, D.READY, paused_at - 1)
    log = _log(dep)

    with caplog.at_level(logging.ERROR), django_capture_on_commit_callbacks(execute=True) as hooks:
        _critical(dep)

    assert any(isinstance(hook, signals._RefreshAfterCommit) for hook in hooks)
    assert read_decision(dep) == {"decision": D.PAUSED, "revision": paused_at}
    assert _log(dep) == log
    _repair_logged(caplog, dep)


def test_a_repair_keeps_the_lift_the_log_records(caplog):
    """The mirror: the operator lifted a pause, and a stale PAUSED was written back
    beneath the lift. The repair re-paused a deployment its operator had released."""
    dep = _scanned_ready()
    recompute_decision(dep, paused=True)
    paused_at = dep.decision_revision
    recompute_decision(dep, paused=False)
    assert _log(dep)[-1] == (paused_at + 1, D.PAUSED, D.READY)
    _write_back(dep, D.PAUSED, paused_at)
    log = _log(dep)

    with caplog.at_level(logging.ERROR):
        recompute_decision(Deployment.objects.get(pk=dep.pk))

    assert read_decision(dep) == {"decision": D.READY, "revision": paused_at + 1}
    assert _log(dep) == log
    _repair_logged(caplog, dep)


@pytest.mark.parametrize(
    ("stored", "logged", "ahead"),
    [
        (D.PAUSED, D.PAUSED, 0),
        (D.READY, D.READY, 0),
        # A row ahead of its log is trusted, so its pause is: the log's older
        # word does not reach back over it.
        (D.PAUSED, D.READY, 4),
        (D.READY, D.PAUSED, 4),
    ],
)
def test_a_row_level_with_or_ahead_of_its_log_keeps_its_own_pause(caplog, stored, logged, ahead):
    dep = _scanned_ready()
    accept_transition(dep, to_decision=logged)
    top = _log(dep)[-1][0]
    Deployment.objects.filter(pk=dep.pk).update(decision=stored, decision_revision=top + ahead)
    log = _log(dep)

    with caplog.at_level(logging.ERROR):
        assert recompute_decision(Deployment.objects.get(pk=dep.pk)) == stored

    assert read_decision(dep) == {"decision": stored, "revision": top + ahead}
    assert _log(dep) == log
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []


@pytest.mark.parametrize(
    ("logged", "paused", "decided"), [(D.PAUSED, False, D.READY), (D.READY, True, D.PAUSED)]
)
def test_an_explicit_pause_or_lift_still_wins_over_the_log(caplog, logged, paused, decided):
    """An operator's explicit word is not "keep the pause", on a repaired row or any
    other. It is a real move FROM what the log records, with its own revision --
    even though the stale row happens to hold the decision asked for."""
    dep = _scanned_ready()
    recompute_decision(dep, paused=True)
    if logged == D.READY:
        recompute_decision(dep, paused=False)
    top = dep.decision_revision
    assert _log(dep)[-1][1:] == (decided, logged)
    _write_back(dep, decided, top - 1)

    with caplog.at_level(logging.ERROR):
        assert recompute_decision(Deployment.objects.get(pk=dep.pk), paused=paused) == decided

    assert read_decision(dep) == {"decision": decided, "revision": top + 1}
    assert _log(dep)[-1] == (top + 1, logged, decided)
    _repair_logged(caplog, dep)


def test_a_reading_of_a_row_that_has_moved_is_refused():
    """``accept_transition(in_force=...)`` trusts the caller's reading. One taken
    before the row moved would be moved FROM -- and when it already held the
    decision accepted, written back: the row beneath its log again."""
    dep = Deployment.objects.create(name="d", owner=_owner())
    accept_transition(dep, to_decision=D.READY)
    reading = decision_in_force(Deployment.objects.get(pk=dep.pk))
    assert reading[:2] == (D.READY, 1)
    accept_transition(Deployment.objects.get(pk=dep.pk), to_decision=D.NOT_RECOMMENDED)
    log = _log(dep)

    for to_decision in (D.READY, D.NEEDS_REMEDIATION):
        with pytest.raises(StaleDecisionRead), transaction.atomic():
            accept_transition(dep, to_decision=to_decision, in_force=reading)

    assert read_decision(dep) == {"decision": D.NOT_RECOMMENDED, "revision": 2}
    assert _log(dep) == log


def test_a_reading_of_another_deployment_is_refused():
    """Two new deployments read the same (decision, revision); the row the reading
    came from is part of it."""
    one = Deployment.objects.create(name="one", owner=_owner())
    other = Deployment.objects.create(name="other", owner=one.owner)
    reading = decision_in_force(Deployment.objects.get(pk=one.pk))

    with pytest.raises(StaleDecisionRead), transaction.atomic():
        accept_transition(other, to_decision=D.READY, in_force=reading)

    assert read_decision(other) == {"decision": None, "revision": 0}
    assert _log(other) == []


def test_a_reading_of_a_row_that_moved_away_and_back_is_refused():
    """The row left READY and came back to it at a later revision: the same
    decision, a different fact. A reading compared on the decision alone accepted
    the old one and wrote the row back to revision 1, beneath its own log -- the
    wedge the repair exists to undo. The revision is part of the reading."""
    dep = Deployment.objects.create(name="d", owner=_owner())
    accept_transition(dep, to_decision=D.READY)
    reading = decision_in_force(Deployment.objects.get(pk=dep.pk))
    accept_transition(Deployment.objects.get(pk=dep.pk), to_decision=D.NOT_RECOMMENDED)
    accept_transition(Deployment.objects.get(pk=dep.pk), to_decision=D.READY)
    log = _log(dep)

    with pytest.raises(StaleDecisionRead), transaction.atomic():
        accept_transition(dep, to_decision=D.READY, in_force=reading)

    assert read_decision(dep) == {"decision": D.READY, "revision": 3}
    assert _log(dep) == log


def test_a_reading_of_a_row_whose_decision_moved_without_a_revision_is_refused():
    """The decision moved and the revision did not -- a write the one writer never
    makes, which is exactly why the reading must not be trusted across it. A reading
    compared on the revision alone moved FROM a decision the row no longer held.
    The decision is part of the reading."""
    dep = Deployment.objects.create(name="d", owner=_owner())
    accept_transition(dep, to_decision=D.READY)
    reading = decision_in_force(Deployment.objects.get(pk=dep.pk))
    Deployment.objects.filter(pk=dep.pk).update(decision=D.NOT_RECOMMENDED)

    with pytest.raises(StaleDecisionRead), transaction.atomic():
        accept_transition(dep, to_decision=D.READY, in_force=reading)

    assert Deployment.objects.values_list("decision", "decision_revision").get(pk=dep.pk) == (
        D.NOT_RECOMMENDED,
        1,
    )
    assert _log(dep) == [(1, "", D.READY)]


def test_a_reading_taken_under_the_lock_is_the_one_moved_from():
    """Passed the reading, the call does not read the log a second time."""
    dep = _behind_its_log()
    reading = decision_in_force(Deployment.objects.get(pk=dep.pk))
    assert reading[:2] == (D.NOT_RECOMMENDED, 2)

    with CaptureQueriesContext(connection) as queries:
        accept_transition(dep, to_decision=D.NEEDS_REMEDIATION, in_force=reading)

    assert not [
        q["sql"]
        for q in queries
        if "assurance_decisiontransition" in q["sql"] and "SELECT" in q["sql"]
    ]
    assert _log(dep)[-1] == (3, D.NOT_RECOMMENDED, D.NEEDS_REMEDIATION)


# ---------------------------------------------------------------------------
# A backstop refresh that fails is loud
# ---------------------------------------------------------------------------


def test_an_integrity_error_in_the_backstop_refresh_is_logged_at_error_naming_the_deployment(
    monkeypatch, caplog
):
    """By commit time the write it follows has committed, so the refresh must not
    raise into the caller. It must not pass unseen either: a torn revision showed
    itself here and nowhere else."""
    from assurance import decision as decision_module

    dep = Deployment.objects.create(name="d", owner=_owner())

    def collides(ids):
        raise IntegrityError(
            "UNIQUE constraint failed: assurance_decisiontransition.deployment_id, "
            "assurance_decisiontransition.revision"
        )

    monkeypatch.setattr(decision_module, "refresh_stored_decisions", collides)
    with caplog.at_level(logging.ERROR, logger="assurance.signals"):
        signals._RefreshAfterCommit(dep.pk, None)()  # does not raise

    [record] = [r for r in caplog.records if r.name == "assurance.signals"]
    assert record.levelno == logging.ERROR
    assert f"deployment {dep.pk};" in record.getMessage()
    assert "not refreshed" in record.getMessage()
    assert record.exc_info and record.exc_info[0] is IntegrityError


# ---------------------------------------------------------------------------
# One writer, held to it
# ---------------------------------------------------------------------------


#: Directory names the one-writer scan never enters: the tests, which plant
#: corrupt rows on purpose, and third-party code a checkout may hold. A virtualenv
#: under any other name is recognised by its ``pyvenv.cfg``.
_NOT_FIRST_PARTY = frozenset({"tests", "node_modules", "site-packages", "__pycache__"})

#: The refresh's own writes of the decision columns -- ONE each. The decision and
#: its revision, with the transition that records the move; and the keyring stamp,
#: beside it and under the same lock.
_THE_REFRESH = Counter(
    {("assurance/revision.py", "_write"): 1, ("assurance/decision.py", "recompute_decision"): 1}
)

_OWNED = r"\b(?:%s)\b" % "|".join(sorted(DECISION_OWNED_FIELDS))
#: A column named anywhere in SQL the ORM turns into model values.
_NAMES_AN_OWNED_COLUMN = re.compile(_OWNED, re.IGNORECASE)
#: SQL that writes a column, naming an owned one.
_SQL_WRITING_AN_OWNED_COLUMN = re.compile(
    r"\b(?:UPDATE\b.*?\bSET|(?:INSERT|REPLACE|MERGE)\b.*?\bINTO|ON\s+CONFLICT)\b.*?" + _OWNED,
    re.IGNORECASE | re.DOTALL,
)
#: The comment that clears ONE write the scan flags, with the reason it is not a
#: writer. For a proven false positive only; the reason is required. A comment,
#: read as a token -- never text inside a string -- on the write's own line: the
#: line of the write's method name, or of the end of its call.
_NOT_A_WRITER = re.compile(r"#\s*not-a-decision-writer:\s*\S")
#: Neither passed nor determinable: an argument hidden behind ``*args``/``**kwargs``.
_UNKNOWN = object()

#: A QuerySet's update, sync and async: its keywords are the columns it writes.
_UPDATES = frozenset({"update", "aupdate"})
#: What an update and a model save come down to: whatever they are handed, they
#: write, and what they are handed is not keywords this scan can read.
_PRIVATE_WRITES = frozenset({"_update", "_do_update", "_save_table"})
#: Each bulk write, sync and async, and where its field list is passed:
#: ``(positional index, keyword)``.
_BULK_WRITES = {
    "bulk_update": (1, "fields"),
    "abulk_update": (1, "fields"),
    # An upsert: rows that collide are UPDATEd with `update_fields`.
    "bulk_create": (4, "update_fields"),
    "abulk_create": (4, "update_fields"),
}
#: Every method a call of which writes columns. Referenced without being called --
#: bound to a name, fetched with getattr, handed to functools.partial -- what it is
#: finally called with cannot be read where it is called.
_WRITE_METHODS = _UPDATES | _PRIVATE_WRITES | frozenset(_BULK_WRITES) | {"save_base"}
#: The query classes an UPDATE is built from by hand.
_UPDATE_QUERIES = frozenset({"UpdateQuery", "SQLUpdateCompiler"})
#: What hands back objects whose ``save()`` is ``save_base(raw=True)``, past
#: Deployment.save, for whatever model the data names: held wherever named.
_RAW_SAVES = frozenset({"deserialize", "DeserializedObject"})
_RAW_SAVE_WHY = "%s: a deserialized object's save() is save_base(raw=True), past Deployment.save"
#: SQL run as it stands, and where each call takes its statements: held to what the
#: statements DO. A SELECT naming the decision reads it.
_RUN_SQL = {
    "execute": ((0, ("sql", "query", "operation")),),
    "executemany": ((0, ("sql", "query", "operation")),),
    "executescript": ((0, ("sql_script",)),),
    # Both run: `reverse_sql` on the way back down.
    "RunSQL": ((0, ("sql",)), (1, ("reverse_sql",))),
}
#: SQL the ORM turns into model values, held to naming an owned column at all:
#: raw() hands back Deployments carrying whatever decision its SQL says, and a
#: RawSQL can stand in the value of an update.
_ORM_SQL = {"raw": ((0, ("raw_query",)),), "RawSQL": ((0, ("sql",)),)}
#: A method fetched by name -- ``getattr``, ``attrgetter``, ``methodcaller``, a
#: class's ``__dict__`` -- that writes, or runs SQL, whatever it is handed.
_FETCHED_WRITES = _WRITE_METHODS | frozenset(_RUN_SQL)
#: The calls that write, save or run SQL, by name, whatever they write. On a line
#: holding more than one, an allow comment cannot say which it is for.
_WRITE_SHAPED = _FETCHED_WRITES | frozenset(_ORM_SQL) | {"save"}
#: The steps from a model to its rows. A chain of these alone from ANOTHER model is
#: that model's queryset; any other step -- a relation, a call that hands back an
#: instance -- may reach a Deployment.
_QUERYSET_STEPS = frozenset(
    {
        "objects", "_default_manager", "_base_manager", "db_manager", "get_queryset",
        "all", "filter", "exclude", "select_for_update", "using", "order_by", "reverse",
        "select_related", "prefetch_related", "annotate", "alias", "distinct", "only",
        "defer", "none", "complex_filter", "extra", "values", "values_list",
    }
)
#: Calls that build a container, which is never a queryset.
_CONTAINERS = frozenset(
    {
        "dict", "set", "list", "tuple", "frozenset",
        "defaultdict", "OrderedDict", "Counter", "ChainMap", "deque",
    }
)
_LITERALS = (
    ast.Dict, ast.Set, ast.List, ast.Tuple, ast.Constant, ast.JoinedStr,
    ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp,
)
#: What a parameter holding a queryset or a manager is called.
_QUERYSET_NAME = re.compile(r"(?:\w+_)?(?:qs|queryset|querysets|manager|objects)")
#: What a queryset or manager class is called.
_QUERYSET_CLASS = re.compile(r"\w*(?:QuerySet|Manager)\b")
#: At most this many values are followed through a string's assembly; past it, the
#: string is one the scan cannot read.
_MOST_VALUES = 256


def _first_party_python(root=_REPO):
    """Every first-party Python file, as ``{repo-relative path: source}``: the code,
    and the migrations apart from it. Every package, not just ``assurance/``: a
    writer in ``failsafe/views.py`` is a second writer all the same."""
    code, migrations = {}, {}
    for directory, subdirectories, files in os.walk(root):
        here = Path(directory)
        subdirectories[:] = sorted(
            name
            for name in subdirectories
            if name not in _NOT_FIRST_PARTY
            and not name.startswith(".")
            and not (here / name / "pyvenv.cfg").exists()
        )
        for name in sorted(files):
            if name.endswith(".py"):
                relative = (here / name).relative_to(root)
                into = migrations if "migrations" in relative.parts else code
                into[relative.as_posix()] = (here / name).read_text()
    return code, migrations


def _names(node):
    """The column names a literal list/tuple/set of strings holds; ``None`` if it is
    anything else, which cannot be read without running it."""
    if isinstance(node, (ast.List, ast.Tuple, ast.Set)) and all(
        isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts
    ):
        return {e.value for e in node.elts}
    return None


def _passed_through(function):
    """The name of ``function``'s own ``**`` parameter, when ``function`` is an
    ``update`` that only hands it on -- as a view's ``def update(self, request,
    *args, **kwargs): return super().update(request, *args, **kwargs)`` does. Those
    keys are its callers', and every caller is an ``update(...)`` call this scan
    reads for itself. ``None`` otherwise: a mapping the function changes, rebinds
    or reads for anything else can carry keys of its own."""
    if not isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)):
        return None
    if function.name != "update" or function.args.kwarg is None:
        return None
    name = function.args.kwarg.arg
    unpacked = {
        id(node.value)
        for node in ast.walk(function)
        if isinstance(node, ast.keyword) and node.arg is None
    }
    for node in ast.walk(function):
        if isinstance(node, ast.Name) and node.id == name and id(node) not in unpacked:
            return None
        if isinstance(node, ast.arg) and node.arg == name and node is not function.args.kwarg:
            return None
    return name


def _keys(keywords, passed_through=None):
    """The keyword names a call passes, ``**{...}`` and ``**dict(...)`` literals
    unpacked; ``None`` if any ``**`` hides keys that cannot be read statically.
    ``passed_through`` names a ``**`` mapping that adds none (see
    :func:`_passed_through`)."""
    names = set()
    for keyword in keywords:
        if keyword.arg is not None:
            names.add(keyword.arg)
            continue
        value = keyword.value
        if passed_through is not None and isinstance(value, ast.Name) and value.id == passed_through:
            continue
        if isinstance(value, ast.Dict):
            for key, item in zip(value.keys, value.values, strict=True):
                if key is None:  # `**{**other}`
                    inner = _keys([ast.keyword(arg=None, value=item)])
                    if inner is None:
                        return None
                    names |= inner
                elif isinstance(key, ast.Constant) and isinstance(key.value, str):
                    names.add(key.value)
                else:
                    return None
        elif (
            isinstance(value, ast.Call)
            and isinstance(value.func, ast.Name)
            and value.func.id == "dict"
            and not value.args
        ):
            inner = _keys(value.keywords)
            if inner is None:
                return None
            names |= inner
        else:
            return None
    return names


def _argument(call, index, keywords):
    """The node passed as parameter ``keywords`` (a name, or a tuple of the names it
    goes by; positional ``index``); ``None`` if not passed, :data:`_UNKNOWN` if it
    may be hidden in ``*args``/``**kwargs``."""
    keywords = (keywords,) if isinstance(keywords, str) else keywords
    for passed in call.keywords:
        if passed.arg in keywords:
            return passed.value
    ahead = call.args[: index + 1]
    if any(isinstance(a, ast.Starred) for a in ahead):
        return _UNKNOWN
    if len(call.args) > index:
        return call.args[index]
    if any(passed.arg is None for passed in call.keywords):
        return _UNKNOWN
    return None


def _fields_write(call, index, keyword, *, absent=None):
    """Why the field list a call passes as ``keyword`` (positional ``index``) writes
    an owned column, or ``None``. ``absent`` is why a call that passes none -- or
    ``None`` -- does, if it does."""
    fields = _argument(call, index, keyword)
    if fields is None or (isinstance(fields, ast.Constant) and fields.value is None):
        return absent
    names = None if fields is _UNKNOWN else _names(fields)
    if names is None:
        return f"{keyword} that cannot be resolved"
    owned = names & DECISION_OWNED_FIELDS
    return f"{keyword} naming {sorted(owned)}" if owned else None


def _called(call):
    func = call.func
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)


def _chain(node):
    """``node`` taken apart as ``(root, steps)``: ``Deployment.objects.filter(pk=1)``
    is the root ``Deployment`` and the steps ``["objects", "filter"]``. A call of a
    bare name (``super()``, ``type(x)``) or of ``get_model`` is a root."""
    steps = []
    while True:
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr != "get_model":
                steps.append(func.attr)
                node = func.value
                continue
        elif isinstance(node, ast.Attribute):
            steps.append(node.attr)
            node = node.value
            continue
        elif isinstance(node, ast.Subscript):
            steps.append("[]")
            node = node.value
            continue
        return node, steps[::-1]


def _bind(found, target, value):
    if isinstance(target, ast.Name):
        found.setdefault(target.id, []).append(value)
    elif isinstance(target, (ast.Tuple, ast.List)):
        for element in target.elts:
            _bind(found, element, _OPAQUE)
    elif isinstance(target, ast.Starred):
        _bind(found, target.value, _OPAQUE)


#: A binding the scan does not follow: a loop target, an augmented assignment, a
#: name another scope rebinds with ``global``/``nonlocal``, ...
_OPAQUE = object()
_COMPREHENSIONS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


def _bindings(scope):
    """Every name ``scope`` binds, as ``{name: [what it is bound to, ...]}``: an
    expression, ``("param", arg)``, ``("import", imported name)``, ``("class",
    node)``, or :data:`_OPAQUE`. Every binding in the scope, wherever it sits, since
    a name read anywhere in it may hold any of them. Nested scopes are not entered.
    """
    found = {}
    if isinstance(scope, _COMPREHENSIONS):
        for generator in scope.generators:
            _bind(found, generator.target, _OPAQUE)
        return found
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
        arguments = scope.args
        for arg in (
            *arguments.posonlyargs, *arguments.args, *arguments.kwonlyargs,
            arguments.vararg, arguments.kwarg,
        ):
            if arg is not None:
                found.setdefault(arg.arg, []).append(("param", arg))
        pending = [scope.body] if isinstance(scope, ast.Lambda) else list(scope.body)
    else:
        pending = list(scope.body)
    for node in ast.walk(scope):
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            for name in node.names:
                found.setdefault(name, []).append(_OPAQUE)
    while pending:
        node = pending.pop()
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)):
            # Its decorators, defaults and bases are evaluated here; its body is not.
            if isinstance(node, ast.ClassDef):
                found.setdefault(node.name, []).append(("class", node))
                pending.extend([*node.decorator_list, *node.bases, *(k.value for k in node.keywords)])
            else:
                if not isinstance(node, ast.Lambda):
                    found.setdefault(node.name, []).append(_OPAQUE)
                    pending.extend(node.decorator_list)
                pending.extend([*node.args.defaults, *(d for d in node.args.kw_defaults if d)])
            continue
        if isinstance(node, _COMPREHENSIONS):
            # Its targets are its own; a walrus inside it binds here.
            for inner in ast.walk(node):
                if isinstance(inner, ast.NamedExpr):
                    _bind(found, inner.target, inner.value)
            pending.append(node.generators[0].iter)
            continue
        if isinstance(node, ast.Assign):
            for target in node.targets:
                _bind(found, target, node.value)
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            _bind(found, node.target, node.value)
        elif isinstance(node, ast.NamedExpr):
            _bind(found, node.target, node.value)
        elif isinstance(node, (ast.AugAssign, ast.For, ast.AsyncFor)):
            _bind(found, node.target, _OPAQUE)
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            _bind(found, node.optional_vars, _OPAQUE)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            found.setdefault(node.name, []).append(_OPAQUE)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            found.setdefault(node.name, []).append(_OPAQUE)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            found.setdefault(node.rest, []).append(_OPAQUE)
        elif isinstance(node, ast.ImportFrom):
            for alias in node.names:
                found.setdefault(alias.asname or alias.name, []).append(("import", alias.name))
        elif isinstance(node, ast.Import):
            for alias in node.names:
                found.setdefault(alias.asname or alias.name.split(".")[0], []).append(_OPAQUE)
        pending.extend(ast.iter_child_nodes(node))
    return found


#: What a receiver is, as far as a write through it goes.
_DEPLOYMENT, _ANOTHER_MODEL, _NOT_A_QUERYSET, _MAY_BE_ANYTHING = (
    "a Deployment",
    "another model",
    "not a queryset",
    "may be anything",
)


def _class_named(name):
    """What an unresolved class name is: a Deployment (or a class named for one), a
    queryset or manager class (which may be anything), or another model."""
    if _QUERYSET_CLASS.fullmatch(name):
        return _MAY_BE_ANYTHING
    if "Deployment" in name:
        return _DEPLOYMENT
    return _ANOTHER_MODEL if name[:1].isupper() else _MAY_BE_ANYTHING


def _imported(name):
    """What a name imported as ``name`` is, by the model registry rather than by
    the name: another model only when the registry holds a model of that name and
    none of that name is Deployment or a subclass or proxy of it. A re-export
    (``AISystem = Deployment``) or a proxy of Deployment, imported under a name
    that does not say Deployment, writes a Deployment all the same; a name the
    registry does not hold may be anything."""
    models = [model for model in django_apps.get_models() if model.__name__ == name]
    if any(issubclass(model, Deployment) for model in models):
        return _DEPLOYMENT
    return _ANOTHER_MODEL if models else _MAY_BE_ANYTHING


def _apply(op, left, right):
    return left + right if isinstance(op, ast.Add) else left % right


def _bounded(values):
    """``values`` as a set, or ``None`` past :data:`_MOST_VALUES` or on a value that
    cannot be computed (a format that does not fit its arguments)."""
    out = set()
    try:
        for value in values:
            out.add(value)
            if len(out) > _MOST_VALUES:
                return None
    except (TypeError, ValueError, KeyError, IndexError, AttributeError):
        return None
    return out


def _strings(values):
    """Every string in ``values``, tuples and lists of statements flattened."""
    for value in values:
        if isinstance(value, str):
            yield value
        elif isinstance(value, tuple):
            yield from _strings(value)


def _allowed_lines(source):
    """The lines of ``source`` carrying an allow comment with its reason: a COMMENT
    token, so a string holding the marker is not one."""
    return {
        token.start[0]
        for token in tokenize.generate_tokens(io.StringIO(source).readline)
        if token.type == tokenize.COMMENT and _NOT_A_WRITER.match(token.string)
    }


def _class_dict_of(node):
    """What ``node`` is the class dict of -- ``X`` for ``X.__dict__`` or ``vars(X)``
    -- or ``None``."""
    if isinstance(node, ast.Attribute) and node.attr == "__dict__":
        return node.value
    if isinstance(node, ast.Call) and _called(node) == "vars" and len(node.args) == 1:
        return node.args[0]
    return None


class _Scan(ast.NodeVisitor):
    """One file's writes of a decision column the model cannot see."""

    def __init__(self, path, source, *, migration, found):
        self.path, self.migration, self.found = path, migration, found
        self.allowed = _allowed_lines(source)
        # Every write-shaped site, counted on each of its own lines; and the
        # writes held, as (scope, line, why, own lines), until `finish` clears
        # the ones an allow comment is for.
        self.sites, self.held = Counter(), []
        # The qualified scope a write is reported under, and the `**` an `update`
        # hands on untouched (see `_passed_through`).
        self.scope, self.passed_through = [], [None]
        # The scopes names are looked up in, innermost last.
        self.chain = []
        self.called = set()
        self._cache = {}

    def finish(self):
        """The writes held, but for each that is the one write-shaped site on a line
        carrying an allow comment -- one write per comment: on a line holding more
        than one site the comment cannot say which it is for, and clears none."""
        for scope, line, why, own in self.held:
            if not any(self.sites[mine] == 1 for mine in own & self.allowed):
                self.found.append((self.path, scope, line, why))

    # -- scopes ---------------------------------------------------------------

    def _visit_within(self, node):
        self.chain.append(node)
        self.generic_visit(node)
        self.chain.pop()

    visit_Module = visit_Lambda = _visit_within
    visit_ListComp = visit_SetComp = visit_DictComp = visit_GeneratorExp = _visit_within

    def _scoped(self, node):
        self.scope.append(node.name)
        self.passed_through.append(_passed_through(node))
        self._visit_within(node)
        self.passed_through.pop()
        self.scope.pop()

    visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _scoped

    def _lookup(self, name, chain):
        """``(scope depth, bindings)`` of the innermost scope in ``chain`` binding
        ``name`` -- a class body only for code directly in it, as Python has it --
        or ``None`` for a name nothing here binds (a builtin, a star import)."""
        for depth in range(len(chain) - 1, -1, -1):
            scope = chain[depth]
            if isinstance(scope, ast.ClassDef) and depth != len(chain) - 1:
                continue
            if id(scope) not in self._cache:
                self._cache[id(scope)] = _bindings(scope)
            bindings = self._cache[id(scope)].get(name)
            if bindings is not None:
                return depth, bindings
        return None

    # -- what a receiver is ---------------------------------------------------

    def _kind(self, node, chain, seen=frozenset()):
        if isinstance(node, _LITERALS) or (isinstance(node, ast.Call) and _called(node) in _CONTAINERS):
            return _NOT_A_QUERYSET
        if isinstance(node, ast.IfExp):
            kinds = {self._kind(node.body, chain, seen), self._kind(node.orelse, chain, seen)}
            return kinds.pop() if len(kinds) == 1 else _MAY_BE_ANYTHING
        root, steps = _chain(node)
        kind = self._root_kind(root, chain, seen)
        if not steps:
            return kind
        if kind == _NOT_A_QUERYSET and set(steps) == {"copy"}:
            return kind
        if kind in (_DEPLOYMENT, _ANOTHER_MODEL) and set(steps) <= _QUERYSET_STEPS:
            return kind
        return _MAY_BE_ANYTHING

    def _root_kind(self, root, chain, seen):
        if isinstance(root, _LITERALS):
            return _NOT_A_QUERYSET
        if isinstance(root, ast.Call):
            if _called(root) in _CONTAINERS:
                return _NOT_A_QUERYSET
            if _called(root) == "get_model":
                named = [a.value for a in root.args if isinstance(a, ast.Constant)]
                if len(named) != len(root.args) or not named or root.keywords:
                    return _MAY_BE_ANYTHING
                model = named[-1].rsplit(".", 1)[-1]
                return _DEPLOYMENT if model.lower() == "deployment" else _ANOTHER_MODEL
            return _MAY_BE_ANYTHING  # super(), type(x), a factory
        if not isinstance(root, ast.Name):
            return _MAY_BE_ANYTHING
        found = self._lookup(root.id, chain)
        if found is None:
            return _class_named(root.id)
        depth, bindings = found
        key = (id(chain[depth]), root.id)
        if key in seen:
            return _MAY_BE_ANYTHING
        kinds = {
            self._binding_kind(root.id, binding, chain[: depth + 1], seen | {key})
            for binding in bindings
        }
        return kinds.pop() if len(kinds) == 1 else _MAY_BE_ANYTHING

    def _binding_kind(self, name, binding, chain, seen):
        if binding is _OPAQUE:
            return _MAY_BE_ANYTHING
        if not isinstance(binding, tuple):
            return self._kind(binding, chain, seen)
        what, node = binding
        if what == "import":
            return _imported(node)
        if what == "class":
            bases = " ".join(ast.unparse(base) for base in node.bases)
            if node.name == "Deployment" or (
                re.search(r"\bDeployment\b", bases) and not _QUERYSET_CLASS.search(bases)
            ):
                return _DEPLOYMENT
            return _MAY_BE_ANYTHING if _QUERYSET_CLASS.search(bases) else _ANOTHER_MODEL
        # A parameter: a queryset only if it says so -- by its name, its annotation,
        # or being `self`/`cls`, which may be a queryset's own.
        annotation = ast.unparse(node.annotation) if node.annotation is not None else ""
        if (
            name in ("self", "cls")
            or _QUERYSET_NAME.fullmatch(name)
            or re.search(r"QuerySet|Manager|Deployment", annotation)
        ):
            return _MAY_BE_ANYTHING
        return _NOT_A_QUERYSET

    def _writes_no_deployment(self, receiver, method, chain=None):
        """Whether ``method`` called on ``receiver`` is proven to write no Deployment:
        a queryset of another model reached through queryset steps alone -- or, for
        an ``update`` (which dicts, sets and hashes have too), a container, a name
        bound only to one, or a parameter whose name does not say queryset. Anything
        else may be a Deployment's -- a relation, a factory, a name this scan cannot
        follow -- and is held to the write rules. ``method`` is ``None`` for one
        whose name is not known."""
        if receiver is None:
            return False
        kind = self._kind(receiver, self.chain if chain is None else chain)
        return kind == _ANOTHER_MODEL or (method in _UPDATES and kind == _NOT_A_QUERYSET)

    def _fetched(self, via, receiver, name):
        """Why fetching the method ``name`` names off ``receiver`` writes: ``name``
        computes -- through the scan's own string values -- to a write method, and
        ``receiver`` is not proven to write no Deployment. ``None`` when it does
        not, or cannot be computed (see :meth:`_calls_a_method_it_cannot_name`)."""
        names = self._values(name, self.chain)
        written = sorted(
            method
            for method in _strings(names or ())
            if method in _FETCHED_WRITES and not self._writes_no_deployment(receiver, method)
        )
        if not written:
            return None
        return f"{via} of {written[0]}: what it is called with cannot be read"

    def _calls_a_method_it_cannot_name(self, func, chain):
        """Whether calling ``func`` calls a method fetched by a name this scan cannot
        compute -- ``getattr(x, name)`` or ``X.__dict__[name]``, or a name bound to
        one -- off a receiver not proven to write no Deployment. It may be any write.
        Fetched and not called, it is only a value, as ``getattr`` mostly is."""
        if isinstance(func, ast.Name):
            found = self._lookup(func.id, chain)
            if found is None:
                return False
            depth, bindings = found
            return any(
                isinstance(binding, (ast.Call, ast.Subscript))
                and self._calls_a_method_it_cannot_name(binding, chain[: depth + 1])
                for binding in bindings
            )
        if isinstance(func, ast.Call) and _called(func) == "getattr" and len(func.args) >= 2:
            receiver, name = func.args[0], func.args[1]
        elif isinstance(func, ast.Subscript) and _class_dict_of(func.value) is not None:
            receiver, name = _class_dict_of(func.value), func.slice
        else:
            return False
        return self._values(name, chain) is None and not self._writes_no_deployment(
            receiver, None, chain
        )

    # -- what a string is -----------------------------------------------------

    def _values(self, node, chain, seen=frozenset()):
        """Every value ``node`` can hold, when each is a constant this scan can
        compute -- through concatenation, ``%``, ``.format``, f-strings, ``join``,
        conditionals and names bound only to such values, here or at module level.
        ``None`` for anything else: a parameter, a call, a name bound in a loop."""
        if isinstance(node, ast.Constant):
            return {node.value}
        if isinstance(node, ast.Attribute) and node.attr == "noop":
            return {""}  # migrations.RunSQL.noop
        if isinstance(node, ast.Name):
            found = self._lookup(node.id, chain)
            if found is None:
                return None
            depth, bindings = found
            key = (id(chain[depth]), node.id)
            # Only what cannot change once bound: a list can be appended to anywhere
            # the name reaches, and a parameter, an import or a loop target is not
            # a value here at all.
            if key in seen or any(
                b is _OPAQUE or isinstance(b, (tuple, ast.List)) for b in bindings
            ):
                return None
            out = set()
            for binding in bindings:
                values = self._values(binding, chain[: depth + 1], seen | {key})
                if values is None:
                    return None
                out |= values
            return _bounded(out)
        if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Add, ast.Mod)):
            left = self._values(node.left, chain, seen)
            right = self._values(node.right, chain, seen)
            if left is None or right is None:
                return None
            return _bounded(_apply(node.op, a, b) for a, b in product(left, right))
        if isinstance(node, (ast.Tuple, ast.List)):
            elements = [self._values(e, chain, seen) for e in node.elts]
            if any(e is None for e in elements):
                return None
            return _bounded(tuple(p) for p in product(*elements))
        if isinstance(node, ast.IfExp):
            body = self._values(node.body, chain, seen)
            orelse = self._values(node.orelse, chain, seen)
            return None if body is None or orelse is None else _bounded(body | orelse)
        if isinstance(node, ast.JoinedStr):
            parts = []
            for value in node.values:
                if isinstance(value, ast.Constant):
                    parts.append({value.value})
                    continue
                inner = self._values(value.value, chain, seen)
                if inner is None or value.format_spec is not None:
                    return None
                convert = {-1: format, 115: str, 114: repr, 97: ascii}[value.conversion]
                parts.append({convert(v) for v in inner})
            return _bounded("".join(p) for p in product(*parts))
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr in ("format", "join")
            and not any(isinstance(a, ast.Starred) for a in node.args)
            and all(k.arg is not None for k in node.keywords)
        ):
            receiver = self._values(node.func.value, chain, seen)
            args = [self._values(a, chain, seen) for a in node.args]
            kwargs = {k.arg: self._values(k.value, chain, seen) for k in node.keywords}
            if receiver is None or None in args or None in kwargs.values():
                return None
            if node.func.attr == "join":
                if len(args) != 1 or kwargs:
                    return None
                return _bounded(r.join(a) for r in receiver for a in args[0])
            names = list(kwargs)
            return _bounded(
                r.format(*p[: len(args)], **dict(zip(names, p[len(args) :], strict=True)))
                for r in receiver
                for p in product(*args, *kwargs.values())
            )
        return None

    # -- the rules ------------------------------------------------------------

    def _site(self, node, why=None):
        """Count ``node`` as a write-shaped site on its own lines -- the line its
        method is named on, and the line its call ends on -- and hold it if ``why``."""
        own = {getattr(node, "func", node).end_lineno, node.end_lineno}
        for line in own:
            self.sites[line] += 1
        if why:
            self.held.append((".".join(self.scope) or "<module>", node.lineno, why, own))

    def _sql(self, call, name, positions, check):
        """Why the SQL ``call`` runs writes -- or, for ``check`` "names", names -- an
        owned column; SQL whose text cannot be computed is counted, since it cannot
        be shown not to."""
        for index, keywords in positions:
            sql = _argument(call, index, keywords)
            if sql is None:
                continue
            values = None if sql is _UNKNOWN else self._values(sql, self.chain)
            if values is None:
                return f"{name}() of SQL that cannot be read statically"
            texts = list(_strings(values))
            if check == "names" and any(_NAMES_AN_OWNED_COLUMN.search(t) for t in texts):
                return f"{name}() of SQL naming a decision column"
            if check == "writes" and any(_SQL_WRITING_AN_OWNED_COLUMN.search(t) for t in texts):
                return "SQL writing a decision column"
        return None

    def _past_deployment_save(self, target):
        """What a ``.save()`` called on ``target`` goes round ``Deployment.save``
        through, or ``None`` for a save that goes through it (an instance's own)."""
        if isinstance(target, ast.Call) and isinstance(target.func, ast.Name) and target.func.id == "super":
            if target.args:
                # super(Deployment, dep): past Deployment's save to Model's.
                named = self._kind(target.args[0], self.chain)
                return None if named == _ANOTHER_MODEL else "super(...)"
            # super() in Deployment's own methods, but for the save itself.
            classes = [s.name for s in self.chain if isinstance(s, ast.ClassDef)]
            methods = [
                s.name for s in self.chain if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
            if classes[-1:] == ["Deployment"] and methods and methods[-1] != "save":
                return "super()"
            return None
        # Model.save(dep, ...): the base class's save, called on the instance.
        if isinstance(target, ast.Attribute):
            return "Model" if target.attr == "Model" else None
        if isinstance(target, ast.Name):
            found = self._lookup(target.id, self.chain)
            imported = found is not None and ("import", "Model") in found[1]
            return "Model" if target.id == "Model" or imported else None
        return None

    def why(self, call):
        """Why ``call`` writes a decision column the model cannot see, or ``None``."""
        name = _called(call)
        receiver = call.func.value if isinstance(call.func, ast.Attribute) else None
        if name in _UPDATES:
            # The columns a QuerySet's update writes are its keywords. A positional
            # argument is a dict's, set's or hash's update -- or an unbound
            # `QuerySet.update(qs, ...)`, whose keywords are read all the same.
            if self._writes_no_deployment(receiver, name):
                return None
            keys = _keys(call.keywords, self.passed_through[-1])
            if keys is None:
                return f"{name}(**...) with keys that cannot be resolved"
            owned = keys & DECISION_OWNED_FIELDS
            return f"{name}() of {sorted(owned)}" if owned else None
        if name in _PRIVATE_WRITES:
            if self._writes_no_deployment(receiver, name):
                return None
            return f"{name}(), which writes what it is handed"
        if name in _BULK_WRITES:
            if self._writes_no_deployment(receiver, name):
                return None
            why = _fields_write(call, *_BULK_WRITES[name])
            return why and f"{name}() with {why}"
        if name == "save_base":
            # Called on an instance, whatever its name: only its update_fields can
            # show it writes no owned column. Unbound -- `Model.save_base(dep, ...)`
            # -- the instance is the first argument.
            unbound = receiver is not None and self._past_deployment_save(receiver) == "Model"
            why = _fields_write(call, 4 + unbound, "update_fields", absent="every column")
            return why and f"save_base() of {why}, past Deployment.save"
        if name == "save" and receiver is not None:
            past = self._past_deployment_save(receiver)
            if past is None:
                return None
            why = _fields_write(call, 3 + (past == "Model"), "update_fields", absent="every column")
            return why and f"{past}.save() of {why}, past Deployment.save"
        if name == "getattr" and receiver is None and len(call.args) >= 2:
            return self._fetched("getattr()", call.args[0], call.args[1])
        if name in ("methodcaller", "attrgetter") and call.args:
            # The name of the method called, or of each attribute fetched (dotted:
            # every step): off what, the call does not say.
            named = call.args[:1] if name == "methodcaller" else call.args
            values = [self._values(a, self.chain) for a in named]
            if None in values:
                return f"{name}() of a name that cannot be read statically"
            written = sorted(
                {
                    step
                    for value in values
                    for text in _strings(value)
                    for step in text.split(".")
                    if step in _FETCHED_WRITES
                }
            )
            if not written:
                return None
            return f"{name}() of {written[0]}: what it is used on cannot be read"
        if self._calls_a_method_it_cannot_name(call.func, self.chain):
            return "a call of a method fetched by a name that cannot be read statically"
        if name in _RUN_SQL:
            # A migration may create or alter these columns in SQL; what no code may
            # do is write them.
            return self._sql(call, name, _RUN_SQL[name], "writes")
        if name in _ORM_SQL:
            return self._sql(call, name, _ORM_SQL[name], "writes" if self.migration else "names")
        return None

    def visit_Call(self, node):
        self.called.add(id(node.func))
        why = self.why(node)
        if why or _called(node) in _WRITE_SHAPED:
            self._site(node, why)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        if isinstance(node.ctx, ast.Load):
            if node.attr in _UPDATE_QUERIES:
                self._site(node, f"{node.attr}: an UPDATE built by hand")
            elif node.attr in _RAW_SAVES:
                self._site(node, _RAW_SAVE_WHY % node.attr)
            elif id(node) not in self.called:
                if node.attr in _WRITE_METHODS and not self._writes_no_deployment(node.value, node.attr):
                    why = "what it is called with cannot be read"
                    self._site(node, f"{node.attr} referenced, not called: {why}")
                elif node.attr in ("execute", "executemany", "executescript"):
                    why = "the SQL it runs cannot be read"
                    self._site(node, f"{node.attr} referenced, not called: {why}")
        self.generic_visit(node)

    def visit_Name(self, node):
        if isinstance(node.ctx, ast.Load) and node.id in _UPDATE_QUERIES:
            self._site(node, f"{node.id}: an UPDATE built by hand")
        elif isinstance(node.ctx, ast.Load) and node.id in _RAW_SAVES:
            self._site(node, _RAW_SAVE_WHY % node.id)

    def visit_Subscript(self, node):
        # A method fetched from a class's dict: `QuerySet.__dict__["update"]`.
        owner = _class_dict_of(node.value)
        if owner is not None:
            why = self._fetched("__dict__[...]", owner, node.slice)
            if why:
                self._site(node, why)
        self.generic_visit(node)


def _decision_writes(sources, *, migration=False):
    """Every write of a decision column in ``sources`` (``{path: source}``) that the
    model cannot see, as ``(path, qualified enclosing function, line, why)``.

    None of these sends a signal or reaches ``Deployment.save``, so they are held
    here, by reading the source:

    - ``update()``/``aupdate()`` whose keywords name an owned column, or whose ``**``
      keys cannot be read; ``bulk_update()``/``abulk_update()``, and a
      ``bulk_create()``/``abulk_create()`` upsert, naming one or hiding its fields;
      ``_update()``, ``_do_update()``, ``_save_table()``; and an ``UpdateQuery``;
    - any of those methods referenced without being called -- bound to a name,
      handed to ``functools.partial``, or fetched by a name the scan computes, as
      it computes SQL text, with ``getattr``, ``attrgetter`` or ``methodcaller`` or
      out of a class's ``__dict__`` -- since what it is finally called with cannot
      be read; and a method fetched by a name the scan cannot compute, where it is
      called, or by ``attrgetter``/``methodcaller`` at all;
    - ``deserialize`` and ``DeserializedObject``, wherever named: a deserialized
      object's ``save()`` is ``save_base(raw=True)``, for whatever model its data
      names;
    - a save that goes round ``Deployment.save``: ``save_base()``,
      ``Model.save(dep, ...)``, ``super(Deployment, dep).save()``, ``super().save()``
      in Deployment's other methods -- unless its ``update_fields`` provably name no
      owned column;
    - SQL run by ``execute()``/``executemany()``/``executescript()``/``RunSQL()``
      that writes an owned column, and SQL handed to ``raw()``/``RawSQL()`` that
      names one. The text is followed through module-level and local string names,
      concatenation, ``%``, ``.format``, f-strings and ``join``; text that cannot be
      computed is counted, since it cannot be shown not to write.

    A receiver proven not to be a Deployment's is let through: a dict or other
    container (or a name bound only to one, or a parameter whose name does not say
    queryset), and another model's queryset reached through queryset steps alone --
    an imported name being another model's only when the model registry holds it
    and it is not Deployment or a subclass or proxy of it. A
    ``**`` whose keys cannot be read is counted: it cannot be shown not to write.

    A write is let through by the comment ``# not-a-decision-writer: <reason>`` --
    for a proven false positive, with its reason -- on its own line: the line its
    method is named on, or the line its call ends on. A comment token, never text
    in a string; and one write per comment: on a line holding more than one call
    that writes, saves or runs SQL, the comment cannot say which it is for and
    clears none."""
    found = []
    for path, source in sorted(sources.items()):
        scan = _Scan(path, source, migration=migration, found=found)
        scan.visit(ast.parse(source))
        scan.finish()
    return found


def _tally(writes):
    return Counter((path, scope) for path, scope, _line, _why in writes)


def test_the_decision_columns_are_bulk_written_only_by_the_refresh():
    code, _migrations = _first_party_python()
    writes = _decision_writes(code)
    # Exactly one write in each: a second one inside an allowed function is a
    # second writer as surely as one anywhere else.
    assert _tally(writes) == _THE_REFRESH, writes


def test_no_migration_writes_the_decision_columns():
    """A migration adds and alters these columns; a data migration that wrote them
    would move the decision with no transition recorded."""
    _code, migrations = _first_party_python()
    assert migrations, "the scan found no migrations to check"
    assert _decision_writes(migrations, migration=True) == []


def test_the_one_writer_scan_reads_every_first_party_package():
    """Pinned so that narrowing the scan back to one package fails here, not
    silently: every installed app in this repository, and the project package
    beside them, which is not an app."""
    from django.apps import apps
    from django.conf import settings

    code, _migrations = _first_party_python()
    scanned = {path.split("/")[0] for path in code}
    ours = {
        relative.parts[0]
        for relative in (
            Path(app.path).resolve().relative_to(_REPO)
            for app in apps.get_app_configs()
            if Path(app.path).resolve().is_relative_to(_REPO)
        )
        if "site-packages" not in relative.parts
    }
    assert {"assurance", "failsafe", "audit"} <= ours <= scanned
    assert settings.ROOT_URLCONF.replace(".", "/") + ".py" in code
    assert not any(path.startswith("tests/") for path in code)


def test_the_one_writer_scan_leaves_out_tests_and_third_party_code(tmp_path):
    for path in (
        "manage.py",
        "app/models.py",
        "app/migrations/0001_initial.py",
        "tests/test_app.py",
        "node_modules/node-gyp/gyp/pylib/gyp/input.py",
        ".tox/py311/lib/x.py",
        "env/bin/activate_this.py",
        "env/lib/python3.11/site-packages/django/db/models/query.py",
        "app/vendor/site-packages/x.py",
    ):
        (tmp_path / path).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / path).write_text("x = 1\n")
    (tmp_path / "env" / "pyvenv.cfg").write_text("home = /usr/bin\n")

    code, migrations = _first_party_python(tmp_path)

    assert sorted(code) == ["app/models.py", "manage.py"]
    assert sorted(migrations) == ["app/migrations/0001_initial.py"]


def _parsed(source, path="failsafe/views.py", **kwargs):
    return [
        (scope, why)
        for _path, scope, _line, why in _decision_writes({path: textwrap.dedent(source)}, **kwargs)
    ]


@pytest.mark.parametrize(
    "source",
    [
        # Outside assurance/ -- the scan used to read one package.
        "def pause(i):\n    Deployment.objects.filter(pk=i).update(decision='ready')\n",
        # Keys hidden behind **: a variable, a computed key, a call.
        "def f(i):\n    fields = {'decision': 'ready'}\n    Deployment.objects.filter(pk=i).update(**fields)\n",
        "def f(i, k):\n    Deployment.objects.filter(pk=i).update(**{k: 'ready'})\n",
        "def f(i):\n    Deployment.objects.filter(pk=i).update(**{**base(), 'name': 'x'})\n",
        "def f(i):\n    Deployment.objects.filter(pk=i).update(*(), **fields())\n",
        # An unbound call: the queryset is positional, the columns are not.
        "def f(qs):\n    QuerySet.update(qs, decision='ready')\n",
        # ** handed on by something that is not itself an update: its callers'
        # keys are never read, so they are not known.
        "def set_fields(qs, **kwargs):\n    qs.update(**kwargs)\n",
        # ... or by an update that adds to it, rebinds it, or hands on more.
        "def update(self, **kwargs):\n    kwargs['decision'] = 'ready'\n    return super().update(**kwargs)\n",
        "def update(self, **kwargs):\n    kwargs = {'decision': 1}\n    return super().update(**kwargs)\n",
        "def update(self, **kwargs):\n    return super().update(**kwargs, **extra())\n",
        "def update(self, **kw):\n    return (lambda **kw: qs.update(**kw))(decision=1)\n",
        # Keys written out through ** literals.
        "def f(i):\n    Deployment.objects.filter(pk=i).update(**{'decision_revision': 9})\n",
        "def f(i):\n    Deployment.objects.filter(pk=i).update(**dict(decision_keyring='k'))\n",
        # bulk_update, named or hidden.
        "def f(rows):\n    Deployment.objects.bulk_update(rows, ['name', 'decision'])\n",
        "def f(rows):\n    Deployment.objects.bulk_update(rows, fields=('decision_revision',))\n",
        "def f(rows, cols):\n    Deployment.objects.bulk_update(rows, cols)\n",
        "def f(rows, opts):\n    Deployment.objects.bulk_update(rows, **opts)\n",
        "def f(args):\n    Deployment.objects.bulk_update(*args)\n",
        # bulk_create as an upsert.
        "def f(rows):\n    Deployment.objects.bulk_create(rows, update_conflicts=True,"
        " unique_fields=['id'], update_fields=['decision'])\n",
        "def f(rows, cols):\n    Deployment.objects.bulk_create(rows, update_conflicts=True, update_fields=cols)\n",
        "def f(rows, opts):\n    Deployment.objects.bulk_create(rows, **opts)\n",
        "def f(rows):\n    Deployment.objects.bulk_create(rows, None, False, True, ['decision'])\n",
        # Raw SQL naming the columns.
        "def f(c):\n    c.execute('UPDATE assurance_deployment SET decision = %s', ['ready'])\n",
        "def f(c, t):\n    c.cursor().executemany(f'update {t} set decision_revision = 1', [])\n",
        "def f():\n    return Deployment.objects.raw('SELECT id, decision FROM assurance_deployment')\n",
        "def f():\n    return Deployment.objects.annotate(d=RawSQL('decision_keyring', []))\n",
        # SQL kept in a constant and executed elsewhere.
        "SQL = 'UPDATE assurance_deployment SET decision_keyring = NULL'\ndef f(c):\n    c.execute(SQL)\n",
        "def f(c):\n    c.execute(Q)\nQ = '''INSERT INTO assurance_deployment (id, decision)\n VALUES (1, 2)'''\n",
    ],
)
def test_the_one_writer_scan_flags_each_way_round_it(source):
    # Once: a string counted as a raw call's SQL is not counted again.
    assert len(_parsed(source)) == 1, (source, _parsed(source))


def test_the_one_writer_scan_counts_a_second_write_inside_an_allowed_function():
    source = """
        def recompute_decision(deployment):
            accept_transition(deployment, to_decision=None)
            Deployment.objects.filter(pk=deployment.pk).update(decision_keyring="k")
            Deployment.objects.filter(pk=deployment.pk).update(decision="ready")
    """
    tally = _tally(_decision_writes({"assurance/decision.py": textwrap.dedent(source)}))
    assert tally == {("assurance/decision.py", "recompute_decision"): 2}
    assert tally != _THE_REFRESH


def test_the_one_writer_scan_names_the_scope_a_write_is_in():
    """A write in a method or a nested function is not the allowed function's."""
    source = """
        class Admin:
            def save(self, i):
                Deployment.objects.filter(pk=i).update(decision="ready")
        def recompute_decision(i):
            def inner():
                Deployment.objects.filter(pk=i).update(decision="ready")
        Deployment.objects.update(decision=None)
    """
    assert [scope for scope, _why in _parsed(source)] == [
        "Admin.save",
        "recompute_decision.inner",
        "<module>",
    ]


def test_a_migration_may_alter_the_columns_but_not_write_them():
    alters = """
        operations = [
            migrations.AddField(model_name="deployment", name="decision_keyring", field=None),
            migrations.RunSQL("ALTER TABLE assurance_deployment ALTER COLUMN decision DROP NOT NULL"),
        ]
    """
    assert _parsed(alters, "assurance/migrations/0099_x.py", migration=True) == []
    writes = """
        def backfill(apps, schema_editor):
            apps.get_model("assurance", "Deployment").objects.update(decision=None)
        operations = [migrations.RunSQL("UPDATE assurance_deployment SET decision = NULL")]
    """
    found = _parsed(writes, "assurance/migrations/0099_x.py", migration=True)
    assert found == [
        ("backfill", "update() of ['decision']"),
        ("<module>", "SQL writing a decision column"),
    ]


@pytest.mark.parametrize(
    "source",
    [
        # Not a QuerySet's update: dicts, sets and hashes take a positional.
        "def f(d, x):\n    d.update({'decision': x})\n    d.update(x)\n    h.update(b'decision')\n",
        # An update handing its own ** on untouched: its callers are read instead.
        "class V:\n    def update(self, request, *args, **kwargs):\n"
        "        return super().update(request, *args, **kwargs)\n",
        # QuerySet writes that name no decision column.
        "def f(i):\n    Deployment.objects.filter(pk=i).update(name='x', **{'description': 'y'})\n",
        "def f(i):\n    Deployment.objects.filter(pk=i).update(**dict(name='x'), **{**{'notes': 1}})\n",
        "def f(rows):\n    Asset.objects.bulk_update(rows, ['last_seen'])\n    Asset.objects.bulk_create(rows)\n",
        "def f(rows):\n    Asset.objects.bulk_create(rows, update_conflicts=True, update_fields=['name'])\n",
        "def f(rows):\n    Asset.objects.bulk_create(rows, update_fields=None)\n",
        # Columns that merely contain the word.
        "def f(c):\n    c.execute('UPDATE assurance_decisiontransition SET to_decision = %s', [1])\n",
        # Prose about the SQL, not SQL.
        'def f():\n    """An UPDATE that would SET the decision column."""\n',
    ],
)
def test_the_one_writer_scan_passes_what_writes_no_decision_column(source):
    assert _parsed(source) == [], source


#: Ways round the one writer the round-four review found the scan missing -- each
#: shown against the real ORM to write an owned column with no transition recorded.
#: Each must be flagged, and flagged once.
_WAYS_ROUND_IT_FOUND_IN_REVIEW = {
    "alias_bound_method": """
        def pause(i):
            write = Deployment.objects.filter(pk=i).update
            write(decision="paused")
    """,
    "getattr_update": """
        def pause(i):
            getattr(Deployment.objects.filter(pk=i), "update")(decision="paused")
    """,
    "functools_partial": """
        from functools import partial
        def pause(i):
            partial(Deployment.objects.filter(pk=i).update, decision="paused")()
    """,
    "save_base_update_fields": """
        def pause(dep):
            dep.decision = "paused"
            dep.save_base(update_fields=["decision"])
    """,
    "model_save_unbound": """
        from django.db import models
        def pause(dep):
            dep.decision = "paused"
            models.Model.save(dep, update_fields=["decision", "decision_revision"])
    """,
    "super_skip_save": """
        def pause(dep):
            dep.decision = "paused"
            super(Deployment, dep).save(update_fields=["decision"])
    """,
    "private_do_update": """
        def pause(i):
            Deployment.objects.filter(pk=i)._update({Deployment._meta.get_field("decision"): "paused"})
    """,
    "sql_concat_outside_call": """
        from django.db import connection
        def pause(i):
            sql = "UPDATE assurance_deployment SET " + "decision = %s WHERE id = %s"
            with connection.cursor() as c:
                c.execute(sql, ["paused", i])
    """,
    "sql_format_column_var": """
        from django.db import connection
        COLUMN = "decision"
        def pause(i):
            with connection.cursor() as c:
                c.execute("UPDATE assurance_deployment SET {} = %s WHERE id = %s".format(COLUMN), ["paused", i])
    """,
    "sql_fstring_column_var": """
        from django.db import connection
        def pause(i, col="decision"):
            with connection.cursor() as c:
                c.execute(f"UPDATE assurance_deployment SET {col} = %s WHERE id = %s", ["paused", i])
    """,
    "sql_via_quote_name": """
        from django.db import connection
        def pause(i):
            col = connection.ops.quote_name("decision")
            with connection.cursor() as c:
                c.execute("UPDATE assurance_deployment SET " + col + " = %s WHERE id = %s", ["paused", i])
    """,
    "helper_module_cursor": """
        from django.db import connection
        def run(sql, params):
            with connection.cursor() as c:
                c.execute(sql, params)
        def pause(i):
            run("UPDATE assurance_deployment SET %s = %%s WHERE id = %%s" % "decision", ["paused", i])
    """,
    "cursor_callproc_or_copy": """
        from django.db import connection
        def pause(i):
            with connection.cursor() as c:
                c.cursor.execute("UPDATE assurance_deployment SET decision='paused' WHERE id=%s" , [i])
    """,
    "update_from_setattr_loop": """
        def pause(i):
            dep = Deployment.objects.get(pk=i)
            for name in ("decision",):
                setattr(dep, name, "paused")
            Deployment.objects.bulk_update([dep], fields=[*("decision",)])
    """,
    "bulk_update_fields_from_constant": """
        FIELDS = ["decision"]
        def pause(dep):
            Deployment.objects.bulk_update([dep], FIELDS)
    """,
    "update_or_create_create_defaults": """
        def pause(i):
            Deployment.objects.filter(pk=i).update(**{"decision": "paused"})
    """,
    "F_expression": """
        from django.db.models import F, Value
        def pause(i):
            Deployment.objects.filter(pk=i).update(decision_revision=F("decision_revision") - 1)
    """,
    "case_when": """
        from django.db.models import Case, When, Value
        def pause(i):
            Deployment.objects.filter(pk=i).update(decision=Case(When(pk=i, then=Value("paused"))))
    """,
    "asyncio_aupdate": """
        async def pause(i):
            await Deployment.objects.filter(pk=i).aupdate(decision="paused")
    """,
    "abulk_update": """
        async def pause(rows):
            await Deployment.objects.abulk_update(rows, ["decision"])
    """,
    "abulk_create_upsert": """
        async def pause(rows):
            await Deployment.objects.abulk_create(rows, update_conflicts=True, unique_fields=["id"], update_fields=["decision"])
    """,
    "update_query_sql": """
        from django.db.models.sql import UpdateQuery
        def pause(i):
            q = UpdateQuery(Deployment)
            q.add_update_values({"decision": "paused"})
            q.add_filter("pk", i)
            q.get_compiler("default").execute_sql()
    """,
}

#: Ways round the one writer the round-five review found the scan missing. Each
#: must be flagged, and flagged once.
_WAYS_ROUND_IT_FOUND_IN_THE_LAST_REVIEW = {
    # getattr with the method's name held in a name, or assembled.
    "getattr_name_bound_to_update": """
        from assurance.models import Deployment
        def f(pk):
            method = "update"
            getattr(Deployment.objects.filter(pk=pk), method)(decision="ready")
    """,
    "getattr_assembled_name": """
        from assurance.models import Deployment
        def f(pk):
            getattr(Deployment.objects.filter(pk=pk), "up" + "date")(decision="ready")
    """,
    # A name no scan can compute: held where the method it fetches is called.
    "generic_dispatch_helper": """
        from assurance.models import Deployment
        def apply(queryset, op, **fields):
            return getattr(queryset, op)(**fields)
        def f(pk):
            apply(Deployment.objects.filter(pk=pk), "update", decision="ready")
    """,
    "operator_attrgetter": """
        from operator import attrgetter
        from assurance.models import Deployment
        def f(pk):
            attrgetter("update")(Deployment.objects.filter(pk=pk))(decision="ready")
    """,
    "class_dict_subscript": """
        from django.db.models import QuerySet
        from assurance.models import Deployment
        def f(pk):
            QuerySet.__dict__["update"](Deployment.objects.filter(pk=pk), decision="ready")
    """,
    "imported_proxy_model": """
        from assurance.proxies import Rollout  # class Rollout(Deployment): Meta.proxy = True
        def f(pk):
            Rollout.objects.filter(pk=pk).update(decision="ready")
    """,
    "imported_alias_of_deployment": """
        from assurance.aliases import AISystem  # aliases.py: AISystem = Deployment
        def f(pk):
            AISystem.objects.filter(pk=pk).update(decision="paused" and "ready")
    """,
    # DeserializedObject.save() is Model.save_base(raw=True), past Deployment.save.
    "deserialized_raw_save": """
        from django.core import serializers
        def restore(payload):
            for obj in serializers.deserialize("json", payload):
                obj.save()
    """,
}

#: A second write inside the refresh's own function, however it is dressed: the
#: tally must not come out as the refresh's one.
_SECOND_WRITES_IN_THE_REFRESH = {
    "second_write_in_allowed_via_helper": """
        def recompute_decision(deployment):
            accept_transition(deployment, to_decision=None)
            Deployment.objects.filter(pk=deployment.pk).update(decision_keyring="k")
            _also(deployment)
        def _also(d):
            write = Deployment.objects.filter(pk=d.pk).update
            write(decision="ready")
    """,
    "lambda_scope_in_allowed": """
        def recompute_decision(deployment):
            Deployment.objects.filter(pk=deployment.pk).update(decision_keyring="k")
            again = lambda: Deployment.objects.filter(pk=deployment.pk).update(decision="ready")
            again()
    """,
    "comprehension_scope_in_allowed": """
        def recompute_decision(deployment):
            Deployment.objects.filter(pk=deployment.pk).update(decision_keyring="k")
            [Deployment.objects.filter(pk=p).update(decision="ready") for p in (1,)]
    """,
}

#: Code the review found the scan flagging that writes no decision column.
_FLAGGED_BUT_NO_WRITE_FOUND_IN_REVIEW = {
    "dict_update_kwargs_decision": """
        def payload(dep):
            body = {"name": dep.name}
            body.update(decision=dep.decision, revision=dep.decision_revision)
            return body
    """,
    "dict_update_star_kwargs": """
        def build(**overrides):
            body = {"a": 1}
            body.update(**overrides)
            return body
    """,
    "select_raw_read_only": """
        def report(c):
            c.execute("SELECT decision, count(*) FROM assurance_deployment GROUP BY decision")
    """,
    "error_message_constant": """
        def refuse():
            raise ValueError("never UPDATE assurance_deployment SET decision by hand")
    """,
    "logging_constant": """
        import logging
        logger = logging.getLogger(__name__)
        def f():
            logger.warning("An UPDATE that SET decision directly is refused")
    """,
    "other_model_bulk_update": """
        def f(rows):
            Verdict.objects.bulk_update(rows, ["decision"])
    """,
    "span_update_decision": """
        def f(span, d):
            span.update(decision=d)
    """,
}


@pytest.mark.parametrize("name", sorted(_WAYS_ROUND_IT_FOUND_IN_REVIEW))
def test_the_one_writer_scan_flags_each_way_round_it_the_review_found(name):
    source = _WAYS_ROUND_IT_FOUND_IN_REVIEW[name]
    assert len(_parsed(source)) == 1, (name, _parsed(source))


@pytest.mark.parametrize("name", sorted(_WAYS_ROUND_IT_FOUND_IN_THE_LAST_REVIEW))
def test_the_one_writer_scan_flags_each_way_round_it_the_last_review_found(name):
    source = _WAYS_ROUND_IT_FOUND_IN_THE_LAST_REVIEW[name]
    assert len(_parsed(source)) == 1, (name, _parsed(source))


@pytest.mark.parametrize("name", sorted(_SECOND_WRITES_IN_THE_REFRESH))
def test_the_one_writer_scan_counts_a_second_write_the_refresh_reaches_however_it_is_dressed(name):
    source = textwrap.dedent(_SECOND_WRITES_IN_THE_REFRESH[name])
    tally = _tally(_decision_writes({"assurance/decision.py": source}))
    assert sum(tally.values()) == 2, tally
    assert tally[("assurance/decision.py", "recompute_decision")] >= 1
    assert tally != _THE_REFRESH


@pytest.mark.parametrize("name", sorted(_FLAGGED_BUT_NO_WRITE_FOUND_IN_REVIEW))
def test_the_one_writer_scan_passes_what_the_review_found_it_flagging(name):
    assert _parsed(_FLAGGED_BUT_NO_WRITE_FOUND_IN_REVIEW[name]) == []


@pytest.mark.parametrize(
    "source",
    [
        # A relation or a call that hands back an instance may reach a Deployment,
        # whatever the chain started from.
        "def f(owner):\n    owner.deployments.update(decision='ready')\n",
        "def f():\n    Finding.objects.get(pk=1).deployment.decision_transitions.update(decision=1)\n",
        # A parameter going by a queryset's name, or reached through a queryset step.
        "def f(span):\n    span.filter(pk=1).update(decision='ready')\n",
        "def f(deployments: QuerySet):\n    deployments.update(decision='ready')\n",
        # Names bound to a Deployment queryset, a Deployment imported under another
        # name, a model fetched by a name the scan cannot read.
        "def f():\n    qs = Deployment.objects.all()\n    qs.update(decision='ready')\n",
        "from assurance.models import Deployment as D\ndef f():\n    D.objects.update(decision='ready')\n",
        "def f(apps, name):\n    apps.get_model('assurance', name).objects.update(decision='ready')\n",
        "def f(apps):\n    apps.get_model('assurance.Deployment').objects.update(decision='ready')\n",
        # An import is another model's only if the model registry says so: a
        # re-export of Deployment (`AISystem = Deployment`), or a name no model
        # goes by, may be a Deployment whatever it is called.
        "from assurance.aliases import AISystem\ndef f(pk):\n"
        "    AISystem.objects.filter(pk=pk).update(decision='ready')\n",
        "from assurance.proxies import Rollout\ndef f(pk):\n"
        "    Rollout.objects.filter(pk=pk).update(decision='ready')\n",
        # A name bound to a container in one branch and a queryset in another.
        "def f(x):\n    rows = {} if x else Deployment.objects.all()\n    rows.update(decision=1)\n",
        "def f(x):\n    rows = {}\n    if x:\n        rows = Deployment.objects.all()\n"
        "    rows.update(decision=1)\n",
        # A queryset of the Deployment's own manager, and a private write.
        "class DeploymentQuerySet(QuerySet):\n"
        "    def pause(self):\n        return self.update(decision='paused')\n",
        "def f(x):\n    x._update({'decision': 1})\n",
        # Saves round Deployment.save.
        "from django.db.models import Model\ndef f(dep):\n    Model.save(dep)\n",
        "def f(dep, fields):\n    models.Model.save(dep, update_fields=fields)\n",
        "def f(dep):\n    super(type(dep), dep).save()\n",
        "class Deployment:\n    def pause(self):\n        super().save(update_fields=['decision'])\n",
        "def f(dep):\n    dep.save_base()\n",
        # SQL whose text the scan follows to a write, or cannot follow at all.
        "def f(c):\n    sql = 'UPDATE assurance_deployment SET '\n    sql += 'decision = 1'\n    c.execute(sql)\n",
        "def f(c):\n    c.execute(' '.join(['UPDATE assurance_deployment', 'SET decision = 1']))\n",
        "def f(c, x):\n    c.execute('SELECT 1' if x else 'UPDATE assurance_deployment SET decision = 1')\n",
        "def f(c):\n    for col in ('decision',):\n"
        "        c.execute(f'UPDATE assurance_deployment SET {col} = 1')\n",
        "from .sql import PAUSE\ndef f(c):\n    c.execute(PAUSE)\n",
        # A list of statements can be appended to wherever its name reaches.
        "def f(c):\n    parts = ['SELECT 1']\n    parts.append('UPDATE assurance_deployment SET decision = 1')\n"
        "    c.execute('; '.join(parts))\n",
        "def f(c):\n    c.execute(query='UPDATE assurance_deployment SET decision_keyring = NULL')\n",
        "def f(c, args):\n    c.execute(*args)\n",
        "operations = [RunSQL('SELECT 1', reverse_sql='UPDATE assurance_deployment SET decision = NULL')]\n",
        # A cursor's execute handed on, or fetched by name.
        "def f(c):\n    run = c.execute\n",
        "def f(c):\n    getattr(c, 'execute')('SELECT 1')\n",
        "def f(qs):\n    methodcaller('update', decision=1)(qs)\n",
        # A method fetched by a name the scan cannot compute, called -- through a
        # name bound to it, or out of a class's dict; methodcaller and attrgetter
        # of such a name at all; attrgetter of a dotted path to a write.
        "def f(qs, op):\n    write = getattr(qs, op)\n    write(decision=1)\n",
        "def f(qs, op):\n    QuerySet.__dict__[op](qs, decision=1)\n",
        "def f(qs, op):\n    write = QuerySet.__dict__[op]\n    write(qs, decision=1)\n",
        "def f(qs):\n    vars(QuerySet)['update'](qs, decision=1)\n",
        "def f(qs, op):\n    methodcaller(op, decision=1)(qs)\n",
        "def f(qs, op):\n    attrgetter(op)(qs)(decision=1)\n",
        "def f(model):\n    attrgetter('objects.update')(model)(decision=1)\n",
        "def f(model):\n    attrgetter('name', 'objects.update')(model)[1](decision=1)\n",
        # A deserialized object built by hand, and a deserializer imported bare.
        "from django.core.serializers.base import DeserializedObject\n"
        "def f(dep):\n    DeserializedObject(dep).save()\n",
        "from django.core.serializers import deserialize\n"
        "def f(p):\n    for obj in deserialize('json', p):\n        obj.save()\n",
    ],
)
def test_the_one_writer_scan_holds_what_it_cannot_prove_is_no_deployment_write(source):
    assert len(_parsed(source)) == 1, (source, _parsed(source))


@pytest.mark.parametrize(
    "source",
    [
        # Another model's queryset, however it is reached through queryset steps.
        "def f():\n    qs = Finding.objects.all()\n    qs.filter(pk=1).update(decision=1)\n",
        "from assurance.models import Finding\n"
        "def f():\n    Finding.objects.select_for_update().filter(pk=1).update(decision=1)\n",
        "def f(apps):\n    apps.get_model('assurance', 'Finding').objects.update(decision=1)\n",
        "def f(apps):\n    Model = apps.get_model('assurance', 'Finding')\n"
        "    Model.objects.bulk_update([], ['decision'])\n",
        # Containers and their copies.
        "def f(dep):\n    body = dict(name=dep.name)\n    body.copy().update(decision=dep.decision)\n",
        "def f(x):\n    rows = {} if x else set()\n    rows.update(decision=1)\n",
        # Saves that go through Deployment.save, or name no owned column.
        "def f(dep):\n    dep.save(update_fields=['name'])\n    Deployment.save(dep)\n",
        "class Deployment:\n    def save(self, update_fields=None):\n"
        "        super().save(update_fields=update_fields)\n",
        "class Finding:\n    def save(self, *args, **kwargs):\n"
        "        super(Finding, self).save(*args, **kwargs)\n",
        "def f(dep):\n    models.Model.save(dep, update_fields=['name'])\n"
        "    dep.save_base(update_fields=['name'])\n",
        # SQL the scan reads to the end and finds writing no owned column.
        "SQL = 'SELECT decision FROM assurance_deployment'\ndef f(c):\n    c.execute(SQL)\n",
        "def f(c):\n    c.execute('UPDATE assurance_deployment SET {} = 1'.format('name'))\n",
        "COL = 'name'\ndef f(c):\n    c.execute(f'UPDATE assurance_deployment SET {COL} = %s', [1])\n",
        "def f(c):\n    c.execute('UPDATE assurance_deployment SET %s = 1' % ('name',))\n",
        "def f(c):\n    c.execute(' '.join(('SELECT', 'decision', 'FROM assurance_deployment')))\n",
        "operations = [RunSQL(['SELECT 1', ('SELECT %s', [1])], reverse_sql=RunSQL.noop)]\n",
        # A value fetched by a name the scan cannot compute and never called; a
        # method it computes to be no write; another model's, whatever its name.
        "def f(claim, field, d):\n    value = getattr(claim, field)\n    return value == d[field]\n",
        "def f(owner, name):\n    return QuerySet.__dict__[name]\n",
        "def f(qs):\n    method = 'co' + 'unt'\n    return getattr(qs, method)()\n",
        "def f(op):\n    getattr(Finding.objects, op)(decision=1)\n",
        "def f(dep):\n    return attrgetter('name', 'owner.email')(dep)\n",
        "def f():\n    getattr(Finding.objects.all(), 'update')(decision=1)\n",
        # A name bound in an enclosing scope is read there, not where it is called.
        "def f(op):\n    rows = Finding.objects.all()\n    write = getattr(rows, op)\n"
        "    def g(rows):\n        write(decision=1)\n",
        "def f(qs):\n    op = 'count'\n    count = getattr(qs, op)\n"
        "    def g(op):\n        return count()\n",
    ],
)
def test_the_one_writer_scan_passes_what_it_proves_is_no_deployment_write(source):
    assert _parsed(source) == [], source


def test_an_imported_model_is_what_the_registry_says_it_is_not_what_it_is_called(monkeypatch):
    """A proxy of Deployment is registered under its own name, which need not say
    Deployment: imported, it is a Deployment, and its writes are held. Another
    registered model's are not."""

    class Rollout(Deployment):
        class Meta:
            apps = Apps()
            app_label = "assurance"
            proxy = True

    registered = django_apps.get_models()
    monkeypatch.setattr(django_apps, "get_models", lambda: [*registered, Rollout])
    write = "from assurance.proxies import {model}\ndef f(pk):\n    {model}.objects.update(decision=1)\n"

    assert len(_parsed(write.format(model="Rollout"))) == 1
    assert _parsed(write.format(model="Finding")) == []


def test_the_one_writer_scan_lets_through_a_line_marked_not_a_writer_with_its_reason():
    """For a proven false positive, on the one line, with the reason. A marker with
    no reason is not one."""
    flagged = "def f(x):\n    x.bulk_update([], ['decision'])\n"
    assert len(_parsed(flagged)) == 1
    marked = flagged.replace("])\n", "])  # not-a-decision-writer: x is a Verdict manager\n")
    assert _parsed(marked) == []
    bare = flagged.replace("])\n", "])  # not-a-decision-writer:\n")
    assert len(_parsed(bare)) == 1
    elsewhere = "# not-a-decision-writer: the next line\n" + flagged
    assert len(_parsed(elsewhere)) == 1


_CHAIN = """
    def f(pk):
        rows = (
            Deployment.objects{0}
            .filter(pk=pk)
            .update({1}
                decision="ready",
            ){2}
        )
"""
_ALLOWED = "  # not-a-decision-writer: a probe"


@pytest.mark.parametrize(
    ("where", "cleared"),
    [
        # The line a chain starts on names no write: a comment there is not beside it.
        ((_ALLOWED, "", ""), False),
        # The line its method is named on, and the line its call ends on, are its own.
        (("", _ALLOWED, ""), True),
        (("", "", _ALLOWED), True),
    ],
)
def test_an_allow_comment_clears_only_a_write_on_its_own_line(where, cleared):
    found = _parsed(_CHAIN.format(*where))
    assert found == ([] if cleared else [("f", "update() of ['decision']")]), found


@pytest.mark.parametrize(
    "line",
    [
        # One write flagged, beside a call that writes nothing it holds: which is
        # the comment for?
        "d.update(**{}); Deployment.objects.filter(pk=pk).update(decision='ready')",
        "d.save(); Deployment.objects.filter(pk=pk).update(decision='ready')",
        "Finding.objects.raw('SELECT 1'); Deployment.objects.update(decision='ready')",
        # Two writes flagged.
        "Deployment.objects.update(decision=1); Deployment.objects.update(decision=2)",
    ],
)
def test_one_allow_comment_clears_one_write_and_no_line_of_them(line):
    """One write per comment: on a line holding more than one call that writes,
    saves or runs SQL, the comment cannot say which it is for, and clears none."""
    bare = f"def f(pk, d):\n    {line}\n"
    marked = f"def f(pk, d):\n    {line}  # not-a-decision-writer: d is a dict\n"
    assert _parsed(bare) and _parsed(marked) == _parsed(bare)


def test_an_allow_comment_clears_the_write_on_its_line_and_no_other():
    source = (
        "def f(x):\n"
        "    x.bulk_update([], ['decision'])  # not-a-decision-writer: x is a Verdict manager\n"
        "    Deployment.objects.update(decision=1)\n"
    )
    assert _parsed(source) == [("f", "update() of ['decision']")]


def test_the_allow_marker_inside_a_string_is_not_an_allow_comment():
    source = (
        "def f(pk):\n    Deployment.objects.filter(pk=pk).update(decision='ready',"
        " decision_keyring='# not-a-decision-writer: x')\n"
    )
    assert len(_parsed(source)) == 1


def test_a_migration_is_held_to_what_its_sql_does_wherever_the_text_is_kept():
    """A migration may alter the columns in SQL, from a constant or not; it may not
    write them, however the statement is assembled."""
    alters = """
        COLUMN = "decision"
        operations = [
            migrations.RunSQL("ALTER TABLE assurance_deployment ALTER COLUMN %s DROP NOT NULL" % COLUMN),
        ]
    """
    assert _parsed(alters, "assurance/migrations/0099_x.py", migration=True) == []
    writes = """
        SQL = "UPDATE assurance_deployment SET " + "decision = NULL"
        def backfill(apps, schema_editor):
            schema_editor.execute(SQL)
        operations = [migrations.RunPython(backfill)]
    """
    assert _parsed(writes, "assurance/migrations/0099_x.py", migration=True) == [
        ("backfill", "SQL writing a decision column")
    ]


def test_a_transition_still_touches_updated_at():
    """The decision is written with a QuerySet update now, which ``auto_now`` does
    not reach; the list orders by ``updated_at``, so the write sets it itself."""
    dep = Deployment.objects.create(name="d", owner=_owner())
    earlier = timezone.now() - timedelta(hours=1)
    Deployment.objects.filter(pk=dep.pk).update(updated_at=earlier)

    accept_transition(dep, to_decision=D.READY)

    assert Deployment.objects.get(pk=dep.pk).updated_at > earlier
