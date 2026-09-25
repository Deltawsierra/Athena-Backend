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
import logging
import os
import re
import textwrap
from collections import Counter
from datetime import timedelta
from pathlib import Path

import pytest
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
#: A column named anywhere in a string handed to raw SQL.
_NAMES_AN_OWNED_COLUMN = re.compile(_OWNED, re.IGNORECASE)
#: SQL that writes a column, naming an owned one -- wherever the string is held,
#: since ``cursor.execute(SQL)`` runs a statement kept in a module constant.
_SQL_WRITING_AN_OWNED_COLUMN = re.compile(
    r"\b(?:UPDATE\b.*?\bSET|(?:INSERT|REPLACE|MERGE)\b.*?\bINTO|ON\s+CONFLICT)\b.*?" + _OWNED,
    re.IGNORECASE | re.DOTALL,
)
_RAW_SQL_CALLS = frozenset({"raw", "execute", "executemany", "executescript", "RawSQL", "RunSQL"})
#: Neither passed nor determinable: an argument hidden behind ``*args``/``**kwargs``.
_UNKNOWN = object()


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


def _argument(call, index, keyword):
    """The node passed as parameter ``keyword`` (positional ``index``); ``None`` if
    not passed, :data:`_UNKNOWN` if it may be hidden in ``*args``/``**kwargs``."""
    for passed in call.keywords:
        if passed.arg == keyword:
            return passed.value
    ahead = call.args[: index + 1]
    if any(isinstance(a, ast.Starred) for a in ahead):
        return _UNKNOWN
    if len(call.args) > index:
        return call.args[index]
    if any(passed.arg is None for passed in call.keywords):
        return _UNKNOWN
    return None


def _fields_write(call, index, keyword):
    """Why a ``bulk_update``/``bulk_create`` call's field list writes an owned
    column, or ``None``."""
    fields = _argument(call, index, keyword)
    if fields is None or (isinstance(fields, ast.Constant) and fields.value is None):
        # bulk_update's fields are required, so a call without them is not a
        # QuerySet's; bulk_create without update_fields is a plain INSERT.
        return None
    names = None if fields is _UNKNOWN else _names(fields)
    if names is None:
        return f"{keyword} that cannot be resolved"
    owned = names & DECISION_OWNED_FIELDS
    return f"{keyword} naming {sorted(owned)}" if owned else None


def _called(call):
    func = call.func
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)


def _why_it_writes_a_decision_column(call, *, migration, passed_through=None):
    """Why ``call`` writes a decision column the model cannot see, or ``None``."""
    name = _called(call)
    if name == "update":
        # The columns a QuerySet's update writes are its keywords. A positional
        # argument is a dict's, set's or hash's update -- or an unbound
        # `QuerySet.update(qs, ...)`, whose keywords are read all the same.
        keys = _keys(call.keywords, passed_through)
        if keys is None:
            return "update(**...) with keys that cannot be resolved"
        owned = keys & DECISION_OWNED_FIELDS
        return f"update() of {sorted(owned)}" if owned else None
    if name == "bulk_update":
        why = _fields_write(call, 1, "fields")
        return why and f"bulk_update() with {why}"
    if name == "bulk_create":
        # An upsert: rows that collide are UPDATEd with `update_fields`.
        why = _fields_write(call, 4, "update_fields")
        return why and f"bulk_create() with {why}"
    if name in _RAW_SQL_CALLS and not migration:
        # A migration may create or alter these columns in SQL; what it may not do
        # is write them, which the SQL-shape check below holds it to.
        strings = [
            c.value
            for c in ast.walk(call)
            if isinstance(c, ast.Constant) and isinstance(c.value, str)
        ]
        if any(_NAMES_AN_OWNED_COLUMN.search(s) for s in strings):
            return f"{name}() of SQL naming a decision column"
    return None


def _decision_writes(sources, *, migration=False):
    """Every write of a decision column in ``sources`` (``{path: source}``) that the
    model cannot see, as ``(path, qualified enclosing function, line, why)``.

    QuerySet ``update()``/``bulk_update()``, a ``bulk_create()`` upsert, raw SQL --
    none sends a signal or reaches ``Deployment.save``, so they are held here, by
    reading the source. A ``**`` whose keys cannot be read is counted as a write:
    it cannot be shown not to be one."""
    found = []

    class Visitor(ast.NodeVisitor):
        def __init__(self, path):
            self.path, self.scope, self.in_raw_sql = path, [], 0
            self.passed_through = [None]

        def _scoped(self, node):
            self.scope.append(node.name)
            self.passed_through.append(_passed_through(node))
            self.generic_visit(node)
            self.passed_through.pop()
            self.scope.pop()

        visit_FunctionDef = visit_AsyncFunctionDef = visit_ClassDef = _scoped

        def _found(self, node, why):
            found.append((self.path, ".".join(self.scope) or "<module>", node.lineno, why))

        def visit_Expr(self, node):
            # A docstring (or any bare string statement) is prose, not SQL.
            if not (isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)):
                self.generic_visit(node)

        def visit_Constant(self, node):
            if (
                not self.in_raw_sql
                and isinstance(node.value, str)
                and _SQL_WRITING_AN_OWNED_COLUMN.search(node.value)
            ):
                self._found(node, "SQL writing a decision column")

        def visit_Call(self, node):
            why = _why_it_writes_a_decision_column(
                node, migration=migration, passed_through=self.passed_through[-1]
            )
            if why:
                self._found(node, why)
            # A string counted as this call's SQL is not counted again on its own.
            raw_sql = bool(why) and _called(node) in _RAW_SQL_CALLS
            self.in_raw_sql += raw_sql
            self.generic_visit(node)
            self.in_raw_sql -= raw_sql

    for path, source in sorted(sources.items()):
        Visitor(path).visit(ast.parse(source))
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


def test_a_transition_still_touches_updated_at():
    """The decision is written with a QuerySet update now, which ``auto_now`` does
    not reach; the list orders by ``updated_at``, so the write sets it itself."""
    dep = Deployment.objects.create(name="d", owner=_owner())
    earlier = timezone.now() - timedelta(hours=1)
    Deployment.objects.filter(pk=dep.pk).update(updated_at=earlier)

    accept_transition(dep, to_decision=D.READY)

    assert Deployment.objects.get(pk=dep.pk).updated_at > earlier
