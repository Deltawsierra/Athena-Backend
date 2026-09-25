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
"""

from __future__ import annotations

import logging
from datetime import timedelta

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


def _bulk_writes_of_the_decision_columns():
    """Every QuerySet ``update()`` / ``bulk_update()`` in ``assurance/`` that names a
    decision column, as (module, enclosing function). The model cannot see these --
    they send no signal and never reach ``Deployment.save`` -- so they are held
    here, by reading the source."""
    import ast
    from pathlib import Path

    root = Path(__file__).resolve().parent.parent / "assurance"
    found = set()

    class Visitor(ast.NodeVisitor):
        def __init__(self, module):
            self.module, self.stack = module, []

        def visit_FunctionDef(self, node):
            self.stack.append(node.name)
            self.generic_visit(node)
            self.stack.pop()

        visit_AsyncFunctionDef = visit_FunctionDef

        def visit_Call(self, node):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in {"update", "bulk_update"}:
                # A dict's `.update({...})` takes a positional mapping; a QuerySet's
                # never does.
                if not (node.args and isinstance(node.args[0], ast.Dict)):
                    named = {k.arg for k in node.keywords} | {
                        c.value
                        for c in ast.walk(node)
                        if isinstance(c, ast.Constant) and isinstance(c.value, str)
                    }
                    if named & DECISION_OWNED_FIELDS:
                        found.add((self.module, self.stack[-1] if self.stack else "<module>"))
            self.generic_visit(node)

    for path in sorted(root.rglob("*.py")):
        if "migrations" in path.parts:
            continue
        Visitor(path.name).visit(ast.parse(path.read_text()))
    return found


def test_the_decision_columns_are_bulk_written_only_by_the_refresh():
    assert _bulk_writes_of_the_decision_columns() == {
        # The decision and its revision, with the transition that records the move.
        ("revision.py", "_write"),
        # The keyring stamp, beside it and under the same lock.
        ("decision.py", "recompute_decision"),
    }


def test_a_transition_still_touches_updated_at():
    """The decision is written with a QuerySet update now, which ``auto_now`` does
    not reach; the list orders by ``updated_at``, so the write sets it itself."""
    dep = Deployment.objects.create(name="d", owner=_owner())
    earlier = timezone.now() - timedelta(hours=1)
    Deployment.objects.filter(pk=dep.pk).update(updated_at=earlier)

    accept_transition(dep, to_decision=D.READY)

    assert Deployment.objects.get(pk=dep.pk).updated_at > earlier
