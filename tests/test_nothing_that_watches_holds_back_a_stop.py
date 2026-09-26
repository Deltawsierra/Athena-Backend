"""No latent-condition evaluation holds a lock a stop waits on (#105, round 3).

Round 2 moved the evaluation out of the revoke and after the commit -- into ONE
transaction over every condition. ``config/settings.py`` makes every transaction
``BEGIN IMMEDIATE``, which on SQLite is the database-wide write lock, so the
evaluation held it while it read every condition: a pause of any other deployment
took 1.5 seconds instead of 0.003 while a hundred conditions over three hundred tools
were read, and with fifteen hundred it outlasted the twenty-second busy timeout and
failed with "database is locked". A pause is a stop, and nothing may delay one.

Now each condition is read with no transaction open, and each outcome that changes
anything is written in its own short transaction, re-checked there; the ones that
change nothing but when they were read are recorded a batch at a time. A write's
own transaction reads no condition at all. And one evaluation is bounded: past its
budget the conditions it did not reach are recorded as not evaluated -- which the
decision reads as unread, not as still pending -- and read first next time.

The first test MEASURES it: a pause of an unrelated deployment made while an
evaluation of many conditions is halfway through, timed. It does not assert the
structure that should make it fast; it asserts that it is.
"""

from __future__ import annotations

import threading
import time

import pytest
from django.contrib.auth import get_user_model
from django.db import connection, transaction
from django.test import override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from assurance import latent
from assurance.claims import derive_claims
from assurance.decision import recompute_decision, refresh_stored_decisions
from assurance.latent import declare_condition, evaluate_conditions, withdraw_condition
from assurance.models import Asset, AssuranceClaim, DataBoundary, Deployment, LatentCondition

pytestmark = pytest.mark.django_db

User = get_user_model()
Kind = LatentCondition.Kind
State = LatentCondition.State
Status = AssuranceClaim.ClaimStatus

#: A pause alone takes a few milliseconds. Waiting on one condition's write is
#: milliseconds more; waiting on the evaluation is the length of the evaluation --
#: here held open for seconds on purpose, see the test.
PROMPT = 1.0


def _user():
    return User.objects.create_user(username=f"u{User.objects.count()}", password="x", role=User.Roles.ADMIN)


def _deployment(name, tools):
    dep = Deployment.objects.create(name=name, owner=_user())
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    DataBoundary.objects.create(
        deployment=dep, allowed_regions=["eu-west-1"], training_allowed=False, third_party_sharing_allowed=False
    )
    Asset.objects.bulk_create(
        [
            Asset(deployment=dep, kind=Asset.Kind.TOOL, name=f"tool-{i}", identifier=f"tool-{i}",
                  classification=Asset.Classification.KNOWN)
            for i in range(tools)
        ]
    )
    derive_claims(Deployment.objects.get(pk=dep.pk))
    recompute_decision(Deployment.objects.get(pk=dep.pk))
    return Deployment.objects.get(pk=dep.pk)


def _watched(dep, count):
    """``count`` declared conditions on ``dep``, none of them true."""
    claim = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk").first()
    now = timezone.now()
    LatentCondition.objects.bulk_create(
        [
            LatentCondition(
                deployment=dep, claim=claim, kind=Kind.ASSET_APPEARS, subject=f"exporter-{i}",
                description="the declared precondition", state=State.PENDING,
                baseline_observation="0 asset(s)", last_evaluated_at=now,
            )
            for i in range(count)
        ]
    )
    return claim


@pytest.mark.django_db(transaction=True)
def test_a_pause_of_another_deployment_during_an_evaluation_of_many_conditions_completes_promptly(monkeypatch):
    """The evaluation is stopped halfway through its conditions and held there until
    the pause of an unrelated deployment finishes, or five seconds pass. Holding
    the database-wide write lock while it reads -- as the one transaction did -- the
    pause cannot finish until the evaluation lets go: it takes the five seconds.
    Holding nothing while it reads, the pause takes what it takes alone."""
    x = _deployment("watched", tools=300)
    y = _deployment("unrelated", tools=1)
    _watched(x, 400)

    def pause_y():
        began = time.monotonic()
        recompute_decision(Deployment.objects.get(pk=y.pk), paused=True)
        took = time.monotonic() - began
        recompute_decision(Deployment.objects.get(pk=y.pk), paused=False)
        return took

    alone = min(pause_y() for _ in range(3))

    halfway, paused = threading.Event(), threading.Event()
    reads = {"before": 0, "after": 0}
    real = latent._OBSERVERS[Kind.ASSET_APPEARS]

    def observing(condition, deployment):
        reads["after" if paused.is_set() else "before"] += 1
        if reads["before"] == 200 and not halfway.is_set():
            halfway.set()
            paused.wait(timeout=5)
        return real(condition, deployment)

    monkeypatch.setitem(latent._OBSERVERS, Kind.ASSET_APPEARS, observing)
    out = {}

    def backstop():  # what every refreshing write of X schedules for after its commit
        try:
            began = time.monotonic()
            refresh_stored_decisions([x.pk])
            out["backstop"] = time.monotonic() - began
        except Exception as exc:  # noqa: BLE001 - reported by the assertion below
            out["backstop_error"] = exc
        finally:
            connection.close()

    started = timezone.now()
    evaluating = threading.Thread(target=backstop)
    evaluating.start()
    try:
        while not halfway.wait(timeout=0.05) and evaluating.is_alive():
            pass
        assert halfway.is_set(), f"the evaluation never reached its conditions: {out}"
        try:
            during = pause_y()
        finally:
            paused.set()
    finally:
        evaluating.join()

    assert "backstop_error" not in out, out
    assert during < PROMPT, (
        f"a pause of an unrelated deployment took {during:.3f}s during the evaluation of 400 "
        f"conditions over 300 tools, {alone:.3f}s alone: the evaluation held a lock it waited on"
    )
    assert reads["after"] > 0, "the pause did not land while the evaluation was reading"
    assert Deployment.objects.get(pk=y.pk).decision != Deployment.Decision.PAUSED  # lifted again
    # And the evaluation it did not wait on was whole: every condition read, and recorded.
    assert LatentCondition.objects.filter(deployment=x, state=State.PENDING, last_evaluated_at__gte=started).count() == 400


def _ready():
    dep = _deployment(f"d{Deployment.objects.count()}", tools=1)
    AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).update(status=Status.SUPPORTED)
    recompute_decision(dep)
    return Deployment.objects.get(pk=dep.pk)


def test_an_evaluation_past_its_budget_records_what_it_did_not_reach_as_not_evaluated():
    """Bounded work: a condition an evaluation did not reach is not one that still does
    not hold. It is recorded as not evaluated -- which holds the decision back as a
    precondition nobody can check -- and it is the first the next evaluation reads."""
    dep = _ready()
    _watched(dep, 3)
    first, second, third = LatentCondition.objects.filter(deployment=dep).order_by("pk")
    LatentCondition.objects.filter(pk__in=[first.pk, second.pk]).update(
        last_evaluated_at=timezone.now() - timezone.timedelta(days=2)
    )
    LatentCondition.objects.filter(pk=third.pk).update(last_evaluated_at=timezone.now() - timezone.timedelta(days=1))

    with override_settings(ASSURANCE_LATENT_EVALUATION_MAX_CONDITIONS=2):
        result = evaluate_conditions(Deployment.objects.get(pk=dep.pk))

    assert result["not_reached"] == [str(third.uuid)]
    assert result["still_pending_count"] == 2
    third.refresh_from_db()
    assert third.state == State.EVALUATION_FAILED and third.last_error.startswith("not reached")
    assert recompute_decision(Deployment.objects.get(pk=dep.pk)) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    # Read first next time -- the least recently read first -- and watched again.
    with override_settings(ASSURANCE_LATENT_EVALUATION_MAX_CONDITIONS=1):
        result = evaluate_conditions(Deployment.objects.get(pk=dep.pk))
    assert result["still_pending"] == [str(third.uuid)]
    assert result["not_reached"] == [str(first.uuid), str(second.uuid)]
    third.refresh_from_db()
    assert (third.state, third.last_error) == (State.PENDING, "")


def test_an_evaluation_out_of_time_reads_nothing_more_and_says_so():
    dep = _ready()
    _watched(dep, 2)

    with override_settings(ASSURANCE_LATENT_EVALUATION_SECONDS=0):
        result = evaluate_conditions(Deployment.objects.get(pk=dep.pk))

    assert result["not_reached_count"] == 2
    assert set(LatentCondition.objects.filter(deployment=dep).values_list("state", flat=True)) == {
        State.EVALUATION_FAILED
    }


def test_a_withdrawal_landing_while_a_condition_is_read_is_not_written_over(monkeypatch):
    """The reading is taken with no lock held, so a person may withdraw the condition
    meanwhile. The write re-reads it under the lock and leaves the withdrawal: firing
    a condition a person withdrew would hold a claim nobody is watching."""
    dep = _ready()
    claim = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk").first()
    condition = declare_condition(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter", description="d")
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="shadow-exporter", identifier="shadow-exporter",
        classification=Asset.Classification.KNOWN,
    )
    real = latent._OBSERVERS[Kind.ASSET_APPEARS]

    def withdrawn_meanwhile(read, deployment):
        withdraw_condition(LatentCondition.objects.get(pk=read.pk), note="not needed")
        return real(read, deployment)

    monkeypatch.setitem(latent._OBSERVERS, Kind.ASSET_APPEARS, withdrawn_meanwhile)
    result = evaluate_conditions(Deployment.objects.get(pk=dep.pk))

    assert result["fired_count"] == 0 and result["skipped"] == [str(condition.uuid)]
    condition.refresh_from_db()
    claim.refresh_from_db()
    assert condition.state == State.WITHDRAWN
    assert claim.status == Status.SUPPORTED


def test_an_earlier_reading_is_not_written_over_a_later_one():
    """Two evaluations of one deployment can overlap. The one that started later read
    later; what the earlier one read is not written over it."""
    dep = _ready()
    claim = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk").first()
    condition = declare_condition(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter", description="d")
    later = timezone.now() + timezone.timedelta(minutes=5)
    evaluate_conditions(Deployment.objects.get(pk=dep.pk), now=later)
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="shadow-exporter", identifier="shadow-exporter",
        classification=Asset.Classification.KNOWN,
    )
    stale = latent._Evaluation(Deployment.objects.get(pk=dep.pk), actor=None, now=later - timezone.timedelta(minutes=1))

    stale.evaluate_all([LatentCondition.objects.select_related("claim", "fired_requirement").get(pk=condition.pk)])

    assert stale.found["skipped"] == [str(condition.uuid)]
    condition.refresh_from_db()
    assert (condition.state, condition.last_evaluated_at) == (State.PENDING, later)


def _reads_inside_a_write(monkeypatch) -> list:
    """Every condition read while a transaction deeper than the test's own is open --
    inside a write's transaction -- by pk."""
    inside = []
    real = latent.observe
    depth = len(connection.atomic_blocks)

    def watching(condition, deployment):
        if len(connection.atomic_blocks) > depth:
            inside.append(condition.pk)
        return real(condition, deployment)

    monkeypatch.setattr(latent, "observe", watching)
    return inside


def _committed():
    """The write's transaction commits: the hooks it scheduled run, as they do before
    the response is sent. The writes before it committed too."""
    from django.test import TestCase

    earlier = list(connection.run_on_commit)
    del connection.run_on_commit[:]
    for _savepoints, callback, _robust in earlier:
        callback()
    return TestCase.captureOnCommitCallbacks(execute=True)


def test_a_boundary_write_reads_no_condition_in_its_own_transaction_and_fires_it_once_committed(monkeypatch):
    """The data boundary route evaluated its own deployment's conditions inside its
    transaction: every one read under the write lock it held."""
    dep = _ready()
    claim = AssuranceClaim.objects.get(
        deployment=dep, valid_to__isnull=True, claim_type=AssuranceClaim.ClaimType.DATA_BOUNDARY
    )
    condition = declare_condition(claim, kind=Kind.BOUNDARY_ALLOWS, subject="training", description="d")
    inside = _reads_inside_a_write(monkeypatch)
    client = APIClient()
    client.force_authenticate(user=_user())

    with _committed():
        written = client.patch(
            f"/api/assurance/deployments/{dep.uuid}/data-boundary/", {"training_allowed": True}, format="json"
        )

    assert written.status_code == 200, written.content
    assert inside == []
    condition.refresh_from_db()
    assert condition.state == State.FIRED


def test_the_invalidation_check_reads_no_condition_in_its_own_transaction(monkeypatch):
    dep = _ready()
    claim = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk").first()
    declare_condition(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter", description="d")
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="shadow-exporter", identifier="shadow-exporter",
        classification=Asset.Classification.KNOWN,
    )
    inside = _reads_inside_a_write(monkeypatch)
    client = APIClient()
    client.force_authenticate(user=_user())

    counts = client.post(f"/api/assurance/deployments/{dep.uuid}/check-invalidations/").json()

    assert counts["conditions_fired"] == 1
    assert inside == []
    assert Deployment.objects.get(pk=dep.pk).decision == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_a_scan_ingest_reads_no_condition_in_its_own_transaction(monkeypatch):
    from assurance import ingest
    from pentest.models import PentestScan

    dep = _ready()
    claim = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk").first()
    condition = declare_condition(claim, kind=Kind.ASSET_APPEARS, subject="shell", description="d")
    inside = _reads_inside_a_write(monkeypatch)
    scan = PentestScan.objects.create(
        user=dep.owner, target_url="https://a.example/bot", consent=True, status=PentestScan.STATUS_COMPLETED,
        engine_response={"findings": []},
        target_config={"agent": {"name": "assistant"}, "tools": [{"name": "shell", "permissions": ["exec"]}]},
    )

    with _committed():
        with transaction.atomic():
            ingest.ingest_scan(scan, deployment=dep)
            assert inside == []

    condition.refresh_from_db()
    assert condition.state == State.FIRED
