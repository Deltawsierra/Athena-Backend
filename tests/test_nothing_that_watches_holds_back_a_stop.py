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


# ---------------------------------------------------------------------------
# Round 4: a revoke waits on no backstop; a refused write is not asked again per
# condition; the asset graph is read before a write lock, never under it; and the
# guards on what an evaluation writes, each held by a test.
# ---------------------------------------------------------------------------


def test_a_revoke_answers_without_waiting_on_the_backstop(monkeypatch):
    """A revoke is a stop. It committed at once, and then its response waited on the
    after-commit refresh its claim's write scheduled -- the carry, every watch on the
    deployment evaluated, the route noted: 0.7 s with 5,000 watches, past the ten
    seconds of the evaluation's budget where the database refused its writes. Now it
    schedules none, and the decision it commits is current: it was recomputed in the
    revoke's own transaction."""
    from assurance import decision
    from assurance.decision import decision_support

    dep = _ready()
    _watched(dep, 5)
    revoked = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("-pk").first()
    with _committed():
        pass  # what the set-up scheduled runs first
    refreshed = []
    real = decision.refresh_stored_decisions

    def counted(ids):
        refreshed.append(list(ids))
        return real(ids)

    monkeypatch.setattr(decision, "refresh_stored_decisions", counted)
    client = APIClient()
    client.force_authenticate(user=_user())

    with _committed():
        response = client.post(f"/api/assurance/claims/{revoked.uuid}/transition/", {"to_status": "revoked"}, format="json")

    assert response.status_code == 200, response.content
    assert AssuranceClaim.objects.get(pk=revoked.pk).status == Status.REVOKED
    assert refreshed == [], "the revoke's response waited on the after-commit backstop"
    stored = Deployment.objects.get(pk=dep.pk)
    assert stored.decision == decision_support(Deployment.objects.get(pk=dep.pk))["decision"]


def _refusing_writes(monkeypatch, *, refused=None, first=None) -> list:
    """Every transaction :mod:`assurance.latent` opens, counted -- and refused, as a
    database locked past its busy timeout refuses it: the ones numbered in
    ``refused`` (from 1), or every one when it is None. ``first``: an error the
    first one raises instead."""
    import types

    from django.db import OperationalError
    from django.db import transaction as real

    calls = []

    def atomic(*args, **kwargs):
        calls.append(len(calls) + 1)
        if first is not None and calls[-1] == 1:
            raise first
        if refused is None or calls[-1] in refused:
            raise OperationalError("database is locked")
        return real.atomic(*args, **kwargs)

    monkeypatch.setattr(latent, "transaction", types.SimpleNamespace(atomic=atomic))
    return calls


def _thirty_watched_one_true(dep, *, true):
    """Thirty watches on ``dep``, read in pk order; the eleventh true when ``true``."""
    _watched(dep, 30)
    LatentCondition.objects.filter(deployment=dep).update(last_evaluated_at=None)
    if true:
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.TOOL, name="exporter-10", identifier="exporter-10",
            classification=Asset.Classification.KNOWN,
        )


@pytest.mark.parametrize("true", [True, False], ids=["a-firing-refused", "a-batch-of-unchanged-refused"])
def test_a_database_that_refuses_a_write_is_not_asked_again_for_each_condition(monkeypatch, true):
    """Each condition whose write the database refused was recorded as failed in a
    write of its own, and each of those waited out the busy timeout again, outside
    the evaluation's budget: sixty watches took 30.8 s against a half-second timeout
    (about twenty minutes at the production twenty seconds), inside the request of
    the write it followed. Now the first refusal ends the writing: what was refused,
    and everything after it, is recorded in ONE write -- two waits, however many
    watches."""
    dep = _ready()
    _thirty_watched_one_true(dep, true=true)
    calls = _refusing_writes(monkeypatch)

    result = evaluate_conditions(Deployment.objects.get(pk=dep.pk))

    assert len(calls) == 2, f"{len(calls)} writes asked of a database that refused the first"
    assert result["not_reached_count"] == 30 and result["fired_count"] == 0
    # Nothing could be written: the rows stand as they were, and the next evaluation
    # reads them first.
    assert set(LatentCondition.objects.filter(deployment=dep).values_list("state", flat=True)) == {State.PENDING}


def test_after_a_refused_write_no_other_condition_is_read_or_written(monkeypatch):
    """The refusal ends the evaluation, not only its batch: a second watch that holds,
    read after it, tried a write of its own and waited out the busy timeout again."""
    dep = _ready()
    _thirty_watched_one_true(dep, true=True)
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="exporter-20", identifier="exporter-20",
        classification=Asset.Classification.KNOWN,
    )
    read = []
    real = latent.observe

    def counting(condition, deployment):
        read.append(condition.subject)
        return real(condition, deployment)

    monkeypatch.setattr(latent, "observe", counting)
    calls = _refusing_writes(monkeypatch)

    result = evaluate_conditions(Deployment.objects.get(pk=dep.pk))

    assert read == [f"exporter-{i}" for i in range(11)], "a condition was read after the refusal"
    assert len(calls) == 2
    assert result["not_reached_count"] == 30


def test_a_database_that_refuses_the_record_of_a_failure_is_not_asked_again_for_each_condition(monkeypatch):
    """A batch whose write failed for another reason is recorded as failed a condition
    at a time; the database refusing that record ends it as a refused write does."""
    from django.db import DatabaseError

    dep = _ready()
    _thirty_watched_one_true(dep, true=False)
    calls = _refusing_writes(monkeypatch, first=DatabaseError("the batch could not be written"))

    evaluate_conditions(Deployment.objects.get(pk=dep.pk))

    # The batch, the first failure's record (refused), and one record of the rest.
    assert len(calls) == 3, f"{len(calls)} writes asked of a database that refused a record"


@pytest.mark.parametrize("true", [True, False], ids=["a-firing-refused", "a-batch-of-unchanged-refused"])
def test_what_an_evaluation_could_not_write_is_recorded_as_not_evaluated_and_holds_the_decision_back(
    monkeypatch, true
):
    """Refused once, then the lock is let go: every condition the evaluation did not
    write -- the one refused, the batch it took with it, the ones never read -- is
    recorded as not evaluated, which the decision reads as a precondition nobody can
    check. They stood PENDING, read as watched and not true: a watch the write had
    just made true among them."""
    dep = _ready()
    _thirty_watched_one_true(dep, true=true)
    calls = _refusing_writes(monkeypatch, refused={1})

    evaluate_conditions(Deployment.objects.get(pk=dep.pk))

    assert len(calls) == 2
    rows = LatentCondition.objects.filter(deployment=dep)
    assert set(rows.values_list("state", flat=True)) == {State.EVALUATION_FAILED}
    assert all(error.startswith("not evaluated: the database refused a write") for error in rows.values_list("last_error", flat=True))
    monkeypatch.undo()
    assert recompute_decision(Deployment.objects.get(pk=dep.pk)) == Deployment.Decision.NEEDS_MORE_EVIDENCE
    # Read first next time, and watched again -- or fired, the one that holds.
    evaluate_conditions(Deployment.objects.get(pk=dep.pk))
    assert rows.filter(state=State.FIRED).count() == (1 if true else 0)
    assert rows.filter(state=State.PENDING).count() == (29 if true else 30)


def test_the_carry_asks_a_database_that_refused_a_write_for_no_other_watch(monkeypatch):
    """converge carries each watch a release that did not carry left on a closed
    version in a transaction of its own. Refused once, it asked again for every other
    watch, each waiting out the busy timeout. It stops at the first refusal; the rest
    stay where they are for the next refresh."""
    from assurance.latent import carry_conditions_to_current

    dep = _ready()
    claim = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk").first()
    for i in range(3):
        declare_condition(claim, kind=Kind.ASSET_APPEARS, subject=f"exporter-{i}", description="d")
    # A re-derive of a release that did not carry: a new version, the watches left behind.
    AssuranceClaim.objects.filter(pk=claim.pk).update(valid_to=timezone.now(), status=Status.SUPERSEDED)
    new = AssuranceClaim.objects.create(
        deployment=dep, claim_type=claim.claim_type, statement=claim.statement, fingerprint=claim.fingerprint,
        system_fingerprint="moved", policy_version=claim.policy_version, environment=dep.environment,
        status=Status.SUPPORTED,
    )
    AssuranceClaim.objects.filter(pk=claim.pk).update(superseded_by=new)
    calls = _refusing_writes(monkeypatch)

    assert carry_conditions_to_current(Deployment.objects.get(pk=dep.pk)) == 0
    assert len(calls) == 1
    assert LatentCondition.objects.filter(deployment=dep, claim=claim).count() == 3


def test_putting_back_holds_asks_a_database_that_refused_a_write_for_no_other_hold(monkeypatch):
    """The same for the holds converge puts back, one claim at a time."""
    from assurance.latent import restore_fired_holds
    from assurance.models import RetestRequirement

    dep = _ready()
    claims = list(AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk"))
    assert len(claims) >= 2
    for i, claim in enumerate(claims):
        declare_condition(claim, kind=Kind.ASSET_APPEARS, subject=f"exporter-{i}", description="d")
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.TOOL, name=f"exporter-{i}", identifier=f"exporter-{i}",
            classification=Asset.Classification.KNOWN,
        )
    assert evaluate_conditions(Deployment.objects.get(pk=dep.pk))["fired_count"] == len(claims)
    AssuranceClaim.objects.filter(pk__in=[c.pk for c in claims]).update(status=Status.SUPPORTED)
    RetestRequirement.objects.filter(deployment=dep).update(resolved_at=timezone.now())
    calls = _refusing_writes(monkeypatch)

    assert restore_fired_holds(Deployment.objects.get(pk=dep.pk)) == 0
    assert len(calls) == 1


def _graph_reads_under_a_write(monkeypatch) -> list:
    """Each read of the whole asset graph (the system fingerprint) from here on:
    whether a transaction deeper than the test's own was open when it was taken."""
    from assurance import fingerprint

    reads = []
    real = fingerprint.compute_system_fingerprint
    depth = len(connection.atomic_blocks)

    def watching(deployment):
        reads.append(len(connection.atomic_blocks) > depth)
        return real(deployment)

    monkeypatch.setattr(fingerprint, "compute_system_fingerprint", watching)
    return reads


def _shadow_watched(dep):
    claim = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk").first()
    condition = declare_condition(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter", description="d")
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="shadow-exporter", identifier="shadow-exporter",
        classification=Asset.Classification.KNOWN,
    )
    return claim, condition


def test_a_firing_reads_the_asset_graph_before_its_write_lock(monkeypatch):
    """A firing opens a retest bound to the system fingerprint, and read under the
    firing's write lock -- SQLite's database-wide one -- the graph held a pause of any
    other deployment for 0.15 s at 300 tools and 0.42 s at 3,000."""
    dep = _ready()
    _shadow_watched(dep)
    reads = _graph_reads_under_a_write(monkeypatch)

    assert evaluate_conditions(Deployment.objects.get(pk=dep.pk))["fired_count"] == 1
    assert reads == [False]


@pytest.mark.parametrize("path", ["an-evaluation", "the-carry"])
def test_a_hold_put_back_reads_the_asset_graph_before_its_write_lock(monkeypatch, path):
    """A FIRED condition whose hold something lifted -- the claim read back to a pass,
    its retest resolved -- is put back with a retest bound to the system fingerprint:
    by an evaluation that finds it still true, and by the carry (converge), 0.29 s
    under the lock at 3,000 tools."""
    from assurance.latent import restore_fired_holds
    from assurance.models import RetestRequirement

    dep = _ready()
    claim, _condition = _shadow_watched(dep)
    assert evaluate_conditions(Deployment.objects.get(pk=dep.pk))["fired_count"] == 1
    AssuranceClaim.objects.filter(pk=claim.pk).update(status=Status.SUPPORTED)
    RetestRequirement.objects.filter(deployment=dep).update(resolved_at=timezone.now())
    reads = _graph_reads_under_a_write(monkeypatch)

    if path == "the-carry":
        assert restore_fired_holds(Deployment.objects.get(pk=dep.pk)) == 1
    else:
        assert evaluate_conditions(Deployment.objects.get(pk=dep.pk))["still_fired_count"] == 1
    assert reads == [False]
    assert AssuranceClaim.objects.get(pk=claim.pk).status == Status.STALE
    assert RetestRequirement.objects.filter(deployment=dep, resolved_at__isnull=True).exists()


def test_a_batch_of_unchanged_readings_is_not_written_over_a_later_reading():
    """Unchanged readings are written a batch at a time, after they were taken; an
    evaluation that started later may have read the condition since. Its reading
    stands."""
    dep = _ready()
    claim = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk").first()
    condition = declare_condition(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter", description="d")
    later = timezone.now()
    run = latent._Evaluation(Deployment.objects.get(pk=dep.pk), actor=None, now=later - timezone.timedelta(seconds=5))
    run._unchanged.append((LatentCondition.objects.get(pk=condition.pk), latent._Reading(holds=False, observation="0")))
    LatentCondition.objects.filter(pk=condition.pk).update(last_evaluated_at=later)  # a later evaluation's reading

    run._touch()

    assert LatentCondition.objects.get(pk=condition.pk).last_evaluated_at == later
    assert run.found["skipped"] == [str(condition.uuid)]


def test_a_batch_of_unchanged_readings_is_not_written_over_a_condition_that_moved_since():
    """Read PENDING and not true; fired meanwhile by another evaluation. The batch
    writes when it was read only where the row still stands as it was read."""
    dep = _ready()
    claim = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk").first()
    condition = declare_condition(claim, kind=Kind.ASSET_APPEARS, subject="shadow-exporter", description="d")
    run = latent._Evaluation(Deployment.objects.get(pk=dep.pk), actor=None, now=timezone.now())
    run._unchanged.append((LatentCondition.objects.get(pk=condition.pk), latent._Reading(holds=False, observation="0")))
    LatentCondition.objects.filter(pk=condition.pk).update(state=State.FIRED, last_evaluated_at=None)

    run._touch()

    assert LatentCondition.objects.get(pk=condition.pk).last_evaluated_at is None
    assert run.found["skipped"] == [str(condition.uuid)]


def test_a_claim_revoked_between_the_reading_and_the_write_is_not_fired_on(monkeypatch):
    """A person revokes the claim while its condition is read, with no lock held. The
    write re-reads it under the lock and fires nothing on a claim taken out of scope."""
    from assurance.models import RetestRequirement

    dep = _ready()
    claim, condition = _shadow_watched(dep)
    read = latent._Reading.of.__func__

    def read_then_revoked(cls, condition, deployment):
        reading = read(cls, condition, deployment)
        AssuranceClaim.objects.filter(pk=condition.claim_id).update(status=Status.REVOKED)  # a stop, meanwhile
        return reading

    monkeypatch.setattr(latent._Reading, "of", classmethod(read_then_revoked))
    result = evaluate_conditions(Deployment.objects.get(pk=dep.pk))

    assert result["fired_count"] == 0 and result["skipped"] == [str(condition.uuid)]
    assert LatentCondition.objects.get(pk=condition.pk).state == State.PENDING
    assert not RetestRequirement.objects.filter(claim=claim).exists()
    assert AssuranceClaim.objects.get(pk=claim.pk).status == Status.REVOKED


def test_one_write_that_makes_three_watches_true_evaluates_them_once(monkeypatch):
    """The refresh a write schedules evaluates the watches with its own writes
    deferred: the firings it writes schedule no refresh of their own. Without that,
    each wrote another refresh that evaluated every watch again."""
    dep = _ready()
    claim = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk").first()
    for i in range(3):
        declare_condition(claim, kind=Kind.ASSET_APPEARS, subject=f"exporter-{i}", description="d")
    with _committed():
        pass  # what the set-up scheduled runs first
    calls = []
    real = latent.evaluate_conditions

    def counted(*args, **kwargs):
        calls.append(1)
        return real(*args, **kwargs)

    monkeypatch.setattr(latent, "evaluate_conditions", counted)
    with _committed():
        with transaction.atomic():
            for i in range(3):
                Asset.objects.create(
                    deployment=dep, kind=Asset.Kind.TOOL, name=f"exporter-{i}", identifier=f"exporter-{i}",
                    classification=Asset.Classification.KNOWN,
                )

    assert LatentCondition.objects.filter(deployment=dep, state=State.FIRED).count() == 3
    assert len(calls) == 1, f"{len(calls)} evaluations for one write"
