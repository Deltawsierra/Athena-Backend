"""A decision the release before recomputed is stamped as this release's only by a
recompute that read the watches after it -- never by one that did not.

The release before evaluates no watch. A tool it records that a watch here names
leaves the watch PENDING, and its recompute after, to the same READY, rewrites the
keyring column bare: that is how this release recognises the row as not its own, and
the first publishing read brings it current and reads the watches. But every other
recompute stamped such a row as this release's without reading them -- a revoke, the
recompute route (a pause and its lift among them), the first read after an accepted
risk lapsed, ``manage.py recompute_chain_decisions`` -- and after that no read and no
``migrate`` recognised it again: READY on every surface, the watch never read, until
the next write of this release's. And the first read itself stamped the row before
the watches were read, so an evaluation the database refused, or a recompute of the
release before landing between the reading and the stamp, left it stamped for good.

Each test here runs a write's commit hooks as a commit runs them, once
(``tests.test_latent_conditions_in_production._committed``).
"""

from __future__ import annotations

import datetime

import pytest
from django.utils import timezone

from assurance import signals
from assurance.decision import current_decision, decision_support, recompute_decision, stamped_in_force
from assurance.models import Asset, AssuranceClaim, Deployment, Finding, LatentCondition
from tests.test_latent_conditions_in_production import (
    Kind,
    State,
    _claim,
    _client,
    _committed,
    _declare,
    _decided_by_the_release_before,
    _derived_ready,
    _recomputed_by_the_release_before,
)

pytestmark = pytest.mark.django_db
D = Deployment.Decision


def _the_release_before_makes_the_watch_true(dep):
    """The release before records a tool a watch here names -- it evaluates no watch --
    and recomputes to the same READY under its rules: the keyring column rewritten
    bare, the revision and the stamp where they were."""
    with signals.refresh_deferred(dep.pk):  # the release before's write: no refresh of this release's
        Asset.objects.create(
            deployment=dep, kind=Asset.Kind.TOOL, name="shadow-exporter", identifier="shadow-exporter",
            classification=Asset.Classification.KNOWN, assessed_at=timezone.now(),
        )
    _recomputed_by_the_release_before(dep)


def _watched(dep):
    condition = _declare(_claim(dep), kind=Kind.ASSET_APPEARS, subject="shadow-exporter")
    with _committed():
        pass  # what the set-up scheduled runs first
    return condition


def _published_after_the_next_read(dep, condition):
    """The next publishing read, what it schedules run; then what every surface
    publishes, what decision support computes, and the watch."""
    with _committed():
        current_decision(Deployment.objects.get(pk=dep.pk))
    published = current_decision(Deployment.objects.get(pk=dep.pk))
    support = decision_support(Deployment.objects.get(pk=dep.pk))["decision"]
    return published, support, LatentCondition.objects.get(pk=condition.pk).state


def test_the_first_read_of_another_releases_decision_reads_the_watch_it_made_true():
    dep = _derived_ready()
    condition = _watched(dep)
    _the_release_before_makes_the_watch_true(dep)

    published, support, state = _published_after_the_next_read(dep, condition)

    assert (published, support, state) == (D.NEEDS_MORE_EVIDENCE, D.NEEDS_MORE_EVIDENCE, State.FIRED)
    assert stamped_in_force(Deployment.objects.get(pk=dep.pk))


def test_the_first_read_outside_a_transaction_publishes_what_the_refresh_it_ran_found(monkeypatch):
    """Outside a transaction -- production's autocommit -- the refresh the first read
    schedules runs at once, before the read returns, and fires the watch. The read
    publishes what that refresh left, not the READY it recomputed before it."""
    dep = _derived_ready()
    condition = _watched(dep)
    _the_release_before_makes_the_watch_true(dep)
    # As `schedule_decision_refresh` does with no transaction open: the hook runs now.
    monkeypatch.setattr(
        signals, "schedule_decision_refresh", lambda pk, **kwargs: signals._RefreshAfterCommit(pk, None)()
    )

    first = current_decision(Deployment.objects.get(pk=dep.pk))

    assert LatentCondition.objects.get(pk=condition.pk).state == State.FIRED
    assert first == D.NEEDS_MORE_EVIDENCE


def test_a_revoke_leaves_another_releases_decision_for_the_read_that_reads_its_watches():
    """The revoke recomputes in its own transaction and schedules no backstop, so it
    reads no watch; its recompute stamped the row, and no read recognised it again."""
    dep = _derived_ready()
    condition = _watched(dep)
    other = (
        AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True)
        .exclude(pk=condition.claim_id)
        .order_by("pk")
        .first()
    )
    _the_release_before_makes_the_watch_true(dep)

    with _committed():
        response = _client().post(
            f"/api/assurance/claims/{other.uuid}/transition/", {"to_status": "revoked"}, format="json"
        )
    assert response.status_code == 200, response.content
    assert LatentCondition.objects.get(pk=condition.pk).state == State.PENDING  # the revoke read no watch
    assert not stamped_in_force(Deployment.objects.get(pk=dep.pk))

    published, support, state = _published_after_the_next_read(dep, condition)

    assert (published, support, state) == (D.NEEDS_MORE_EVIDENCE, D.NEEDS_MORE_EVIDENCE, State.FIRED)


@pytest.mark.parametrize("body", [{}, {"paused": True}], ids=["a-recompute", "a-pause-then-its-lift"])
def test_the_recompute_route_leaves_another_releases_decision_for_the_read_that_reads_its_watches(body):
    dep = _derived_ready()
    condition = _watched(dep)
    _the_release_before_makes_the_watch_true(dep)
    client = _client()

    with _committed():
        response = client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", body, format="json")
    assert response.status_code == 200, response.content
    if body:
        assert current_decision(Deployment.objects.get(pk=dep.pk)) == D.PAUSED  # the pause, as it stands
        with _committed():
            response = client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": False}, format="json")
        assert response.status_code == 200, response.content
    assert not stamped_in_force(Deployment.objects.get(pk=dep.pk))

    published, support, state = _published_after_the_next_read(dep, condition)

    assert (published, support, state) == (D.NEEDS_MORE_EVIDENCE, D.NEEDS_MORE_EVIDENCE, State.FIRED)


def test_the_first_read_after_an_acceptance_lapsed_still_brings_another_releases_decision_current(monkeypatch):
    """The lapse was read before the stamp: the first read after an acceptance's end
    recomputed -- and stamped -- the release before's READY without reading the watch
    that release made true."""
    dep = _derived_ready()
    condition = _watched(dep)
    finding = Finding.objects.create(
        deployment=dep, fingerprint="fp-low-lapse", finding_type="t", title="T", severity="low",
        status=Finding.Status.ACCEPTED, risk_accepted_until=timezone.now() + datetime.timedelta(hours=1),
        risk_accepted_severity="low",
    )
    with _committed():
        pass
    row = Deployment.objects.get(pk=dep.pk)
    assert row.decision == D.READY_RESTRICTED and row.decision_valid_until is not None
    # The release before: the finding closed, a tool a watch names recorded, READY
    # decided under its rules -- the revision moved, the keyring column bare.
    Finding.objects.filter(pk=finding.pk).update(status=Finding.Status.CLOSED)
    _the_release_before_makes_the_watch_true(dep)
    _decided_by_the_release_before(dep, D.READY)
    later = timezone.now() + datetime.timedelta(hours=2)
    monkeypatch.setattr(timezone, "now", lambda: later)  # the acceptance's end has passed

    published, support, state = _published_after_the_next_read(dep, condition)

    assert (published, support, state) == (D.NEEDS_MORE_EVIDENCE, D.NEEDS_MORE_EVIDENCE, State.FIRED)
    assert stamped_in_force(Deployment.objects.get(pk=dep.pk))


def test_recompute_chain_decisions_leaves_another_releases_decision_for_the_read_that_reads_its_watches():
    import io

    from django.core.management import call_command

    from assurance.composition import HELD
    from assurance.models import WorkflowChainOutcome

    dep = _derived_ready()
    WorkflowChainOutcome.objects.create(
        deployment=dep, workflow="silent", status=HELD, observed_at=timezone.now() - datetime.timedelta(minutes=5)
    )
    condition = _watched(dep)
    assert recompute_decision(Deployment.objects.get(pk=dep.pk)) == D.READY
    _the_release_before_makes_the_watch_true(dep)

    call_command("recompute_chain_decisions", stdout=io.StringIO())
    assert not stamped_in_force(Deployment.objects.get(pk=dep.pk))

    published, support, state = _published_after_the_next_read(dep, condition)

    assert (published, support, state) == (D.NEEDS_MORE_EVIDENCE, D.NEEDS_MORE_EVIDENCE, State.FIRED)


def test_the_migrate_after_a_revoke_still_reads_the_watch_the_release_before_made_true():
    """No read in between: the next `migrate` finds the row as the revoke left it --
    not this release's -- reads the watches, and only then stamps it."""
    from django.core.management.sql import emit_post_migrate_signal

    dep = _derived_ready()
    condition = _watched(dep)
    other = (
        AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True)
        .exclude(pk=condition.claim_id)
        .order_by("pk")
        .first()
    )
    _the_release_before_makes_the_watch_true(dep)
    with _committed():
        response = _client().post(
            f"/api/assurance/claims/{other.uuid}/transition/", {"to_status": "revoked"}, format="json"
        )
    assert response.status_code == 200, response.content

    with _committed():
        emit_post_migrate_signal(verbosity=0, interactive=False, db="default")

    fresh = Deployment.objects.get(pk=dep.pk)
    assert LatentCondition.objects.get(pk=condition.pk).state == State.FIRED
    assert fresh.decision == D.NEEDS_MORE_EVIDENCE
    assert stamped_in_force(fresh)


def test_an_evaluation_the_database_refused_leaves_the_decision_for_the_next_read(monkeypatch):
    """The first read stamped the release before's READY before the watches were read.
    Its refresh's writes refused -- the firing and the record of what was not
    evaluated both -- nothing was written, the watch stayed PENDING, and no later read
    brought the row current. It is stamped only once the watches are read."""
    from django.db import OperationalError

    from assurance import latent

    dep = _derived_ready()
    condition = _watched(dep)
    _the_release_before_makes_the_watch_true(dep)

    def refused(self, stored, reading):
        raise OperationalError("database is locked")

    monkeypatch.setattr(latent._Evaluation, "_apply", refused)
    monkeypatch.setattr(latent, "_record_not_evaluated", lambda *args, **kwargs: False)
    with _committed():
        current_decision(Deployment.objects.get(pk=dep.pk))  # the first read; its refresh is refused
    monkeypatch.undo()
    assert LatentCondition.objects.get(pk=condition.pk).state == State.PENDING
    assert not stamped_in_force(Deployment.objects.get(pk=dep.pk))

    published, support, state = _published_after_the_next_read(dep, condition)  # the database takes writes

    assert (published, support, state) == (D.NEEDS_MORE_EVIDENCE, D.NEEDS_MORE_EVIDENCE, State.FIRED)


def test_a_recompute_of_the_release_before_between_the_watches_and_the_stamp_is_not_stamped_over(monkeypatch):
    """The refresh reads the watches, then recomputes and stamps. A write of the
    release before landing between the two -- a tool a watch names, recomputed to the
    same READY -- was stamped over: the watch it made true never read, and no read
    recognising the row again. Found bare again after this release claimed it, the
    keyring column says so, and the row is left for the next read."""
    from assurance import latent

    dep = _derived_ready()
    condition = _watched(dep)
    _recomputed_by_the_release_before(dep)  # a write of the release before that makes nothing true
    real, landed = latent.fire_due_conditions, []

    def and_then_the_release_before_writes(deployment, **kwargs):
        fired = real(deployment, **kwargs)
        if not landed:
            landed.append(True)
            _the_release_before_makes_the_watch_true(dep)
        return fired

    monkeypatch.setattr(latent, "fire_due_conditions", and_then_the_release_before_writes)
    with _committed():
        current_decision(Deployment.objects.get(pk=dep.pk))  # the first read; what it schedules runs
    monkeypatch.undo()
    assert landed
    assert not stamped_in_force(Deployment.objects.get(pk=dep.pk))

    published, support, state = _published_after_the_next_read(dep, condition)

    assert (published, support, state) == (D.NEEDS_MORE_EVIDENCE, D.NEEDS_MORE_EVIDENCE, State.FIRED)


# -- A recompute of this release's between the release before's and the refresh's stamp --
#
# The refresh read the watches; then the release before made one true and recomputed
# (the keyring column bare); then a recompute of this release's that reads no watch --
# a revoke, a contradict, the recompute route, a pause and its lift,
# `recompute_chain_decisions` -- marked the column again. The refresh's recompute found
# it marked, and stamped the READY the watch it had read before no longer bore out: the
# watch left PENDING, and no read and no `migrate` recognising the row again. Only the
# refresh's own claim, still standing under the lock, says no recompute landed since.


def _other_claim(dep, condition):
    return (
        AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True)
        .exclude(pk=condition.claim_id)
        .order_by("pk")
        .first()
    )


def _transition(status):
    def act(dep, condition):
        response = _client().post(
            f"/api/assurance/claims/{_other_claim(dep, condition).uuid}/transition/", {"to_status": status},
            format="json",
        )
        assert response.status_code == 200, response.content

    return act


def _the_recompute_route(dep, condition):
    response = _client().post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {}, format="json")
    assert response.status_code == 200, response.content


def _a_pause_and_its_lift(dep, condition):
    client = _client()
    for paused in (True, False):
        response = client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": paused}, format="json")
        assert response.status_code == 200, response.content


def _recompute_chain_decisions(dep, condition):
    import io

    from django.core.management import call_command

    call_command("recompute_chain_decisions", stdout=io.StringIO())


def _with_a_chain_outcome(dep):
    from assurance.composition import HELD
    from assurance.models import WorkflowChainOutcome

    WorkflowChainOutcome.objects.create(
        deployment=dep, workflow="silent", status=HELD, observed_at=timezone.now() - datetime.timedelta(minutes=5)
    )
    assert recompute_decision(Deployment.objects.get(pk=dep.pk)) == D.READY


_RECOMPUTES_THAT_READ_NO_WATCH = [
    pytest.param(_transition("revoked"), None, D.NEEDS_MORE_EVIDENCE, id="a-revoke"),
    pytest.param(_transition("contradicted"), None, D.NEEDS_REMEDIATION, id="a-contradict"),
    pytest.param(_the_recompute_route, None, D.NEEDS_MORE_EVIDENCE, id="the-recompute-route"),
    pytest.param(_a_pause_and_its_lift, None, D.NEEDS_MORE_EVIDENCE, id="a-pause-and-its-lift"),
    pytest.param(_recompute_chain_decisions, _with_a_chain_outcome, D.NEEDS_MORE_EVIDENCE, id="recompute-chain-decisions"),
]
_AS_THE_REFRESH_FINDS_IT = [
    pytest.param(False, id="this-releases"),
    pytest.param(True, id="another-writers-it-claims"),
]


def _refreshed_while(dep, *steps, monkeypatch):
    """The deployment's refresh, as the backstop runs it; ``steps`` land once it has
    read the watches, before it recomputes."""
    from assurance import latent
    from assurance.decision import refresh_stored_decisions

    real, landed = latent.fire_due_conditions, []

    def and_then(deployment, **kwargs):
        fired = real(deployment, **kwargs)
        if not landed:
            landed.append(True)
            for step in steps:
                step()
        return fired

    monkeypatch.setattr(latent, "fire_due_conditions", and_then)
    refresh_stored_decisions([dep.pk])
    monkeypatch.undo()
    assert landed


@pytest.mark.parametrize("claimed", _AS_THE_REFRESH_FINDS_IT)
@pytest.mark.parametrize(("recompute", "prepare", "expected"), _RECOMPUTES_THAT_READ_NO_WATCH)
def test_a_recompute_that_reads_no_watch_after_the_release_before_is_not_stamped_over_by_the_refresh(
    recompute, prepare, expected, claimed, monkeypatch
):
    dep = _derived_ready()
    if prepare is not None:
        prepare(dep)
    condition = _watched(dep)
    if claimed:
        _recomputed_by_the_release_before(dep)  # a write of the release before that makes nothing true
    assert stamped_in_force(Deployment.objects.get(pk=dep.pk)) is not claimed

    _refreshed_while(
        dep, lambda: _the_release_before_makes_the_watch_true(dep), lambda: recompute(dep, condition),
        monkeypatch=monkeypatch,
    )

    assert LatentCondition.objects.get(pk=condition.pk).state == State.PENDING  # read before it came true
    assert not stamped_in_force(Deployment.objects.get(pk=dep.pk))

    published, support, state = _published_after_the_next_read(dep, condition)

    assert (published, support, state) == (expected, expected, State.FIRED)
    assert stamped_in_force(Deployment.objects.get(pk=dep.pk))


def _refused_evaluation(monkeypatch):
    from django.db import OperationalError

    from assurance import latent

    def refused(self, stored, reading):
        raise OperationalError("database is locked")

    monkeypatch.setattr(latent._Evaluation, "_apply", refused)
    monkeypatch.setattr(latent, "_record_not_evaluated", lambda *args, **kwargs: False)


@pytest.mark.parametrize("claimed", _AS_THE_REFRESH_FINDS_IT)
def test_a_second_refresh_whose_evaluation_is_refused_does_not_let_the_first_stamp(claimed, monkeypatch):
    """Two refreshes of one deployment. The first read the watches; the release before
    made one true; the second claimed the row -- marking the keyring column again --
    and its evaluation was refused. Neither read the watch after it came true, so
    neither stamps: the first's claim is no longer the row's, and the second read
    nothing since its own."""
    from assurance.decision import refresh_stored_decisions

    dep = _derived_ready()
    condition = _watched(dep)
    if claimed:
        _recomputed_by_the_release_before(dep)

    def the_second_refresh_refused():
        with pytest.MonkeyPatch.context() as refusing:
            _refused_evaluation(refusing)
            refresh_stored_decisions([dep.pk])

    _refreshed_while(
        dep, lambda: _the_release_before_makes_the_watch_true(dep), the_second_refresh_refused,
        monkeypatch=monkeypatch,
    )

    assert LatentCondition.objects.get(pk=condition.pk).state == State.PENDING
    assert not stamped_in_force(Deployment.objects.get(pk=dep.pk))

    published, support, state = _published_after_the_next_read(dep, condition)

    assert (published, support, state) == (D.NEEDS_MORE_EVIDENCE, D.NEEDS_MORE_EVIDENCE, State.FIRED)


def test_a_second_refresh_claiming_between_the_first_ones_reading_and_its_stamp_leaves_the_row_unstamped(
    monkeypatch,
):
    """The same two refreshes interleaved the other way: the second claims before the
    first recomputes, and recomputes -- its evaluation refused -- after it. The claim
    marked the keyring column the release before had left bare, so the first read the
    row as claimed by it and stamped; the second then found the row stamped."""
    from assurance.decision import _claim_for_this_release, _watches_read_since
    from assurance.latent import fire_due_conditions

    dep = _derived_ready()
    condition = _watched(dep)
    _recomputed_by_the_release_before(dep)
    second = {}

    def the_second_refresh_claims():
        second["since"] = timezone.now()
        second["claim"] = _claim_for_this_release(Deployment.objects.get(pk=dep.pk))

    _refreshed_while(
        dep, lambda: _the_release_before_makes_the_watch_true(dep), the_second_refresh_claims,
        monkeypatch=monkeypatch,
    )
    # The second refresh goes on as `refresh_stored_decisions` does: its evaluation
    # refused, then its recompute.
    with pytest.MonkeyPatch.context() as refusing:
        _refused_evaluation(refusing)
        with signals.refresh_deferred(dep.pk):
            fire_due_conditions(Deployment.objects.get(pk=dep.pk), schedule_refresh=False)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk),
        brought_current=bool(second["claim"]) and _watches_read_since(dep.pk, second["since"]),
        after_claim=second["claim"],
    )

    assert LatentCondition.objects.get(pk=condition.pk).state == State.PENDING
    assert not stamped_in_force(Deployment.objects.get(pk=dep.pk))

    published, support, state = _published_after_the_next_read(dep, condition)

    assert (published, support, state) == (D.NEEDS_MORE_EVIDENCE, D.NEEDS_MORE_EVIDENCE, State.FIRED)


def test_the_migrate_that_finds_the_row_this_releases_by_its_claim_does_not_stamp_it_after_another_writer(
    monkeypatch,
):
    """The post-migrate receiver selects the row as another writer's; by its claim a
    refresh has brought it current, so it claims nothing. While it reads the watches
    the release before makes one true, and a revoke marks the keyring column again.
    With no claim of its own standing, it leaves the row for the next read."""
    from django.core.management.sql import emit_post_migrate_signal

    from assurance import decision, latent

    dep = _derived_ready()
    condition = _watched(dep)
    _recomputed_by_the_release_before(dep)  # selected by the receiver as another writer's
    real_claim, real_fire, armed, refreshing = decision._claim_for_this_release, latent.fire_due_conditions, [], []

    def a_refresh_first(deployment):
        if deployment.pk == dep.pk and not armed and not refreshing:
            refreshing.append(True)
            decision.refresh_stored_decisions([dep.pk])  # the row is this release's again
            assert stamped_in_force(Deployment.objects.get(pk=dep.pk))
            armed.append(True)
        return real_claim(deployment)

    def and_then(deployment, **kwargs):
        fired = real_fire(deployment, **kwargs)
        if deployment.pk == dep.pk and armed == [True]:
            armed.append(True)
            _the_release_before_makes_the_watch_true(dep)
            _transition("revoked")(dep, condition)
        return fired

    monkeypatch.setattr(decision, "_claim_for_this_release", a_refresh_first)
    monkeypatch.setattr(latent, "fire_due_conditions", and_then)
    emit_post_migrate_signal(verbosity=0, interactive=False, db="default")
    monkeypatch.undo()
    assert armed == [True, True]

    assert LatentCondition.objects.get(pk=condition.pk).state == State.PENDING
    assert not stamped_in_force(Deployment.objects.get(pk=dep.pk))

    published, support, state = _published_after_the_next_read(dep, condition)

    assert (published, support, state) == (D.NEEDS_MORE_EVIDENCE, D.NEEDS_MORE_EVIDENCE, State.FIRED)


# -- A watch left pending on a version the release before closed, the carry refused --


def _left_on_a_closed_version_and_made_true(dep):
    from tests.test_latent_conditions_in_production import _re_derived_by_the_release_before

    claim = _claim(dep)
    condition = _watched(dep)
    with signals.refresh_deferred(dep.pk):
        current = _re_derived_by_the_release_before(dep, claim)  # the watch left on the version it closed
    _the_release_before_makes_the_watch_true(dep)
    return condition, current


def _the_carry_refused(monkeypatch):
    from assurance import carry

    def refused(*args, **kwargs):
        raise RuntimeError("the carry was refused")

    monkeypatch.setattr(carry, "converge", refused)


def test_a_watch_left_pending_on_a_closed_version_is_not_read_as_watched(monkeypatch):
    """Nothing evaluates a closed version. While the carry that would move the watch to
    the current one is refused, the decision counted it as watched: READY published on
    every read -- none of them stamping it -- over a watch whose subject had come
    true. It is read as unread, and the plan names it."""
    from assurance.revalidation import plan_revalidation

    dep = _derived_ready()
    condition, current = _left_on_a_closed_version_and_made_true(dep)
    _the_carry_refused(monkeypatch)

    for _ in range(2):
        published, support, state = _published_after_the_next_read(dep, condition)
        assert (published, support, state) == (D.NEEDS_MORE_EVIDENCE, D.NEEDS_MORE_EVIDENCE, State.PENDING)
    unread = decision_support(Deployment.objects.get(pk=dep.pk))["claims"]["unread_conditions"]
    assert [c["uuid"] for c in unread] == [str(condition.uuid)]
    plan = plan_revalidation(Deployment.objects.get(pk=dep.pk))
    required = {w["claim_uuid"]: w for w in plan["required"]}
    assert str(current.uuid) in required, plan
    assert "closed" in required[str(current.uuid)]["reason"]
    assert "Nothing needs to be re-run" not in plan["note"]

    monkeypatch.undo()  # the carry goes through again
    published, support, state = _published_after_the_next_read(dep, condition)

    assert (published, support, state) == (D.NEEDS_MORE_EVIDENCE, D.NEEDS_MORE_EVIDENCE, State.FIRED)
    assert stamped_in_force(Deployment.objects.get(pk=dep.pk))


def test_a_watch_left_on_a_closed_version_of_a_claim_a_person_revoked_holds_nothing(monkeypatch):
    """A person took the claim out of scope: a watch left on any version of it is no
    more a mark against readiness than the claim is, in the decision and the plan
    alike -- whatever the carry does."""
    from assurance.revalidation import plan_revalidation

    dep = _derived_ready()
    condition, current = _left_on_a_closed_version_and_made_true(dep)
    with _committed():
        response = _client().post(
            f"/api/assurance/claims/{current.uuid}/transition/", {"to_status": "revoked"}, format="json"
        )
    assert response.status_code == 200, response.content
    _the_carry_refused(monkeypatch)

    published, support, _state = _published_after_the_next_read(dep, condition)

    assert published == support
    assert decision_support(Deployment.objects.get(pk=dep.pk))["claims"]["unread_conditions"] == []
    plan = plan_revalidation(Deployment.objects.get(pk=dep.pk))
    assert str(current.uuid) not in {w["claim_uuid"] for w in plan["required"]}
    assert published == D.READY
