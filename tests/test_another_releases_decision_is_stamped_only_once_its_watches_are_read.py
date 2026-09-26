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
