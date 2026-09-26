"""An accepted risk is carried, not removed (owner decision Q6).

Accepting a finding took it out of the decision altogether, so accepting a critical
finding read READY -- the same answer as fixing it. An acceptance now:

- holds the deployment at READY_RESTRICTED at best while it stands;
- must name when it ends, in the future, to be made at all;
- caps the decision at NEEDS_MORE_EVIDENCE once it lapses, or if it never named an
  end (every acceptance made before this rule);
- lapses at its moment even when nothing is written: the stored decision records
  when it stops holding, and the first read after that recomputes it.
"""

from __future__ import annotations

from datetime import timedelta
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from assurance.decision import compute_decision, current_decision, decision_support, recompute_decision
from assurance.models import Deployment, Finding
from assurance.revision import read_decision
from tests.decision_surfaces import one_decision

pytestmark = pytest.mark.django_db

User = get_user_model()
D = Deployment.Decision


def _admin():
    return User.objects.create_user(
        username=f"admin{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )


def _client():
    client = APIClient()
    client.force_authenticate(user=_admin())
    return client


def _scanned():
    dep = Deployment.objects.create(name=f"d{Deployment.objects.count()}", owner=_admin())
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    dep.refresh_from_db()
    return dep


def _finding(dep, severity="critical", *, status=Finding.Status.OPEN, until=None, n="1", accepted_at=None):
    # An acceptance written here covers the severity the finding has, as the
    # acceptance route records it (Finding.risk_accepted_severity), unless a test
    # says it was given at another.
    accepted = severity if accepted_at is None else accepted_at
    return Finding.objects.create(
        deployment=dep, fingerprint=f"fp-{severity}-{n}", finding_type="t", title=f"T{n}",
        severity=severity, status=status, risk_accepted_until=until,
        risk_accepted_severity=accepted if status == Finding.Status.ACCEPTED else "",
    )


def _in(days):
    return timezone.now() + timedelta(days=days)


# ---- The rule. ----


@pytest.mark.parametrize("severity", ["critical", "high", "medium", "low", "info"])
def test_a_standing_acceptance_is_ready_with_restrictions_at_best(severity):
    dep = _scanned()
    _finding(dep, severity, status=Finding.Status.ACCEPTED, until=_in(30))
    assert compute_decision(dep) == D.READY_RESTRICTED


def test_an_acceptance_that_never_named_an_end_needs_more_evidence():
    """Every acceptance made before the rule. Nobody decided how long to carry it."""
    dep = _scanned()
    _finding(dep, status=Finding.Status.ACCEPTED, until=None)
    assert compute_decision(dep) == D.NEEDS_MORE_EVIDENCE


def test_a_lapsed_acceptance_needs_more_evidence():
    dep = _scanned()
    _finding(dep, status=Finding.Status.ACCEPTED, until=_in(-1))
    assert compute_decision(dep) == D.NEEDS_MORE_EVIDENCE


def test_one_lapsed_acceptance_among_standing_ones_needs_more_evidence():
    dep = _scanned()
    _finding(dep, status=Finding.Status.ACCEPTED, until=_in(30), n="a")
    _finding(dep, status=Finding.Status.ACCEPTED, until=_in(-1), n="b")
    assert compute_decision(dep) == D.NEEDS_MORE_EVIDENCE


def test_an_acceptance_never_lifts_the_decision():
    """A cap: an open high finding beside a standing acceptance still needs
    remediation."""
    dep = _scanned()
    _finding(dep, "high", n="open")
    _finding(dep, status=Finding.Status.ACCEPTED, until=_in(30), n="acc")
    assert compute_decision(dep) == D.NEEDS_REMEDIATION


def test_closed_and_false_positive_still_leave_the_decision():
    dep = _scanned()
    _finding(dep, status=Finding.Status.CLOSED, n="cl")
    _finding(dep, status=Finding.Status.FALSE_POSITIVE, n="fp")
    assert compute_decision(dep) == D.READY


# ---- Time moves the decision where no write does. ----


def test_the_stored_decision_records_when_it_stops_holding():
    dep = _scanned()
    first, second = _in(10), _in(30)
    _finding(dep, status=Finding.Status.ACCEPTED, until=second, n="a")
    _finding(dep, status=Finding.Status.ACCEPTED, until=first, n="b")
    recompute_decision(dep)
    dep.refresh_from_db()
    assert dep.decision == D.READY_RESTRICTED
    assert dep.decision_valid_until == first


def test_an_acceptance_lapses_on_every_surface_without_a_write():
    """Nothing is written between the two reads. The stored READY_RESTRICTED used
    to stand until something else recomputed the deployment."""
    dep = _scanned()
    until = _in(1)
    _finding(dep, status=Finding.Status.ACCEPTED, until=until)
    recompute_decision(dep)
    client = _client()
    assert one_decision(dep, client) == D.READY_RESTRICTED

    later = until + timedelta(seconds=1)
    with mock.patch.object(timezone, "now", return_value=later):
        assert read_decision(dep)["decision"] == D.NEEDS_MORE_EVIDENCE
        assert one_decision(dep, client) == D.NEEDS_MORE_EVIDENCE
    dep.refresh_from_db()
    assert dep.decision == D.NEEDS_MORE_EVIDENCE
    assert dep.decision_valid_until is None


def test_a_decision_with_nothing_to_lapse_records_no_end():
    dep = _scanned()
    _finding(dep, "high")
    recompute_decision(dep)
    dep.refresh_from_db()
    assert dep.decision_valid_until is None


def test_a_pause_records_no_end():
    dep = _scanned()
    _finding(dep, status=Finding.Status.ACCEPTED, until=_in(1))
    recompute_decision(dep, paused=True)
    dep.refresh_from_db()
    assert dep.decision == D.PAUSED
    assert dep.decision_valid_until is None


# ---- The upgrade. ----


def test_acceptances_made_before_the_rule_are_recomputed_at_their_first_read():
    """Their stored decision was computed with the finding left out: READY, logged
    as READY, and stamped with the rules it was computed under. The upgrade moves
    the policy pin; the first read sees a decision stamped under other rules and
    recomputes it under these. Without the stamp, the stale READY is what every
    surface publishes -- and marking it from a migration would write a decision
    column behind the transition log."""
    from assurance.decision import _current_policy_pin

    dep = _scanned()
    untouched = _scanned()
    _finding(untouched, "low")
    for d in (dep, untouched):
        recompute_decision(d)
    # Accepted before the rule: `bulk_create` sends no signal, so nothing
    # recomputes -- the stored READY is the one the old rule computed, which left
    # the accepted finding out.
    Finding.objects.bulk_create([
        Finding(deployment=dep, fingerprint="fp-legacy", finding_type="t", title="legacy",
                severity="critical", status=Finding.Status.ACCEPTED),
    ])
    dep = Deployment.objects.get(pk=dep.pk)
    assert current_decision(dep) == D.READY, "stamped under the rules in force: read as stored"

    # The decisions as the release before this one left them: stamped under its pin.
    Deployment.objects.filter(pk__in=[dep.pk, untouched.pk]).update(decision_policy="policy-before")

    dep = Deployment.objects.get(pk=dep.pk)
    assert current_decision(dep) == D.NEEDS_MORE_EVIDENCE
    assert Deployment.objects.get(pk=dep.pk).decision == D.NEEDS_MORE_EVIDENCE
    assert Deployment.objects.get(pk=dep.pk).decision_policy == _current_policy_pin()
    # The other is recomputed too -- to what it already was, and stamped.
    untouched = Deployment.objects.get(pk=untouched.pk)
    before = untouched.decision
    assert current_decision(untouched) == before
    assert Deployment.objects.get(pk=untouched.pk).decision_policy == _current_policy_pin()


def test_the_upgrade_recomputes_every_decision_stamped_under_other_rules():
    """Eagerly, at migrate, for a deployment nothing reads: the post-migrate
    receiver recomputes each stored decision whose stamp is not the pin in force,
    and leaves one stamped under it alone."""
    from django.apps import apps

    from assurance import signals
    from assurance.decision import _current_policy_pin

    stale, current = _scanned(), _scanned()
    for d in (stale, current):
        recompute_decision(d)
    Finding.objects.bulk_create([
        Finding(deployment=stale, fingerprint="fp-legacy-2", finding_type="t", title="legacy",
                severity="critical", status=Finding.Status.ACCEPTED),
    ])
    Deployment.objects.filter(pk=stale.pk).update(decision_policy=None)
    revision = Deployment.objects.get(pk=current.pk).decision_revision

    signals.recompute_decisions_computed_under_another_rule(apps.get_app_config("assurance"), using="default")

    assert Deployment.objects.get(pk=stale.pk).decision == D.NEEDS_MORE_EVIDENCE
    assert Deployment.objects.get(pk=stale.pk).decision_policy == _current_policy_pin()
    assert Deployment.objects.get(pk=current.pk).decision_revision == revision


# ---- Accepting a risk names when the acceptance ends. ----


def _patch(client, finding, body):
    return client.patch(f"/api/assurance/findings/{finding.uuid}/", body, format="json")


def test_accepting_without_an_end_is_refused():
    dep = _scanned()
    finding = _finding(dep)
    response = _patch(_client(), finding, {"status": "accepted"})
    assert response.status_code == 400
    assert "risk_accepted_until" in response.json()
    finding.refresh_from_db()
    assert finding.status == Finding.Status.OPEN


def test_accepting_with_an_end_in_the_past_is_refused():
    dep = _scanned()
    finding = _finding(dep)
    response = _patch(_client(), finding, {"status": "accepted", "risk_accepted_until": _in(-1).isoformat()})
    assert response.status_code == 400


def test_accepting_with_an_end_holds_the_deployment_at_ready_with_restrictions():
    dep = _scanned()
    finding = _finding(dep)
    recompute_decision(dep)
    client = _client()
    assert one_decision(dep, client) == D.NOT_RECOMMENDED
    response = _patch(client, finding, {"status": "accepted", "risk_accepted_until": _in(30).isoformat()})
    assert response.status_code == 200, response.content
    assert one_decision(dep, client) == D.READY_RESTRICTED


def test_extending_a_standing_acceptance_keeps_it_and_moves_its_end():
    dep = _scanned()
    finding = _finding(dep, status=Finding.Status.ACCEPTED, until=_in(1))
    recompute_decision(dep)
    later = _in(60)
    response = _patch(_client(), finding, {"risk_accepted_until": later.isoformat()})
    assert response.status_code == 200, response.content
    dep.refresh_from_db()
    assert dep.decision_valid_until == later


def test_any_other_status_clears_the_end():
    dep = _scanned()
    finding = _finding(dep, status=Finding.Status.ACCEPTED, until=_in(30))
    response = _patch(_client(), finding, {"status": "open"})
    assert response.status_code == 200, response.content
    finding.refresh_from_db()
    assert finding.risk_accepted_until is None


@pytest.mark.parametrize("until", [_in(-1), None], ids=["lapsed", "never-dated"])
def test_editing_an_accepted_finding_is_not_judged_as_a_new_acceptance(until):
    """Reassigning an accepted finding, or noting its impact, is not accepting it
    again: it was refused when the acceptance had lapsed or predates the rule, so
    the finding could not be handed to anyone. The acceptance is left as it was --
    still lapsed, still holding the decision -- until someone renews it."""
    dep = _scanned()
    finding = _finding(dep, status=Finding.Status.ACCEPTED, until=until)
    recompute_decision(dep)
    client = _client()
    response = _patch(client, finding, {"business_impact": "Refunds past the limit reach a real account."})
    assert response.status_code == 200, response.content
    finding.refresh_from_db()
    assert finding.status == Finding.Status.ACCEPTED
    assert finding.risk_accepted_until == until
    assert finding.business_impact.startswith("Refunds")
    assert one_decision(dep, client) == D.NEEDS_MORE_EVIDENCE
    # Renewing it is still judged: a past end is refused, a future one stands.
    assert _patch(client, finding, {"risk_accepted_until": _in(-2).isoformat()}).status_code == 400
    assert _patch(client, finding, {"risk_accepted_until": _in(30).isoformat()}).status_code == 200
    assert one_decision(dep, client) == D.READY_RESTRICTED


def test_an_end_on_a_risk_nobody_accepted_is_refused():
    dep = _scanned()
    finding = _finding(dep)
    response = _patch(_client(), finding, {"risk_accepted_until": _in(30).isoformat()})
    assert response.status_code == 400


# ---- decision-support says so. ----


def test_decision_support_names_the_acceptance_that_binds():
    dep = _scanned()
    until = _in(30)
    _finding(dep, status=Finding.Status.ACCEPTED, until=until)
    payload = decision_support(dep)
    assert payload["decision"] == D.READY_RESTRICTED
    assert payload["accepted_risk_cap"] == D.READY_RESTRICTED
    assert [f["accepted_until"] for f in payload["accepted_risk"]["standing"]] == [until.isoformat()]
    assert payload["accepted_risk"]["lapsed"] == []
    assert "accepted until" in payload["note"]


def test_decision_support_names_the_lapsed_acceptance():
    dep = _scanned()
    _finding(dep, status=Finding.Status.ACCEPTED, until=None)
    payload = decision_support(dep)
    assert payload["decision"] == D.NEEDS_MORE_EVIDENCE
    assert [f["accepted_until"] for f in payload["accepted_risk"]["lapsed"]] == [None]
    assert "lapsed or never named an end" in payload["note"]
