"""The gate reads the record in force; a reader is served only what it says (#125 review round 1).

- F1. Serving a page of findings reads their closure records from the prefetch,
  and the gate at the save read them there too: a fooled retest committed after the
  finding was loaded was never seen, and the closure stood. The gate reads the
  database at the save, always; only serving reads the prefetch.
- F2. One record whose outcome was an object or a list raised on the membership
  test, a 500 for every read of every finding on the page. It reads unreadable.
- F3. A finding still OPEN whose remediation was RESOLVED was served
  ``verified_closed``. Only status CLOSED is a closure; an accepted or a
  false-positive finding is served ``not_a_closure``, never ``closable``.
- F4. A run's outcome is served only as one the gate knows, or ``unreadable``.
"""

from __future__ import annotations

import copy
from datetime import timedelta

import pytest
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import serializers as serializers_module
from assurance.models import ClaimEvidence, Finding, RetestClosureEvidence
from assurance.retest_closure import (
    CLOSABLE,
    INCOMPLETE_REPAIR,
    NOT_A_CLOSURE,
    NOT_CLOSABLE,
    NOT_GATED,
    OUTCOMES,
    VERIFIED_CLOSED,
    ClosureRefused,
    _served_latest,
    closure_standing,
    latest_record,
    record_closure_evidence,
)
from assurance.views import FindingViewSet
from tests.test_a_finding_serves_what_its_closure_stands_on import COMPLETE, _finding, _record, _served

pytestmark = pytest.mark.django_db


def _fooled():
    fixtures = copy.deepcopy(COMPLETE)
    fixtures[INCOMPLETE_REPAIR]["displaced_effects"] = {"ran": True, "outcome": "passed"}
    return fixtures


def test_the_gate_at_the_save_reads_a_record_committed_after_the_finding_was_loaded():
    finding = _finding()
    now = timezone.now()
    _record(finding, now=now + timedelta(minutes=1))
    loaded = Finding.objects.prefetch_related("closure_evidence").get(pk=finding.pk)
    _record(finding, _fooled(), now=now + timedelta(minutes=2))  # a retest worker, meanwhile
    loaded.status = Finding.Status.CLOSED

    with pytest.raises(ClosureRefused, match="displaced_effects"):
        loaded.save()


def test_the_gate_at_the_save_sees_a_passing_record_added_after_the_load():
    finding = _finding()
    loaded = Finding.objects.prefetch_related("closure_evidence").get(pk=finding.pk)
    _record(finding)
    loaded.status = Finding.Status.CLOSED

    loaded.save()

    assert Finding.objects.get(pk=finding.pk).status == Finding.Status.CLOSED


def test_a_close_over_the_api_is_refused_when_a_fooled_retest_lands_mid_request(monkeypatch):
    finding = _finding()
    now = timezone.now()
    _record(finding, now=now + timedelta(minutes=1))
    validate = serializers_module.FindingSerializer.validate

    def a_retest_lands(self, attrs):
        _record(finding, _fooled(), now=now + timedelta(minutes=2))
        return validate(self, attrs)

    monkeypatch.setattr(serializers_module.FindingSerializer, "validate", a_retest_lands)
    request = APIRequestFactory().patch(f"/x/{finding.uuid}/", {"status": "closed"}, format="json")
    force_authenticate(request, user=finding.deployment.owner)

    response = FindingViewSet.as_view({"patch": "partial_update"})(request, uuid=str(finding.uuid))

    assert response.status_code == 400, response.data
    assert Finding.objects.get(pk=finding.pk).status != Finding.Status.CLOSED


@pytest.mark.parametrize("backdated", [False, True], ids=["tied", "backdated-later-insert"])
def test_the_served_record_is_the_gate_s_through_the_prefetch_or_without_it(backdated):
    finding = _finding()
    now = timezone.now()
    _record(finding, _fooled(), now=now)
    # Tied on created_at, the higher pk is the latest; inserted later but backdated,
    # the earlier created_at is not, whatever its pk.
    _record(finding, now=now - timedelta(minutes=5) if backdated else now)
    fresh = Finding.objects.get(pk=finding.pk)
    cached = Finding.objects.prefetch_related("closure_evidence").get(pk=finding.pk)

    gate_reads = latest_record(fresh)
    assert _served_latest(cached).pk == _served_latest(fresh).pk == gate_reads.pk
    expected = RetestClosureEvidence.objects.filter(finding_id=finding.pk).order_by("-created_at", "-pk").first()
    assert gate_reads.pk == expected.pk
    assert closure_standing(cached) == closure_standing(fresh)
    assert closure_standing(cached)["standing"] == (NOT_CLOSABLE if backdated else CLOSABLE)


@pytest.mark.parametrize("outcome", [["failed"], {"html": "<script>x</script>"}, 7, None])
def test_an_outcome_nobody_declared_reads_unreadable_and_breaks_no_read(outcome):
    good = _finding()
    _record(good)
    bad = _finding()
    fixtures = copy.deepcopy(COMPLETE)
    fixtures["vulnerable"] = {"ran": True, "outcome": outcome}
    record_closure_evidence(bad, fixtures=fixtures, origin=ClaimEvidence.Origin.INDEPENDENT, content_digest="d")
    request = APIRequestFactory().get("/api/assurance/findings/")
    force_authenticate(request, user=bad.deployment.owner)

    response = FindingViewSet.as_view({"get": "list"})(request)

    assert response.status_code == 200
    served = _served(Finding.objects.get(pk=bad.pk))
    assert served["standing"] == NOT_CLOSABLE
    assert served["evidence"]["fixtures"]["vulnerable"] == {"ran": True, "outcome": "unreadable"}
    assert any("vulnerable: unreadable outcome" in reason for reason in served["reasons"])


def test_every_served_outcome_is_one_the_gate_knows_or_unreadable():
    finding = _finding()
    record = _record(finding)
    fixtures = copy.deepcopy(COMPLETE)
    fixtures["benign"] = {"ran": True, "outcome": "PASSED"}
    fixtures[INCOMPLETE_REPAIR]["changed_defaults"] = {"ran": False, "outcome": "passed"}
    RetestClosureEvidence.objects.filter(pk=record.pk).update(fixtures=fixtures)

    served = _served(Finding.objects.get(pk=finding.pk))["evidence"]["fixtures"]

    assert served["benign"] == {"ran": True, "outcome": "unreadable"}
    assert served[INCOMPLETE_REPAIR]["changed_defaults"] == {"ran": False, "outcome": None}
    runs = [served[name] for name in ("vulnerable", "repaired", "benign")] + list(served[INCOMPLETE_REPAIR].values())
    assert all(run["outcome"] in (*OUTCOMES, "unreadable", None) for run in runs)


def test_a_resolved_remediation_on_a_finding_still_open_is_never_served_verified_closed():
    finding = _finding()
    _record(finding)
    resolved = Finding.objects.get(pk=finding.pk)
    resolved.remediation_state = Finding.RemediationState.RESOLVED
    resolved.save()
    resolved = Finding.objects.get(pk=finding.pk)
    assert resolved.status == Finding.Status.OPEN

    assert _served(resolved)["standing"] == CLOSABLE

    ungated = _finding(retest_required=False)
    Finding.objects.filter(pk=ungated.pk).update(remediation_state=Finding.RemediationState.RESOLVED)
    assert _served(Finding.objects.get(pk=ungated.pk))["standing"] == NOT_GATED


@pytest.mark.parametrize("status", [Finding.Status.ACCEPTED, Finding.Status.FALSE_POSITIVE])
@pytest.mark.parametrize("retest_required", [True, False])
def test_an_accepted_or_false_positive_finding_is_not_a_closure(status, retest_required):
    finding = _finding(status=status, retest_required=retest_required)
    _record(finding)

    served = _served(Finding.objects.get(pk=finding.pk))

    assert served["standing"] == NOT_A_CLOSURE
    assert served["reasons"] == []
    assert served["evidence"]["origin"] == ClaimEvidence.Origin.INDEPENDENT


def test_a_closure_served_verified_names_the_origin_it_stands_on_and_an_ungated_one_no_reasons():
    finding = _finding()
    _record(finding)
    closed = Finding.objects.get(pk=finding.pk)
    closed.status = Finding.Status.CLOSED
    closed.save()
    served = _served(Finding.objects.get(pk=finding.pk))
    assert served["standing"] == VERIFIED_CLOSED
    assert served["evidence"]["origin"] == ClaimEvidence.Origin.INDEPENDENT

    vendor = _finding(retest_required=False)
    _record(vendor, origin=ClaimEvidence.Origin.VENDOR)
    served = _served(Finding.objects.get(pk=vendor.pk))
    assert served["reasons"] == [] and served["evidence"]["origin"] == ClaimEvidence.Origin.VENDOR
