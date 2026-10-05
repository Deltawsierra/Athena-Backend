"""A finding serves what its closure stands on (Phase 6 item 3, the closure display).

The closure gate (assurance/retest_closure.py) decided, at the save, whether a
retest-gated closure stands -- and said so to nobody else: the API served
``status: closed`` the same for a finding closed on complete, independent closure
evidence and for one closed with no retest asked. Every finding now serves
``closure``: the gate's own verdict per finding (FREEZE.md's worked case: an existing
verdict exposed per record), so a reader can tell an effect-backed closure from a
disposition, and an open finding's closure that would be refused from one that would
stand. "verified_closed" is served only where the gate's evidence carries it.
"""

from __future__ import annotations

import copy
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.models import ClaimEvidence, Deployment, Finding
from assurance.retest_closure import (
    CLOSABLE,
    CLOSED_UNVERIFIED,
    INCOMPLETE_REPAIR,
    INCOMPLETE_REPAIR_PATTERNS,
    NOT_CLOSABLE,
    NOT_GATED,
    VERIFIED_CLOSED,
    closure_standing,
    record_closure_evidence,
    refusal_reasons,
)
from assurance.views import FindingViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()

COMPLETE = {
    "vulnerable": {"ran": True, "outcome": "failed"},
    "repaired": {"ran": True, "outcome": "passed"},
    "benign": {"ran": True, "outcome": "passed"},
    INCOMPLETE_REPAIR: {p: {"ran": True, "outcome": "failed"} for p in INCOMPLETE_REPAIR_PATTERNS},
}


def _admin():
    return User.objects.create_user(
        username=f"admin{User.objects.count()}", password="x", role=User.Roles.ADMIN
    )


def _finding(retest_required=True, **kwargs):
    dep = Deployment.objects.create(name=f"d{Deployment.objects.count()}", owner=_admin())
    defaults = dict(
        deployment=dep, fingerprint=f"fp{Finding.objects.count()}", finding_type="sql_injection",
        title="SQLi", severity="critical", retest_required=retest_required,
    )
    defaults.update(kwargs)
    return Finding.objects.create(**defaults)


def _record(finding, fixtures=None, *, origin=ClaimEvidence.Origin.INDEPENDENT, now=None):
    return record_closure_evidence(
        finding, fixtures=copy.deepcopy(COMPLETE if fixtures is None else fixtures),
        origin=origin, content_digest="sha256:ab12", now=now,
    )


def _close(finding):
    finding = Finding.objects.get(pk=finding.pk)
    finding.status = Finding.Status.CLOSED
    finding.save()
    return Finding.objects.get(pk=finding.pk)


def _served(finding, user=None):
    request = APIRequestFactory().get(f"/api/assurance/findings/{finding.uuid}/")
    force_authenticate(request, user=user or finding.deployment.owner)
    response = FindingViewSet.as_view({"get": "retrieve"})(request, uuid=str(finding.uuid))
    assert response.status_code == 200, response.data
    return response.data["closure"]


def test_a_closure_on_complete_independent_evidence_is_served_verified_closed():
    finding = _finding()
    _record(finding)
    closed = _close(finding)

    served = _served(closed)

    assert served["standing"] == VERIFIED_CLOSED
    assert served["reasons"] == []
    assert served["evidence"]["origin"] == ClaimEvidence.Origin.INDEPENDENT
    assert served["evidence"]["content_digest"] == "sha256:ab12"
    assert served["evidence"]["fixtures"]["vulnerable"] == {"ran": True, "outcome": "failed"}
    assert set(served["evidence"]["fixtures"][INCOMPLETE_REPAIR]) == set(INCOMPLETE_REPAIR_PATTERNS)


def test_a_closure_with_no_retest_asked_is_a_disposition_never_verified():
    closed = _close(_finding(retest_required=False))

    served = _served(closed)

    assert served["standing"] == CLOSED_UNVERIFIED
    assert served["retest_required"] is False
    assert served["evidence"] is None


def test_an_open_finding_says_whether_its_closure_would_stand_and_why_not():
    standing = _finding()
    _record(standing)
    assert _served(standing)["standing"] == CLOSABLE

    fooled = _finding()
    fixtures = copy.deepcopy(COMPLETE)
    fixtures[INCOMPLETE_REPAIR]["displaced_effects"] = {"ran": True, "outcome": "passed"}
    _record(fooled, fixtures)
    served = _served(fooled)
    assert served["standing"] == NOT_CLOSABLE
    assert served["reasons"] == refusal_reasons(fooled), "the gate's own reasons, not a second judgement"
    assert any("displaced_effects" in reason for reason in served["reasons"])
    assert served["evidence"]["fixtures"][INCOMPLETE_REPAIR]["displaced_effects"]["outcome"] == "passed"

    nothing = _finding()
    assert _served(nothing)["standing"] == NOT_CLOSABLE
    assert _served(nothing)["evidence"] is None

    vendor = _finding()
    _record(vendor, origin=ClaimEvidence.Origin.VENDOR)
    assert _served(vendor)["standing"] == NOT_CLOSABLE

    open_ungated = _finding(retest_required=False)
    assert _served(open_ungated)["standing"] == NOT_GATED


def test_a_closed_finding_seen_again_since_its_retest_no_longer_reads_verified():
    finding = _finding()
    now = timezone.now()
    _record(finding, now=now)
    closed = _close(finding)
    Finding.objects.filter(pk=closed.pk).update(last_seen=now + timedelta(hours=1))

    served = _served(Finding.objects.get(pk=closed.pk))

    assert served["standing"] == NOT_CLOSABLE
    assert any("last observed" in reason for reason in served["reasons"])


def test_the_latest_record_is_the_one_served_as_the_gate_reads_it():
    finding = _finding()
    now = timezone.now()
    _record(finding, now=now - timedelta(minutes=5))
    fixtures = copy.deepcopy(COMPLETE)
    fixtures["benign"] = {"ran": False}
    later = _record(finding, fixtures, now=now)

    served = _served(finding)

    assert served["evidence"]["uuid"] == str(later.uuid)
    assert served["standing"] == NOT_CLOSABLE
    assert served["evidence"]["fixtures"]["benign"] == {"ran": False, "outcome": None}


def test_an_unreadable_record_is_served_unreadable_never_as_a_pass():
    finding = _finding()
    record = _record(finding)
    type(record).objects.filter(pk=record.pk).update(fixtures={"vulnerable": "yes"})

    served = _served(finding)

    assert served["standing"] == NOT_CLOSABLE
    assert served["evidence"]["fixtures"]["vulnerable"] == {"ran": None, "outcome": "unreadable"}
    assert served["evidence"]["fixtures"][INCOMPLETE_REPAIR]["changed_defaults"]["outcome"] == "unreadable"


def test_the_standing_is_the_same_read_through_the_prefetch_or_without_it():
    finding = _finding()
    _record(finding)
    plain = closure_standing(Finding.objects.get(pk=finding.pk))
    prefetched = closure_standing(Finding.objects.prefetch_related("closure_evidence").get(pk=finding.pk))
    assert plain == prefetched


def test_a_page_of_findings_serves_its_closures_in_a_fixed_number_of_queries():
    owner = _admin()

    def page_queries(n):
        for _ in range(n):
            finding = _finding(deployment=Deployment.objects.create(name=f"d{Deployment.objects.count()}", owner=owner))
            _record(finding)
        request = APIRequestFactory().get("/api/assurance/findings/")
        force_authenticate(request, user=owner)
        with CaptureQueriesContext(connection) as queries:
            response = FindingViewSet.as_view({"get": "list"})(request)
        assert response.status_code == 200
        return len(queries)

    few = page_queries(2)
    many = page_queries(6)
    assert many == few, f"{few} queries for 2 findings, {many} for 8: the closure standing is read per finding"
