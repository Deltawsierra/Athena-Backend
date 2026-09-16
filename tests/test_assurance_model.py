"""Athena Phase 0.1 — the assurance system-of-record data model and ingestion.

Proves the durable model and the engine-response ingestion: structured Finding +
graded Evidence rows under a Deployment, the evidence-classification taxonomy as
data, idempotent re-ingest that preserves human workflow state, and the
scoped/patchable Finding API. The viewsets are exercised directly via
APIRequestFactory so these tests do not import the full URLconf (which pulls in
report-generation deps this suite does not need).
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import ingest
from assurance.models import (
    Deployment,
    Evidence,
    EvidenceClass,
    Finding,
    Provider,
    evidence_strength,
)
from assurance.views import FindingViewSet
from pentest.models import Engagement, PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(
        username=name, password="x", role=role or User.Roles.ANALYST
    )


def _scan(user, engagement=None, findings=None):
    resp = {"findings": findings} if findings is not None else None
    return PentestScan.objects.create(
        user=user,
        target_url="https://app.client.example/login",
        consent=True,
        status=PentestScan.STATUS_COMPLETED,
        engagement=engagement,
        engine_response=resp,
    )


# A realistic engine response: one confirmed exploit, one informational note,
# and one internal (adapter-error) entry that must be ignored.
ENGINE_FINDINGS = [
    {
        "type": "sql_injection",
        "report_severity": "critical",
        "confidence": 0.95,
        "cvss_score": 9.8,
        "cvss_vector": "AV:N/AC:L",
        "tier": "confirmed",
        "exploit_like": True,
        "recommendation": "Use parameterised queries.",
        "mitre": ["T1190"],
        "evidence": {"endpoint": "/search", "attack_id": "sqli-1"},
    },
    {
        "type": "missing_security_header",
        "severity": "info",
        "confidence": 0.6,
        "tier": "info",
        "exploit_like": False,
        "evidence": {"endpoint": "/"},
    },
    {"type": "adapter_error", "severity": "high", "internal": True},
]


def test_ingest_creates_structured_findings_and_graded_evidence():
    user = _user()
    scan = _scan(user, findings=ENGINE_FINDINGS)

    created = ingest.ingest_scan(scan)

    # The internal entry is skipped; two real findings land.
    assert len(created) == 2
    dep = Deployment.objects.get()
    assert dep.findings.count() == 2

    sqli = dep.findings.get(finding_type="sql_injection")
    assert sqli.severity == "critical"
    assert sqli.cvss_score == 9.8
    assert sqli.control_mapping.get("mitre") == ["T1190"]
    assert sqli.location == "/search"
    assert sqli.retest_required is True  # critical must be proven fixed
    # A confirmed, exploit-like finding is technically verified.
    assert sqli.evidence_class == EvidenceClass.TECHNICALLY_VERIFIED
    assert sqli.evidence.get().source == "engine_scan"

    note = dep.findings.get(finding_type="missing_security_header")
    assert note.severity == "info"
    assert note.retest_required is False
    # An informational, non-exploit observation is configuration verified.
    assert note.evidence_class == EvidenceClass.CONFIGURATION_VERIFIED


def test_ingest_is_idempotent_and_preserves_human_state():
    user = _user()
    scan = _scan(user, findings=ENGINE_FINDINGS)
    ingest.ingest_scan(scan)

    sqli = Finding.objects.get(finding_type="sql_injection")
    first_seen = sqli.first_seen
    # A human triages and assigns the finding.
    sqli.status = Finding.Status.TRIAGED
    sqli.owner = user
    sqli.save(update_fields=["status", "owner"])

    # Re-ingest the same scan (e.g. a re-scan of the same system).
    ingest.ingest_scan(scan)

    assert Finding.objects.filter(finding_type="sql_injection").count() == 1  # no duplicate
    sqli.refresh_from_db()
    assert sqli.status == Finding.Status.TRIAGED  # human state preserved
    assert sqli.owner == user
    assert sqli.first_seen == first_seen
    assert sqli.last_seen >= first_seen
    # Still one evidence row from the scan, not a second.
    assert sqli.evidence.filter(source="engine_scan").count() == 1


def test_same_engagement_maps_to_one_deployment():
    user = _user()
    eng = Engagement.objects.create(name="Acme AI", created_by=user, scope_hosts=["client.example"])
    ingest.ingest_scan(_scan(user, engagement=eng, findings=ENGINE_FINDINGS))
    ingest.ingest_scan(_scan(user, engagement=eng, findings=ENGINE_FINDINGS))
    assert Deployment.objects.filter(engagement=eng).count() == 1


def test_ingest_no_findings_returns_empty_and_creates_nothing():
    user = _user()
    assert ingest.ingest_scan(_scan(user, findings=None)) == []
    assert ingest.ingest_scan(_scan(user, findings=[])) == []
    assert Finding.objects.count() == 0
    # Absence of findings is never a clean bill: no Deployment is fabricated.
    assert Deployment.objects.count() == 0


def test_evidence_class_is_the_weakest_link():
    user = _user()
    dep = Deployment.objects.create(name="d", owner=user)
    f = Finding.objects.create(
        deployment=dep, fingerprint="fp1", finding_type="t", title="T", severity="high"
    )
    Evidence.objects.create(finding=f, classification=EvidenceClass.TECHNICALLY_VERIFIED)
    Evidence.objects.create(finding=f, classification=EvidenceClass.VENDOR_ASSERTED)
    # Weakest of the two wins (a chain is only as strong as its weakest link).
    assert f.evidence_class == EvidenceClass.VENDOR_ASSERTED
    assert evidence_strength(EvidenceClass.TECHNICALLY_VERIFIED) < evidence_strength(
        EvidenceClass.VENDOR_ASSERTED
    )


def test_evidence_class_defaults_unknown_with_no_evidence():
    user = _user()
    dep = Deployment.objects.create(name="d", owner=user)
    f = Finding.objects.create(
        deployment=dep, fingerprint="fp1", finding_type="t", title="T"
    )
    assert f.evidence_class == EvidenceClass.UNKNOWN.value
    assert f.status == Finding.Status.OPEN  # default lifecycle state


def test_deployment_supports_all_six_decision_states():
    user = _user()
    for state in Deployment.Decision.values:
        Deployment.objects.create(name=f"d-{state}", owner=user, decision=state)
    assert Deployment.objects.count() == 6
    assert set(Deployment.Decision.values) == {
        "ready",
        "ready_restricted",
        "needs_more_evidence",
        "needs_remediation",
        "not_recommended",
        "paused",
    }


# ---------------------------------------------------------------- API
def test_finding_api_patch_updates_status_but_not_engine_fields():
    user = _user()
    scan = _scan(user, findings=ENGINE_FINDINGS)
    ingest.ingest_scan(scan)
    sqli = Finding.objects.get(finding_type="sql_injection")

    factory = APIRequestFactory()
    view = FindingViewSet.as_view({"patch": "partial_update"})
    # Try to change both a workflow field (allowed) and severity (read-only).
    request = factory.patch(
        f"/api/assurance/findings/{sqli.uuid}/",
        {"status": "remediating", "severity": "low"},
        format="json",
    )
    force_authenticate(request, user=user)
    resp = view(request, uuid=str(sqli.uuid))
    assert resp.status_code == 200

    sqli.refresh_from_db()
    assert sqli.status == Finding.Status.REMEDIATING  # workflow field changed
    assert sqli.severity == "critical"  # engine field unchanged (read-only)


def test_finding_api_scopes_to_visible_findings():
    owner = _user("owner")
    stranger = _user("stranger")
    scan = _scan(owner, findings=ENGINE_FINDINGS)
    ingest.ingest_scan(scan)

    factory = APIRequestFactory()
    view = FindingViewSet.as_view({"get": "list"})

    # The stranger (analyst) is privileged in this project's model and sees all;
    # a viewer sees only their own. Use a viewer to prove scoping.
    viewer = _user("viewer", role=User.Roles.VIEWER)
    request = factory.get("/api/assurance/findings/")
    force_authenticate(request, user=viewer)
    resp = view(request)
    assert resp.status_code == 200
    # A viewer who owns no deployment and launched no scan sees nothing.
    assert resp.data["count"] == 0 if isinstance(resp.data, dict) else resp.data == []
