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


# A realistic engine response in the engine's OWN vocabulary (the same keys the
# PDF renderer reads): a substantive signature finding, an informational note,
# and one internal (adapter-error) entry that must be ignored.
ENGINE_FINDINGS = [
    {
        "type": "sql_injection",
        "signature_id": "SQLI-001",
        "report_severity": "critical",
        "confidence": 0.95,
        "cvss_score": 9.8,
        "cvss_vector": "AV:N/AC:L",
        "signature_description": "SQL injection in the search parameter",
        "signature_recommendation": "Use parameterised queries.",
        "explanation": "An attacker can read or modify the backing database.",
    },
    {
        "type": "missing_security_header",
        "signature_id": "HDR-014",
        "severity": "info",
        "confidence": 0.6,
        "signature_description": "Missing Content-Security-Policy header",
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
    # Title, recommendation, and impact come from the engine's real fields.
    assert sqli.title == "SQL injection in the search parameter"
    assert sqli.recommendation == "Use parameterised queries."
    assert sqli.impact == "An attacker can read or modify the backing database."
    assert sqli.retest_required is True  # critical must be proven fixed
    # A passive signature scan observes, it does not prove an exploit, so a
    # substantive finding is partially verified — never technically verified.
    assert sqli.evidence_class == EvidenceClass.PARTIALLY_VERIFIED
    assert sqli.evidence.get().source == "engine_scan"
    assert sqli.evidence.get().raw.get("signature_id") == "SQLI-001"

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


def _scan_at(user, target_url, engagement=None, findings=None):
    return PentestScan.objects.create(
        user=user,
        target_url=target_url,
        consent=True,
        status=PentestScan.STATUS_COMPLETED,
        engagement=engagement,
        engine_response={"findings": findings} if findings is not None else None,
    )


def test_same_engagement_and_host_maps_to_one_deployment():
    user = _user()
    eng = Engagement.objects.create(name="Acme AI", created_by=user, scope_hosts=["client.example"])
    url = "https://app.client.example/login"
    ingest.ingest_scan(_scan_at(user, url, engagement=eng, findings=ENGINE_FINDINGS))
    ingest.ingest_scan(_scan_at(user, url, engagement=eng, findings=ENGINE_FINDINGS))
    # Same engagement AND same host → one deployment, re-scan updates it.
    assert Deployment.objects.filter(engagement=eng).count() == 1


def test_distinct_hosts_in_one_engagement_are_distinct_deployments():
    """A multi-host engagement must not blend two systems into one Deployment."""
    user = _user()
    eng = Engagement.objects.create(
        name="Acme AI", created_by=user, scope_hosts=["api.client.example", "admin.client.example"]
    )
    ingest.ingest_scan(_scan_at(user, "https://api.client.example/", engagement=eng, findings=ENGINE_FINDINGS))
    ingest.ingest_scan(_scan_at(user, "https://admin.client.example/", engagement=eng, findings=ENGINE_FINDINGS))
    assert Deployment.objects.filter(engagement=eng).count() == 2


def test_non_numeric_cvss_does_not_abort_ingestion():
    """A bad cvss_score on one finding must not raise and drop the whole scan."""
    user = _user()
    findings = [
        {"type": "sql_injection", "signature_id": "S1", "report_severity": "critical",
         "cvss_score": "N/A", "signature_description": "SQLi"},
        {"type": "xss", "signature_id": "S2", "report_severity": "high",
         "cvss_score": 7.5, "signature_description": "XSS"},
    ]
    created = ingest.ingest_scan(_scan(user, findings=findings))
    assert len(created) == 2  # both persisted; the bad cvss became absent, not an abort
    dep = Deployment.objects.get()
    assert dep.findings.get(finding_type="sql_injection").cvss_score is None
    assert dep.findings.get(finding_type="xss").cvss_score == 7.5
    assert dep.decision == Deployment.Decision.NOT_RECOMMENDED  # decision still computed


def test_locationless_findings_of_same_type_do_not_collide():
    """Two distinct findings of one type must not overwrite each other on the key."""
    user = _user()
    findings = [
        {"type": "misconfiguration", "report_severity": "high",
         "signature_description": "Weak TLS on the gateway"},
        {"type": "misconfiguration", "report_severity": "critical",
         "signature_description": "Debug endpoint exposed"},
    ]
    created = ingest.ingest_scan(_scan(user, findings=findings))
    assert len(created) == 2
    assert Deployment.objects.get().findings.count() == 2  # not collapsed to one


def test_same_signature_id_dedupes_across_rescans():
    user = _user()
    f = [{"type": "sql_injection", "signature_id": "SQLI-9", "report_severity": "high",
          "signature_description": "SQLi"}]
    ingest.ingest_scan(_scan(user, findings=f))
    ingest.ingest_scan(_scan(user, findings=f))
    assert Finding.objects.filter(finding_type="sql_injection").count() == 1


def test_unrecognised_severity_is_normalised_not_stored_verbatim():
    user = _user()
    findings = [{"type": "note", "report_severity": "informational", "signature_id": "N1",
                 "signature_description": "note"}]
    ingest.ingest_scan(_scan(user, findings=findings))
    assert Finding.objects.get().severity == "info"  # normalised into SEVERITY_ORDER


def test_paused_decision_survives_reingest():
    """An operator's failsafe pause is not silently cleared by an automated re-ingest."""
    user = _user()
    scan = _scan(user, findings=ENGINE_FINDINGS)
    ingest.ingest_scan(scan)
    dep = Deployment.objects.get()
    dep.decision = Deployment.Decision.PAUSED
    dep.save(update_fields=["decision"])

    ingest.ingest_scan(scan)  # a re-scan lands
    dep.refresh_from_db()
    assert dep.decision == Deployment.Decision.PAUSED  # still paused


def test_ingest_with_nothing_reported_creates_nothing():
    """No response and no findings list mean *nothing was reported*.

    There is nothing to ingest and no basis to score anything, so no Deployment
    is fabricated: absence of a result is never a clean bill.
    """
    user = _user()
    assert ingest.ingest_scan(_scan(user, findings=None)) == []
    assert Finding.objects.count() == 0
    assert Deployment.objects.count() == 0


def test_ingest_of_a_reported_zero_is_a_real_clean_result():
    """`findings: []` is the engine saying it looked and found nothing.

    That is a result -- the best one a customer can get -- and it used to be
    dropped on the same line as "no response at all": the deployment was never
    created, the register never refreshed, the decision never computed. A clean
    scan was indistinguishable from a scan that never arrived.
    """
    user = _user()
    assert ingest.ingest_scan(_scan(user, findings=[])) == []
    assert Finding.objects.count() == 0, "a clean scan invents no findings"

    deployment = Deployment.objects.get()
    assert deployment.decision == Deployment.Decision.READY
    assert deployment.evidence_incomplete is False


def test_a_scan_the_engine_stopped_early_is_not_ready():
    """The engine marks a stopped run with an internal `scan_incomplete` row.

    Internal rows are exactly what the ingest filters out, so a scan the operator
    stopped arrived here as a findings list of length zero and scored READY. The
    scanners that did not run are the ones that would have found the rest.
    """
    user = _user()
    stopped = _scan(
        user,
        findings=[{
            "type": "scan_incomplete",
            "message": "Scan stopped before it finished",
            "severity": "info",
            "internal": True,
        }],
    )
    assert PentestScan.scan_was_incomplete(stopped.engine_response) is True
    assert PentestScan.derive_verdict(stopped.engine_response) is None, (
        "a stopped run has no verdict; null is not READY"
    )

    assert ingest.ingest_scan(stopped) == []
    deployment = Deployment.objects.get()
    assert deployment.evidence_incomplete is True
    assert deployment.decision == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_a_later_complete_scan_clears_the_incomplete_evidence_cap():
    """The cap is a statement about the latest evidence, not a permanent mark."""
    user = _user()
    ingest.ingest_scan(
        _scan(user, findings=[{"type": "scan_incomplete", "severity": "info", "internal": True}])
    )
    deployment = Deployment.objects.get()
    assert deployment.evidence_incomplete is True

    ingest.ingest_scan(_scan(user, findings=[]), deployment=deployment)
    deployment.refresh_from_db()
    assert deployment.evidence_incomplete is False
    assert deployment.decision == Deployment.Decision.READY


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
    # A finding PATCH mutates the record, so it is admin-only.
    admin = _user("boss", role=User.Roles.ADMIN)
    scan = _scan(admin, findings=ENGINE_FINDINGS)
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
    force_authenticate(request, user=admin)
    resp = view(request, uuid=str(sqli.uuid))
    assert resp.status_code == 200

    sqli.refresh_from_db()
    assert sqli.status == Finding.Status.REMEDIATING  # workflow field changed
    assert sqli.severity == "critical"  # engine field unchanged (read-only)


def test_finding_api_patch_denied_to_non_admin():
    """A non-admin may read findings but not mutate them (open reads, admin writes)."""
    analyst = _user("ana", role=User.Roles.ANALYST)
    scan = _scan(analyst, findings=ENGINE_FINDINGS)
    ingest.ingest_scan(scan)
    sqli = Finding.objects.get(finding_type="sql_injection")

    factory = APIRequestFactory()
    view = FindingViewSet.as_view({"patch": "partial_update"})
    request = factory.patch(
        f"/api/assurance/findings/{sqli.uuid}/", {"status": "remediating"}, format="json"
    )
    force_authenticate(request, user=analyst)
    resp = view(request, uuid=str(sqli.uuid))
    assert resp.status_code == 403
    sqli.refresh_from_db()
    assert sqli.status == Finding.Status.OPEN  # unchanged


def test_finding_owner_serialized_as_username_not_id():
    """The owner column is a username, not a raw user id (meaningless to a reader)."""
    admin = _user("boss", role=User.Roles.ADMIN)
    scan = _scan(admin, findings=ENGINE_FINDINGS)
    ingest.ingest_scan(scan)
    sqli = Finding.objects.get(finding_type="sql_injection")

    factory = APIRequestFactory()
    detail = FindingViewSet.as_view({"get": "retrieve", "patch": "partial_update"})
    # Assign an owner by username, then read it back as a username.
    request = factory.patch(
        f"/api/assurance/findings/{sqli.uuid}/", {"owner": "boss"}, format="json"
    )
    force_authenticate(request, user=admin)
    resp = detail(request, uuid=str(sqli.uuid))
    assert resp.status_code == 200
    assert resp.data["owner"] == "boss"  # username, not the integer pk


def test_finding_api_malformed_deployment_filter_is_not_a_500():
    """A bad ?deployment= uuid must yield an empty result, not an uncaught 500."""
    admin = _user("boss", role=User.Roles.ADMIN)
    scan = _scan(admin, findings=ENGINE_FINDINGS)
    ingest.ingest_scan(scan)

    factory = APIRequestFactory()
    view = FindingViewSet.as_view({"get": "list"})
    request = factory.get("/api/assurance/findings/?deployment=not-a-uuid")
    force_authenticate(request, user=admin)
    resp = view(request)
    assert resp.status_code == 200
    count = resp.data["count"] if isinstance(resp.data, dict) else len(resp.data)
    assert count == 0


def test_finding_api_scopes_to_visible_findings():
    owner = _user("owner")
    scan = _scan(owner, findings=ENGINE_FINDINGS)
    ingest.ingest_scan(scan)

    factory = APIRequestFactory()
    view = FindingViewSet.as_view({"get": "list"})

    # An analyst is privileged in this project's model and sees all findings;
    # a viewer sees only their own. Use a viewer to prove scoping.
    viewer = _user("viewer", role=User.Roles.VIEWER)
    request = factory.get("/api/assurance/findings/")
    force_authenticate(request, user=viewer)
    resp = view(request)
    assert resp.status_code == 200
    # A viewer who owns no deployment and launched no scan sees nothing.
    assert resp.data["count"] == 0 if isinstance(resp.data, dict) else resp.data == []
