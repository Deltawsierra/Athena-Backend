"""Athena Phase 0.5 — a deployment's findings aggregate into its six-state decision.

Proves the decision precedence (paused > critical > high > medium/low >
needs-more-evidence > ready), that resolved findings stop counting, that
ingesting a scan refreshes the decision, and the recompute API action.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import ingest
from assurance.decision import compute_decision, recompute_decision
from assurance.models import Deployment, EvidenceClass, Evidence, Finding
from assurance.views import DeploymentViewSet
from pentest.models import PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _deployment(user):
    return Deployment.objects.create(name="Support Agent", owner=user)


def _finding(dep, severity, *, status=Finding.Status.OPEN, evidence_class=None, n="1"):
    f = Finding.objects.create(
        deployment=dep,
        fingerprint=f"fp-{severity}-{n}",
        finding_type="t",
        title="T",
        severity=severity,
        status=status,
    )
    if evidence_class is not None:
        Evidence.objects.create(finding=f, classification=evidence_class)
    return f


def test_decision_precedence_by_worst_active_severity():
    user = _user()
    dep = _deployment(user)
    assert compute_decision(dep) is None  # never assessed (no findings) → no decision

    _finding(dep, "low", n="lo")
    assert compute_decision(dep) == Deployment.Decision.READY_RESTRICTED

    _finding(dep, "high", n="hi")
    assert compute_decision(dep) == Deployment.Decision.NEEDS_REMEDIATION

    _finding(dep, "critical", n="cr")
    assert compute_decision(dep) == Deployment.Decision.NOT_RECOMMENDED


def test_paused_overrides_everything():
    user = _user()
    dep = _deployment(user)
    _finding(dep, "critical", n="cr")
    assert compute_decision(dep, paused=True) == Deployment.Decision.PAUSED


def test_resolved_findings_do_not_count():
    user = _user()
    dep = _deployment(user)
    _finding(dep, "critical", status=Finding.Status.CLOSED, n="cl")
    _finding(dep, "high", status=Finding.Status.ACCEPTED, n="ac")
    _finding(dep, "high", status=Finding.Status.FALSE_POSITIVE, n="fp")
    # All resolved → nothing active → READY.
    assert compute_decision(dep) == Deployment.Decision.READY


def test_unverified_only_needs_more_evidence():
    user = _user()
    dep = _deployment(user)
    # An info-severity finding whose evidence could not be verified.
    _finding(dep, "info", evidence_class=EvidenceClass.UNKNOWN, n="u")
    assert compute_decision(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE

    # A verified info observation alone is a clean pass.
    dep2 = _deployment(_user("a2"))
    _finding(dep2, "info", evidence_class=EvidenceClass.CONFIGURATION_VERIFIED, n="v")
    assert compute_decision(dep2) == Deployment.Decision.READY


def test_recompute_persists_and_reports_change():
    user = _user()
    dep = _deployment(user)
    _finding(dep, "high", n="hi")
    assert dep.decision is None
    decision = recompute_decision(dep)
    assert decision == Deployment.Decision.NEEDS_REMEDIATION
    dep.refresh_from_db()
    assert dep.decision == Deployment.Decision.NEEDS_REMEDIATION


def test_ingesting_a_scan_sets_the_deployment_decision():
    user = _user()
    scan = PentestScan.objects.create(
        user=user,
        target_url="https://app.example/login",
        consent=True,
        status=PentestScan.STATUS_COMPLETED,
        engine_response={
            "findings": [
                {"type": "sql_injection", "signature_id": "S1", "report_severity": "critical",
                 "confidence": 0.9, "signature_description": "SQLi"},
            ]
        },
    )
    ingest.ingest_scan(scan)
    dep = Deployment.objects.get()
    assert dep.decision == Deployment.Decision.NOT_RECOMMENDED


def test_recompute_api_action():
    # Recompute mutates the record, so it is admin-only.
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = _deployment(admin)
    _finding(dep, "medium", n="me")

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"post": "recompute"})
    request = factory.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {}, format="json")
    force_authenticate(request, user=admin)
    resp = view(request, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["decision"] == Deployment.Decision.READY_RESTRICTED

    # The paused override via the API.
    request2 = factory.post(
        f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json"
    )
    force_authenticate(request2, user=admin)
    resp2 = view(request2, uuid=str(dep.uuid))
    assert resp2.data["decision"] == Deployment.Decision.PAUSED


def test_recompute_preserves_an_operator_pause():
    """A routine recompute must not silently clear a failsafe pause. With the
    deployment already 'Deployment paused', a recompute with no body keeps it
    paused; only an explicit ``paused=false`` lifts it."""
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = _deployment(admin)
    _finding(dep, "medium", n="me")
    dep.decision = Deployment.Decision.PAUSED
    dep.save(update_fields=["decision"])

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"post": "recompute"})

    # No body: the pause is preserved, not recomputed away.
    req = factory.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {}, format="json")
    force_authenticate(req, user=admin)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["decision"] == Deployment.Decision.PAUSED
    dep.refresh_from_db()
    assert dep.decision == Deployment.Decision.PAUSED

    # Explicit paused=false lifts it and recomputes from findings.
    lift = factory.post(
        f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": False}, format="json"
    )
    force_authenticate(lift, user=admin)
    resp2 = view(lift, uuid=str(dep.uuid))
    assert resp2.data["decision"] == Deployment.Decision.READY_RESTRICTED


def test_recompute_form_encoded_paused_false_lifts_pause():
    """Regression (M1): a form-encoded ``paused=false`` sends the flag as the
    string ``"false"``. The old ``bool(request.data.get("paused"))`` read
    ``bool("false") == True`` and HELD the pause instead of lifting it — a
    safety-relevant control on the failsafe path. It must now lift the pause, and a
    bogus value must be a clean 400, never a silent hold."""
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = _deployment(admin)
    _finding(dep, "medium", n="me")
    dep.decision = Deployment.Decision.PAUSED
    dep.save(update_fields=["decision"])

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"post": "recompute"})

    # Form-encoded paused=false (a string) must LIFT the pause, not hold it.
    lift = factory.post(
        f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": "false"}, format="multipart"
    )
    force_authenticate(lift, user=admin)
    resp = view(lift, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["decision"] == Deployment.Decision.READY_RESTRICTED
    dep.refresh_from_db()
    assert dep.decision == Deployment.Decision.READY_RESTRICTED

    # A JSON boolean false lifts it too (parity with the form path).
    dep.decision = Deployment.Decision.PAUSED
    dep.save(update_fields=["decision"])
    jlift = factory.post(
        f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": False}, format="json"
    )
    force_authenticate(jlift, user=admin)
    jresp = view(jlift, uuid=str(dep.uuid))
    assert jresp.data["decision"] == Deployment.Decision.READY_RESTRICTED

    # Form-encoded paused=on / true HOLDS (sets) the pause.
    hold = factory.post(
        f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": "on"}, format="multipart"
    )
    force_authenticate(hold, user=admin)
    hresp = view(hold, uuid=str(dep.uuid))
    assert hresp.data["decision"] == Deployment.Decision.PAUSED

    # A bogus value is a clean 400, never a guessed hold or lift.
    bogus = factory.post(
        f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": "maybe"}, format="multipart"
    )
    force_authenticate(bogus, user=admin)
    bresp = view(bogus, uuid=str(dep.uuid))
    assert bresp.status_code == 400


def test_recompute_denied_to_non_admin():
    """A non-admin can read the graph but may not mutate the decision."""
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = _deployment(analyst)
    _finding(dep, "medium", n="me")

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"post": "recompute"})
    request = factory.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {}, format="json")
    force_authenticate(request, user=analyst)
    resp = view(request, uuid=str(dep.uuid))
    assert resp.status_code == 403
