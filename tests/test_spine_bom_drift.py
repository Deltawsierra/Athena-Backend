"""SPINE Stage 3 — declared-vs-observed AI-BOM drift → findings + invalidation.

Proves the drift engine is honest and closes the loop:

- assess_bom_drift compares the declared architecture to the observed AI-BOM:
  undeclared (shadow) components and providers are drift; declared-not-observed is
  surfaced softly; with NO declaration there is no drift to compute (never a pass);
- record_bom_drift_findings turns drift into managed findings idempotently — a
  re-record opens no duplicate, a cleared drift auto-closes, a returned drift
  re-opens a machine-closed finding, and a human's disposition is never clobbered;
- an undeclared component CONTRADICTS the AI-BOM claim (the deferred CONTRADICTED
  path), which via Stage 1C lowers the decision and via Stage 1D lands in the
  revalidation plan;
- with no declaration the AI-BOM claim behaves exactly as before (backward
  compatible);
- the endpoints return 200 and enforce admin on the writes.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.bom_drift import assess_bom_drift, record_bom_drift_findings
from assurance.claims import derive_claims
from assurance.decision import compute_decision
from assurance.models import (
    Asset,
    AssuranceClaim,
    DeclaredComponent,
    Deployment,
    EvidenceClass,
    Finding,
    Provider,
    ProviderAssertion,
)
from assurance.revalidation import plan_revalidation
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType
Decision = Deployment.Decision
Kind = Asset.Kind


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _provider(name="OpenAI", region="eu"):
    p = Provider.objects.create(name=name, kind=Provider.Kind.MODEL_PROVIDER)
    ProviderAssertion.objects.create(
        provider=p, field="region", value=region, evidence_class=EvidenceClass.CONFIGURATION_VERIFIED
    )
    return p


def _asset(dep, *, kind=Kind.TOOL, name="t", identifier=None, provider=None, classification=Asset.Classification.KNOWN):
    return Asset.objects.create(
        deployment=dep, kind=kind, name=name, identifier=identifier or name,
        provider=provider, classification=classification,
    )


def _declared(dep, *, kind=Kind.TOOL, name="t", identifier=None, provider_name=""):
    return DeclaredComponent.objects.create(
        deployment=dep, kind=kind, name=name, identifier=identifier or name, provider_name=provider_name
    )


# ---------------------------------------------------------------------------
# assess_bom_drift
# ---------------------------------------------------------------------------


def test_no_declaration_means_no_drift_to_compute():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Kind.TOOL, name="search")
    d = assess_bom_drift(dep)
    assert d["has_declared"] is False
    assert d["drift_detected"] is False
    assert "not a clean bill of materials" in d["note"]


def test_declaration_matching_observed_has_no_drift():
    dep = Deployment.objects.create(name="d", owner=_user())
    _declared(dep, kind=Kind.TOOL, name="search", identifier="search")
    _asset(dep, kind=Kind.TOOL, name="search", identifier="search")
    d = assess_bom_drift(dep)
    assert d["has_declared"] is True
    assert d["drift_detected"] is False
    assert d["summary"]["matched"] == 1


def test_undeclared_component_is_drift_with_severity_by_kind():
    dep = Deployment.objects.create(name="d", owner=_user())
    _declared(dep, kind=Kind.TOOL, name="search", identifier="search")
    _asset(dep, kind=Kind.TOOL, name="search", identifier="search")  # matches
    _asset(dep, kind=Kind.MCP_SERVER, name="shadow-mcp", identifier="shadow-mcp")  # undeclared, high
    d = assess_bom_drift(dep)
    assert d["drift_detected"] is True
    assert d["summary"]["undeclared"] == 1
    assert d["undeclared"][0]["name"] == "shadow-mcp"
    assert d["undeclared"][0]["severity"] == "high"  # an MCP server is high


def test_undeclared_tool_is_medium():
    dep = Deployment.objects.create(name="d", owner=_user())
    _declared(dep, kind=Kind.MODEL, name="m", identifier="m")
    _asset(dep, kind=Kind.TOOL, name="extra-tool", identifier="extra-tool")
    d = assess_bom_drift(dep)
    assert d["undeclared"][0]["severity"] == "medium"


def test_declared_not_observed_is_missing_not_drift():
    dep = Deployment.objects.create(name="d", owner=_user())
    _declared(dep, kind=Kind.TOOL, name="retired", identifier="retired")
    d = assess_bom_drift(dep)
    assert d["summary"]["missing"] == 1
    # missing alone (no undeclared) is not the drift signal that contradicts the BOM
    assert d["drift_detected"] is False


def test_undeclared_provider_is_drift():
    dep = Deployment.objects.create(name="d", owner=_user())
    _declared(dep, kind=Kind.MODEL, name="m", identifier="m", provider_name="OpenAI")
    _asset(dep, kind=Kind.MODEL, name="m", identifier="m", provider=_provider("Anthropic"))  # matches component, drifts provider
    d = assess_bom_drift(dep)
    assert d["summary"]["undeclared"] == 0  # the component matches
    assert d["undeclared_providers"] == ["Anthropic"]
    assert d["drift_detected"] is True


def test_provider_drift_needs_a_declared_provider_baseline():
    dep = Deployment.objects.create(name="d", owner=_user())
    _declared(dep, kind=Kind.MODEL, name="m", identifier="m")  # no provider_name declared
    _asset(dep, kind=Kind.MODEL, name="m", identifier="m", provider=_provider("Anthropic"))
    d = assess_bom_drift(dep)
    # No declared provider baseline → we cannot single out a vendor as undeclared.
    assert d["undeclared_providers"] == []
    assert d["drift_detected"] is False


# ---------------------------------------------------------------------------
# record_bom_drift_findings — idempotent, non-destructive
# ---------------------------------------------------------------------------


def _drift_dep():
    dep = Deployment.objects.create(name="d", owner=_user())
    _declared(dep, kind=Kind.TOOL, name="search", identifier="search")
    _asset(dep, kind=Kind.TOOL, name="search", identifier="search")
    _asset(dep, kind=Kind.TOOL, name="shadow", identifier="shadow")  # undeclared
    return dep


def test_drift_creates_a_finding_then_is_idempotent():
    dep = _drift_dep()
    c1 = record_bom_drift_findings(dep)
    assert c1["created"] == 1 and c1["drift_detected"] is True
    f = dep.findings.get(finding_type="bom_drift.undeclared_component")
    assert f.severity == "medium" and f.status == Finding.Status.OPEN

    c2 = record_bom_drift_findings(dep)
    assert c2["created"] == 0 and c2["updated"] == 1
    assert dep.findings.filter(finding_type__startswith="bom_drift.").count() == 1


def test_cleared_drift_auto_closes_then_returns_reopens():
    dep = _drift_dep()
    record_bom_drift_findings(dep)
    f = dep.findings.get(finding_type="bom_drift.undeclared_component")

    # Declare the shadow tool: drift clears, finding auto-closes.
    _declared(dep, kind=Kind.TOOL, name="shadow", identifier="shadow")
    c = record_bom_drift_findings(dep)
    assert c["resolved"] == 1
    f.refresh_from_db()
    assert f.status == Finding.Status.CLOSED
    assert f.raw.get("auto_resolved") is True

    # Undeclare it again: drift returns, the machine-closed finding re-opens.
    DeclaredComponent.objects.filter(deployment=dep, identifier="shadow").delete()
    c = record_bom_drift_findings(dep)
    assert c["reopened"] == 1
    f.refresh_from_db()
    assert f.status == Finding.Status.OPEN


def test_human_disposition_is_never_clobbered():
    dep = _drift_dep()
    record_bom_drift_findings(dep)
    f = dep.findings.get(finding_type="bom_drift.undeclared_component")
    f.status = Finding.Status.ACCEPTED  # a human accepts the shadow tool as a risk
    f.save()

    # Drift clears — a human-accepted finding must NOT be auto-closed/changed.
    _declared(dep, kind=Kind.TOOL, name="shadow", identifier="shadow")
    c = record_bom_drift_findings(dep)
    assert c["resolved"] == 0
    f.refresh_from_db()
    assert f.status == Finding.Status.ACCEPTED


def test_missing_declared_records_a_low_finding():
    dep = Deployment.objects.create(name="d", owner=_user())
    _declared(dep, kind=Kind.TOOL, name="retired", identifier="retired")
    record_bom_drift_findings(dep)
    f = dep.findings.get(finding_type="bom_drift.declared_not_observed")
    assert f.severity == "low"


# ---------------------------------------------------------------------------
# Invalidation: the AI-BOM claim is CONTRADICTED by drift
# ---------------------------------------------------------------------------


def test_drift_contradicts_the_ai_bom_claim():
    dep = Deployment.objects.create(name="d", owner=_user())
    _declared(dep, kind=Kind.MODEL, name="m", identifier="m")
    _asset(dep, kind=Kind.MODEL, name="m", identifier="m", provider=_provider())
    _asset(dep, kind=Kind.TOOL, name="shadow", identifier="shadow")  # undeclared → drift
    derive_claims(dep)
    bom = AssuranceClaim.objects.get(deployment=dep, claim_type=ClaimType.AI_BOM, valid_to__isnull=True)
    assert bom.status == Status.CONTRADICTED
    assert bom.confidence is None  # a false completeness claim has no supporting confidence


def test_no_declaration_leaves_ai_bom_claim_uncontradicted():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Kind.MODEL, name="m", identifier="m", provider=_provider())
    derive_claims(dep)
    bom = AssuranceClaim.objects.get(deployment=dep, claim_type=ClaimType.AI_BOM, valid_to__isnull=True)
    assert bom.status in (Status.SUPPORTED, Status.UNKNOWN)  # never CONTRADICTED without a declaration


def test_drift_lowers_the_decision_and_lands_in_the_revalidation_plan():
    dep = Deployment.objects.create(name="d", owner=_user())
    _declared(dep, kind=Kind.MODEL, name="m", identifier="m")
    _asset(dep, kind=Kind.MODEL, name="m", identifier="m", provider=_provider())
    _asset(dep, kind=Kind.TOOL, name="shadow", identifier="shadow")
    derive_claims(dep)
    # Stage 1C: a contradicted AI-BOM claim caps the decision at needs_remediation.
    assert compute_decision(dep) == Decision.NEEDS_REMEDIATION
    # Stage 1D: the contradicted claim is in the revalidation plan.
    plan = plan_revalidation(dep)
    assert any(w["claim_type"] == ClaimType.AI_BOM for w in plan["required"])


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


def test_declared_architecture_put_is_admin_only_and_get_returns_drift():
    admin = _user("boss", role=User.Roles.ADMIN)
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=admin)
    _asset(dep, kind=Kind.TOOL, name="shadow", identifier="shadow")
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "declared_architecture", "put": "declared_architecture"})

    body = [{"kind": "tool", "name": "search", "identifier": "search"}]
    denied = factory.put("/x/", body, format="json")
    force_authenticate(denied, user=analyst)
    assert view(denied, uuid=str(dep.uuid)).status_code == 403

    ok = factory.put("/x/", body, format="json")
    force_authenticate(ok, user=admin)
    resp = view(ok, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert len(resp.data["declared"]) == 1
    # "search" declared, "shadow" observed → drift.
    assert resp.data["drift"]["drift_detected"] is True

    got = factory.get("/x/")
    force_authenticate(got, user=admin)
    gresp = view(got, uuid=str(dep.uuid))
    assert gresp.status_code == 200
    assert gresp.data["drift"]["summary"]["undeclared"] == 1


def test_record_bom_drift_endpoint_is_admin_only():
    admin = _user("boss", role=User.Roles.ADMIN)
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = _drift_dep()
    dep.owner = admin
    dep.save()
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"post": "record_bom_drift"})

    denied = factory.post("/x/")
    force_authenticate(denied, user=analyst)
    assert view(denied, uuid=str(dep.uuid)).status_code == 403

    ok = factory.post("/x/")
    force_authenticate(ok, user=admin)
    resp = view(ok, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["created"] == 1
    assert resp.data["drift_detected"] is True
