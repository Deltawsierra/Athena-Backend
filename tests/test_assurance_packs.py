"""Athena — Vertical Assurance Packs.

Proves the packs are a data-driven, code-only lens over the compliance map: the
catalog is present and names only the framework identifiers compliance.py already
defines (no redefined catalog); applying a pack filters the compliance map to the
pack's frameworks and reports coverage honestly (a touched control is a gap, never
"passed"); regulatory regimes are carried as context, not computed coverage; an
unknown pack key raises a clear error and the API returns a clean 400; the output
is deterministic; and the reads are open to any operator.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import compliance
from assurance.models import Deployment, Finding
from assurance.packs import UnknownPack, apply_pack, list_packs
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()

_EXPECTED_KEYS = {"healthcare", "financial-services", "federal", "general-ai"}
_KNOWN_FRAMEWORKS = {
    compliance.FRAMEWORK_NIST,
    compliance.FRAMEWORK_OWASP,
    compliance.FRAMEWORK_OWASP_LLM,
    compliance.FRAMEWORK_DOD_ZT,
}


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _finding(dep, finding_type, severity="high", *, status=Finding.Status.OPEN, n="1"):
    return Finding.objects.create(
        deployment=dep, fingerprint=f"fp-{finding_type}-{n}", finding_type=finding_type,
        title=finding_type, severity=severity, status=status,
    )


def test_catalog_covers_the_required_verticals():
    packs = {p["key"]: p for p in list_packs()["packs"]}
    assert _EXPECTED_KEYS <= set(packs)
    assert list_packs()["summary"]["packs"] == len(packs)
    # Each pack carries its identity fields.
    for pack in packs.values():
        assert pack["name"] and pack["vertical"] and pack["description"]
        assert isinstance(pack["evidence_expectations"], list) and pack["evidence_expectations"]


def test_packs_reuse_only_compliance_framework_identifiers():
    # No pack may name a framework the compliance map does not define — the catalog
    # is reused, never redefined.
    for pack in list_packs()["packs"]:
        assert set(pack["frameworks"]) <= _KNOWN_FRAMEWORKS
        assert set(pack["framework_names"]) == set(pack["frameworks"])


def test_named_regimes_match_the_roadmap():
    packs = {p["key"]: p for p in list_packs()["packs"]}
    assert "HIPAA" in packs["healthcare"]["regulatory_regimes"]
    assert {"PCI-DSS", "SOX"} <= set(packs["financial-services"]["regulatory_regimes"])
    assert "FedRAMP" in packs["federal"]["regulatory_regimes"]
    assert "NIST AI RMF" in packs["general-ai"]["regulatory_regimes"]
    # DoD Zero Trust is a computed framework for federal, not just a named regime.
    assert compliance.FRAMEWORK_DOD_ZT in packs["federal"]["frameworks"]


def test_apply_pack_filters_to_the_packs_frameworks():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "prompt_injection", "high")

    result = apply_pack(dep, "general-ai")
    keys = {fw["key"] for fw in result["frameworks"]}
    # general-ai emphasizes OWASP LLM + OWASP; NIST/DoD are filtered out of the view.
    assert keys <= {compliance.FRAMEWORK_OWASP_LLM, compliance.FRAMEWORK_OWASP}
    assert compliance.FRAMEWORK_NIST not in keys
    assert result["summary"]["frameworks_emphasized"] == len(result["frameworks"])


def test_touched_control_is_a_gap_never_passed():
    dep = Deployment.objects.create(name="d", owner=_user())
    # prompt_injection touches OWASP LLM01 — an OPEN finding against it.
    _finding(dep, "prompt_injection", "high")

    result = apply_pack(dep, "general-ai")
    assert result["summary"]["controls_with_active_findings"] >= 1
    assert result["summary"]["worst_severity"] == "high"
    # No control in the view reads as passed/compliant; each is a touched control.
    for fw in result["frameworks"]:
        for control in fw["controls"]:
            assert "passed" not in control and "compliant" not in control
            assert control["active_finding_count"] >= 0
    # The pack itself never claims compliance.
    assert "compliant" not in result["summary"]


def test_resolved_finding_is_not_an_active_gap():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "prompt_injection", "critical", status=Finding.Status.CLOSED)

    result = apply_pack(dep, "general-ai")
    assert result["summary"]["controls_with_active_findings"] == 0
    assert result["summary"]["worst_severity"] is None
    assert result["summary"]["active_findings"] == 0
    assert result["summary"]["resolved_findings"] == 1


def test_regulatory_regimes_are_context_not_computed_coverage():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "sql_injection", "high")

    result = apply_pack(dep, "healthcare")
    regimes = {r["name"]: r for r in result["regulatory_regimes"]}
    assert "HIPAA" in regimes
    # HIPAA is carried as context with an explicit note — never scored as controls.
    assert "context" in regimes["HIPAA"]["note"].lower()
    computed_keys = {fw["key"] for fw in result["frameworks"]}
    assert "HIPAA" not in computed_keys


def test_unknown_pack_key_raises_and_api_returns_400():
    dep = Deployment.objects.create(name="d", owner=_user())
    with pytest.raises(UnknownPack):
        apply_pack(dep, "not-a-real-pack")

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "assurance_pack"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/assurance-packs/not-a-real-pack/")
    force_authenticate(req, user=dep.owner)
    resp = view(req, uuid=str(dep.uuid), pack="not-a-real-pack")
    assert resp.status_code == 400
    assert "Unknown assurance pack" in resp.data["detail"]


def test_apply_pack_is_deterministic():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "prompt_injection", "high", n="a")
    _finding(dep, "sql_injection", "medium", n="b")
    assert apply_pack(dep, "general-ai") == apply_pack(dep, "general-ai")


def test_empty_deployment_is_honest_empty_coverage():
    dep = Deployment.objects.create(name="d", owner=_user())
    result = apply_pack(dep, "federal")
    assert result["summary"]["controls_touched"] == 0
    assert result["summary"]["controls_with_active_findings"] == 0
    assert result["summary"]["worst_severity"] is None
    assert result["summary"]["total_findings"] == 0


def test_packs_catalog_api_is_open_to_any_operator():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "assurance_packs"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/assurance-packs/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert {p["key"] for p in resp.data["packs"]} >= _EXPECTED_KEYS


def test_apply_pack_api_returns_200_and_expected_shape():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    _finding(dep, "prompt_injection", "high")

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "assurance_pack"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/assurance-packs/general-ai/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid), pack="general-ai")
    assert resp.status_code == 200
    assert resp.data["pack"]["key"] == "general-ai"
    assert set(resp.data) == {"pack", "frameworks", "regulatory_regimes", "summary"}
