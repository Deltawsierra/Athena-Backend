"""Athena Phase 1.3 — AI System Capability Map.

Proves the capability map is the honest ground truth of what a deployment can
*do*, derived from the asset graph and the declared tool permission map: an
asset kind confers a capability, a tool's declared permissions surface sensitive
powers (code execution, network, money movement) on their own, a power evidenced
only by an unmanaged component is a shadow capability with its risk raised, and
the API read is open to any operator. Nothing is invented that discovery did not
record.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import capability
from assurance.capability import RISK_ELEVATED, RISK_HIGH, assess_capabilities
from assurance.models import Asset, Deployment
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _asset(dep, *, kind, classification=Asset.Classification.KNOWN, name="c", identifier=None, metadata=None):
    return Asset.objects.create(
        deployment=dep, kind=kind, classification=classification,
        name=name, identifier=identifier or name, metadata=metadata or {},
    )


def _caps_by_key(result):
    return {c["key"]: c for c in result["capabilities"]}


def test_asset_kinds_confer_their_capabilities():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.MODEL, name="gpt-x")
    _asset(dep, kind=Asset.Kind.VECTOR_DB, name="pinecone")
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant")

    caps = _caps_by_key(assess_capabilities(dep))
    assert "model_inference" in caps
    assert "retrieval" in caps
    # The agent's power is autonomous action, and it is elevated by default.
    assert caps["autonomous_action"]["risk"] == RISK_ELEVATED
    assert caps["model_inference"]["sources"][0]["asset_name"] == "gpt-x"


def test_declared_tool_permissions_surface_sensitive_capabilities():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(
        dep, kind=Asset.Kind.TOOL, name="shell-tool", classification=Asset.Classification.APPROVED,
        metadata={"declared": True, "permissions": ["exec", "network:http"]},
    )

    caps = _caps_by_key(assess_capabilities(dep))
    # Code execution is high risk and names the permission it came from.
    assert caps["code_execution"]["risk"] == RISK_HIGH
    assert any("exec" in s["detail"] for s in caps["code_execution"]["sources"])
    # Network access is surfaced separately.
    assert "network_access" in caps
    # A declared, managed tool → the capability is declared, not shadow.
    assert caps["code_execution"]["declared"] is True
    assert caps["code_execution"]["shadow"] is False


def test_money_movement_is_a_high_risk_capability():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(
        dep, kind=Asset.Kind.TOOL, name="billing", classification=Asset.Classification.KNOWN,
        metadata={"permissions": ["create_payment", "refund"]},
    )
    caps = _caps_by_key(assess_capabilities(dep))
    assert caps["financial_action"]["risk"] == RISK_HIGH


def test_capability_from_an_unmanaged_component_is_a_shadow_capability():
    dep = Deployment.objects.create(name="d", owner=_user())
    # A shadow MCP server nobody declared: unmanaged classification.
    _asset(
        dep, kind=Asset.Kind.MCP_SERVER, name="rogue-mcp",
        classification=Asset.Classification.UNMANAGED, identifier="mcp://rogue",
    )
    result = assess_capabilities(dep)
    cap = _caps_by_key(result)["external_tool_access"]
    assert cap["shadow"] is True
    assert cap["declared"] is False
    # Base risk (elevated) is raised one band because it is a shadow capability.
    assert cap["risk"] == RISK_HIGH
    assert result["summary"]["shadow"] == 1


def test_same_capability_from_two_assets_merges_with_both_sources():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.TOOL, name="tool-a", identifier="a")
    _asset(dep, kind=Asset.Kind.TOOL, name="tool-b", identifier="b")
    caps = _caps_by_key(assess_capabilities(dep))
    names = {s["asset_name"] for s in caps["tool_invocation"]["sources"]}
    assert names == {"tool-a", "tool-b"}


def test_a_managed_source_keeps_a_capability_out_of_the_shadow():
    dep = Deployment.objects.create(name="d", owner=_user())
    # Two tools grant network access: one declared, one shadow. The managed one
    # keeps the *capability* out of the shadow, but both are recorded.
    _asset(dep, kind=Asset.Kind.TOOL, name="declared", classification=Asset.Classification.APPROVED,
           identifier="d1", metadata={"permissions": ["network"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="rogue", classification=Asset.Classification.UNMANAGED,
           identifier="d2", metadata={"permissions": ["network"]})
    cap = _caps_by_key(assess_capabilities(dep))["network_access"]
    assert cap["shadow"] is False
    assert cap["declared"] is True
    assert len(cap["sources"]) == 2


def test_summary_and_category_rollup():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.MODEL, name="m")  # baseline cognition
    _asset(dep, kind=Asset.Kind.TOOL, name="t", metadata={"permissions": ["exec"]})  # high execution
    result = assess_capabilities(dep)
    assert result["summary"]["total"] >= 3
    assert result["summary"]["high_risk"] >= 1
    # The most-concerning capability leads the sorted list.
    assert result["capabilities"][0]["risk"] == RISK_HIGH
    # Categories roll up with their worst risk.
    execution = next(c for c in result["categories"] if c["category"] == "execution")
    assert execution["max_risk"] == RISK_HIGH


def test_empty_deployment_is_an_honest_empty_map():
    dep = Deployment.objects.create(name="d", owner=_user())
    result = assess_capabilities(dep)
    assert result["capabilities"] == []
    assert result["summary"]["total"] == 0


def test_permission_matching_is_case_insensitive_and_substringy():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.TOOL, name="fs", metadata={"permissions": ["FileSystem:READ"]})
    caps = _caps_by_key(assess_capabilities(dep))
    assert "filesystem_access" in caps


def test_capabilities_api_is_open_to_any_operator():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    _asset(dep, kind=Asset.Kind.MODEL, name="m")

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "capabilities"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/capabilities/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["summary"]["total"] == 1
    assert resp.data["capabilities"][0]["key"] == "model_inference"


def test_permission_specs_helper_matches_multiple_powers():
    # A single permission string can carry more than one power.
    specs = capability._permission_specs("exec+network")
    keys = {s["key"] for s in specs}
    assert {"code_execution", "network_access"} <= keys
