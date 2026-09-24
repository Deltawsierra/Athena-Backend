"""Athena Phase 1.6 — System / Route Map.

Proves the route map reconstructs the layered data-flow graph honestly: every
component sits in its pipeline layer (app → gateway → model → data → tools →
logs); a declared agent→tool edge is a fact while the reference-pipeline spine is
marked inferred; a tool the agent names but discovery cannot place is an
unresolved (dangling) edge, not a silent drop; an unmanaged node is a shadow on
the map; an empty logs layer is surfaced as the finding it is; and the API read
is open to any operator.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import route
from assurance.models import Asset, Deployment, Provider
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _asset(dep, *, kind, classification=Asset.Classification.KNOWN, name="c", identifier=None, provider=None, metadata=None):
    return Asset.objects.create(
        deployment=dep, kind=kind, classification=classification, provider=provider,
        name=name, identifier=identifier or name, metadata=metadata or {},
    )


def _layer_of_node(result, uuid):
    return next(n["layer"] for n in result["nodes"] if n["uuid"] == uuid)


def _edge(result, src_uuid, dst_uuid):
    return next(
        (e for e in result["edges"] if e["source"] == src_uuid and e["target"] == dst_uuid), None
    )


def test_components_sit_in_their_pipeline_layers():
    dep = Deployment.objects.create(name="d", owner=_user())
    api = _asset(dep, kind=Asset.Kind.API, name="app.example.com", metadata={"source": "scan_target"})
    gw = _asset(dep, kind=Asset.Kind.GATEWAY, name="gw")
    model = _asset(dep, kind=Asset.Kind.MODEL, name="gpt-x")
    vdb = _asset(dep, kind=Asset.Kind.VECTOR_DB, name="pinecone")
    tool = _asset(dep, kind=Asset.Kind.TOOL, name="search")

    result = route.build_route_map(dep)
    assert _layer_of_node(result, str(api.uuid)) == route.LAYER_APP
    assert _layer_of_node(result, str(gw.uuid)) == route.LAYER_GATEWAY
    assert _layer_of_node(result, str(model.uuid)) == route.LAYER_MODEL
    assert _layer_of_node(result, str(vdb.uuid)) == route.LAYER_DATA
    assert _layer_of_node(result, str(tool.uuid)) == route.LAYER_TOOLS
    # Layers come back in canonical order.
    assert [l["key"] for l in result["layers"]] == route.LAYER_ORDER


def test_declared_agent_tool_edge_is_a_fact_the_spine_is_inferred():
    dep = Deployment.objects.create(name="d", owner=_user())
    agent = _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
                   metadata={"tools": ["search-tool"]})
    tool = _asset(dep, kind=Asset.Kind.TOOL, name="search", identifier="search-tool")
    model = _asset(dep, kind=Asset.Kind.MODEL, name="gpt-x", identifier="gpt-x")

    result = route.build_route_map(dep)
    # The agent→tool edge is declared (the inventory attests it).
    e = _edge(result, str(agent.uuid), str(tool.uuid))
    assert e is not None and e["declared"] is True and e["kind"] == "invokes"
    # The agent→model edge is the inferred pipeline spine, not an observed flow.
    spine = _edge(result, str(agent.uuid), str(model.uuid))
    assert spine is not None and spine["declared"] is False
    assert result["summary"]["declared_edges"] >= 1
    assert result["summary"]["inferred_edges"] >= 1


def test_gateway_sits_between_the_caller_and_the_model():
    dep = Deployment.objects.create(name="d", owner=_user())
    agent = _asset(dep, kind=Asset.Kind.AGENT, name="a", identifier="a")
    gw = _asset(dep, kind=Asset.Kind.GATEWAY, name="gw", identifier="gw")
    model = _asset(dep, kind=Asset.Kind.MODEL, name="m", identifier="m")

    result = route.build_route_map(dep)
    # caller → gateway → model, and no direct caller → model edge.
    assert _edge(result, str(agent.uuid), str(gw.uuid)) is not None
    assert _edge(result, str(gw.uuid), str(model.uuid)) is not None
    assert _edge(result, str(agent.uuid), str(model.uuid)) is None


def test_a_tool_the_agent_names_but_we_cannot_place_is_an_unresolved_edge():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="a", identifier="a", metadata={"tools": ["ghost-tool"]})

    result = route.build_route_map(dep)
    assert result["summary"]["unresolved_edges"] == 1
    assert result["summary"]["unresolved_tool_references"] == 1
    assert result["unresolved"][0] == {
        "source": "a",
        "source_kind": Asset.Kind.AGENT,
        "reference": "ghost-tool",
        "mechanism": "tools",
        "reason": "not_found",
    }


def test_a_tool_declares_the_mcp_server_that_hosts_it():
    dep = Deployment.objects.create(name="d", owner=_user())
    tool = _asset(dep, kind=Asset.Kind.TOOL, name="fetch", identifier="fetch",
                  metadata={"server": "mcp://files"})
    mcp = _asset(dep, kind=Asset.Kind.MCP_SERVER, name="files", identifier="mcp://files")

    result = route.build_route_map(dep)
    e = _edge(result, str(tool.uuid), str(mcp.uuid))
    assert e is not None and e["declared"] is True and e["kind"] == "hosted_by"


def test_an_unmanaged_component_is_a_shadow_on_the_map():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.MCP_SERVER, name="rogue", identifier="mcp://rogue",
           classification=Asset.Classification.UNMANAGED)
    result = route.build_route_map(dep)
    assert result["summary"]["shadow_nodes"] == 1
    assert any(n["shadow"] for n in result["nodes"])


def test_an_observability_provider_puts_a_node_in_the_logs_layer():
    dep = Deployment.objects.create(name="d", owner=_user())
    obs = Provider.objects.create(name="Datadog", kind=Provider.Kind.OBSERVABILITY)
    sink = _asset(dep, kind=Asset.Kind.API, name="logs.dd", identifier="logs.dd", provider=obs)

    result = route.build_route_map(dep)
    assert _layer_of_node(result, str(sink.uuid)) == route.LAYER_LOGS
    assert result["summary"]["logs_observed"] is True


def test_empty_logs_layer_is_surfaced_as_the_finding():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.MODEL, name="m")
    result = route.build_route_map(dep)
    assert result["summary"]["logs_observed"] is False
    # The logs layer exists in the map but holds no nodes.
    logs = next(l for l in result["layers"] if l["key"] == route.LAYER_LOGS)
    assert logs["nodes"] == []


def test_no_agent_the_front_reaches_the_model_and_tools_directly():
    dep = Deployment.objects.create(name="d", owner=_user())
    api = _asset(dep, kind=Asset.Kind.API, name="app", identifier="app", metadata={"source": "scan_target"})
    model = _asset(dep, kind=Asset.Kind.MODEL, name="m", identifier="m")
    tool = _asset(dep, kind=Asset.Kind.TOOL, name="t", identifier="t")

    result = route.build_route_map(dep)
    assert _edge(result, str(api.uuid), str(model.uuid)) is not None
    assert _edge(result, str(api.uuid), str(tool.uuid)) is not None


def test_empty_deployment_is_an_honest_empty_map():
    dep = Deployment.objects.create(name="d", owner=_user())
    result = route.build_route_map(dep)
    assert result["nodes"] == []
    assert result["edges"] == []
    assert result["summary"]["node_count"] == 0


def test_route_map_api_is_open_to_any_operator():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    _asset(dep, kind=Asset.Kind.MODEL, name="m")

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "route_map"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/route-map/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["summary"]["node_count"] == 1
    assert [l["key"] for l in resp.data["layers"]] == route.LAYER_ORDER
