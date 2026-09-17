"""Athena Phase 2.5 — Ripple Effect (blast-radius) assessment.

Proves the assessment is a *few well-supported* downstream consequences of an
origin worth tracing — read off the effective-access reach graph (Phase 3.1) and
the data boundary (Phase 1.4), never a speculative cascade of its own:

- a high-severity finding tied to a component that reaches a data store yields a
  data_exposure consequence carrying its evidenced via-path;
- a reach to a code-exec power yields a code_execution consequence;
- NO consequence is produced for a hop the graph lacks (inherits access.py's guard);
- consequences are ranked (most-concerning first) and bounded ("a few", not
  exhaustive), with the full evidenced count reported;
- a resolved finding is not an active origin;
- no dollar figure, no realized-loss claim, no "contained/safe" claim anywhere;
- output is deterministic (same graph → same output);
- the empty graph is an honest empty blast radius, not a "safe" verdict;
- the API action is open to any operator and returns the expected shape.
"""

from __future__ import annotations

import json

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.models import Asset, Deployment, Finding
from assurance.ripple import (
    CATEGORY_CODE_EXECUTION,
    CATEGORY_DATA_EXPOSURE,
    MAX_CONSEQUENCES_PER_ORIGIN,
    MAX_CONSEQUENCES_TOTAL,
    assess_ripple,
)
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


def _finding(dep, *, asset=None, severity="high", status=Finding.Status.OPEN,
             finding_type="excessive_agency", title="t"):
    return Finding.objects.create(
        deployment=dep, asset=asset, fingerprint=f"fp-{title}-{severity}-{status}",
        finding_type=finding_type, title=title, severity=severity, status=status,
    )


def _origins_by_name(result):
    return {o["origin"]: o for o in result["origins"]}


def test_high_finding_reaching_a_data_store_yields_data_exposure_with_via_path():
    dep = Deployment.objects.create(name="d", owner=_user())
    agent = _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
                   metadata={"tools": ["query-tool"]})
    # A declared edge for every hop: agent → tool → data store.
    _asset(dep, kind=Asset.Kind.TOOL, name="query-tool", identifier="query-tool",
           metadata={"permissions": ["db:read"], "server": "warehouse"})
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="warehouse", identifier="warehouse")
    _finding(dep, asset=agent, severity="high", finding_type="excessive_agency", title="over-broad agent")

    result = assess_ripple(dep)
    # The agent is an origin (an active high finding is tied to it).
    origin = _origins_by_name(result)["assistant"]
    assert "finding" in origin["origin_types"]
    assert origin["evidenced_reach"] is True

    # A data_exposure consequence reaches the warehouse, carrying its full via-path.
    exposure = next(
        c for c in result["consequences"]
        if c["category"] == CATEGORY_DATA_EXPOSURE and c["target"] == "warehouse"
    )
    assert exposure["via"] == ["assistant", "query-tool", "warehouse"]
    assert exposure["potential"] is True
    assert exposure["evidence_basis"]  # a non-empty basis ties it to evidence
    assert exposure["origin"] == "assistant"


def test_reach_to_a_code_exec_power_yields_a_code_execution_consequence():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["shell"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="shell", identifier="shell",
           metadata={"permissions": ["exec"]})

    result = assess_ripple(dep)
    # The agent is a privileged principal (holds code execution) → an origin.
    origin = _origins_by_name(result)["assistant"]
    assert "principal" in origin["origin_types"]
    codeexec = next(c for c in result["consequences"] if c["category"] == CATEGORY_CODE_EXECUTION)
    assert codeexec["potential"] is True
    assert "Could execute code" in codeexec["consequence"]


def test_no_consequence_for_a_hop_the_graph_lacks():
    dep = Deployment.objects.create(name="d", owner=_user())
    agent = _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
                   metadata={"tools": ["query-tool"]})
    # Nothing links the tool to the data store — no declared edge for that hop.
    _asset(dep, kind=Asset.Kind.TOOL, name="query-tool", identifier="query-tool",
           metadata={"permissions": ["db:read"]})
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="warehouse", identifier="warehouse")
    _finding(dep, asset=agent, severity="high", title="over-broad agent")

    result = assess_ripple(dep)
    # The tool (and its data_query power) is reached; the unlinked store is NOT.
    assert not any(c["target"] == "warehouse" for c in result["consequences"])


def test_downstream_sliced_by_uuid_not_colliding_name():
    """Regression (M2): asset names are not unique. A ``tool`` and a ``data_store``
    both named "store" must not cross-contaminate blast radius. The tool "store" is
    a mid-path hop that reaches the "warehouse" downstream; the unrelated,
    terminal data_store "store" (an origin via a high finding) reaches nothing.

    The old name-based path slicing found "store" in the tool's path and wrongly
    attributed the warehouse consequence to the data_store origin. Slicing on the
    origin node's uuid attributes it to the correct node — the data_store origin
    has no evidenced downstream reach."""
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["tool-store"]})
    # A TOOL named "store" reaches the warehouse (a real downstream hop).
    _asset(dep, kind=Asset.Kind.TOOL, name="store", identifier="tool-store",
           metadata={"permissions": ["db:read"], "server": "warehouse"})
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="warehouse", identifier="warehouse")
    # A SEPARATE terminal data_store, also named "store", is the origin (high finding).
    ds_store = _asset(dep, kind=Asset.Kind.DATA_STORE, name="store", identifier="ds-store")
    _finding(dep, asset=ds_store, severity="high", finding_type="data_exposure", title="exposed store")

    result = assess_ripple(dep)
    store_origin = _origins_by_name(result)["store"]
    # The data_store "store" is terminal — no evidenced downstream reach. Under the
    # name-slicing bug it wrongly inherited the tool "store"'s reach to warehouse.
    assert store_origin["origin_uuid"] == str(ds_store.uuid)
    assert store_origin["evidenced_reach"] is False
    assert store_origin["consequence_count"] == 0
    # No consequence is attributed to the data_store "store" origin.
    assert not any(
        c["origin"] == "store" and c["target"] == "warehouse" for c in result["consequences"]
    )


def test_consequences_are_ranked_and_bounded_to_a_few():
    dep = Deployment.objects.create(name="d", owner=_user())
    # One agent reaching many high-power tools — an exhaustive tree if unbounded.
    tools = [f"tool{i}" for i in range(8)]
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": tools})
    for i, t in enumerate(tools):
        _asset(dep, kind=Asset.Kind.TOOL, name=t, identifier=t,
               metadata={"permissions": ["exec", "create_payment", "network", "db:query"]})

    result = assess_ripple(dep)
    origin = _origins_by_name(result)["assistant"]
    # Bounded per origin and overall — a few well-supported, not exhaustive.
    per_origin = [c for c in result["consequences"] if c["origin"] == "assistant"]
    assert len(per_origin) <= MAX_CONSEQUENCES_PER_ORIGIN
    assert len(result["consequences"]) <= MAX_CONSEQUENCES_TOTAL
    # The bounding is visible, not hidden: the full evidenced count exceeds the shown.
    assert result["summary"]["evidenced_consequences"] > len(result["consequences"])
    assert result["summary"]["bounded"] is True
    # Ranked most-concerning first: the first row is the worst band present.
    assert result["consequences"][0]["risk"] == result["summary"]["worst_risk"]
    assert origin["consequence_count"] >= len(per_origin)


def test_a_resolved_finding_is_not_an_active_origin():
    dep = Deployment.objects.create(name="d", owner=_user())
    # A plain tool (not a principal) connected to a store, with a finding on it.
    tool = _asset(dep, kind=Asset.Kind.TOOL, name="query-tool", identifier="query-tool",
                  metadata={"permissions": ["db:read"], "server": "warehouse"})
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="warehouse", identifier="warehouse")

    # Resolved (verified closed): the tool is not an active origin.
    _finding(dep, asset=tool, severity="high", status=Finding.Status.CLOSED, title="fixed")
    assert "query-tool" not in _origins_by_name(assess_ripple(dep))

    # An OPEN high finding on the same tool makes it an origin.
    _finding(dep, asset=tool, severity="high", status=Finding.Status.OPEN, title="live")
    result = assess_ripple(dep)
    assert "query-tool" in _origins_by_name(result)
    assert any(c["origin"] == "query-tool" and c["target"] == "warehouse" for c in result["consequences"])


def test_no_dollar_no_realized_loss_no_contained_or_safe_claim():
    dep = Deployment.objects.create(name="d", owner=_user())
    agent = _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
                   metadata={"tools": ["shell", "billing"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="shell", identifier="shell",
           metadata={"permissions": ["exec"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="billing", identifier="billing",
           metadata={"permissions": ["create_payment"]})
    _finding(dep, asset=agent, severity="critical", title="agent takeover")

    blob = json.dumps(assess_ripple(dep)).lower()
    assert "$" not in blob
    for forbidden in (
        "realized loss", "actual loss", "loss of $", "contained", "mitigated",
        "is safe", "secure", "no risk", "least privilege",
    ):
        assert forbidden not in blob


def test_origin_with_no_evidenced_downstream_reach_reads_honestly():
    dep = Deployment.objects.create(name="d", owner=_user())
    # A high finding on a leaf data store: nothing lies downstream of it.
    store = _asset(dep, kind=Asset.Kind.DATA_STORE, name="warehouse", identifier="warehouse")
    _finding(dep, asset=store, severity="critical", title="exposed store")

    result = assess_ripple(dep)
    origin = _origins_by_name(result)["warehouse"]
    assert origin["evidenced_reach"] is False
    assert "no evidenced downstream reach" in origin["note"].lower()
    # Honest: not "safe", not "contained".
    assert "safe" not in origin["note"].lower()
    assert result["consequences"] == []


def test_deterministic_same_graph_same_output():
    def build():
        dep = Deployment.objects.create(name="d", owner=_user(name=f"u{Deployment.objects.count()}"))
        agent = _asset(dep, kind=Asset.Kind.AGENT, name="a", identifier="a",
                       metadata={"tools": ["x", "y"]})
        _asset(dep, kind=Asset.Kind.TOOL, name="x", identifier="x",
               metadata={"permissions": ["exec"], "server": "store"})
        _asset(dep, kind=Asset.Kind.TOOL, name="y", identifier="y", metadata={"permissions": ["network"]})
        _asset(dep, kind=Asset.Kind.DATA_STORE, name="store", identifier="store")
        _finding(dep, asset=agent, severity="high", title="finding")
        return dep

    def _strip_origin(o):
        # key and origin_uuid are uuid-derived (non-deterministic across builds).
        out = {k: v for k, v in o.items() if k not in ("key", "origin_uuid")}
        # Finding UUIDs are non-deterministic by design; compare structural content.
        out["findings"] = [{k: v for k, v in f.items() if k != "uuid"} for f in o["findings"]]
        return out

    def strip_keys(r):
        return json.dumps(
            {
                "summary": r["summary"],
                "origins": [_strip_origin(o) for o in r["origins"]],
                "consequences": [{k: v for k, v in c.items() if k != "origin_key"} for c in r["consequences"]],
            },
            sort_keys=True,
        )

    first = assess_ripple(build())
    second = assess_ripple(build())
    assert strip_keys(first) == strip_keys(second)


def test_empty_deployment_is_an_honest_empty_blast_radius():
    dep = Deployment.objects.create(name="d", owner=_user())
    result = assess_ripple(dep)
    assert result["origins"] == []
    assert result["consequences"] == []
    assert result["summary"]["origins"] == 0
    assert result["summary"]["worst_risk"] is None
    # No "safe" / "contained" verdict slips in on the empty case.
    assert "safe" not in json.dumps(result).lower()


def test_boundary_crossing_target_enriches_the_evidence_basis():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["exfil-tool"]})
    # The tool reaches an unmanaged MCP server — a shadow data destination that
    # crosses the boundary. The boundary assessment gives the basis a concrete role.
    _asset(dep, kind=Asset.Kind.TOOL, name="exfil-tool", identifier="exfil-tool",
           metadata={"permissions": ["network"], "server": "rogue-mcp"})
    _asset(dep, kind=Asset.Kind.MCP_SERVER, name="rogue-mcp", identifier="rogue-mcp",
           classification=Asset.Classification.UNMANAGED)

    result = assess_ripple(dep)
    egress = next((c for c in result["consequences"] if c["target"] == "rogue-mcp"), None)
    assert egress is not None
    joined = " ".join(egress["evidence_basis"]).lower()
    assert "boundary" in joined


def test_ripple_api_is_open_to_any_operator():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["shell"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="shell", identifier="shell",
           metadata={"permissions": ["exec"]})

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "ripple_effect"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/ripple-effect/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert set(resp.data.keys()) == {"origins", "consequences", "summary"}
    assert resp.data["summary"]["origins"] >= 1
    assert any(c["category"] == CATEGORY_CODE_EXECUTION for c in resp.data["consequences"])
