"""Athena Phase 3.1 — Identity Assurance & Effective Access Discovery.

Proves the assessment is the honest inventory of a deployment's principals (the
identities that can act) and what each can effectively reach, by direct and
transitive paths through the asset graph:

- a principal that reaches a code-exec / privileged / money-moving tool is flagged
  privileged at risk high, and reads as high-privilege;
- a principal evidenced only by an unmanaged asset reads as shadow, with its risk
  raised one band;
- a transitive path (agent → tool → data store) is reported with its via-path
  when a declared edge evidences every hop;
- NO reach is invented when the graph lacks the hop;
- the honesty invariants hold: least privilege / "secure" is never asserted;
- output is deterministic (same graph → same output);
- the empty graph is an honest empty inventory;
- the API action is open to any operator and returns the expected shape.
"""

from __future__ import annotations

import json

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.access import (
    PRIVILEGE_ELEVATED,
    PRIVILEGE_HIGH,
    assess_effective_access,
)
from assurance.capability import RISK_HIGH
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


def _principals_by_name(result):
    return {p["name"]: p for p in result["principals"]}


def test_agent_reaching_a_code_exec_tool_is_privileged_high_risk():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["shell-tool"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="shell", identifier="shell-tool",
           classification=Asset.Classification.APPROVED, metadata={"permissions": ["exec"]})

    result = assess_effective_access(dep)
    agent = _principals_by_name(result)["assistant"]
    # It holds code execution (via the tool it invokes) → high privilege, high risk.
    assert agent["privilege_level"] == PRIVILEGE_HIGH
    assert any(c["key"] == "code_execution" for c in agent["capabilities"])
    assert agent["privileged"] is True
    assert agent["risk"] == RISK_HIGH
    gap = next(g for g in agent["gaps"] if g["type"] == "privileged_access")
    assert gap["risk"] == RISK_HIGH
    assert "code_execution" in gap["capabilities"]
    assert result["summary"]["privileged"] == 1


def test_money_movement_and_privileged_control_are_privileged():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="ops", identifier="ops",
           metadata={"tools": ["billing", "admin"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="billing", identifier="billing",
           metadata={"permissions": ["create_payment"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="admin", identifier="admin",
           metadata={"permissions": ["iam:grant"]})

    ops = _principals_by_name(assess_effective_access(dep))["ops"]
    held = {c["key"] for c in ops["capabilities"]}
    assert {"financial_action", "privileged_control"} <= held
    assert ops["privilege_level"] == PRIVILEGE_HIGH
    assert ops["privileged"] is True


def test_shadow_principal_reads_as_shadow_with_risk_raised():
    dep = Deployment.objects.create(name="d", owner=_user())
    # An unmanaged agent nobody approved, wired to a plain (elevated) tool.
    _asset(dep, kind=Asset.Kind.AGENT, name="rogue", identifier="rogue",
           classification=Asset.Classification.UNMANAGED, metadata={"tools": ["t"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="t", identifier="t",
           metadata={"permissions": ["network"]})

    rogue = _principals_by_name(assess_effective_access(dep))["rogue"]
    assert rogue["shadow"] is True
    assert rogue["managed"] is False
    # Base risk from a network power is elevated; shadow raises it to high.
    assert any(g["type"] == "shadow_identity" for g in rogue["gaps"])
    shadow_gap = next(g for g in rogue["gaps"] if g["type"] == "shadow_identity")
    assert shadow_gap["risk"] == RISK_HIGH
    assert rogue["risk"] == RISK_HIGH
    assert assess_effective_access(dep)["summary"]["shadow"] == 1


def test_transitive_path_agent_tool_data_store_reports_its_via_path():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["query-tool"]})
    # The tool declares the data store it connects to: a declared edge for every hop.
    _asset(dep, kind=Asset.Kind.TOOL, name="query-tool", identifier="query-tool",
           metadata={"permissions": ["db:read"], "server": "warehouse"})
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="warehouse", identifier="warehouse")

    result = assess_effective_access(dep)
    agent = _principals_by_name(result)["assistant"]
    # The data store is reached transitively, and its via-path shows every hop.
    store_reach = next(
        (r for r in agent["effective_reach"]
         if r["target_kind"] == Asset.Kind.DATA_STORE and r["target"] == "warehouse"),
        None,
    )
    assert store_reach is not None
    assert store_reach["via"] == ["assistant", "query-tool", "warehouse"]
    # The tool hop is reported too, before the store.
    assert any(r["target"] == "query-tool" for r in agent["effective_reach"])


def test_no_invented_reach_when_the_graph_lacks_the_hop():
    dep = Deployment.objects.create(name="d", owner=_user())
    # Agent invokes a tool, but nothing links the tool to the data store.
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["query-tool"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="query-tool", identifier="query-tool",
           metadata={"permissions": ["db:read"]})
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="warehouse", identifier="warehouse")

    agent = _principals_by_name(assess_effective_access(dep))["assistant"]
    # The tool is reached; the data store is NOT — no hop evidences it.
    assert any(r["target"] == "query-tool" for r in agent["effective_reach"])
    assert not any(r["target"] == "warehouse" for r in agent["effective_reach"])


def test_a_tool_the_agent_names_but_we_cannot_place_is_not_reached():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["ghost-tool"]})
    agent = _principals_by_name(assess_effective_access(dep))["assistant"]
    # A dangling reference is never fabricated into a reach.
    assert agent["effective_reach"] == []


def test_over_broad_reach_spanning_data_execution_network_is_surfaced():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["swiss-army"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="swiss-army", identifier="swiss-army",
           metadata={"permissions": ["exec", "network", "db:query"]})

    agent = _principals_by_name(assess_effective_access(dep))["assistant"]
    assert agent["over_broad"] is True
    gap = next(g for g in agent["gaps"] if g["type"] == "over_broad")
    assert {"data", "execution", "network"} <= set(gap["categories"])


def test_orphaned_service_account_with_no_use_is_surfaced():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.SERVICE_ACCOUNT, name="svc-unused", identifier="svc-unused")

    result = assess_effective_access(dep)
    sa = _principals_by_name(result)["svc-unused"]
    assert sa["orphaned"] is True
    assert any(g["type"] == "orphaned" for g in sa["gaps"])
    assert result["summary"]["orphaned"] == 1


def test_a_used_service_account_is_not_orphaned():
    dep = Deployment.objects.create(name="d", owner=_user())
    # An agent acts under this service identity → it is used, not orphaned.
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"identity": "svc-support", "tools": []})
    _asset(dep, kind=Asset.Kind.SERVICE_ACCOUNT, name="svc-support", identifier="svc-support")

    sa = _principals_by_name(assess_effective_access(dep))["svc-support"]
    assert sa["orphaned"] is False


def test_ungoverned_reach_to_an_unmanaged_target_is_surfaced():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["rogue-mcp"]})
    _asset(dep, kind=Asset.Kind.MCP_SERVER, name="rogue-mcp", identifier="rogue-mcp",
           classification=Asset.Classification.UNMANAGED)

    agent = _principals_by_name(assess_effective_access(dep))["assistant"]
    gap = next(g for g in agent["gaps"] if g["type"] == "ungoverned_reach")
    assert "rogue-mcp" in gap["targets"]
    # Reaching an unmanaged target reads at a raised risk.
    reach = next(r for r in agent["effective_reach"] if r["target"] == "rogue-mcp")
    assert reach["target_managed"] is False
    assert reach["risk"] == RISK_HIGH  # base elevated (mcp) raised one band


def test_base_principal_holds_tools_no_agent_owns():
    dep = Deployment.objects.create(name="d", owner=_user())
    # No agent: the deployment's own app/model wields the tool directly.
    _asset(dep, kind=Asset.Kind.MODEL, name="gpt-x", identifier="gpt-x")
    _asset(dep, kind=Asset.Kind.TOOL, name="shell", identifier="shell",
           metadata={"permissions": ["exec"]})

    result = assess_effective_access(dep)
    base = _principals_by_name(result)["d"]
    assert base["kind"] == "deployment"
    assert base["privilege_level"] == PRIVILEGE_HIGH
    assert any(r["target"] == "shell" for r in base["effective_reach"])
    assert base["effective_reach"][0]["via"][0] == "d"


def test_agent_owned_tool_is_not_also_a_base_principal():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["shell"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="shell", identifier="shell",
           metadata={"permissions": ["exec"]})

    names = {p["name"] for p in assess_effective_access(dep)["principals"]}
    # The agent owns the only tool, so there is no separate base principal.
    assert names == {"assistant"}


def test_least_privilege_and_secure_are_never_asserted():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["t"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="t", identifier="t",
           classification=Asset.Classification.APPROVED, metadata={"permissions": ["net"]})

    blob = json.dumps(assess_effective_access(dep)).lower()
    for forbidden in ("least privilege", "least_privilege", "least-privilege", "secure", "compliant"):
        assert forbidden not in blob


def test_privilege_level_is_elevated_for_a_non_high_power():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["net-tool"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="net-tool", identifier="net-tool",
           metadata={"permissions": ["network"]})

    agent = _principals_by_name(assess_effective_access(dep))["assistant"]
    assert agent["privilege_level"] == PRIVILEGE_ELEVATED
    assert agent["privileged"] is False


def test_deterministic_same_graph_same_output():
    def build():
        dep = Deployment.objects.create(name="d", owner=_user(name=f"u{Deployment.objects.count()}"))
        _asset(dep, kind=Asset.Kind.AGENT, name="a", identifier="a", metadata={"tools": ["x", "y"]})
        _asset(dep, kind=Asset.Kind.TOOL, name="x", identifier="x", metadata={"permissions": ["exec"]})
        _asset(dep, kind=Asset.Kind.TOOL, name="y", identifier="y", metadata={"permissions": ["network"]})
        _asset(dep, kind=Asset.Kind.SERVICE_ACCOUNT, name="svc", identifier="svc")
        return dep

    first = assess_effective_access(build())
    second = assess_effective_access(build())
    # UUID-derived keys differ between builds; compare the structural content.
    def _strip_reach(reach):
        # target_uuid / via_keys are uuid-derived (added for stable per-node keying),
        # so drop them the same way the principal's own key is dropped.
        return [{k: v for k, v in r.items() if k not in ("target_uuid", "via_keys")} for r in reach]

    def strip_keys(r):
        return json.dumps(
            {
                "summary": r["summary"],
                "principals": [
                    {
                        k: (_strip_reach(v) if k == "effective_reach" else v)
                        for k, v in p.items()
                        if k != "key"
                    }
                    for p in r["principals"]
                ],
            },
            sort_keys=True,
        )
    assert strip_keys(first) == strip_keys(second)


def test_empty_deployment_is_an_honest_empty_inventory():
    dep = Deployment.objects.create(name="d", owner=_user())
    result = assess_effective_access(dep)
    assert result["principals"] == []
    assert result["summary"]["principals"] == 0
    assert result["summary"]["worst_risk"] is None


def test_principals_are_ordered_most_concerning_first():
    dep = Deployment.objects.create(name="d", owner=_user())
    # A high-risk privileged agent and a low-concern service account.
    _asset(dep, kind=Asset.Kind.AGENT, name="danger", identifier="danger",
           metadata={"tools": ["shell"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="shell", identifier="shell",
           metadata={"permissions": ["exec"]})
    _asset(dep, kind=Asset.Kind.SERVICE_ACCOUNT, name="svc", identifier="svc",
           metadata={"identity": "svc"})

    result = assess_effective_access(dep)
    assert result["principals"][0]["name"] == "danger"
    assert result["summary"]["worst_risk"] == RISK_HIGH


def test_effective_access_api_is_open_to_any_operator():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["shell"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="shell", identifier="shell",
           metadata={"permissions": ["exec"]})

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "effective_access"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/effective-access/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["summary"]["principals"] == 1
    assert resp.data["principals"][0]["name"] == "assistant"
    assert resp.data["principals"][0]["privilege_level"] == PRIVILEGE_HIGH


def test_reach_and_summary_expose_high_risk_reach_count():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["shell"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="shell", identifier="shell",
           metadata={"permissions": ["exec"]})

    result = assess_effective_access(dep)
    assert result["summary"]["high_risk_reach"] >= 1
    # The code-execution power reach is present and high risk.
    agent = result["principals"][0]
    assert any(
        r["capability"] == "code_execution" and r["risk"] == RISK_HIGH
        for r in agent["effective_reach"]
    )


def test_an_agent_holds_the_powers_of_the_account_it_acts_as():
    """An agent acting as an account with admin rights has admin rights. The reach
    stopped at the agent's own tools, so the account's powers were held by no
    agent and the agent read as standard-privilege."""
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"identity": "svc-admin", "tools": []})
    _asset(dep, kind=Asset.Kind.SERVICE_ACCOUNT, name="svc-admin", identifier="svc-admin",
           metadata={"permissions": ["iam:admin"]})

    agent = _principals_by_name(assess_effective_access(dep))["assistant"]
    assert "privileged_control" in {c["key"] for c in agent["capabilities"]}
    assert agent["privilege_level"] == "high"


def test_an_identity_nobody_can_place_keeps_the_access_claim_off_verified():
    from assurance.claims import derive_claims
    from assurance.models import AssuranceClaim

    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"identity": "svc-nowhere", "tools": []})

    derive_claims(dep)
    claim = AssuranceClaim.objects.get(
        deployment=dep, claim_type=AssuranceClaim.ClaimType.EFFECTIVE_ACCESS, valid_to__isnull=True
    )
    assert claim.status == AssuranceClaim.ClaimStatus.PARTIALLY_VERIFIED
    assert "assistant → svc-nowhere" in claim.supporting_summary
