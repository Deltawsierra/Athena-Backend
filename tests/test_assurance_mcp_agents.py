"""Athena Phase 1.2 — MCP & Agent-Skill Assurance.

Proves the assurance graph's agent/tool/MCP/skill nodes are populated from what a
scan *declares* (``target_config``: an ``agent`` and its ``tools[]``), on the
same honesty discipline as the declared LLM target: each tool carries its own
permission map and provenance, the agent records what it is authorised to call,
an approved tool reads as approved and a merely-declared one as known, and a tool
the customer did not declare is never fabricated. Derivation is idempotent and
never overwrites a human's re-classification.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from assurance.assets import derive_assets
from assurance.models import Asset, Deployment, Finding
from pentest.models import PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst"):
    return User.objects.create_user(username=name, password="x", role=User.Roles.ANALYST)


AGENT_CONFIG = {
    "kind": "agent",
    "agent": {"name": "Support Copilot", "identifier": "agent:support-copilot", "identity": "svc-support"},
    "tools": [
        {
            "name": "CRM lookup",
            "kind": "mcp_server",
            "identifier": "mcp://crm.internal",
            "permissions": ["crm:read", "crm:write"],
            "provenance": "first_party",
            "approved": True,
        },
        {
            "name": "web-search",
            "kind": "tool",
            "identifier": "tool:web-search",
            "permissions": ["net:egress"],
            "provenance": "community",
            "approved": False,
        },
        {"name": "summarize", "kind": "skill", "identifier": "skill:summarize"},
    ],
}


def _scan(user, cfg=AGENT_CONFIG, findings=None):
    return PentestScan.objects.create(
        user=user,
        target_url="https://agent.example/chat",
        consent=True,
        status=PentestScan.STATUS_COMPLETED,
        engine_response={"findings": findings or []},
        target_config=cfg,
    )


def test_declared_tools_become_typed_graph_assets():
    user = _user()
    dep = Deployment.objects.create(name="d", owner=user)
    derive_assets(dep, _scan(user))

    mcp = dep.assets.get(kind=Asset.Kind.MCP_SERVER, identifier="mcp://crm.internal")
    assert mcp.name == "CRM lookup"
    tool = dep.assets.get(kind=Asset.Kind.TOOL, identifier="tool:web-search")
    skill = dep.assets.get(kind=Asset.Kind.SKILL, identifier="skill:summarize")
    assert {mcp.kind, tool.kind, skill.kind} == {"mcp_server", "tool", "skill"}


def test_each_tool_carries_its_permission_map_and_provenance():
    user = _user()
    dep = Deployment.objects.create(name="d", owner=user)
    derive_assets(dep, _scan(user))

    mcp = dep.assets.get(identifier="mcp://crm.internal")
    assert mcp.metadata["permissions"] == ["crm:read", "crm:write"]
    assert mcp.metadata["provenance"] == "first_party"
    assert mcp.metadata["declared"] is True


def test_approved_tool_is_approved_and_a_declared_one_is_known():
    user = _user()
    dep = Deployment.objects.create(name="d", owner=user)
    derive_assets(dep, _scan(user))

    assert dep.assets.get(identifier="mcp://crm.internal").classification == Asset.Classification.APPROVED
    # Declared but not marked approved: we know it is there, it is not blessed.
    assert dep.assets.get(identifier="tool:web-search").classification == Asset.Classification.KNOWN


def test_agent_identity_records_the_tools_it_may_call():
    user = _user()
    dep = Deployment.objects.create(name="d", owner=user)
    derive_assets(dep, _scan(user))

    agent = dep.assets.get(kind=Asset.Kind.AGENT)
    assert agent.name == "Support Copilot"
    assert agent.metadata["identity"] == "svc-support"
    # The agent→tool edge: every declared tool identifier the agent can reach.
    assert set(agent.metadata["tools"]) == {"mcp://crm.internal", "tool:web-search", "skill:summarize"}


def test_tools_declared_without_an_agent_block_still_imply_the_agent():
    """A scan that lists tools but no explicit agent still gets an agent node —
    something is calling those tools."""
    user = _user()
    dep = Deployment.objects.create(name="d", owner=user)
    cfg = {"kind": "agent", "tools": [{"name": "t", "kind": "tool", "identifier": "tool:t"}]}
    derive_assets(dep, _scan(user, cfg=cfg))
    assert dep.assets.filter(kind=Asset.Kind.AGENT).exists()
    assert dep.assets.filter(kind=Asset.Kind.TOOL, identifier="tool:t").exists()


def test_an_agent_finding_attaches_to_the_agent_asset():
    user = _user()
    dep = Deployment.objects.create(name="d", owner=user)
    finding = Finding.objects.create(
        deployment=dep, fingerprint="fp1", finding_type="tool_abuse",
        title="Tool permitted to write CRM without approval", severity="high",
    )
    derive_assets(dep, _scan(user))
    agent = dep.assets.get(kind=Asset.Kind.AGENT)
    finding.refresh_from_db()
    assert finding.asset_id == agent.pk


def test_derive_is_idempotent_and_preserves_human_classification():
    user = _user()
    dep = Deployment.objects.create(name="d", owner=user)
    derive_assets(dep, _scan(user))
    tool = dep.assets.get(identifier="tool:web-search")
    # A human reclassifies — recorded with HUMAN provenance, so a re-derive treats
    # it as authoritative and never overwrites it.
    tool.classification = Asset.Classification.HIGH_RISK
    tool.classification_source = Asset.ClassificationSource.HUMAN
    tool.save()

    derive_assets(dep, _scan(user))  # re-scan
    assert dep.assets.filter(identifier="tool:web-search").count() == 1  # no duplicate
    tool.refresh_from_db()
    assert tool.classification == Asset.Classification.HIGH_RISK  # human decision kept


def test_tools_on_an_llm_scan_register_alongside_the_model():
    """An LLM scan may also declare tools; both the model and the tools land."""
    user = _user()
    dep = Deployment.objects.create(name="d", owner=user)
    cfg = {
        "kind": "llm", "adapter": "openai_style", "base_url": "https://api.llm.test/v1", "model": "gpt-x",
        "tools": [{"name": "retriever", "kind": "mcp_server", "identifier": "mcp://vectors"}],
    }
    derive_assets(dep, _scan(user, cfg=cfg))
    assert dep.assets.filter(kind=Asset.Kind.MODEL, name="gpt-x").exists()
    assert dep.assets.filter(kind=Asset.Kind.MCP_SERVER, identifier="mcp://vectors").exists()


def test_a_scan_that_declares_no_inventory_adds_no_agent_or_tools():
    """The honest floor: no declared agent/tools → no agent/tool nodes invented."""
    user = _user()
    dep = Deployment.objects.create(name="d", owner=user)
    derive_assets(dep, _scan(user, cfg={"kind": "llm", "base_url": "https://x.test", "model": "m"}))
    assert not dep.assets.filter(kind__in=[Asset.Kind.AGENT, Asset.Kind.TOOL, Asset.Kind.SKILL]).exists()
