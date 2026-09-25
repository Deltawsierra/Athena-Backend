"""One identity per component, and every row that answers to it counted.

Four places decided which records were "the same component", and each could be
told two different things by the same inventory:

- the drift assessment and the coverage manifest kept ONE row per identity
  (``{key: row}``), so a second row answering to the same identity vanished from
  the lists, the counts, and -- in the manifest -- the verdict;
- the manifest and the drift assessment disagreed about an identifier of only
  whitespace, so one reader called a declared component observed and the other
  called it never observed;
- the orphaned-service-account check compared an agent's declared identity to
  every account's NAME, so a second account sharing the name hid the orphan;
- an agent the scan implied but did not name was the literal ``"agent"``, one row
  per deployment, so two agents at two targets were written into one.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from assurance.access import assess_effective_access
from assurance.assets import derive_assets
from assurance.bom_drift import assess_bom_drift, record_bom_drift_findings
from assurance.component_identity import by_identity, component_key
from assurance.coverage import coverage_manifest
from assurance.models import Asset, DeclaredComponent, Deployment, Finding
from pentest.models import PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()
Kind = Asset.Kind


def _dep(name="d"):
    user = User.objects.create_user(username=f"u-{name}-{Deployment.objects.count()}", password="x",
                                    role=User.Roles.ANALYST)
    return Deployment.objects.create(name=name, owner=user)


def _asset(dep, *, kind=Kind.TOOL, name, identifier=None, assessed=False, metadata=None):
    return Asset.objects.create(
        deployment=dep, kind=kind, name=name,
        identifier=identifier if identifier is not None else name,
        classification=Asset.Classification.KNOWN,
        assessed_at=timezone.now() if assessed else None,
        metadata=metadata or {},
    )


def _declare(dep, *, kind=Kind.TOOL, name, identifier=None):
    return DeclaredComponent.objects.create(
        deployment=dep, kind=kind, name=name,
        identifier=identifier if identifier is not None else name,
    )


# ---- The key, and the grouping. ----


def test_a_blank_or_whitespace_identifier_falls_back_to_the_name():
    assert component_key("tool", identifier="", name=" Reader ") == ("tool", "reader")
    assert component_key("tool", identifier="   ", name="Reader") == ("tool", "reader")
    assert component_key("tool", identifier=" READER ", name="other") == ("tool", "reader")


def test_grouping_keeps_every_row_under_an_identity():
    dep = _dep()
    a = _asset(dep, name="Reader")
    b = _asset(dep, name="reader")
    groups = by_identity([a, b])
    assert list(groups) == [("tool", "reader")]
    assert groups[("tool", "reader")] == [a, b]


# ---- The coverage manifest. ----


@pytest.mark.parametrize("assessed_spelling", ["Reader", "reader"])
def test_one_unassessed_row_under_a_declared_identity_holds_the_manifest(assessed_spelling):
    """Two rows answer to the declared ``reader``; one was assessed. The declared
    component was not assessed as a whole. A dict kept whichever row sorted last,
    so with the assessed spelling sorting last the manifest read COMPLETE."""
    dep = _dep()
    _declare(dep, name="reader")
    unassessed_spelling = "reader" if assessed_spelling == "Reader" else "Reader"
    _asset(dep, name=assessed_spelling, assessed=True)
    unassessed = _asset(dep, name=unassessed_spelling)

    manifest = coverage_manifest(dep)

    assert manifest["verdict"] == "incomplete"
    assert [e["asset_uuid"] for e in manifest["declared_but_unassessed"]] == [str(unassessed.uuid)]
    assert manifest["never_observed"] == []


def test_the_manifest_and_the_drift_agree_on_a_whitespace_identifier():
    """A declaration whose identifier is only whitespace is matched on its name
    by both readers. The manifest used to match it on the empty string and file
    it as never observed while the drift assessment matched it."""
    dep = _dep()
    _declare(dep, name="reader", identifier="   ")
    _asset(dep, name="reader", assessed=True)

    assert coverage_manifest(dep)["never_observed"] == []
    drift = assess_bom_drift(dep)
    assert drift["missing"] == []
    assert drift["summary"]["matched"] == 1


def test_every_duplicate_declaration_nothing_answers_to_is_listed():
    dep = _dep()
    _declare(dep, name="Ghost")
    _declare(dep, name="ghost")
    _asset(dep, kind=Kind.MODEL, name="unrelated", assessed=True)

    manifest = coverage_manifest(dep)
    assert sorted(e["identifier"] for e in manifest["never_observed"]) == ["Ghost", "ghost"]
    assert sorted(c["identifier"] for c in assess_bom_drift(dep)["missing"]) == ["Ghost", "ghost"]


# ---- The drift assessment. ----


def test_every_undeclared_row_is_listed_and_the_summary_adds_up():
    dep = _dep()
    _declare(dep, kind=Kind.MODEL, name="gpt")
    _asset(dep, kind=Kind.MODEL, name="gpt")
    _asset(dep, name="Shadow")
    _asset(dep, name="shadow")

    drift = assess_bom_drift(dep)
    summary = drift["summary"]

    assert sorted(c["identifier"] for c in drift["undeclared"]) == ["Shadow", "shadow"]
    assert summary["undeclared"] == 2
    assert summary["observed_count"] == summary["matched"] + summary["undeclared"]


def test_two_rows_under_a_declared_identity_are_both_matched():
    dep = _dep()
    _declare(dep, name="reader")
    _asset(dep, name="Reader")
    _asset(dep, name="reader")

    drift = assess_bom_drift(dep)
    assert drift["undeclared"] == []
    assert drift["summary"]["matched"] == 2
    assert drift["summary"]["observed_count"] == 2


def test_one_identity_is_one_finding_carrying_every_row():
    """Two undeclared rows under one identity are one finding, created once -- not
    created and then 'updated' by its own second write -- and the finding carries
    both rows."""
    dep = _dep()
    _declare(dep, kind=Kind.MODEL, name="gpt")
    _asset(dep, kind=Kind.MODEL, name="gpt")
    _asset(dep, name="Shadow")
    _asset(dep, name="shadow")

    counts = record_bom_drift_findings(dep)

    assert (counts["created"], counts["updated"]) == (1, 0)
    finding = Finding.objects.get(deployment=dep, finding_type="bom_drift.undeclared_component")
    assert sorted(c["identifier"] for c in finding.raw["drift"]["components"]) == ["Shadow", "shadow"]

    again = record_bom_drift_findings(dep)
    assert (again["created"], again["updated"], again["resolved"]) == (0, 1, 0)


# ---- The orphaned service account. ----


def _principal(result, name):
    matches = [p for p in result["principals"] if p["name"] == name]
    assert len(matches) == 1, [p["name"] for p in result["principals"]]
    return matches[0]


def _gap_types(principal):
    return sorted(g["type"] for g in principal["gaps"])


def test_a_namesake_does_not_hide_an_orphan():
    """The agent acts under ``svc-a``, which is one account's identifier. A second
    account merely NAMED ``svc-a`` is used by nobody, and the name comparison
    counted it as used."""
    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="bot", metadata={"identity": "svc-a"})
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="svc-a", identifier="svc-a")
    legacy = _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="svc-a", identifier="svc-a-legacy")

    result = assess_effective_access(dep)
    orphans = [p for p in result["principals"] if p["orphaned"]]

    assert [p["key"] for p in orphans] == [f"asset:{legacy.uuid}"]
    assert result["summary"]["orphaned"] == 1


def test_an_identity_two_accounts_answer_to_proves_neither_used_nor_orphaned():
    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="bot", metadata={"identity": "billing"})
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="billing", identifier="sa-1")
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="billing", identifier="sa-2")

    result = assess_effective_access(dep)
    accounts = [p for p in result["principals"] if p["kind"] == Kind.SERVICE_ACCOUNT]

    assert [_gap_types(p) for p in accounts] == [["use_unproven"], ["use_unproven"]]
    assert result["summary"]["orphaned"] == 0


def test_a_proven_use_is_not_undone_by_an_ambiguous_one():
    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="bot", metadata={"identity": "billing"})
    _asset(dep, kind=Kind.AGENT, name="payer", metadata={"identity": "sa-1"})
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="billing", identifier="sa-1")
    second = _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="billing", identifier="sa-2")

    result = assess_effective_access(dep)
    gaps = {p["key"]: _gap_types(p) for p in result["principals"] if p["kind"] == Kind.SERVICE_ACCOUNT}

    assert gaps == {
        next(k for k in gaps if k != f"asset:{second.uuid}"): [],
        f"asset:{second.uuid}": ["use_unproven"],
    }


def test_an_identity_only_something_else_carries_leaves_the_account_orphaned():
    """An identity is the account an agent acts as. A tool that happens to carry
    the string is not an account, so it cannot make one used."""
    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="bot", metadata={"identity": "reader"})
    _asset(dep, kind=Kind.TOOL, name="reader")
    account = _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="svc", identifier="svc")

    result = assess_effective_access(dep)
    assert _principal(result, "svc")["orphaned"] is True
    assert _principal(result, "svc")["key"] == f"asset:{account.uuid}"


# ---- The agent a scan implies but does not name. ----


def _scan(user, target_url, tools):
    return PentestScan.objects.create(
        user=user, target_url=target_url, consent=True, status=PentestScan.STATUS_COMPLETED,
        engine_response={"findings": []},
        target_config={"tools": [{"name": t} for t in tools]},
    )


def test_two_unnamed_agents_at_two_targets_are_two_agents():
    """Each keeps its own tools. As one ``"agent"`` row the second scan replaced
    the first scan's tools, and those tools fell to the deployment as powers no
    agent owned."""
    dep = _dep()
    derive_assets(dep, _scan(dep.owner, "https://a.example/bot", ["search"]))
    derive_assets(dep, _scan(dep.owner, "https://b.example/bot", ["shell"]))

    agents = {a.identifier: a.metadata["tools"] for a in dep.assets.filter(kind=Kind.AGENT)}
    assert agents == {"agent@a.example/bot": ["search"], "agent@b.example/bot": ["shell"]}


def test_a_rescan_of_the_same_target_is_the_same_agent():
    dep = _dep()
    derive_assets(dep, _scan(dep.owner, "https://a.example/bot", ["search"]))
    derive_assets(dep, _scan(dep.owner, "https://a.example/bot?session=1", ["search", "fetch"]))

    agents = list(dep.assets.filter(kind=Kind.AGENT))
    assert [(a.identifier, a.metadata["tools"]) for a in agents] == [
        ("agent@a.example/bot", ["search", "fetch"])
    ]


def test_a_named_agent_keeps_its_own_identity():
    dep = _dep()
    scan = PentestScan.objects.create(
        user=dep.owner, target_url="https://a.example/bot", consent=True,
        status=PentestScan.STATUS_COMPLETED, engine_response={"findings": []},
        target_config={"agent": {"name": "Planner"}, "tools": [{"name": "search"}]},
    )
    derive_assets(dep, scan)
    assert list(dep.assets.filter(kind=Kind.AGENT).values_list("identifier", flat=True)) == ["Planner"]


# ---- A declared tool's own identity. ----


def _inventory_scan(user, tools, target_url="https://a.example/bot"):
    return PentestScan.objects.create(
        user=user, target_url=target_url, consent=True, status=PentestScan.STATUS_COMPLETED,
        engine_response={"findings": []},
        target_config={"agent": {"name": "assistant"}, "tools": tools},
    )


def test_two_tools_on_one_server_are_two_tools_with_their_own_powers():
    """Both fell back to the server as their identifier, so they were one row with
    the permissions of whichever came second -- here the agent's shell vanished."""
    dep = _dep()
    derive_assets(dep, _inventory_scan(dep.owner, [
        {"name": "exec", "server": "tools-mcp", "permissions": ["shell"]},
        {"name": "search", "server": "tools-mcp", "permissions": ["web"]},
    ]))

    tools = {a.identifier: a.metadata["permissions"] for a in dep.assets.filter(kind=Kind.TOOL)}
    assert tools == {"exec@tools-mcp": ["shell"], "search@tools-mcp": ["web"]}
    agent = _principal(assess_effective_access(dep), "assistant")
    assert "code_execution" in {c["key"] for c in agent["capabilities"]}


@pytest.mark.parametrize("shell_first", [True, False])
def test_a_tool_declared_twice_holds_every_permission_either_line_gave_it(shell_first):
    lines = [
        {"name": "db", "identifier": "db", "permissions": ["shell"], "approved": True},
        {"name": "db", "identifier": "db", "permissions": ["read"]},
    ]
    if not shell_first:
        lines.reverse()
    dep = _dep()
    derive_assets(dep, _inventory_scan(dep.owner, lines))

    tool = dep.assets.get(kind=Kind.TOOL)
    assert sorted(tool.metadata["permissions"]) == ["read", "shell"]
    # One line calling it approved does not vouch for the line that did not.
    assert tool.classification == Asset.Classification.KNOWN
    assert dep.assets.get(kind=Kind.AGENT).metadata["tools"] == ["db"]


def test_a_tool_on_a_declared_mcp_server_is_hosted_by_it_not_itself():
    """Identified by its server, the tool's own ``server`` reference found the
    tool and the server both -- an ambiguous reference in a fully enumerated
    inventory."""
    from assurance import route

    dep = _dep()
    derive_assets(dep, _inventory_scan(dep.owner, [
        {"name": "reader", "server": "mcp-prod", "permissions": ["read"]},
        {"name": "mcp-prod", "kind": "mcp_server"},
    ]))

    result = route.build_route_map(dep)
    assert result["unresolved"] == []
    names = {n["uuid"]: n["name"] for n in result["nodes"]}
    assert {(names[e["source"]], names[e["target"]], e["kind"]) for e in result["edges"] if e["declared"]} == {
        ("assistant", "reader", "invokes"),
        ("assistant", "mcp-prod", "invokes"),
        ("reader", "mcp-prod", "hosted_by"),
    }


# ---- Rows written under the identities this module replaced. ----


def _old_rows(dep, *, agent_tools):
    """What the rules before one-identity-per-component wrote for two tools on
    ``files-mcp``: one row at the server's key, named for the first tool and
    holding the last one's permissions, and the unnamed agent at ``"agent"``."""
    inventory = {"source": "declared_inventory", "declared": True}
    _asset(dep, kind=Kind.TOOL, name="read_file", identifier="files-mcp",
           metadata={**inventory, "server": "files-mcp", "permissions": ["shell"]})
    return _asset(dep, kind=Kind.AGENT, name="agent", identifier="agent",
                  metadata={**inventory, "identity": "", "tools": agent_tools})


def _files_scan(user):
    return PentestScan.objects.create(
        user=user, target_url="https://app.example.com", consent=True,
        status=PentestScan.STATUS_COMPLETED, engine_response={"findings": []},
        target_config={"tools": [
            {"name": "read_file", "server": "files-mcp", "permissions": ["read"]},
            {"name": "run_cmd", "server": "files-mcp", "permissions": ["shell"]},
        ]},
    )


def _graph(dep):
    from assurance import route

    result = route.build_route_map(dep)
    unresolved = sorted((u["reference"], u["mechanism"], u["reason"]) for u in result["unresolved"])
    return (
        sorted(dep.assets.values_list("kind", "identifier")),
        unresolved,
        sorted((u["reference"], u["mechanism"], u["reason"])
               for u in assess_effective_access(dep)["unresolved"]),
    )


def test_a_deployment_scanned_under_the_old_identities_reads_as_a_fresh_one():
    """Rescanned, the old server-keyed tool row and the old ``"agent"`` row stayed
    beside the new ones. The tools' ``server: files-mcp`` then resolved to the old
    tool row, so the gap a fresh deployment reports -- no such server declared --
    read as no gap, and the one agent was two."""
    fresh = _dep("fresh")
    derive_assets(fresh, _files_scan(fresh.owner))

    upgraded = _dep("upgraded")
    _old_rows(upgraded, agent_tools=["files-mcp", "files-mcp"])
    derive_assets(upgraded, _files_scan(upgraded.owner))

    assert _graph(upgraded) == _graph(fresh)
    assert ("files-mcp", "server", "not_found") in _graph(upgraded)[1]


def test_an_old_agent_row_another_agent_still_answers_to_is_kept():
    """The one ``"agent"`` row was every unnamed agent's. One naming tools this
    scan does not declare is another agent, not yet rescanned: deleting it would
    take its powers off the graph until it is."""
    dep = _dep()
    other = _old_rows(dep, agent_tools=["other-mcp"])
    derive_assets(dep, _files_scan(dep.owner))

    assert dep.assets.filter(pk=other.pk).exists()


def test_an_old_tool_row_the_inventory_no_longer_names_is_kept():
    dep = _dep()
    _old_rows(dep, agent_tools=["files-mcp"])
    scan = _files_scan(dep.owner)
    scan.target_config = {"tools": [{"name": "run_cmd", "server": "files-mcp", "permissions": ["shell"]}]}
    scan.save()
    derive_assets(dep, scan)

    assert dep.assets.filter(kind=Kind.TOOL, identifier="files-mcp").exists()


# ---- Where an unnamed agent is. ----


@pytest.mark.parametrize(
    "first, second",
    [
        ("https://bots.example.com:8443/agent", "https://bots.example.com:9443/agent"),
        ("http://bots.example.com/agent", "https://bots.example.com/agent"),
    ],
)
def test_two_unnamed_agents_on_one_host_at_two_ports_are_two_agents(first, second):
    """The anchor was host and path. Two services on one host were one row, and
    the first one's ``exec`` fell to the deployment as a power nobody owned."""
    dep = _dep()
    derive_assets(dep, _scan(dep.owner, first, ["exec"]))
    derive_assets(dep, _scan(dep.owner, second, ["search"]))

    agents = sorted(a.metadata["tools"] for a in dep.assets.filter(kind=Kind.AGENT))
    assert agents == [["exec"], ["search"]]


def test_the_common_https_anchor_reads_host_and_path():
    dep = _dep()
    derive_assets(dep, _scan(dep.owner, "https://a.example:443/bot/", ["search"]))
    assert list(dep.assets.filter(kind=Kind.AGENT).values_list("identifier", flat=True)) == [
        "agent@a.example/bot"
    ]


# ---- An identity is cut to the row's length once. ----


def test_two_tools_that_differ_past_the_identifier_limit_keep_both_powers():
    """They were two merge groups written to one row -- the second replacing the
    first's permissions -- and the agent's edges named strings no row carried."""
    from assurance.assets import IDENTIFIER_MAX

    stem = "x" * IDENTIFIER_MAX
    dep = _dep()
    derive_assets(dep, _inventory_scan(dep.owner, [
        {"name": "run", "identifier": stem + "-a", "permissions": ["shell"]},
        {"name": "fetch", "identifier": stem + "-b", "permissions": ["http:get"]},
    ]))

    tool = dep.assets.get(kind=Kind.TOOL)
    assert sorted(tool.metadata["permissions"]) == ["http:get", "shell"]
    result = assess_effective_access(dep)
    assert result["unresolved"] == []
    assert "code_execution" in {c["key"] for c in _principal(result, "assistant")["capabilities"]}


# ---- An agent's identity is one identity, as every other reader keys it. ----


def test_an_identity_differing_only_in_case_is_the_account_it_names():
    from assurance import route

    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="assistant", metadata={"identity": " SVC-Admin ", "tools": []})
    account = _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="svc-admin",
                     metadata={"permissions": ["iam:admin"]})

    result = assess_effective_access(dep)
    agent = _principal(result, "assistant")
    assert agent["privilege_level"] == "high"
    assert result["unresolved"] == []
    assert _gap_types(_principal(result, "svc-admin")) == []
    edges = route.build_route_map(dep)["edges"]
    assert [e["kind"] for e in edges if e["target"] == str(account.uuid)] == ["acts_as"]


# ---- The lines the mutants could change with every test still passing. ----


def test_an_mcp_server_named_apart_from_its_key_is_the_server_its_tools_run_on():
    from assurance import route

    dep = _dep()
    derive_assets(dep, _inventory_scan(dep.owner, [
        {"name": "Production MCP", "kind": "mcp_server", "server": "mcp-prod"},
        {"name": "reader", "server": "mcp-prod", "permissions": ["read"]},
    ]))

    assert list(dep.assets.filter(kind=Kind.MCP_SERVER).values_list("identifier", flat=True)) == ["mcp-prod"]
    result = route.build_route_map(dep)
    assert result["unresolved"] == []
    names = {n["uuid"]: n["name"] for n in result["nodes"]}
    assert ("reader", "Production MCP", "hosted_by") in {
        (names[e["source"]], names[e["target"]], e["kind"]) for e in result["edges"]
    }


def test_a_tool_that_names_its_endpoint_is_that_endpoint_wherever_it_runs():
    dep = _dep()
    derive_assets(dep, _inventory_scan(dep.owner, [
        {"name": "reader", "endpoint": "https://files.example/read", "server": "mcp-prod"},
    ]))
    assert list(dep.assets.filter(kind=Kind.TOOL).values_list("identifier", flat=True)) == [
        "https://files.example/read"
    ]


def test_a_proven_use_is_not_undone_by_an_ambiguous_one_in_either_order():
    """The first version of this held only because ``bot`` sorts before
    ``payer``: the proven agent is read first here."""
    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="alpha", metadata={"identity": "sa-1"})
    _asset(dep, kind=Kind.AGENT, name="zulu", metadata={"identity": "billing"})
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="billing", identifier="sa-1")
    second = _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="billing", identifier="sa-2")

    result = assess_effective_access(dep)
    gaps = {p["key"]: _gap_types(p) for p in result["principals"] if p["kind"] == Kind.SERVICE_ACCOUNT}
    assert sorted(gaps.values()) == [[], ["use_unproven"]]
    assert gaps[f"asset:{second.uuid}"] == ["use_unproven"]


def test_an_unproven_use_is_an_elevated_gap():
    from assurance.capability import RISK_ELEVATED

    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="bot", metadata={"identity": "billing"})
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="billing", identifier="sa-1")
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="billing", identifier="sa-2")

    for account in (p for p in assess_effective_access(dep)["principals"] if p["kind"] == Kind.SERVICE_ACCOUNT):
        assert [(g["type"], g["risk"]) for g in account["gaps"]] == [("use_unproven", RISK_ELEVATED)]


def test_a_permission_declared_on_two_lines_is_held_once():
    dep = _dep()
    derive_assets(dep, _inventory_scan(dep.owner, [
        {"name": "db", "identifier": "db", "permissions": ["shell", "read"]},
        {"name": "db", "identifier": "db", "permissions": ["shell"]},
    ]))
    assert dep.assets.get(kind=Kind.TOOL).metadata["permissions"] == ["shell", "read"]
