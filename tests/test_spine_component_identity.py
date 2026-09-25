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


def _references(dep):
    from assurance import route

    access = sorted((u["reference"], u["mechanism"], u["reason"])
                    for u in assess_effective_access(dep)["unresolved"])
    assert access == sorted((u["reference"], u["mechanism"], u["reason"])
                            for u in route.build_route_map(dep)["unresolved"])
    return access


def test_a_deployment_scanned_under_the_old_identities_hides_no_gap():
    """Rescanned, the old server-keyed tool row answered the tools' ``server:
    files-mcp`` -- the gap a fresh deployment reports, no such server declared,
    read as no gap. Every reference to a row no scan has recorded under the
    current rules is now followed AND reported, so the upgraded deployment names
    each reference the fresh one does."""
    fresh = _dep("fresh")
    derive_assets(fresh, _files_scan(fresh.owner))
    assert _references(fresh) == [("files-mcp", "server", "not_found")] * 2

    upgraded = _dep("upgraded")
    _old_rows(upgraded, agent_tools=["files-mcp", "files-mcp"])
    derive_assets(upgraded, _files_scan(upgraded.owner))
    # The two new tools' server, the old row's own server (its own key -- it used
    # to resolve to itself and say nothing), and the old agent's two tools.
    assert _references(upgraded) == [("files-mcp", "server", "superseded_identity")] * 3 + [
        ("files-mcp", "tools", "superseded_identity")
    ] * 2


def test_no_scan_deletes_a_row_whatever_rules_wrote_it():
    """Deciding which old row a new declaration replaces meant guessing from its
    content, and every guess deleted somebody's row: a named agent called
    ``agent``, another unnamed agent's row, a server row another agent still
    invoked, a row a person had classified. A row kept is at worst a power
    counted twice, and reported; a row deleted wrongly is a power gone."""
    dep = _dep()
    _old_rows(dep, agent_tools=["files-mcp", "files-mcp"])
    human = dep.assets.get(identifier="files-mcp")
    human.classification = Asset.Classification.HIGH_RISK
    human.classification_source = Asset.ClassificationSource.HUMAN
    human.save()
    before = set(dep.assets.values_list("pk", flat=True))

    derive_assets(dep, _files_scan(dep.owner))
    derive_assets(dep, _scan(dep.owner, "https://b.example/bot", ["files-mcp"]))

    assert before <= set(dep.assets.values_list("pk", flat=True))
    human.refresh_from_db()
    assert human.classification == Asset.Classification.HIGH_RISK


def test_a_rescan_records_an_unchanged_identity_under_the_current_rules():
    from assurance.graph_refs import IDENTITY_RULES

    dep = _dep()
    inventory = {"source": "declared_inventory", "declared": True}
    _asset(dep, kind=Kind.AGENT, name="assistant", metadata={**inventory, "tools": ["reader"]})
    _asset(dep, kind=Kind.TOOL, name="reader", metadata={**inventory, "permissions": ["read"]})
    assert _references(dep) == [("reader", "tools", "superseded_identity")]

    derive_assets(dep, _inventory_scan(dep.owner, [{"name": "reader", "identifier": "reader"}]))

    assert {a.metadata["identity_rules"] for a in dep.assets.filter(kind__in=[Kind.AGENT, Kind.TOOL])} == {
        IDENTITY_RULES
    }
    assert _references(dep) == []


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
    assert _gap_types(_principal(result, "svc-admin")) == ["privileged_access"]
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


@pytest.mark.parametrize(
    "identity, identifier, name",
    [(" SVC-Ops ", "svc-ops", "Operations"), ("BILLING", "sa-9", "billing")],
)
def test_an_account_named_in_another_case_is_used_not_orphaned(identity, identifier, name):
    """An account with no powers of its own is orphaned unless some agent acts as
    it, so this is where the identity lookup shows: by identifier, and by name."""
    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="bot", metadata={"identity": identity})
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name=name, identifier=identifier)

    result = assess_effective_access(dep)
    assert _principal(result, name)["orphaned"] is False
    assert result["unresolved"] == []


def test_an_exact_spelling_beats_a_case_blind_one():
    """Case-folded first, ``SVC-Admin`` found the account IDENTIFIED ``svc-admin``
    before the one NAMED ``SVC-Admin`` and gave the agent the wrong account's
    powers -- none -- with no gap to say so."""
    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="bot", metadata={"identity": "SVC-Admin", "tools": []})
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="Reporting SA", identifier="svc-admin")
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="SVC-Admin", identifier="sa-b",
           metadata={"permissions": ["iam:admin"]})

    result = assess_effective_access(dep)
    assert _principal(result, "bot")["privilege_level"] == "high"
    assert _references(dep) == []


def test_an_anchor_never_carries_the_targets_credentials_or_query():
    dep = _dep()
    derive_assets(dep, _scan(dep.owner, "https://ops:S3cr3t@bots.example.com:99999/agent?token=abc", ["a"]))
    agent = dep.assets.get(kind=Kind.AGENT)
    assert (agent.identifier, agent.name) == ("agent@bots.example.com:99999/agent",) * 2


def test_two_ipv6_agents_are_two_anchors():
    dep = _dep()
    derive_assets(dep, _scan(dep.owner, "https://[2001:db8::1]:8443/agent", ["exec"]))
    derive_assets(dep, _scan(dep.owner, "https://[2001:db8::1:8443]/agent", ["search"]))
    assert sorted(dep.assets.filter(kind=Kind.AGENT).values_list("identifier", flat=True)) == [
        "agent@[2001:db8::1:8443]/agent",
        "agent@[2001:db8::1]:8443/agent",
    ]


def test_a_target_with_no_host_anchors_no_agent():
    """No host is nowhere: no agent node, rather than one named for the raw
    target. Its tools still count, as powers the deployment holds."""
    dep = _dep()
    derive_assets(dep, _scan(dep.owner, "https:///agent", ["exec"]))
    assert not dep.assets.filter(kind=Kind.AGENT).exists()
    assert dep.assets.filter(kind=Kind.TOOL, identifier="exec").exists()


# ---- A declaration that lands on an old row it is not. ----


def _landing_scan(user, tool):
    return PentestScan.objects.create(
        user=user, target_url="https://b.example/bot", consent=True,
        status=PentestScan.STATUS_COMPLETED, engine_response={"findings": []},
        target_config={"tools": [tool]},
    )


def test_another_agents_declaration_merges_into_an_old_row_and_leaves_it_reported():
    """A tool named for the server writes the key the old collapsed row holds. The
    refresh replaced its permissions and stamped it current, so the old agent --
    not rescanned -- lost its shell and the reason naming the row disappeared."""
    dep = _dep()
    _old_rows(dep, agent_tools=["files-mcp"])
    derive_assets(dep, _landing_scan(dep.owner, {"name": "files-mcp", "permissions": ["http:get"]}))

    ghost = dep.assets.get(kind=Kind.TOOL, identifier="files-mcp")
    assert sorted(ghost.metadata["permissions"]) == ["http:get", "shell"]
    assert "identity_rules" not in ghost.metadata
    assert ghost.metadata["server"] == "files-mcp"
    result = assess_effective_access(dep)
    assert "code_execution" in {c["key"] for c in _principal(result, "agent")["capabilities"]}
    assert ("files-mcp", "tools", "superseded_identity") in _references(dep)


def test_a_nameless_tool_on_a_server_has_its_own_key_and_leaves_the_old_row_alone():
    """As the server's bare name it landed on the old collapsed row. It is
    ``@server`` now, which no old row holds."""
    dep = _dep()
    _old_rows(dep, agent_tools=["files-mcp"])
    derive_assets(dep, _landing_scan(dep.owner, {"server": "files-mcp", "permissions": ["http:get"]}))

    assert dep.assets.get(kind=Kind.TOOL, identifier="files-mcp").metadata["permissions"] == ["shell"]
    assert dep.assets.get(kind=Kind.TOOL, identifier="@files-mcp").metadata["permissions"] == ["http:get"]


def test_a_declaration_that_does_not_cover_an_old_row_cannot_stamp_it():
    """The row's NAME was the test, and the name is written once, at creation:
    the old rules went on replacing the permissions under it. Created by a nameless
    tool and then overwritten by a named one, the row matched a new declaration's
    name, was stamped current, and the agent it still served lost its shell with
    nothing left reporting it -- the agent itself stamped by 0034."""
    from assurance.graph_refs import IDENTITY_RULES

    dep = _dep()
    inventory = {"source": "declared_inventory", "declared": True}
    _asset(dep, kind=Kind.TOOL, name="files-mcp", identifier="files-mcp",
           metadata={**inventory, "server": "files-mcp", "permissions": ["shell"]})
    _asset(dep, kind=Kind.AGENT, name="beta", identifier="beta",
           metadata={**inventory, "identity_rules": IDENTITY_RULES, "identity": "", "tools": ["files-mcp"]})
    derive_assets(dep, _landing_scan(dep.owner, {"name": "files-mcp", "permissions": ["http:get"]}))

    row = dep.assets.get(kind=Kind.TOOL, identifier="files-mcp")
    assert sorted(row.metadata["permissions"]) == ["http:get", "shell"]
    assert "identity_rules" not in row.metadata
    result = assess_effective_access(dep)
    assert "code_execution" in {c["key"] for c in _principal(result, "beta")["capabilities"]}
    assert ("files-mcp", "tools", "superseded_identity") in _references(dep)


def test_a_declaration_that_covers_the_old_agent_row_re_records_it():
    """An agent named "agent" re-declaring what the old row holds is that row.
    Matched on the name alone it could never be stamped, and the claim stayed
    partially verified however many times it was rescanned."""
    from assurance.graph_refs import IDENTITY_RULES

    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="agent", identifier="agent",
           metadata={"source": "declared_inventory", "declared": True, "identity": "", "tools": ["search"]})
    scan = _inventory_scan(dep.owner, [{"name": "search", "identifier": "search"}])
    scan.target_config = {**scan.target_config, "agent": {"name": "agent"}}
    scan.save()
    derive_assets(dep, scan)

    assert dep.assets.get(kind=Kind.AGENT, identifier="agent").metadata["identity_rules"] == IDENTITY_RULES
    assert _references(dep) == []

    # Recorded under the current rules now, it is replaced like any other row: a
    # declaration dropping the tool drops it.
    scan.target_config = {"agent": {"name": "agent"}, "tools": []}
    scan.save()
    derive_assets(dep, scan)
    assert dep.assets.get(kind=Kind.AGENT, identifier="agent").metadata["tools"] == []


def test_a_row_the_current_rules_wrote_is_replaced_not_merged():
    """Only a row carrying an older stamp merges: once stamped, a re-declaration
    that drops a permission drops it."""
    dep = _dep()
    derive_assets(dep, _inventory_scan(dep.owner, [{"name": "db", "server": "files-mcp", "permissions": ["shell", "read"]}]))
    derive_assets(dep, _inventory_scan(dep.owner, [{"name": "db", "server": "files-mcp", "permissions": ["read"]}]))
    assert dep.assets.get(kind=Kind.TOOL, identifier="db@files-mcp").metadata["permissions"] == ["read"]


def test_an_old_row_whose_key_the_rules_never_collapsed_is_replaced_not_merged():
    """A named tool with no server was one row under both rules; an older stamp on
    it is no sign of a collapse, and a re-declaration replaces it."""
    from assurance.graph_refs import IDENTITY_RULES

    dep = _dep()
    _asset(dep, kind=Kind.TOOL, name="db", identifier="db",
           metadata={"source": "declared_inventory", "declared": True, "permissions": ["shell", "read"]})
    derive_assets(dep, _inventory_scan(dep.owner, [{"name": "db", "identifier": "db", "permissions": ["read"]}]))
    row = dep.assets.get(kind=Kind.TOOL, identifier="db")
    assert (row.metadata["permissions"], row.metadata["identity_rules"]) == (["read"], IDENTITY_RULES)


def test_an_mcp_server_row_is_never_a_collapse():
    from assurance.graph_refs import IDENTITY_RULES

    dep = _dep()
    _asset(dep, kind=Kind.MCP_SERVER, name="files-mcp", identifier="files-mcp",
           metadata={"source": "declared_inventory", "declared": True, "server": "files-mcp",
                     "permissions": ["shell"]})
    derive_assets(dep, _inventory_scan(dep.owner, [{"name": "files-mcp", "kind": "mcp_server", "server": "files-mcp"}]))
    row = dep.assets.get(kind=Kind.MCP_SERVER)
    assert (row.metadata["permissions"], row.metadata["identity_rules"]) == ([], IDENTITY_RULES)


@pytest.mark.parametrize("row_approved, approved, expected", [
    (False, True, Asset.Classification.KNOWN),
    (True, True, Asset.Classification.APPROVED),
    (True, False, Asset.Classification.KNOWN),
])
def test_a_merge_is_approved_only_if_the_row_and_the_declaration_both_are(row_approved, approved, expected):
    dep = _dep()
    _old_rows(dep, agent_tools=["files-mcp"])
    ghost = dep.assets.get(kind=Kind.TOOL, identifier="files-mcp")
    ghost.classification = Asset.Classification.APPROVED if row_approved else Asset.Classification.KNOWN
    ghost.save()
    derive_assets(dep, _landing_scan(dep.owner, {"name": "files-mcp", "permissions": ["http:get"], "approved": approved}))
    assert dep.assets.get(pk=ghost.pk).classification == expected


# ---- An old agent row is a source too. ----


def test_the_old_agent_row_proves_no_use_of_the_account_it_names():
    """A principal: no reference resolves TO it, so while only targets were
    checked its identity counted as proven use and the orphaned account read as
    used, with nothing anywhere to say why."""
    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="agent", identifier="agent",
           metadata={"source": "declared_inventory", "identity": "svc-legacy", "tools": []})
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="svc-legacy")

    result = assess_effective_access(dep)
    assert _gap_types(_principal(result, "svc-legacy")) == ["use_unproven"]
    assert _references(dep) == [("svc-legacy", "identity", "superseded_identity")]


def test_an_ambiguous_reference_with_an_old_candidate_says_both():
    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="bot", metadata={
        "source": "declared_inventory", "identity_rules": 2, "tools": ["files-mcp"]})
    _asset(dep, kind=Kind.TOOL, name="read_file", identifier="files-mcp",
           metadata={"source": "declared_inventory", "server": "", "permissions": ["shell"]})
    _asset(dep, kind=Kind.MCP_SERVER, name="files-mcp",
           metadata={"source": "declared_inventory", "identity_rules": 2})

    assert _reasons(dep) == [("files-mcp", "tools", ("ambiguous", "superseded_identity"))]


def test_the_old_candidate_is_named_wherever_it_stands_among_the_candidates():
    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="bot", metadata={
        "source": "declared_inventory", "identity_rules": 2, "tools": ["files-mcp"]})
    _asset(dep, kind=Kind.MCP_SERVER, name="files-mcp",
           metadata={"source": "declared_inventory", "identity_rules": 2})
    _asset(dep, kind=Kind.TOOL, name="read_file", identifier="files-mcp",
           metadata={"source": "declared_inventory", "server": "", "permissions": ["shell"]})

    assert _reasons(dep) == [("files-mcp", "tools", ("ambiguous", "superseded_identity"))]


def _reasons(dep):
    from assurance import route

    access = sorted((u["reference"], u["mechanism"], tuple(u["reasons"]))
                    for u in assess_effective_access(dep)["unresolved"])
    assert access == sorted((u["reference"], u["mechanism"], tuple(u["reasons"]))
                            for u in route.build_route_map(dep)["unresolved"])
    return access


def test_an_older_stamp_is_superseded_too():
    from assurance.graph_refs import superseded_identity

    dep = _dep()
    older = _asset(dep, metadata={"source": "declared_inventory", "identity_rules": 1}, name="t")
    current = _asset(dep, metadata={"source": "declared_inventory", "identity_rules": 2}, name="u")
    scanned = _asset(dep, metadata={"source": "scan_target"}, name="v")
    assert [superseded_identity(a) for a in (older, current, scanned)] == [True, False, False]


# ---- The identity lookup's order. ----


def test_an_identity_is_an_account_before_anything_else_carrying_the_string():
    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="bot", metadata={"identity": "svc-x", "tools": []})
    _asset(dep, kind=Kind.TOOL, name="exporter", identifier="svc-x")
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="svc-x", identifier="sa-7",
           metadata={"permissions": ["iam:admin"]})

    assert _principal(assess_effective_access(dep), "bot")["privilege_level"] == "high"


def test_an_exact_spelling_two_accounts_share_is_ambiguous_not_a_folded_third():
    """Exactly spelled, ``Billing`` is two accounts' name. Falling back to the
    case-blind index whenever the exact lookup was not a clean single match
    handed the agent a third account's admin powers as if it were the one."""
    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="bot", metadata={"identity": "Billing", "tools": []})
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="Billing", identifier="sa-1")
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="Billing", identifier="sa-2")
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="Other", identifier="billing",
           metadata={"permissions": ["iam:admin"]})

    assert _principal(assess_effective_access(dep), "bot")["privilege_level"] != "high"
    assert _references(dep) == [("Billing", "identity", "ambiguous")]


# ---- More of where an unnamed agent is. ----


@pytest.mark.parametrize(
    "target, anchor",
    [
        ("https://u:pw@h.example.com/a", "agent@h.example.com/a"),
        ("u:p@h.example.com/a?tok=1", "agent@h.example.com/a"),
        ("h.example.com:8443/a?tok=secret", "agent@h.example.com:8443/a"),
        ("https://h.example.com:0443/a", "agent@h.example.com/a"),
        ("http://h.example.com:080/a", "agent@h.example.com:80/a"),
    ],
)
def test_an_anchor_is_host_port_and_path_and_nothing_else(target, anchor):
    dep = _dep()
    derive_assets(dep, _scan(dep.owner, target, ["a"]))
    assert list(dep.assets.filter(kind=Kind.AGENT).values_list("identifier", flat=True)) == [anchor]


def test_a_target_the_parser_rejects_anchors_no_agent():
    dep = _dep()
    derive_assets(dep, _scan(dep.owner, "https://u:pw@[::1/agent?tok=1", ["a"]))
    assert not dep.assets.filter(kind=Kind.AGENT).exists()



# ---- Round 4. ----


def test_a_nameless_tool_and_a_tool_named_for_its_server_are_two_tools():
    """One key, `github`, for both: on a fresh deployment the second agent's scan
    replaced the first one's shell, with nothing to say it had."""
    dep = _dep()
    derive_assets(dep, _landing_scan(dep.owner, {"server": "github", "permissions": ["shell"]}))
    scan = _inventory_scan(dep.owner, [{"name": "github", "permissions": ["http:get"]}])
    derive_assets(dep, scan)

    tools = {a.identifier: a.metadata["permissions"] for a in dep.assets.filter(kind=Kind.TOOL)}
    assert tools == {"@github": ["shell"], "github": ["http:get"]}
    agents = {a.identifier: a for a in dep.assets.filter(kind=Kind.AGENT)}
    unnamed = next(a for k, a in agents.items() if k.startswith("agent@"))
    assert unnamed.metadata["tools"] == ["@github"]


def test_the_old_agent_row_keeps_every_identity_it_was_declared_with():
    """The literal "agent" row stood for every unnamed agent. Merging kept its
    first identity and dropped the one arriving, so an agent named "agent" that
    acts as an admin account read as holding nothing."""
    from assurance import route

    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="agent", identifier="agent",
           metadata={"source": "declared_inventory", "declared": True, "identity": "svc-read", "tools": []})
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="svc-read")
    admin = _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="svc-admin", metadata={"permissions": ["iam:admin"]})
    scan = _inventory_scan(dep.owner, [])
    scan.target_config = {"agent": {"name": "agent", "identity": "svc-admin"}, "tools": []}
    scan.save()
    derive_assets(dep, scan)
    derive_assets(dep, scan)

    row = dep.assets.get(kind=Kind.AGENT, identifier="agent")
    assert (row.metadata["identity"], row.metadata["merged_identities"]) == ("svc-read", ["svc-admin"])
    assert _principal(assess_effective_access(dep), "agent")["privilege_level"] == "high"
    edges = route.build_route_map(dep)["edges"]
    assert str(admin.uuid) in {e["target"] for e in edges if e["kind"] == "acts_as"}


def test_the_old_agent_row_merges_its_tools_rather_than_losing_them():
    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="agent", identifier="agent",
           metadata={"source": "declared_inventory", "declared": True, "identity": "", "tools": ["old-tool"]})
    scan = _inventory_scan(dep.owner, [{"name": "search", "identifier": "search"}])
    scan.target_config = {**scan.target_config, "agent": {"name": "agent"}}
    scan.save()
    derive_assets(dep, scan)
    assert dep.assets.get(kind=Kind.AGENT, identifier="agent").metadata["tools"] == ["old-tool", "search"]


def test_an_account_only_an_unrecorded_agent_names_says_so():
    """The gap claimed more than one service account answered to the identity. The
    deployment had one; the cause was an agent row no scan had re-recorded."""
    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="agent", identifier="agent",
           metadata={"source": "declared_inventory", "identity": "svc-legacy", "tools": []})
    _asset(dep, kind=Kind.SERVICE_ACCOUNT, name="svc-legacy")

    (gap,) = _principal(assess_effective_access(dep), "svc-legacy")["gaps"]
    assert gap["type"] == "use_unproven"
    assert "re-recorded" in gap["detail"]
    assert "more than one service account" not in gap["detail"]


def test_one_reference_is_one_row_however_many_reasons():
    """A row per reason counted one reference twice in every summary built on the
    list, and the claim digest named it twice, once as unplaceable and once as
    followed."""
    from assurance import route
    from assurance.claims import _derive_effective_access

    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="bot", metadata={
        "source": "declared_inventory", "identity_rules": 2, "tools": ["files-mcp"]})
    _asset(dep, kind=Kind.TOOL, name="read_file", identifier="files-mcp",
           metadata={"source": "declared_inventory", "server": "", "permissions": ["shell"]})
    _asset(dep, kind=Kind.MCP_SERVER, name="files-mcp",
           metadata={"source": "declared_inventory", "identity_rules": 2})

    assert assess_effective_access(dep)["summary"]["unresolved_references"] == 1
    summary = route.build_route_map(dep)["summary"]
    assert (summary["unresolved_edges"], summary["unresolved_tool_references"]) == (1, 1)
    digest = _derive_effective_access(dep)["supporting_summary"]
    assert digest.count("bot → files-mcp") == 1
    assert "could not be placed" in digest


def test_a_reference_only_an_old_row_answers_is_named_as_followed_not_unplaced():
    from assurance.claims import _derive_effective_access

    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="bot", metadata={
        "source": "declared_inventory", "identity_rules": 2, "tools": ["reader"]})
    _asset(dep, kind=Kind.TOOL, name="reader", metadata={"source": "declared_inventory", "permissions": ["read"]})

    digest = _derive_effective_access(dep)["supporting_summary"]
    assert "could not be placed" not in digest
    assert "a rescan is what confirms it: bot → reader." in digest


def test_an_old_source_whose_reference_names_nothing_is_not_found_only():
    """"Followed" would say the reference led somewhere. It led nowhere."""
    dep = _dep()
    _asset(dep, kind=Kind.AGENT, name="agent", identifier="agent",
           metadata={"source": "declared_inventory", "tools": ["gone"]})
    assert _reasons(dep) == [("gone", "tools", ("not_found",))]


def test_an_old_source_is_named_on_its_server_reference_too():
    dep = _dep()
    _asset(dep, kind=Kind.TOOL, name="read_file", identifier="files-mcp",
           metadata={"source": "declared_inventory", "server": "mcp-prod", "permissions": ["read"]})
    _asset(dep, kind=Kind.MCP_SERVER, name="mcp-prod",
           metadata={"source": "declared_inventory", "identity_rules": 2})
    assert _reasons(dep) == [("mcp-prod", "server", ("superseded_identity",))]


@pytest.mark.parametrize("target, anchor", [
    ("https://bots.example.com:\u00b2/agent", "agent@bots.example.com:\u00b2/agent"),
    ("https://h.example.com:0/a", "agent@h.example.com:0/a"),
])
def test_a_port_is_its_number_only_when_it_is_ascii_digits(target, anchor):
    """`str.isdigit` accepts "²", which `int` refuses: the anchor raised out of the
    scan's derivation instead of keeping the port as written."""
    dep = _dep()
    derive_assets(dep, _scan(dep.owner, target, ["a"]))
    assert list(dep.assets.filter(kind=Kind.AGENT).values_list("identifier", flat=True)) == [anchor]


def test_a_bare_path_target_anchors_no_agent():
    dep = _dep()
    derive_assets(dep, _scan(dep.owner, "/agent", ["a"]))
    assert not dep.assets.filter(kind=Kind.AGENT).exists()


# ---- 0034: which rows it records under the current rules. ----


def test_0034_stamps_exactly_the_rows_both_rules_key_alike():
    from importlib import import_module

    from django.apps import apps

    migration = import_module("assurance.migrations.0034_stamp_unchanged_identities")
    dep = _dep()
    inv = {"source": "declared_inventory"}
    rows = {
        "named agent": _asset(dep, kind=Kind.AGENT, name="bot", metadata={**inv}),
        "the literal agent": _asset(dep, kind=Kind.AGENT, name="agent", identifier="agent", metadata={**inv}),
        "tool keyed by its server": _asset(dep, name="read_file", identifier="files-mcp",
                                           metadata={**inv, "server": "files-mcp"}),
        "tool with its own identifier": _asset(dep, name="reader", identifier="https://x/read",
                                               metadata={**inv, "server": "files-mcp"}),
        "tool with no server": _asset(dep, name="search", metadata={**inv}),
        "mcp server": _asset(dep, kind=Kind.MCP_SERVER, name="mcp-prod", metadata={**inv, "server": "mcp-prod"}),
        "not declared inventory": _asset(dep, name="scanned", metadata={"source": "scan_target"}),
        "an older stamp": _asset(dep, name="older", metadata={**inv, "identity_rules": 1}),
    }
    for _ in range(2):  # the second pass changes nothing
        migration.stamp(apps, None)
        stamped = {k for k, a in rows.items() if Asset.objects.get(pk=a.pk).metadata.get("identity_rules") == 2}
        assert stamped == {"named agent", "tool with its own identifier", "tool with no server", "mcp server"}
    assert Asset.objects.get(pk=rows["an older stamp"].pk).metadata["identity_rules"] == 1
