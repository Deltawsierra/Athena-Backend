"""There is one asset graph, and every reader of it must see the same graph.

Two modules reconstruct the deployment's asset→asset edges from the same strings
in ``Asset.metadata``: :func:`assurance.access.assess_effective_access` (who can
reach what) and :func:`assurance.route.build_route_map` (the layered data-flow
map). Neither stores an edge; both resolve the references at read time. They were
resolving them differently, so they disagreed about which hops exist — and a hop
that exists for the reach assessment and not for the route map is a hop the
operator is told about in one report and not the other.

Measured on the same deployment, before :mod:`assurance.graph_refs`:

=================================== ============== ==============
reference                            access read    route read
=================================== ============== ==============
tool named by name, not identifier   a proven hop   nothing
``server`` → a data store            a proven hop   nothing
``server`` → a non-existent name     nothing        nothing
``server`` on a non-tool asset       a proven hop   nothing
=================================== ============== ==============

The third row is the one that matters most and it is why the resolver is shared
rather than merely fixed in one place. A reference the inventory declares and
discovery cannot place is a FACT — "this system names a component we could not
find" — and both readers dropped it on the floor for the ``server`` mechanism.
Not an edge and not a gap: the map read as complete because the incompleteness
had nowhere to go. That is this platform's governing defect, a silent zero, in
the middle of the substrate every cross-cutting claim is supposed to stand on.

So: these tests assert PARITY, not behaviour in one module. Each one builds one
deployment, asks both readers, and requires them to agree. A future change that
fixes one reader and not the other fails here.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from assurance import route
from assurance.access import assess_effective_access
from assurance.graph_refs import (
    MECHANISM_IDENTITY,
    MECHANISM_SERVER,
    MECHANISM_TOOLS,
    UNRESOLVED_AMBIGUOUS,
    UNRESOLVED_NAMES_A_PRINCIPAL,
    UNRESOLVED_NOT_FOUND,
)
from assurance.models import Asset, Deployment

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst"):
    return User.objects.create_user(username=name, password="x", role=User.Roles.ANALYST)


def _dep(name="d"):
    return Deployment.objects.create(name=name, owner=_user(f"u-{name}"))


def _scan(dep, inventory: dict):
    """A completed scan carrying a declared inventory in ``target_config``, which is
    what the production asset writer reads. Built through the real model so the test
    exercises the writer rather than a hand-made asset shape it never produces."""
    from pentest.models import PentestScan

    return PentestScan.objects.create(
        user=dep.owner,
        target_url="https://app.example.com/",
        consent=True,
        status=PentestScan.STATUS_COMPLETED,
        target_config=inventory,
    )


def _asset(dep, *, kind, name, identifier=None, metadata=None,
           classification=Asset.Classification.KNOWN):
    return Asset.objects.create(
        deployment=dep, kind=kind, classification=classification,
        name=name, identifier=identifier if identifier is not None else name,
        metadata=metadata or {},
    )


# ---- How each reader reports a hop, reduced to one comparable shape. ----


def _access_hops(dep) -> set[tuple[str, str]]:
    """``(principal name, reached component name)`` for every hop the reach
    assessment can evidence. Reach is transitive, so a chain contributes the whole
    closure; these tests keep their graphs one hop deep so that stays readable."""
    result = assess_effective_access(dep)
    return {
        (p["name"], r["target"])
        for p in result["principals"]
        for r in p["effective_reach"]
    }


def _route_declared_hops(dep) -> set[tuple[str, str]]:
    """``(source name, target name)`` for every DECLARED edge on the route map.
    Inferred spine edges are excluded on purpose: they are the map's own shape,
    not a claim the inventory made, and the reach assessment draws none of them."""
    result = route.build_route_map(dep)
    by_uuid = {n["uuid"]: n["name"] for n in result["nodes"]}
    return {
        (by_uuid[e["source"]], by_uuid[e["target"]])
        for e in result["edges"]
        if e["declared"]
    }


def _unresolved_rows(dep) -> tuple[list[dict], list[dict]]:
    return (
        assess_effective_access(dep)["unresolved"],
        route.build_route_map(dep)["unresolved"],
    )


# ---- Negative control: the shared resolver did not break the ordinary hop. ----


def test_a_tool_named_by_its_identifier_is_still_a_hop_for_both_readers():
    """The control. Every other test here is about a reference that used to be
    read wrongly; this one is about the reference that was always read right, and
    it must keep being read right. Without it, "the readers agree" could be
    satisfied by both of them seeing nothing."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["fetch-tool"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="fetch", identifier="fetch-tool")

    assert ("assistant", "fetch") in _access_hops(dep)
    assert ("assistant", "fetch") in _route_declared_hops(dep)
    assert _unresolved_rows(dep) == ([], [])


# ---- The three measured disagreements. ----


def test_a_tool_named_by_name_rather_than_identifier_is_a_hop_for_both_readers():
    """The inventory's ``tools`` list holds free strings, and a discovery source
    that writes the tool's NAME there is not making a mistake — the resolver's
    contract is identifier first, then name. The route map used to consult the
    identifier index alone, so this hop existed for one reader only."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["Payments API"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="Payments API", identifier="tool-9931")

    assert ("assistant", "Payments API") in _access_hops(dep)
    assert ("assistant", "Payments API") in _route_declared_hops(dep)
    # And it is a hop, not a gap: resolving by name is resolution.
    assert _unresolved_rows(dep) == ([], [])


def test_a_server_reference_to_something_that_is_not_an_mcp_server_is_a_hop_for_both():
    """``metadata.server`` is "the backend this component is wired to". The route
    map only drew the edge when the target's kind was MCP_SERVER and dropped it
    otherwise — so a tool wired to a data store was a proven path to the data for
    the reach assessment and no path at all on the map, with nothing in the gaps
    to say a declaration had been discarded."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.TOOL, name="report-builder", identifier="report-builder",
           metadata={"server": "customer-db"})
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="customer-db", identifier="customer-db")

    assert ("report-builder", "customer-db") in _route_declared_hops(dep)
    assert _unresolved_rows(dep) == ([], [])

    # The reach assessment reads it through whichever principal owns the tool; with
    # no principal in this graph there is no reach to compare, so the parity claim
    # here is about the edge. Add the agent and both readers must show the chain.
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["report-builder"]})
    hops = _access_hops(dep)
    assert ("assistant", "report-builder") in hops
    assert ("assistant", "customer-db") in hops, "the transitive hop through the tool"
    assert ("report-builder", "customer-db") in _route_declared_hops(dep)


def test_a_server_reference_naming_nothing_is_recorded_by_both_readers():
    """The worst of the three. An unresolvable ``server`` was invisible to BOTH
    readers: no edge, and no unresolved row either, because only the agent→tool
    mechanism had somewhere to put a miss. An inventory pointing at a component
    nobody can find was indistinguishable from an inventory pointing at nothing."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.TOOL, name="report-builder", identifier="report-builder",
           metadata={"server": "mcp-ghost"})

    access_rows, route_rows = _unresolved_rows(dep)
    expected = {
        "source": "report-builder",
        "source_kind": Asset.Kind.TOOL,
        "reference": "mcp-ghost",
        "mechanism": MECHANISM_SERVER,
        "reason": "not_found",
        "reasons": ["not_found"],
    }
    assert access_rows == [expected]
    assert route_rows == [expected]
    # No node was invented to satisfy it.
    assert [n["name"] for n in route.build_route_map(dep)["nodes"]] == ["report-builder"]


def test_a_server_declared_on_a_non_tool_asset_is_read_by_both():
    """The route map read ``server`` on three kinds (tool, MCP server, skill); the
    reach assessment read it on every asset. So an API naming its backend was a
    hop for one reader and did not exist for the other."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.API, name="app.example.com", identifier="app.example.com",
           metadata={"server": "orders-db"})
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="orders-db", identifier="orders-db")

    assert ("app.example.com", "orders-db") in _route_declared_hops(dep)
    assert _unresolved_rows(dep) == ([], [])


# ---- The unresolved channel itself. ----


def test_an_unresolvable_tool_reference_is_recorded_identically_by_both_readers():
    """Both readers had a channel for this one; they described it differently
    (``{agent, tool_identifier}`` vs nothing at all in the reach assessment).
    One shape now, so an operator reading either report chases the same string."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["ghost-tool"]})

    access_rows, route_rows = _unresolved_rows(dep)
    expected = {
        "source": "assistant",
        "source_kind": Asset.Kind.AGENT,
        "reference": "ghost-tool",
        "mechanism": MECHANISM_TOOLS,
        "reason": "not_found",
        "reasons": ["not_found"],
    }
    assert access_rows == [expected]
    assert route_rows == [expected]


def test_the_summary_counts_the_unresolved_references_it_reports():
    """A gap nobody counts is a gap nobody reads. Each reader's summary must add
    up to its own list — including the per-mechanism split on the route map, so
    "the inventory names four tools we cannot find" cannot hide inside a total."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["ghost-a", "ghost-b"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="report-builder", identifier="report-builder",
           metadata={"server": "mcp-ghost"})

    access_result = assess_effective_access(dep)
    assert access_result["summary"]["unresolved_references"] == 3
    assert len(access_result["unresolved"]) == 3

    route_result = route.build_route_map(dep)
    assert route_result["summary"]["unresolved_edges"] == 3
    assert route_result["summary"]["unresolved_tool_references"] == 2
    assert route_result["summary"]["unresolved_server_references"] == 1
    assert len(route_result["unresolved"]) == 3


def test_an_empty_reference_is_not_a_gap_for_either_reader():
    """An empty string in the ``tools`` list is not a reference to anything — it is
    noise from whatever wrote the metadata. Counting it would inflate the gap
    count with nothing an operator could act on, which is the mirror image of the
    silent zero: a manufactured finding."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["", "   ", None], "server": "  "})

    assert _unresolved_rows(dep) == ([], [])
    assert _route_declared_hops(dep) == set()


def test_the_identifier_index_wins_over_the_name_index():
    """Two assets, one's identifier equal to the other's name. The resolver's
    order is identifier first because the identifier is the dedup key
    (``UniqueConstraint(deployment, kind, identifier)``) and a name is not unique;
    resolving by name first would make the edge depend on iteration order."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["shared-key"]})
    by_name = _asset(dep, kind=Asset.Kind.TOOL, name="shared-key", identifier="tool-by-name")
    by_ident = _asset(dep, kind=Asset.Kind.TOOL, name="the-real-target", identifier="shared-key")

    assert ("assistant", by_ident.name) in _access_hops(dep)
    assert ("assistant", by_ident.name) in _route_declared_hops(dep)
    assert ("assistant", by_name.name) not in _access_hops(dep)
    assert ("assistant", by_name.name) not in _route_declared_hops(dep)


def test_a_reference_cannot_reach_another_deployment(): 
    """Resolution is scoped to one deployment's inventory. A name that exists in
    another tenant's graph resolves to nothing here — and, being unresolvable, is
    reported as the gap it is rather than quietly reaching across the boundary."""
    mine = _dep("mine")
    theirs = _dep("theirs")
    _asset(theirs, kind=Asset.Kind.TOOL, name="their-tool", identifier="their-tool")
    _asset(mine, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["their-tool"]})

    access_rows, route_rows = _unresolved_rows(mine)
    assert [r["reference"] for r in access_rows] == ["their-tool"]
    assert [r["reference"] for r in route_rows] == ["their-tool"]
    assert _route_declared_hops(mine) == set()
    assert _access_hops(mine) == set()


def test_a_self_reference_is_neither_an_edge_nor_a_gap_for_either_reader():
    """A component naming itself as its backend resolves — so it is not a
    dangling reference — but a self-loop is not a hop. Both readers must land on
    the same answer, which is that there is nothing here to report in either
    channel."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="warehouse", identifier="warehouse",
           metadata={"server": "warehouse"})

    assert _unresolved_rows(dep) == ([], [])
    assert _route_declared_hops(dep) == set()
    assert _access_hops(dep) == set()


def test_an_agent_listing_itself_as_a_tool_is_a_gap_both_readers_report():
    """An agent's ``tools`` name tools; an agent is not one. So an agent whose
    tool list names only itself names no tool at all -- it used to resolve to
    itself and vanish as a self-loop, reading as a clean declaration. It is still
    no edge, and now both readers say the reference names a principal."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["assistant"]})

    access_rows, route_rows = _unresolved_rows(dep)
    assert access_rows == route_rows
    assert [(r["reference"], r["mechanism"], r["reason"]) for r in access_rows] == [
        ("assistant", MECHANISM_TOOLS, UNRESOLVED_NAMES_A_PRINCIPAL)
    ]
    assert _route_declared_hops(dep) == set()
    assert _access_hops(dep) == set()


def test_a_tool_reference_a_principal_shares_is_the_tool_alone_for_both_readers():
    """A tool and another agent carrying the same identifier. The reference
    was followed to both and filed as ambiguous, so the calling agent was handed
    every power the namesake agent held -- here, its shell -- through a tool entry
    that only ever meant the tool. A ``tools`` entry cannot mean an agent, so it
    is one hop, to the tool, and nothing is unresolved."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="caller", identifier="caller",
           metadata={"tools": ["planner"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="planner", identifier="planner")
    _asset(dep, kind=Asset.Kind.AGENT, name="planner", identifier="planner",
           metadata={"tools": ["shell"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="shell", identifier="shell",
           metadata={"permissions": ["code_execution"]})

    assert _unresolved_rows(dep) == ([], [])
    assert _route_declared_hops(dep) == {("caller", "planner"), ("planner", "shell")}
    assert {target for principal, target in _access_hops(dep) if principal == "caller"} == {"planner"}


# ---- What the hole means for the claim built on top of it. ----


def test_an_unresolved_reference_stops_the_access_claim_reaching_verified():
    """The EFFECTIVE_ACCESS claim is derived from this same reach assessment, and
    its VERIFIED status means "we checked and the reach is least-privilege". A
    dangling reference means the assessment could not follow part of the graph it
    was asked to assess, so VERIFIED would be a statement about a graph we do not
    have. It lands on PARTIALLY_VERIFIED — the reach IS verified over the part
    that could be read — and names what it could not place in the supporting
    digest."""
    from assurance.claims import _derive_effective_access

    clean = _dep("clean")
    _asset(clean, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["reader"]})
    _asset(clean, kind=Asset.Kind.TOOL, name="reader", identifier="reader",
           metadata={"permissions": ["read"]})
    verified = _derive_effective_access(clean)
    assert verified["status"] == "verified", "the control: a whole graph can verify"
    assert verified["contradicting_summary"] == ""

    holed = _dep("holed")
    _asset(holed, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["reader", "ghost-tool"]})
    _asset(holed, kind=Asset.Kind.TOOL, name="reader", identifier="reader",
           metadata={"permissions": ["read"]})
    capped = _derive_effective_access(holed)
    assert capped["status"] == "partially_verified"
    assert capped["evidence_class"] == "partially_verified"
    # In the supporting digest, not the contradicting one. Nothing about an
    # unreadable reference argues the access IS over-broad, and filing it as
    # contradicting evidence claims we found something against the deployment
    # when what we found is that we could not look.
    assert capped["contradicting_summary"] == ""
    assert "could not be placed" in capped["supporting_summary"]
    assert "assistant → ghost-tool" in capped["supporting_summary"]


# ---- What an adversary pass found once the readers agreed on the SET. ----
#
# The set of hops and the set of unplaceable references really did agree: 500
# randomized inventories produced zero set-level divergences. What did not agree
# was the LIST, the COUNTS, and -- worse -- whether the gap was real at all. The
# platform's own writer was manufacturing one.


def test_a_server_a_tool_names_stays_a_reference_and_never_becomes_a_node():
    """The first attempt at this fixed a manufactured gap by manufacturing a node,
    which is the same defect pointed the other way.

    ``assets.py`` writes ``server`` onto every tool entry that declares one, while
    only entries in ``cfg["tools"]`` become assets. So "tool `reader` is hosted by
    `mcp-prod`", without listing `mcp-prod` separately, leaves a reference to a
    component no code path created. The fix that shipped materialised `mcp-prod` as
    an MCP_SERVER asset — and a node nobody enumerated is a fact nobody stated. It
    read as an undeclared component to the BOM drift check, as a governed one to
    every ``_MANAGED`` predicate, and it moved the deployment fingerprint for an
    inventory that had not changed.

    So: the reference stays a reference. It is reported as unresolved by both
    readers — which is true, the inventory really did not enumerate that component
    — and what it costs is the *claim's* confidence, not the *graph's* contents.
    """
    from assurance.assets import derive_assets

    dep = _dep("declared")
    scan = _scan(dep, {
        "agent": {"name": "assistant", "identifier": "assistant"},
        "tools": [{"name": "reader", "identifier": "reader",
                   "permissions": ["read"], "server": "mcp-prod"}],
    })
    derive_assets(dep, scan)

    assert not dep.assets.filter(identifier="mcp-prod").exists(), (
        "the inventory named a host; it did not enumerate a component, and a node "
        "written from a name is a fact this platform invented"
    )
    access_rows, route_rows = _unresolved_rows(dep)
    assert [(r["source"], r["reference"]) for r in access_rows] == [("reader", "mcp-prod")]
    assert access_rows == route_rows


def test_a_routine_declared_inventory_is_partially_verified_not_verified():
    """The claim-level half. A deployment with one agent, one read-only tool and a
    named-but-unenumerated host has no privileged reach, no shadow principal and
    nothing over-broad — so the reach is clean over the graph that could be read,
    and part of the graph could not be read.

    That is PARTIALLY_VERIFIED exactly: not VERIFIED, which would report the hole
    as a clean bill of health, and not SUPPORTED, which would lose that the part we
    could see *was* verified. The unplaceable reference is named in the supporting
    digest and nowhere in the contradicting one — it is a limit on the measurement,
    not evidence the access is over-broad."""
    from assurance.assets import derive_assets
    from assurance.claims import _derive_effective_access

    dep = _dep("routine")
    scan = _scan(dep, {
        "agent": {"name": "assistant", "identifier": "assistant"},
        "tools": [{"name": "reader", "identifier": "reader",
                   "permissions": ["read"], "server": "mcp-prod"}],
    })
    derive_assets(dep, scan)

    claim = _derive_effective_access(dep)
    assert claim["status"] == "partially_verified"
    assert claim["evidence_class"] == "partially_verified"
    assert claim["contradicting_summary"] == "", (
        "an unreadable reference does not argue the statement is false"
    )
    assert "reader → mcp-prod" in claim["supporting_summary"]
    # Not a silent zero and not a pass. The confidence must MOVE.
    assert claim["confidence"] is not None
    assert claim["confidence"] < 0.88


def test_a_whole_graph_still_verifies_at_full_confidence():
    """The negative control for the two above. The same inventory with the host
    enumerated has nothing unresolved, so the claim must VERIFY at the
    configuration-verified evidence class. Without this, "unresolved weakens the
    claim" could be satisfied by weakening every claim."""
    from assurance.assets import derive_assets
    from assurance.claims import _derive_effective_access

    dep = _dep("whole")
    scan = _scan(dep, {
        "agent": {"name": "assistant", "identifier": "assistant"},
        "tools": [
            {"name": "reader", "identifier": "reader",
             "permissions": ["read"], "server": "mcp-prod"},
            {"name": "mcp-prod", "identifier": "mcp-prod", "kind": "mcp_server"},
        ],
    })
    derive_assets(dep, scan)

    assert _unresolved_rows(dep) == ([], [])
    claim = _derive_effective_access(dep)
    assert claim["status"] == "verified"
    assert claim["evidence_class"] == "configuration_verified"
    assert "could not be placed" not in claim["supporting_summary"]


def test_the_unreadable_reference_moves_no_decision_and_no_fingerprint():
    """What the materialisation actually cost, measured through the real derivers.

    The shipped fix wrote the named host in as an ``MCP_SERVER`` asset. That node
    was not a DeclaredComponent, so ``assess_bom_drift`` called it undeclared
    shadow supply chain at high severity, which raised a
    ``bom_drift.undeclared_component`` finding, which moved the decision from
    ``audit_incomplete`` to ``needs_remediation`` — strictly worse, and the exact
    unearned change the whole change existed to prevent, moved one step along. It
    also put an asset in the graph that the customer never enumerated, so the
    system fingerprint moved for an inventory that had not changed.

    Same inventory, same declaration: none of that may happen."""
    from assurance.assets import derive_assets
    from assurance.bom_drift import assess_bom_drift
    from assurance.claims import _derive_effective_access
    from assurance.decision import recompute_decision
    from assurance.fingerprint import compute_system_fingerprint
    from assurance.models import Asset as AssetModel, DeclaredComponent

    dep = _dep("named-only")
    derive_assets(dep, _scan(dep, {
        "agent": {"name": "assistant", "identifier": "assistant"},
        "tools": [{"name": "reader", "identifier": "reader",
                   "permissions": ["read"], "server": "mcp-prod"}],
    }))
    # The customer declared everything that was observed -- the agent, the tool,
    # and the scan's own target surface. So the declaration is complete, and the
    # ONLY thing that can turn up undeclared below is a component this platform
    # invented. That is what makes the assertion sharp rather than incidental.
    for kind, ident in (
        (AssetModel.Kind.AGENT, "assistant"),
        (AssetModel.Kind.TOOL, "reader"),
        (AssetModel.Kind.API, "app.example.com"),
    ):
        DeclaredComponent.objects.create(
            deployment=dep, kind=kind, identifier=ident, name=ident
        )

    # 1. No node nobody enumerated -- which is also why the fingerprint holds.
    #    (``app.example.com`` is the scan's own target surface, which every scan
    #    produces and the declaration does not cover; it is not what this is about.)
    assert sorted(dep.assets.values_list("identifier", flat=True)) == [
        "app.example.com", "assistant", "reader",
    ]
    fingerprint = compute_system_fingerprint(dep)

    # 2. No manufactured drift finding. `mcp-prod` is a name in a tool entry, not
    #    a component the customer is hiding.
    drift = assess_bom_drift(dep)
    assert drift["undeclared"] == [], drift["undeclared"]
    assert drift["drift_detected"] is False

    # 3. No decision change. An unreadable reference is a limit on the
    #    measurement, and a limit is not a defect to remediate.
    decision = recompute_decision(dep)
    assert decision != "needs_remediation", decision

    # 4. And the whole cost lands where it belongs: on the claim's confidence.
    claim = _derive_effective_access(dep)
    assert claim["status"] == "partially_verified"

    # Deriving twice changes nothing -- the shipped version forked a duplicate on
    # a rename, so idempotency is part of the contract now.
    derive_assets(dep, _scan(dep, {
        "agent": {"name": "assistant", "identifier": "assistant"},
        "tools": [{"name": "reader", "identifier": "reader",
                   "permissions": ["read"], "server": "mcp-prod"}],
    }))
    assert sorted(dep.assets.values_list("identifier", flat=True)) == [
        "app.example.com", "assistant", "reader",
    ]
    assert compute_system_fingerprint(dep) == fingerprint


def test_both_readers_report_the_same_gaps_in_the_same_order():
    """The set agreed; the list did not. ``access`` interleaves an asset's tools and
    its server per asset; ``route`` walks every agent's tools first and then every
    asset's server. Two agents with one gap each came out in opposite orders —
    measured at roughly one in ten agent-heavy inventories — and both lists are
    returned verbatim from their own endpoint, so the same gaps appeared in two
    reports in two orders. Sorted on the row's content, so the order is a property
    of the graph rather than of the walk."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="billing-agent", identifier="billing-agent",
           metadata={"server": "mcp-payments"})
    _asset(dep, kind=Asset.Kind.AGENT, name="support-agent", identifier="support-agent",
           metadata={"tools": ["zendesk-tool"]})

    access_rows, route_rows = _unresolved_rows(dep)
    assert access_rows == route_rows
    assert [(r["source"], r["reference"]) for r in access_rows] == [
        ("billing-agent", "mcp-payments"),
        ("support-agent", "zendesk-tool"),
    ]


def test_one_relationship_is_one_edge_even_when_declared_and_inferred_agree():
    """A declared edge and the inferred spine's guess at the same pair used to be
    drawn as two arrows between two nodes. The declared-vs-inferred ratio is this
    map's central honesty claim — how much of the picture is attested rather than
    guessed — and it was inflated on the attested side by an inferred edge nobody
    needed, because the pair was already attested."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"server": "customer-db"})
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="customer-db", identifier="customer-db")

    result = route.build_route_map(dep)
    assert result["summary"]["edge_count"] == 1
    assert result["summary"]["declared_edges"] == 1
    assert result["summary"]["inferred_edges"] == 0
    assert result["edges"][0]["kind"] == "connects_to"


def test_the_same_target_named_twice_is_one_hop_to_both_readers():
    """Named through both mechanisms at once. The reach assessment dedups on the
    node pair and reports one hop; the map dedups on (source, target, KIND) and
    reported two declared edges plus an inferred one — three edges for one
    relationship, and the two readers disagreeing about the size of one graph."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="orchestrator", identifier="orchestrator",
           metadata={"tools": ["vec-1"], "server": "vec-1"})
    _asset(dep, kind=Asset.Kind.VECTOR_DB, name="vec-1", identifier="vec-1")

    result = route.build_route_map(dep)
    assert result["summary"]["declared_edges"] == 1
    assert result["summary"]["edge_count"] == 1
    assert len(_access_hops(dep)) == 1
    assert _route_declared_hops(dep) == _access_hops(dep)


def test_the_claim_counts_the_references_it_lists():
    """It counted ``len(unresolved)`` and enumerated a SET of pairs, so a duplicated
    inventory line said "2 declared reference(s)" above one pair. An operator told
    to chase two and handed one goes looking for a reference that does not exist."""
    from assurance.claims import _derive_effective_access

    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["ghost-tool", "ghost-tool"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="reader", identifier="reader",
           metadata={"permissions": ["read"]})

    claim = _derive_effective_access(dep)
    assert "1 declared reference(s)" in claim["supporting_summary"]
    assert claim["supporting_summary"].count("→") == 1


def test_an_unknown_claim_does_not_carry_measured_contradicting_evidence():
    """With no principals the claim is UNKNOWN and ``vendor_asserted``. Appending a
    measured gap as *contradicting* evidence produced a claim saying "nothing to
    assess", "the vendor asserted this" and "here is evidence we measured against
    it" at once — and ``vendor_asserted`` is flatly wrong for a finding this
    platform produced itself. The gap is still said, on the supporting side, where
    it reads as the limit of what we could see."""
    from assurance.claims import _derive_effective_access

    dep = _dep()
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="orders-db", identifier="orders-db",
           metadata={"server": "ghost-backend"})

    claim = _derive_effective_access(dep)
    assert claim["status"] == "unknown"
    assert claim["vendor_asserted"] is True
    assert claim["contradicting_summary"] == ""
    assert "could not be placed" in claim["supporting_summary"]


def test_a_malformed_tools_declaration_is_one_finding_not_one_per_character():
    """``metadata["tools"] = "reader"`` is a plausible typo for ``["reader"]``, and
    iterating a string yields its characters: six manufactured gaps from one
    mistyped field, counted in both summaries, and — since resolution falls back to
    a name — a single character matching an asset's name became a declared hop.
    Manufacturing findings is the same defect as dropping them, pointed the other
    way."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": "xy"})
    _asset(dep, kind=Asset.Kind.TOOL, name="x", identifier="tool-4471")

    access_rows, route_rows = _unresolved_rows(dep)
    assert access_rows == route_rows
    assert [r["reference"] for r in access_rows] == ["tools (not a list)"]
    assert _route_declared_hops(dep) == set(), "no hop is fabricated from one character"
    # The agent declares nothing usable, so it reaches nothing. (The tool is then
    # owned by no agent, which the reach assessment reports honestly as reachable
    # by the deployment's own surface -- that is not a fabricated hop, it is what
    # an unowned capability-bearing tool means.)
    assert not any(p == "assistant" for p, _ in _access_hops(dep))


def test_neither_reader_raises_on_metadata_that_is_not_a_dict():
    """Two readers cannot agree about a graph when one of them cannot read it. The
    map's front-door lookup had no isinstance guard where the reach assessment
    guards every metadata read, so an asset whose metadata is a JSON string made
    the map raise AttributeError while the assessment returned normally."""
    dep = _dep()
    a = _asset(dep, kind=Asset.Kind.API, name="app.example.com", identifier="app.example.com")
    Asset.objects.filter(pk=a.pk).update(metadata="not-a-dict")

    assert route.build_route_map(dep)["summary"]["node_count"] == 1
    assert assess_effective_access(dep)["summary"]["principals"] == 0


def test_every_report_built_on_the_reach_graph_carries_its_gaps():
    """The commit's own thesis — a gap that reads as an absence of gaps — still held
    for three more reports. ``ripple`` (blast radius) and ``personal_context``
    (who can reach personal data) both read the reach assessment wholesale and
    published summaries built on it while reading only ``principals``. Carried
    through rather than re-derived: one source for the gap, one shape."""
    from assurance.personal_context import assess_personal_context
    from assurance.ripple import assess_ripple

    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           metadata={"tools": ["ghost-mcp"]})
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="orders-db", identifier="orders-db",
           metadata={"server": "ghost-backend"})

    expected = assess_effective_access(dep)["unresolved"]
    assert len(expected) == 2

    for report in (assess_ripple(dep), assess_personal_context(dep)):
        assert report["unresolved"] == expected
        assert report["summary"]["unresolved_references"] == 2


# ---- The account an agent acts as. ----


def test_an_agent_acts_as_the_account_its_identity_names_for_both_readers():
    """The identity was read by one check -- whether an account was orphaned --
    and by neither reader of the graph. An agent acting as an account is a hop:
    whatever the account can do, the agent can do."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", metadata={"identity": "svc-support"})
    _asset(dep, kind=Asset.Kind.SERVICE_ACCOUNT, name="svc-support")

    assert _unresolved_rows(dep) == ([], [])
    assert _route_declared_hops(dep) == {("assistant", "svc-support")}
    assert ("assistant", "svc-support") in _access_hops(dep)


def test_an_identity_naming_no_account_is_recorded_by_both_readers():
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", metadata={"identity": "svc-gone"})

    access_rows, route_rows = _unresolved_rows(dep)
    assert access_rows == route_rows == [{
        "source": "assistant",
        "source_kind": Asset.Kind.AGENT,
        "reference": "svc-gone",
        "mechanism": MECHANISM_IDENTITY,
        "reason": UNRESOLVED_NOT_FOUND,
        "reasons": [UNRESOLVED_NOT_FOUND],
    }]
    assert route.build_route_map(dep)["summary"]["unresolved_identity_references"] == 1
    assert assess_effective_access(dep)["summary"]["unresolved_references"] == 1


def test_an_identity_two_accounts_answer_to_is_followed_to_both_and_recorded():
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", metadata={"identity": "billing"})
    _asset(dep, kind=Asset.Kind.SERVICE_ACCOUNT, name="billing", identifier="sa-1")
    _asset(dep, kind=Asset.Kind.SERVICE_ACCOUNT, name="billing", identifier="sa-2")

    access_rows, route_rows = _unresolved_rows(dep)
    assert access_rows == route_rows
    assert [(r["mechanism"], r["reason"]) for r in access_rows] == [
        (MECHANISM_IDENTITY, UNRESOLVED_AMBIGUOUS)
    ]
    route_targets = [
        e["target"] for e in route.build_route_map(dep)["edges"] if e["kind"] == "acts_as"
    ]
    assert len(route_targets) == 2


def test_an_identity_resolves_among_accounts_before_anything_else_carrying_it():
    """A tool whose IDENTIFIER is the string and an account whose NAME is. The
    identifier-first rule picks between an account's keys; it does not let a
    component that cannot be an identity stop resolution, which would have left
    the agent acting as nobody and the account unused."""
    dep = _dep()
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", metadata={"identity": "reader"})
    _asset(dep, kind=Asset.Kind.TOOL, name="Reader tool", identifier="reader")
    _asset(dep, kind=Asset.Kind.SERVICE_ACCOUNT, name="reader", identifier="sa-reader")

    assert _unresolved_rows(dep) == ([], [])
    assert _route_declared_hops(dep) == {("assistant", "reader")}
