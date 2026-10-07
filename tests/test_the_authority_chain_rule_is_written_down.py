"""The authority-chain verification rule, exercised as the pure function it is.

:mod:`assurance.authority_chain` states, hop by hop, what proves an authority chain,
what leaves a hop unproven and what breaks it. Every branch of that rule is pinned
here with hand-built inputs -- no database -- so a test cannot be made vacuous by a
fixture: the reference chain below is the roadmap's own example, every hop of it
supported, and each test takes one support away and names what the rule must say.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from assurance import authority_chain as ac
from assurance import composition as comp

WF = "support-update"
APPROVAL_DIGEST = "ab" * 32
CONTRACT = "cd" * 32


def component(uuid, kind, name, **kw):
    kw.setdefault("classification", "approved")
    return ac.Component(uuid=uuid, kind=kind, name=name, identifier=name, **kw)


AGENT = component("a1", "agent", "support-agent")
TOOL = component("t1", "mcp_server", "crm-mcp", permissions=("customer:update", "customer:read"))
ACCOUNT = component("s1", "service_account", "svc-x")
OTHER_ACCOUNT = component("s2", "service_account", "svc-admin")


def graph(**over):
    base = {
        "components": (AGENT, TOOL, ACCOUNT, OTHER_ACCOUNT),
        "declared": frozenset({("a1", "invokes", "t1"), ("a1", "acts_as", "s1")}),
        "reach": {"a1": frozenset({"t1", "s1"}), "s1": frozenset(), "s2": frozenset()},
    }
    base.update(over)
    return ac.Graph(**base)


def approval(**over):
    base = {
        "slug": WF,
        "digest": APPROVAL_DIGEST,
        "tools": (ac.ApprovedTool("mcp_server", "crm-mcp", CONTRACT, CONTRACT, ("customer:update",)),),
    }
    base.update(over)
    return ac.Approval(**base)


GATE = ac.CitedOutcome("gate1", WF, comp.HELD, comp.EVIDENCE_AUTHORIZATION_CHECK)
#: What the observed effect's evidence document says: the CRM tool, observed on the
#: dispatch of gate decision ``gate1``.
OBSERVED = ac.ObservedEffect("mcp_server", "crm-mcp", "gate1", "d" * 32, "sha256:" + "e" * 64, "customer:update")
EFFECT = ac.CitedOutcome("eff1", WF, comp.HELD, comp.EVIDENCE_OBSERVED_EFFECT, OBSERVED)


def inputs(**over):
    base = {"graph": graph(), "approvals": {WF: approval()}, "outcomes": {"gate1": GATE, "eff1": EFFECT}}
    base.update(over)
    return ac.Inputs(**base)


def node(kind, ref, version=None):
    out = {"kind": kind, "ref": ref}
    if version:
        out["version"] = version
    return out


def hop(source, relation, target):
    return {"from": source, "relation": relation, "to": target}


PERSON = node("person", "employee:alice")
USER = node("user", "support-user")
AGENT_N = node("agent", "support-agent")
POLICY = node("policy", WF, APPROVAL_DIGEST)
TOOL_N = node("mcp_server", "crm-mcp")
ACCOUNT_N = node("service_account", "svc-x")
ACTION = node("action", "customer:update")
EFFECT_N = node("effect", "customer-record-change")

#: Every hop this platform can hold data for, from the agent to the effect.
SUPPORTED = [
    hop(AGENT_N, "under_policy", POLICY),
    hop(POLICY, "invokes", TOOL_N),
    hop(TOOL_N, "through_identity", ACCOUNT_N),
    hop(ACCOUNT_N, "performs", ACTION),
    hop(ACTION, "produces", EFFECT_N),
]
#: The roadmap's example, whole: Employee -> Support User -> Support Agent -> ...
ROADMAP = [hop(PERSON, "authenticated_as", USER), hop(USER, "delegates_to", AGENT_N), *SUPPORTED]


def chain(raw=None, **kw):
    hops, errors = ac.parse_hops(SUPPORTED if raw is None else raw, kw.pop("workflow", WF))
    assert not errors, errors
    kw.setdefault("gate_outcome_id", "gate1")
    kw.setdefault("effect_outcome_id", "eff1")
    kw.setdefault("route", comp.ROUTE_CURRENT)
    return ac.Chain(WF, hops, **kw)


def verdicts(result):
    return [h.verdict for h in result.hops]


def codes(h):
    return {r.code for r in (h.proven_by if h.verdict == ac.PROVEN else h.reasons)}


def at(result, relation):
    return next(h for h in result.hops if h.hop.relation == relation)


# ------------------------------------------------------------- the reference chain


def test_a_chain_every_hop_of_which_the_record_supports_is_proven_and_says_by_what():
    result = ac.verify(chain(), inputs())
    assert result.verdict == ac.PROVEN
    assert verdicts(result) == [ac.PROVEN] * 5
    assert codes(at(result, "under_policy")) == {"approval_in_force"}
    assert codes(at(result, "invokes")) == {"approved_contract_in_force", "declared_edge"}
    assert codes(at(result, "through_identity")) == {"declared_identity"}
    assert codes(at(result, "performs")) == {"declared_permission", "within_approval", "gate_permit"}
    assert codes(at(result, "produces")) == {"observed_effect"}


def test_the_roadmap_example_reconstructs_and_names_the_hops_nothing_here_records():
    result = ac.verify(chain(ROADMAP), inputs())
    assert result.verdict == ac.UNPROVEN
    assert verdicts(result) == [ac.UNPROVEN, ac.UNPROVEN, *[ac.PROVEN] * 5]
    assert [h.index for h in result.unproven] == [0, 1]
    assert codes(result.hops[0]) == codes(result.hops[1]) == {"no_record"}
    assert result.broken == ()


def test_a_hop_type_with_no_data_is_unproven_never_proven():
    # Even with every check around it passing, the relations nothing records stay
    # unproven -- the rule does not let surrounding support stand in for them.
    for relation in ac.NO_RECORD_RELATIONS:
        result = ac.verify(chain(ROADMAP), inputs())
        assert at(result, relation).verdict == ac.UNPROVEN


def test_nothing_observes_an_effect_today_so_the_best_chain_stops_short_of_proven():
    result = ac.verify(chain(effect_outcome_id=""), inputs())
    assert result.verdict == ac.UNPROVEN
    assert [h.hop.relation for h in result.unproven] == ["produces"]
    assert codes(at(result, "produces")) == {"effect_not_observed"}


@pytest.mark.parametrize(
    ("cited", "expected", "code"),
    [
        (ac.CitedOutcome("eff1", WF, comp.VIOLATED, comp.EVIDENCE_OBSERVED_EFFECT, OBSERVED), ac.BROKEN, "effect_violated"),
        (ac.CitedOutcome("eff1", WF, comp.HELD, comp.EVIDENCE_AUTHORIZATION_CHECK), ac.UNPROVEN, "not_an_observed_effect"),
        (ac.CitedOutcome("eff1", WF, comp.HELD, comp.EVIDENCE_ATTESTED), ac.UNPROVEN, "not_an_observed_effect"),
        (ac.CitedOutcome("eff1", "other", comp.HELD, comp.EVIDENCE_OBSERVED_EFFECT, OBSERVED), ac.UNPROVEN, "effect_outcome_other_workflow"),
        (ac.CitedOutcome("eff1", WF, comp.INCOMPLETE, comp.EVIDENCE_OBSERVED_EFFECT, OBSERVED), ac.UNPROVEN, "effect_not_established"),
        # Signed by the observed-effect key, but with no document matching its digest:
        # nothing says what it observed.
        (ac.CitedOutcome("eff1", WF, comp.HELD, comp.EVIDENCE_OBSERVED_EFFECT), ac.UNPROVEN, "effect_evidence_unread"),
        (None, ac.UNPROVEN, "effect_outcome_not_recorded"),
    ],
)
def test_what_the_effect_outcome_cited_says_about_the_produces_hop(cited, expected, code):
    outcomes = {"gate1": GATE} if cited is None else {"gate1": GATE, "eff1": cited}
    h = at(ac.verify(chain(), inputs(outcomes=outcomes)), "produces")
    assert (h.verdict, codes(h)) == (expected, {code})


# ------------------------------------------- the observation is bound to this chain


def _produces_with(effect, **kw):
    cited = ac.CitedOutcome("eff1", WF, comp.HELD, comp.EVIDENCE_OBSERVED_EFFECT, effect)
    over = {"outcomes": {"gate1": GATE, "eff1": cited}, **kw.pop("inputs", {})}
    return at(ac.verify(chain(**kw), inputs(**over)), "produces")


@pytest.mark.parametrize(
    ("effect", "code"),
    [
        (ac.ObservedEffect("mcp_server", "billing-mcp", "gate1", action="customer:update"), "effect_other_tool"),
        (ac.ObservedEffect("tool", "crm-mcp", "gate1", action="customer:update"), "effect_other_tool"),
        (ac.ObservedEffect("mcp_server", "crm-mcp", "gate2", action="customer:update"), "effect_other_dispatch"),
    ],
    ids=["another-tool", "another-kind", "another-gate-decision"],
)
def test_an_observation_of_another_tool_or_dispatch_does_not_prove_this_chain(effect, code):
    """A signature says the dispatch saw AN effect. Only the document says whose, and
    an observation of another tool, or made on another gate decision's dispatch, is
    no support for this chain's produces hop -- and no contradiction of it either."""
    h = _produces_with(effect)
    assert (h.verdict, codes(h)) == (ac.UNPROVEN, {code})


def test_an_observation_cannot_be_replayed_onto_a_chain_that_cites_no_gate_decision():
    h = _produces_with(OBSERVED, gate_outcome_id="")
    assert h.verdict == ac.UNPROVEN and "effect_other_dispatch" in codes(h)


@pytest.mark.parametrize(
    ("raw", "action", "code"),
    [
        (None, "customer:delete", "effect_other_action"),
        ([hop(POLICY, "invokes", TOOL_N), hop(TOOL_N, "through_identity", ACCOUNT_N)], "customer:update", None),
    ],
    ids=["another-action", "no-performs-hop"],
)
def test_an_observation_of_another_action_does_not_prove_this_chain(raw, action, code):
    """The permit names the action the dispatch carried out; the chain's performs hop
    names the action it claims. Another action is no support for this chain."""
    if raw is None:
        h = _produces_with(ac.ObservedEffect("mcp_server", "crm-mcp", "gate1", action=action))
        assert (h.verdict, codes(h)) == (ac.UNPROVEN, {code})
        return
    # A chain with no performs hop before produces (a grammar-valid stub is not
    # possible: produces starts at an action), read on the produces check directly.
    stub = ac.Chain(WF, ac.parse_hops(SUPPORTED, WF)[0][:2] + ac.parse_hops(SUPPORTED, WF)[0][4:],
                    gate_outcome_id="gate1", effect_outcome_id="eff1", route=comp.ROUTE_CURRENT)
    readings = ac._produces(stub, len(stub.hops) - 1, None, None, inputs(), ac._Index(graph()))
    assert {r.code for r in readings} == {"effect_action_unnamed"}


def test_one_observation_proves_one_chain():
    h = _produces_with(OBSERVED, inputs={"effect_citations": {"eff1": 2}})
    assert (h.verdict, codes(h)) == (ac.UNPROVEN, {"effect_outcome_cited_twice"})
    assert _produces_with(OBSERVED, inputs={"effect_citations": {"eff1": 1}}).verdict == ac.PROVEN


def test_a_chain_with_no_invokes_hop_has_no_tool_for_the_observation_to_match():
    raw = [hop(ACCOUNT_N, "performs", ACTION), hop(ACTION, "produces", EFFECT_N)]
    h = _produces_with(OBSERVED, raw=raw)
    assert (h.verdict, codes(h)) == (ac.UNPROVEN, {"effect_tool_unnamed"})


def test_every_binding_that_fails_is_named():
    h = _produces_with(
        ac.ObservedEffect("mcp_server", "billing-mcp", "gate2", action="customer:update"), inputs={"effect_citations": {"eff1": 3}}
    )
    assert codes(h) == {"effect_other_tool", "effect_other_dispatch", "effect_outcome_cited_twice"}


def test_the_tool_matches_by_reference_or_by_the_one_component_both_resolve_to():
    """The invokes hop may name the tool by its name; the document names it by its
    identifier. The same one component is the same tool."""
    renamed = ac.Component(
        uuid="t1", kind="mcp_server", name="crm-mcp", identifier="crm-mcp-prod",
        classification="approved", permissions=TOOL.permissions,
    )
    g = graph(components=(AGENT, renamed, ACCOUNT, OTHER_ACCOUNT))
    h = _produces_with(ac.ObservedEffect("mcp_server", "crm-mcp-prod", "gate1", action="customer:update"), inputs={"graph": g})
    assert (h.verdict, codes(h)) == (ac.PROVEN, {"observed_effect"})
    other = ac.Component(uuid="t9", kind="mcp_server", name="crm-mcp-prod", identifier="crm-mcp-prod",
                         classification="approved")
    g = graph(components=(AGENT, TOOL, other, ACCOUNT, OTHER_ACCOUNT))
    h = _produces_with(ac.ObservedEffect("mcp_server", "crm-mcp-prod", "gate1", action="customer:update"), inputs={"graph": g})
    assert codes(h) == {"effect_other_tool"}


# --------------------------------------------------------------------- the nodes


def test_a_shadow_node_leaves_every_hop_that_touches_it_unproven():
    shadow = component("t1", "mcp_server", "crm-mcp", classification="unmanaged", shadow=True,
                       permissions=TOOL.permissions)
    result = ac.verify(chain(), inputs(graph=graph(components=(AGENT, shadow, ACCOUNT, OTHER_ACCOUNT))))
    assert result.verdict == ac.UNPROVEN
    assert [h.hop.relation for h in result.unproven] == ["invokes", "through_identity"]
    for h in result.unproven:
        assert "shadow_node" in codes(h)
        assert any("crm-mcp" in r.detail and "unmanaged" in r.detail for r in h.reasons)


def test_a_component_the_coverage_manifest_lists_unassessed_is_unproven():
    unassessed = component("s1", "service_account", "svc-x", assessed=False)
    result = ac.verify(chain(), inputs(graph=graph(components=(AGENT, TOOL, unassessed, OTHER_ACCOUNT))))
    assert [h.hop.relation for h in result.unproven] == ["through_identity", "performs"]
    assert all("unassessed_node" in codes(h) for h in result.unproven)


def test_a_node_the_inventory_does_not_hold_is_a_dangling_reference():
    raw = [
        hop(AGENT_N, "under_policy", POLICY),
        hop(POLICY, "invokes", node("mcp_server", "billing-mcp")),
        hop(node("mcp_server", "billing-mcp"), "through_identity", ACCOUNT_N),
        hop(ACCOUNT_N, "performs", ACTION),
        hop(ACTION, "produces", EFFECT_N),
    ]
    result = ac.verify(chain(raw), inputs())
    assert "dangling_node" in codes(at(result, "invokes"))
    assert at(result, "invokes").verdict == ac.BROKEN  # and the approval names crm-mcp, not it


def test_a_node_two_components_answer_to_is_ambiguous():
    twin = component("t2", "mcp_server", "crm-mcp")
    result = ac.verify(chain(), inputs(graph=graph(components=(AGENT, TOOL, twin, ACCOUNT))))
    assert "ambiguous_node" in codes(at(result, "invokes"))
    assert at(result, "through_identity").verdict == ac.UNPROVEN


# ---------------------------------------------------------------- the approval


def test_no_approval_on_record_leaves_every_policy_check_unproven():
    result = ac.verify(chain(), inputs(approvals={}))
    for relation in ("under_policy", "invokes", "performs"):
        assert "no_approval" in codes(at(result, relation)), relation
        assert at(result, relation).verdict == ac.UNPROVEN


def test_the_policy_version_must_be_the_one_in_force():
    unnamed = [hop(AGENT_N, "under_policy", node("policy", WF)), *SUPPORTED[1:]]
    unnamed[1] = hop(node("policy", WF), "invokes", TOOL_N)
    result = ac.verify(chain(unnamed), inputs())
    assert codes(at(result, "under_policy")) == {"policy_version_unnamed"}

    stale = [hop(AGENT_N, "under_policy", node("policy", WF, "ee" * 32)), *SUPPORTED[1:]]
    stale[1] = hop(node("policy", WF, "ee" * 32), "invokes", TOOL_N)
    h = at(ac.verify(chain(stale), inputs()), "under_policy")
    assert codes(h) == {"policy_version_not_in_force"} and h.verdict == ac.UNPROVEN
    assert APPROVAL_DIGEST in h.reasons[0].detail


def test_a_tool_outside_the_approval_is_broken_and_none_named_is_unproven():
    other = approval(tools=(ac.ApprovedTool("tool", "refund", CONTRACT, CONTRACT, ("refund:issue",)),))
    result = ac.verify(chain(), inputs(approvals={WF: other}))
    assert at(result, "invokes").verdict == ac.BROKEN
    assert "outside_approval" in codes(at(result, "invokes"))
    assert result.verdict == ac.BROKEN

    none = ac.verify(chain(), inputs(approvals={WF: approval(tools=())}))
    assert "approval_names_no_tools" in codes(at(none, "invokes"))
    assert at(none, "invokes").verdict == ac.UNPROVEN


def test_a_tool_approved_under_a_superseded_contract_is_unproven():
    moved = approval(tools=(ac.ApprovedTool("mcp_server", "crm-mcp", CONTRACT, "99" * 32, ("customer:update",)),))
    h = at(ac.verify(chain(), inputs(approvals={WF: moved})), "invokes")
    assert h.verdict == ac.UNPROVEN and "superseded_contract" in codes(h)
    gone = approval(tools=(ac.ApprovedTool("mcp_server", "crm-mcp", CONTRACT, None, ("customer:update",)),))
    h = at(ac.verify(chain(), inputs(approvals={WF: gone})), "invokes")
    assert "superseded_contract" in codes(h) and "no longer registered" in h.reasons[0].detail


# --------------------------------------------------------------------- the reach


def test_reach_over_effective_access_alone_proves_the_invocation():
    g = graph(declared=frozenset({("a1", "acts_as", "s1")}))
    assert "effective_reach" in codes(at(ac.verify(chain(), inputs(graph=g)), "invokes"))


def test_an_inferred_edge_alone_is_unproven():
    g = graph(declared=frozenset({("a1", "acts_as", "s1")}), reach={}, inferred=frozenset({("a1", "t1")}))
    h = at(ac.verify(chain(), inputs(graph=g)), "invokes")
    assert h.verdict == ac.UNPROVEN and "inferred_edge" in codes(h)


def test_a_dangling_reference_from_the_agent_leaves_its_reach_unproven():
    g = graph(
        declared=frozenset({("a1", "acts_as", "s1")}), reach={},
        gaps={"a1": (ac.Gap("tools", "billing", ("not_found",)),)},
    )
    h = at(ac.verify(chain(), inputs(graph=g)), "invokes")
    assert h.verdict == ac.UNPROVEN and "dangling_edge" in codes(h)


def test_a_reference_to_the_tool_itself_that_is_unresolved_is_unproven_even_with_its_edge():
    g = graph(gaps={"a1": (ac.Gap("tools", "crm-mcp", ("ambiguous", "superseded_identity")),)})
    h = at(ac.verify(chain(), inputs(graph=g)), "invokes")
    assert h.verdict == ac.UNPROVEN and "dangling_edge" in codes(h)
    assert "superseded_identity" in h.reasons[0].detail


def test_effective_access_over_a_resolved_graph_that_cannot_reach_the_tool_breaks_the_hop():
    g = graph(declared=frozenset({("a1", "acts_as", "s1")}), reach={"a1": frozenset({"s1"})})
    result = ac.verify(chain(), inputs(graph=g))
    h = at(result, "invokes")
    assert h.verdict == ac.BROKEN and "unreachable" in codes(h)
    assert result.verdict == ac.BROKEN and [x.index for x in result.broken] == [1]


@pytest.mark.parametrize(("route", "code"), [(comp.ROUTE_MOVED, "route_moved"), (comp.ROUTE_UNRECORDED, "route_unrecorded")])
def test_a_chain_recorded_against_another_served_route_is_unproven(route, code):
    h = at(ac.verify(chain(route=route), inputs()), "invokes")
    assert h.verdict == ac.UNPROVEN and code in codes(h)


def test_a_chain_with_no_agent_names_no_actor():
    raw = [
        hop(POLICY, "invokes", TOOL_N),
        hop(TOOL_N, "through_identity", ACCOUNT_N),
        hop(ACCOUNT_N, "performs", ACTION),
        hop(ACTION, "produces", EFFECT_N),
    ]
    result = ac.verify(chain(raw), inputs())
    assert "no_actor" in codes(at(result, "invokes"))
    assert "no_actor" in codes(at(result, "through_identity"))


# ------------------------------------------------------------------ the identity


def test_an_agent_that_acts_as_another_account_breaks_the_identity_hop():
    g = graph(declared=frozenset({("a1", "invokes", "t1"), ("a1", "acts_as", "s2")}))
    h = at(ac.verify(chain(), inputs(graph=g)), "through_identity")
    assert h.verdict == ac.BROKEN and "acts_as_another" in codes(h)
    assert "svc-admin" in h.reasons[0].detail


def test_an_agent_that_declares_no_identity_or_an_unresolved_one_is_unproven():
    g = graph(declared=frozenset({("a1", "invokes", "t1")}))
    assert "no_declared_identity" in codes(at(ac.verify(chain(), inputs(graph=g)), "through_identity"))
    g = graph(gaps={"a1": (ac.Gap("identity", "svc", ("ambiguous",)),)})
    h = at(ac.verify(chain(), inputs(graph=g)), "through_identity")
    assert h.verdict == ac.UNPROVEN and "identity_unresolved" in codes(h)


# --------------------------------------------------------------- the action


def test_an_action_no_declaring_component_permits_is_broken():
    narrow = component("t1", "mcp_server", "crm-mcp", permissions=("customer:read",))
    account = component("s1", "service_account", "svc-x", permissions=())
    g = graph(components=(AGENT, narrow, account, OTHER_ACCOUNT))
    h = at(ac.verify(chain(), inputs(graph=g)), "performs")
    assert h.verdict == ac.BROKEN and "permission_not_declared" in codes(h)


def test_an_action_nothing_declares_either_way_is_unproven():
    silent = component("t1", "mcp_server", "crm-mcp")
    g = graph(components=(AGENT, silent, ACCOUNT, OTHER_ACCOUNT))
    h = at(ac.verify(chain(), inputs(graph=g)), "performs")
    assert h.verdict == ac.UNPROVEN and "permissions_undeclared" in codes(h)


def test_an_action_outside_what_the_approval_permits_is_broken():
    other = approval(tools=(ac.ApprovedTool("mcp_server", "crm-mcp", CONTRACT, CONTRACT, ("customer:read",)),))
    h = at(ac.verify(chain(), inputs(approvals={WF: other})), "performs")
    assert h.verdict == ac.BROKEN and "outside_approval" in codes(h)
    undeclared = approval(tools=(ac.ApprovedTool("mcp_server", "crm-mcp", CONTRACT, CONTRACT, None),))
    h = at(ac.verify(chain(), inputs(approvals={WF: undeclared})), "performs")
    assert h.verdict == ac.UNPROVEN and "approval_permissions_undeclared" in codes(h)


@pytest.mark.parametrize(
    ("gate_id", "outcomes", "expected", "code"),
    [
        ("", {}, ac.UNPROVEN, "no_gate_decision"),
        ("gate9", {}, ac.UNPROVEN, "gate_decision_not_recorded"),
        ("gate1", {"gate1": ac.CitedOutcome("gate1", "other", comp.HELD, comp.EVIDENCE_AUTHORIZATION_CHECK)},
         ac.UNPROVEN, "gate_decision_other_workflow"),
        # A row whose signature does not verify now reads at its basis in force.
        ("gate1", {"gate1": ac.CitedOutcome("gate1", WF, comp.HELD, comp.EVIDENCE_ATTESTED)},
         ac.UNPROVEN, "not_a_gate_decision"),
        ("gate1", {"gate1": ac.CitedOutcome("gate1", WF, comp.HELD, comp.EVIDENCE_SCAN)},
         ac.UNPROVEN, "not_a_gate_decision"),
        ("gate1", {"gate1": ac.CitedOutcome("gate1", WF, comp.NOT_DEMONSTRATED, comp.EVIDENCE_AUTHORIZATION_CHECK)},
         ac.BROKEN, "gate_refused"),
        ("gate1", {"gate1": ac.CitedOutcome("gate1", WF, comp.INCOMPLETE, comp.EVIDENCE_AUTHORIZATION_CHECK)},
         ac.UNPROVEN, "gate_incomplete"),
    ],
)
def test_the_action_gate_decision_the_chain_cites(gate_id, outcomes, expected, code):
    h = at(ac.verify(chain(gate_outcome_id=gate_id), inputs(outcomes={**outcomes, "eff1": EFFECT})), "performs")
    assert h.verdict == expected
    assert code in codes(h)


# --------------------------------------------------------------- the composition


def test_a_hop_is_proven_only_when_every_reading_is():
    # The approval proves the invocation; a moved route alone keeps it unproven.
    h = at(ac.verify(chain(route=comp.ROUTE_MOVED), inputs()), "invokes")
    assert h.verdict == ac.UNPROVEN
    assert h.proven_by == () and {r.code for r in h.reasons} == {"route_moved"}


def test_a_broken_reading_outranks_any_number_of_unproven_ones():
    g = graph(declared=frozenset({("a1", "acts_as", "s1")}), reach={"a1": frozenset({"s1"})})
    h = at(ac.verify(chain(route=comp.ROUTE_UNRECORDED), inputs(approvals={}, graph=g)), "invokes")
    assert h.verdict == ac.BROKEN
    assert h.reasons[0].verdict == ac.BROKEN, "the reason that decides comes first"


def test_the_verdict_order_is_total_and_worst_of_nothing_is_unproven():
    assert set(ac._VERDICT_RANK) == ac.HOP_VERDICTS
    assert len(set(ac._VERDICT_RANK.values())) == len(ac.HOP_VERDICTS)
    assert ac.worst([]) == ac.UNPROVEN
    assert ac.worst([ac.PROVEN, ac.BROKEN, ac.UNPROVEN]) == ac.BROKEN


def test_a_stored_hop_outside_the_grammar_is_read_unproven_and_garbage_never_raises():
    hops = ac.hops_from_stored(
        [{"from": {"kind": "agent", "ref": "x"}, "relation": "teleports", "to": {"kind": "effect", "ref": "y"}},
         "not a hop", {"from": None, "relation": None}]
    )
    result = ac.verify(ac.Chain(WF, hops), inputs())
    assert result.verdict == ac.UNPROVEN
    assert all(codes(h) == {"not_in_grammar"} for h in result.hops)
    assert ac.verify(ac.Chain(WF, ac.hops_from_stored("junk")), inputs()).verdict == ac.UNPROVEN


def test_every_relation_has_a_check_and_the_grammar_covers_every_relation():
    assert set(ac.GRAMMAR) == set(ac.RELATIONS)
    assert set(ac._relation_checks) == set(ac.RELATIONS)
    assert ac.NO_RECORD_RELATIONS <= set(ac.RELATIONS)
    assert ac.TOOL_NODE_KINDS <= ac.GRAPH_KINDS


def test_every_reading_code_the_rule_emits_is_published_and_every_published_one_is_emitted():
    source = Path(ac.__file__).read_text(encoding="utf-8")
    emitted = set(re.findall(r'Reading\(\s*(?:PROVEN|UNPROVEN|BROKEN),\s*"([a-z_]+)"', source))
    assert emitted == set(ac.REASONS), (sorted(emitted - set(ac.REASONS)), sorted(set(ac.REASONS) - emitted))


# --------------------------------------------------------------- the write shape


@pytest.mark.parametrize(
    ("raw", "says"),
    [
        ([], "non-empty"),
        ([hop(AGENT_N, "under_policy", POLICY), hop(TOOL_N, "through_identity", ACCOUNT_N)], "is not hops[0].to"),
        ([hop(AGENT_N, "teleports", EFFECT_N)], "relation is one of"),
        ([hop(TOOL_N, "under_policy", POLICY)], "under_policy joins agent to policy"),
        ([hop(AGENT_N, "under_policy", POLICY)], "the last hop is the effect"),
        ([hop(AGENT_N, "performs", ACTION), hop(ACTION, "produces", EFFECT_N),
          hop(EFFECT_N, "produces", EFFECT_N)], "produces joins action to effect, not effect to effect"),
        ([hop(USER, "delegates_to", AGENT_N), hop(AGENT_N, "delegates_to", node("agent", "b")),
          hop(node("agent", "b"), "delegates_to", AGENT_N), hop(AGENT_N, "performs", ACTION),
          hop(ACTION, "produces", EFFECT_N)], "twice"),
        ([hop(AGENT_N, "under_policy", node("policy", "other-workflow")),
          hop(node("policy", "other-workflow"), "invokes", TOOL_N)], "this chain serves"),
        ([hop(node("agent", "a", "ab" * 32), "performs", ACTION)], "only a policy node carries a version"),
        ([hop(AGENT_N, "under_policy", node("policy", WF, "not-hex"))], "approval digest"),
        ([hop(AGENT_N, "performs", {"kind": "agent", "ref": ""})], "non-empty reference"),
        ([hop(AGENT_N, "performs", ACTION)] * (ac.MAX_HOPS + 1), "more than"),
        ("hops", "non-empty list"),
    ],
)
def test_a_write_that_is_not_a_chain_is_refused_whole(raw, says):
    hops, errors = ac.parse_hops(raw, WF)
    assert hops == ()
    assert any(says in e for e in errors), errors


def test_the_newest_chain_for_an_effect_stands_and_the_rest_are_superseded():
    first, second = chain(), chain(effect_outcome_id="")
    other_effect = chain(SUPPORTED[:-1] + [hop(ACTION, "produces", node("effect", "refund"))])
    standing, superseded = ac.in_force([(1, first), (2, other_effect), (3, second)])
    assert standing == [2, 3] and superseded == [1]
