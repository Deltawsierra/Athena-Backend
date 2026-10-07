"""The authority-chain verification rule, exercised as the pure function it is.

:mod:`assurance.authority_chain` states, hop by hop, what proves an authority chain,
what leaves a hop unproven and what breaks it. Every branch of that rule is pinned
here with hand-built inputs -- no database -- so a test cannot be made vacuous by a
fixture: the reference chain below is the roadmap's own example, every hop of it
supported, and each test takes one support away and names what the rule must say.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone as dt_timezone
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
#: When the effect was observed: the instant sign-in and delegation are placed against.
EFFECT_AT = datetime(2026, 10, 7, 12, 0, tzinfo=dt_timezone.utc)
#: When its dispatch left (part 5): a second before the effect was observed.
DISPATCHED_AT = EFFECT_AT - timedelta(seconds=1)
ROUTE = "5e" * 32
EPOCH = "running#c0ffee.0"
#: The state the dispatch ran under, as the gate signed it into the observed effect:
#: its own epoch and operator policy, and the approval and contract it was presented
#: under -- the ones in force at the dispatch instant by the history below -- and the
#: route this backend recorded as serving then.
DISPATCH = ac.DispatchState(
    dispatched_at=DISPATCHED_AT,
    epoch=EPOCH,
    permit_epoch=EPOCH,
    policy_id="support-policy",
    policy_digest="sha256:" + "b0" * 32,
    permit_policy_digest="sha256:" + "b0" * 32,
    approval_digest=APPROVAL_DIGEST,
    contracts={("mcp_server", "crm-mcp"): CONTRACT},
    route_at_dispatch=ROUTE,
)
OBSERVED = ac.ObservedEffect(
    "mcp_server", "crm-mcp", "gate1", "d" * 32, "sha256:" + "e" * 64, "customer:update", observed_at=EFFECT_AT,
    dispatch=DISPATCH,
)
EFFECT = ac.CitedOutcome("eff1", WF, comp.HELD, comp.EVIDENCE_OBSERVED_EFFECT, OBSERVED)
#: The approval's history: in force since the day before the dispatch, binding the
#: CRM server under CONTRACT; and that contract, recorded two days before.
V1 = ac.ApprovalVersion(EFFECT_AT - timedelta(days=1), APPROVAL_DIGEST, (("mcp_server", "crm-mcp", CONTRACT),))
APPROVAL_HISTORY = {WF: (V1,)}
CONTRACT_HISTORY = {("mcp_server", "crm-mcp"): (ac.ContractVersion(EFFECT_AT - timedelta(days=2), CONTRACT),)}


def inputs(**over):
    base = {
        "graph": graph(),
        "approvals": {WF: approval()},
        "outcomes": {"gate1": GATE, "eff1": EFFECT},
        "approval_history": APPROVAL_HISTORY,
        "contract_history": CONTRACT_HISTORY,
    }
    base.update(over)
    return ac.Inputs(**base)


def with_dispatch(**over):
    """The reference outcomes, with the observed effect's dispatch state changed."""
    from dataclasses import replace

    effect = replace(OBSERVED, dispatch=replace(DISPATCH, **over))
    return {"gate1": GATE, "eff1": ac.CitedOutcome("eff1", WF, comp.HELD, comp.EVIDENCE_OBSERVED_EFFECT, effect)}


#: The roadmap's first two hops, recorded: employee:alice signed in as support-user
#: half an hour before the effect, in an eight-hour session; support-user delegated
#: support-agent customer:update for the day around it.
SIGNED_IN = ac.Authentication(
    "auth1", "employee:alice", "support-user", EFFECT_AT - timedelta(minutes=30), EFFECT_AT + timedelta(hours=8),
    issuer="https://idp.example.test", protocol="oidc", witness="mythos",
)
GRANT = ac.Delegation(
    "dlg1", "sha256:" + "9" * 64, "user", "support-user", "support-agent", frozenset({"customer:update"}),
    EFFECT_AT - timedelta(hours=1), EFFECT_AT + timedelta(days=1), witness="mythos",
)


def identity_inputs(authentications=(SIGNED_IN,), delegations=(GRANT,), **over):
    return inputs(authentications=tuple(authentications), delegations=tuple(delegations), **over)


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
    assert codes(at(result, "under_policy")) == {"approval_in_force_at_dispatch"}
    assert codes(at(result, "invokes")) == {"contract_in_force_at_dispatch", "route_at_dispatch", "declared_edge"}
    assert codes(at(result, "through_identity")) == {"declared_identity"}
    assert codes(at(result, "performs")) == {"declared_permission", "within_approval", "gate_permit"}
    assert codes(at(result, "produces")) == {"observed_effect"}


def test_the_roadmap_example_reconstructs_and_names_the_records_its_first_hops_lack():
    result = ac.verify(chain(ROADMAP), inputs())
    assert result.verdict == ac.UNPROVEN
    assert verdicts(result) == [ac.UNPROVEN, ac.UNPROVEN, *[ac.PROVEN] * 5]
    assert [h.index for h in result.unproven] == [0, 1]
    assert codes(result.hops[0]) == {"no_authentication_record"}
    assert codes(result.hops[1]) == {"no_delegation_record"}
    assert result.broken == ()


def test_a_hop_type_with_no_data_is_unproven_never_proven(monkeypatch):
    # A relation that has no record is unproven whatever its check -- or the records
    # around it -- would say: the rule does not let surrounding support stand in.
    # Since part 4 none does; put one back and it reads no_record again.
    assert ac.NO_RECORD_RELATIONS == frozenset()
    proven = ac.verify(chain(ROADMAP), identity_inputs())
    assert proven.verdict == ac.PROVEN
    for relation in (ac.AUTHENTICATED_AS, ac.DELEGATES_TO):
        monkeypatch.setattr(ac, "NO_RECORD_RELATIONS", frozenset({relation}))
        result = ac.verify(chain(ROADMAP), identity_inputs())
        assert at(result, relation).verdict == ac.UNPROVEN
        assert codes(at(result, relation)) == {"no_record"}


def test_nothing_observes_an_effect_today_so_the_best_chain_stops_short_of_proven():
    result = ac.verify(chain(effect_outcome_id=""), inputs())
    assert result.verdict == ac.UNPROVEN
    # Since part 5 the policy and the invocation are read as of dispatch, and with no
    # observed effect nothing records the state the dispatch ran under: they read
    # unproven too, never live in its place.
    assert [h.hop.relation for h in result.unproven] == ["under_policy", "invokes", "produces"]
    assert codes(at(result, "produces")) == {"effect_not_observed"}
    assert codes(at(result, "under_policy")) == {"dispatch_state_unrecorded"}
    assert "dispatch_state_unrecorded" in codes(at(result, "invokes"))


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


@pytest.mark.parametrize(
    ("dispatched_at", "proven"),
    [
        (EFFECT_AT, True),
        (EFFECT_AT - timedelta(seconds=ac.DISPATCH_EFFECT_WINDOW_SECONDS), True),
        (EFFECT_AT + timedelta(microseconds=1), False),
        (EFFECT_AT - timedelta(seconds=ac.DISPATCH_EFFECT_WINDOW_SECONDS, microseconds=1), False),
    ],
    ids=["same-instant", "window-edge", "observed-before-dispatch", "past-the-window"],
)
def test_the_dispatch_instant_bounds_the_effect_instant(dispatched_at, proven):
    history = {WF: (ac.ApprovalVersion(dispatched_at - timedelta(days=1), APPROVAL_DIGEST, V1.tools),)}
    result = ac.verify(chain(), inputs(outcomes=with_dispatch(dispatched_at=dispatched_at), approval_history=history))
    h = at(result, "produces")
    if proven:
        assert h.verdict == ac.PROVEN, codes(h)
    else:
        assert h.verdict == ac.UNPROVEN and codes(h) == {"effect_outside_dispatch_window"}


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


# ---------------------------------------------- sign-in and delegation (part 4)


def _replace(record, **kw):
    from dataclasses import replace

    return replace(record, **kw)


def test_a_chain_that_starts_at_a_person_is_proven_by_its_signed_records():
    result = ac.verify(chain(ROADMAP), identity_inputs())
    assert result.verdict == ac.PROVEN, [(h.hop.relation, codes(h)) for h in result.hops]
    assert codes(at(result, "authenticated_as")) == {"authentication"}
    assert codes(at(result, "delegates_to")) == {"delegation"}
    # Who witnessed it is named in what proves the hop; it does not weaken it.
    assert "witnessed by mythos" in at(result, "authenticated_as").proven_by[0].detail
    assert "witnessed by mythos" in at(result, "delegates_to").proven_by[0].detail


@pytest.mark.parametrize(
    ("record", "code"),
    [
        ({"person": "employee:bob"}, "no_authentication_record"),
        ({"principal": "admin-user"}, "no_authentication_record"),
        ({"authenticated_at": EFFECT_AT + timedelta(seconds=1)}, "authentication_out_of_window"),
        (
            {"authenticated_at": EFFECT_AT - timedelta(seconds=ac.AUTHENTICATION_WINDOW_SECONDS + 1)},
            "authentication_out_of_window",
        ),
        ({"expires_at": EFFECT_AT}, "authentication_expired"),
    ],
    ids=["another-person", "another-principal", "after-the-effect", "before-the-window", "session-expired"],
)
def test_a_sign_in_proves_the_hop_only_for_this_person_and_principal_inside_the_window(record, code):
    result = ac.verify(chain(ROADMAP), identity_inputs(authentications=[_replace(SIGNED_IN, **record)]))
    assert at(result, "authenticated_as").verdict == ac.UNPROVEN
    assert codes(at(result, "authenticated_as")) == {code}
    assert at(result, "delegates_to").verdict == ac.PROVEN


def test_when_the_gate_saw_a_sign_in_and_a_grant_only_those_records_prove_the_person_hops():
    signed = _replace(SIGNED_IN, assertion_digest="sha256:" + "5a" * 32)
    outcomes = with_dispatch(assertion_digest=signed.assertion_digest, grant_digest=GRANT.grant_digest)
    result = ac.verify(chain(ROADMAP), identity_inputs(authentications=(signed,), outcomes=outcomes))
    assert result.verdict == ac.PROVEN, [(h.hop.relation, codes(h)) for h in result.hops]
    # Another sign-in, another grant: records of them exist, and they are not what the
    # gate saw at dispatch.
    other = with_dispatch(assertion_digest="sha256:" + "6c" * 32, grant_digest="sha256:" + "7d" * 32)
    result = ac.verify(chain(ROADMAP), identity_inputs(authentications=(signed,), outcomes=other))
    assert codes(at(result, "authenticated_as")) == {"authentication_not_dispatched"}
    assert codes(at(result, "delegates_to")) == {"delegation_not_dispatched"}
    # The gate saw none: the person hops are placed against the effect's instant alone.
    assert ac.verify(chain(ROADMAP), identity_inputs()).verdict == ac.PROVEN


def test_the_window_is_inclusive_at_both_ends():
    for instant in (EFFECT_AT, EFFECT_AT - timedelta(seconds=ac.AUTHENTICATION_WINDOW_SECONDS)):
        record = _replace(SIGNED_IN, authenticated_at=instant, expires_at=EFFECT_AT + timedelta(hours=1))
        result = ac.verify(chain(ROADMAP), identity_inputs(authentications=[record]))
        assert at(result, "authenticated_as").verdict == ac.PROVEN


def test_one_sign_in_inside_the_window_proves_the_hop_whatever_else_is_on_record():
    stale = _replace(SIGNED_IN, outcome_id="auth0", authenticated_at=EFFECT_AT - timedelta(days=3),
                     expires_at=EFFECT_AT - timedelta(days=2))
    result = ac.verify(chain(ROADMAP), identity_inputs(authentications=[stale, SIGNED_IN]))
    assert codes(at(result, "authenticated_as")) == {"authentication"}


@pytest.mark.parametrize(
    ("record", "code"),
    [
        ({"principal_ref": "admin-user"}, "no_delegation_record"),
        ({"principal_kind": "person"}, "no_delegation_record"),
        ({"agent": "billing-agent"}, "no_delegation_record"),
        ({"actions": frozenset({"customer:read"})}, "delegation_out_of_scope"),
        ({"not_before": EFFECT_AT + timedelta(seconds=1)}, "delegation_out_of_window"),
        ({"not_after": EFFECT_AT}, "delegation_expired"),
        ({"revoked_at": EFFECT_AT - timedelta(seconds=1)}, "delegation_revoked"),
        ({"revoked_at": EFFECT_AT}, "delegation_revoked"),
    ],
    ids=["another-principal", "another-principal-kind", "another-agent", "out-of-scope", "not-yet-open",
         "expired", "revoked-before", "revoked-at-the-instant"],
)
def test_a_delegation_proves_the_hop_only_for_this_principal_agent_scope_window_and_revocation(record, code):
    result = ac.verify(chain(ROADMAP), identity_inputs(delegations=[_replace(GRANT, **record)]))
    assert at(result, "delegates_to").verdict == ac.UNPROVEN
    assert codes(at(result, "delegates_to")) == {code}
    assert at(result, "authenticated_as").verdict == ac.PROVEN


def test_revocation_is_read_at_the_effect_a_later_one_does_not_unprove_it():
    """The effect-time rule: authority is what was in force when the effect was
    produced. A grant revoked after the effect leaves it proven, and says so; one
    revoked before it does not."""
    revoked_later = _replace(GRANT, outcome_id="dlg2", revoked_at=EFFECT_AT + timedelta(seconds=1))
    result = ac.verify(chain(ROADMAP), identity_inputs(delegations=[GRANT, revoked_later]))
    hop = at(result, "delegates_to")
    assert hop.verdict == ac.PROVEN and "after the effect, which stands" in hop.proven_by[0].detail
    revoked_before = _replace(GRANT, outcome_id="dlg3", revoked_at=EFFECT_AT - timedelta(seconds=1))
    result = ac.verify(chain(ROADMAP), identity_inputs(delegations=[GRANT, revoked_later, revoked_before]))
    assert codes(at(result, "delegates_to")) == {"delegation_revoked"}


def test_the_earliest_revocation_of_a_grant_decides_and_an_active_record_never_unrevokes_it():
    revoked = _replace(GRANT, outcome_id="dlg2", revoked_at=EFFECT_AT - timedelta(minutes=5))
    result = ac.verify(chain(ROADMAP), identity_inputs(delegations=[revoked, GRANT]))
    assert codes(at(result, "delegates_to")) == {"delegation_revoked"}


def test_another_grant_in_force_proves_the_hop_when_one_is_revoked():
    revoked = _replace(GRANT, revoked_at=EFFECT_AT - timedelta(minutes=5))
    other = _replace(GRANT, outcome_id="dlg9", grant_digest="sha256:" + "8" * 64)
    result = ac.verify(chain(ROADMAP), identity_inputs(delegations=[revoked, other]))
    assert codes(at(result, "delegates_to")) == {"delegation"}


def test_every_reason_no_grant_proves_it_for_is_named_once():
    bad = _replace(GRANT, actions=frozenset({"customer:read"}), revoked_at=EFFECT_AT - timedelta(minutes=1))
    worse = _replace(bad, grant_digest="sha256:" + "7" * 64, not_after=EFFECT_AT)
    result = ac.verify(chain(ROADMAP), identity_inputs(delegations=[bad, worse]))
    # Grant by grant, in digest order (worse's first), each code once.
    assert [r.code for r in at(result, "delegates_to").reasons] == [
        "delegation_out_of_scope", "delegation_expired", "delegation_revoked",
    ]


def test_the_agent_matches_by_reference_or_by_the_one_component_both_resolve_to():
    by_uuid_name = _replace(GRANT, agent="support-agent")
    assert codes(at(ac.verify(chain(ROADMAP), identity_inputs(delegations=[by_uuid_name])), "delegates_to")) == {
        "delegation"
    }
    renamed = ac.Component(uuid="a1", kind="agent", name="Support Agent", identifier="agent-001",
                           classification="approved")
    g = graph(components=(renamed, TOOL, ACCOUNT, OTHER_ACCOUNT))
    raw = [hop(PERSON, "authenticated_as", USER), hop(USER, "delegates_to", node("agent", "Support Agent")),
           *[hop(node("agent", "Support Agent"), "under_policy", POLICY)], *SUPPORTED[1:]]
    result = ac.verify(chain(raw), identity_inputs(delegations=[_replace(GRANT, agent="agent-001")], graph=g))
    assert codes(at(result, "delegates_to")) == {"delegation"}


def test_sign_in_and_delegation_need_the_effects_signed_instant():
    for result in (
        ac.verify(chain(ROADMAP, effect_outcome_id=""), identity_inputs()),
        ac.verify(chain(ROADMAP), identity_inputs(outcomes={"gate1": GATE, "eff1": _replace(EFFECT, effect=None)})),
    ):
        assert codes(at(result, "authenticated_as")) == codes(at(result, "delegates_to")) == {"effect_instant_unknown"}


def test_a_delegation_with_no_action_after_it_has_no_scope_to_cover():
    # Unreachable through a write (an action is only ever a performs hop's target);
    # a stored row is read leniently, so the rule still names it.
    hops = (
        ac.Hop(ac.Node("user", "support-user"), "delegates_to", ac.Node("agent", "support-agent")),
        ac.Hop(ac.Node("agent", "support-agent"), "under_policy", ac.Node("policy", WF, APPROVAL_DIGEST)),
    )
    result = ac.verify(ac.Chain(WF, hops, "gate1", "eff1", comp.ROUTE_CURRENT), identity_inputs())
    assert codes(at(result, "delegates_to")) == {"delegation_action_unnamed"}


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
    # No version of the approval recorded by the dispatch: the policy and the
    # invocation have no state to be read against. The approval's permissions, which
    # `performs` reads as they stand, are missing live.
    result = ac.verify(chain(), inputs(approvals={}, approval_history={}))
    for relation in ("under_policy", "invokes"):
        assert "dispatch_state_unrecorded" in codes(at(result, relation)), relation
        assert at(result, relation).verdict == ac.UNPROVEN
    assert "no_approval" in codes(at(result, "performs"))
    # Withdrawn before the dispatch: no approval was in force at it.
    withdrawn = {WF: (V1, ac.ApprovalVersion(DISPATCHED_AT - timedelta(minutes=5), ""))}
    result = ac.verify(chain(), inputs(approval_history=withdrawn))
    assert codes(at(result, "under_policy")) == {"dispatched_under_superseded_policy"}
    assert "withdrawn" in at(result, "under_policy").reasons[0].detail
    assert codes(at(result, "invokes")) == {"no_approval"}


def test_the_policy_version_must_be_the_one_in_force():
    unnamed = [hop(AGENT_N, "under_policy", node("policy", WF)), *SUPPORTED[1:]]
    unnamed[1] = hop(node("policy", WF), "invokes", TOOL_N)
    result = ac.verify(chain(unnamed), inputs())
    assert codes(at(result, "under_policy")) == {"policy_version_unnamed"}

    stale = [hop(AGENT_N, "under_policy", node("policy", WF, "ee" * 32)), *SUPPORTED[1:]]
    stale[1] = hop(node("policy", WF, "ee" * 32), "invokes", TOOL_N)
    h = at(ac.verify(chain(stale), inputs()), "under_policy")
    assert codes(h) == {"policy_version_not_in_force"} and h.verdict == ac.UNPROVEN
    assert APPROVAL_DIGEST in h.reasons[0].detail and "signed" in h.reasons[0].detail


# ----------------------------------------------- the approval, read as of dispatch


V2 = "a2" * 32


def test_a_re_approval_after_the_dispatch_leaves_it_proven_citing_the_version_it_ran_under():
    # Live, approval v2 is in force now (approvals= is what stands); the history says
    # v1 was in force at the dispatch, and v1 is what the gate signed.
    later = {WF: (V1, ac.ApprovalVersion(EFFECT_AT + timedelta(hours=1), V2, V1.tools))}
    result = ac.verify(chain(), inputs(approvals={WF: approval(digest=V2)}, approval_history=later))
    h = at(result, "under_policy")
    assert result.verdict == ac.PROVEN and codes(h) == {"approval_in_force_at_dispatch"}
    assert APPROVAL_DIGEST in h.proven_by[0].detail and V2 not in h.proven_by[0].detail


def test_an_effect_dispatched_after_its_approval_was_superseded_reads_unproven_even_once_it_is_restored():
    superseded = (V1, ac.ApprovalVersion(DISPATCHED_AT - timedelta(minutes=5), V2, V1.tools))
    result = ac.verify(chain(), inputs(approval_history={WF: superseded}))
    h = at(result, "under_policy")
    assert h.verdict == ac.UNPROVEN and codes(h) == {"dispatched_under_superseded_policy"}
    assert f"superseded by {V2}" in h.reasons[0].detail
    # v1 restored after the effect: live it is in force again, and it changes nothing.
    restored = (*superseded, ac.ApprovalVersion(EFFECT_AT + timedelta(hours=1), APPROVAL_DIGEST, V1.tools))
    h = at(ac.verify(chain(), inputs(approval_history={WF: restored})), "under_policy")
    assert codes(h) == {"dispatched_under_superseded_policy"}
    # A version noted only after the dispatch was not in force at it either.
    noted_late = {WF: (ac.ApprovalVersion(EFFECT_AT + timedelta(minutes=1), APPROVAL_DIGEST, V1.tools),)}
    h = at(ac.verify(chain(), inputs(approval_history=noted_late)), "under_policy")
    assert codes(h) == {"dispatch_state_unrecorded"}
    # A version never on record for the workflow is not the one in force.
    other = {WF: (ac.ApprovalVersion(V1.in_force_from, V2, V1.tools),)}
    h = at(ac.verify(chain(), inputs(approval_history=other)), "under_policy")
    assert codes(h) == {"dispatched_under_superseded_policy"} and "was not in force" in h.reasons[0].detail


@pytest.mark.parametrize(
    ("over", "says"),
    [
        ({"epoch": "stood_down#c0ffee.1", "permit_epoch": "stood_down#c0ffee.1"}, "not running"),
        ({"permit_epoch": "running#c0ffee.0", "epoch": "running#c0ffee.1"}, "issued under authority epoch"),
        ({"policy_digest": "sha256:" + "b1" * 32}, "operator policy"),
    ],
    ids=["stopped", "epoch-moved", "policy-moved"],
)
def test_a_dispatch_under_a_superseded_gate_epoch_or_policy_reads_unproven(over, says):
    h = at(ac.verify(chain(), inputs(outcomes=with_dispatch(**over))), "under_policy")
    assert h.verdict == ac.UNPROVEN and codes(h) == {"dispatched_under_superseded_policy"}
    assert any(says in r.detail for r in h.reasons)


@pytest.mark.parametrize(
    ("outcomes", "relations"),
    [
        # A v1 observed effect: it proves produces, and records no dispatch state.
        (
            {"gate1": GATE, "eff1": ac.CitedOutcome(
                "eff1", WF, comp.HELD, comp.EVIDENCE_OBSERVED_EFFECT,
                ac.ObservedEffect("mcp_server", "crm-mcp", "gate1", "d" * 32, "sha256:" + "e" * 64,
                                  "customer:update", observed_at=EFFECT_AT),
            )},
            ("under_policy", "invokes"),
        ),
        (with_dispatch(epoch="", permit_epoch=""), ("under_policy",)),
        (with_dispatch(approval_digest=None), ("under_policy",)),
        (with_dispatch(contracts={}), ("invokes",)),
        (with_dispatch(route_at_dispatch=""), ("invokes",)),
    ],
    ids=["v1-document", "no-epoch", "no-approval-presented", "no-contract-presented", "no-route-recorded"],
)
def test_a_dispatch_time_record_that_is_missing_reads_unproven_never_live(outcomes, relations):
    result = ac.verify(chain(), inputs(outcomes=outcomes))
    assert [h.hop.relation for h in result.unproven] == list(relations)
    for relation in relations:
        assert "dispatch_state_unrecorded" in codes(at(result, relation))


def test_no_history_at_the_dispatch_instant_reads_unproven():
    result = ac.verify(chain(), inputs(contract_history={}))
    assert [h.hop.relation for h in result.unproven] == ["invokes"]
    assert "no contract of mcp_server 'crm-mcp' is recorded" in at(result, "invokes").reasons[0].detail
    late = {("mcp_server", "crm-mcp"): (ac.ContractVersion(EFFECT_AT + timedelta(seconds=1), CONTRACT),)}
    assert "dispatch_state_unrecorded" in codes(at(ac.verify(chain(), inputs(contract_history=late)), "invokes"))


def test_a_tool_outside_the_approval_is_broken_and_none_named_is_unproven():
    other = {WF: (ac.ApprovalVersion(V1.in_force_from, APPROVAL_DIGEST, (("tool", "refund", CONTRACT),)),)}
    result = ac.verify(chain(), inputs(approval_history=other))
    assert at(result, "invokes").verdict == ac.BROKEN
    assert "outside_approval" in codes(at(result, "invokes"))
    assert result.verdict == ac.BROKEN

    none = ac.verify(chain(), inputs(approval_history={WF: (ac.ApprovalVersion(V1.in_force_from, APPROVAL_DIGEST),)}))
    assert "approval_names_no_tools" in codes(at(none, "invokes"))
    assert at(none, "invokes").verdict == ac.UNPROVEN


def test_a_tool_approved_under_a_contract_superseded_by_the_dispatch_is_unproven():
    moved = {("mcp_server", "crm-mcp"): (*CONTRACT_HISTORY[("mcp_server", "crm-mcp")],
                                         ac.ContractVersion(DISPATCHED_AT - timedelta(minutes=1), "99" * 32))}
    h = at(ac.verify(chain(), inputs(contract_history=moved)), "invokes")
    assert h.verdict == ac.UNPROVEN and codes(h) >= {"dispatched_under_superseded_contract"}
    assert any("approved under contract" in r.detail for r in h.reasons)
    # Presented under another contract than the one in force then.
    h = at(ac.verify(chain(), inputs(outcomes=with_dispatch(contracts={("mcp_server", "crm-mcp"): "99" * 32}))), "invokes")
    assert codes(h) == {"dispatched_under_superseded_contract"} and "presented contract" in h.reasons[0].detail


def test_a_contract_changed_after_the_effect_leaves_the_invocation_proven():
    # Live, the binding is superseded (current digest moved); at the dispatch it was not.
    moved_live = approval(tools=(ac.ApprovedTool("mcp_server", "crm-mcp", CONTRACT, "99" * 32, ("customer:update",)),))
    after = {("mcp_server", "crm-mcp"): (*CONTRACT_HISTORY[("mcp_server", "crm-mcp")],
                                         ac.ContractVersion(EFFECT_AT + timedelta(minutes=1), "99" * 32))}
    result = ac.verify(chain(), inputs(approvals={WF: moved_live}, contract_history=after))
    assert result.verdict == ac.PROVEN
    assert codes(at(result, "invokes")) == {"contract_in_force_at_dispatch", "route_at_dispatch", "declared_edge"}


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


@pytest.mark.parametrize("route", [comp.ROUTE_MOVED, comp.ROUTE_UNRECORDED, comp.ROUTE_CURRENT])
def test_the_route_is_read_at_the_dispatch_and_a_move_after_it_unproves_nothing(route):
    # The chain's own route against the route serving now no longer decides: the route
    # serving at the dispatch instant, recorded with the effect, does.
    h = at(ac.verify(chain(route=route), inputs()), "invokes")
    assert h.verdict == ac.PROVEN and "route_at_dispatch" in codes(h)


def test_a_dispatch_the_gate_signed_on_another_route_reads_unproven():
    h = at(ac.verify(chain(), inputs(outcomes=with_dispatch(route_fingerprint="99" * 32))), "invokes")
    assert h.verdict == ac.UNPROVEN and codes(h) == {"dispatched_on_another_route"}
    same = at(ac.verify(chain(), inputs(outcomes=with_dispatch(route_fingerprint=ROUTE))), "invokes")
    assert same.verdict == ac.PROVEN


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
    # The approval and contract prove the invocation; a route nothing recorded at the
    # dispatch alone keeps it unproven.
    h = at(ac.verify(chain(), inputs(outcomes=with_dispatch(route_at_dispatch=""))), "invokes")
    assert h.verdict == ac.UNPROVEN
    assert h.proven_by == () and {r.code for r in h.reasons} == {"dispatch_state_unrecorded"}


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
    # The codes part 5 retired are published apart, and the rule emits none of them.
    assert set(ac.RETIRED_REASONS) == {
        "approval_in_force", "approved_contract_in_force", "superseded_contract", "route_moved", "route_unrecorded",
    }
    assert not set(ac.RETIRED_REASONS) & (emitted | set(ac.REASONS))


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
