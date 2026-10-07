"""This exact authority chain produced this effect -- and which of its hops are proven.

The compositional graph (:mod:`assurance.composition`) records one status per
approved workflow: held, violated, not demonstrated, incomplete. It says the
workflow's authority-to-effect chain held, and never WHICH chain, so a ``held``
over an authority that ran through an unmanaged MCP server reads exactly like one
that ran through a governed one. Measured on master before this module: a
deployment with a signed ``held`` and an effect whose authority ran through a
shadow tool read ``ready_restricted`` (an Achilles permit check) or ``ready`` (an
Athena scan), and nothing could say so.

This module is the rule for the missing half. An AUTHORITY CHAIN is the ordered
list of hops one consequential effect was produced through, each hop
``(from, relation, to)``:

    person --authenticated_as--> user --delegates_to--> agent
          --under_policy--> policy --invokes--> tool --through_identity--> account
          --performs--> action --produces--> effect

and :func:`verify` reads every hop against what this platform already holds --
the declared graph (:mod:`assurance.route`, :mod:`assurance.access`, resolved by
:mod:`assurance.graph_refs`), the approvals and the tool contracts they bind
(:mod:`assurance.tool_contract`), the coverage manifest
(:mod:`assurance.coverage`), the served route (:mod:`assurance.served_route`) and
the signed outcomes the Action Gate and any effect collector report
(:mod:`assurance.observed_outcomes`).

Deliberately PURE, as :mod:`assurance.composition` is: no models, no ORM, no
clock. The persistence layer (:mod:`assurance.authority_chain_records`) loads the
inputs and calls this; a rule only a database can exercise is a rule nobody will.

THE VERIFICATION RULE
---------------------

Every hop gets ONE of three verdicts:

    proven    every check that applies to the hop passed, and at least one
              piece of recorded data supports it. Each piece is named
              (``proven_by``): a declared edge, an approval in force, a gate
              permit.
    unproven  nothing contradicts the hop, and something it needs is missing,
              unverified, shadow, superseded or not in force. Each such thing is
              named (``reasons``).
    broken    the recorded data CONTRADICTS the hop: effective access over a
              fully resolved graph says the identity cannot reach the tool, the
              approval names other tools and not this one, the action is outside
              what the approval's tools permit, the gate refused the action.

A hop's verdict is the worst of its readings; a chain's is the worst of its hops.
A hop no check speaks for is ``unproven`` -- **a hop type this platform holds no
data for is unproven, never proven** (:data:`NO_RECORD_RELATIONS`, empty since part 4
of the 7 Oct decision gave sign-in and delegation a record). So is ``produces``
unless the chain cites an ``observed_effect`` outcome bound to it
(:mod:`assurance.observed_effects`): Achilles signs one, with a key mapped to that kind
and nothing else, when the dispatch that carried the permitted action out saw the
provider complete it. And so are ``authenticated_as`` and ``delegates_to`` unless a
signed ``authentication`` or ``delegation`` record (:mod:`assurance.identity_evidence`)
names exactly that hop, at the effect's instant. With all three, a chain that starts
at a person can be fully proven from production data.

What each check reads, per hop:

* **Every graph node** (an agent, a service account, a tool, an MCP server, a
  skill), at both ends of every hop: it must resolve to exactly one component of
  that kind (a dangling or ambiguous reference is unproven), be governed (a
  shadow node is unproven -- :func:`assurance.governance.is_shadow`), and be
  assessed (a component the coverage manifest lists unassessed is unproven).
* ``under_policy`` (agent -> policy), AS OF DISPATCH: the policy node is the chain's
  own workflow's approval; the version it names is the approval digest the gate
  signed at dispatch (the cited observed effect's ``mythos.observed-effect/v2``
  ``dispatch`` block); the gate ran under the authority epoch and operator policy the
  permit was issued under, in the running state; and that version was the approval
  in force at the dispatch instant by the recorded history
  (:mod:`assurance.approval_history`). A version already superseded at the dispatch,
  a stopped or moved epoch, or a moved operator policy: unproven
  (``dispatched_under_superseded_policy``). No dispatch state on record -- no
  observed effect, a v1 one, no approval digest presented, no version recorded by
  then: unproven (``dispatch_state_unrecorded``), never read live instead.
* ``invokes`` (policy or agent -> tool): AS OF DISPATCH, the approval in force at the
  dispatch instant names this tool (another tool set and not this one: broken; no
  tools at all: unproven) under the contract in force at that instant, which is the
  one the gate signed (either superseded by then: unproven,
  ``dispatched_under_superseded_contract``), and the served route at that instant is
  on record -- bound when the effect was recorded -- and is the one the gate signed,
  if it signed one; and, as the graph stands, the nearest agent before it reaches it
  over a declared edge (only an inferred edge, or a dangling reference from that
  agent: unproven; neither, over a graph with no gap from that agent: broken).
* ``through_identity`` (tool -> service account): the nearest agent declares
  that it acts as this account (it declares another one: broken; none, or one
  that does not resolve cleanly: unproven).
* ``performs`` (account or agent -> action): the action is a permission the
  identity, the tool it acts through, or a tool it reaches declares (every one of
  them declares its permissions and none this one: broken; some declare none:
  unproven); it is within what the approval's tools were approved to permit
  (outside: broken); and the chain cites the Action Gate decision that let it
  through -- an Achilles-signed outcome for the same workflow that verifies now:
  a permit proves it, a refusal breaks it, anything else is unproven.
* ``produces`` (action -> effect): the chain cites an ``observed_effect`` outcome
  for the same workflow, whose evidence document (``mythos.observed-effect`` v1 or v2,
  re-read against its signed digest) names the tool the chain's ``invokes`` hop
  names, the action its ``performs`` hop names, and the gate decision the chain
  cites -- the observation was made on that dispatch -- and that no other chain in
  force cites: ``held`` proves it, ``violated`` breaks it. An observation of another
  tool, another action or another dispatch, or claimed by two chains, is unproven:
  it does not contradict the hop, and it does not support it.
* ``authenticated_as`` (person -> user): a signed ``authentication`` record names
  this person and this principal, and its instant falls inside the chain's window --
  at most :data:`AUTHENTICATION_WINDOW_SECONDS` before the effect's instant (the
  cited observed effect's, read against its signed digest), and not after it -- and
  the session it opened had not expired by the effect. No record naming both:
  unproven; one outside the window or expired: unproven, named.
* ``delegates_to`` (person, user or agent -> agent): a signed ``delegation`` record
  names this principal and this agent, every action the chain performs after it is
  within the delegated scope, the effect's instant is within the grant's window, and
  the grant was not revoked as of the effect. Revocation is read at the EFFECT's
  instant: a grant revoked after the effect does not unprove it, one revoked before
  (or at) it does. A revoked, expired, not-yet-valid or out-of-scope grant is
  unproven, each named.

Both identity hops need the effect's instant, and the only instant a chain carries
that a signature vouches for is its observed effect's: with none, they are unproven
(``effect_instant_unknown``). Who witnessed the record (``witness``: today the
Mythos-run collectors, per the owner's 5 Oct scope call) is named in what proves the
hop; it does not weaken the proof, because no basis rule here reads a Mythos-witnessed
signature as weaker -- the observed effect that proves ``produces`` is Mythos-witnessed
too -- and that is stated rather than implied.

THE APPROVAL, THE CONTRACTS AND THE ROUTE ARE READ AS OF DISPATCH (part 5 of the 7
Oct decision). Achilles signs, into the observed effect, the state its dispatch ran
under: its own epoch and operator policy and the instant, from its service, and the
approval digest, contract digests, route and sign-in and grant digests the dispatch
was presented under. ``under_policy`` and ``invokes`` are proven against that and
the history this backend keeps -- the approvals' versions
(:class:`assurance.models.ApprovalVersion`), the tools' contracts
(:class:`assurance.models.ToolContract`) and the route bound per effect at its
dispatch instant -- so a re-approval, a contract change or a route move AFTER the
effect does not unprove it, and an effect dispatched under an approval already
superseded reads unproven even once that approval is restored. The dispatch instant
bounds the effect's (:data:`DISPATCH_EFFECT_WINDOW_SECONDS`), and when the gate saw
a sign-in assertion or a grant, only those records prove the person hops.

Everything else is read as the record stands NOW: the graph (reach, identity,
permissions), shadow and coverage, the approval's permissions ``performs`` reads, and
whether each signature verifies under the keyring in force. No history of the graph
is kept, so a chain can still move from proven to unproven without anyone touching
it, which errs in the direction a decision about deploying now has to.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from . import composition as _composition
from . import graph_refs as _refs

# ---------------------------------------------------------------- the vocabulary

#: Every check that applies passed, and recorded data supports the hop.
PROVEN = "proven"
#: Nothing contradicts the hop, and something it needs is missing or unverified.
UNPROVEN = "unproven"
#: Recorded data contradicts the hop.
BROKEN = "broken"

#: Every hop verdict. A verdict outside it is not read as any of them.
HOP_VERDICTS: frozenset[str] = frozenset({PROVEN, UNPROVEN, BROKEN})
#: Worst last, for taking the worst of a hop's readings and of a chain's hops.
#: Total over :data:`HOP_VERDICTS`, asserted by test.
_VERDICT_RANK: Mapping[str, int] = {PROVEN: 0, UNPROVEN: 1, BROKEN: 2}

# The relations, closed. The example the roadmap gives, hop for hop.
AUTHENTICATED_AS = "authenticated_as"
DELEGATES_TO = "delegates_to"
UNDER_POLICY = "under_policy"
INVOKES = "invokes"
THROUGH_IDENTITY = "through_identity"
PERFORMS = "performs"
PRODUCES = "produces"

#: The relations, in the order a chain runs from a person to an effect.
RELATIONS: tuple[str, ...] = (
    AUTHENTICATED_AS, DELEGATES_TO, UNDER_POLICY, INVOKES, THROUGH_IDENTITY, PERFORMS, PRODUCES,
)

# The node kinds. Five are the asset kinds of the graph (spelled as
# ``Asset.Kind`` spells them, so this module stays free of the models); the rest
# name things the graph does not hold as assets.
PERSON = "person"
USER = "user"
AGENT = "agent"
SERVICE_ACCOUNT = "service_account"
TOOL = "tool"
MCP_SERVER = "mcp_server"
SKILL = "skill"
POLICY = "policy"
ACTION = "action"
EFFECT = "effect"

#: The node kinds that are components of the deployment's graph, resolved by
#: reference (:mod:`assurance.graph_refs`) and checked for shadow and coverage.
GRAPH_KINDS: frozenset[str] = frozenset({AGENT, SERVICE_ACCOUNT, TOOL, MCP_SERVER, SKILL})
#: The graph kinds that are tools: what an agent invokes and what declares the
#: permissions an action is checked against.
TOOL_NODE_KINDS: frozenset[str] = frozenset({TOOL, MCP_SERVER, SKILL})

#: Which kinds each relation joins: ``relation -> (from kinds, to kinds)``.
GRAMMAR: Mapping[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    AUTHENTICATED_AS: ((PERSON,), (USER,)),
    DELEGATES_TO: ((PERSON, USER, AGENT), (AGENT,)),
    UNDER_POLICY: ((AGENT,), (POLICY,)),
    INVOKES: ((POLICY, AGENT), (TOOL, MCP_SERVER, SKILL)),
    THROUGH_IDENTITY: ((TOOL, MCP_SERVER, SKILL), (SERVICE_ACCOUNT,)),
    PERFORMS: ((SERVICE_ACCOUNT, AGENT), (ACTION,)),
    PRODUCES: ((ACTION,), (EFFECT,)),
}

#: The relations this platform holds no record of at all. Unproven, never proven.
#: Empty since part 4 of the 7 Oct decision: sign-in and delegation have signed
#: records (:mod:`assurance.identity_evidence`), read by their own checks below. A
#: relation that loses its record goes back here, and reads unproven whatever its
#: check would say.
NO_RECORD_RELATIONS: frozenset[str] = frozenset()

#: The chain's window, for an ``authenticated_as`` hop: a sign-in proves it only if
#: it happened at most this long before the effect's instant, and not after it. A
#: day: a session older than that is not the one this effect was produced in, however
#: long the identity provider let it live.
AUTHENTICATION_WINDOW_SECONDS = 24 * 60 * 60

#: The most hops one chain may carry. A write bound, not a rule: a chain is read
#: whole on every decision of its deployment.
MAX_HOPS = 16

#: How long after its dispatch an effect may be observed and still be that
#: dispatch's (part 5 of the 7 Oct decision): the dispatch instant bounds the effect
#: instant from below, and this from above. Achilles carries the action out in the
#: dispatch itself, through a provider it gives at most 30 s
#: (``achilles.observed_effect.MAX_PROVIDER_TIMEOUT_S``); twice that is the slack.
DISPATCH_EFFECT_WINDOW_SECONDS = 60

#: The gate's authority epoch is ``<state>#<generation>``
#: (``achilles.failsafe.authority_epoch``); a dispatch is authority only under this
#: state. Spelled here so the rule stays free of Achilles, and pinned by test.
RUNNING_EPOCH_STATE = "running"
EPOCH_SEPARATOR = "#"

#: The document a chain's digest is taken over, and an engine's signature covers.
CHAIN_SCHEMA = "mythos.authority-chain/v1"

#: What each reading code means, published beside it. The codes are what the
#: receipt carries (names stay out of it); the words are for a reader.
REASONS: Mapping[str, str] = {
    # proven by
    "declared_edge": "the inventory declares that the acting agent invokes this tool",
    "effective_reach": "effective access reaches this tool from the acting agent over declared edges",
    "declared_identity": "the acting agent declares that it acts as this account",
    "declared_permission": "a component the identity acts through declares this permission",
    "within_approval": "a tool the approval names was approved with this permission",
    "gate_permit": "the Action Gate authorized this workflow's action at dispatch (a signed permit check)",
    "observed_effect": (
        "the dispatch that carried the action out saw the provider complete it, and signed that with "
        "a key mapped to observed effects and nothing else"
    ),
    "authentication": (
        "a signed authentication record says this person signed in as this principal inside the chain's "
        "window, in a session still open at the effect"
    ),
    "delegation": (
        "a signed delegation record says this principal delegated this agent a scope covering the action, "
        "for a window holding the effect, not revoked as of the effect"
    ),
    "approval_in_force_at_dispatch": (
        "the approval version the gate signed at dispatch is the chain's, and was the version in force at "
        "the dispatch instant"
    ),
    "contract_in_force_at_dispatch": (
        "the approval in force at dispatch names this tool under the contract that was in force at the "
        "dispatch instant, the one the gate signed"
    ),
    "route_at_dispatch": "the served route at the dispatch instant is on record, and is the one the gate signed",
    # unproven
    "no_record": "this platform holds no record of this kind of hop",
    "not_in_grammar": "the hop does not follow the relation grammar in force",
    "dangling_node": "the node names no component in the inventory",
    "ambiguous_node": "more than one component answers to the node's reference",
    "shadow_node": "the component is outside governance (unmanaged, unknown, high risk or retired)",
    "unassessed_node": "the coverage manifest lists the component as never assessed",
    "no_approval": "no approval of this workflow is on record",
    "other_workflow_approval": "the policy node names another workflow's approval",
    "policy_version_unnamed": "the chain does not name which version of the approval it ran under",
    "policy_version_not_in_force": "the approval version the chain names is not the one in force",
    "approval_names_no_tools": "the approval names no tools, so nothing says this tool is within it",
    "approval_permissions_undeclared": "the approved tool contracts do not declare what they permit",
    "no_actor": "no agent in the chain before this hop acts",
    "actor_unresolved": "the acting agent does not resolve to one governed component",
    "inferred_edge": "only an inferred edge -- the shape of the pipeline, not a declaration -- joins them",
    "dangling_edge": "the acting agent declares references discovery could not place",
    "identity_unresolved": "the acting agent's declared identity does not resolve cleanly",
    "no_declared_identity": "the acting agent declares no identity",
    "permissions_undeclared": "the components the identity acts through do not all declare their permissions",
    "no_gate_decision": "the chain cites no Action Gate decision",
    "gate_decision_not_recorded": "the Action Gate decision the chain cites is not recorded here",
    "gate_decision_other_workflow": "the Action Gate decision the chain cites is for another workflow",
    "not_a_gate_decision": "the outcome cited is not a signed Action Gate permit check that verifies now",
    "gate_incomplete": "the Action Gate decision cited is incomplete",
    "effect_not_observed": "nothing observed the effect: the chain cites no observed-effect outcome",
    "effect_outcome_not_recorded": "the observed-effect outcome the chain cites is not recorded here",
    "effect_outcome_other_workflow": "the observed-effect outcome cited is for another workflow",
    "not_an_observed_effect": "the outcome cited is not an observed effect signed by a key trusted now",
    "effect_not_established": "the observed-effect outcome cited does not establish the effect",
    "effect_evidence_unread": (
        "the observed-effect outcome cited carries no evidence document matching its signed digest, so "
        "nothing says which tool, permit or dispatch it observed"
    ),
    "effect_tool_unnamed": "the chain names no tool in an invokes hop for the observed effect to match",
    "effect_other_tool": "the observed effect is of another tool than the one the chain's invokes hop names",
    "effect_action_unnamed": "the chain names no action in a performs hop for the observed effect to match",
    "effect_other_action": "the observed effect is of another action than the one the chain's performs hop names",
    "effect_other_dispatch": (
        "the effect was observed on the dispatch of another gate decision than the one the chain cites"
    ),
    "effect_outcome_cited_twice": "another chain in force cites the same observed effect: one observation proves one chain",
    "effect_instant_unknown": (
        "the chain cites no observed effect whose signed document says when the effect happened, so no "
        "sign-in or delegation can be placed against it"
    ),
    "no_authentication_record": (
        "no signed authentication record in force names this person signing in as this principal"
    ),
    "authentication_out_of_window": (
        "the sign-in recorded for this person and principal falls outside the chain's window: after the "
        "effect, or more than a day before it"
    ),
    "authentication_expired": "the session the recorded sign-in opened had expired by the time of the effect",
    "no_delegation_record": "no signed delegation record in force names this principal delegating to this agent",
    "delegation_action_unnamed": "the chain names no action in a performs hop for the delegated scope to cover",
    "delegation_out_of_scope": "the action the chain performs is outside the scope the principal delegated",
    "delegation_out_of_window": "the effect happened before the delegation's window opened",
    "delegation_expired": "the effect happened after the delegation's window closed",
    "delegation_revoked": "the delegation was revoked before (or at) the instant of the effect",
    "dispatch_state_unrecorded": (
        "nothing records the state the effect's dispatch ran under -- no observed effect signed with it, or "
        "no approval, contract or route on record at the dispatch instant -- so the hop is not read live instead"
    ),
    "dispatched_under_superseded_policy": (
        "the dispatch ran under an approval, or a gate epoch or operator policy, already superseded at the "
        "dispatch instant"
    ),
    "dispatched_under_superseded_contract": (
        "the dispatch ran under a tool contract already superseded at the dispatch instant"
    ),
    "dispatched_on_another_route": (
        "the gate signed a served route at dispatch that is not the route serving at the dispatch instant"
    ),
    "effect_outside_dispatch_window": (
        "the effect was observed before its dispatch left, or longer after it than the dispatch window"
    ),
    "authentication_not_dispatched": (
        "the gate saw another sign-in at dispatch: no record in force with the assertion it carried names "
        "this person and principal"
    ),
    "delegation_not_dispatched": (
        "the gate saw another grant at dispatch: no record in force of the grant it carried names this "
        "principal and agent"
    ),
    "unchecked": "no check speaks for this hop",
    # broken
    "outside_approval": "the approval names other tools, or permissions, and not this one",
    "unreachable": "effective access over a fully resolved graph says the acting agent cannot reach this tool",
    "acts_as_another": "the acting agent declares that it acts as another account",
    "permission_not_declared": "every component the identity acts through declares its permissions, and none this one",
    "gate_refused": "the Action Gate refused this workflow's action",
    "effect_violated": "the observed-effect outcome cited says the effect was produced outside its authority",
}


#: Codes this rule emitted before part 5 of the 7 Oct decision and no longer does:
#: ``under_policy`` and ``invokes`` are read as of dispatch now, against the approval,
#: contracts and route in force at the dispatch instant, so nothing reads them against
#: the record in force when the receipt is computed. Published still, for receipts that
#: carry them (the v6.0 spec lists them as retired); never in :data:`REASONS`, which is
#: exactly what the rule emits.
RETIRED_REASONS: Mapping[str, str] = {
    "approval_in_force": "the policy node names the approval in force, at its current version",
    "approved_contract_in_force": "the approval names this tool, under the contract in force",
    "superseded_contract": "the tool was approved under a contract that has since changed",
    "route_moved": "the chain was recorded against a served route that no longer serves",
    "route_unrecorded": "nothing records which served route the chain was taken against",
}


# ------------------------------------------------------------------- the chain


@dataclass(frozen=True)
class Node:
    """One node of a chain: a ``kind`` from :data:`GRAMMAR` and the reference that
    names it -- an asset's identifier or name for a graph kind
    (:mod:`assurance.graph_refs` resolves it), an approved workflow's slug for a
    policy, a permission for an action, the effect's own name for an effect.
    ``version`` is a policy's: the approval digest the chain ran under."""

    kind: str
    ref: str
    version: str = ""

    def as_dict(self) -> dict:
        out = {"kind": self.kind, "ref": self.ref}
        if self.version:
            out["version"] = self.version
        return out


@dataclass(frozen=True)
class Hop:
    """``(source, relation, target)`` -- spelled ``from``/``to`` on the wire."""

    source: Node
    relation: str
    target: Node

    def as_dict(self) -> dict:
        return {"from": self.source.as_dict(), "relation": self.relation, "to": self.target.as_dict()}


@dataclass(frozen=True)
class Chain:
    """One consequential effect's authority chain, bound to the workflow it serves.

    ``gate_outcome_id`` cites the Action Gate decision (an Achilles-signed chain
    outcome recorded on the deployment) the action went through;
    ``effect_outcome_id`` cites an outcome that observed the effect. ``route``
    says whether the chain was recorded against the served route serving now
    (:data:`assurance.composition.CHAIN_ROUTES`), decided by the persistence layer.
    """

    workflow: str
    hops: tuple[Hop, ...]
    gate_outcome_id: str = ""
    effect_outcome_id: str = ""
    route: str = _composition.ROUTE_UNRECORDED

    @property
    def effect(self) -> str:
        return self.hops[-1].target.ref if self.hops else ""

    def nodes(self) -> list[Node]:
        """The nodes in order: the first hop's source, then every hop's target."""
        return [self.hops[0].source, *(h.target for h in self.hops)] if self.hops else []


def parse_node(raw, where: str, errors: list[str]) -> Node | None:
    if not isinstance(raw, Mapping):
        errors.append(f"{where} is an object with a kind and a ref")
        return None
    unknown = sorted(set(raw) - {"kind", "ref", "version"})
    if unknown:
        errors.append(f"{where} carries unknown field(s) {unknown}")
    kind, ref, version = raw.get("kind"), raw.get("ref"), raw.get("version", "")
    if not isinstance(kind, str) or kind not in _node_kinds():
        errors.append(f"{where}.kind is one of {sorted(_node_kinds())}, not {kind!r}")
        return None
    if not isinstance(ref, str) or not ref.strip() or len(ref) > 200:
        errors.append(f"{where}.ref is a non-empty reference of at most 200 characters")
        return None
    if version in (None, ""):
        version = ""
    elif kind != POLICY:
        errors.append(f"{where}: only a policy node carries a version")
        return None
    elif not isinstance(version, str) or len(version) != 64 or any(c not in "0123456789abcdef" for c in version):
        errors.append(f"{where}.version is the approval digest: 64 lowercase hex characters")
        return None
    return Node(kind=kind, ref=ref.strip(), version=version)


def _node_kinds() -> frozenset[str]:
    return frozenset(k for froms, tos in GRAMMAR.values() for k in (*froms, *tos))


def parse_hops(raw, workflow: str) -> tuple[tuple[Hop, ...], list[str]]:
    """The hops a write carries, and every reason it is not a chain.

    A CHAIN, not a set of statements: the hops are contiguous (each hop's ``to``
    is the next hop's ``from``), follow :data:`GRAMMAR`, end in the effect
    (``produces``), visit no node twice, and a policy node names the chain's own
    workflow. A write that fails any of these is refused whole -- a dangling hop in
    the middle of a chain is not a chain with one hop unproven, it is two chains
    nobody joined.
    """
    errors: list[str] = []
    if not isinstance(raw, list) or not raw:
        return (), ["hops is a non-empty list"]
    if len(raw) > MAX_HOPS:
        return (), [f"{len(raw)} hops is more than the {MAX_HOPS} one chain may carry"]
    hops: list[Hop] = []
    for i, item in enumerate(raw):
        where = f"hops[{i}]"
        if not isinstance(item, Mapping):
            errors.append(f"{where} is an object with from, relation and to")
            continue
        unknown = sorted(set(item) - {"from", "relation", "to"})
        if unknown:
            errors.append(f"{where} carries unknown field(s) {unknown}")
        relation = item.get("relation")
        if relation not in GRAMMAR:
            errors.append(f"{where}.relation is one of {list(RELATIONS)}, not {relation!r}")
            continue
        source = parse_node(item.get("from"), f"{where}.from", errors)
        target = parse_node(item.get("to"), f"{where}.to", errors)
        if source is None or target is None:
            continue
        froms, tos = GRAMMAR[relation]
        if source.kind not in froms or target.kind not in tos:
            errors.append(
                f"{where}: {relation} joins {'/'.join(froms)} to {'/'.join(tos)}, not {source.kind} to {target.kind}"
            )
            continue
        hops.append(Hop(source, relation, target))
    if errors:
        return (), errors
    for i in range(1, len(hops)):
        if hops[i].source != hops[i - 1].target:
            errors.append(f"hops[{i}].from is not hops[{i - 1}].to: the chain is broken between them")
    if hops[-1].relation != PRODUCES:
        errors.append("the last hop is the effect: it is a produces hop")
    seen: set[tuple[str, str]] = set()
    for node in Chain(workflow, tuple(hops)).nodes():
        key = (node.kind, node.ref)
        if key in seen:
            errors.append(f"the chain visits {node.kind} {node.ref!r} twice; a chain is not a loop")
        seen.add(key)
        if node.kind == POLICY and node.ref != workflow:
            errors.append(
                f"the policy node names the approval of {node.ref!r}; this chain serves {workflow!r}"
            )
    return (tuple(hops) if not errors else ()), errors


def hops_from_stored(raw) -> tuple[Hop, ...]:
    """Hops as a stored row holds them, read leniently: a stored row is never
    refused on read. Whatever does not parse as a node is kept as written, and the
    grammar check in :func:`verify` reads it as unproven."""
    hops = []
    for item in raw if isinstance(raw, list) else []:
        item = item if isinstance(item, Mapping) else {}

        def node(value) -> Node:
            value = value if isinstance(value, Mapping) else {}
            return Node(str(value.get("kind") or ""), str(value.get("ref") or ""), str(value.get("version") or ""))

        hops.append(Hop(node(item.get("from")), str(item.get("relation") or ""), node(item.get("to"))))
    return tuple(hops)


# ------------------------------------------------------------------- the inputs


@dataclass(frozen=True)
class Component:
    """One component of the deployment's graph, as the hop checks read it.

    Duck-types what :mod:`assurance.graph_refs` resolves against (``kind``,
    ``identifier``, ``name``, ``metadata``), so a node is resolved by the same rule
    the route map and effective access resolve the inventory's own references by.
    ``permissions`` is ``None`` when the component declares none -- distinct from
    an empty declaration, which says it may do nothing."""

    uuid: str
    kind: str
    name: str
    identifier: str = ""
    classification: str = ""
    shadow: bool = False
    assessed: bool = True
    permissions: tuple[str, ...] | None = None

    @property
    def metadata(self) -> dict:
        return {}


@dataclass(frozen=True)
class Gap:
    """A reference a component declares that discovery could not place cleanly
    (:func:`assurance.graph_refs.unresolved_row`)."""

    mechanism: str
    reference: str
    reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class Graph:
    """The declared graph: components, declared edges ``(source uuid, kind, target
    uuid)`` as the route map draws them (``invokes``, ``acts_as``, ``hosted_by``,
    ``connects_to``), inferred ``(source, target)`` pairs, each component's gaps,
    and each principal's effective reach (target uuids, :mod:`assurance.access`)."""

    components: tuple[Component, ...] = ()
    declared: frozenset[tuple[str, str, str]] = frozenset()
    inferred: frozenset[tuple[str, str]] = frozenset()
    gaps: Mapping[str, tuple[Gap, ...]] = field(default_factory=dict)
    reach: Mapping[str, frozenset[str]] = field(default_factory=dict)


@dataclass(frozen=True)
class ApprovedTool:
    """One tool an approval binds (:func:`assurance.tool_contract.approved_tools`),
    with the permissions the APPROVED contract declared (``None``: it declared
    none) and the digest in force now (``None``: no longer registered)."""

    kind: str
    identifier: str
    approved_digest: str
    current_digest: str | None
    permissions: tuple[str, ...] | None = None

    @property
    def superseded(self) -> bool:
        return self.current_digest != self.approved_digest


@dataclass(frozen=True)
class Approval:
    """An approved workflow as a policy node is checked against: its digest in
    force (:func:`assurance.authority_chain_records.approval_digest`) and its tools."""

    slug: str
    digest: str
    tools: tuple[ApprovedTool, ...] = ()


@dataclass(frozen=True)
class DispatchState:
    """The state an effect's dispatch ran under, as the gate signed it into the observed
    effect (``mythos.observed-effect/v2``'s ``dispatch`` block), read against its signed
    digest -- and the served route at that instant, as this backend bound it when it
    recorded the effect.

    From Achilles' service: ``dispatched_at``, the authority ``epoch`` at the spend and
    the ``permit_epoch`` the permit was issued under, the operator ``policy_digest`` at
    the spend and the ``permit_policy_digest`` the permit was decided under. As the
    dispatch was presented (Achilles signs it and cannot judge it): ``approval_digest``,
    ``contracts`` (``(kind, identifier) -> digest``), ``route_fingerprint``,
    ``assertion_digest`` and ``grant_digest`` -- ``None`` (empty) for none. And
    ``route_at_dispatch``: this backend's own record of the route serving at
    ``dispatched_at`` (blank: the record cannot say)."""

    dispatched_at: datetime
    epoch: str = ""
    permit_epoch: str = ""
    policy_id: str = ""
    policy_digest: str = ""
    permit_policy_digest: str = ""
    approval_digest: str | None = None
    contracts: Mapping[tuple[str, str], str] = field(default_factory=dict)
    route_fingerprint: str | None = None
    assertion_digest: str | None = None
    grant_digest: str | None = None
    route_at_dispatch: str = ""


@dataclass(frozen=True)
class ApprovalVersion:
    """One recorded version of a workflow's approval (:mod:`assurance.approval_history`):
    its digest (blank once withdrawn), the tools it bound as ``(kind, identifier,
    contract digest)``, and when the platform noted it in force."""

    in_force_from: datetime
    digest: str
    tools: tuple[tuple[str, str, str], ...] = ()


@dataclass(frozen=True)
class ContractVersion:
    """One recorded contract of a tool (:class:`assurance.models.ToolContract`): its
    digest, and when it was recorded -- in force from then until the next one."""

    recorded_at: datetime
    digest: str


@dataclass(frozen=True)
class ObservedEffect:
    """What an observed-effect outcome's evidence document says it observed, as far
    as the rule reads it: the tool, and the dispatch it was observed on -- that
    dispatch's gate decision, its id and the permit's digest -- and, for a v2
    document, the state that dispatch ran under (``dispatch``; ``None`` for v1)."""

    tool_kind: str
    tool_identifier: str
    gate_outcome_id: str
    dispatch_id: str = ""
    permit_digest: str = ""
    #: The permitted action the dispatch carried out, as its permit named it.
    action: str = ""
    #: When the effect was observed: the document's own instant, which the signed
    #: outcome repeats. The one instant of a chain a signature vouches for, and so
    #: the one sign-in and delegation are placed against.
    observed_at: datetime | None = None
    dispatch: DispatchState | None = None


@dataclass(frozen=True)
class CitedOutcome:
    """A recorded chain outcome a chain cites, as the rule may rely on it:
    ``evidence`` is :func:`assurance.composition.evidence_kind` over the basis IN
    FORCE, so an envelope that no longer verifies reads as what it then is.
    ``effect`` is an observed effect's evidence document, read against its signed
    digest (:func:`assurance.observed_effects.evidence_in_force`); ``None`` for
    every other outcome, and for one whose document does not match."""

    outcome_id: str
    workflow: str
    status: str
    evidence: str
    effect: ObservedEffect | None = None


@dataclass(frozen=True)
class Authentication:
    """A signed ``authentication`` record in force, as the rule reads it
    (:mod:`assurance.identity_evidence`, ``mythos.authentication/v1``): ``person``
    signed in as ``principal`` at ``authenticated_at``, through ``issuer`` over
    ``protocol``, in a session that expires at ``expires_at``; ``witness`` says who
    witnessed it."""

    outcome_id: str
    person: str
    principal: str
    authenticated_at: datetime
    expires_at: datetime
    issuer: str = ""
    protocol: str = ""
    witness: str = ""
    #: ``sha256:`` of the id_token or assertion: one sign-in, one record.
    assertion_digest: str = ""


@dataclass(frozen=True)
class Delegation:
    """A signed ``delegation`` record in force (``mythos.delegation/v1``): the grant
    ``grant_digest`` names -- ``principal_kind``/``principal_ref`` delegated ``agent``
    the ``actions`` in scope, for ``[not_before, not_after)`` -- and, when the record
    says so, the instant it was revoked. A grant may have several records (granted,
    then revoked); the digest binds them to one grant."""

    outcome_id: str
    grant_digest: str
    principal_kind: str
    principal_ref: str
    agent: str
    actions: frozenset[str]
    not_before: datetime
    not_after: datetime
    revoked_at: datetime | None = None
    witness: str = ""


@dataclass(frozen=True)
class Inputs:
    graph: Graph = field(default_factory=Graph)
    approvals: Mapping[str, Approval] = field(default_factory=dict)
    outcomes: Mapping[str, CitedOutcome] = field(default_factory=dict)
    #: How many chains in force cite each observed-effect outcome, by its id: one
    #: observation proves one chain.
    effect_citations: Mapping[str, int] = field(default_factory=dict)
    #: The signed sign-in and delegation records in force that name a principal the
    #: chains name.
    authentications: tuple[Authentication, ...] = ()
    delegations: tuple[Delegation, ...] = ()
    #: Every recorded version of the chains' workflows' approvals, oldest first, by
    #: slug; and every recorded contract of the tools they bound, oldest first, by
    #: ``(kind, identifier)``. What ``under_policy`` and ``invokes`` are read against,
    #: as of each chain's dispatch instant.
    approval_history: Mapping[str, tuple[ApprovalVersion, ...]] = field(default_factory=dict)
    contract_history: Mapping[tuple[str, str], tuple[ContractVersion, ...]] = field(default_factory=dict)


# ------------------------------------------------------------------ the verdict


@dataclass(frozen=True)
class Reading:
    """One thing a check found about a hop: its verdict, a code from
    :data:`REASONS`, and the sentence naming what it found."""

    verdict: str
    code: str
    detail: str


@dataclass(frozen=True)
class HopVerdict:
    index: int
    hop: Hop
    verdict: str
    proven_by: tuple[Reading, ...] = ()
    reasons: tuple[Reading, ...] = ()


@dataclass(frozen=True)
class ChainVerdict:
    chain: Chain
    verdict: str
    hops: tuple[HopVerdict, ...]

    @property
    def unproven(self) -> tuple[HopVerdict, ...]:
        return tuple(h for h in self.hops if h.verdict == UNPROVEN)

    @property
    def broken(self) -> tuple[HopVerdict, ...]:
        return tuple(h for h in self.hops if h.verdict == BROKEN)


def worst(verdicts) -> str:
    """The worst of ``verdicts``; :data:`UNPROVEN` for none -- nothing is proven by
    nothing having been checked."""
    verdicts = list(verdicts)
    if not verdicts:
        return UNPROVEN
    return max(verdicts, key=lambda v: _VERDICT_RANK[v])


def _hop_verdict(index: int, hop: Hop, readings: list[Reading]) -> HopVerdict:
    if not readings:
        readings = [Reading(UNPROVEN, "unchecked", "no check speaks for this hop")]
    # Proven only when EVERY reading is: one unproven reading among proven ones
    # leaves the hop unproven, whatever else supports it.
    verdict = worst(r.verdict for r in readings)
    proven =tuple(r for r in readings if r.verdict == PROVEN) if verdict == PROVEN else ()
    reasons = tuple(
        sorted((r for r in readings if r.verdict != PROVEN), key=lambda r: -_VERDICT_RANK[r.verdict])
    )
    return HopVerdict(index, hop, verdict, proven, reasons)


class _Index:
    """The graph, indexed once per verification."""

    def __init__(self, graph: Graph):
        self.graph = graph
        self.by_identifier, self.by_name = _refs.reference_index(graph.components)
        self.by_uuid = {c.uuid: c for c in graph.components}

    def resolve(self, node: Node) -> tuple[Component | None, list[Reading]]:
        """The component a graph node names, and what is wrong with it. ``None``
        for a node that is not a graph kind, or names no single component."""
        if node.kind not in GRAPH_KINDS:
            return None, []
        candidates, why = _refs.resolve_reference(
            node.ref, self.by_identifier, self.by_name, only_kinds=frozenset({node.kind})
        )
        if not candidates:
            return None, [Reading(UNPROVEN, "dangling_node", f"no {node.kind} {node.ref!r} is in the inventory")]
        if len(candidates) > 1 or why is not None:
            return None, [
                Reading(
                    UNPROVEN,
                    "ambiguous_node",
                    f"{len(candidates)} components answer to {node.kind} {node.ref!r}; the chain does not say which",
                )
            ]
        component = candidates[0]
        readings = []
        if component.shadow:
            readings.append(
                Reading(
                    UNPROVEN,
                    "shadow_node",
                    f"{node.kind} {component.name!r} is {component.classification or 'ungoverned'}: a shadow node",
                )
            )
        if not component.assessed:
            readings.append(
                Reading(
                    UNPROVEN,
                    "unassessed_node",
                    f"the coverage manifest lists {node.kind} {component.name!r} as never assessed",
                )
            )
        return component, readings

    def gaps(self, component: Component, mechanism: str) -> tuple[Gap, ...]:
        return tuple(g for g in self.graph.gaps.get(component.uuid, ()) if g.mechanism == mechanism)


def _last_before(chain: Chain, index: int, kinds) -> Node | None:
    """The last node of one of ``kinds`` at or before hop ``index``'s source."""
    for node in reversed(chain.nodes()[: index + 1]):
        if node.kind in kinds:
            return node
    return None


# ---------------------------------------------------------- the relation checks


def _no_record(chain, i, source, target, inputs, index) -> list[Reading]:
    return [
        Reading(
            UNPROVEN,
            "no_record",
            f"this platform holds no record of {chain.hops[i].relation.replace('_', ' ')}: "
            "nothing here can show it happened",
        )
    ]


def _unrecorded(detail: str) -> Reading:
    return Reading(UNPROVEN, "dispatch_state_unrecorded", detail)


def _dispatch_state(chain: Chain, inputs: Inputs) -> tuple[DispatchState | None, Reading | None]:
    """The state the chain's effect was dispatched under, or why nothing records it:
    the cited observed effect's v2 ``dispatch`` block, read from the document its
    signed digest names. Never the record as it stands now in its place: a hop read
    as of dispatch with no dispatch state on record is unproven, not read live."""
    cited = chain.effect_outcome_id
    if not cited:
        return None, _unrecorded(
            "the chain cites no observed effect, so nothing records the state its dispatch ran under"
        )
    outcome = inputs.outcomes.get(cited)
    if (
        outcome is None
        or outcome.workflow != chain.workflow
        or outcome.evidence != _composition.EVIDENCE_OBSERVED_EFFECT
        or outcome.effect is None
    ):
        return None, _unrecorded(
            f"the observed effect the chain cites ({cited}) is not one in force for {chain.workflow!r} "
            "with a document matching its signed digest, so nothing records the state its dispatch ran under"
        )
    if outcome.effect.dispatch is None:
        return None, _unrecorded(
            f"observed effect {cited} is a mythos.observed-effect/v1 document: it records no state its "
            "dispatch ran under"
        )
    return outcome.effect.dispatch, None


def _version_at(versions, instant: datetime, when) -> tuple[object | None, list]:
    """The version of ``versions`` (oldest first) in force at ``instant`` -- the last
    one ``when`` puts at or before it -- and every one before that."""
    current, before = None, []
    for version in versions:
        if when(version) > instant:
            break
        if current is not None:
            before.append(current)
        current = version
    return current, before


def _gate_epoch(dispatch: DispatchState) -> list[Reading]:
    """What the gate's own epoch and policy at the spend say: nothing when the dispatch
    ran under the authority the permit was issued under, a reading otherwise."""
    if not dispatch.epoch:
        return [_unrecorded("the gate bound no authority epoch into the dispatch")]
    readings = []
    state = dispatch.epoch.partition(EPOCH_SEPARATOR)[0]
    if state != RUNNING_EPOCH_STATE:
        readings.append(
            Reading(
                UNPROVEN,
                "dispatched_under_superseded_policy",
                f"the gate's authority epoch at the dispatch was {dispatch.epoch!r}, not {RUNNING_EPOCH_STATE}",
            )
        )
    if dispatch.permit_epoch != dispatch.epoch:
        readings.append(
            Reading(
                UNPROVEN,
                "dispatched_under_superseded_policy",
                f"the permit was issued under authority epoch {dispatch.permit_epoch!r}; at the dispatch the epoch "
                f"in force was {dispatch.epoch!r}",
            )
        )
    if dispatch.permit_policy_digest != dispatch.policy_digest:
        readings.append(
            Reading(
                UNPROVEN,
                "dispatched_under_superseded_policy",
                f"the permit was decided under operator policy {dispatch.permit_policy_digest or 'none'}; at the "
                f"dispatch the policy in force was {dispatch.policy_digest or 'none'}",
            )
        )
    return readings


def _under_policy(chain, i, source, target, inputs, index) -> list[Reading]:
    """Read AS OF DISPATCH (part 5 of the 7 Oct decision): the version the chain names
    is the one the gate signed at dispatch, the gate ran under the epoch and operator
    policy the permit was issued under, and that version was the approval in force at
    the dispatch instant by the recorded history -- not the approval in force now. A
    re-approval after the effect does not unprove it; an approval already superseded
    at the dispatch does, and so does a dispatch whose state nothing records."""
    policy = chain.hops[i].target
    if policy.ref != chain.workflow:
        return [
            Reading(
                UNPROVEN,
                "other_workflow_approval",
                f"the policy node names {policy.ref!r}; this chain serves {chain.workflow!r}",
            )
        ]
    if not policy.version:
        return [
            Reading(
                UNPROVEN,
                "policy_version_unnamed",
                f"the chain does not name the version of {policy.ref!r} it ran under",
            )
        ]
    dispatch, missing = _dispatch_state(chain, inputs)
    if missing is not None:
        return [missing]
    readings = _gate_epoch(dispatch)
    presented = dispatch.approval_digest
    at = _when(dispatch.dispatched_at)
    if presented is None:
        return [*readings, _unrecorded(f"the dispatch at {at} presented no approval digest of {policy.ref!r}")]
    if policy.version != presented:
        readings.append(
            Reading(
                UNPROVEN,
                "policy_version_not_in_force",
                f"the chain ran under version {policy.version} of {policy.ref!r}; the gate signed version "
                f"{presented} at the dispatch at {at}",
            )
        )
    versions = inputs.approval_history.get(chain.workflow, ())
    current, before = _version_at(versions, dispatch.dispatched_at, lambda v: v.in_force_from)
    if current is None:
        readings.append(
            _unrecorded(f"no version of the approval of {policy.ref!r} is recorded at or before the dispatch at {at}")
        )
    elif current.digest != presented:
        if not current.digest:
            why = f"the approval of {policy.ref!r} had been withdrawn (from {_when(current.in_force_from)})"
        elif any(v.digest == presented for v in before):
            why = (
                f"version {presented} of {policy.ref!r} had been superseded by {current.digest} "
                f"(from {_when(current.in_force_from)})"
            )
        else:
            why = (
                f"version {presented} of {policy.ref!r} was not in force; {current.digest} was "
                f"(from {_when(current.in_force_from)})"
            )
        readings.append(Reading(UNPROVEN, "dispatched_under_superseded_policy", f"{why} at the dispatch at {at}"))
    elif not readings:
        readings.append(
            Reading(
                PROVEN,
                "approval_in_force_at_dispatch",
                f"approval {policy.ref!r} at {presented}, the version in force (from "
                f"{_when(current.in_force_from)}) at the dispatch at {at}, under gate epoch {dispatch.epoch!r}",
            )
        )
    return readings


def _approved_at_dispatch(chain: Chain, node: Node, target, dispatch: DispatchState, inputs: Inputs) -> list[Reading]:
    """The approval and contract half of ``invokes``, as of dispatch: the approval in
    force at the dispatch instant names this tool, under the contract in force at that
    instant, which is the one the gate signed."""
    at = _when(dispatch.dispatched_at)
    approval, _ = _version_at(
        inputs.approval_history.get(chain.workflow, ()), dispatch.dispatched_at, lambda v: v.in_force_from
    )
    if approval is None:
        return [_unrecorded(f"no version of the approval of {chain.workflow!r} is recorded at or before the dispatch at {at}")]
    if not approval.digest:
        return [
            Reading(
                UNPROVEN, "no_approval", f"the approval of {chain.workflow!r} had been withdrawn by the dispatch at {at}"
            )
        ]
    if not approval.tools:
        return [
            Reading(
                UNPROVEN,
                "approval_names_no_tools",
                f"the approval of {chain.workflow!r} in force at the dispatch at {at} names no tools",
            )
        ]
    keys = {(node.kind, node.ref)}
    if target is not None:
        keys.add((target.kind, target.identifier))
    approved = next((t for t in approval.tools if (t[0], t[1]) in keys), None)
    if approved is None:
        named = ", ".join(sorted(f"{k} {ident!r}" for k, ident, _ in approval.tools))
        return [
            Reading(
                BROKEN,
                "outside_approval",
                f"the approval of {chain.workflow!r} in force at the dispatch at {at} names {named}, and not "
                f"{node.kind} {node.ref!r}",
            )
        ]
    kind, identifier, approved_digest = approved
    contract, _ = _version_at(
        inputs.contract_history.get((kind, identifier), ()), dispatch.dispatched_at, lambda v: v.recorded_at
    )
    presented = dispatch.contracts.get((kind, identifier))
    readings: list[Reading] = []
    if contract is None:
        readings.append(_unrecorded(f"no contract of {kind} {identifier!r} is recorded at or before the dispatch at {at}"))
    elif contract.digest != approved_digest:
        readings.append(
            Reading(
                UNPROVEN,
                "dispatched_under_superseded_contract",
                f"{kind} {identifier!r} was approved under contract {approved_digest}; the contract in force at the "
                f"dispatch at {at} was {contract.digest} (from {_when(contract.recorded_at)})",
            )
        )
    if presented is None:
        readings.append(_unrecorded(f"the dispatch at {at} presented no contract digest of {kind} {identifier!r}"))
    elif contract is not None and presented != contract.digest:
        readings.append(
            Reading(
                UNPROVEN,
                "dispatched_under_superseded_contract",
                f"the dispatch at {at} presented contract {presented} of {kind} {identifier!r}; the contract in "
                f"force then was {contract.digest}",
            )
        )
    if readings:
        return readings
    return [
        Reading(
            PROVEN,
            "contract_in_force_at_dispatch",
            f"approved under contract {approved_digest}, the contract in force at the dispatch at {at}, as presented",
        )
    ]


def _route_at_dispatch(dispatch: DispatchState) -> Reading:
    at = _when(dispatch.dispatched_at)
    if not dispatch.route_at_dispatch:
        return _unrecorded(f"the served route at the dispatch at {at} is not on record")
    if dispatch.route_fingerprint is not None and dispatch.route_fingerprint != dispatch.route_at_dispatch:
        return Reading(
            UNPROVEN,
            "dispatched_on_another_route",
            f"the gate signed served route {dispatch.route_fingerprint} at the dispatch at {at}; the route serving "
            f"then was {dispatch.route_at_dispatch}",
        )
    return Reading(
        PROVEN,
        "route_at_dispatch",
        f"the dispatch at {at} ran on served route {dispatch.route_at_dispatch}, as recorded when its effect was",
    )


def _invokes(chain, i, source, target, inputs, index) -> list[Reading]:
    """The approval, contract and route are read AS OF DISPATCH (part 5 of the 7 Oct
    decision): a contract changed or a route moved after the effect does not unprove
    it, and a dispatch whose state nothing records is unproven rather than read live.
    The graph -- whether the acting agent reaches the tool -- is read as it stands: no
    history of it is kept."""
    readings: list[Reading] = []
    node = chain.hops[i].target
    dispatch, missing = _dispatch_state(chain, inputs)
    if missing is not None:
        readings.append(missing)
    else:
        readings.extend(_approved_at_dispatch(chain, node, target, dispatch, inputs))
        readings.append(_route_at_dispatch(dispatch))

    actor_node = _last_before(chain, i, {AGENT})
    if actor_node is None:
        readings.append(Reading(UNPROVEN, "no_actor", "no agent in the chain before this hop invokes the tool"))
    else:
        actor, _ = index.resolve(actor_node)
        if actor is None:
            readings.append(
                Reading(UNPROVEN, "actor_unresolved", f"agent {actor_node.ref!r} does not resolve to one component")
            )
        elif target is not None:
            readings.append(_reach(index, actor, target))
    return readings


def _reach(index: _Index, actor: Component, tool: Component) -> Reading:
    graph = index.graph
    names = {tool.identifier, tool.name}
    gaps = index.gaps(actor, _refs.MECHANISM_TOOLS)
    about_this = [g for g in gaps if g.reference in names]
    if about_this:
        why = ", ".join(sorted({r for g in about_this for r in g.reasons})) or "unresolved"
        return Reading(
            UNPROVEN, "dangling_edge", f"agent {actor.name!r} names {tool.name!r} by a reference that is {why}"
        )
    if (actor.uuid, "invokes", tool.uuid) in graph.declared:
        return Reading(PROVEN, "declared_edge", f"agent {actor.name!r} declares that it invokes {tool.name!r}")
    if tool.uuid in graph.reach.get(actor.uuid, frozenset()):
        return Reading(
            PROVEN, "effective_reach", f"effective access reaches {tool.name!r} from agent {actor.name!r}"
        )
    if (actor.uuid, tool.uuid) in graph.inferred:
        return Reading(
            UNPROVEN,
            "inferred_edge",
            f"only an inferred edge joins agent {actor.name!r} to {tool.name!r}; nothing declares it",
        )
    if gaps:
        return Reading(
            UNPROVEN,
            "dangling_edge",
            f"agent {actor.name!r} declares {len(gaps)} tool reference(s) discovery could not place, so "
            f"its reach is not known whole",
        )
    return Reading(
        BROKEN,
        "unreachable",
        f"effective access over a fully resolved graph: agent {actor.name!r} cannot reach {tool.name!r}",
    )


def _through_identity(chain, i, source, target, inputs, index) -> list[Reading]:
    actor_node = _last_before(chain, i, {AGENT})
    if actor_node is None:
        return [Reading(UNPROVEN, "no_actor", "no agent in the chain before this hop acts through an identity")]
    actor, _ = index.resolve(actor_node)
    if actor is None:
        return [Reading(UNPROVEN, "actor_unresolved", f"agent {actor_node.ref!r} does not resolve to one component")]
    gaps = index.gaps(actor, _refs.MECHANISM_IDENTITY)
    if gaps:
        why = ", ".join(sorted({r for g in gaps for r in g.reasons})) or "unresolved"
        return [
            Reading(UNPROVEN, "identity_unresolved", f"agent {actor.name!r} declares an identity that is {why}")
        ]
    acts_as = {t for (s, kind, t) in index.graph.declared if s == actor.uuid and kind == "acts_as"}
    if target is not None and target.uuid in acts_as:
        return [Reading(PROVEN, "declared_identity", f"agent {actor.name!r} declares that it acts as {target.name!r}")]
    if acts_as:
        others = ", ".join(sorted(index.by_uuid[u].name for u in acts_as if u in index.by_uuid))
        return [
            Reading(
                BROKEN,
                "acts_as_another",
                f"agent {actor.name!r} declares that it acts as {others}, not {chain.hops[i].target.ref!r}",
            )
        ]
    return [Reading(UNPROVEN, "no_declared_identity", f"agent {actor.name!r} declares no identity")]


def _performs(chain, i, source, target, inputs, index) -> list[Reading]:
    action = chain.hops[i].target.ref
    readings: list[Reading] = []

    # What the identity can do: its own declared permissions, the tool it acts
    # through in this chain, and every tool its effective access reaches.
    relevant: dict[str, Component] = {}
    if source is not None:
        relevant[source.uuid] = source
        for uuid in index.graph.reach.get(source.uuid, frozenset()):
            component = index.by_uuid.get(uuid)
            if component is not None and component.kind in TOOL_NODE_KINDS:
                relevant[uuid] = component
    tool_node = _last_before(chain, i, TOOL_NODE_KINDS)
    if tool_node is not None:
        tool, _ = index.resolve(tool_node)
        if tool is not None:
            relevant[tool.uuid] = tool
    holders = sorted(c.name for c in relevant.values() if c.permissions is not None and action in c.permissions)
    declaring = [c for c in relevant.values() if c.permissions is not None]
    if holders:
        readings.append(
            Reading(PROVEN, "declared_permission", f"{', '.join(holders)} declare(s) the permission {action!r}")
        )
    elif relevant and len(declaring) == len(relevant):
        readings.append(
            Reading(
                BROKEN,
                "permission_not_declared",
                f"{', '.join(sorted(c.name for c in relevant.values()))} declare their permissions, "
                f"and none of them is {action!r}",
            )
        )
    else:
        readings.append(
            Reading(
                UNPROVEN,
                "permissions_undeclared",
                f"nothing the identity acts through declares {action!r}, and not everything it acts "
                "through declares its permissions",
            )
        )

    approval = inputs.approvals.get(chain.workflow)
    if approval is None:
        readings.append(Reading(UNPROVEN, "no_approval", f"no approval of {chain.workflow!r} is on record"))
    elif not approval.tools:
        readings.append(
            Reading(UNPROVEN, "approval_names_no_tools", f"the approval of {chain.workflow!r} names no tools")
        )
    else:
        within = sorted(t.identifier for t in approval.tools if t.permissions is not None and action in t.permissions)
        if within:
            readings.append(
                Reading(
                    PROVEN,
                    "within_approval",
                    f"{', '.join(within)} {'was' if len(within) == 1 else 'were'} approved with {action!r}",
                )
            )
        elif all(t.permissions is not None for t in approval.tools):
            readings.append(
                Reading(
                    BROKEN,
                    "outside_approval",
                    f"no tool the approval of {chain.workflow!r} names was approved with {action!r}",
                )
            )
        else:
            readings.append(
                Reading(
                    UNPROVEN,
                    "approval_permissions_undeclared",
                    f"the approval of {chain.workflow!r} names tools whose approved contracts declare no permissions",
                )
            )
    readings.append(_gate(chain, inputs))
    return readings


def _gate(chain: Chain, inputs: Inputs) -> Reading:
    """The Action Gate decision the chain cites (an Achilles permit check)."""
    cited = chain.gate_outcome_id
    if not cited:
        return Reading(UNPROVEN, "no_gate_decision", "the chain cites no Action Gate decision for this action")
    outcome = inputs.outcomes.get(cited)
    if outcome is None:
        return Reading(UNPROVEN, "gate_decision_not_recorded", f"no outcome {cited} is recorded on this deployment")
    if outcome.workflow != chain.workflow:
        return Reading(
            UNPROVEN,
            "gate_decision_other_workflow",
            f"outcome {cited} is for {outcome.workflow!r}; this chain serves {chain.workflow!r}",
        )
    if outcome.evidence != _composition.EVIDENCE_AUTHORIZATION_CHECK:
        return Reading(
            UNPROVEN,
            "not_a_gate_decision",
            f"outcome {cited} is {outcome.evidence} evidence, not a signed Action Gate permit check that verifies now",
        )
    if outcome.status == _composition.HELD:
        return Reading(PROVEN, "gate_permit", f"the Action Gate authorized it at dispatch (outcome {cited})")
    if outcome.status in (_composition.NOT_DEMONSTRATED, _composition.VIOLATED):
        return Reading(
            BROKEN,
            "gate_refused",
            f"the Action Gate refused this workflow's action (outcome {cited}, {outcome.status}): the chain "
            "claims an action the gate did not let through",
        )
    return Reading(UNPROVEN, "gate_incomplete", f"the Action Gate decision {cited} is {outcome.status}")


def _last_hop_before(chain: Chain, index: int, relation: str) -> Hop | None:
    """The last hop of ``relation`` before hop ``index``."""
    for hop in reversed(chain.hops[:index]):
        if hop.relation == relation:
            return hop
    return None


def _same_tool(index: _Index, node: Node, effect: ObservedEffect) -> bool:
    """Whether the invokes hop's tool ``node`` is the tool ``effect`` observed: the same
    kind, and the same reference or two references that resolve to the same one
    component."""
    if node.kind != effect.tool_kind:
        return False
    if node.ref == effect.tool_identifier:
        return True
    named, _ = index.resolve(node)
    observed, _ = index.resolve(Node(effect.tool_kind, effect.tool_identifier))
    return named is not None and observed is not None and named.uuid == observed.uuid


def _produces(chain, i, source, target, inputs, index) -> list[Reading]:
    cited = chain.effect_outcome_id
    if not cited:
        return [
            Reading(
                UNPROVEN,
                "effect_not_observed",
                "nothing observed the effect: the chain cites no observed-effect outcome",
            )
        ]
    outcome = inputs.outcomes.get(cited)
    if outcome is None:
        return [Reading(UNPROVEN, "effect_outcome_not_recorded", f"no outcome {cited} is recorded on this deployment")]
    if outcome.workflow != chain.workflow:
        return [
            Reading(
                UNPROVEN,
                "effect_outcome_other_workflow",
                f"outcome {cited} is for {outcome.workflow!r}; this chain serves {chain.workflow!r}",
            )
        ]
    if outcome.evidence != _composition.EVIDENCE_OBSERVED_EFFECT:
        return [
            Reading(
                UNPROVEN,
                "not_an_observed_effect",
                f"outcome {cited} is {outcome.evidence} evidence; only an observed effect shows the effect happened",
            )
        ]
    effect = outcome.effect
    if effect is None:
        return [
            Reading(
                UNPROVEN,
                "effect_evidence_unread",
                f"outcome {cited} carries no evidence document matching its signed digest: nothing says which "
                "tool or dispatch it observed",
            )
        ]
    # THE BINDING. A signature says the observer saw AN effect; these say it is THIS
    # chain's: its tool, its dispatch, and no other chain's.
    readings: list[Reading] = []
    invokes = _last_hop_before(chain, i, INVOKES)
    if invokes is None:
        readings.append(
            Reading(
                UNPROVEN,
                "effect_tool_unnamed",
                f"the chain names no tool in an invokes hop; outcome {cited} observed {effect.tool_kind} "
                f"{effect.tool_identifier!r}",
            )
        )
    elif not _same_tool(index, invokes.target, effect):
        readings.append(
            Reading(
                UNPROVEN,
                "effect_other_tool",
                f"outcome {cited} observed {effect.tool_kind} {effect.tool_identifier!r}; the chain's invokes hop "
                f"names {invokes.target.kind} {invokes.target.ref!r}",
            )
        )
    performs = _last_hop_before(chain, i, PERFORMS)
    if performs is None:
        readings.append(
            Reading(
                UNPROVEN,
                "effect_action_unnamed",
                f"the chain names no action in a performs hop; outcome {cited} observed {effect.action!r}",
            )
        )
    elif performs.target.ref != effect.action:
        readings.append(
            Reading(
                UNPROVEN,
                "effect_other_action",
                f"outcome {cited} observed the action {effect.action!r}; the chain's performs hop names "
                f"{performs.target.ref!r}",
            )
        )
    if effect.gate_outcome_id != chain.gate_outcome_id:
        readings.append(
            Reading(
                UNPROVEN,
                "effect_other_dispatch",
                f"outcome {cited} was observed on the dispatch of gate decision {effect.gate_outcome_id}; this "
                f"chain cites {chain.gate_outcome_id or 'none'}",
            )
        )
    if inputs.effect_citations.get(cited, 0) > 1:
        readings.append(
            Reading(
                UNPROVEN,
                "effect_outcome_cited_twice",
                f"{inputs.effect_citations[cited]} chains in force cite outcome {cited}; one observation proves "
                "one chain",
            )
        )
    dispatch = effect.dispatch
    if dispatch is not None:
        # The dispatch instant bounds the effect's: not before the dispatch left, and
        # within the dispatch window after it.
        observed = effect.observed_at
        window = timedelta(seconds=DISPATCH_EFFECT_WINDOW_SECONDS)
        if observed is None or observed < dispatch.dispatched_at or observed - dispatch.dispatched_at > window:
            readings.append(
                Reading(
                    UNPROVEN,
                    "effect_outside_dispatch_window",
                    f"outcome {cited} observed the effect at {_when(observed)}; its dispatch left at "
                    f"{_when(dispatch.dispatched_at)}, and an effect is that dispatch's only within "
                    f"{DISPATCH_EFFECT_WINDOW_SECONDS} s after it",
                )
            )
    if readings:
        return readings
    if outcome.status == _composition.HELD:
        return [
            Reading(
                PROVEN,
                "observed_effect",
                f"the dispatch {effect.dispatch_id or '(unnamed)'} that carried the action out observed the "
                f"provider complete it (outcome {cited})",
            )
        ]
    if outcome.status == _composition.VIOLATED:
        return [
            Reading(
                BROKEN,
                "effect_violated",
                f"outcome {cited} says the effect was produced outside its authority",
            )
        ]
    return [Reading(UNPROVEN, "effect_not_established", f"the observed-effect outcome {cited} is {outcome.status}")]


def _effect_instant(chain: Chain, inputs: Inputs) -> datetime | None:
    """When the chain's effect happened, as far as a signature says: the instant of
    the observed effect it cites, read from the document its signed digest names. None
    when it cites none, or one that is not this workflow's, not an observed effect, or
    carries no document in force."""
    cited = chain.effect_outcome_id
    outcome = inputs.outcomes.get(cited) if cited else None
    if (
        outcome is None
        or outcome.workflow != chain.workflow
        or outcome.evidence != _composition.EVIDENCE_OBSERVED_EFFECT
        or outcome.effect is None
    ):
        return None
    return outcome.effect.observed_at


def _instant_unknown(chain: Chain) -> Reading:
    return Reading(
        UNPROVEN,
        "effect_instant_unknown",
        f"the chain cites no observed effect whose signed document says when the effect happened "
        f"({chain.effect_outcome_id or 'none cited'}), so nothing can be placed against it",
    )


def _when(instant: datetime | None) -> str:
    return instant.isoformat() if instant is not None else "never"


def _authenticated_as(chain, i, source, target, inputs, index) -> list[Reading]:
    hop = chain.hops[i]
    person, principal = hop.source.ref, hop.target.ref
    named = [a for a in inputs.authentications if a.person == person and a.principal == principal]
    if not named:
        return [
            Reading(
                UNPROVEN,
                "no_authentication_record",
                f"no signed authentication record in force says {person!r} signed in as {principal!r}",
            )
        ]
    # The sign-in the gate saw at dispatch, if it saw one: only that record proves it.
    dispatch, _ = _dispatch_state(chain, inputs)
    if dispatch is not None and dispatch.assertion_digest is not None:
        named = [a for a in named if a.assertion_digest == dispatch.assertion_digest]
        if not named:
            return [
                Reading(
                    UNPROVEN,
                    "authentication_not_dispatched",
                    f"the dispatch carried sign-in assertion {dispatch.assertion_digest}; no record in force of it "
                    f"says {person!r} signed in as {principal!r}",
                )
            ]
    instant = _effect_instant(chain, inputs)
    if instant is None:
        return [_instant_unknown(chain)]
    opens = instant - timedelta(seconds=AUTHENTICATION_WINDOW_SECONDS)
    in_window = [a for a in named if opens <= a.authenticated_at <= instant]
    live = [a for a in in_window if instant < a.expires_at]
    if live:
        a = max(live, key=lambda a: (a.authenticated_at, a.outcome_id))
        return [
            Reading(
                PROVEN,
                "authentication",
                f"{person!r} signed in as {principal!r} through {a.issuer or 'an identity provider'} "
                f"({a.protocol or 'protocol unnamed'}) at {_when(a.authenticated_at)}, inside the chain's window "
                f"[{_when(opens)}, {_when(instant)}], in a session open until {_when(a.expires_at)} "
                f"(record {a.outcome_id}, witnessed by {a.witness or 'unnamed'})",
            )
        ]
    if in_window:
        a = max(in_window, key=lambda a: (a.expires_at, a.outcome_id))
        return [
            Reading(
                UNPROVEN,
                "authentication_expired",
                f"the session {person!r} opened as {principal!r} at {_when(a.authenticated_at)} expired at "
                f"{_when(a.expires_at)}, before the effect at {_when(instant)}",
            )
        ]
    return [
        Reading(
            UNPROVEN,
            "authentication_out_of_window",
            f"{len(named)} sign-in(s) of {person!r} as {principal!r} on record, none inside the chain's window "
            f"[{_when(opens)}, {_when(instant)}]: at {', '.join(sorted(_when(a.authenticated_at) for a in named))}",
        )
    ]


def _names(index: _Index, node: Node, kind: str, ref: str) -> bool:
    """Whether ``node`` is the ``kind`` ``ref`` a record names: the same kind, and the
    same reference -- or, for a graph kind, two references that resolve to the same
    one component."""
    if node.kind != kind:
        return False
    if node.ref == ref:
        return True
    if kind not in GRAPH_KINDS:
        return False
    named, _ = index.resolve(node)
    recorded, _ = index.resolve(Node(kind, ref))
    return named is not None and recorded is not None and named.uuid == recorded.uuid


def _delegates_to(chain, i, source, target, inputs, index) -> list[Reading]:
    hop = chain.hops[i]
    named = [
        d
        for d in inputs.delegations
        if _names(index, hop.source, d.principal_kind, d.principal_ref) and _names(index, hop.target, AGENT, d.agent)
    ]
    who = f"{hop.source.kind} {hop.source.ref!r}"
    if not named:
        return [
            Reading(
                UNPROVEN,
                "no_delegation_record",
                f"no signed delegation record in force says {who} delegated to agent {hop.target.ref!r}",
            )
        ]
    # The grant the gate saw at dispatch, if it saw one: only that grant proves it.
    dispatch, _ = _dispatch_state(chain, inputs)
    if dispatch is not None and dispatch.grant_digest is not None:
        named = [d for d in named if d.grant_digest == dispatch.grant_digest]
        if not named:
            return [
                Reading(
                    UNPROVEN,
                    "delegation_not_dispatched",
                    f"the dispatch carried grant {dispatch.grant_digest}; no record in force of it says {who} "
                    f"delegated to agent {hop.target.ref!r}",
                )
            ]
    instant = _effect_instant(chain, inputs)
    if instant is None:
        return [_instant_unknown(chain)]
    actions = [h.target.ref for h in chain.hops[i + 1 :] if h.relation == PERFORMS]
    if not actions:
        return [
            Reading(
                UNPROVEN,
                "delegation_action_unnamed",
                f"the chain names no action after {who}'s delegation for its scope to cover",
            )
        ]
    grants: dict[str, list[Delegation]] = {}
    for d in named:
        grants.setdefault(d.grant_digest, []).append(d)
    failures: list[Reading] = []
    for digest in sorted(grants):
        records = grants[digest]
        grant = records[0]  # the digest binds every record of it to the same grant
        # REVOCATION IS AUTHORITY, read at the effect's instant: the earliest revocation
        # on record. Revoked after the effect, the effect was produced under a grant in
        # force and stays proven; revoked before (or at) it, it was not.
        revoked = min((r.revoked_at for r in records if r.revoked_at is not None), default=None)
        why: list[Reading] = []
        outside = [a for a in actions if a not in grant.actions]
        if outside:
            why.append(
                Reading(
                    UNPROVEN,
                    "delegation_out_of_scope",
                    f"grant {digest} delegated {sorted(grant.actions)}; the chain performs {outside}",
                )
            )
        if instant < grant.not_before:
            why.append(
                Reading(
                    UNPROVEN,
                    "delegation_out_of_window",
                    f"grant {digest} opens at {_when(grant.not_before)}, after the effect at {_when(instant)}",
                )
            )
        elif instant >= grant.not_after:
            why.append(
                Reading(
                    UNPROVEN,
                    "delegation_expired",
                    f"grant {digest} closed at {_when(grant.not_after)}, before the effect at {_when(instant)}",
                )
            )
        if revoked is not None and revoked <= instant:
            why.append(
                Reading(
                    UNPROVEN,
                    "delegation_revoked",
                    f"grant {digest} was revoked at {_when(revoked)}, before the effect at {_when(instant)}",
                )
            )
        if not why:
            after = f"; revoked at {_when(revoked)}, after the effect, which stands" if revoked is not None else ""
            return [
                Reading(
                    PROVEN,
                    "delegation",
                    f"{who} delegated agent {hop.target.ref!r} {sorted(grant.actions)} for "
                    f"[{_when(grant.not_before)}, {_when(grant.not_after)}), holding the effect at {_when(instant)} "
                    f"(grant {digest}, witnessed by {grant.witness or 'unnamed'}){after}",
                )
            ]
        failures.extend(why)
    # No grant proves it: every reason any grant fails for, each code once.
    seen: set[str] = set()
    return [r for r in failures if not (r.code in seen or seen.add(r.code))]


_relation_checks = {
    AUTHENTICATED_AS: _authenticated_as,
    DELEGATES_TO: _delegates_to,
    UNDER_POLICY: _under_policy,
    INVOKES: _invokes,
    THROUGH_IDENTITY: _through_identity,
    PERFORMS: _performs,
    PRODUCES: _produces,
}


def _in_grammar(hop: Hop) -> bool:
    spec = GRAMMAR.get(hop.relation)
    return spec is not None and hop.source.kind in spec[0] and hop.target.kind in spec[1]


def verify(chain: Chain, inputs: Inputs) -> ChainVerdict:
    """Every hop of ``chain``, read against ``inputs``. Pure; never raises on data.

    A hop in no relation the grammar in force defines -- a stored row written under
    a grammar since changed -- is unproven, read rather than refused: a stored
    chain is never dropped from the decision for being malformed. A relation in
    :data:`NO_RECORD_RELATIONS` is unproven whatever its checks would say."""
    index = _Index(inputs.graph)
    out = []
    for i, hop in enumerate(chain.hops):
        if not _in_grammar(hop):
            readings = [
                Reading(UNPROVEN, "not_in_grammar", f"{hop.relation!r} from {hop.source.kind} to {hop.target.kind}")
            ]
        else:
            source, source_readings = index.resolve(hop.source)
            target, target_readings = index.resolve(hop.target)
            check = _no_record if hop.relation in NO_RECORD_RELATIONS else _relation_checks.get(hop.relation)
            readings = [*source_readings, *target_readings]
            if check is not None:
                readings += check(chain, i, source, target, inputs, index)
        out.append(_hop_verdict(i, hop, readings))
    verdict = worst(h.verdict for h in out) if out else UNPROVEN
    return ChainVerdict(chain=chain, verdict=verdict, hops=tuple(out))


def in_force(records: Sequence[tuple[int, Chain]]) -> tuple[list[int], list[int]]:
    """Which recorded chains stand: the newest per ``(workflow, effect)``, by the
    order they were recorded in. Returns ``(standing, superseded)`` record keys.

    A newer chain for the same effect of the same workflow is a correction of the
    older one, and the older one is kept and published as superseded -- never
    deleted. The cost, owned: a chain with a broken hop is lifted by recording the
    chain that actually ran. Lifted to what that chain proves, and no further:
    every chain is verified against the record, so a newer chain claims nothing the
    graph, the approval and the signed outcomes do not bear out."""
    newest: dict[tuple[str, str], int] = {}
    for key, chain in records:
        group = (chain.workflow, chain.effect)
        if group not in newest or key > newest[group]:
            newest[group] = key
    standing = sorted(newest.values())
    kept = set(standing)
    return standing, sorted(k for k, _ in records if k not in kept)
