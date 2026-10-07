"""Which effects need an authority chain -- decided from data, never from whether
anyone recorded one.

:mod:`assurance.authority_chain` verifies the chains somebody recorded. Before this
module, an effect nobody recorded a chain for capped nothing: the decision of a
deployment with no chain was the decision it had before chains existed, so
recording a chain could only LOWER a decision -- an incentive not to record one.
The owner decided (7 Oct) that a missing chain reads unproven, and that which
effects need one is computed from data.

THE RULE
--------

An approved workflow covers the tools its approval binds
(:func:`assurance.tool_contract.approved_tools`, #132). Each such tool is one EFFECT
of the workflow -- ``(workflow, tool kind, tool identifier)`` -- and its CLASS is read
off the tool's contract in force, the registration row as it stands now
(:func:`assurance.tool_contract.contract_descriptor`):

    consequential  the declared ``effect_class`` is one of
                   :data:`CONSEQUENTIAL_EFFECT_CLASSES` (``write``, ``destructive``
                   -- the vocabulary the declarations use), OR the declared MCP
                   annotations say the tool is destructive
                   (:data:`DESTRUCTIVE_ANNOTATIONS` set to ``true``). An annotation
                   only ever RAISES a tool to consequential; nothing lowers one.
    read_only      the declared ``effect_class`` is one of
                   :data:`READ_ONLY_EFFECT_CLASSES` (``read``), and nothing else
                   declared says it is destructive.
    unknown        anything else: no effect class declared, a label outside the
                   vocabulary, or a tool no longer registered. NOT read as
                   read-only: an effect nobody classified is one nobody can say
                   needs no chain.

Conflicting declarations (two entries for one tool that disagree,
``{"conflicting_declarations": [...]}``) are each classified, and the tool takes the
worst of them (:data:`_CLASS_RANK`): ``read`` and ``destructive`` is consequential.

Each effect then has one STATUS:

    covered        consequential, and a chain IN FORCE for the same workflow names
                   the tool in an ``invokes`` hop. That chain's own verdict decides
                   from there, through the caps it already carries
                   (``authority_chain_broken`` / ``authority_chain_unproven``): a
                   chain whose every hop is proven lifts the effect.
    missing        consequential, and no chain in force names it. Unproven: the
                   decision caps at ``needs_more_evidence``
                   (``authority_chain_missing``) and names the effect, so it says
                   exactly which chain to record.
    unknown        the class is unknown. Unproven too, with its own cap
                   (``effect_class_unknown``) and reason, WHETHER OR NOT a chain
                   covers it: a chain proves who produced an effect, not what kind
                   of effect it is. The fix is to declare the tool's effect class --
                   which changes its contract, so the approval has to be bound to it
                   again (:mod:`assurance.tool_contract`).
    not_required   read-only: no chain is needed.

Deliberately PURE, as :mod:`assurance.authority_chain` is: no models, no ORM, no
clock. :mod:`assurance.authority_chain_records` loads the bindings, the
registrations and the chains in force, and calls :func:`effects`.

What it does not cover, stated: an effect produced through a tool NO approval binds
is not one of these -- an unapproved tool's effect is held by the shadow and
coverage readings, not here -- and an approved workflow that binds no tools has no
effect this rule can name.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass

from . import authority_chain as _chain
from . import graph_refs as _refs

# ------------------------------------------------------------------ the vocabulary

#: The declared effect classes that make a tool's effect consequential, spelled as
#: the declarations write them (lowercased by :mod:`assurance.assets`).
CONSEQUENTIAL_EFFECT_CLASSES: frozenset[str] = frozenset({"write", "destructive"})
#: The declared effect classes that need no chain.
READ_ONLY_EFFECT_CLASSES: frozenset[str] = frozenset({"read"})
#: The MCP annotations that, set to ``true``, make a tool consequential whatever its
#: effect class says. Raise-only: no annotation makes a tool read-only.
DESTRUCTIVE_ANNOTATIONS: frozenset[str] = frozenset({"destructiveHint"})

CONSEQUENTIAL = "consequential"
READ_ONLY = "read_only"
UNKNOWN = "unknown"

#: Every class an effect can have.
CLASSES: frozenset[str] = frozenset({CONSEQUENTIAL, READ_ONLY, UNKNOWN})
#: Worst last, for the worst of a tool's conflicting declarations. Total over
#: :data:`CLASSES`, asserted by test.
_CLASS_RANK: Mapping[str, int] = {READ_ONLY: 0, UNKNOWN: 1, CONSEQUENTIAL: 2}

COVERED = "covered"
MISSING = "missing"
NOT_REQUIRED = "not_required"

#: Every status an effect can have (:data:`UNKNOWN` is a class and a status).
STATUSES: frozenset[str] = frozenset({COVERED, MISSING, UNKNOWN, NOT_REQUIRED})
#: The statuses that read unproven: the decision cannot read ready past them.
UNPROVEN_STATUSES: frozenset[str] = frozenset({MISSING, UNKNOWN})

#: The document an effect's digest is taken over: the receipt names an effect by it,
#: never by the workflow's or the tool's name.
EFFECT_SCHEMA = "mythos.consequential-effect/v1"

#: What each code means, published beside it.
REASONS: Mapping[str, str] = {
    # why it is consequential
    "declared_write": "the tool's contract declares the effect class write",
    "declared_destructive": "the tool's contract declares the effect class destructive",
    "annotated_destructive": "the tool's declared MCP annotations say it is destructive",
    # why it needs no chain
    "declared_read": "the tool's contract declares the effect class read",
    # why its class is unknown
    "effect_class_undeclared": "the tool's contract declares no effect class, so nothing says whether its effect "
    "is consequential",
    "effect_class_unrecognised": "the tool's contract declares an effect class outside the vocabulary "
    "(read, write, destructive)",
    "tool_not_registered": "no registration of the tool is in the graph now, so nothing says what it does",
    # its status
    "chain_in_force": "an authority chain in force for this workflow names the tool; its verdict decides",
    "no_chain_in_force": "no authority chain in force for this workflow names the tool: record the chain the "
    "effect was produced through",
}


# ------------------------------------------------------------------- the inputs


@dataclass(frozen=True)
class ApprovedTool:
    """One tool an approved workflow's approval binds, with its contract IN FORCE:
    the registration's :func:`assurance.tool_contract.contract_descriptor`, or
    ``None`` when the tool is no longer registered."""

    workflow: str
    kind: str
    identifier: str
    contract: Mapping | None


@dataclass(frozen=True)
class Effect:
    """One effect of one approved workflow, through one tool: its class, its status,
    every code that says why (:data:`REASONS`), the declared effect class as written
    (``None`` when none is), and the keys of the chains in force that name it."""

    workflow: str
    kind: str
    identifier: str
    effect_class: object
    klass: str
    status: str
    reasons: tuple[str, ...]
    chains: tuple = ()

    @property
    def unproven(self) -> bool:
        return self.status in UNPROVEN_STATUSES

    def document(self, deployment_uuid: str) -> dict:
        """What the effect's digest is taken over: which deployment, which workflow,
        which tool. Its class and status are read, not part of what it IS."""
        return {
            "schema": EFFECT_SCHEMA,
            "deployment": deployment_uuid,
            "workflow": self.workflow,
            "tool_kind": self.kind,
            "tool_identifier": self.identifier,
        }


# -------------------------------------------------------------------- the rule


def _labels(value) -> list:
    """The declared values of one contract field: one, or every one of a conflict."""
    if isinstance(value, Mapping) and isinstance(value.get("conflicting_declarations"), list):
        return list(value["conflicting_declarations"])
    return [value]


def _class_of(label) -> tuple[str, str]:
    if label is None:
        return UNKNOWN, "effect_class_undeclared"
    if isinstance(label, str) and label in CONSEQUENTIAL_EFFECT_CLASSES:
        return CONSEQUENTIAL, f"declared_{label}"
    if isinstance(label, str) and label in READ_ONLY_EFFECT_CLASSES:
        return READ_ONLY, f"declared_{label}"
    return UNKNOWN, "effect_class_unrecognised"


def _worst(classes) -> str:
    return max(classes, key=lambda c: _CLASS_RANK[c])


def classify(contract: Mapping | None) -> tuple[str, tuple[str, ...]]:
    """``(class, codes)`` for a tool's contract in force. Pure; never raises on data.

    The class is the worst of every declared effect class (a conflict is each of its
    values), raised to consequential by a destructive annotation. The codes are the
    ones that decided it: for a consequential tool every code that makes it so, for
    an unknown one every reason it is unknown, for a read-only one its declaration."""
    if not isinstance(contract, Mapping):
        return UNKNOWN, ("tool_not_registered",)
    readings = [_class_of(label) for label in _labels(contract.get("effect_class"))]
    for declared in _labels(contract.get("annotations")):
        if isinstance(declared, Mapping) and any(declared.get(k) is True for k in DESTRUCTIVE_ANNOTATIONS):
            readings.append((CONSEQUENTIAL, "annotated_destructive"))
    klass = _worst(c for c, _ in readings)
    return klass, tuple(sorted({code for c, code in readings if c == klass}))


def _names(node: _chain.Node, kind: str, identifier: str, index) -> bool:
    """Whether ``node`` names the tool ``(kind, identifier)``: by its identifier, or
    by a reference that resolves to exactly that one registration -- the rule
    :func:`assurance.authority_chain.verify` resolves the same node by."""
    if node.kind != kind:
        return False
    if node.ref == identifier:
        return True
    by_identifier, by_name = index
    candidates, why = _refs.resolve_reference(node.ref, by_identifier, by_name, only_kinds=frozenset({kind}))
    return why is None and len(candidates) == 1 and getattr(candidates[0], "identifier", None) == identifier


def covering(chains: Sequence[tuple[object, _chain.Chain]], workflow: str, kind: str, identifier: str, index):
    """The keys of the chains in ``chains`` that name the tool for ``workflow``: the
    chain serves that workflow and one of its ``invokes`` hops reaches the tool."""
    return tuple(
        key
        for key, chain in chains
        if chain.workflow == workflow
        and any(h.relation == _chain.INVOKES and _names(h.target, kind, identifier, index) for h in chain.hops)
    )


def effects(
    tools: Sequence[ApprovedTool], chains: Sequence[tuple[object, _chain.Chain]] = (), components=()
) -> tuple[Effect, ...]:
    """Every effect of every approved workflow through every tool it binds, each with
    its class and status. ``chains``: the chains IN FORCE, ``(key, chain)``.
    ``components``: what a chain's tool node is resolved against (anything with
    ``kind``, ``identifier``, ``name``, ``metadata``). Ordered by workflow, kind and
    identifier. Pure."""
    index = _refs.reference_index(components)
    out = []
    for tool in sorted(tools, key=lambda t: (t.workflow, t.kind, t.identifier)):
        klass, codes = classify(tool.contract)
        named = covering(chains, tool.workflow, tool.kind, tool.identifier, index)
        if klass == READ_ONLY:
            status = NOT_REQUIRED
        elif klass == UNKNOWN:
            status = UNKNOWN
        elif named:
            status, codes = COVERED, (*codes, "chain_in_force")
        else:
            status, codes = MISSING, (*codes, "no_chain_in_force")
        declared = tool.contract.get("effect_class") if isinstance(tool.contract, Mapping) else None
        out.append(Effect(tool.workflow, tool.kind, tool.identifier, declared, klass, status, codes, named))
    return tuple(out)
