"""Which effects need an authority chain, exercised as the pure rule it is.

:mod:`assurance.consequential` decides, from the contract each approved tool
declares, whether the workflow's effect through it is consequential (it needs a
chain), read-only (it needs none) or of an unknown class (nobody can say, so it
reads unproven), and whether a chain in force names it. Every branch is pinned here
with hand-built inputs -- no database.

On master (0679a6c) the module does not exist, so every test here fails there.
"""

from __future__ import annotations

import pytest

from assurance import authority_chain as ac

WF = "refund-over-limit"


def _rule():
    from assurance import consequential

    return consequential


def contract(**fields):
    return {"contract_version": 1, "kind": "tool", "identifier": "refund@payments", **fields}


def tool(contract_in_force, *, workflow=WF, kind="tool", identifier="refund@payments"):
    return _rule().ApprovedTool(workflow=workflow, kind=kind, identifier=identifier, contract=contract_in_force)


def chain(*, workflow=WF, kind="tool", ref="refund@payments"):
    agent = ac.Node("agent", "support-agent")
    target = ac.Node(kind, ref)
    action = ac.Node("action", "payments:refund")
    return ac.Chain(
        workflow=workflow,
        hops=(
            ac.Hop(agent, ac.INVOKES, target),
            ac.Hop(target, ac.THROUGH_IDENTITY, ac.Node("service_account", "svc")),
            ac.Hop(ac.Node("service_account", "svc"), ac.PERFORMS, action),
            ac.Hop(action, ac.PRODUCES, ac.Node("effect", "refund-issued")),
        ),
    )


REFUND = ac.Component(uuid="t1", kind="tool", name="refund", identifier="refund@payments")


# ------------------------------------------------------------------ the class


@pytest.mark.parametrize(
    ("declared", "expected", "codes"),
    [
        ({"effect_class": "write"}, "consequential", ("declared_write",)),
        ({"effect_class": "destructive"}, "consequential", ("declared_destructive",)),
        ({"effect_class": "read"}, "read_only", ("declared_read",)),
        # Undeclared is UNKNOWN, never silently read-only.
        ({}, "unknown", ("effect_class_undeclared",)),
        ({"effect_class": None}, "unknown", ("effect_class_undeclared",)),
        # A label outside the vocabulary is not read as whichever one it resembles.
        ({"effect_class": "read-only"}, "unknown", ("effect_class_unrecognised",)),
        ({"effect_class": "mutating"}, "unknown", ("effect_class_unrecognised",)),
        ({"effect_class": ["write"]}, "unknown", ("effect_class_unrecognised",)),
        # Two declarations that disagree: the worst of them.
        ({"effect_class": {"conflicting_declarations": ["destructive", "read"]}}, "consequential",
         ("declared_destructive",)),
        ({"effect_class": {"conflicting_declarations": ["read", "sideways"]}}, "unknown",
         ("effect_class_unrecognised",)),
        # A destructive annotation raises a tool to consequential; nothing lowers one.
        ({"effect_class": "read", "annotations": {"destructiveHint": True}}, "consequential",
         ("annotated_destructive",)),
        ({"annotations": {"destructiveHint": True}}, "consequential", ("annotated_destructive",)),
        ({"effect_class": "read", "annotations": {"destructiveHint": False}}, "read_only", ("declared_read",)),
        ({"annotations": {"readOnlyHint": True}}, "unknown", ("effect_class_undeclared",)),
        ({"effect_class": "read", "annotations": {"conflicting_declarations": [{}, {"destructiveHint": True}]}},
         "consequential", ("annotated_destructive",)),
        # "true" the string is not true.
        ({"effect_class": "read", "annotations": {"destructiveHint": "true"}}, "read_only", ("declared_read",)),
    ],
)
def test_the_class_is_read_off_the_contract_the_tool_declares(declared, expected, codes):
    assert _rule().classify(contract(**declared)) == (expected, codes)


def test_a_tool_no_longer_registered_has_an_unknown_class():
    assert _rule().classify(None) == ("unknown", ("tool_not_registered",))
    assert _rule().classify("garbage") == ("unknown", ("tool_not_registered",))


# ------------------------------------------------------------------ the status


def test_a_consequential_effect_no_chain_names_is_missing_and_says_which_one():
    (effect,) = _rule().effects([tool(contract(effect_class="write"))])
    assert (effect.workflow, effect.kind, effect.identifier) == (WF, "tool", "refund@payments")
    assert (effect.klass, effect.status, effect.unproven) == ("consequential", "missing", True)
    assert effect.reasons == ("declared_write", "no_chain_in_force")
    assert effect.chains == ()


def test_a_chain_in_force_for_the_workflow_that_invokes_the_tool_covers_it():
    (effect,) = _rule().effects([tool(contract(effect_class="destructive"))], [("c1", chain())], [REFUND])
    assert (effect.status, effect.unproven, effect.chains) == ("covered", False, ("c1",))
    assert effect.reasons == ("declared_destructive", "chain_in_force")


def test_a_chain_names_the_tool_by_a_reference_that_resolves_to_exactly_it():
    (effect,) = _rule().effects([tool(contract(effect_class="write"))], [("c1", chain(ref="refund"))], [REFUND])
    assert effect.status == "covered"
    # Two registrations answer to the name: the chain does not say which, so it covers neither.
    twin = ac.Component(uuid="t2", kind="tool", name="refund", identifier="refund@ledger")
    (effect,) = _rule().effects([tool(contract(effect_class="write"))], [("c1", chain(ref="refund"))], [REFUND, twin])
    assert effect.status == "missing"


@pytest.mark.parametrize(
    "other",
    [
        {"workflow": "another-workflow"},  # the chain serves another workflow
        {"ref": "lookup@crm"},  # the chain goes through another tool
        {"kind": "mcp_server"},  # the same identifier, another kind of node
    ],
)
def test_a_chain_that_does_not_name_this_workflows_tool_does_not_cover_it(other):
    (effect,) = _rule().effects([tool(contract(effect_class="write"))], [("c1", chain(**other))], [REFUND])
    assert effect.status == "missing"


def test_a_chain_that_never_invokes_the_tool_does_not_cover_it():
    performs = ac.Chain(
        workflow=WF,
        hops=(
            ac.Hop(ac.Node("agent", "support-agent"), ac.PERFORMS, ac.Node("action", "refund@payments")),
            ac.Hop(ac.Node("action", "refund@payments"), ac.PRODUCES, ac.Node("effect", "refund@payments")),
        ),
    )
    (effect,) = _rule().effects([tool(contract(effect_class="write"))], [("c1", performs)], [REFUND])
    assert effect.status == "missing"


def test_a_read_only_effect_needs_no_chain():
    (effect,) = _rule().effects([tool(contract(effect_class="read"))])
    assert (effect.klass, effect.status, effect.unproven, effect.reasons) == (
        "read_only", "not_required", False, ("declared_read",),
    )


def test_an_unknown_class_reads_unproven_whether_or_not_a_chain_names_it():
    for chains in ([], [("c1", chain())]):
        (effect,) = _rule().effects([tool(contract())], chains, [REFUND])
        assert (effect.klass, effect.status, effect.unproven) == ("unknown", "unknown", True)
        assert effect.reasons == ("effect_class_undeclared",)
        assert effect.chains == tuple(k for k, _ in chains), "the chains that name it are still reported"


def test_every_effect_of_every_workflow_is_listed_in_a_stable_order():
    found = _rule().effects(
        [
            tool(contract(effect_class="read"), workflow="b", identifier="lookup@crm"),
            tool(contract(effect_class="write"), workflow="b"),
            tool(None, workflow="a"),
        ]
    )
    assert [(e.workflow, e.identifier, e.status) for e in found] == [
        ("a", "refund@payments", "unknown"),
        ("b", "lookup@crm", "not_required"),
        ("b", "refund@payments", "missing"),
    ]


# -------------------------------------------------------------- the vocabulary


def test_the_class_order_is_total_and_the_vocabulary_is_closed():
    rule = _rule()
    assert set(rule._CLASS_RANK) == rule.CLASSES
    assert rule.UNPROVEN_STATUSES == {rule.MISSING, rule.UNKNOWN} and rule.UNPROVEN_STATUSES < rule.STATUSES
    assert not rule.CONSEQUENTIAL_EFFECT_CLASSES & rule.READ_ONLY_EFFECT_CLASSES


def test_every_code_the_rule_emits_is_published_and_every_published_one_is_emitted():
    rule = _rule()
    contracts = [
        None, contract(), contract(effect_class="mutating"), contract(effect_class="read"),
        contract(effect_class="write"), contract(effect_class="destructive"),
        contract(effect_class="read", annotations={"destructiveHint": True}),
    ]
    emitted = set()
    for chains in ([], [("c1", chain())]):
        for found in rule.effects([tool(c) for c in contracts], chains, [REFUND]):
            emitted.update(found.reasons)
    assert emitted == set(rule.REASONS)
