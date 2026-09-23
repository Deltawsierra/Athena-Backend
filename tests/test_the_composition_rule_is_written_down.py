"""The aggregation rule, exercised case by case.

The roadmap's bar for this item is explicit: *"the aggregation rule is written
down and testable -- given a specific set of chain statuses, the rule produces
one deterministic deployment decision, and a reviewer can explain why from the
rule alone, not from an implementation detail."*

So the centre of this file is a table. Each row is a set of chain statuses and
the decision it must produce, and a reviewer can check any row against
`composition.py`'s stated floors without reading a line of the implementation.
Everything else here defends a specific way the rule could be got wrong.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from assurance import composition as comp
from assurance.composition import (
    HELD,
    INCOMPLETE,
    NOT_DEMONSTRATED,
    VIOLATED,
    ChainOutcome,
    UnknownChainStatus,
    compose,
)

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _outcomes(*pairs, at=None):
    return [
        ChainOutcome(workflow=name, status=status, observed_at=at)
        for name, status in pairs
    ]


# --- the table ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        # Nothing at all is no decision -- never READY.
        pytest.param([], None, id="nothing-is-no-decision"),
        # One chain, each status, straight from FLOORS.
        pytest.param([HELD], comp.READY, id="one-held"),
        pytest.param([NOT_DEMONSTRATED], comp.NEEDS_MORE_EVIDENCE, id="one-undemonstrated"),
        pytest.param([INCOMPLETE], comp.AUDIT_INCOMPLETE, id="one-incomplete"),
        pytest.param([VIOLATED], comp.NOT_RECOMMENDED, id="one-violated"),
        # Worst-of-N. Each row is the same set with one worse member added.
        pytest.param([HELD, HELD, HELD], comp.READY, id="all-held"),
        pytest.param([HELD, NOT_DEMONSTRATED], comp.NEEDS_MORE_EVIDENCE, id="held+undemonstrated"),
        pytest.param([HELD, INCOMPLETE], comp.AUDIT_INCOMPLETE, id="held+incomplete"),
        pytest.param([HELD, VIOLATED], comp.NOT_RECOMMENDED, id="held+violated"),
        pytest.param(
            [NOT_DEMONSTRATED, INCOMPLETE], comp.AUDIT_INCOMPLETE, id="incomplete-beats-undemonstrated"
        ),
        pytest.param([INCOMPLETE, VIOLATED], comp.NOT_RECOMMENDED, id="violated-beats-incomplete"),
        # The case the weighting argument is about: forty-nine good, one bad.
        pytest.param(
            [HELD] * 49 + [VIOLATED], comp.NOT_RECOMMENDED, id="forty-nine-held-one-violated"
        ),
    ],
)
def test_the_rule_produces_one_deterministic_decision(statuses, expected) -> None:
    """The table. Each row is checkable against the floors in `composition.py`."""
    outcomes = _outcomes(*[(f"workflow-{i}", s) for i, s in enumerate(statuses)])
    assert compose(outcomes).decision == expected


def test_the_rule_is_order_independent() -> None:
    """A decision that depended on the order rows came back from a database is a
    decision nobody can reproduce."""
    statuses = [HELD, VIOLATED, INCOMPLETE, NOT_DEMONSTRATED, HELD]
    forward = _outcomes(*[(f"w{i}", s) for i, s in enumerate(statuses)])
    backward = list(reversed(forward))
    assert compose(forward).decision == compose(backward).decision
    assert compose(forward).census == compose(backward).census


# --- worst-of-N rather than coverage-weighted --------------------------------


def test_one_violated_chain_in_fifty_is_not_averaged_away() -> None:
    """The decision the roadmap asks to be justified rather than assumed.

    A deployment where one workflow can produce an effect its authority does not
    cover is not 98% safe. It is a deployment with that way in.
    """
    outcomes = _outcomes(*[(f"w{i}", HELD) for i in range(49)]) + _outcomes(("w49", VIOLATED))
    result = compose(outcomes)
    assert result.decision == comp.NOT_RECOMMENDED
    assert result.census[HELD] == 49


def test_the_census_is_what_tells_one_bad_in_fifty_from_one_bad_in_one() -> None:
    """What the weighting argument was actually reaching for, answered without
    blurring the decision."""
    many = compose(
        _outcomes(*[(f"w{i}", HELD) for i in range(49)]) + _outcomes(("w49", VIOLATED))
    )
    one = compose(_outcomes(("only", VIOLATED)))
    assert many.decision == one.decision == comp.NOT_RECOMMENDED
    assert many.census != one.census
    assert many.census[HELD] == 49 and one.census[HELD] == 0


def test_the_census_reports_every_status_including_zeros() -> None:
    """A count that appears only when non-zero is a count nobody checks, and its
    absence reads exactly like a zero."""
    result = compose(_outcomes(("w", HELD)))
    assert set(result.census) == set(comp.CHAIN_STATUSES)
    assert result.census[VIOLATED] == 0


def test_every_workflow_that_set_the_floor_is_named() -> None:
    """Reporting one of three violated chains invites fixing it and expecting
    the decision to move."""
    result = compose(_outcomes(("a", VIOLATED), ("b", VIOLATED), ("c", HELD)))
    assert result.deciding == ("a", "b")


# --- a workflow with no chain is not_demonstrated, not absent ----------------


def test_one_held_chain_out_of_fifty_approved_workflows_is_not_ready() -> None:
    """The silent zero of this domain. "We checked one thing and it holds" is
    not "we checked everything and it holds"."""
    approved = [f"w{i}" for i in range(50)]
    result = compose(_outcomes(("w0", HELD)), expected_workflows=approved)
    assert result.decision == comp.NEEDS_MORE_EVIDENCE
    assert result.workflows_unreported == 49
    assert result.census[NOT_DEMONSTRATED] == 49


def test_the_same_chains_without_a_known_workflow_set_say_so(caplog) -> None:
    """Omitting the set is allowed and honest: the result is about the outcomes
    it was handed and claims nothing about the ones it was not."""
    result = compose(_outcomes(("w0", HELD)))
    assert result.decision == comp.READY
    assert result.workflows_expected is None
    assert result.workflows_unreported == 0


def test_every_approved_workflow_exercised_and_holding_is_ready() -> None:
    """The negative control for the rule above. If supplying the set made READY
    unreachable, the parameter would just be a way to never pass."""
    approved = ["a", "b", "c"]
    result = compose(
        _outcomes(("a", HELD), ("b", HELD), ("c", HELD)), expected_workflows=approved
    )
    assert result.decision == comp.READY
    assert result.workflows_unreported == 0
    assert result.all_held is True


def test_an_outcome_for_a_workflow_nobody_approved_still_counts() -> None:
    """A chain exercised against a workflow outside the approved set is a fact
    about this deployment. Dropping it because it was unexpected would discard
    the one finding most worth having."""
    result = compose(
        _outcomes(("approved", HELD), ("shadow-workflow", VIOLATED)),
        expected_workflows=["approved"],
    )
    assert result.decision == comp.NOT_RECOMMENDED
    assert "shadow-workflow" in result.deciding


# --- re-runs: the only case that needs arbitration ---------------------------


def test_a_newer_outcome_supersedes_an_older_one_for_the_same_workflow() -> None:
    """Re-running a workflow is what supersession means."""
    result = compose(
        [
            ChainOutcome("w", VIOLATED, observed_at=T0),
            ChainOutcome("w", HELD, observed_at=T0 + timedelta(hours=1)),
        ]
    )
    assert result.decision == comp.READY
    assert result.superseded == 1
    assert result.workflows_assessed == 1


def test_an_older_outcome_does_not_supersede_a_newer_one() -> None:
    """The same pair, delivered the other way round. Order must not matter."""
    result = compose(
        [
            ChainOutcome("w", HELD, observed_at=T0 + timedelta(hours=1)),
            ChainOutcome("w", VIOLATED, observed_at=T0),
        ]
    )
    assert result.decision == comp.READY


def test_a_tie_on_recency_keeps_the_worse_status() -> None:
    """Two outcomes at the same instant. Picking by iteration order would make
    the decision depend on database ordering; picking the better would let a
    passing re-run erase a violation it never contradicted."""
    for pair in (
        [ChainOutcome("w", VIOLATED, observed_at=T0), ChainOutcome("w", HELD, observed_at=T0)],
        [ChainOutcome("w", HELD, observed_at=T0), ChainOutcome("w", VIOLATED, observed_at=T0)],
    ):
        assert compose(pair).decision == comp.NOT_RECOMMENDED


@pytest.mark.parametrize(
    ("first", "second"),
    [
        pytest.param(
            ChainOutcome("w", VIOLATED, observed_at=T0),
            ChainOutcome("w", HELD, observed_at=None),
            id="dated-violation-first",
        ),
        pytest.param(
            ChainOutcome("w", HELD, observed_at=None),
            ChainOutcome("w", VIOLATED, observed_at=T0),
            id="undated-pass-first",
        ),
        # The two that matter most: the UNDATED one is the violation, and the
        # dated one would look newer to any rule that reads "no timestamp" as
        # "oldest". It is not oldest -- its age is unknown -- so it stays in
        # contention and the tie rule keeps the violation.
        pytest.param(
            ChainOutcome("w", VIOLATED, observed_at=None),
            ChainOutcome("w", HELD, observed_at=T0),
            id="undated-violation-first",
        ),
        pytest.param(
            ChainOutcome("w", HELD, observed_at=T0),
            ChainOutcome("w", VIOLATED, observed_at=None),
            id="dated-pass-first",
        ),
    ],
)
def test_an_outcome_with_no_timestamp_supersedes_nothing(first, second) -> None:
    """"We do not know when this was observed" is not evidence that it is
    current, so it cannot displace a dated outcome -- and it is not displaced
    either, so the tie rule decides and the worse survives.

    All four arrangements, because the rule has to hold in both directions: a
    rule that read an absent timestamp as "oldest" would give the same answer
    for two of these and quietly let a dated pass erase an undated violation in
    the other two.
    """
    assert compose([first, second]).decision == comp.NOT_RECOMMENDED


def test_a_dated_outcome_does_supersede_another_dated_one() -> None:
    """The control for the four above. Without it, "the worse always survives"
    would satisfy every one of them and recency would never be read at all."""
    result = compose(
        [
            ChainOutcome("w", VIOLATED, observed_at=T0),
            ChainOutcome("w", HELD, observed_at=T0 + timedelta(days=1)),
        ]
    )
    assert result.decision == comp.READY


def test_one_approved_workflow_named_twice_is_one_workflow() -> None:
    """`expected_workflows` is a SET of approved workflows, however the caller
    spells it. Counting a repeat twice would inflate the denominator and make a
    deployment look less covered than it is -- a manufactured gap, which is the
    silent zero's mirror image and just as much a lie."""
    result = compose(
        _outcomes(("a", HELD)), expected_workflows=["a", "b", "b", "b"]
    )

    assert result.workflows_expected == 2
    assert result.workflows_assessed == 2
    assert result.workflows_unreported == 1
    assert result.census[NOT_DEMONSTRATED] == 1


def test_outcomes_for_different_workflows_never_supersede_each_other() -> None:
    """Two chains saying different things are two statements about two different
    workflows, both true. There is no arbitration to do."""
    result = compose(
        [
            ChainOutcome("a", HELD, observed_at=T0 + timedelta(days=1)),
            ChainOutcome("b", VIOLATED, observed_at=T0),
        ]
    )
    assert result.superseded == 0
    assert result.workflows_assessed == 2
    assert result.decision == comp.NOT_RECOMMENDED


# --- refusing what it does not understand ------------------------------------


@pytest.mark.parametrize("status", ["passed", "fail", "", "HELD", "unknown", "ok"])
def test_a_status_this_module_does_not_define_is_refused(status) -> None:
    """Not defaulted. Defaulting to `violated` turns a typo into a permanent
    NOT_RECOMMENDED nobody can explain; defaulting to `held` reads an
    unrecognised word as a pass."""
    with pytest.raises(UnknownChainStatus):
        ChainOutcome(workflow="w", status=status)


def test_an_outcome_must_name_its_workflow() -> None:
    """A chain outcome that names no workflow cannot be compared with anything,
    so it would silently form its own group of one."""
    with pytest.raises(ValueError, match="workflow"):
        ChainOutcome(workflow="", status=HELD)


def test_demonstrated_is_membership_not_the_absence_of_violated() -> None:
    """Three of the four statuses are not-held for three different reasons, and
    a reader that only excludes the obvious one treats an unexercised chain as a
    passing one."""
    assert ChainOutcome("w", HELD).demonstrated is True
    for status in (VIOLATED, NOT_DEMONSTRATED, INCOMPLETE):
        assert ChainOutcome("w", status).demonstrated is False


# --- the rule must not drift from the decision model it feeds ----------------


def test_the_readiness_order_matches_the_one_decisions_are_made_with() -> None:
    """`composition.py` restates the order so it stays importable without
    Django. A restatement that drifted would make this signal disagree with the
    module that consumes it, and the disagreement would be invisible.

    `paused` is left out on purpose: it is the operator failsafe, and no set of
    chain outcomes can reach it. Both halves are asserted -- that it is the ONLY
    omission and that it is the worst state -- because a filter that merely
    drops a name would go on passing if a second state were added and missed.
    """
    from assurance.decision import _READINESS_ORDER

    full = tuple(str(state) for state in _READINESS_ORDER)

    assert set(full) - set(comp.READINESS_ORDER) == {"paused"}, (
        "composition omits a decision state other than the operator failsafe"
    )
    assert full[-1] == "paused", "paused is no longer the worst state"
    assert comp.READINESS_ORDER == full[:-1]


def test_every_decision_string_is_one_the_model_defines() -> None:
    """A floor spelled slightly wrong would be stored and rendered as a state
    that does not exist."""
    from assurance.models import Deployment

    valid = {choice.value for choice in Deployment.Decision}
    assert set(comp.READINESS_ORDER) <= valid
    assert set(comp.FLOORS.values()) <= valid


def test_every_status_has_a_floor_or_is_deliberately_held() -> None:
    """A status added later without a floor would silently contribute nothing,
    which is the same as declaring it harmless."""
    assert set(comp.FLOORS) | comp.DEMONSTRATED == comp.CHAIN_STATUSES


# --- the explanation must come from the same values as the decision ----------


def test_the_explanation_names_the_decision_and_what_set_it() -> None:
    """The bar says a reviewer explains the decision from the rule alone. That
    is only true if the sentence is generated from what the decision was
    computed from."""
    result = compose(_outcomes(("billing-export", VIOLATED), ("support-lookup", HELD)))
    text = comp.explain(result)
    assert comp.NOT_RECOMMENDED in text
    assert "billing-export" in text
    assert "1 violated" in text


def test_the_explanation_of_nothing_does_not_claim_a_decision() -> None:
    assert "places the deployment nowhere" in comp.explain(compose([]))


def test_the_explanation_says_how_much_was_never_exercised() -> None:
    """The number that turns "one chain holds" into something a reader can size."""
    result = compose(_outcomes(("a", HELD)), expected_workflows=["a", "b", "c"])
    assert "never exercised" in comp.explain(result)
    assert "1 of 3" in comp.explain(result) or "3 approved" in comp.explain(result)
