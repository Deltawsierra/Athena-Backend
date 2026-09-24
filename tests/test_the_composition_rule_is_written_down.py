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

from datetime import UTC, datetime, timedelta, tzinfo
from itertools import permutations

import pytest

from assurance import composition as comp
from assurance.composition import (
    CHAIN_STATUSES,
    HELD,
    INCOMPLETE,
    NOT_DEMONSTRATED,
    VIOLATED,
    ChainOutcome,
    UnknownChainStatus,
    compose,
)

T0 = datetime(2026, 1, 1, tzinfo=UTC)


def _signature(result):
    """Every value a caller can read, including the sentence.

    Order-independence has to be asserted over the whole of what is reported.
    Reading only `decision` and `census` left six fields and `explain()` free to
    depend on the arrival order, and one of them did.
    """
    return (
        result.decision,
        tuple(sorted(result.census.items())),
        result.deciding,
        result.workflows_assessed,
        result.workflows_expected,
        result.workflows_unreported,
        result.workflows_unapproved,
        result.superseded,
        result.all_held,
        tuple(sorted(result.basis_census.items())),
        result.unexercised,
        result.held_floored,
        comp.explain(result),
    )


def _outcomes(*pairs, at=None, basis=comp.BASIS_UNKNOWN):
    return [
        ChainOutcome(workflow=name, status=status, observed_at=at, basis=basis)
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
    decision nobody can reproduce.

    EVERY permutation, and every outcome names the SAME workflow. The version of
    this test that shipped first used five DISTINCT workflows, which meant it
    never entered the only code path that can be order-dependent -- with one
    outcome per workflow the decision is a max over floors and the census is a
    bag of counts, both order-independent whatever `_surviving` does. It
    survived `_surviving` being replaced by "the last row wins" and by "the
    first row wins", and it passed against the live defect below. A test that
    names a property and cannot fail on it is worse than no test: it is a
    claim on the record that nobody checked.
    """
    history = [
        ChainOutcome("w", VIOLATED, observed_at=None),
        ChainOutcome("w", VIOLATED, observed_at=T0),
        ChainOutcome("w", HELD, observed_at=T0 + timedelta(days=1)),
        ChainOutcome("w", INCOMPLETE, observed_at=T0 + timedelta(days=1)),
        ChainOutcome("w", NOT_DEMONSTRATED, observed_at=T0 - timedelta(days=1)),
    ]
    answers = {_signature(compose(list(order))) for order in permutations(history)}
    assert len(answers) == 1, f"the answer depends on the arrival order: {answers}"


def test_every_reported_field_is_order_independent_not_only_the_decision() -> None:
    """The signature above is the WHOLE composition, and this is why.

    It was `(decision, census)`, and with that signature `deciding` losing its
    `sorted()` -- arrival-order dependence in a reported field, the exact defect
    class this branch exists to fix -- passed the entire suite. A property test
    that reads two of eight fields is a property test for two of eight fields.
    """
    history = [
        ChainOutcome("zebra", VIOLATED, observed_at=T0),
        ChainOutcome("alpha", VIOLATED, observed_at=T0),
        ChainOutcome("alpha", INCOMPLETE, observed_at=T0 + timedelta(days=1)),
        ChainOutcome("middle", HELD, observed_at=None),
    ]
    answers = {
        _signature(compose(list(order), expected_workflows=["alpha", "zebra", "unrun"]))
        for order in permutations(history)
    }
    assert len(answers) == 1, f"a reported field depends on the arrival order: {answers}"


def test_two_recorded_violations_do_not_compose_into_ready() -> None:
    """The defect an adversarial review caught before this merged.

    `_surviving` was a fold over a single running incumbent, carrying the
    winner's own timestamp forward. An undated outcome -- which this module
    promises supersedes nothing and is superseded by nothing -- was evicted by
    proxy: the same-status dated duplicate won the tie, became the incumbent,
    and was then legitimately superseded by something newer, taking the undated
    violation's verdict with it.

    One arrival order out of six answered `ready`, with `census["violated"] == 0`
    and `explain()` saying "Every chain held", for a workflow with TWO recorded
    violations. Written as the adversary reproduced it.
    """
    history = [
        ChainOutcome("billing-export", VIOLATED, observed_at=None),
        ChainOutcome("billing-export", VIOLATED, observed_at=T0),
        ChainOutcome("billing-export", HELD, observed_at=T0 + timedelta(days=1)),
    ]
    for order in permutations(history):
        result = compose(list(order), expected_workflows=["billing-export"])
        assert result.decision == comp.NOT_RECOMMENDED, [o.status for o in order]
        assert result.census[VIOLATED] == 1
        assert "held" not in comp.explain(result).lower().split(",")[0]


def test_a_superseded_violation_is_not_manufactured_back() -> None:
    """The same defect's mirror, and the reason the fix is not "keep the worst".

    An undated HELD alongside a dated HELD that genuinely supersedes a dated
    VIOLATED must stay `ready`. A rule that simply kept the worst status it ever
    saw would report a violation the history says was superseded -- a
    manufactured fact, which this module treats as exactly as bad as a silent
    zero.
    """
    history = [
        ChainOutcome("w", HELD, observed_at=None),
        ChainOutcome("w", HELD, observed_at=T0 + timedelta(days=1)),
        ChainOutcome("w", VIOLATED, observed_at=T0),
    ]
    for order in permutations(history):
        assert compose(list(order)).decision == comp.READY, [o.status for o in order]


def test_the_four_statuses_have_four_distinct_floors() -> None:
    """`_worse_status` is only a total order if no two statuses tie on rank.

    If two did, the worse of them would depend on which was handed in first,
    and every order-independence claim above would be true only by accident.
    """
    ranks = {status: comp._RANK[comp.FLOORS.get(status, comp.READY)] for status in CHAIN_STATUSES}
    assert len(set(ranks.values())) == len(CHAIN_STATUSES), ranks


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
        _outcomes(("a", HELD), ("b", HELD), ("c", HELD), basis=comp.BASIS_DEMONSTRATED),
        expected_workflows=approved,
    )
    assert result.decision == comp.READY
    assert result.workflows_unreported == 0
    assert result.all_held is True


@pytest.mark.parametrize("basis", sorted(comp.UNEXERCISED_BASES))
def test_every_approved_workflow_held_but_not_exercised_is_not_ready(basis) -> None:
    """The same approved set, every chain held, and no run behind any of them.
    "Exercised" is what READY asks for; a held nobody demonstrated floors exactly
    as an approved workflow that never reported, and the explanation says so."""
    approved = ["a", "b", "c"]
    result = compose(
        _outcomes(("a", HELD), ("b", HELD), ("c", HELD), basis=basis),
        expected_workflows=approved,
    )
    assert result.decision == comp.NEEDS_MORE_EVIDENCE
    assert result.deciding == ("a", "b", "c")
    assert result.workflows_unexercised == 3
    assert "counts as not_demonstrated" in comp.explain(result)

    # Demonstrating two of the three leaves the third deciding.
    mixed = compose(
        _outcomes(("a", HELD), ("b", HELD), basis=comp.BASIS_DEMONSTRATED)
        + _outcomes(("c", HELD), basis=basis),
        expected_workflows=approved,
    )
    assert mixed.decision == comp.NEEDS_MORE_EVIDENCE
    assert mixed.deciding == ("c",)

    # No approved list: nothing to count it against, and no floor.
    assert compose(_outcomes(("a", HELD), basis=basis)).decision == comp.READY


def test_an_asserted_verdict_cannot_supersede_a_demonstrated_one() -> None:
    """A later ATTESTED held -- however late; 2099 is as late as any -- does not
    displace an earlier DEMONSTRATED violated. Evidence may outrank an assertion,
    not the reverse. And a later demonstrated verdict still supersedes both."""
    from datetime import datetime, timezone as tz

    early = datetime(2026, 1, 1, tzinfo=tz.utc)
    late = datetime(2099, 1, 1, tzinfo=tz.utc)
    demonstrated = ChainOutcome(workflow="w", status=VIOLATED, observed_at=early, basis=comp.BASIS_DEMONSTRATED)
    asserted = ChainOutcome(workflow="w", status=HELD, observed_at=late, basis=comp.BASIS_ATTESTED)
    for order in ([demonstrated, asserted], [asserted, demonstrated]):
        result = compose(order)
        assert result.decision == comp.NOT_RECOMMENDED
        assert result.census[VIOLATED] == 1
        assert result.superseded == 0

    rerun = ChainOutcome(
        workflow="w", status=HELD, observed_at=datetime(2026, 2, 1, tzinfo=tz.utc), basis=comp.BASIS_DEMONSTRATED
    )
    result = compose([demonstrated, asserted, rerun])
    assert result.census[VIOLATED] == 0
    assert result.superseded == 1, "the demonstrated re-run displaces the violation; the assertion stands beside it"

    # The other direction is unchanged: a later demonstrated verdict displaces an assertion.
    earlier_assertion = ChainOutcome(workflow="w", status=VIOLATED, observed_at=early, basis=comp.BASIS_ATTESTED)
    later_run = ChainOutcome(workflow="w", status=HELD, observed_at=late, basis=comp.BASIS_DEMONSTRATED)
    result = compose([earlier_assertion, later_run])
    assert result.census[VIOLATED] == 0
    assert result.superseded == 1


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
    sentence = comp.explain(result)

    # Every number, read back. The version of this test that shipped first
    # asserted `"never exercised" in text` -- a static literal in the f-string,
    # which can never be absent -- and `"1 of 3" in text or "3 approved" in
    # text`, where the second disjunct is present unconditionally. It could not
    # fail on the quantity it is named after, and a mutation replacing
    # `{workflows_unreported}` with `0` printed "0 of them never exercised
    # (... 49 not_demonstrated ...)" with the whole suite green.
    assert "3 workflow(s) against 3 approved" in sentence, sentence
    assert "2 of them never exercised" in sentence, sentence


def test_the_explanation_counts_a_large_gap_correctly() -> None:
    """The self-contradicting sentence, as its own case.

    Fifty approved workflows and one exercised is the scenario the module's own
    docstring argues about, and it is where a wrong count is least likely to be
    noticed by eye.
    """
    approved = [f"w{i}" for i in range(50)]
    sentence = comp.explain(compose(_outcomes(("w1", HELD)), expected_workflows=approved))

    assert "50 workflow(s) against 50 approved" in sentence, sentence
    assert "49 of them never exercised" in sentence, sentence
    assert "49 not_demonstrated" in sentence, sentence


def test_the_explanation_counts_what_it_has_when_there_is_no_approved_list() -> None:
    """The other branch of the scope sentence, which nothing read at all."""
    sentence = comp.explain(compose(_outcomes(("a", HELD), ("b", VIOLATED))))

    assert "2 workflow(s), with no approved list" in sentence, sentence


# --- what the module will not let itself be asked -----------------------------


def test_a_naive_timestamp_is_refused_where_the_workflow_can_still_be_named() -> None:
    """A naive and an aware datetime cannot be compared at all.

    Left to `_surviving`, one legacy row took a whole deployment's composition
    down with a `TypeError` raised three frames from anything that names a
    workflow. Refused at construction, where the refusal can say which workflow
    and why -- the same reason an unknown status raises rather than defaults.
    """
    with pytest.raises(ValueError) as refusal:
        # DTZ001 is right about production code and is the subject here: a naive
        # datetime is exactly the input under test.
        ChainOutcome("billing-export", HELD, observed_at=datetime(2026, 1, 1))  # noqa: DTZ001

    assert "billing-export" in str(refusal.value)
    assert "naive" in str(refusal.value)


def test_a_workflow_is_named_by_a_string() -> None:
    """Truthiness was the whole check, so `1` and `True` were workflow names.

    Two workflows named by values of different types live happily in a dict and
    blow up the moment `deciding` is sorted -- a `TypeError` about `<` arriving
    from a module whose subject is assurance.
    """
    for not_a_name in (1, True, ("tuple",), 3.0):
        with pytest.raises(TypeError):
            ChainOutcome(not_a_name, HELD)  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        ChainOutcome("", HELD)


def test_an_exhausted_iterable_cannot_invent_a_denominator() -> None:
    """`expected_workflows` is read twice, and a generator was empty the second time.

    The result claimed `workflows_expected == 0` while three workflows had just
    been counted against it, and `explain()` said "3 of 0 approved workflow(s)".
    A confident wrong number is the manufactured half of what this module
    refuses; it is materialised once now.
    """
    result = compose(_outcomes(("a", HELD)), expected_workflows=(w for w in ["a", "b", "c"]))

    assert result.workflows_expected == 3
    assert result.workflows_unreported == 2
    assert "3 approved" in comp.explain(result)


# --- what the numbers beside the decision have to mean -------------------------


def test_nothing_assessed_is_not_everything_held() -> None:
    """`all_held` over an empty composition is the silent zero in one property.

    `census[HELD] == workflows_assessed` is `0 == 0` for a composition that
    assessed nothing at all, so without its guard "we looked at nothing" reads
    as "every workflow held".
    """
    assert compose([]).all_held is False
    assert compose(_outcomes(("a", HELD))).all_held is True
    assert compose(_outcomes(("a", HELD), ("b", VIOLATED))).all_held is False


def test_a_tie_on_recency_is_not_a_supersession() -> None:
    """`superseded` counts what a re-run displaced, and a tie displaced nothing.

    It used to increment for every duplicate, including the pairs where
    `_surviving` explicitly establishes that neither outcome supersedes the
    other -- reporting a re-run that never happened.
    """
    undated_beside_dated = compose(
        [
            ChainOutcome("w", VIOLATED, observed_at=None),
            ChainOutcome("w", HELD, observed_at=T0),
        ]
    )
    assert undated_beside_dated.superseded == 0

    same_instant = compose(
        [
            ChainOutcome("w", VIOLATED, observed_at=T0),
            ChainOutcome("w", HELD, observed_at=T0),
        ]
    )
    assert same_instant.superseded == 0

    genuinely_newer = compose(
        [
            ChainOutcome("w", VIOLATED, observed_at=T0),
            ChainOutcome("w", HELD, observed_at=T0 + timedelta(days=1)),
        ]
    )
    assert genuinely_newer.superseded == 1


def test_a_workflow_nobody_approved_is_counted_and_named() -> None:
    """An outcome for an unapproved workflow is a finding, not a rounding error.

    A chain exercising a workflow that is not on the approved list is exactly
    what this platform exists to notice. It also has to be counted for the scope
    sentence to be checkable: without it the explanation read "2 of 1 approved
    workflow(s)", which is not something a reviewer can check a rule against.
    """
    result = compose(
        _outcomes(("approved", HELD), ("shadow", VIOLATED)),
        expected_workflows=["approved"],
    )

    assert result.workflows_assessed == 2
    assert result.workflows_expected == 1
    assert result.workflows_unapproved == 1
    assert result.decision == comp.NOT_RECOMMENDED
    assert "shadow" in result.deciding

    sentence = comp.explain(result)
    assert "2 of 1" not in sentence
    assert "not on the approved list" in sentence


def test_the_explanation_keeps_the_zeros_the_census_keeps() -> None:
    """`Composition` argues that a count appearing only when non-zero is a count
    nobody checks. The sentence a human actually reads used to drop them."""
    sentence = comp.explain(compose(_outcomes(("a", HELD), ("b", HELD))))

    assert "0 violated" in sentence
    assert "0 incomplete" in sentence
    assert "0 not_demonstrated" in sentence


# --- only a verdict supersedes ------------------------------------------------


@pytest.mark.parametrize("later", [INCOMPLETE, NOT_DEMONSTRATED], ids=["a gap", "thin evidence"])
def test_a_later_non_observation_does_not_erase_a_recorded_violation(later) -> None:
    """A scan that could not look is not news that the violation went away.

    It used to supersede: a violation on Jan 1 and a Jan 5 run that could not
    finish composed to `audit_incomplete` with `census["violated"] == 0`. An
    operator reading `0 violated` for a workflow this platform recorded
    violating would call that wrong, and the module's own definitions agree --
    `violated` is "A fact, not a doubt", the other two are the absence of one.
    It is also the same argument the module already makes about an undated
    outcome, on the other axis: what is not known cannot displace what is.
    """
    result = compose(
        [
            ChainOutcome("billing-export", VIOLATED, observed_at=T0),
            ChainOutcome("billing-export", later, observed_at=T0 + timedelta(days=4)),
        ],
        expected_workflows=["billing-export"],
    )

    assert result.decision == comp.NOT_RECOMMENDED
    assert result.census[VIOLATED] == 1
    assert result.superseded == 0, "nothing was displaced, so nothing should be counted as such"


def test_a_later_verdict_does_clear_a_violation() -> None:
    """The control, and the reason this is not just "the worst status wins".

    A re-run that actually exercised the chain and found it holding supersedes,
    exactly as before. Without this the rule above could be satisfied by a
    module that had simply stopped superseding anything.
    """
    cleared = compose(
        [
            ChainOutcome("billing-export", VIOLATED, observed_at=T0),
            ChainOutcome("billing-export", HELD, observed_at=T0 + timedelta(days=4)),
        ]
    )
    assert cleared.decision == comp.READY
    assert cleared.superseded == 1

    # And a verdict supersedes everything older, gaps included.
    through_a_gap = compose(
        [
            ChainOutcome("billing-export", VIOLATED, observed_at=T0),
            ChainOutcome("billing-export", INCOMPLETE, observed_at=T0 + timedelta(days=4)),
            ChainOutcome("billing-export", HELD, observed_at=T0 + timedelta(days=9)),
        ]
    )
    assert through_a_gap.decision == comp.READY
    assert through_a_gap.superseded == 2


def test_a_later_violation_supersedes_an_earlier_pass() -> None:
    """The rule is about verdicts, not about good news.

    A `held` on Jan 1 and a `violated` on Jan 10 is one workflow that has since
    been found violating, not two standing facts. Without this, narrowing
    `VERDICTS` to `{held}` alone -- so that only good news could supersede --
    reaches the same decision by a different route and reports `superseded: 0`
    for a re-run that plainly displaced something.
    """
    result = compose(
        [
            ChainOutcome("billing-export", HELD, observed_at=T0),
            ChainOutcome("billing-export", VIOLATED, observed_at=T0 + timedelta(days=9)),
        ]
    )

    assert result.decision == comp.NOT_RECOMMENDED
    assert result.census[HELD] == 0
    assert result.superseded == 1


def test_verdicts_are_the_two_statuses_that_say_whether_the_chain_holds() -> None:
    """Membership, stated once, so the rule above cannot drift from its reason."""
    assert comp.VERDICTS == {HELD, VIOLATED}
    assert comp.VERDICTS < CHAIN_STATUSES


def test_a_re_run_is_counted_for_every_workflow_that_had_one() -> None:
    """`superseded` is a total across workflows, and it was only ever tested
    with one. A `+=` written as `=` counted the last workflow alone and passed
    the whole suite."""
    result = compose(
        [
            ChainOutcome("a", VIOLATED, observed_at=T0),
            ChainOutcome("a", HELD, observed_at=T0 + timedelta(days=1)),
            ChainOutcome("b", VIOLATED, observed_at=T0),
            ChainOutcome("b", HELD, observed_at=T0 + timedelta(days=1)),
        ]
    )

    assert result.superseded == 2
    assert result.workflows_assessed == 2


# --- an instant, and an approved list, are checked like a name ----------------


def test_a_timestamp_must_be_a_datetime() -> None:
    """Anything with a `.tzinfo` attribute used to pass.

    An aware `datetime.time` was accepted and then raised `TypeError: '>' not
    supported between datetime.datetime and datetime.time` from inside
    `_surviving`; a `str`, an `int` and a `date` were refused only by accident,
    with an `AttributeError` naming no workflow at all.
    """
    for not_an_instant in (datetime(2026, 1, 1, tzinfo=UTC).time(), "2026-01-01", 0, 1.5):
        with pytest.raises(TypeError) as refusal:
            ChainOutcome("billing-export", HELD, observed_at=not_an_instant)  # type: ignore[arg-type]
        assert "billing-export" in str(refusal.value)


def test_a_tzinfo_that_offers_no_offset_is_still_naive() -> None:
    """`tzinfo is None` is not what aware means.

    A tzinfo whose `utcoffset()` returns `None` leaves `.tzinfo` set and the
    datetime NAIVE in Python's own model. The guard that used to be here
    accepted it, and the `TypeError: can't compare offset-naive and
    offset-aware datetimes` still arrived from `_surviving` -- with a guard
    sitting in front of it claiming otherwise, which is worse than no guard,
    because the next reader believes it.
    """

    class NoOffset(tzinfo):
        def utcoffset(self, moment):
            return None

        def tzname(self, moment):
            return "no-offset"

        def dst(self, moment):
            return None

    looks_aware = datetime(2026, 1, 1, tzinfo=NoOffset())
    assert looks_aware.tzinfo is not None
    assert looks_aware.utcoffset() is None

    with pytest.raises(ValueError) as refusal:
        ChainOutcome("billing-export", HELD, observed_at=looks_aware)

    assert "billing-export" in str(refusal.value)
    assert "naive" in str(refusal.value)


def test_one_workflow_name_is_not_an_approved_list() -> None:
    """`str` satisfies `Sequence[str]`, so no type checker objects.

    Iterating it shredded one name into seven approved workflows: a wrong
    denominator, a wrong census, `needs_more_evidence` where the truth was
    `ready`, and a sentence naming workflows `c, e, h, k, o, t, u`. Same failure
    mode as the exhausted generator, through a door the `tuple()` fix did not
    close.
    """
    with pytest.raises(TypeError) as refusal:
        compose(_outcomes(("checkout", HELD)), expected_workflows="checkout")

    assert "one name" in str(refusal.value)


def test_an_approved_workflow_is_named_by_a_string() -> None:
    """The same `sorted()` TypeError `ChainOutcome` now refuses, one door over.

    An unreported approved workflow becomes a real entry, so a non-string name
    reaches `tuple(sorted(deciding))` and raises from a module whose subject is
    assurance. Closing one door and leaving the other open is a guard that only
    looks like one.
    """
    for bad in ([1, "a"], [None], [("tuple",)]):
        with pytest.raises(TypeError):
            compose([], expected_workflows=bad)  # type: ignore[arg-type]

    with pytest.raises(ValueError):
        compose([], expected_workflows=["a", ""])


# --- which basis stands, and when the held clause is said ----------------------


def test_the_basis_rank_is_total_over_the_bases() -> None:
    """Every basis has a rank and no two share one, so a tie between survivors
    reporting one status never falls to arrival order."""
    assert set(comp._BASIS_RANK) == comp.CHAIN_BASES
    assert len(set(comp._BASIS_RANK.values())) == len(comp.CHAIN_BASES)
    assert comp._BASIS_RANK[comp.BASIS_DEMONSTRATED] < comp._BASIS_RANK[comp.BASIS_ATTESTED]
    assert comp._BASIS_RANK[comp.BASIS_ATTESTED] < comp._BASIS_RANK[comp.BASIS_UNKNOWN]


@pytest.mark.parametrize(
    ("bases", "stands"),
    [
        pytest.param((comp.BASIS_ATTESTED, comp.BASIS_UNKNOWN), comp.BASIS_ATTESTED, id="attested-over-unknown"),
        pytest.param((comp.BASIS_DEMONSTRATED, comp.BASIS_UNKNOWN), comp.BASIS_DEMONSTRATED, id="demonstrated-over-unknown"),
        pytest.param(
            (comp.BASIS_UNKNOWN, comp.BASIS_ATTESTED, comp.BASIS_DEMONSTRATED),
            comp.BASIS_DEMONSTRATED,
            id="demonstrated-over-both",
        ),
    ],
)
def test_a_tie_between_bases_goes_to_the_strongest_in_any_order(bases, stands) -> None:
    """Survivors at one instant saying one thing: the strongest basis stands,
    whichever arrived first. Between attested and unknown this used to go to
    whichever came first, so one set of outcomes had two basis censuses."""
    outcomes = [ChainOutcome("w", HELD, observed_at=T0, basis=basis) for basis in bases]
    signatures = set()
    for order in permutations(outcomes):
        result = compose(list(order))
        assert result.basis_census[stands] == 1
        assert sum(result.basis_census.values()) == 1
        signatures.add(_signature(result))
    assert len(signatures) == 1


@pytest.mark.parametrize("basis", sorted(comp.UNEXERCISED_BASES))
def test_the_held_clause_names_the_workflows_it_floored_and_only_those(basis) -> None:
    approved = ["a", "b"]
    floored = compose(
        _outcomes(("a", HELD), basis=basis) + _outcomes(("b", HELD), basis=comp.BASIS_DEMONSTRATED),
        expected_workflows=approved,
    )
    assert floored.held_floored == ("a",)
    sentence = comp.explain(floored)
    assert "The held reported for a rests on no demonstrated exercise" in sentence
    assert "counts as not_demonstrated" in sentence


@pytest.mark.parametrize("basis", sorted(comp.UNEXERCISED_BASES))
def test_no_held_clause_under_a_floor_the_typed_in_held_did_not_set(basis) -> None:
    """A signed violation sets the floor; an asserted held beside it is floored
    too, but below the violation, so it decides nothing. The clause explaining
    why a held decides was printed there anyway, under a decision it had no part
    in."""
    result = compose(
        _outcomes(("a", HELD), basis=basis) + _outcomes(("b", VIOLATED), basis=comp.BASIS_DEMONSTRATED),
        expected_workflows=["a", "b"],
    )
    assert result.decision == comp.NOT_RECOMMENDED
    assert result.deciding == ("b",)
    assert result.held_floored == ()
    assert "counts as not_demonstrated" not in comp.explain(result)


@pytest.mark.parametrize("basis", sorted(comp.UNEXERCISED_BASES))
def test_no_held_clause_without_an_approved_list_or_when_everything_is_demonstrated(basis) -> None:
    unlisted = compose(_outcomes(("a", HELD), ("b", NOT_DEMONSTRATED), basis=basis))
    assert unlisted.held_floored == ()
    assert "counts as not_demonstrated" not in comp.explain(unlisted)

    demonstrated = compose(
        _outcomes(("a", HELD), ("b", NOT_DEMONSTRATED), basis=comp.BASIS_DEMONSTRATED),
        expected_workflows=["a", "b"],
    )
    assert demonstrated.deciding == ("b",)
    assert demonstrated.held_floored == ()
    assert "counts as not_demonstrated" not in comp.explain(demonstrated)


def test_an_asserted_not_demonstrated_is_not_named_as_a_floored_held() -> None:
    """``held_floored`` is the rule's addition only: a not_demonstrated floors by
    its own status, whoever reported it, and is not a held the rule demoted."""
    result = compose(
        _outcomes(("a", HELD), ("b", NOT_DEMONSTRATED), basis=comp.BASIS_ATTESTED),
        expected_workflows=["a", "b"],
    )
    assert result.deciding == ("a", "b")
    assert result.held_floored == ("a",)


def test_the_held_clause_rolls_up_past_the_named_limit() -> None:
    names = [f"w{i:02d}" for i in range(comp._UNEXERCISED_NAMED + 3)]
    result = compose(_outcomes(*[(n, HELD) for n in names], basis=comp.BASIS_ATTESTED), expected_workflows=names)
    assert result.held_floored == tuple(names)
    assert "and 3 more rests on no demonstrated exercise" in comp.explain(result)


@pytest.mark.parametrize("basis", sorted(comp.UNEXERCISED_BASES))
def test_an_asserted_incomplete_is_audit_incomplete(basis) -> None:
    """An asserted gap floors by its status, as the docstring of ``_floor_of``
    says: a claim that something could not be checked is acted on whoever
    makes it."""
    result = compose(_outcomes(("a", INCOMPLETE), basis=basis), expected_workflows=["a"])
    assert result.decision == comp.AUDIT_INCOMPLETE
    assert result.held_floored == ()
