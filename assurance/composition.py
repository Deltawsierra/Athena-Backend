"""How a set of per-workflow assurance chains composes into ONE deployment decision.

The unit of assurance is the approved business workflow: which agent may use
which governed information, under whose authority, to produce which external
effects. A deployment is not one such chain, it is many -- and `decision.py`
composes only DEPLOYMENT-WIDE signals (findings, claims, coverage), each of
which already speaks for the whole deployment. Nothing said how N workflow-scoped
chains become one decision, and the roadmap flags that as the missing half of the
graph: *"no research document or the code itself has yet defined"* it.

This module is that rule, written down before any per-workflow fingerprint is
built, so the fingerprints are built against a stated contract rather than the
contract being inferred afterwards from whatever they happened to produce.

Deliberately PURE -- no models, no ORM, no database. The rule is a function from
a set of chain outcomes to a decision, and a rule you can only exercise by
constructing a deployment is a rule nobody will exercise. The persistence layer
comes later and calls this.

FOUR CHAIN STATUSES, and each names a different thing:

    held              the chain was exercised and it holds. The authority
                      covers the effect.
    violated          the chain was exercised and it does NOT hold: the
                      deployment produced an effect its authority does not
                      cover. A fact, not a doubt.
    not_demonstrated  the chain was exercised and did not establish itself.
                      The subject is known; the evidence is thin.
    incomplete        the chain was not fully exercised. Parts of it were never
                      examined at all.

The floors they set follow `decision.py`'s existing order and its existing
argument, which is why they are not invented here:

    violated          -> NOT_RECOMMENDED
    incomplete        -> AUDIT_INCOMPLETE
    not_demonstrated  -> NEEDS_MORE_EVIDENCE
    held              -> no floor

`incomplete` sits above `not_demonstrated` for the reason the `AUDIT_INCOMPLETE`
enum member already gives: *"weak evidence at least has a subject, whereas an
unassessed component could hold anything."* A chain half-exercised is the wider
gap of the two.

WORST-OF-N, NOT COVERAGE-WEIGHTED, and this is the decision the roadmap asks to
be justified rather than assumed.

A coverage-weighted rule -- "forty-nine of fifty workflows hold, so call it
mostly ready" -- is exactly the arithmetic that lets one violated chain
disappear into an average. A deployment where one workflow can move customer
records to an unauthorised destination is not 98% safe; it is a deployment with
a way to move customer records to an unauthorised destination. Weighting is the
right tool for reporting BREADTH and the wrong tool for PLACING a decision, and
the two get confused because both produce a number.

So the decision is the worst floor. What the weighting argument is actually
reaching for -- "is this one bad workflow out of fifty, or the only one?" -- is a
real question with a better answer than a weighted decision: report the CENSUS
alongside. `Composition` carries how many workflows landed in each status and
which ones set the floor, so a reader can tell those two deployments apart
without the decision having to blur them together.

CHAINS DO NOT DISAGREE. The question "what happens when chains disagree"
presupposes a conflict that does not exist: two chains saying different things
are two statements about two different workflows, both true. There is no
arbitration to do. The case that DOES need a rule is the same workflow carrying
two outcomes -- a re-run -- and there the newest supersedes, with a tie broken
toward the worse of the tied rather than by arbitrary order (see
`_surviving`).

A WORKFLOW WITH NO CHAIN IS `not_demonstrated`, NOT ABSENT. This is the silent
zero of this domain, and refusing it is why `compose` takes `expected_workflows`.
A deployment with fifty approved workflows and one chain, held, is not a
deployment that is ready: it is a deployment where one workflow was checked. If
the caller knows the workflow set, every workflow without an outcome is counted
as undemonstrated and the decision reflects it. If the caller does NOT know the
set, `compose` says so -- `workflows_expected` is None and the result is about
the chains it was given and nothing else -- rather than quietly reading silence
as success.

NOTHING AT ALL IS `None`, NEVER `READY`. A deployment with no chains and no
expected set is unassessed by this signal, which `decision.py` already knows how
to combine: `None` means "this signal did not assess anything" and never wins
over a real state. An absent decision is not a good one.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import datetime

#: The chain was exercised and holds.
HELD = "held"
#: The chain was exercised and does not hold. A fact.
VIOLATED = "violated"
#: The chain was exercised and did not establish itself. A doubt.
NOT_DEMONSTRATED = "not_demonstrated"
#: The chain was not fully exercised. A gap.
INCOMPLETE = "incomplete"

#: Every status this module understands. A status outside it is an error rather
#: than a default, because the one default that would be safe -- treating an
#: unknown status as bad -- also silently accepts a typo forever, and the one
#: that is convenient reads an unrecognised word as `held`.
CHAIN_STATUSES: frozenset[str] = frozenset({HELD, VIOLATED, NOT_DEMONSTRATED, INCOMPLETE})

#: WHAT THE RECORD RESTS ON, which is a different axis from what it says.
#:
#: Every status above claims an EXERCISE. `held` is spelled "the chain was
#: exercised and it holds"; `not_demonstrated` is "the chain was exercised and did
#: not establish itself"; even `incomplete` is "not FULLY exercised". The status
#: axis cannot express "nobody exercised this and a person told us it holds", and
#: that is the only shape any outcome in this platform has ever had: across every
#: repository the sole writer of a chain outcome is an operator POST.
#:
#: Measured, before this axis existed. Fifty approved workflows, fifty rows typed
#: in by hand as `held`, and the graph answered:
#:
#:     "Every chain held across 50 workflow(s) against 50 approved, 0 of them
#:      never exercised (50 held, 0 incomplete, 0 not_demonstrated, 0 violated),
#:      so the rule places the deployment at ready."
#:
#: "0 of them never exercised", over a graph where nothing was exercised at all.
#: `source` was recorded per row and censused by
#: `workflow_chains.read_chain_provenance`, but it is FREE TEXT:
#: `source="nightly-scan"` on those same hand-typed rows reads identically, and a
#: blank one is counted as `unattributed`. A census of strings cannot answer "did a
#: run produce this", so nothing could.
BASIS_DEMONSTRATED = "demonstrated"
#: A person asserted it. An assertion may well be true; what it is not is an
#: exercise, and a record that cannot tell the two apart reports an assertion in
#: the words of a measurement.
BASIS_ATTESTED = "attested"
#: The record does not say. THE DEFAULT, and deliberately not either of the
#: others: every row written before this axis existed made no claim about its own
#: basis, and defaulting them to `attested` would invent an attester while
#: defaulting them to `demonstrated` would invent a run. The same refusal
#: `observed_at` already makes about an absent timestamp, on the axis beside it.
BASIS_UNKNOWN = "unknown"

#: Every basis this module understands. A value outside it is an error rather than
#: a default, for the reason `CHAIN_STATUSES` gives: the convenient default reads a
#: typo as the reassuring value.
CHAIN_BASES: frozenset[str] = frozenset({BASIS_DEMONSTRATED, BASIS_ATTESTED, BASIS_UNKNOWN})

#: The bases that do NOT support a status claiming an exercise. Membership rather
#: than `!= BASIS_DEMONSTRATED`, so a basis added later has to be classified here
#: on purpose instead of silently joining the supported side.
UNEXERCISED_BASES: frozenset[str] = frozenset({BASIS_ATTESTED, BASIS_UNKNOWN})

#: How many unexercised workflows `explain` names before rolling the rest into a
#: count. One sentence naming fifty workflows is a sentence nobody reads, and the
#: full list is on `Composition.unexercised` for anyone who needs it.
_UNEXERCISED_NAMED = 3

#: Statuses under which a workflow is actually demonstrated. Membership, not
#: `!= VIOLATED`: three of the four are not-held for three different reasons, and
#: a reader that only excludes the obvious one treats an unexercised chain as a
#: passing one.
DEMONSTRATED: frozenset[str] = frozenset({HELD})

#: The statuses that SAY WHETHER THE CHAIN HOLDS. Only these supersede.
#:
#: `held` and `violated` are verdicts. `not_demonstrated` and `incomplete` are
#: the absence of one -- thin evidence and a gap -- and an absence is not news
#: that contradicts an earlier fact. Without this, a later non-observation
#: erased a recorded violation:
#:
#:     violated Jan 1, then a Jan 5 scan that could not finish (incomplete)
#:         -> audit_incomplete, census["violated"] == 0
#:
#: An operator reading `0 violated` for a workflow this platform recorded
#: violating, whose only later news is that a scanner could not look at it,
#: would call that wrong, and they would be right: it is the silent zero, and a
#: scan that failed to run is the last thing that should clear a finding. It is
#: also the same argument the module already makes about an undated outcome --
#: what is not known cannot displace what is -- applied to the other axis.
#:
#: The cost is owned rather than hidden: a recorded violation now stands until
#: something actually exercises that chain again and returns a verdict. Repeated
#: inconclusive re-runs do not clear it. That is the conservative direction, and
#: it is the one this module is for.
VERDICTS: frozenset[str] = frozenset({HELD, VIOLATED})

# Decision states, spelled as the strings `Deployment.Decision` uses. Duplicated
# rather than imported so this module stays importable without Django -- and
# `test_the_composition_rule_is_written_down.py` asserts the two agree, so the
# duplication cannot drift into a disagreement.
READY = "ready"
READY_RESTRICTED = "ready_restricted"
NEEDS_MORE_EVIDENCE = "needs_more_evidence"
AUDIT_INCOMPLETE = "audit_incomplete"
NEEDS_REMEDIATION = "needs_remediation"
NOT_RECOMMENDED = "not_recommended"

#: Best to worst, matching `decision.py`'s `_READINESS_ORDER` except for its last
#: member, `paused`. That one is the operator failsafe -- a human standing the
#: engine down -- and no set of chain outcomes can reach it, so a rule that could
#: emit it would be claiming an authority it does not have. It is the ONLY
#: omission, and `test_the_readiness_order_matches_the_one_decisions_are_made_with`
#: asserts both halves: that the rest agrees exactly, and that `paused` is the
#: single state left out and the worst one.
READINESS_ORDER: tuple[str, ...] = (
    READY,
    READY_RESTRICTED,
    NEEDS_MORE_EVIDENCE,
    AUDIT_INCOMPLETE,
    NEEDS_REMEDIATION,
    NOT_RECOMMENDED,
)
_RANK = {state: rank for rank, state in enumerate(READINESS_ORDER)}

#: The floor each status puts under the deployment decision. `held` is absent
#: rather than mapped to READY: a floor is the worst the decision may be, and a
#: chain that holds does not make anything better -- it declines to make it worse.
FLOORS: Mapping[str, str] = {
    VIOLATED: NOT_RECOMMENDED,
    INCOMPLETE: AUDIT_INCOMPLETE,
    NOT_DEMONSTRATED: NEEDS_MORE_EVIDENCE,
}


class UnknownChainBasis(ValueError):
    """A basis outside :data:`CHAIN_BASES`.

    Its own type rather than a bare ``ValueError`` for the reason
    :class:`UnknownChainStatus` has one: a caller wanting to handle "this row is
    malformed" differently from "this row is about an unapproved workflow" needs to
    be able to, and matching on message text is not that.
    """


class UnknownChainStatus(ValueError):
    """A chain outcome carries a status this module does not define.

    Raised rather than defaulted. Defaulting to `violated` would turn a typo
    into a permanent NOT_RECOMMENDED nobody can explain; defaulting to `held`
    would read an unrecognised word as a pass. Neither is an answer, and this
    module's whole job is to not produce answers it does not have.
    """


@dataclass(frozen=True)
class ChainOutcome:
    """What one exercise of one workflow's authority-to-effect chain established.

    ``workflow`` identifies the approved business workflow, and is what makes
    two outcomes comparable or not: two outcomes for the same workflow are
    successive attempts at one question, and two for different workflows are
    answers to different questions.

    ``observed_at`` may be ``None``. An outcome with no time is not "oldest" --
    it is an outcome whose recency is unknown, and `_surviving` treats it as
    unable to supersede anything AND as impossible to supersede.

    What it may NOT be is naive. A naive and an aware datetime cannot be
    compared at all, and two outcomes for one workflow are compared -- so a
    single naive row would take a whole deployment's composition down with a
    `TypeError` raised three frames from anything that names a workflow. It is
    refused here, where the offending workflow can still be named, for the same
    reason an unknown status is: this module does not produce answers it does
    not have, and it does not fail in a place that cannot say why.
    """

    workflow: str
    status: str
    observed_at: datetime | None = None
    detail: str = ""
    #: What the outcome rests on -- see :data:`BASIS_UNKNOWN`, the default: a
    #: caller that says nothing has made no claim, and the two other values are
    #: both claims.
    basis: str = BASIS_UNKNOWN

    def __post_init__(self) -> None:
        if self.status not in CHAIN_STATUSES:
            raise UnknownChainStatus(
                f"chain outcome for {self.workflow!r} has status {self.status!r}; "
                f"this module defines {', '.join(sorted(CHAIN_STATUSES))}"
            )
        if self.basis not in CHAIN_BASES:
            raise UnknownChainBasis(
                f"chain outcome for {self.workflow!r} has basis {self.basis!r}; "
                f"this module defines {', '.join(sorted(CHAIN_BASES))}"
            )
        # A name, not merely something truthy. Two workflows named by values of
        # different types compare fine in a dict and blow up the moment the
        # deciding workflows are sorted -- an error about `<` arriving from a
        # module whose subject is assurance.
        if not isinstance(self.workflow, str):
            raise TypeError(
                f"a workflow is named by a string, not by {type(self.workflow).__name__}"
            )
        if not self.workflow:
            raise ValueError("a chain outcome must name the workflow it is about")
        if self.observed_at is not None:
            # `isinstance`, because ANYTHING with a `.tzinfo` attribute passed the
            # check that used to be here -- an aware `datetime.time` among them,
            # which then raised `TypeError: '>' not supported between
            # datetime.datetime and datetime.time` from inside `_surviving`. A
            # `str`, an `int` and a `date` were refused only by accident, with an
            # `AttributeError` naming no workflow.
            if not isinstance(self.observed_at, datetime):
                raise TypeError(
                    f"chain outcome for {self.workflow!r} carries "
                    f"{type(self.observed_at).__name__} as an instant; recency is "
                    "established between datetimes"
                )
            # `utcoffset()`, not `tzinfo is None`. A tzinfo whose `utcoffset()`
            # returns None leaves `.tzinfo` set and the datetime NAIVE in
            # Python's own model, so the previous check accepted it and the
            # `TypeError: can't compare offset-naive and offset-aware datetimes`
            # still arrived from `_surviving`, three frames from anything that
            # names a workflow -- with a guard sitting in front of it claiming
            # otherwise. A guard that is wrong is worse than no guard, because
            # the next reader believes it.
            if self.observed_at.utcoffset() is None:
                raise ValueError(
                    f"chain outcome for {self.workflow!r} carries a naive timestamp "
                    f"({self.observed_at!r}); an instant with no offset cannot be "
                    "compared with one that has a zone, so it cannot establish recency"
                )

    @property
    def demonstrated(self) -> bool:
        return self.status in DEMONSTRATED


@dataclass(frozen=True)
class Composition:
    """The decision, and everything a reader needs to explain it.

    ``decision`` is the worst floor any surviving outcome sets. ``None`` means
    this signal assessed nothing at all -- never ``READY``, because an absent
    decision is not a good one.

    ``census`` counts the surviving outcomes by status -- one entry per status
    this module defines, ALWAYS, including zeros. A count that appears only when
    it is non-zero is a count nobody checks, and its absence reads as "no
    violated chains" exactly like a zero does, which is the distinction this
    platform exists to keep.

    ``deciding`` names the workflows whose status set the floor, sorted. Plural
    on purpose: with three violated chains, all three are why, and reporting one
    would invite fixing it and expecting the decision to move.

    ``workflows_expected`` is how many approved workflows the caller said exist,
    or ``None`` when the caller did not say. ``workflows_unreported`` is how many
    of them had no outcome -- counted as `not_demonstrated`, never as absent.

    ``workflows_unapproved`` is the other direction, and it is the more
    interesting one: outcomes arrived for this many workflows that are NOT on
    the approved list. A chain exercising a workflow nobody approved is exactly
    what this platform exists to notice, so it is counted and named rather than
    quietly folded in -- and without it the scope reads "2 of 1 approved
    workflow(s)", which is not a sentence anyone can check a rule against.

    ``superseded`` counts outcomes a re-run genuinely displaced: strictly later,
    both dated. An outcome nothing could be shown to be newer than is not
    superseded, and is not counted here.
    """

    decision: str | None
    census: Mapping[str, int]
    deciding: tuple[str, ...] = ()
    workflows_assessed: int = 0
    workflows_expected: int | None = None
    workflows_unreported: int = 0
    workflows_unapproved: int = 0
    superseded: int = 0
    #: How many standing outcomes rest on each basis. Beside ``census`` rather than
    #: folded into it: what a chain SAYS and what the record RESTS ON are two
    #: independent distributions, and one table keyed by pairs would have twelve
    #: cells most of which are structurally empty.
    basis_census: Mapping[str, int] = field(default_factory=dict)
    #: Standing outcomes whose status claims an exercise while their basis does not
    #: say one happened. Every status claims one, so this is every standing outcome
    #: with an attested or unknown basis -- and a consumer cannot derive it from the
    #: two censuses, which is why it is a field rather than left to them.
    workflows_unexercised: int = 0
    #: Which ones, sorted, for the reason ``deciding`` names its workflows: a count
    #: says how much of the graph is assertion, and only the names say which part of
    #: the deployment to go and exercise.
    unexercised: tuple[str, ...] = ()

    @property
    def all_held(self) -> bool:
        """Every workflow this composition speaks for is demonstrated.

        Not the same as "the deployment is fine": it is fine as far as the
        chains go, which is what `workflows_expected` exists to qualify.
        """
        return self.workflows_assessed > 0 and self.census[HELD] == self.workflows_assessed


def _worse_status(a: str, b: str) -> str:
    """The status that places a deployment worse.

    A total order on the four statuses, because their four floors have four
    distinct ranks -- asserted by test, since two statuses sharing a rank would
    make this depend on which one it was handed first.
    """
    return a if _RANK[FLOORS.get(a, READY)] >= _RANK[FLOORS.get(b, READY)] else b


def _surviving(outcomes: Iterable[ChainOutcome]) -> tuple[dict[str, ChainOutcome], int]:
    """The outcome that stands for each workflow, and how many a re-run displaced.

    Returns the surviving OUTCOME rather than its status alone, and that is how the
    basis axis became reportable at all: the value the rule composed over had
    already thrown away everything the row said about itself. A parallel dict of
    bases keyed by workflow would work and would be a second thing to keep in step
    with this one; one dict of outcomes cannot disagree with itself.

    An outcome is SUPERSEDED when a later VERDICT exists for the same workflow:
    another outcome that says whether the chain holds (`held` or `violated`),
    strictly later, with both carrying a time. Everything not superseded
    survives, and the WORST surviving status stands. It is a property of the
    workflow's history rather than of any order it arrives in.

    Only a verdict supersedes, because only a verdict is news. See `VERDICTS`:
    a re-run that could not finish is not evidence that an earlier violation
    has gone away.

    THIS WAS A FOLD, AND THE FOLD WAS ORDER-DEPENDENT. It compared each outcome
    to a single running incumbent and carried the winner's own timestamp
    forward. An undated outcome -- which this module promises supersedes nothing
    and is superseded by nothing -- could therefore be evicted by proxy: a
    same-status duplicate that happened to carry a date won the tie, became the
    incumbent, and was then legitimately superseded by something newer, taking
    the undated outcome's verdict with it. Measured on the version before this
    one, with three rows for one workflow:

        [violated(no time), violated(Jan 1), held(Jan 2)] -> ready
        [violated(Jan 1), violated(no time), held(Jan 2)] -> not_recommended

    Two recorded violations of one workflow, and one arrival order reported
    `ready` with `census["violated"] == 0` and `explain()` saying "Every chain
    held". That is the silent zero this module was written to refuse, produced
    by the module itself, and reachable from nothing more exotic than a
    three-row history with a nullable timestamp. Both directions were reachable:
    288 status/time multisets of size two or three disagreed across orderings,
    half of them reading BETTER than the rule allows and half WORSE -- a
    manufactured violation being just as wrong as a vanished one.

    A fold cannot be rescued by a better tie-break here, because the defect is
    that "newest" is not a total order once recency can be unknown. So survival
    is computed against the workflow's whole history: one pass for the newest
    established instant, one to keep everything that instant does not displace.
    """
    history: dict[str, list[ChainOutcome]] = {}
    for outcome in outcomes:
        history.setdefault(outcome.workflow, []).append(outcome)

    standing: dict[str, ChainOutcome] = {}
    superseded = 0
    for workflow, attempts in history.items():
        dated = [
            attempt.observed_at
            for attempt in attempts
            if attempt.observed_at is not None and attempt.status in VERDICTS
        ]
        newest = max(dated) if dated else None
        survivors = [
            attempt
            for attempt in attempts
            if attempt.observed_at is None or newest is None or attempt.observed_at >= newest
        ]
        superseded += len(attempts) - len(survivors)
        status = survivors[0].status
        for attempt in survivors[1:]:
            status = _worse_status(status, attempt.status)
        # Among the survivors carrying that status, a DEMONSTRATED one wins the tie.
        # Two survivors saying the same thing about one chain, one of them from a
        # run, means a run really did establish it, and reporting the attested row's
        # basis there would understate what the platform holds. The other direction
        # is the one that matters more and is already handled by taking the worst
        # status first: an attested `held` cannot hide a demonstrated `violated`,
        # because the violated status wins outright.
        tied = [attempt for attempt in survivors if attempt.status == status]
        standing[workflow] = next(
            (attempt for attempt in tied if attempt.basis == BASIS_DEMONSTRATED), tied[0]
        )
    return standing, superseded


def _checked_approved(expected_workflows: Sequence[str]) -> tuple[str, ...]:
    """The approved workflow list, materialised once and checked like a name.

    Materialised because it is read twice, and a generator was empty the second
    time: `workflows_expected` came back 0 while three workflows had been
    counted against it.

    Checked because `str` satisfies `Sequence[str]`, so no type checker objects
    to `compose(outcomes, expected_workflows="checkout")` -- and iterating it
    shredded one workflow name into seven approved workflows, with a wrong
    denominator, a wrong census, a decision of `needs_more_evidence` where the
    truth was `ready`, and a sentence naming workflows `c, e, h, k, o, t, u`.
    A confident wrong number is worse than a refusal.

    And checked per entry, because a non-string name here reaches
    `tuple(sorted(deciding))` and raises the same `TypeError: '<' not supported
    between instances of 'str' and 'int'` that `ChainOutcome` now refuses at
    construction. Closing one door on that and leaving the other open would be
    a guard that only looks like one.
    """
    if isinstance(expected_workflows, str):
        raise TypeError(
            "expected_workflows is the set of approved workflows, not one name: "
            f"{expected_workflows!r} would be read one character at a time"
        )
    approved = tuple(expected_workflows)
    for workflow in approved:
        if not isinstance(workflow, str):
            raise TypeError(
                f"approved workflow {workflow!r} is named by "
                f"{type(workflow).__name__}, not by a string"
            )
        if not workflow:
            raise ValueError("an approved workflow must have a name")
    return approved


def compose(
    outcomes: Iterable[ChainOutcome],
    *,
    expected_workflows: Sequence[str] | None = None,
) -> Composition:
    """Compose per-workflow chain outcomes into one deployment decision.

    ``expected_workflows`` is the set of approved business workflows this
    deployment has. Supplying it is what lets the rule count a workflow NOBODY
    EXERCISED as `not_demonstrated` rather than as nothing at all -- the
    difference between "we checked everything and it holds" and "we checked one
    thing and it holds". Omitting it is allowed and honest: the result then says
    `workflows_expected is None`, meaning this composition is about the outcomes
    it was handed and makes no claim about the ones it was not.

    The decision is the worst floor among the surviving outcomes. A composition
    over nothing is ``None``.
    """
    standing, superseded = _surviving(outcomes)

    # Materialised once. It is read twice below, and a caller passing a
    # generator got the second read empty: `workflows_expected` came back 0
    # while three workflows had just been counted against it, and `explain()`
    # said "3 of 0 approved workflow(s)". A confident wrong number is worse
    # than a refusal, and this module is about not producing either.
    approved = None if expected_workflows is None else _checked_approved(expected_workflows)

    unreported: set[str] = set()
    unapproved = 0
    if approved is not None:
        # Every approved workflow with no outcome is undemonstrated. Added as a
        # real entry rather than as a number on the side, so the census, the
        # floor and `deciding` all see them and no consumer has to remember to
        # add them back in.
        for workflow in approved:
            if workflow not in standing:
                unreported.add(workflow)
                # BASIS_UNKNOWN, and not a fourth basis meaning "never reported".
                # `workflows_unreported` already counts these exactly, so a separate
                # basis would be a second spelling of one fact and would put two
                # numbers in the payload that must always agree.
                standing[workflow] = ChainOutcome(
                    workflow=workflow, status=NOT_DEMONSTRATED, basis=BASIS_UNKNOWN
                )
        # Hoisted, and that is not a micro-optimisation: `set(approved)` inside
        # the genexpr was rebuilt once per surviving workflow, making this O(n*m).
        # Profiled, it was 99.5% of `compose`'s runtime -- 11ms at 1,000 approved
        # workflows, 2.2s at 8,000, 61s at 40,000 -- and the route that writes the
        # approved set left its size to the caller. A pure rule with no I/O should
        # not be the slowest thing in an assurance read.
        approved_set = set(approved)
        unapproved = sum(1 for workflow in standing if workflow not in approved_set)

    census = dict.fromkeys(sorted(CHAIN_STATUSES), 0)
    basis_census = dict.fromkeys(sorted(CHAIN_BASES), 0)
    # Chains whose status CLAIMS an exercise while their basis does not say one
    # happened. Every status claims an exercise, so this is every standing outcome
    # whose basis is attested or unknown -- counted here rather than left for a
    # consumer to derive, because the two censuses are independent distributions and
    # this number is not in either of them.
    unexercised: list[str] = []
    for workflow, outcome in standing.items():
        census[outcome.status] += 1
        basis_census[outcome.basis] += 1
        if outcome.basis in UNEXERCISED_BASES:
            unexercised.append(workflow)

    decision: str | None = None
    deciding: list[str] = []
    for workflow, outcome in standing.items():
        floor = FLOORS.get(outcome.status)
        if floor is None:
            continue
        if decision is None or _RANK[floor] > _RANK[decision]:
            decision, deciding = floor, [workflow]
        elif floor == decision:
            deciding.append(workflow)

    if decision is None and standing:
        # Every chain held. READY *by this signal*; `decision.py` still combines
        # it with findings, claims and coverage, any of which can be worse.
        decision = READY

    return Composition(
        decision=decision,
        census=census,
        deciding=tuple(sorted(deciding)),
        workflows_assessed=len(standing),
        workflows_expected=None if approved is None else len(set(approved)),
        workflows_unreported=len(unreported),
        workflows_unapproved=unapproved,
        superseded=superseded,
        basis_census=basis_census,
        workflows_unexercised=len(unexercised),
        unexercised=tuple(sorted(unexercised)),
    )


def explain(composition: Composition) -> str:
    """One sentence a reviewer can check the rule against.

    The quality bar this module was written to says a reviewer must be able to
    explain the decision *from the rule alone, not from an implementation
    detail*. That is only true if the explanation is generated from the same
    values the decision was, which is what this does.
    """
    if composition.decision is None:
        return "No chains were composed, so this signal places the deployment nowhere."
    # Every status, including the zeros. `Composition` argues at length that a
    # count which appears only when it is non-zero is a count nobody checks, and
    # that its absence reads as "no violated chains" exactly as a zero does.
    # This sentence used to drop them, which made the argument true of the one
    # line a human actually reads.
    counted = ", ".join(
        f"{count} {status}" for status, count in sorted(composition.census.items())
    )
    if composition.workflows_expected is None:
        scope = f"{composition.workflows_assessed} workflow(s), with no approved list to compare against"
    else:
        scope = (
            f"{composition.workflows_assessed} workflow(s) against "
            f"{composition.workflows_expected} approved, "
            f"{composition.workflows_unreported} of them never exercised"
        )
        if composition.workflows_unapproved:
            scope += f", and {composition.workflows_unapproved} not on the approved list"
    # The basis clause, appended to whichever sentence follows. It used to be
    # absent, and "0 of them never exercised" was then printed over a graph where
    # nothing had been exercised -- the one line a human actually reads making the
    # strongest available claim about evidence nobody had. Silent when every
    # standing outcome is demonstrated, because a clause that appears
    # unconditionally is one readers learn to skip; `basis_census` carries the zero
    # for anything reading the payload rather than the sentence.
    if composition.workflows_unexercised:
        named = ", ".join(composition.unexercised[:_UNEXERCISED_NAMED])
        if len(composition.unexercised) > _UNEXERCISED_NAMED:
            named += f" and {len(composition.unexercised) - _UNEXERCISED_NAMED} more"
        basis_clause = (
            f" {composition.workflows_unexercised} of these rest on no demonstrated"
            f" exercise ({named}): every status above claims the chain was"
            f" exercised, and for these the record does not say one was."
        )
    else:
        basis_clause = ""

    if not composition.deciding:
        # "THE RULE PLACES", not "this signal says". This function knows
        # `composition.decision` -- the rule's verdict over the outcomes it was
        # handed -- and nothing about what the caller publishes as its `signal`.
        # Those two differ exactly when the scope is not closed, and the old
        # wording then contradicted the field beside it in one payload: a
        # deployment with an unapproved chain outcome published `signal: null`
        # next to "so this signal says ready", and a paused deployment published
        # the same sentence. The reassuring half was the human-readable one.
        # `workflow_chains.composition_payload` adds the narrowing sentence when
        # the two differ; this one now only claims what it can see.
        return (
            f"Every chain held across {scope} ({counted}), so the rule places the "
            f"deployment at {composition.decision}.{basis_clause}"
        )
    return (
        f"Across {scope} ({counted}), the worst chain status sets the floor: "
        f"{composition.decision}, from {', '.join(composition.deciding)}.{basis_clause}"
    )
