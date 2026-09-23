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
from dataclasses import dataclass
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

#: Statuses under which a workflow is actually demonstrated. Membership, not
#: `!= VIOLATED`: three of the four are not-held for three different reasons, and
#: a reader that only excludes the obvious one treats an unexercised chain as a
#: passing one.
DEMONSTRATED: frozenset[str] = frozenset({HELD})

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
    unable to supersede anything rather than as superseded by everything.
    """

    workflow: str
    status: str
    observed_at: datetime | None = None
    detail: str = ""

    def __post_init__(self) -> None:
        if self.status not in CHAIN_STATUSES:
            raise UnknownChainStatus(
                f"chain outcome for {self.workflow!r} has status {self.status!r}; "
                f"this module defines {', '.join(sorted(CHAIN_STATUSES))}"
            )
        if not self.workflow:
            raise ValueError("a chain outcome must name the workflow it is about")

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
    """

    decision: str | None
    census: Mapping[str, int]
    deciding: tuple[str, ...] = ()
    workflows_assessed: int = 0
    workflows_expected: int | None = None
    workflows_unreported: int = 0
    superseded: int = 0

    @property
    def all_held(self) -> bool:
        """Every workflow this composition speaks for is demonstrated.

        Not the same as "the deployment is fine": it is fine as far as the
        chains go, which is what `workflows_expected` exists to qualify.
        """
        return self.workflows_assessed > 0 and self.census[HELD] == self.workflows_assessed


def _is_newer(candidate: ChainOutcome, incumbent: ChainOutcome) -> bool:
    """Does ``candidate`` supersede ``incumbent``?

    Only when both carry a time and the candidate's is strictly later. An
    outcome with no time supersedes nothing -- "we do not know when this was
    observed" is not evidence that it is current -- and nothing supersedes it
    either, so it stays in contention and the tie rule below decides.
    """
    if candidate.observed_at is None or incumbent.observed_at is None:
        return False
    return candidate.observed_at > incumbent.observed_at


def _worse_status(a: str, b: str) -> str:
    """The status that places a deployment worse. Used only to break a tie."""
    return a if _RANK[FLOORS.get(a, READY)] >= _RANK[FLOORS.get(b, READY)] else b


def _surviving(outcomes: Iterable[ChainOutcome]) -> tuple[dict[str, ChainOutcome], int]:
    """One outcome per workflow -- the newest -- and how many were superseded.

    A re-run supersedes its predecessor: that is what re-running means. Where
    recency cannot be established (equal timestamps, or either side missing
    one), the WORSE status survives. Picking by iteration order would make the
    decision depend on the order rows came back from a database, which is the
    kind of dependency that produces a decision no one can reproduce; picking
    the better would let a passing re-run erase a violation it never
    contradicted.
    """
    latest: dict[str, ChainOutcome] = {}
    superseded = 0
    for outcome in outcomes:
        incumbent = latest.get(outcome.workflow)
        if incumbent is None:
            latest[outcome.workflow] = outcome
            continue
        superseded += 1
        if _is_newer(outcome, incumbent):
            latest[outcome.workflow] = outcome
        elif _is_newer(incumbent, outcome):
            continue
        elif _worse_status(outcome.status, incumbent.status) == outcome.status:
            # A genuine tie on recency. The worse status survives, and it is a
            # tie rather than a judgement that the newer one is wrong.
            latest[outcome.workflow] = outcome
    return latest, superseded


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
    latest, superseded = _surviving(outcomes)

    unreported: list[str] = []
    if expected_workflows is not None:
        # Every approved workflow with no outcome is undemonstrated. Added as
        # real entries rather than as a number on the side, so the census, the
        # floor and `deciding` all see them and no consumer has to remember to
        # add them back in.
        for workflow in expected_workflows:
            if workflow not in latest:
                unreported.append(workflow)
                latest[workflow] = ChainOutcome(workflow=workflow, status=NOT_DEMONSTRATED)

    census = dict.fromkeys(sorted(CHAIN_STATUSES), 0)
    for outcome in latest.values():
        census[outcome.status] += 1

    decision: str | None = None
    deciding: list[str] = []
    for outcome in latest.values():
        floor = FLOORS.get(outcome.status)
        if floor is None:
            continue
        if decision is None or _RANK[floor] > _RANK[decision]:
            decision, deciding = floor, [outcome.workflow]
        elif floor == decision:
            deciding.append(outcome.workflow)

    if decision is None and latest:
        # Every chain held. READY *by this signal*; `decision.py` still combines
        # it with findings, claims and coverage, any of which can be worse.
        decision = READY

    return Composition(
        decision=decision,
        census=census,
        deciding=tuple(sorted(deciding)),
        workflows_assessed=len(latest),
        workflows_expected=None if expected_workflows is None else len(set(expected_workflows)),
        workflows_unreported=len(unreported),
        superseded=superseded,
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
    counted = ", ".join(
        f"{count} {status}" for status, count in sorted(composition.census.items()) if count
    )
    scope = (
        f"{composition.workflows_assessed} workflow(s)"
        if composition.workflows_expected is None
        else (
            f"{composition.workflows_assessed} of {composition.workflows_expected} "
            f"approved workflow(s), {composition.workflows_unreported} of them never exercised"
        )
    )
    if not composition.deciding:
        return f"Every chain held across {scope} ({counted}), so this signal says {composition.decision}."
    return (
        f"Across {scope} ({counted}), the worst chain status sets the floor: "
        f"{composition.decision}, from {', '.join(composition.deciding)}."
    )
