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

    held              the chain was exercised and it holds, as far as the
                      evidence behind it reaches -- which is its own axis (see
                      `EVIDENCE_KINDS`). Nothing that records a held today
                      observes the effect itself: the one an engine signs at
                      dispatch means the gate authorized the workflow's action
                      (a permit check), which shows the authority chain
                      resolves and does not show the effect happened.
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

#: The chain was exercised and holds -- as far as its evidence reaches, which
#: :func:`evidence_kind` says and this word does not.
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
#: Strongest first, for breaking a tie between survivors that report one status.
#: Total over :data:`CHAIN_BASES` -- asserted by test -- so the tie never falls to
#: arrival order.
_BASIS_RANK: Mapping[str, int] = {BASIS_DEMONSTRATED: 0, BASIS_ATTESTED: 1, BASIS_UNKNOWN: 2}

#: WHAT KIND OF EVIDENCE THE RECORD IS, a third axis, and it follows from WHO
#: signed it. ``demonstrated`` says an engine this deployment trusts signed the
#: outcome. It does not say what that engine could see, and the engines see very
#: different things -- so a signed ``held`` published with nothing beside it read
#: as an effect somebody watched happen, which no signer here can see.
#:
#: Derived, never stored: the signer is already recorded and verified on every
#: signed row (``observer_engine``, checked against the key that signed it), so a
#: column would be a second copy of one fact that could disagree with the first.
#:
#: Achilles signs at dispatch (``achilles/chain_outcome.py::attach_outcome``):
#: ``held`` whenever the gate's permit check passes, ``not_demonstrated`` when it
#: refuses. That is an AUTHORIZATION CHECK. The gate authorized the workflow's
#: action at dispatch, which shows the authority chain resolves; it does not show
#: the effect happened. The gate sees the action it is asked about, never the
#: effect itself.
EVIDENCE_AUTHORIZATION_CHECK = "authorization_check"
#: Athena signs per scan (``engine/chain_outcome.py::scan_status``): what its
#: checks found against the target. They probe the target; they do not watch this
#: workflow's own effect either.
EVIDENCE_SCAN = "scan"
#: Reserved for an outcome signed by an independent collector's key -- one that
#: watched the effect itself happen, separately from the engine that authorized
#: it. NOTHING PRODUCES ONE YET: no signer maps to it, and a test pins that, so
#: the first thing to claim it has to be added on purpose rather than by a typo.
EVIDENCE_OBSERVED_EFFECT = "observed_effect"
#: Signed by a key this deployment trusts, for an engine this module has not
#: classified. Not `observed_effect`: a signer nobody has looked at is read as no
#: more than a signature, which is the direction this module errs in on purpose.
EVIDENCE_UNCLASSIFIED = "unclassified"
#: An unsigned record is exactly as strong as its basis says, so its evidence kind
#: IS its basis -- the same word, and never a second spelling that could drift.
EVIDENCE_ATTESTED = BASIS_ATTESTED
EVIDENCE_UNKNOWN = BASIS_UNKNOWN

#: Every evidence kind this module understands.
EVIDENCE_KINDS: frozenset[str] = frozenset(
    {
        EVIDENCE_AUTHORIZATION_CHECK,
        EVIDENCE_SCAN,
        EVIDENCE_OBSERVED_EFFECT,
        EVIDENCE_UNCLASSIFIED,
        EVIDENCE_ATTESTED,
        EVIDENCE_UNKNOWN,
    }
)

#: Which signer's outcomes are which kind of evidence, by the engine name a
#: verified signature binds. Exact names: a signer not listed here is
#: `unclassified`, never whichever entry it happens to resemble.
SIGNER_EVIDENCE: Mapping[str, str] = {
    "achilles": EVIDENCE_AUTHORIZATION_CHECK,
    "athena": EVIDENCE_SCAN,
}

#: The kind an UNSIGNED basis names. A basis missing here raises rather than
#: defaulting, so a basis added later has to be classified on purpose.
_UNSIGNED_EVIDENCE: Mapping[str, str] = {
    BASIS_ATTESTED: EVIDENCE_ATTESTED,
    BASIS_UNKNOWN: EVIDENCE_UNKNOWN,
}

#: What a reader is told each kind means, published beside it. One place, so the
#: route and any later surface cannot describe one kind two ways.
EVIDENCE_LABELS: Mapping[str, str] = {
    EVIDENCE_AUTHORIZATION_CHECK: (
        "Authorization check — the action gate authorized (or refused) this "
        "workflow's action at dispatch, a permit check. It shows whether the "
        "authority chain resolves; it does not show the effect happened"
    ),
    EVIDENCE_SCAN: (
        "Scan — an engine's checks ran against the target. They did not watch this "
        "workflow's own effect"
    ),
    EVIDENCE_OBSERVED_EFFECT: (
        "Observed effect — an independent collector saw the effect happen. Nothing "
        "records this kind yet"
    ),
    EVIDENCE_UNCLASSIFIED: (
        "Unclassified — signed by an engine this deployment trusts, whose evidence "
        "this platform has not classified"
    ),
    EVIDENCE_ATTESTED: "Attested — a person asserted it",
    EVIDENCE_UNKNOWN: "Unknown — the record does not say",
}

#: Strongest first, for breaking a tie between survivors that share a status AND
#: a basis. Total over :data:`EVIDENCE_KINDS` -- asserted by test -- so, as with
#: the basis, the tie never falls to arrival order. A scan outranks an
#: authorization check only because it at least sent something to the target; the
#: order is not a claim that either one observed the effect, and neither did.
_EVIDENCE_RANK: Mapping[str, int] = {
    EVIDENCE_OBSERVED_EFFECT: 0,
    EVIDENCE_SCAN: 1,
    EVIDENCE_AUTHORIZATION_CHECK: 2,
    EVIDENCE_UNCLASSIFIED: 3,
    EVIDENCE_ATTESTED: 4,
    EVIDENCE_UNKNOWN: 5,
}


def evidence_kind(basis: str, signer: str = "") -> str:
    """What kind of evidence an outcome resting on ``basis`` is, given who signed it.

    ``basis`` must be the basis IN FORCE (see
    :func:`assurance.observed_outcomes.basis_in_force`), not the column: a row that
    says demonstrated with no envelope that verifies now is attested, and the name
    in its ``observer_engine`` then vouches for nothing. ``signer`` is read only
    for a demonstrated basis, for that reason.
    """
    if basis == BASIS_DEMONSTRATED:
        return SIGNER_EVIDENCE.get(signer, EVIDENCE_UNCLASSIFIED)
    return _UNSIGNED_EVIDENCE[basis]


#: WHAT THE OUTCOME WAS TAKEN AGAINST, a fourth axis. An exercise is an exercise
#: of the system that served it: the model, its revision and quantization, the
#: tokenizer, the system template, the tool schema (see
#: :mod:`assurance.served_route`). A ``held`` taken against one route says nothing
#: about another, and a deployment whose route changed after its chains were
#: exercised has chains nobody has exercised against what serves now.
#:
#: Decided by the persistence layer, which alone can see the deployment: the route
#: the platform had noted as serving when the outcome was observed, compared with
#: the route serving now. This module only reads the answer.
#:
#: The route serving now is the one the outcome was taken against.
ROUTE_CURRENT = "current"
#: The outcome was taken against a route that no longer serves.
ROUTE_MOVED = "moved"
#: Nothing says which route the outcome was taken against: it was recorded before
#: routes were bound, it carries no instant, or it was observed before the platform
#: had noted the route serving at that instant. THE DEFAULT, for the reason
#: ``BASIS_UNKNOWN`` is one: a caller that says nothing has made no claim, and
#: defaulting to ``current`` would invent the one fact this axis exists to check.
ROUTE_UNRECORDED = "unrecorded"

#: Every route reading this module understands.
CHAIN_ROUTES: frozenset[str] = frozenset({ROUTE_CURRENT, ROUTE_MOVED, ROUTE_UNRECORDED})

#: The readings under which an outcome is NOT evidence about the route serving now.
#: Membership rather than ``!= ROUTE_CURRENT``, for the reason
#: :data:`UNEXERCISED_BASES` gives.
OFF_ROUTE: frozenset[str] = frozenset({ROUTE_MOVED, ROUTE_UNRECORDED})
#: Strongest first, for breaking a tie between survivors that share a status and a
#: basis: an exercise of what serves now outranks one of something else. Total over
#: :data:`CHAIN_ROUTES`, asserted by test.
_ROUTE_RANK: Mapping[str, int] = {ROUTE_CURRENT: 0, ROUTE_MOVED: 1, ROUTE_UNRECORDED: 2}

#: How many unexercised workflows `explain` names before rolling the rest into a
#: count. One sentence naming fifty workflows is a sentence nobody reads, and the
#: full list is on `Composition.unexercised` for anyone who needs it.
_UNEXERCISED_NAMED = 3


def _named(workflows) -> str:
    """Up to :data:`_UNEXERCISED_NAMED` workflow names, the rest as a count."""
    named = ", ".join(workflows[:_UNEXERCISED_NAMED])
    if len(workflows) > _UNEXERCISED_NAMED:
        named += f" and {len(workflows) - _UNEXERCISED_NAMED} more"
    return named

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


def _floor_of(workflow: str, outcome: ChainOutcome, approved: set[str] | None) -> str | None:
    """The floor one standing outcome puts under the decision.

    Its status's floor, with ONE addition: a ``held`` on an APPROVED workflow that
    rests on no demonstrated exercise OF THE ROUTE SERVING NOW floors exactly as
    that workflow would had it never reported at all -- :data:`NOT_DEMONSTRATED`'s
    floor. Two ways to miss that: the basis says no run happened, or the run was of
    a route that no longer serves (or of one nothing recorded). A model swapped, a
    tokenizer changed or a system template edited after the run leaves a ``held``
    that speaks for a system that is gone, and reading it as current evidence would
    make a route change the one change that never needs a retest.

    Without it, a closed approved set whose every chain was typed in composed to
    READY, and ``composition_decision_signal`` handed that READY to the decision:
    the deployment was ready on the strength of assertions, with
    ``workflows_unexercised`` counting every one of them and deciding nothing. An
    approved workflow is one the deployment says it must be able to do safely; an
    assertion that it does is not the demonstration READY asks for, and treating
    it as one would make typing ``held`` a way to skip the run. Typing it now does
    exactly what not reporting does, which is the honest reading of an outcome no
    run produced.

    Deliberately NOT applied:

    * to a workflow off the approved list, or with no list at all. There the
      composition makes no claim about the deployment -- the signal it hands the
      decision is already ``None`` -- and a floor would make recording an
      assertion WORSE than recording nothing, a reason to stop recording them.
    * to any status but ``held``. An asserted violation, gap or thin evidence
      already carries a floor at least this bad; a claim that something failed is
      one to act on whoever makes it, which is the conservative direction. The same
      holds on the route axis: a violation seen on a route that has since changed
      stands, because a route change is not a fix, and only a later verdict can
      show one.
    """
    floor = FLOORS.get(outcome.status)
    if (
        floor is None
        and approved is not None
        and workflow in approved
        and (outcome.basis in UNEXERCISED_BASES or outcome.route in OFF_ROUTE)
    ):
        return FLOORS[NOT_DEMONSTRATED]
    return floor


class UnknownChainBasis(ValueError):
    """A basis outside :data:`CHAIN_BASES`.

    Its own type rather than a bare ``ValueError`` for the reason
    :class:`UnknownChainStatus` has one: a caller wanting to handle "this row is
    malformed" differently from "this row is about an unapproved workflow" needs to
    be able to, and matching on message text is not that.
    """


class UnknownChainRoute(ValueError):
    """A route reading outside :data:`CHAIN_ROUTES`, refused for the reason
    :class:`UnknownChainBasis` is: the convenient default reads a typo as current."""


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
    #: The engine whose verified signature the outcome rests on, or "" when none
    #: does. Read only through :attr:`evidence`, and only for a demonstrated basis.
    signer: str = ""
    #: Whether the outcome was taken against the route serving now -- see
    #: :data:`ROUTE_UNRECORDED`, the default.
    route: str = ROUTE_UNRECORDED

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
        if self.route not in CHAIN_ROUTES:
            raise UnknownChainRoute(
                f"chain outcome for {self.workflow!r} has route {self.route!r}; "
                f"this module defines {', '.join(sorted(CHAIN_ROUTES))}"
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

    @property
    def evidence(self) -> str:
        """What kind of evidence this outcome is: see :func:`evidence_kind`."""
        return evidence_kind(self.basis, self.signer)


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
    #: The deciding workflows whose floor came from the typed-in-``held`` rule in
    #: :func:`_floor_of` rather than from their status, sorted. ``explain`` keys its
    #: "an assertion is not the run READY asks for" clause on this and nothing
    #: looser: the clause is true of exactly these workflows, and a looser trigger
    #: (any unexercised outcome beside any deciding one) printed it under a floor a
    #: signed ``violated`` set, where it explained a decision it had no part in.
    held_floored: tuple[str, ...] = ()
    #: How many standing outcomes are each kind of evidence, every kind including
    #: the zeros -- so ``observed_effect: 0`` is always there to be read, rather than
    #: its absence reading as a kind nobody tracks.
    evidence_census: Mapping[str, int] = field(default_factory=dict)
    #: The workflows whose standing outcome is an authorization check, sorted.
    #: ``explain`` names them, because "every chain held" is a sentence a reader
    #: takes to mean the effects were seen, and for these nothing saw them.
    authorization_checked: tuple[str, ...] = ()
    #: How many standing outcomes read each way on the route axis, every reading
    #: including the zeros. An approved workflow nobody reported is counted
    #: ``unrecorded``, as it is counted ``unknown`` on the basis axis: it is the
    #: absence of an outcome, and no route can be said of it.
    route_census: Mapping[str, int] = field(default_factory=dict)
    #: The workflows whose standing ``held`` was taken against a route that no
    #: longer serves, or against one nothing recorded, sorted. These are the chains
    #: to exercise again; ``explain`` names them.
    off_route: tuple[str, ...] = ()

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


def _newest_verdict(attempts: Sequence[ChainOutcome]) -> datetime | None:
    """The latest instant at which any of ``attempts`` returned a dated verdict."""
    dated = [
        attempt.observed_at
        for attempt in attempts
        if attempt.observed_at is not None and attempt.status in VERDICTS
    ]
    return max(dated) if dated else None


def _survives(attempt: ChainOutcome, newest: datetime | None) -> bool:
    """Is ``attempt`` still standing, given the newest verdict allowed to displace it?"""
    return attempt.observed_at is None or newest is None or attempt.observed_at >= newest


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
        # Two newest instants, because what may supersede depends on what is being
        # superseded. ANY later verdict displaces an outcome no run produced; only a
        # later DEMONSTRATED verdict displaces one a run did. Without the split, a
        # typed-in `held` dated after a signed `violated` -- or dated 2099 -- evicted
        # it: the violation left the census and the deployment read READY, and every
        # later signed violation was evicted by the same row. An assertion may be
        # outranked by evidence; it may not outrank it.
        newest_verdict = _newest_verdict(attempts)
        newest_demonstrated = _newest_verdict(
            [attempt for attempt in attempts if attempt.basis == BASIS_DEMONSTRATED]
        )
        survivors = [
            attempt
            for attempt in attempts
            if _survives(
                attempt,
                newest_demonstrated if attempt.basis == BASIS_DEMONSTRATED else newest_verdict,
            )
        ]
        superseded += len(attempts) - len(survivors)
        status = survivors[0].status
        for attempt in survivors[1:]:
            status = _worse_status(status, attempt.status)
        # Among the survivors carrying that status, the strongest basis wins the tie:
        # demonstrated, then attested, then unknown. Two survivors saying the same
        # thing about one chain, one of them from a run, means a run really did
        # establish it, and reporting the weaker row's basis there would understate
        # what the platform holds. Ranked in full rather than "demonstrated, else
        # whichever came first": between an attested and an unknown row the answer
        # used to depend on arrival order, so the same outcomes composed to two
        # different basis censuses. The other direction is the one that matters
        # more and is already handled by taking the worst status first: an attested
        # `held` cannot hide a demonstrated `violated`, because the violated status
        # wins outright.
        #
        # Then the strongest evidence kind among those, for the same reason one step
        # down: an Achilles and an Athena outcome can both be signed `held` for one
        # workflow, and without a rank the kind reported would be whichever arrived
        # first.
        #
        # Then the route, between the two: of two signed `held`s for one workflow, the
        # one taken against the route serving now is the one that speaks for the
        # deployment, whatever kind of evidence the other is. Ranked before the
        # evidence kind so a scan of a route that is gone cannot outrank a permit
        # check of the one that serves.
        tied = [attempt for attempt in survivors if attempt.status == status]
        standing[workflow] = min(
            tied,
            key=lambda attempt: (
                _BASIS_RANK[attempt.basis],
                _ROUTE_RANK[attempt.route],
                _EVIDENCE_RANK[attempt.evidence],
            ),
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
    evidence_census = dict.fromkeys(sorted(EVIDENCE_KINDS), 0)
    authorization_checked: list[str] = []
    route_census = dict.fromkeys(sorted(CHAIN_ROUTES), 0)
    off_route: list[str] = []
    for workflow, outcome in standing.items():
        census[outcome.status] += 1
        basis_census[outcome.basis] += 1
        if outcome.basis in UNEXERCISED_BASES:
            unexercised.append(workflow)
        evidence_census[outcome.evidence] += 1
        if outcome.evidence == EVIDENCE_AUTHORIZATION_CHECK:
            authorization_checked.append(workflow)
        route_census[outcome.route] += 1
        if outcome.status == HELD and outcome.route in OFF_ROUTE:
            off_route.append(workflow)

    decision: str | None = None
    deciding: list[str] = []
    floored_by_rule: set[str] = set()
    for workflow, outcome in standing.items():
        floor = _floor_of(workflow, outcome, approved_set if approved is not None else None)
        if floor is None:
            continue
        if FLOORS.get(outcome.status) is None:
            floored_by_rule.add(workflow)
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
        held_floored=tuple(sorted(set(deciding) & floored_by_rule)),
        evidence_census=evidence_census,
        authorization_checked=tuple(sorted(authorization_checked)),
        route_census=route_census,
        off_route=tuple(sorted(off_route)),
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
    # The route clause, beside the basis clause and for the same reason: a `held`
    # taken against a route that no longer serves reads, in the census, exactly
    # like one taken against the route that does. Silent when there is none.
    if composition.off_route:
        basis_clause += (
            f" {len(composition.off_route)} held chain(s) were exercised against a served"
            f" route that is not the one serving now, or one nothing recorded"
            f" ({_named(list(composition.off_route))})."
        )
    # When an approved workflow's `held` is what set the floor, the sentence above
    # names a held workflow as the reason the decision is not ready, which reads as
    # a contradiction unless it says why -- and only then. There are two whys, and
    # each workflow gets the true one: the basis when no run is recorded at all,
    # the route when a run is but of a route that no longer serves.
    unexercised = set(composition.unexercised)
    asserted = [w for w in composition.held_floored if w in unexercised]
    rerouted = [w for w in composition.held_floored if w not in unexercised]
    held_clause = ""
    if asserted:
        held_clause += (
            f" The held reported for {_named(asserted)} rests on no demonstrated exercise, and"
            f" on an approved workflow that counts as {NOT_DEMONSTRATED}: an assertion"
            f" is not the run READY asks for."
        )
    if rerouted:
        held_clause += (
            f" The held reported for {_named(rerouted)} was taken against a served route"
            f" that is not the one serving now, or one nothing recorded, and on an approved"
            f" workflow that counts as {NOT_DEMONSTRATED}: a run of another route is not a"
            f" run of this one, so the chain must be exercised again."
        )
    # The evidence clause. "Every chain held" reads as "the effects were seen", and
    # for a workflow whose standing outcome is an authorization check nothing saw
    # them: the gate checked the action it was asked about, at dispatch, and that
    # is all it can see. The status, the basis and the decision are left exactly as
    # they are -- this says what they rest on, it does not re-weigh them. Silent
    # when no standing outcome is one, for the basis clause's reason;
    # `evidence_census` carries the zero for anything reading the payload.
    if composition.authorization_checked:
        checked = ", ".join(composition.authorization_checked[:_UNEXERCISED_NAMED])
        if len(composition.authorization_checked) > _UNEXERCISED_NAMED:
            checked += f" and {len(composition.authorization_checked) - _UNEXERCISED_NAMED} more"
        evidence_clause = (
            f" {len(composition.authorization_checked)} of these rest on an"
            f" authorization check, not an observed effect ({checked}): a held there"
            f" means the gate authorized the workflow's action at dispatch (a permit"
            f" check), which shows the authority chain resolves; it does not show the"
            f" effect happened."
        )
    else:
        evidence_clause = ""

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
            f"deployment at {composition.decision}.{basis_clause}{evidence_clause}"
        )
    return (
        f"Across {scope} ({counted}), the worst chain sets the floor: "
        f"{composition.decision}, from {', '.join(composition.deciding)}.{basis_clause}"
        f"{held_clause}{evidence_clause}"
    )
