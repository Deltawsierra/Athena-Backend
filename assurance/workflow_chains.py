"""The persistence half of the compositional assurance graph.

:mod:`assurance.composition` writes down the rule: how N per-workflow
authority-to-effect chains compose into ONE deployment decision. It is
deliberately pure -- no models, no ORM, no clock -- and its own docstring ends
by saying *"The persistence layer comes later and calls this."*

Later did not come. The rule shipped with ~850 lines of tests and **no caller
anywhere in the codebase**: :mod:`assurance.decision` never imported it, no
model held a workflow, and no request could reach it. A rule nothing consults
is a decorative control, the same shape as an unreachable vendor packet or an
exemption that checks nothing, and a worse one than most because the roadmap
counts this rule as the compositional assurance graph being *in place*.

This module is that missing layer, and it is deliberately thin. The split is
load-bearing rather than tidy: `compose` stays exercisable from a plain Python
prompt with four hand-made outcomes, so its tests cannot be made vacuous by a
database fixture, and everything that needs a deployment lives here.

Four queries, no writes, no clock: the outcomes, the approved set, the
provenance census below, and the assets the route serving now is read from. The
count is stated rather than left stale, because a docstring that undercounts its
own reads is how a caller ends up fencing the wrong number of them in a
transaction.
"""

from __future__ import annotations

from . import observed_outcomes
from .composition import (
    EVIDENCE_UNCLASSIFIED,
    READY,
    READY_RESTRICTED,
    ROUTE_CURRENT,
    ROUTE_MOVED,
    ROUTE_UNRECORDED,
    ChainOutcome,
    Composition,
    compose,
    explain,
)
from .served_route import serving_route_now


def read_chain_outcomes(deployment, keyring=observed_outcomes.READ_KEYRING) -> list[ChainOutcome]:
    """Every recorded chain outcome for a deployment, as the rule's own type.

    The conversion is deliberately TOTAL: every row becomes a
    :class:`~assurance.composition.ChainOutcome`, including rows naming a
    workflow nobody approved. Filtering those out here is the one edit that would
    make :attr:`~assurance.composition.Composition.workflows_unapproved` a zero
    no input can reach -- and that counter is how a chain exercising an
    unapproved workflow becomes visible at all.
    """
    # One keyring read for the whole deployment, not one per row -- or none, when
    # the caller read it already: a decision stamped with the keyring it was
    # computed under must have been computed under exactly that one.
    if keyring is observed_outcomes.READ_KEYRING:
        keyring = observed_outcomes.trusted_keyring()
    deployment_uuid = str(deployment.uuid)
    rows = list(deployment.chain_outcomes.all())
    # The route serving now, read once, and only when there is an outcome to compare
    # with it: a deployment with no chains reads no assets here.
    serving = serving_route_now(deployment) if rows else ""
    return [
        ChainOutcome(
            workflow=row.workflow,
            status=row.status,
            observed_at=row.observed_at,
            basis=_basis_of(row, keyring, deployment_uuid),
            # Who signed it, so the rule can say what kind of evidence the row is.
            # Passed whatever the basis: `evidence_kind` reads it only when the
            # basis in force is demonstrated, i.e. when the signature naming this
            # engine verifies now.
            signer=row.observer_engine,
            route=route_of(row, serving),
        )
        for row in rows
    ]


def route_of(row, serving: str) -> str:
    """Whether ``row`` was taken against ``serving``, the route serving now.

    Compared with the route computed from the graph NOW, not with the one noted
    when the row was written: the note says what served then, and the question is
    whether that is what serves. A blank binding is
    :data:`~assurance.composition.ROUTE_UNRECORDED` -- the row cannot say which
    route it exercised, and "current" would be the one guess this axis refuses.
    """
    bound = row.route_fingerprint or ""
    if not bound:
        return ROUTE_UNRECORDED
    return ROUTE_CURRENT if bound == serving else ROUTE_MOVED


def _basis_of(row, keyring, deployment_uuid: str) -> str:
    """The basis the rule may rely on for ``row``: see
    :func:`assurance.observed_outcomes.basis_in_force`, which the outcome routes
    also publish per row, so the graph and the rows it was built from agree."""
    return observed_outcomes.basis_in_force(row, keyring, deployment_uuid=deployment_uuid)


#: How many distinct sources the provenance census names before rolling the rest
#: up. `source` is free text on purpose -- the producers are not all modelled --
#: so its cardinality is whatever callers posted, and an uncapped census would
#: put an unbounded dict in every decision payload.
PROVENANCE_LIMIT = 20

#: The key a blank ``source`` is counted under. A recorded outcome that does not
#: say where it came from is a fact about the graph, so it gets a name rather than
#: being dropped into the total or folded in with something attributed.
UNATTRIBUTED = "unattributed"


def read_chain_provenance(deployment) -> dict:
    """Where the outcomes under a deployment's composition came from. One query.

    WHY THIS EXISTS. Every other counter in the payload describes what the chains
    SAID. None of them described who said it, and `source` -- recorded per row
    since the model was written, and serialised per row by the outcome routes --
    was never aggregated anywhere a reader of the graph would meet it. So a
    compositional assurance graph assembled entirely by one operator with a REST
    client read exactly like one fed by real campaign runs.

    That was not hypothetical when this census was written: the only writer of a
    chain outcome was this app's own admin POST route, and the graph could not say
    so. Engines now sign outcomes too (:mod:`assurance.observed_outcomes`), and a
    signed outcome is still not one that watched the effect: Achilles signs the
    gate's authorization check at dispatch. Typed-in input, permit checks and
    watched effects make three different controls, and a reader deciding how much
    weight to give a `held` needs to be able to tell which they are looking at --
    which ``basis_census`` and ``evidence_census`` say, and a census of free-text
    sources cannot.

    THE CENSUS COUNTS EVERY RECORDED OUTCOME, INCLUDING SUPERSEDED ONES, and that
    is deliberate. The question it answers is "what has ever fed this graph",
    which a superseded operator entry answers as much as a standing one. So these
    counts do NOT sum to ``workflows_assessed`` and must not be read as if they
    did -- ``recorded`` is published beside them to say what they do sum to.

    Workflows that are approved but unreported are NOT in the census. The rule
    synthesises those as `not_demonstrated`, and they are the absence of an
    outcome rather than an outcome from nowhere; giving them a provenance entry
    would invent a source for a row that does not exist.
    """
    counts: dict[str, int] = {}
    recorded = 0
    for source in deployment.chain_outcomes.values_list("source", flat=True):
        recorded += 1
        key = (source or "").strip() or UNATTRIBUTED
        counts[key] = counts.get(key, 0) + 1

    # Sorted by count then name so the census is deterministic: an arbitrary tie
    # order would make two reads of one unchanged deployment differ, and a payload
    # that changes without the deployment changing is one a consumer cannot diff.
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    kept = dict(ranked[:PROVENANCE_LIMIT])
    dropped = ranked[PROVENANCE_LIMIT:]

    return {
        "sources": kept,
        # Stated separately and always, in the idiom the outcome route already
        # uses: `len(sources)` is not the number of distinct sources and must not
        # be usable as one.
        "distinct": len(counts),
        "recorded": recorded,
        "truncated": bool(dropped),
        # What the cap hid, as a number rather than silently. A census that
        # dropped rows without saying how many would understate a producer nobody
        # has noticed -- which is the whole thing this census is for.
        "not_shown": sum(count for _, count in dropped),
    }


def read_expected_workflows(deployment) -> list[str] | None:
    """The approved workflow slugs, or ``None`` when the set is not recorded.

    ``None`` and ``[]`` mean genuinely different things to
    :func:`~assurance.composition.compose`, and the database cannot tell them
    apart: no rows might mean "this deployment has no approved workflows" or
    "nobody has written the approved set down yet".

    Only one of those two readings is safe. Treating no rows as a known-empty set
    would mark every recorded outcome unapproved, and would let a deployment with
    no approvals and no chains report a closed, fully covered scope. So no rows
    reads as *not recorded*, and the composition then speaks for the chains it was
    given and nothing else -- which is exactly what `compose` does with ``None``.
    """
    slugs = list(deployment.approved_workflows.values_list("slug", flat=True))
    return slugs or None


def composition_for(deployment, keyring=observed_outcomes.READ_KEYRING) -> Composition:
    """The composition of a deployment's recorded chains. Two queries, no writes."""
    return compose(
        read_chain_outcomes(deployment, keyring),
        expected_workflows=read_expected_workflows(deployment),
    )


def closed_scope(composition: Composition) -> bool:
    """Does this composition speak for the deployment, or only for what it was handed?

    One function because two callers need the same answer and two copies of it
    could disagree: `composition_decision_signal` decides whether ``READY`` may
    contribute, and `_explanation` decides whether an un-narrowed verdict is
    explained by an open scope or by something outside the rule entirely.

    `workflows_unreported == 0` is NOT tested here. An approved workflow with no
    outcome is counted `not_demonstrated`, which carries a floor, so a
    composition with one can never be READY in the first place -- the implication
    is written down in `composition_decision_signal` and pinned by
    `test_ready_already_implies_every_approved_workflow_reported`.
    """
    return (
        composition.workflows_expected is not None
        and composition.workflows_unapproved == 0
    )


def composition_decision_signal(composition: Composition) -> str | None:
    """What a composition contributes to the deployment decision. Pure.

    A FLOOR ALWAYS; ``READY`` ONLY WHEN THE SCOPE IS CLOSED. This is the one
    judgement this module makes, and it exists because `compose` cannot make it.

    :attr:`~assurance.composition.Composition.decision` is ``READY`` whenever no
    surviving outcome sets a floor -- including for a single held chain on a
    deployment with fifty approved workflows nobody wrote down. That is correct
    *of the composition*, which says so in ``workflows_expected`` and in
    :func:`~assurance.composition.explain`. It would be wrong *of the
    deployment*. Handing that ``READY`` straight to
    :func:`assurance.decision.decide` would let one held workflow turn a
    deployment nothing else has assessed into ``ready`` -- the exact silent zero
    `composition.py`'s own docstring refuses, arriving through the wiring instead
    of through the rule.

    So:

    * a floor (anything worse than ``READY``) passes through as-is. It is the
      rule's verdict and nothing here may soften it;
    * ``READY`` passes through only when the composition speaks for a CLOSED
      scope -- the approved set is recorded, every approved workflow reported, and
      no outcome arrived for a workflow off the list. Then "these chains hold" is
      a statement about the deployment and enters as an assessment, exactly as a
      completed clean scan does -- as ``READY_RESTRICTED`` when any workflow holds
      on an authorization check alone, which shows the gate authorized the action
      and not that the effect happened;
    * otherwise ``None``: this signal assessed nothing, which
      :func:`assurance.decision._worse` already knows never to treat as good news.

    An unapproved outcome blocks ``READY`` and is deliberately given NO floor of
    its own. A chain exercising a workflow nobody approved is serious, and it is
    already the drift path's business (:func:`assurance.bom_drift.assess_bom_drift`
    raises a finding, which reaches the decision through
    :func:`assurance.decision._decision_from_findings`). Inventing a second floor
    here would put the platform's answer to one question in two places that could
    disagree, and the disagreement -- not the severity -- is what this codebase
    keeps refusing. It is recorded in `decision_support` either way, so an
    operator sees the count without the decision having to double-count it.
    """
    if composition.decision is None:
        return None
    if composition.decision != READY:
        return composition.decision
    # `workflows_unreported == 0` is NOT tested here, and its absence is the point.
    #
    # It was, until a mutation showed the condition could not fire: deleting it broke
    # nothing. An approved workflow with no outcome is counted `not_demonstrated` by
    # the rule, `not_demonstrated` carries a floor, and a floor means
    # `composition.decision` is not READY -- so the branch above has already
    # returned. Reaching this line with `workflows_expected` set means every approved
    # workflow reported, as an implication rather than as a check.
    #
    # Leaving it in would have been a condition that always holds, which reads as a
    # guard and guards nothing -- the shape this module exists to refuse. It is
    # written down here and pinned by
    # `test_ready_already_implies_every_approved_workflow_reported`, so the
    # simplification stays sound if the rule's flooring ever changes.
    if not closed_scope(composition):
        return None
    # A workflow held on an authorization check alone makes the deployment READY
    # _RESTRICTED at best (owner default, #278). Achilles signs `held` when its
    # permit check passes at dispatch: the authority chain resolves, and nothing in
    # the record shows the effect happened inside it. Counted as READY, a permit
    # check stood in for the exercise the status names. Restricted rather than
    # refused: a chain that resolves is evidence, and nothing here found a fault.
    # Any one such workflow is enough -- the others' effects being seen says
    # nothing about this one's. Only reachable with every approved workflow held,
    # so every name in `authorization_checked` here is a held.
    if composition.authorization_checked:
        return READY_RESTRICTED
    # And so does one signed by an engine this platform has not classified. Its
    # signature verifies, and nothing says what the signer could see -- which is
    # at best a permit check's worth. Left at READY it outranked the permit check
    # it cannot be shown to exceed: weaker evidence, the better decision. Every
    # standing outcome is an approved `held` here, so the census counts exactly
    # the held chains resting on such a signer.
    if composition.evidence_census.get(EVIDENCE_UNCLASSIFIED, 0):
        return READY_RESTRICTED
    return READY


def composition_payload(
    composition: Composition, *, signal: str | None, provenance: dict
) -> dict:
    """The reported shape of a composition. Built here so its two publishers
    cannot drift apart.

    :func:`assurance.decision.decision_support` publishes this block, and so do
    the ingest routes that write the approved set and the chain outcomes. Those
    are separate call sites describing the same thing, and an operator who
    declares three approved workflows, reads ``workflows_expected: 3`` back from
    the write route, then reads ``workflows_expected: null`` from the decision
    route has been told two incompatible things about one deployment. One builder
    is the only way that stays impossible as fields are added.

    ``census`` always carries all four statuses including the zeros, and
    ``workflows_expected: null`` is the honest answer when nobody has recorded the
    approved set -- distinguishable from a recorded set of zero, which is the
    distinction the whole signal turns on.

    ``signal`` is passed in rather than derived. Only the caller knows what the
    composition contributed *to the answer it is publishing*:
    :func:`~assurance.decision.decision_support` nulls it under the operator
    failsafe, because then the failsafe decided and no signal contributed; the
    ingest routes are not making a decision, so they pass what the chains
    currently carry. The census below is never nulled either way -- a paused
    deployment's violated chain is still a violated chain.
    """
    return {
        "signal": signal,
        "rule_decision": composition.decision,
        "census": dict(composition.census),
        "deciding": list(composition.deciding),
        "workflows_assessed": composition.workflows_assessed,
        "workflows_expected": composition.workflows_expected,
        "workflows_unreported": composition.workflows_unreported,
        "workflows_unapproved": composition.workflows_unapproved,
        "superseded": composition.superseded,
        # Beside the status census, not inside it: what a chain SAYS and what the
        # record RESTS ON are two independent distributions.
        "basis_census": dict(composition.basis_census),
        # The number a reader of this payload most needs and cannot compute from the
        # two censuses: standing outcomes whose status claims an exercise while the
        # record does not say one happened. Published with the names, because a count
        # says how much of the graph is assertion and only the names say which part
        # of the deployment to go and exercise.
        "workflows_unexercised": composition.workflows_unexercised,
        "unexercised": list(composition.unexercised),
        # What KIND of evidence the standing outcomes are, every kind including the
        # zeros, and which workflows rest on an authorization check. `demonstrated`
        # in the basis census says a trusted engine signed; this says what that
        # engine could see -- and `observed_effect` is always here, at 0 until
        # something that watches effects signs one.
        "evidence_census": dict(composition.evidence_census),
        "authorization_checked": list(composition.authorization_checked),
        # Which standing outcomes were taken against the route serving now, every
        # reading including the zeros, and which `held`s were not: the chains a
        # route change left to be exercised again, named so a reader can go and do
        # it rather than infer it from a count.
        "route_census": dict(composition.route_census),
        "off_route": list(composition.off_route),
        "explanation": _explanation(composition, signal),
        # Required rather than defaulted, for the reason this builder exists at
        # all: a default would let a new publisher omit provenance and still
        # render a payload, and the omission would read as a graph with nothing
        # to say about its sources rather than as a caller that did not look.
        "provenance": provenance,
    }


def _explanation(composition: Composition, signal: str | None) -> str:
    """The rule's sentence, plus what narrowed it, when those differ.

    `explain` speaks for the rule over the outcomes it was handed. `signal` is
    what this composition CONTRIBUTES, which `composition_decision_signal`
    narrows and a caller may null further. Publishing the first beside the second
    with no sentence joining them put two answers in one payload, and the
    human-readable one was the wrong one:

        signal      = null
        explanation = "... so the rule places the deployment at ready."

    -- for a deployment with a chain outcome for a workflow nobody approved,
    which is precisely the case `workflows_unapproved` exists to make visible. A
    paused deployment read the same way. So when the published signal is not the
    rule's verdict, the sentence says which one reached the answer and why.
    """
    sentence = explain(composition)
    if signal == composition.decision:
        return sentence
    if signal is None and not closed_scope(composition):
        # The rule's verdict was withheld HERE, by the seam, because the
        # composition does not speak for the deployment.
        return (
            f"{sentence} That verdict did NOT reach the deployment decision: this "
            "composition speaks for a scope that is not closed, so it contributed "
            "nothing rather than a verdict."
        )
    if signal is None:
        # The scope IS closed, so it was not this module that withheld the
        # verdict. Something outside the rule nulled it -- the operator failsafe
        # is the one thing that does. Named as an example rather than as a
        # certainty, because this function cannot see the caller's reason and must
        # not invent one: claiming "the scope is not closed" here was exactly that
        # mistake, and it was false for every paused deployment.
        return (
            f"{sentence} That verdict did NOT reach the deployment decision, which "
            "was placed by something outside the chains -- the operator failsafe "
            "nulls every signal."
        )
    if signal == READY_RESTRICTED and composition.decision == READY and composition.authorization_checked:
        return (
            f"{sentence} What reached the deployment decision was ready with "
            f"restrictions: {len(composition.authorization_checked)} workflow(s) hold on an "
            "authorization check alone -- the gate authorized the action at dispatch, "
            "and no record shows the effect happened within that authority."
        )
    unclassified = composition.evidence_census.get(EVIDENCE_UNCLASSIFIED, 0)
    if signal == READY_RESTRICTED and composition.decision == READY and unclassified:
        return (
            f"{sentence} What reached the deployment decision was ready with "
            f"restrictions: {unclassified} workflow(s) hold on the signature of an engine "
            "this platform has not classified, which says who reported the chain and "
            "not what that engine could see."
        )
    return (
        f"{sentence} What reached the deployment decision was {signal}, not the "
        "rule's own verdict."
    )


def composition_signal(deployment) -> str | None:
    """The deployment's composition signal, read from the database."""
    return composition_decision_signal(composition_for(deployment))
