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

Two queries, no writes, no clock.
"""

from __future__ import annotations

from .composition import READY, ChainOutcome, Composition, compose, explain


def read_chain_outcomes(deployment) -> list[ChainOutcome]:
    """Every recorded chain outcome for a deployment, as the rule's own type.

    The conversion is deliberately TOTAL: every row becomes a
    :class:`~assurance.composition.ChainOutcome`, including rows naming a
    workflow nobody approved. Filtering those out here is the one edit that would
    make :attr:`~assurance.composition.Composition.workflows_unapproved` a zero
    no input can reach -- and that counter is how a chain exercising an
    unapproved workflow becomes visible at all.
    """
    return [
        ChainOutcome(
            workflow=row.workflow,
            status=row.status,
            observed_at=row.observed_at,
        )
        for row in deployment.chain_outcomes.all()
    ]


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


def composition_for(deployment) -> Composition:
    """The composition of a deployment's recorded chains. Two queries, no writes."""
    return compose(
        read_chain_outcomes(deployment),
        expected_workflows=read_expected_workflows(deployment),
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
      completed clean scan does;
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
    closed_scope = (
        composition.workflows_expected is not None
        and composition.workflows_unapproved == 0
    )
    return READY if closed_scope else None


def composition_payload(composition: Composition, *, signal: str | None) -> dict:
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
        "explanation": explain(composition),
    }


def composition_signal(deployment) -> str | None:
    """The deployment's composition signal, read from the database."""
    return composition_decision_signal(composition_for(deployment))
