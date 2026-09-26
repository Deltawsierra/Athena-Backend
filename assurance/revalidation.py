"""The targeted revalidation planner — SPINE Stage 1D.

When a change invalidates a claim (Phase 2 marks it stale and opens a retest
obligation), the question a customer actually needs answered is *not* "re-run the
whole assessment" but "what exactly must be re-run because of this change, and what
stays current?". Re-running everything on every change makes continuous assurance
economically impractical; naming the minimal set makes it practical.

This module answers that. It is a PURE, deterministic computed view over the
deployment's current claims and open retest obligations — no I/O beyond the read,
no mutation, no timestamps. For each current claim whose bound state has drifted
(an open retest obligation), expired (STALE), or been falsified (CONTRADICTED) it
names:

- the **Athena reassessment** that re-derives that claim (so fresh evidence
  replaces the stale claim), reached by POSTing ``recompute-claims``; and
- the **Achilles capability areas** whose behavioural tests should be re-run to
  regather the evidence the claim rests on — named for the Achilles engine to
  execute (this module plans, it does not run traffic).

Everything else — the supported/verified claims with no open obligation — is listed
as *still current*: explicitly NOT re-run. Restoring a claim requires FRESH
evidence, not merely the absence of the original finding, which is why the plan
points at re-derivation and behavioural retests rather than declaring the claim
resolved on its own.

The mapping from a claim type to its Athena assessment and Achilles capabilities is
a small, explicit, commented table — the same discipline the rest of the SPINE
layer keeps — not a general inference engine.
"""

from __future__ import annotations

from . import observability as obs
from .fingerprint import compute_system_fingerprint
from .models import LATENT_HOLDING_STATES, AssuranceClaim, LatentCondition, RetestRequirement
from .workflow_chains import composition_for, read_expected_workflows

ClaimType = AssuranceClaim.ClaimType
Status = AssuranceClaim.ClaimStatus

# The Athena assessment that re-derives each claim type. Re-running it (via the
# deployment's ``recompute-claims`` action, which calls ``derive_claims``) is what
# rebinds the claim to the current state and replaces the stale version.
_ATHENA_REASSESSMENT: dict[str, str] = {
    ClaimType.DATA_BOUNDARY.value: "data-boundary assessment (assess_boundary)",
    ClaimType.EFFECTIVE_ACCESS.value: "effective-access assessment (assess_effective_access)",
    ClaimType.AI_BOM.value: "AI-BOM assessment (build_ai_bom)",
}

# The Achilles capability areas whose behavioural tests regather the evidence a
# claim type rests on. Named for the Achilles engine to run (see the Achilles
# policy-binding layer). AI-BOM is a supply-chain *inventory* claim: it is
# revalidated by re-deriving the graph, not by a behavioural attack, so it has no
# Achilles capabilities — surfaced honestly as an empty list, not a fabricated one.
_ACHILLES_CAPABILITIES: dict[str, tuple[str, ...]] = {
    ClaimType.DATA_BOUNDARY.value: ("RAG Leakage",),
    ClaimType.EFFECTIVE_ACCESS.value: ("Permission Boundary", "Agent / Tool Misuse"),
    ClaimType.AI_BOM.value: (),
}


def _reason_for(claim: AssuranceClaim, requirement: RetestRequirement | None, holding=None) -> str:
    """Why this claim needs revalidating: the open retest obligation's own reason
    when a change opened one, else the declared condition that fired on it and holds
    it (``holding``), else the honest reason its status implies."""
    if requirement is not None:
        return requirement.reason
    if holding is not None:
        return (
            f"A declared condition fired on this claim and still holds it: {holding.description} "
            f"({holding.get_kind_display()}; subject {holding.subject!r}). Observed when it fired: "
            f"{holding.fired_observation or '(not recorded)'}. It is held at stale until the "
            "condition is found back at its baseline or a person withdraws it."
        )
    if claim.status == Status.CONTRADICTED:
        return "The current state contradicts this claim; fresh evidence is required to restore or retire it."
    if claim.status == Status.STALE:
        return "The claim's evidence has expired; a retest is due before it can be read as current."
    return "The claim requires fresh evidence."


def _claim_work(claim: AssuranceClaim, requirement: RetestRequirement | None, holding=None) -> dict:
    """The minimal revalidation work for one drifted/stale/contradicted/held claim."""
    reassessment = _ATHENA_REASSESSMENT.get(claim.claim_type)
    return {
        "claim_uuid": str(claim.uuid),
        "claim_type": claim.claim_type,
        "statement": claim.statement,
        "status": claim.status,
        "reason": _reason_for(claim, requirement, holding),
        "retest_requirement_uuid": str(requirement.uuid) if requirement is not None else None,
        # The minimal Athena work: re-derive exactly this claim's assessment.
        "athena_reassessments": [reassessment] if reassessment else [],
        # The behavioural retests, for the Achilles engine to run.
        "achilles_capabilities": list(_ACHILLES_CAPABILITIES.get(claim.claim_type, ())),
    }


# A claim in one of these states is not established: UNKNOWN never had evidence,
# PARTIALLY_VERIFIED was established over a graph part of which could not be read.
# Neither is drift, so neither belongs in `required` -- re-running the same
# assessment over the same inventory produces the same hole. Both are real work
# to reach assurance, which is what `outstanding_unknowns` is for.
_NOT_ESTABLISHED = frozenset({Status.UNKNOWN, Status.PARTIALLY_VERIFIED})


def plan_revalidation(deployment) -> dict:
    """The minimal revalidation plan for a deployment (Stage 1D).

    For each CURRENT claim (``valid_to`` null, excluding human REVOKED withdrawals):

    - **required** — the claim has an open retest obligation, is STALE, is
      CONTRADICTED, or a FIRED latent condition holds it (whatever its row reads):
      name the exact Athena reassessment and Achilles capability areas to re-run.
      This is the change-driven minimal set.
    - **outstanding_unknowns** — the claim is UNKNOWN or PARTIALLY_VERIFIED: a
      pre-existing gap in what could be established, surfaced as work to reach
      assurance but distinct from what *this* change invalidated. Each entry
      carries its ``status``, so the two cases stay distinguishable: UNKNOWN
      never had evidence, PARTIALLY_VERIFIED was established over a graph part
      of which could not be read.
    - **still_current** — the claim is SUPPORTED or VERIFIED with no open
      obligation: explicitly NOT re-run.

    PARTIALLY_VERIFIED belongs in the second bucket, not the third. It used to
    fall through to ``still_current`` — whose contract, two lines up, is
    "supported/verified with no open obligation" — and the plan's note then said
    "every current claim is supported or verified ... Nothing needs to be
    re-run." Both statements were false about it, and the unplaceable reference
    it records is the one item in the whole plan a person could actually go and
    chase. A plan that tells an operator there is nothing to do, about the claim
    that exists to say part of the graph could not be read, is worse than no
    plan.

    Pure and deterministic: rules are read once, matched to their open obligations by
    stable claim identity (fingerprint), and the required list is sorted by claim
    type. To recompute the current fingerprint and read the graph in a fixed number
    of queries, pass a deployment the caller has prefetched
    (``assets__provider__assertions``, ``data_boundary``).
    """
    with obs.span(obs.PLAN, component="plan_revalidation", subject=str(deployment.pk)):
        current = list(
            deployment.assurance_claims.current().exclude(status=Status.REVOKED)
        )

        # Map each OPEN retest obligation to the claim identity it is about. A retest is
        # opened against the version that drifted; its identity fingerprint matches the
        # current version, so a re-derivation that rebinds resolves it (Phase 2).
        open_reqs: dict[str, RetestRequirement] = {}
        for req in (
            RetestRequirement.objects.filter(deployment=deployment, resolved_at__isnull=True)
            .select_related("claim")
            .order_by("opened_at")
        ):
            open_reqs.setdefault(req.claim.fingerprint, req)

        required: list[dict] = []
        outstanding_unknowns: list[dict] = []
        still_current: list[dict] = []

        # And each claim a FIRED latent condition holds, on any version of it: it is
        # work until the condition re-arms or a person withdraws it, whatever the
        # claim row reads -- the decision reads it the same way.
        holding: dict[str, LatentCondition] = {}
        for condition in (
            LatentCondition.objects.filter(deployment=deployment, state__in=LATENT_HOLDING_STATES)
            .select_related("claim")
            .order_by("pk")
        ):
            holding.setdefault(condition.claim.fingerprint, condition)

        for claim in current:
            requirement = open_reqs.get(claim.fingerprint)
            held = holding.get(claim.fingerprint)
            drifted = (
                requirement is not None
                or held is not None
                or claim.status in (Status.CONTRADICTED, Status.STALE)
            )
            if drifted:
                required.append(_claim_work(claim, requirement, held))
            elif claim.status in _NOT_ESTABLISHED:
                outstanding_unknowns.append(
                    {
                        "claim_uuid": str(claim.uuid),
                        "claim_type": claim.claim_type,
                        "statement": claim.statement,
                        "status": claim.status,
                    }
                )
            else:
                still_current.append(
                    {
                        "claim_uuid": str(claim.uuid),
                        "claim_type": claim.claim_type,
                        "status": claim.status,
                    }
                )

        required.sort(key=lambda w: (w["claim_type"], w["claim_uuid"]))

        # THE CHAINS A ROUTE CHANGE LEFT UNEXERCISED. No claim reads the served
        # route, so the claim loop above cannot see a model swap or a tokenizer
        # change -- and the evidence such a change does invalidate is the chain
        # outcomes, each an exercise of the route that served it. Each standing
        # `held` taken against another route (or one nothing recorded) is work: run
        # that workflow's chain again against what serves now.
        composition = composition_for(deployment)
        approved = set(read_expected_workflows(deployment) or ())
        workflows = [
            {
                "workflow": workflow,
                # Only an approved workflow's chain holds the decision back; the
                # others are still evidence gone stale, and are listed as such.
                "approved": workflow in approved,
                "reason": (
                    "a held for it was taken against a served route that is not the one "
                    "serving now, or one nothing recorded, and nothing as strong has been "
                    "taken against the route that serves; exercise the chain again against it"
                ),
            }
            for workflow in composition.off_route
        ]

        if required:
            note = (
                f"{len(required)} claim(s) need revalidation because of a change, an expiry, or a "
                f"contradiction; {len(still_current)} remain current and need not be re-run. Re-run "
                "only the named Athena reassessment(s) and Achilles capability area(s), then recompute "
                "claims to rebind the deployment to its current state."
            )
        elif outstanding_unknowns:
            # Not "nothing to do". Nothing DRIFTED, which is a different
            # statement, and saying the first when only the second is true turns
            # a known gap into a clean bill of health.
            note = (
                f"No claim needs revalidation: nothing drifted, expired or was contradicted. "
                f"But {len(outstanding_unknowns)} current claim(s) are not fully established — "
                "re-running an assessment will not close them, because the gap is in what could "
                "be read, not in when it was read. See each claim's supporting summary for what "
                "it could not establish."
            )
        else:
            note = (
                "No claim needs revalidation: every current claim is supported or verified with no open "
                "retest obligation. Nothing needs to be re-run."
            )
        if workflows:
            # Never "nothing to re-run" beside a chain that ran against another
            # route: every claim can be current while the chains are not, because no
            # claim reads the route and every chain exercised one.
            chains = (
                f"{len(workflows)} workflow chain(s) were exercised against a served route "
                "that no longer serves, or one nothing recorded: exercise each named chain "
                "again against the route that serves."
            )
            if required or outstanding_unknowns:
                note = f"{note} Separately, {chains}"
            else:
                note = f"No claim needs revalidation, but {chains} Nothing else needs re-running."

        return {
            "deployment_uuid": str(deployment.uuid),
            "system_fingerprint": compute_system_fingerprint(deployment),
            "summary": {
                "required": len(required),
                "still_current": len(still_current),
                "outstanding_unknowns": len(outstanding_unknowns),
                "workflows_to_exercise": len(workflows),
            },
            "recompute_action": "POST deployments/{uuid}/recompute-claims to re-derive after the named retests run.",
            "required": required,
            "outstanding_unknowns": outstanding_unknowns,
            "still_current": still_current,
            "workflows_to_exercise": workflows,
            "note": note,
        }
