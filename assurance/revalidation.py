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
from .models import AssuranceClaim, RetestRequirement

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


def _reason_for(claim: AssuranceClaim, requirement: RetestRequirement | None) -> str:
    """Why this claim needs revalidating: the open retest obligation's own reason
    when a change opened one, else the honest reason its status implies."""
    if requirement is not None:
        return requirement.reason
    if claim.status == Status.CONTRADICTED:
        return "The current state contradicts this claim; fresh evidence is required to restore or retire it."
    if claim.status == Status.STALE:
        return "The claim's evidence has expired; a retest is due before it can be read as current."
    return "The claim requires fresh evidence."


def _claim_work(claim: AssuranceClaim, requirement: RetestRequirement | None) -> dict:
    """The minimal revalidation work for one drifted/stale/contradicted claim."""
    reassessment = _ATHENA_REASSESSMENT.get(claim.claim_type)
    return {
        "claim_uuid": str(claim.uuid),
        "claim_type": claim.claim_type,
        "statement": claim.statement,
        "status": claim.status,
        "reason": _reason_for(claim, requirement),
        "retest_requirement_uuid": str(requirement.uuid) if requirement is not None else None,
        # The minimal Athena work: re-derive exactly this claim's assessment.
        "athena_reassessments": [reassessment] if reassessment else [],
        # The behavioural retests, for the Achilles engine to run.
        "achilles_capabilities": list(_ACHILLES_CAPABILITIES.get(claim.claim_type, ())),
    }


def plan_revalidation(deployment) -> dict:
    """The minimal revalidation plan for a deployment (Stage 1D).

    For each CURRENT claim (``valid_to`` null, excluding human REVOKED withdrawals):

    - **required** — the claim has an open retest obligation, is STALE, or is
      CONTRADICTED: name the exact Athena reassessment and Achilles capability areas
      to re-run. This is the change-driven minimal set.
    - **outstanding_unknowns** — the claim is UNKNOWN: a pre-existing gap (never had
      evidence), surfaced as work to reach assurance but distinct from what *this*
      change invalidated.
    - **still_current** — the claim is supported/verified with no open obligation:
      explicitly NOT re-run.

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

        for claim in current:
            requirement = open_reqs.get(claim.fingerprint)
            drifted = requirement is not None or claim.status in (Status.CONTRADICTED, Status.STALE)
            if drifted:
                required.append(_claim_work(claim, requirement))
            elif claim.status == Status.UNKNOWN:
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

        if required:
            note = (
                f"{len(required)} claim(s) need revalidation because of a change, an expiry, or a "
                f"contradiction; {len(still_current)} remain current and need not be re-run. Re-run "
                "only the named Athena reassessment(s) and Achilles capability area(s), then recompute "
                "claims to rebind the deployment to its current state."
            )
        else:
            note = (
                "No claim needs revalidation: every current claim is supported or verified with no open "
                "retest obligation. Nothing needs to be re-run."
            )

        return {
            "deployment_uuid": str(deployment.uuid),
            "system_fingerprint": compute_system_fingerprint(deployment),
            "summary": {
                "required": len(required),
                "still_current": len(still_current),
                "outstanding_unknowns": len(outstanding_unknowns),
            },
            "recompute_action": "POST deployments/{uuid}/recompute-claims to re-derive after the named retests run.",
            "required": required,
            "outstanding_unknowns": outstanding_unknowns,
            "still_current": still_current,
            "note": note,
        }
