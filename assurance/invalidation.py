"""The temporal / INVALIDATES backbone — a change invalidates dependent claims.

SPINE Phase 2, building directly on the Phase 1 Assurance Claims Engine
(:mod:`assurance.claims`). Phase 1 left one cross-version seam: a change in a
claim's ``system_fingerprint`` SUPERSEDES the old version and opens a new one.
This module makes the *obligation that change creates* first-class and honest: a
detected system change **invalidates** the claims that were true of the old state
and **requires a retest** before they may be read as current again.

The mechanism, and why it is honest:

- **Detection is grounded in the fingerprint, not a guess.** A claim is true of a
  system state; :func:`assurance.fingerprint.compute_system_fingerprint` is the
  stable, timestamp-free identity of that state. A current claim whose bound
  ``system_fingerprint`` no longer equals the deployment's current fingerprint has
  drifted — its evidence no longer reflects what is running. That, and only that,
  is what "invalidated" means here. The human-readable ``invalidation_conditions``
  a claim carries (a region change, an added permission, a changed boundary) are
  exactly the inputs the system fingerprint is computed over, so a fingerprint
  drift *is* one of those conditions having fired — the two never disagree.

- **Invalidation never reads as a pass.** A drifted claim is not left reading
  VERIFIED/SUPPORTED while a retest is pending; it is moved *away* from a pass to
  STALE ("a retest is due") through the same Phase 1 status seam
  (:func:`assurance.claims._mark_stale`), and never to an invented "invalid but
  passing" state. A live CONTRADICTED claim is not softened to STALE (that would
  read as *less* wrong); it keeps its status but still owes a retest.

- **The obligation is durable, attributed, and idempotent.** Each invalidation
  opens a :class:`~assurance.models.RetestRequirement` with a reason and an actor
  (null = the machine), and writes a :class:`~assurance.models.ClaimEvent` so the
  claim's own lifecycle carries the fact. Re-running the engine never opens a
  duplicate for the same open obligation (the identity-level guard below plus the
  model's partial unique constraint).

- **Resolution is earned, not assumed.** A requirement is resolved ONLY when a
  fresh :func:`assurance.claims.derive_claims` produces a new current version bound
  to the changed state — a machine no longer flagging drift is not proof of a
  retest; a re-derivation that rebinds is. That wiring lives in
  :func:`resolve_satisfied_requirements`, which ``derive_claims`` calls after it
  reconciles, and which this engine also calls so a check reports what it settled.

A human REVOKED claim is a withdrawal and is never invalidated, never marked, and
never given a retest obligation.
"""

from __future__ import annotations

from django.db import transaction
from django.utils import timezone

from . import observability as obs
from .claims import Status
from .fingerprint import compute_system_fingerprint
from .fingerprint import policy_version as _current_policy_version
from .models import AssuranceClaim, ClaimEvent, Deployment, RetestRequirement

ClaimType = AssuranceClaim.ClaimType

# The statuses a drifted claim is NOT moved to STALE from — mirrors
# ``assurance.claims._mark_stale``'s skip set. A live CONTRADICTED claim is not
# softened to "stale" (that would read as less wrong); REVOKED is a terminal human
# withdrawal; STALE/SUPERSEDED are already not a pass. A claim in any of these
# still owes a retest (the obligation is opened regardless, except for REVOKED),
# but its *status* is left honest rather than moved.
_STALE_SKIP = frozenset({Status.CONTRADICTED, Status.REVOKED, Status.STALE, Status.SUPERSEDED})


# ---------------------------------------------------------------------------
# Cross-claim propagation — the INVALIDATES edge (explicit, minimal, honest)
# ---------------------------------------------------------------------------

# The declared dependency edges between claim types: "a change to the inputs of
# the KEY claim type should also require a retest of the VALUE claim types,
# because they rest on those same inputs." This is the small, readable
# INVALIDATES table the roadmap asks for — NOT a general graph engine.
#
#   - AI_BOM rests on the provider/component supply chain. A change there also
#     bears on DATA_BOUNDARY (which providers data reaches) and EFFECTIVE_ACCESS
#     (which components a principal can reach).
#   - DATA_BOUNDARY rests on the approved boundary + provider postures; a change
#     bears on the supply-chain reading AI_BOM makes.
#   - EFFECTIVE_ACCESS rests on the asset/permission graph.
#
# IMPORTANT — why this table is documentation today, not an extra code path:
# every claim in Phase 1 binds to the SAME deployment-wide
# ``compute_system_fingerprint`` (models: one ``system_fp`` for all derivers), so
# ANY change to the asset / provider / boundary graph moves the fingerprint of
# EVERY current claim at once. Single-claim invalidation therefore ALREADY opens a
# retest on each dependent claim — the propagation is a consequence of the shared
# fingerprint, and opening additional requirements off this map would be
# redundant, not a distinct edge. Rather than fake an edge the current inputs make
# indistinguishable from co-invalidation, this table is left as the explicit,
# commented SEAM: when per-claim-type input fingerprints land (so a change can
# move one claim's fingerprint without the others'), this is exactly where
# propagation plugs in — iterate the directly-invalidated types, union their
# dependents, and open requirements on those dependents' current claims too.
_CLAIM_DEPENDENCIES: dict[str, frozenset[str]] = {
    ClaimType.AI_BOM.value: frozenset(
        {ClaimType.DATA_BOUNDARY.value, ClaimType.EFFECTIVE_ACCESS.value}
    ),
    ClaimType.DATA_BOUNDARY.value: frozenset({ClaimType.AI_BOM.value}),
    ClaimType.EFFECTIVE_ACCESS.value: frozenset(),
}


# ---------------------------------------------------------------------------
# Opening + resolving obligations
# ---------------------------------------------------------------------------


def _has_open_requirement(deployment, claim) -> bool:
    """Whether an OPEN retest obligation already exists for this claim's identity.

    Keyed on the stable identity ``fingerprint`` (not the version pk), so an
    obligation opened against an earlier version still counts — re-running the
    engine never opens a second obligation for the same open drift."""
    return RetestRequirement.objects.filter(
        deployment=deployment,
        claim__fingerprint=claim.fingerprint,
        resolved_at__isnull=True,
    ).exists()


def _open_requirement(deployment, claim, *, system_fp, now, actor, reason) -> RetestRequirement:
    """Open a retest obligation for ``claim`` and attribute it on the claim's own
    lifecycle (a same-status ``ClaimEvent`` noting the invalidation), mirroring how
    every other claim status seam writes a ClaimEvent."""
    req = RetestRequirement.objects.create(
        deployment=deployment,
        claim=claim,
        reason=reason,
        triggering_system_fingerprint=system_fp,
        actor=actor,
        opened_at=now,
    )
    ClaimEvent.objects.create(
        claim=claim,
        from_status=claim.status,
        to_status=claim.status,
        actor=actor,
        note=f"Retest required: {reason}",
    )
    return req


def _mark_stale(claim, now) -> None:
    """Move a drifted claim away from a pass to STALE ("a retest is due"), through
    the same status seam Phase 1 uses, and attribute it. Skips a claim whose status
    must not be softened (see ``_STALE_SKIP``)."""
    if claim.status in _STALE_SKIP:
        return
    old_status = claim.status
    claim.status = Status.STALE
    claim.save(update_fields=["status", "updated_at"])
    ClaimEvent.objects.create(
        claim=claim,
        from_status=old_status,
        to_status=Status.STALE,
        actor=None,
        note="System state changed; claim invalidated, retest due.",
    )


def resolve_satisfied_requirements(deployment, *, system_fp=None, policy_version=None, now=None) -> int:
    """Resolve every open retest obligation that a fresh derivation has satisfied.

    An obligation is satisfied when the claim's CURRENT version is bound to the
    deployment's current system state (``system_fingerprint == system_fp``) AND the
    policy in force (``policy_version``) and is a *different* version than the one
    that was invalidated — i.e. a fresh :func:`assurance.claims.derive_claims` has
    rebound the claim to the changed state and policy. A claim still bound to the
    old state or the old policy (the version that drifted, whatever its status) does
    not satisfy anything: a machine no longer flagging drift is not a retest, a
    rebinding re-derivation is. Records ``resolving_claim`` and ``resolved_at`` and
    returns how many it resolved.

    Called by ``derive_claims`` after it reconciles (so a re-derive settles the
    obligations it answered) and by :func:`check_invalidations` (so a check reports
    what it settled, e.g. after a change was reverted)."""
    now = now or timezone.now()
    if system_fp is None:
        system_fp = compute_system_fingerprint(deployment)
    if policy_version is None:
        policy_version = _current_policy_version(deployment)

    resolved = 0
    open_reqs = RetestRequirement.objects.filter(
        deployment=deployment, resolved_at__isnull=True
    ).select_related("claim")
    for req in open_reqs:
        current = (
            AssuranceClaim.objects.filter(
                deployment=deployment,
                fingerprint=req.claim.fingerprint,
                valid_to__isnull=True,
            )
            .exclude(pk=req.claim_id)
            .first()
        )
        # Only a NEW current version bound to the current state AND policy answers
        # the retest — a rebinding that matches both, not just one.
        if current is None or current.system_fingerprint != system_fp or current.policy_version != policy_version:
            continue
        req.resolving_claim = current
        req.resolved_at = now
        req.save(update_fields=["resolving_claim", "resolved_at", "updated_at"])
        ClaimEvent.objects.create(
            claim=current,
            from_status=current.status,
            to_status=current.status,
            actor=None,
            note="Retest requirement satisfied by re-derivation to current state.",
        )
        resolved += 1
    return resolved


@transaction.atomic
def check_invalidations(deployment, *, actor=None, now=None) -> dict:
    """Run the invalidation engine over a deployment and reconcile its retest
    obligations. Pure of any assessment recomputation — it reads the stored claims
    and the current system fingerprint only.

    For each CURRENT claim (``valid_to`` null) that is not a human REVOKED
    withdrawal: if its bound ``system_fingerprint`` no longer equals the
    deployment's current fingerprint, OR its bound ``policy_version`` no longer
    equals the policy in force, the claim has drifted and is *invalidated* — a
    retest obligation is opened (idempotently, once per claim identity), the claim
    is moved away from a pass to STALE, and the fact is attributed on the claim's
    lifecycle. Binding a claim to the policy it was assessed under is what lets a
    *policy* change (not just a system change) invalidate a decision. It then
    resolves any open obligation a prior re-derivation has already satisfied.
    Idempotent and transactional.

    Returns ``{invalidated, retests_opened, retests_resolved}``:
      - ``invalidated`` — current, non-REVOKED claims whose bound state OR policy has drifted;
      - ``retests_opened`` — NEW obligations opened (0 on an idempotent re-run);
      - ``retests_resolved`` — obligations a rebinding re-derivation has satisfied.

    Query-light: the current fingerprint and policy pin are computed once over a
    prefetched deployment, and the claims are read in one scoped query."""
    with obs.span(obs.PLAN, component="check_invalidations", subject=str(deployment.pk)):
        now = now or timezone.now()
        dep = (
            Deployment.objects.prefetch_related("assets__provider__assertions")
            .select_related("data_boundary")
            .get(pk=deployment.pk)
        )
        system_fp = compute_system_fingerprint(dep)
        policy_version = _current_policy_version(dep)

        invalidated = 0
        opened = 0
        currents = list(
            AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True)
        )
        for claim in currents:
            # A human REVOKED claim is a withdrawal — never invalidated, marked, or
            # given a retest obligation.
            if claim.status == Status.REVOKED:
                continue
            # Drift is the signal: the state the claim was true of, or the policy it was
            # judged under, no longer matches what is in force. (See the module
            # docstring on why this is the honest, fingerprint-grounded definition of
            # "invalidated".)
            state_drift = claim.system_fingerprint != system_fp
            policy_drift = claim.policy_version != policy_version
            if not (state_drift or policy_drift):
                continue
            invalidated += 1
            if not _has_open_requirement(dep, claim):
                if state_drift and policy_drift:
                    reason = "System fingerprint and assurance policy both changed; the state and the policy this claim was true of no longer match the deployment."
                elif state_drift:
                    reason = "System fingerprint changed; the state this claim was true of no longer matches the deployment."
                else:
                    reason = "Assurance policy changed; the policy this claim was assessed under is no longer the policy in force."
                _open_requirement(
                    dep,
                    claim,
                    system_fp=system_fp,
                    now=now,
                    actor=actor,
                    reason=reason,
                )
                opened += 1
            # Move the drifted claim away from a pass (STALE), never to an invented
            # "invalid but passing" state.
            _mark_stale(claim, now)

        resolved = resolve_satisfied_requirements(
            dep, system_fp=system_fp, policy_version=policy_version, now=now
        )
        return {"invalidated": invalidated, "retests_opened": opened, "retests_resolved": resolved}
