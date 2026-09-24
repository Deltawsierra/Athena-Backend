"""The temporal / INVALIDATES backbone — a change invalidates dependent claims.

SPINE Phase 2, building directly on the Phase 1 Assurance Claims Engine
(:mod:`assurance.claims`). Phase 1 left one cross-version seam: a change in a
claim's ``system_fingerprint`` SUPERSEDES the old version and opens a new one.
This module makes the *obligation that change creates* first-class and honest: a
detected system change **invalidates** the claims that were true of the old state
and **requires a retest** before they may be read as current again.

The mechanism, and why it is honest:

- **Detection is grounded in the fingerprint, not a guess.** A claim is true of
  the inputs its deriver reads; :func:`assurance.fingerprint.claim_input_fingerprints`
  is the stable, timestamp-free identity of exactly those inputs, per claim type
  (:data:`assurance.fingerprint.CLAIM_INPUTS`). A current claim whose bound
  ``input_fingerprint`` no longer equals its current one has drifted — its evidence
  no longer reflects what is running. That, and only that, is what "invalidated"
  means here, and it is decided per claim: a change to an input only one claim
  reads invalidates that claim and no other. A row bound before per-claim
  fingerprints carries none and is compared on the whole
  :func:`assurance.fingerprint.compute_system_fingerprint`, the conservative
  reading.

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
from .fingerprint import (
    CLAIM_INPUTS,
    claim_input_fingerprints,
    claim_state_moved,
    compute_system_fingerprint,
)
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
# Cross-claim propagation — the INVALIDATES relation
# ---------------------------------------------------------------------------

# There used to be a `_CLAIM_DEPENDENCIES` table here, and it was documentation,
# not code: every claim bound to ONE deployment-wide fingerprint, so any change
# co-invalidated every claim and the table could never be exercised. Its own
# comment named the seam -- "when per-claim-type input fingerprints land ... this
# is exactly where propagation plugs in".
#
# They have landed, as :data:`assurance.fingerprint.CLAIM_INPUTS`, and propagation
# did not need a second table after all. Each claim binds to the inputs its
# deriver reads; two claims that rest on a shared input (the asset graph, a
# provider's posture) both move when it moves, and a change to an input only one
# of them reads (the approved boundary, a principal's permissions) moves only
# that one. The relation is the input table read in the other direction, so it
# cannot drift from what the derivers actually read.


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


def _inputs_phrase(claim) -> str:
    """The input families a claim rests on, for a reason a human reads. A row with
    no input fingerprint was bound to the whole system, and says so."""
    if not claim.input_fingerprint:
        return "the whole system state, bound before per-claim fingerprints"
    return ", ".join(CLAIM_INPUTS.get(claim.claim_type, ("the whole system state",)))


def _rederived_since(claim, req) -> bool:
    """Whether a derivation has re-read this version since the requirement was
    opened, and left it reading something other than the STALE mark the
    invalidation put on it."""
    return claim.last_seen > req.opened_at and claim.status != Status.STALE


def resolve_satisfied_requirements(deployment, *, system_fp=None, policy_version=None, now=None, input_fps=None) -> int:
    """Resolve every open retest obligation that a fresh derivation has satisfied.

    An obligation is satisfied when the claim's CURRENT version is bound to the
    inputs in force (:func:`assurance.fingerprint.claim_state_moved`) AND the
    policy in force (``policy_version``), and a fresh
    :func:`assurance.claims.derive_claims` has read it: either a new version it
    opened on the changed state, or -- when the change was reverted -- the same
    version, re-derived after the requirement opened. A claim still bound to the
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
    if input_fps is None:
        input_fps = claim_input_fingerprints(deployment)

    resolved = 0
    open_reqs = RetestRequirement.objects.filter(
        deployment=deployment, resolved_at__isnull=True
    ).select_related("claim")
    for req in open_reqs:
        current = (
            AssuranceClaim.objects.filter(
                deployment=deployment,
                fingerprint=req.claim.fingerprint,
            )
            .current()
            .first()
        )
        # Only a current version bound to the current state AND policy answers the
        # retest — a rebinding that matches both, not just one.
        if (
            current is None
            or claim_state_moved(current, system_fp=system_fp, input_fps=input_fps)
            or current.policy_version != policy_version
        ):
            continue
        if current.pk == req.claim_id and not _rederived_since(current, req):
            # The version the retest was opened on, bound to the current state
            # again because the change was reverted. That alone is a machine no
            # longer flagging drift, not a retest. It answers the retest once a
            # derivation has re-read it after the requirement opened: it used to
            # be excluded outright, so a reverted change left its retest open --
            # and the claim capped at NEEDS_MORE_EVIDENCE -- until some unrelated
            # change happened to supersede it.
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
            Deployment.objects.prefetch_related(
                "assets__provider__assertions", "declared_components"
            )
            .select_related("data_boundary")
            .get(pk=deployment.pk)
        )
        system_fp = compute_system_fingerprint(dep)
        input_fps = claim_input_fingerprints(dep)
        policy_version = _current_policy_version(dep)

        invalidated = 0
        opened = 0
        currents = list(
            AssuranceClaim.objects.filter(deployment=dep).current()
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
            state_drift = claim_state_moved(claim, system_fp=system_fp, input_fps=input_fps)
            policy_drift = claim.policy_version != policy_version
            if not (state_drift or policy_drift):
                continue
            invalidated += 1
            if not _has_open_requirement(dep, claim):
                inputs = _inputs_phrase(claim)
                if state_drift and policy_drift:
                    reason = f"The inputs this claim rests on ({inputs}) and the assurance policy both changed; the state and the policy this claim was true of no longer match the deployment."
                elif state_drift:
                    reason = f"The inputs this claim rests on ({inputs}) changed; the state this claim was true of no longer matches the deployment."
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
            dep, system_fp=system_fp, policy_version=policy_version, now=now, input_fps=input_fps
        )
        return {"invalidated": invalidated, "retests_opened": opened, "retests_resolved": resolved}
