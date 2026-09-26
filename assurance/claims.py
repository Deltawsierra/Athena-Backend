"""The Assurance Claims Engine — deriving, versioning, and moving claims (SPINE).

An :class:`~assurance.models.AssuranceClaim` is a positive, falsifiable statement
bound to a system state. This module is where those statements are *produced* from
the assessments the rest of the package already computes, *versioned* honestly when
the system state changes, and *moved* through their lifecycle under attribution.

Three parts:

- **Derivers** — one pure function per :class:`ClaimType`, each reading a shipped
  assessment (:func:`assurance.boundary.assess_boundary`,
  :func:`assurance.access.assess_effective_access`,
  :func:`assurance.bom.build_ai_bom`) and reducing it to a claim's honest fields.
  Every deriver keeps the six honesty invariants: it NEVER returns VERIFIED unless
  the evidence is configuration/technically verified AND there is no
  contradiction/unknown; a declared fact that breaks a declared rule is
  CONTRADICTED; an undeclared/unassessed input is UNKNOWN; ``confidence`` is
  ``None`` for UNKNOWN (never ``0``); ``evidence_class`` is the weakest supporting
  class; and a claim resting on vendor assertions caps at SUPPORTED.

- **:func:`derive_claims`** — the idempotent, transactional reconciler. For each
  deriver it computes the stable identity fingerprint and the current system
  fingerprint, finds the current version, and: creates it if none exists; refreshes
  the machine fields in place when the system state is unchanged (preserving human
  fields and never overwriting a human REVOKED); or SUPERSEDES the old version and
  opens a new one when the inputs that claim rests on have changed. It also marks a current,
  non-contradicted claim STALE once its evidence expires — never toward a pass.

- **:func:`apply_claim_transition`** — the attributed lifecycle state machine,
  mirroring :mod:`assurance.remediation`. It refuses illegal jumps, refuses to let
  STALE/SUPERSEDED be a human target, and HARD-refuses any move into VERIFIED that
  is not backed by configuration/technically-verified, non-vendor evidence.

The input-fingerprint-change → supersede seam is the cross-version mechanism
here. Each claim binds to a fingerprint of the inputs ITS deriver reads
(:data:`assurance.fingerprint.CLAIM_INPUTS`), so a change versions exactly the
claims that rest on it; the deployment-wide system fingerprint is still recorded on
every version, and still decides for a row bound before per-claim fingerprints; the temporal INVALIDATES backbone that turns a state change into an
attributed, durable *retest obligation* on the affected claims lives in
:mod:`assurance.invalidation` (SPINE Phase 2), which extends this module. Its one
tie-back into :func:`derive_claims` is at the end of the reconciler: once a
re-derivation has rebound a claim to the changed state, any open retest obligation
that rebinding satisfies is resolved (:func:`assurance.invalidation.resolve_satisfied_requirements`).
"""

from __future__ import annotations

import hashlib
from datetime import timedelta

from django.db import models, transaction
from django.utils import timezone

from . import observability as obs
from .access import assess_effective_access
from .bom import build_ai_bom
from .bom_drift import assess_bom_drift
from .boundary import assess_boundary
from .capability import RISK_HIGH
from .change import EVIDENCE_TTL_DAYS, age_days
from .fingerprint import (
    claim_input_fingerprints,
    claim_state_moved,
    compute_system_fingerprint,
    policy_version,
)
from .models import (
    LATENT_HOLDING_STATES,
    LATENT_LIVE_STATES,
    AssuranceClaim,
    ClaimEvent,
    Deployment,
    EvidenceClass,
    LatentCondition,
    evidence_strength,
)
from .legal import ruling_for_next_version
from .receipt import build_assurance_receipt

Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType

# The evidence grades strong enough to back a VERIFIED claim (invariant 3/4). A
# claim whose weakest supporting evidence is not one of these can never read
# VERIFIED, whether the machine derived it or a human tried to hand-verify it.
_VERIFIED_GRADE = frozenset(
    {EvidenceClass.TECHNICALLY_VERIFIED.value, EvidenceClass.CONFIGURATION_VERIFIED.value}
)

# The access-gap types whose HIGH-risk presence contradicts a least-privilege
# claim (as opposed to merely capping it at SUPPORTED).
_CONTRADICTING_ACCESS_GAPS = frozenset({"privileged_access", "over_broad", "ungoverned_reach"})


# ---------------------------------------------------------------------------
# Shared honesty helpers
# ---------------------------------------------------------------------------


def _grade_pool(classes: list[str]) -> tuple[str, str | None, bool]:
    """Reduce a pool of evidence classes to ``(weakest, strongest, vendor_asserted)``.

    ``weakest`` is the honest confidence floor (invariant 5). ``vendor_asserted`` is
    True when even the *strongest* supporting evidence is vendor-asserted-or-weaker
    (invariant 4) — including the empty pool, where nothing verified backs the
    claim. An empty pool reads as UNKNOWN with no strongest evidence."""
    if not classes:
        return EvidenceClass.UNKNOWN.value, None, True
    weakest = max(classes, key=evidence_strength)
    strongest = min(classes, key=evidence_strength)
    vendor = evidence_strength(strongest) >= evidence_strength(EvidenceClass.VENDOR_ASSERTED.value)
    return weakest, strongest, vendor


def _confidence(status: str, evidence_class: str) -> float | None:
    """Confidence in the positive claim, derived from how strongly it is supported.

    ``None`` whenever the claim is not standing on supporting evidence — for
    UNKNOWN (invariant 2: never ``0`` as a pass) and for CONTRADICTED (a false
    statement has no supporting confidence). Otherwise a value in (0, 1] that falls
    as the weakest supporting evidence weakens — never zero."""
    if status not in (Status.SUPPORTED, Status.VERIFIED, Status.PARTIALLY_VERIFIED):
        return None
    return round(max(0.1, 1.0 - 0.12 * evidence_strength(evidence_class)), 2)


def _clip(text: str, limit: int = 500) -> str:
    """Bound a summary's length so a claim carries an honest, readable digest, never
    an unbounded dump. (Inputs here are already non-sensitive config facts.)"""
    text = (text or "").strip()
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


# ---------------------------------------------------------------------------
# Derivers — one pure function per ClaimType
# ---------------------------------------------------------------------------


def _derive_data_boundary(deployment) -> dict:
    """DATA_BOUNDARY claim from :func:`assurance.boundary.assess_boundary`.

    Violations ⇒ CONTRADICTED; any undeclared posture / no declared boundary / no
    assessable flow ⇒ UNKNOWN; all flows approved ⇒ SUPPORTED, promoted to VERIFIED
    only when the weakest supporting evidence is configuration/technically verified
    and the boundary does not rest on vendor assertions (invariant 4)."""
    result = assess_boundary(deployment)
    flows = result["flows"]
    summary = result["summary"]
    declared = result["declared"]

    # The weakest pool folds in a synthetic UNKNOWN for every undeclared posture (a
    # gap is unknown evidence); the declared pool holds only real assertions, and is
    # what the vendor-asserted / strongest read is taken over.
    weak_pool: list[str] = []
    declared_pool: list[str] = []
    for flow in flows:
        if flow["status"] == "unknown":
            weak_pool.append(EvidenceClass.UNKNOWN.value)
        for key in ("region", "training", "sharing"):
            cell = flow.get(key)
            if cell and cell.get("evidence_class"):
                weak_pool.append(cell["evidence_class"])
                declared_pool.append(cell["evidence_class"])
    weakest, _strongest, vendor_asserted = _grade_pool(declared_pool)
    # Weakest across everything, undeclared postures included.
    weakest = max(weak_pool, key=evidence_strength) if weak_pool else EvidenceClass.UNKNOWN.value

    has_unknown = (not declared) or summary["unknowns"] > 0 or any(f["status"] == "unknown" for f in flows)
    if summary["violations"] > 0:
        status = Status.CONTRADICTED
    elif not flows or has_unknown:
        status = Status.UNKNOWN
    elif weakest in _VERIFIED_GRADE and not vendor_asserted:
        status = Status.VERIFIED
    else:
        status = Status.SUPPORTED

    evidence_class = weakest if status != Status.UNKNOWN else EvidenceClass.UNKNOWN.value

    supporting = f"{summary['approved']} of {len(flows)} data flow(s) reconciled within the approved boundary."
    contradicting_bits: list[str] = []
    if summary["violations"] > 0:
        reasons = [r for f in flows for r in f.get("violations", [])]
        contradicting_bits.append(
            f"{summary['violations']} flow(s) outside the boundary: " + "; ".join(reasons[:3])
        )
    if summary["unknowns"] > 0:
        contradicting_bits.append(f"{summary['unknowns']} flow(s) with an undeclared posture.")
    if summary["shadow_destinations"] > 0:
        contradicting_bits.append(f"{summary['shadow_destinations']} shadow (unmanaged) destination(s).")

    return {
        "claim_type": ClaimType.DATA_BOUNDARY.value,
        "subject": None,
        "statement": f"Every data destination for deployment '{deployment.name}' is within its approved data boundary.",
        "status": status.value,
        "evidence_class": evidence_class,
        "vendor_asserted": vendor_asserted,
        "confidence": _confidence(status, evidence_class),
        "assessment": deployment.decision,
        "supporting_summary": _clip(supporting),
        "contradicting_summary": _clip(" ".join(contradicting_bits)),
        "invalidation_conditions": [
            "A data destination declares a region outside the approved boundary.",
            "A provider declares it trains on customer data while the boundary forbids it.",
            "A provider declares third-party sharing while the boundary forbids it.",
            "A new unmanaged (shadow) data destination appears.",
            "The approved data boundary is changed.",
        ],
    }


def _derive_effective_access(deployment) -> dict:
    """EFFECTIVE_ACCESS claim from :func:`assurance.access.assess_effective_access`.

    Any principal carrying a HIGH-risk privileged / over-broad / ungoverned-reach
    gap ⇒ CONTRADICTED; nothing to assess (no principals) ⇒ UNKNOWN; any other
    high-risk gap ⇒ SUPPORTED; a clean reach over a graph with an unplaceable
    reference in it ⇒ PARTIALLY_VERIFIED; a clean reach over a whole graph ⇒
    VERIFIED. The reach is read from declared configuration, so its evidence class
    is ``configuration_verified`` — except where the graph could not be read
    whole, which is the next paragraph.

    **An unresolved reference makes it PARTIALLY_VERIFIED, not VERIFIED.** The
    reach is computed over the graph the inventory declares, and a dangling
    reference means part of that graph could not be placed: the assessment cannot
    have followed a hop into a component discovery never found. "No high-risk
    reach" over an incomplete graph is a measurement of what we could see, not a
    verification, and calling it VERIFIED would turn the hole into a clean bill of
    health.

    PARTIALLY_VERIFIED is the exact state, and it already exists: the reach IS
    verified over the part of the graph that could be read, and the part that could
    not be read is why the claim stops short of VERIFIED. SUPPORTED would lose that
    distinction -- it says "there is supporting evidence", not "we verified what we
    could see and here is what we could not". The evidence class drops to
    ``partially_verified`` for the same reason, so the confidence number moves with
    the hole instead of reading 0.88 either way.

    What this deliberately does NOT do is materialise the unplaced reference as an
    asset. An earlier version of this change did, and a node nobody enumerated is a
    manufactured fact: it reads as an undeclared component to the BOM drift check,
    as a governed one to every ``_MANAGED`` predicate, and it moves the deployment's
    fingerprint for an inventory that did not change. The gap belongs in the
    claim's *confidence*, where it is a statement about how well we know; it does
    not belong in the *graph*, where it would be a statement about what exists.

    PARTIALLY_VERIFIED imposes no decision cap (see
    :func:`assurance.decision.claim_cap`), which is the point: an unreadable
    reference is a limit on the measurement, not a finding against the deployment.
    Nothing here may move a decision on its own."""
    result = assess_effective_access(deployment)
    principals = result["principals"]
    unresolved = result["unresolved"]

    if not principals:
        status = Status.UNKNOWN
        evidence_class = EvidenceClass.UNKNOWN.value
        vendor_asserted = True
        # No status or evidence change for an unplaceable reference here: with no
        # principals the claim is already UNKNOWN, which is as weak as it goes.
        # It still reaches the supporting digest below, because it is the reason
        # an operator should not read "nothing to assess" as "nothing here".
    else:
        gaps = [g for p in principals for g in p["gaps"]]
        contradicting = [
            g for g in gaps if g["type"] in _CONTRADICTING_ACCESS_GAPS and g["risk"] == RISK_HIGH
        ]
        any_high_risk_gap = any(g["risk"] == RISK_HIGH for g in gaps)
        # The reach is read from declared configuration -- except where it could
        # not be read at all. An unplaceable reference means the graph the reach
        # was computed over had a hole in it, and that is a fact about the
        # strength of the evidence, so it is recorded as one. Without this the
        # confidence number is identical whether the graph was whole or not.
        evidence_class = (
            EvidenceClass.PARTIALLY_VERIFIED.value
            if unresolved
            else EvidenceClass.CONFIGURATION_VERIFIED.value
        )
        vendor_asserted = False
        if contradicting:
            status = Status.CONTRADICTED
        elif any_high_risk_gap:
            # A measured high-risk gap outranks an unreadable reference: it is
            # something we found, not something we could not look at. The
            # incompleteness is not lost on this branch -- the evidence class
            # above is already partially_verified, and the supporting digest
            # below names every reference that could not be placed.
            status = Status.SUPPORTED
        elif unresolved:
            status = Status.PARTIALLY_VERIFIED
        else:
            status = Status.VERIFIED

    summary = result["summary"]
    supporting = (
        f"{summary['principals']} principal(s) assessed; "
        f"{summary['privileged']} privileged, {summary['shadow']} shadow, {summary['over_broad']} over-broad."
    )
    if unresolved:
        # In the SUPPORTING digest on both branches, not the contradicting one.
        # An unplaceable reference is a limit on what was measured, not evidence
        # that the access is over-broad: nothing about it argues the statement is
        # false, and filing it as contradicting evidence says we found something
        # against the deployment when what we found is that we could not look.
        # The supporting digest is the record of what the assessment covered, and
        # what it could not reach is part of that record.
        #
        # Counted over the SAME set it enumerates. It used to count
        # len(unresolved) and enumerate a set of "source → reference" pairs, so a
        # duplicated inventory line said "2 declared reference(s)" above one pair:
        # an operator told to chase two and handed one goes looking for a
        # reference that does not exist. Distinct pairs, counted and listed.
        #
        # A reference to or from a row no scan has recorded under the current
        # identity rules WAS placed and followed; saying it "could not be placed"
        # is false and sends the operator looking for a component that exists.
        # What it needs is a rescan, and the digest says that instead.
        #
        # Read off every reason a row carries, not its first. An ambiguous
        # reference to an old row is both, and splitting on the first said only
        # "could not be placed" where the page says both. It is named ONCE --
        # under the sentence for what could not be placed, with what else is true
        # of it said beside the name -- because a reference counted under two
        # sentences is a reference a reader sums twice.
        def _reasons(u: dict) -> set:
            listed = u.get("reasons")
            return {str(r) for r in listed} if isinstance(listed, list) and listed else {str(u.get("reason"))}

        _followed = {"superseded_identity", "legacy_unnamed_agent"}

        def _named(u: dict) -> str:
            name = f"{u['source']} → {u['reference']}"
            reasons = _reasons(u)
            if "superseded_identity" in reasons:
                name += " (reached through a row no scan has re-recorded since)"
            if "legacy_unnamed_agent" in reasons:
                name += " (declared by the old row for every unnamed agent)"
            return name

        pairs = sorted({_named(u) for u in unresolved if _reasons(u) - _followed})
        # A reference from the old unnamed row goes under its sentence alone, even
        # when what it reaches is an old row too: no rescan clears either.
        stale = sorted(
            {f"{u['source']} → {u['reference']}" for u in unresolved
             if _reasons(u) <= _followed and "superseded_identity" in _reasons(u)
             and "legacy_unnamed_agent" not in _reasons(u)}
        )
        legacy = sorted(
            {f"{u['source']} → {u['reference']}" for u in unresolved
             if _reasons(u) <= _followed and "legacy_unnamed_agent" in _reasons(u)}
        )
        if pairs:
            supporting += (
                f" {len(pairs)} declared reference(s) could not be placed, so this is "
                "the reach over the graph we could read rather than all of it: "
                + ", ".join(pairs)
                + "."
            )
        if stale:
            supporting += (
                f" {len(stale)} declared reference(s) were followed to or from a component "
                "recorded under identity rules this platform no longer writes, which no scan "
                "has recorded since; the reach through them is counted, and a rescan is what "
                "confirms it: "
                + ", ".join(stale)
                + "."
            )
        if legacy:
            supporting += (
                f" {len(legacy)} declared reference(s) come from the row the old identity "
                "rules wrote for every unnamed agent at once; the reach through them is "
                "counted as the rows they name stand now, and a rescan records each unnamed "
                "agent under a row of its own, keyed by where it is, not that one: "
                + ", ".join(legacy)
                + "."
            )
    contradicting_bits: list[str] = []
    if principals:
        offenders = sorted(
            {
                p["name"]
                for p in principals
                for g in p["gaps"]
                if g["type"] in _CONTRADICTING_ACCESS_GAPS and g["risk"] == RISK_HIGH
            }
        )
        if offenders:
            contradicting_bits.append(
                "High-risk privileged/over-broad/ungoverned reach on: " + ", ".join(offenders)
            )

    return {
        "claim_type": ClaimType.EFFECTIVE_ACCESS.value,
        "subject": None,
        "statement": f"The effective access of every principal in deployment '{deployment.name}' is least-privilege.",
        "status": status.value,
        "evidence_class": evidence_class,
        "vendor_asserted": vendor_asserted,
        "confidence": _confidence(status, evidence_class),
        "assessment": deployment.decision,
        "supporting_summary": _clip(supporting),
        "contradicting_summary": _clip(" ".join(contradicting_bits)),
        "invalidation_conditions": [
            "A principal gains privileged reach (code execution, money movement, or privileged control).",
            "A principal's effective reach spans data, execution and network (over-broad).",
            "A principal reaches an unmanaged / shadow target.",
            "A new shadow identity appears.",
            "A declared reference between components cannot be resolved to a discovered component.",
        ],
    }


def _derive_ai_bom(deployment) -> dict:
    """AI_BOM claim from :func:`assurance.bom.build_ai_bom` and declared-vs-observed
    drift (:func:`assurance.bom_drift.assess_bom_drift`, SPINE Stage 3).

    No providers ⇒ UNKNOWN; otherwise SUPPORTED, capped by the BOM's weakest
    evidence. **Drift is the deferred CONTRADICTED path**: when the customer has
    declared an architecture and an undeclared (shadow) component or provider is
    observed, the BOM does not enumerate the full supply chain, so the claim is
    CONTRADICTED — the invalidation Stage 1C/1D then act on."""
    result = build_ai_bom(deployment)
    providers = result["providers"]
    summary = result["summary"]
    drift = assess_bom_drift(deployment)

    fact_classes = [
        f["evidence_class"] for p in providers for f in p["declared_facts"] if f.get("evidence_class")
    ]
    weakest, _strongest, vendor_asserted = _grade_pool(fact_classes)

    if drift["drift_detected"]:
        # A declared architecture with an undeclared component/provider observed:
        # the BOM is demonstrably incomplete. Drift is a configuration-verified
        # observation (we saw the component), so the contradiction is not vendor
        # evidence — a false completeness claim carries no supporting confidence.
        status = Status.CONTRADICTED
        evidence_class = EvidenceClass.CONFIGURATION_VERIFIED.value
        vendor_asserted = False
    elif summary["provider_count"] == 0:
        status = Status.UNKNOWN
        evidence_class = EvidenceClass.UNKNOWN.value
        vendor_asserted = True
    else:
        status = Status.SUPPORTED
        evidence_class = summary["weakest_evidence"] or weakest

    supporting = (
        f"{summary['component_count']} component(s) across {summary['provider_count']} provider(s); "
        f"{summary['shadow_components']} shadow component(s)."
    )
    contradicting_bits: list[str] = []
    if drift["drift_detected"]:
        d = drift["summary"]
        parts = []
        if d["undeclared"]:
            parts.append(f"{d['undeclared']} undeclared component(s)")
        if d["undeclared_providers"]:
            parts.append(f"{d['undeclared_providers']} undeclared provider(s)")
        contradicting_bits.append(
            "Observed architecture drifts from the declaration: "
            + ", ".join(parts)
            + " not in the declared bill of materials."
        )
    if summary["shadow_components"] > 0:
        contradicting_bits.append(
            f"{summary['shadow_components']} unmanaged (shadow) component(s) in the supply chain."
        )

    return {
        "claim_type": ClaimType.AI_BOM.value,
        "subject": None,
        "statement": f"The AI bill of materials for deployment '{deployment.name}' enumerates its full supply chain.",
        "status": status.value,
        "evidence_class": evidence_class,
        "vendor_asserted": vendor_asserted,
        "confidence": _confidence(status, evidence_class),
        "assessment": deployment.decision,
        "supporting_summary": _clip(supporting),
        "contradicting_summary": _clip(" ".join(contradicting_bits)),
        "invalidation_conditions": [
            "A new AI component or provider appears in the supply chain.",
            "A provider's declared posture changes.",
            "A component becomes unmanaged (shadow).",
        ],
    }


# The registry of derivers — one per ClaimType, extensible.
_DERIVERS = (
    _derive_data_boundary,
    _derive_effective_access,
    _derive_ai_bom,
)


# ---------------------------------------------------------------------------
# Identity + version reconciliation
# ---------------------------------------------------------------------------


def _identity_fingerprint(deployment, claim_type: str, subject_key: str) -> str:
    """The STABLE claim-identity key, the same across every version of the claim:
    sha256(deployment.uuid | claim_type | subject_key)."""
    raw = f"{deployment.uuid}|{claim_type}|{subject_key}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _prefetched(deployment) -> Deployment:
    """The deployment re-fetched with everything the derivers, the fingerprint, and
    the receipt read — so a derive is a fixed number of queries, never O(assets)."""
    return (
        Deployment.objects.prefetch_related(
            "assets__provider__assertions", "findings__evidence", "declared_components"
        )
        .select_related("data_boundary")
        .get(pk=deployment.pk)
    )


# ---------------------------------------------------------------------------
# The hold a fired latent condition keeps on its claim
# ---------------------------------------------------------------------------

#: The statuses a hold leaves as they are -- the ones ``_mark_stale`` never moves:
#: a live contradiction is not softened, a withdrawal is terminal, and STALE and
#: SUPERSEDED are already no pass.
_HOLD_KEEPS = frozenset({Status.CONTRADICTED, Status.REVOKED, Status.STALE, Status.SUPERSEDED})

#: Why a re-derived claim reads STALE where its deriver reads a pass.
_HELD = (
    "held at stale while a declared condition that fired on this claim still stands; "
    "it clears when the condition is found back at its baseline or a person withdraws it"
)


def held_by_fired_conditions(deployment) -> frozenset:
    """The claim identities (``fingerprint``) on ``deployment`` that a FIRED latent
    condition holds: on any version of the claim, since the hold is on the claim and
    not on one version of it.

    Such a claim reads no better than STALE and its retest stays open, whatever a
    re-derive reads. A re-derive used to refresh it straight back to VERIFIED and
    resolve the retest, and the deployment read READY again while the precondition
    the condition named was still true (:mod:`assurance.latent`).
    """
    return frozenset(
        LatentCondition.objects.filter(
            deployment=deployment, state__in=LATENT_HOLDING_STATES
        ).values_list("claim__fingerprint", flat=True)
    )


def _held_status(status: str) -> str:
    """``status`` as a claim held by a fired condition may read it: no better than
    STALE, exactly as the firing left it (``invalidation._mark_stale``)."""
    return status if status in _HOLD_KEEPS else Status.STALE


def _make_claim(
    deployment, *, identity_fp, system_fp, input_fp, pol_version, receipt_digest, derived, now,
    human_owner=None, legal_status=None, held=False,
) -> AssuranceClaim:
    """Create a new CURRENT claim version from a deriver's output, and seed its
    lifecycle with a ``∅ → status`` :class:`ClaimEvent`. ``legal_status`` is the
    version it replaces' (see :func:`_supersede`); a first version is not assessed.
    ``held``: a fired latent condition holds this claim, so it opens at STALE."""
    status = derived["status"]
    note = "Derived"
    if held and _held_status(status) != status:
        status = _held_status(status)
        note = f"Derived; {_HELD}."
    legal = {} if legal_status is None else {"legal_status": legal_status}
    claim = AssuranceClaim.objects.create(
        deployment=deployment,
        asset=derived["subject"],
        claim_type=derived["claim_type"],
        statement=derived["statement"],
        fingerprint=identity_fp,
        system_fingerprint=system_fp,
        input_fingerprint=input_fp,
        policy_version=pol_version,
        environment=deployment.environment,
        status=status,
        evidence_class=derived["evidence_class"],
        confidence=derived["confidence"],
        vendor_asserted=derived["vendor_asserted"],
        assessment=derived["assessment"],
        supporting_summary=derived["supporting_summary"],
        contradicting_summary=derived["contradicting_summary"],
        invalidation_conditions=derived["invalidation_conditions"],
        receipt_digest=receipt_digest,
        human_owner=human_owner,
        **legal,
        valid_from=now,
        first_seen=now,
        last_seen=now,
        verified_at=now if status == Status.VERIFIED else None,
        expiration=now + timedelta(days=EVIDENCE_TTL_DAYS),
    )
    ClaimEvent.objects.create(
        claim=claim, from_status="", to_status=status, actor=None, note=note
    )
    return claim


#: The fields that are a claim's reading: what it says, how strongly, and why.
_READING_FIELDS = ("evidence_class", "vendor_asserted", "supporting_summary", "contradicting_summary")


def _status_set_by_a_person(claim: AssuranceClaim) -> bool:
    """Whether the claim's current status was put there by a person.

    Read from the claim's own lifecycle: the latest event that CHANGED its status
    carries an actor when :func:`apply_claim_transition` made it, and none when a
    derive or an invalidation did."""
    last_move = (
        claim.events.exclude(from_status=models.F("to_status")).order_by("-pk").first()
    )
    return bool(
        last_move is not None
        and last_move.actor_id is not None
        and last_move.to_status == claim.status
    )


def _same_reading(claim: AssuranceClaim, derived, *, human_status: bool = False) -> bool:
    """Whether a stored version already reads what the deriver reads now.

    Two statuses are not the machine's reading, so they match whatever status the
    deriver produces: a STALE mark (evidence expired, or a retest pending) and a
    status a person set (``human_status``). Every other status must match
    exactly. The machine's own reading -- evidence class, vendor reliance, the two
    summaries -- must always match."""
    if (
        not human_status
        and claim.status != Status.STALE
        and claim.status != derived["status"]
    ):
        return False
    return all(getattr(claim, field) == derived[field] for field in _READING_FIELDS)


def _refresh_machine_fields(
    claim: AssuranceClaim, derived, receipt_digest, now, *, human_status: bool = False, held: bool = False
) -> bool:
    """Refresh a current claim's MACHINE fields in place (system state unchanged),
    preserving every human field -- including a status a person set, which stands
    on this version until the inputs or the policy it was set against change.
    Writes a :class:`ClaimEvent` only on an actual status change. Returns whether
    the row was updated.

    ``held``: a fired latent condition holds this claim, and it reads no better
    than STALE whatever the deriver -- or a person -- reads. The STALE mark the
    firing left used to be read as "whatever the deriver says now", and a re-derive
    turned it straight back into VERIFIED with the precondition still true."""
    old_status = claim.status
    new_status = old_status if human_status else derived["status"]
    note = "Re-derived"
    if held and _held_status(new_status) != new_status:
        new_status = _held_status(new_status)
        note = f"Re-derived; {_HELD}."

    claim.statement = derived["statement"]
    claim.evidence_class = derived["evidence_class"]
    claim.vendor_asserted = derived["vendor_asserted"]
    claim.confidence = derived["confidence"]
    claim.assessment = derived["assessment"]
    claim.supporting_summary = derived["supporting_summary"]
    claim.contradicting_summary = derived["contradicting_summary"]
    claim.invalidation_conditions = derived["invalidation_conditions"]
    claim.receipt_digest = receipt_digest
    claim.last_seen = now
    claim.expiration = now + timedelta(days=EVIDENCE_TTL_DAYS)

    status_changed = new_status != old_status
    if status_changed:
        claim.status = new_status
        if new_status == Status.VERIFIED:
            claim.verified_at = now
    claim.save()

    if status_changed:
        ClaimEvent.objects.create(
            claim=claim, from_status=old_status, to_status=new_status, actor=None, note=note
        )
    return True


def record_retroactive_claim(
    deployment,
    *,
    claim_type,
    statement,
    effective_from,
    effective_to,
    system_fingerprint,
    status,
    evidence_class,
    subject=None,
    confidence=None,
    vendor_asserted=False,
    supporting_summary="",
    contradicting_summary="",
    now=None,
) -> AssuranceClaim:
    """Record something learned NOW about a window that has already closed.

    The case the single temporal axis could not express: an audit log arrives
    late, a provider discloses a configuration that was in force last week, a
    retest establishes that a boundary was already breached on Tuesday. Under one
    axis the only ways to record that were to overwrite today's current claim --
    asserting a fact about last week as though it were about now -- or to drop the
    observation. Both lose something, and the first loses it silently.

    So this writes a version whose EFFECTIVE window is closed
    (``effective_to`` set) while its RECORDED window is open (``valid_to`` null):
    Mythos believes it, and believes it about the past. It is therefore not
    ``current()`` and cannot collide with today's claim on the partial unique
    constraint, while ``believed_now()`` and ``effective_at(when)`` both find it.

    ``effective_to`` is required and must be in the past relative to
    ``effective_from``'s successor -- a retroactive claim with an open effective
    window is not retroactive, it is a claim about now, and it belongs in
    :func:`derive_claims` where it will contend for the current slot properly.
    Refused rather than accepted, because accepting it would put a second row in
    the current slot's blind spot.
    """
    now = now or timezone.now()
    if effective_to is None:
        raise ValueError(
            "a retroactive claim must close its effective window: a claim with an "
            "open effective window is a claim about now, and belongs in derive_claims"
        )
    if effective_to <= effective_from:
        raise ValueError("effective_to must be after effective_from")

    subject_key = str(subject.uuid) if subject is not None else ""
    identity_fp = _identity_fingerprint(deployment, claim_type, subject_key)

    claim = AssuranceClaim.objects.create(
        deployment=deployment,
        asset=subject,
        claim_type=claim_type,
        statement=statement,
        fingerprint=identity_fp,
        system_fingerprint=system_fingerprint,
        policy_version=policy_version(deployment),
        environment=deployment.environment,
        status=status,
        evidence_class=evidence_class,
        confidence=confidence,
        vendor_asserted=vendor_asserted,
        supporting_summary=supporting_summary,
        contradicting_summary=contradicting_summary,
        # Recorded now, effective then. The two axes carry different dates, which
        # is the whole point of there being two.
        valid_from=now,
        effective_from=effective_from,
        effective_to=effective_to,
        first_seen=now,
        last_seen=now,
    )
    ClaimEvent.objects.create(
        claim=claim,
        from_status="",
        to_status=status,
        actor=None,
        note=(
            f"Recorded {now.isoformat()} about the window "
            f"{effective_from.isoformat()} to {effective_to.isoformat()}."
        ),
    )
    return claim


def _supersede(
    current: AssuranceClaim, deployment, *, identity_fp, system_fp, input_fp, pol_version, receipt_digest,
    derived, now, note, held=False,
) -> None:
    """Close the current version (``valid_to`` set, status SUPERSEDED, its own
    ClaimEvent), open a new current version bound to the new system state, and link
    ``old.superseded_by = new``. The old version is closed BEFORE the new one is
    created so the partial unique constraint (one current version per identity) is
    never momentarily violated. ``held``: a fired latent condition holds the claim,
    and the new version opens at STALE."""
    old_status = current.status
    current.valid_to = now
    current.status = Status.SUPERSEDED
    current.save(update_fields=["valid_to", "status", "updated_at"])
    ClaimEvent.objects.create(
        claim=current,
        from_status=old_status,
        to_status=Status.SUPERSEDED,
        actor=None,
        note=note,
    )
    new_claim = _make_claim(
        deployment,
        identity_fp=identity_fp,
        system_fp=system_fp,
        input_fp=input_fp,
        pol_version=pol_version,
        receipt_digest=receipt_digest,
        derived=derived,
        now=now,
        human_owner=current.human_owner,
        # The legal axis is not re-judged by a re-derive (assurance.legal decides
        # what the new version starts with). Dropped here, every re-derive erased a
        # person's materiality ruling and any review still pending.
        legal_status=ruling_for_next_version(current),
        held=held,
    )
    current.superseded_by = new_claim
    current.save(update_fields=["superseded_by", "updated_at"])
    # And the watches declared on it: a latent condition is about the claim, not one
    # version of it. Left on the closed version, it was evaluated never again -- only
    # current versions are -- while the posture went on counting it as watched.
    # Every live one, a FIRED one too: it holds the claim, not the version it fired
    # on, and it is read again to find whether it has come back to its baseline.
    LatentCondition.objects.filter(claim=current, state__in=LATENT_LIVE_STATES).update(
        claim=new_claim, updated_at=now
    )


def _mark_stale(deployment, now) -> int:
    """Mark every CURRENT claim whose evidence has expired STALE — unless it is
    already contradicted (a live contradiction is not softened to "stale"),
    revoked (a human withdrawal is terminal), or itself already stale/superseded.
    Staleness moves a claim away from a pass, never toward one."""
    count = 0
    skip = (Status.CONTRADICTED, Status.REVOKED, Status.STALE, Status.SUPERSEDED)
    currents = AssuranceClaim.objects.filter(deployment=deployment).current()
    for claim in currents:
        if claim.status in skip:
            continue
        days = age_days(claim, now)
        if days is not None and days >= EVIDENCE_TTL_DAYS:
            old_status = claim.status
            claim.status = Status.STALE
            claim.save(update_fields=["status", "updated_at"])
            ClaimEvent.objects.create(
                claim=claim,
                from_status=old_status,
                to_status=Status.STALE,
                actor=None,
                note="Evidence expired; claim is stale.",
            )
            count += 1
    return count


@transaction.atomic
def derive_claims(deployment, *, now=None) -> dict:
    """Reconcile a deployment's assurance claims with its current state.

    Idempotent and transactional. For each deriver: computes the stable identity
    fingerprint and the claim's current input fingerprint; finds the current version
    (``valid_to`` null); then creates it, refreshes it in place (its inputs and the
    policy unchanged), or supersedes it (either changed). A human REVOKED claim is
    left untouched. Finally marks current, non-contradicted claims STALE once their
    evidence expires. Returns ``{created, updated, superseded, stale}``.

    Query-light: it re-fetches the deployment once with the prefetches every
    assessment, the fingerprint and the receipt need."""
    now = now or timezone.now()
    dep = _prefetched(deployment)

    with obs.span(obs.PLAN, component="derive_claims", subject=str(deployment.pk)):
        return _derive_claims(dep, now)


def _derive_claims(dep, now) -> dict:
    """The body of :func:`derive_claims`, lifted out so one span wraps it.

    Extracted rather than re-indented: a re-indent would rewrite every line of the
    claim deriver, and a reviewer could not tell the tracing change from a logic
    change in that diff.
    """
    system_fp = compute_system_fingerprint(dep)
    input_fps = claim_input_fingerprints(dep)
    pol_version = policy_version(dep)
    receipt_digest = build_assurance_receipt(dep)["digest"]
    # Read once, before anything moves: a supersede below carries each fired
    # condition to the claim's new version, and the identity it holds is the same.
    held = held_by_fired_conditions(dep)

    counts = {"created": 0, "updated": 0, "superseded": 0, "stale": 0}

    for deriver in _DERIVERS:
        derived = deriver(dep)
        subject = derived["subject"]
        subject_key = str(subject.uuid) if subject is not None else ""
        identity_fp = _identity_fingerprint(dep, derived["claim_type"], subject_key)
        input_fp = input_fps.get(derived["claim_type"], system_fp)

        current = (
            AssuranceClaim.objects.filter(deployment=dep, fingerprint=identity_fp)
            .current()
            .first()
        )

        if current is None:
            _make_claim(
                dep,
                identity_fp=identity_fp,
                system_fp=system_fp,
                input_fp=input_fp,
                pol_version=pol_version,
                receipt_digest=receipt_digest,
                derived=derived,
                now=now,
                held=identity_fp in held,
            )
            counts["created"] += 1
            continue

        # A human REVOKED claim is a withdrawal; a re-derive never touches it — not
        # its status, not its last_seen, not a supersede.
        if current.status == Status.REVOKED:
            continue

        # A claim is bound to BOTH the inputs it rests on and the policy it was
        # assessed under. It is refreshed in place only while both still hold; a
        # change to either supersedes it and opens a new current version bound to
        # the change. A change to an input this claim does not read is not a change
        # to this claim: it used to supersede every claim on the deployment at once.
        state_moved = claim_state_moved(current, system_fp=system_fp, input_fps=input_fps)
        policy_moved = current.policy_version != pol_version
        # A person's verdict on this version -- a claim moved to CONTRADICTED with
        # "we know it leaks" -- is not the machine's reading drifting. It stands on
        # this version while the inputs and policy it was set against hold, and a
        # re-derivation refreshes the machine's fields around it. It used to be
        # overwritten in place, and for one round was superseded with a note
        # blaming a gap in CLAIM_INPUTS; neither was true. When the inputs or the
        # policy move, the version is superseded as always: the verdict was about
        # the state that moved.
        human_status = _status_set_by_a_person(current)
        reading_moved = not (state_moved or policy_moved) and not _same_reading(
            current, derived, human_status=human_status
        )
        if not (state_moved or policy_moved or reading_moved):
            if not current.input_fingerprint:
                # A legacy row whose state and reading both still hold: bind it to
                # its inputs now, so the next change is read per claim rather than
                # for the whole deployment.
                current.input_fingerprint = input_fp
            if _refresh_machine_fields(
                current, derived, receipt_digest, now, human_status=human_status, held=identity_fp in held
            ):
                counts["updated"] += 1
        else:
            if state_moved and policy_moved:
                note = "The inputs this claim rests on and the assurance policy both changed; version superseded."
            elif state_moved:
                note = "The inputs this claim rests on changed; version superseded."
            elif policy_moved:
                note = "Assurance policy changed; version superseded."
            else:
                # Neither the inputs this claim is bound to nor the policy moved,
                # and the deriver reads something else now. Refreshing in place
                # would rewrite the version's verdict under it -- one version
                # spanning two readings, with no supersede and no retest. That is
                # what a gap in CLAIM_INPUTS looks like from here, and a row bound
                # before per-claim fingerprints lands here too when its system
                # state holds but its reading does not. Either way a reading that
                # moved is a new version, and the note says why, so the gap is
                # visible in the claim's own history rather than silent.
                note = (
                    "The reading changed though no input this claim is bound to did; "
                    "version superseded."
                )
            _supersede(
                current,
                dep,
                identity_fp=identity_fp,
                system_fp=system_fp,
                input_fp=input_fp,
                pol_version=pol_version,
                receipt_digest=receipt_digest,
                derived=derived,
                now=now,
                note=note,
                held=identity_fp in held,
            )
            counts["superseded"] += 1

    counts["stale"] = _mark_stale(dep, now)

    # The temporal backbone tie-back (SPINE Phase 2): now that this reconcile has
    # rebound each claim to the current system state, resolve any open retest
    # obligation that rebinding satisfies. A retest is earned by a re-derivation
    # that rebinds, never by a machine merely no longer flagging drift. Imported
    # lazily because assurance.invalidation imports from this module. This never
    # changes the returned counts — resolution is a side effect on the obligations,
    # and the check-invalidations endpoint reports the resolved count itself.
    from .invalidation import resolve_satisfied_requirements

    resolve_satisfied_requirements(
        dep, system_fp=system_fp, policy_version=pol_version, now=now, input_fps=input_fps, held=held
    )
    return counts


# ---------------------------------------------------------------------------
# Lifecycle transitions — attributed, mirroring assurance.remediation
# ---------------------------------------------------------------------------

# The legal human transitions, keyed by the status the claim is in. STALE and
# SUPERSEDED never appear as a *target* (they are machine-only outcomes), and
# SUPERSEDED / REVOKED have no outgoing human moves (terminal). REVOKED is
# reachable from every live state — a human may always withdraw a claim.
_ALLOWED: dict[str, frozenset[str]] = {
    Status.DRAFT: frozenset(
        {Status.SUPPORTED, Status.PARTIALLY_VERIFIED, Status.VERIFIED, Status.CONTRADICTED, Status.UNKNOWN, Status.REVOKED}
    ),
    Status.SUPPORTED: frozenset(
        {Status.VERIFIED, Status.PARTIALLY_VERIFIED, Status.CONTRADICTED, Status.UNKNOWN, Status.REVOKED}
    ),
    Status.PARTIALLY_VERIFIED: frozenset(
        {Status.VERIFIED, Status.SUPPORTED, Status.CONTRADICTED, Status.UNKNOWN, Status.REVOKED}
    ),
    Status.VERIFIED: frozenset(
        {Status.SUPPORTED, Status.PARTIALLY_VERIFIED, Status.CONTRADICTED, Status.UNKNOWN, Status.REVOKED}
    ),
    Status.CONTRADICTED: frozenset(
        {Status.SUPPORTED, Status.PARTIALLY_VERIFIED, Status.UNKNOWN, Status.REVOKED}
    ),
    Status.UNKNOWN: frozenset(
        {Status.SUPPORTED, Status.PARTIALLY_VERIFIED, Status.VERIFIED, Status.CONTRADICTED, Status.REVOKED}
    ),
    Status.STALE: frozenset(
        {Status.SUPPORTED, Status.PARTIALLY_VERIFIED, Status.VERIFIED, Status.CONTRADICTED, Status.UNKNOWN, Status.REVOKED}
    ),
}

# Never a legal human target — these are only ever set by the machine.
_MACHINE_ONLY_TARGETS = frozenset({Status.STALE, Status.SUPERSEDED})


class IllegalClaimTransition(ValueError):
    """A claim lifecycle move the state machine forbids. A caller turns this into a
    clean 400 rather than letting an illegal jump be silently coerced."""


def _can_verify(claim: AssuranceClaim) -> bool:
    """Whether a claim MAY read VERIFIED: its (weakest) evidence is
    configuration/technically verified AND it does not rest on vendor assertions
    (invariants 3 & 4). A human cannot hand-verify an unknown, contradicted, or
    vendor claim."""
    return claim.evidence_class in _VERIFIED_GRADE and not claim.vendor_asserted


def can_transition(from_status: str, to_status: str) -> bool:
    """Whether ``from_status → to_status`` is a legal claim lifecycle move,
    ignoring the separate evidence gate on VERIFIED (checked in
    :func:`apply_claim_transition`)."""
    return to_status in _ALLOWED.get(from_status, frozenset())


@transaction.atomic
def apply_claim_transition(claim: AssuranceClaim, to_status: str, *, actor, note: str = "") -> ClaimEvent:
    """Move ``claim`` to ``to_status`` and record who did it.

    Rejects (with :class:`IllegalClaimTransition`) a machine-only target
    (STALE/SUPERSEDED), an illegal jump, and — the HARD RULE — any move into
    VERIFIED that is not backed by configuration/technically-verified, non-vendor
    evidence. Updates only ``status`` (and ``verified_at`` on a move to VERIFIED)
    and writes an attributed :class:`ClaimEvent`. Atomic so the change and its audit
    record land together or not at all."""
    to_status = Status(to_status)
    from_status = claim.status

    if to_status in _MACHINE_ONLY_TARGETS:
        raise IllegalClaimTransition(
            f"{to_status} is a machine-only status, not a valid human transition target."
        )
    if not can_transition(from_status, to_status):
        raise IllegalClaimTransition(
            f"{from_status} → {to_status} is not a legal claim transition."
        )
    if to_status == Status.VERIFIED and not _can_verify(claim):
        raise IllegalClaimTransition(
            "Cannot verify a claim whose evidence is not configuration/technically "
            "verified, or that rests on vendor assertions."
        )

    claim.status = to_status
    fields = ["status", "updated_at"]
    if to_status == Status.VERIFIED:
        claim.verified_at = timezone.now()
        fields.append("verified_at")
    claim.save(update_fields=fields)

    return ClaimEvent.objects.create(
        claim=claim, from_status=from_status, to_status=to_status, actor=actor, note=note or ""
    )
