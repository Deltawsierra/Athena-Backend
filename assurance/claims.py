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
  class; and a claim resting on vendor assertions caps at SUPPORTED. The
  confidence is mythos-core's strength for that class, and follows the status
  whoever sets it (:mod:`assurance.claim_confidence`).

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

Recorded evidence (issue #333, :mod:`assurance.evidence_audit`) is read beside the
deriver at every reconcile and every attributed transition. It can hold a claim
back -- CONTRADICTED on load-bearing failure, UNKNOWN when contested or when
adverse evidence had to be refused -- and it can never lift one: target-authored,
stale, wrong-subject or signature-only evidence carries no weight, and a person
cannot move a claim ABOVE its reading to a status the evidence would hold back at
once. A person can always lower the reading (recorded under the hold) and always
stop the claim.

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
from .claim_confidence import claim_confidence
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
    ClaimEvidence,
    Deployment,
    EvidenceClass,
    LatentCondition,
    evidence_strength,
)
from .legal import ruling_for_next_version
from .receipt import build_assurance_receipt
from .served_route import served_route_fingerprint
from . import evidence_audit as ea

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
        "confidence": claim_confidence(status, evidence_class),
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
        "confidence": claim_confidence(status, evidence_class),
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

    # Each fact at the class its source can prove, never its label alone (#343).
    fact_classes = [
        f["effective_evidence_class"] for p in providers for f in p["declared_facts"] if f.get("effective_evidence_class")
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
        "confidence": claim_confidence(status, evidence_class),
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
    human_owner=None, legal_status=None, held=False, audited=None, carried=None,
) -> AssuranceClaim:
    """Create a new CURRENT claim version from a deriver's output, and seed its
    lifecycle with a ``∅ → status`` :class:`ClaimEvent`. ``legal_status`` is the
    version it replaces' (see :func:`_supersede`); a first version is not assessed.
    ``held``: a fired latent condition holds this claim, so it opens at STALE.
    ``audited``: the evidence audit of this version (:mod:`assurance.evidence_audit`)
    -- it opens at the status the audit holds it at, with the audit's own event, and
    carries the verdict; never above what the deriver reads.
    ``carried``: ``(stop event, version it was on)`` -- a person's stop on the
    version this one supersedes (:func:`_persons_stop`). The new version opens at
    that stop, attributed to the person who made it, and says which version it was
    carried from; ``audited`` is then the audit of the stop as the reading, which
    holds nothing (nothing ranks below a stop)."""
    status = derived["status"]
    note = "Derived"
    audit_event = None
    if carried is not None:
        stop_event, _carried_from = carried
        status = stop_event.to_status
    elif audited is not None and audited["held"]:
        # The confidence the reading under the hold carries -- the one it would carry
        # with no evidence recorded, read for its status like every confidence
        # (assurance.claim_confidence) -- recorded with the hold.
        audited = {**audited, "base_confidence": claim_confidence(audited["base_status"], derived["evidence_class"])}
        audit_event = (status, audited["status"], ea.audit_note(audited))
        status = audited["status"]
    if carried is None and held and _held_status(status) != status:
        status = _held_status(status)
        note = f"Derived; {_HELD}."
    # The confidence of the status the version opens at -- the deriver's, the audit's
    # hold, a fired condition's STALE, or a person's stop carried to it -- and never
    # the deriver's for a status the version does not open at.
    confidence = claim_confidence(status, derived["evidence_class"])
    legal = {} if legal_status is None else {"legal_status": legal_status}
    verdict = {} if audited is None else ea.audit_columns(audited)
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
        confidence=confidence,
        vendor_asserted=derived["vendor_asserted"],
        assessment=derived["assessment"],
        supporting_summary=derived["supporting_summary"],
        contradicting_summary=derived["contradicting_summary"],
        invalidation_conditions=derived["invalidation_conditions"],
        receipt_digest=receipt_digest,
        human_owner=human_owner,
        **legal,
        **verdict,
        valid_from=now,
        first_seen=now,
        last_seen=now,
        verified_at=now if status == Status.VERIFIED else None,
        expiration=now + timedelta(days=EVIDENCE_TTL_DAYS),
    )
    if audited is not None:
        ea.store_weighing(claim, audited)
    if carried is not None:
        # What the deriver read, then the person's stop carried onto it: the stop is
        # the version's reading, a person's, and it lifts only by a person's act.
        stop_event, carried_from = carried
        # The person's OWN act, wherever along a chain of carries it was made.
        original = stop_event.carried_from or stop_event
        ClaimEvent.objects.create(
            claim=claim, from_status="", to_status=derived["status"], actor=None, note="Derived"
        )
        ClaimEvent.objects.create(
            claim=claim,
            from_status=derived["status"],
            to_status=status,
            actor_id=original.actor_id,
            by_person=True,
            actor_username=original.actor_username,
            carried_from=original,
            cause=ClaimEvent.CAUSE_PERSON_READING if derived["status"] == status else "",
            note=_carried_note(original, carried_from),
        )
    elif audit_event is None:
        ClaimEvent.objects.create(
            claim=claim, from_status="", to_status=status, actor=None, note=note
        )
    else:
        # What the deriver read, then what the evidence held it at: the version's
        # history shows both, and the hold is marked as the audit's, so it is
        # never read as the reading itself.
        read, audit_status, audit_note = audit_event
        ClaimEvent.objects.create(claim=claim, from_status="", to_status=read, actor=None, note="Derived")
        ClaimEvent.objects.create(
            claim=claim,
            from_status=read,
            to_status=audit_status,
            actor=None,
            cause=ClaimEvent.CAUSE_EVIDENCE_AUDIT,
            note=audit_note,
        )
        if status != audit_status:
            ClaimEvent.objects.create(
                claim=claim, from_status=audit_status, to_status=status, actor=None, note=note
            )
    return claim


def _carried_note(original: ClaimEvent, carried_from: AssuranceClaim) -> str:
    """The note of a person's stop carried to a new version: the person's own note,
    clipped to leave room, then where it was carried from and whose act it is --
    never clipped. It was the previous carried note plus a suffix, clipped to 500
    characters: a long note carried with no "carried from" at all, and along a chain
    of drifts the version it came from stopped being named from the fourth carry on
    (round 5, B1)."""
    made_on = AssuranceClaim.objects.filter(pk=original.claim_id).values_list("uuid", flat=True).first()
    by = original.actor_username or "an account since removed"
    carried = (
        f"[carried from {carried_from.uuid}: the stop {by} made on version {made_on} (event {original.uuid}) "
        "stands on this version until a person lifts it; no evidence and no re-derive lifts it.]"
    )
    own = (original.note or "").strip()
    if not own:
        return carried
    return f"{_clip(own, max(1, 500 - len(carried) - 1))} {carried}"


#: The fields that are a claim's reading: what it says, how strongly, and why.
_READING_FIELDS = ("evidence_class", "vendor_asserted", "supporting_summary", "contradicting_summary")


def _status_set_by_a_person(claim: AssuranceClaim) -> bool:
    """Whether the claim's current status was put there by a person.

    Read from the claim's own lifecycle: the latest event that CHANGED its status
    carries an actor when :func:`apply_claim_transition` made it, and none when a
    derive or an invalidation did. A hold the evidence audit put on it is not a
    move of the reading: a person's status the audit held back is still the
    person's, read under the hold (:func:`assurance.evidence_audit.reading_status`).
    A person's move that left the status it shows where it was -- a contradiction
    of a claim the evidence already held at CONTRADICTED -- is still a move of the
    reading (:attr:`ClaimEvent.CAUSE_PERSON_READING`); other same-status events
    are not."""
    return _persons_move(claim) is not None


def _persons_move(claim: AssuranceClaim) -> ClaimEvent | None:
    """The person's event that set the claim's current reading, or None when the
    machine set it (:func:`_status_set_by_a_person`).

    A person's event is one a person made (:attr:`ClaimEvent.by_person`, written
    with the event), never one that still has an account row: ``actor`` is nulled
    when the account is deleted, and reading it turned a removed operator's stop
    into the machine's reading -- the next re-derive lifted it (round 5, B2)."""
    last_move = (
        claim.events.filter(
            ~models.Q(from_status=models.F("to_status")) | models.Q(cause=ClaimEvent.CAUSE_PERSON_READING)
        )
        .exclude(cause=ClaimEvent.CAUSE_EVIDENCE_AUDIT)
        .order_by("-pk")
        .first()
    )
    if last_move is not None and last_move.by_person and last_move.to_status == ea.reading_status(claim):
        return last_move
    return None


def _persons_stop(claim: AssuranceClaim) -> ClaimEvent | None:
    """The stop (contradict, revoke) a person put on this version that it still
    reads, or None.

    Owner decision (round 4): a person's stop carries to the version that
    supersedes this one, when a re-derive or a drift in its inputs versions it
    (:func:`_make_claim`). It used to stay on the closed version, and the new one
    opened at whatever the deriver read -- a claim a person had taken down read
    VERIFIED again because an input it rests on moved, which lifted the stop with
    no one lifting it."""
    if ea.reading_status(claim) not in ea.STOPS:
        return None
    return _persons_move(claim)


def _same_reading(claim: AssuranceClaim, derived, *, human_status: bool = False) -> bool:
    """Whether a stored version already reads what the deriver reads now.

    Two statuses are not the machine's reading, so they match whatever status the
    deriver produces: a STALE mark (evidence expired, or a retest pending) and a
    status a person set (``human_status``). Every other status must match
    exactly. The machine's own reading -- evidence class, vendor reliance, the two
    summaries -- must always match.

    A status the evidence audit holds the claim at is not a reading either: the
    reading under the hold is compared (:func:`assurance.evidence_audit.reading_status`),
    so recorded evidence holds a version back in place rather than superseding it on
    every re-derive."""
    reading = ea.reading_status(claim)
    if (
        not human_status
        and reading != Status.STALE
        and reading != derived["status"]
    ):
        return False
    return all(getattr(claim, field) == derived[field] for field in _READING_FIELDS)


def _refresh_audit(claim: AssuranceClaim, derived, now, *, human_status: bool, held: bool, audit_context):
    """The evidence audit a refresh in place writes onto ``claim``
    (:func:`_refresh_machine_fields`): of the reading -- the deriver's, or the
    person's under any hold -- as a fired condition leaves it. ``None`` when nothing
    is recorded against the identity. Pure: taken while the re-derive is planned,
    outside the write lock."""
    if audit_context is None:
        return None
    new_status = ea.reading_status(claim) if human_status else derived["status"]
    subject, items = audit_context
    # The reading the evidence is weighed against is the one a fired condition
    # leaves: no better than STALE. Read against the deriver's pass instead, a
    # hold stored that pass as its reading, and releasing it lifted the claim
    # over a condition that still stands.
    return ea.audit(
        base_status=_held_status(new_status) if held else new_status,
        vendor_asserted=derived["vendor_asserted"],
        evidence_class=derived["evidence_class"],
        subject=subject,
        items=items,
        now=now,
        # A person's status that stands on this version is re-audited as a
        # person's: never the pass side of a contradiction.
        reading_by_person=human_status,
    )


def _refresh_machine_fields(
    claim: AssuranceClaim, derived, receipt_digest, now, *, human_status: bool = False, held: bool = False,
    audit_context=None, audited=None, weighing_unchanged: bool = False,
) -> bool:
    """Refresh a current claim's MACHINE fields in place (system state unchanged),
    preserving every human field -- including a status a person set, which stands
    on this version until the inputs or the policy it was set against change.
    Writes a :class:`ClaimEvent` only on an actual status change. Returns whether
    the row was updated.

    ``held``: a fired latent condition holds this claim, and it reads no better
    than STALE whatever the deriver -- or a person -- reads. The STALE mark the
    firing left used to be read as "whatever the deriver says now", and a re-derive
    turned it straight back into VERIFIED with the precondition still true.

    ``audit_context``: ``(subject, items)`` for the evidence audit of this version
    (:mod:`assurance.evidence_audit`), read against the reading -- the deriver's, or
    the person's under any hold -- and held back where the evidence says so.
    ``audited``: that audit, already taken (:func:`_refresh_audit`) while the
    re-derive was planned outside the write lock; taken here when not given."""
    old_status = claim.status
    # Whether the evidence audit was holding this claim as the refresh began: a
    # refresh that lets that hold go writes the audit's move, not the deriver's.
    was_held_by_audit = ea._held_by_audit(claim)
    new_status = ea.reading_status(claim) if human_status else derived["status"]
    note = "Re-derived"
    if audited is None and audit_context is not None:
        audited = _refresh_audit(claim, derived, now, human_status=human_status, held=held, audit_context=audit_context)
    if audited is not None and audited["held"]:
        new_status = audited["status"]
        note = ea.audit_note(audited)
    condition_held = False
    if held and _held_status(new_status) != new_status:
        new_status = _held_status(new_status)
        note = f"Re-derived; {_HELD}."
        condition_held = True

    claim.statement = derived["statement"]
    claim.evidence_class = derived["evidence_class"]
    claim.vendor_asserted = derived["vendor_asserted"]
    if audited is not None:
        if audited["held"]:
            # The confidence the reading under the hold carries -- the deriver's, or
            # a person's status standing on this version -- recorded with the hold.
            audited = {
                **audited,
                "base_confidence": claim_confidence(audited["base_status"], derived["evidence_class"]),
            }
        ea.store_audit(claim, audited)
    elif audit_context is not None and claim.evidence_audit:
        # Nothing recorded against this identity any more: no verdict to carry.
        ea.store_audit(claim, None)
        ea.store_weighing(claim, None)
    claim.assessment = derived["assessment"]
    claim.supporting_summary = derived["supporting_summary"]
    claim.contradicting_summary = derived["contradicting_summary"]
    claim.invalidation_conditions = derived["invalidation_conditions"]
    claim.receipt_digest = receipt_digest
    claim.last_seen = now
    claim.expiration = now + timedelta(days=EVIDENCE_TTL_DAYS)

    # The confidence of the status the claim reads after this refresh, whoever set
    # it (assurance.claim_confidence). A person's status standing on this version
    # carries the strength for ITS status: it used to be given the deriver's
    # confidence for the deriver's status, so a person's SUPPORTED over a derived
    # CONTRADICTED read None and a person's UNKNOWN over a derived VERIFIED read
    # 0.88. An evidence hold, a fired condition's STALE and a stop -- the deriver's
    # or a person's (see :func:`_take_down`) -- carry none.
    claim.confidence = claim_confidence(new_status, derived["evidence_class"])
    status_changed = new_status != old_status
    if status_changed:
        claim.status = new_status
        if new_status == Status.VERIFIED:
            claim.verified_at = now
    claim.save()
    if audited is not None and not weighing_unchanged:
        ea.store_weighing(claim, audited)

    if status_changed:
        # The audit's move: its hold, or its hold let go -- a release lands the claim
        # on the reading it kept under the hold, whoever set that reading. Recorded
        # as the audit's (cause evidence_audit), so :func:`_persons_move` never reads
        # a release as the move that set the reading: written as the deriver's, it
        # hid a person's SUPPORTED, and the next re-derive lifted the claim to the
        # deriver's VERIFIED (#124 review round 1, F1).
        held_by_audit = audited is not None and audited["held"] and new_status == audited["status"]
        released_by_audit = was_held_by_audit and audited is not None and not audited["held"] and not condition_held
        by_audit = held_by_audit or released_by_audit
        ClaimEvent.objects.create(
            claim=claim, from_status=old_status, to_status=new_status, actor=None, note=note,
            cause=ClaimEvent.CAUSE_EVIDENCE_AUDIT if by_audit else "",
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
    vendor_asserted=False,
    supporting_summary="",
    contradicting_summary="",
    now=None,
) -> AssuranceClaim:
    """Record something learned NOW about a window that has already closed.

    Its confidence is read for its status and evidence class like every claim's
    (:mod:`assurance.claim_confidence`). It used to take a ``confidence=`` argument,
    a number the caller typed in beside the evidence class it contradicted or
    repeated; no caller passed one, and none can now.

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
        confidence=claim_confidence(status, evidence_class),
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
    derived, now, note, held=False, audited=None, carried_stop=None,
) -> None:
    """Close the current version (``valid_to`` set, status SUPERSEDED, its own
    ClaimEvent), open a new current version bound to the new system state, and link
    ``old.superseded_by = new``. The old version is closed BEFORE the new one is
    created so the partial unique constraint (one current version per identity) is
    never momentarily violated. ``held``: a fired latent condition holds the claim,
    and the new version opens at STALE. ``carried_stop``: a person's stop on
    ``current`` (:func:`_persons_stop`), which the new version opens at."""
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
        audited=audited,
        carried=None if carried_stop is None else (carried_stop, current),
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


def _evidence_by_identity(deployment, fingerprint: str | None = None) -> dict[str, list]:
    """The evidence recorded against each claim identity on ``deployment`` (only
    ``fingerprint``'s, when given), in one query, oldest first
    (:class:`~assurance.models.ClaimEvidence`)."""
    grouped: dict[str, list] = {}
    items = ClaimEvidence.objects.filter(deployment=deployment)
    if fingerprint is not None:
        items = items.filter(claim_fingerprint=fingerprint)
    for item in items.order_by("created_at", "pk"):
        grouped.setdefault(item.claim_fingerprint, []).append(item)
    return grouped


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
            # Expired evidence supports nothing now: the confidence of the status
            # written (none), never the one the claim carried before it expired.
            claim.confidence = claim_confidence(claim.status, claim.evidence_class)
            claim.save(update_fields=["status", "confidence", "updated_at"])
            ClaimEvent.objects.create(
                claim=claim,
                from_status=old_status,
                to_status=Status.STALE,
                actor=None,
                note="Evidence expired; claim is stale.",
            )
            count += 1
    return count


#: How many times a re-derive checks its plan against what is committed, and plans
#: again what moved, before it gives up (:func:`derive_claims`).
DERIVE_ATTEMPTS = 5


class ClaimsKeptMoving(RuntimeError):
    """Every check of a re-derive's plan found a claim it writes -- or the evidence
    or a fired condition on one -- moved since it was planned. Nothing was written:
    the claims read what those writes left, and the caller asks again. Never raised
    to a stop -- a stop is one of the writes that overtook it, and it stands."""


def derive_claims(deployment, *, now=None, then=None) -> dict:
    """Reconcile a deployment's assurance claims with its current state.

    Idempotent and transactional. For each deriver: computes the stable identity
    fingerprint and the claim's current input fingerprint; finds the current version
    (``valid_to`` null); then creates it, refreshes it in place (its inputs and the
    policy unchanged), or supersedes it (either changed). A human REVOKED claim is
    left untouched, and a person's stop on a version that is superseded carries to
    the new one (:func:`_persons_stop`). Finally marks current, non-contradicted
    claims STALE once their evidence expires. Returns ``{created, updated,
    superseded, stale}``. ``then``: called inside the transaction that writes the
    claims, after them (the recompute route refreshes the stored decision there).

    Planned OUTSIDE the write lock, written inside it. Reading the deployment and
    auditing every evidence item recorded against its claims grows with the
    evidence (1.3 s at 10,000 items), and SQLite's write lock is the whole
    database's: a stop arriving during a re-derive waited all of that out -- and past
    the busy timeout the stop was LOST (round 4, W1). So the plan -- what each claim
    becomes, and the audit of it -- is taken with no transaction open, and written
    in one short transaction only if nothing it read about the claims it writes has
    moved: for each claim identity, its current version
    (:func:`assurance.evidence_audit.claim_token`), the evidence recorded against it
    and every invalidation of that evidence
    (:func:`assurance.evidence_audit.evidence_token`), and whether a fired condition
    holds it. If anything did -- a stop landed, an item was invalidated -- nothing is
    written, and the steps that moved are planned again from what is committed now,
    so the stop is what the re-derive reads and is never overwritten. The steps that
    did not move keep their plan: a person triaging ANOTHER claim of the deployment
    overtook the whole plan, which was taken again from scratch -- at 10,000 items
    each re-plan outlasted the gap between the person's moves, and every recompute
    ended 409 while the drift it was asked to apply never reached the claim (round
    5, D1). Past :data:`DERIVE_ATTEMPTS` checks, :class:`ClaimsKeptMoving`, with
    nothing written.

    A plan is of the deployment's state as it was read. A write to an input landing
    between the read and the write is what it would be had it landed just after the
    re-derive: drift, which the next check or re-derive finds.

    Query-light: it re-fetches the deployment once with the prefetches every
    assessment, the fingerprint and the receipt need."""
    with obs.span(obs.PLAN, component="derive_claims", subject=str(deployment.pk)):
        plan = _plan_derive(deployment, now)
        for attempt in range(DERIVE_ATTEMPTS):
            with transaction.atomic():
                moved = _moved_steps(plan)
                if not moved:
                    counts = _write_plan(plan)
                    if then is not None:
                        then()
                    return counts
            if attempt + 1 < DERIVE_ATTEMPTS:
                _plan_again(plan, moved)
    raise ClaimsKeptMoving(
        f"The claims of deployment {deployment.pk} kept changing while they were re-derived "
        f"({DERIVE_ATTEMPTS} checks, each finding a claim the re-derive writes moved since it was "
        "planned). Nothing was written; re-derive again."
    )


class _Plan:
    """What a re-derive will write, and what it read to decide it (:func:`derive_claims`)."""

    def __init__(self, dep, now):
        self.dep = dep
        # The caller's instant, or -- when it named none -- the instant each step's
        # evidence was read (:func:`_plan_derive`, :func:`_plan_again`).
        self.fixed_now = now is not None
        self.now = now or timezone.now()
        self.steps: list[dict] = []
        self.route = None

    def weighed_now(self) -> None:
        """The evidence was just read: weigh it as of now. An invalidation the read
        saw is then in the audit's past, never "dated ahead" -- an instant taken
        before the read counted an invalidation committed in between as one that
        has not taken effect yet."""
        if not self.fixed_now:
            self.now = timezone.now()


def _plan_derive(deployment, now) -> _Plan:
    """Everything :func:`derive_claims` decides, read and computed with no write
    lock held: the derivers, the fingerprints, the receipt, and a step for each
    claim identity (:func:`_plan_step`). ``now``: the caller's instant, or None."""
    plan = _Plan(_prefetched(deployment), now)
    dep = plan.dep
    plan.system_fp = compute_system_fingerprint(dep)
    plan.input_fps = claim_input_fingerprints(dep)
    plan.pol_version = policy_version(dep)
    plan.receipt_digest = build_assurance_receipt(dep)["digest"]
    # Read once, before anything moves: a supersede below carries each fired
    # condition to the claim's new version, and the identity it holds is the same.
    plan.held = held_by_fired_conditions(dep)
    readings = []
    for deriver in _DERIVERS:
        derived = deriver(dep)
        subject = derived["subject"]
        subject_key = str(subject.uuid) if subject is not None else ""
        readings.append((derived, subject_key, _identity_fingerprint(dep, derived["claim_type"], subject_key)))
    # The claims, then the evidence: each identity's token, then the items. An item
    # recorded after the claims were read is followed by its own audit, a write to
    # its claim's row -- which the check then finds moved -- or it is in what was
    # read here; its token catches the rest, and an invalidation too.
    currents = {
        claim.fingerprint: claim
        for claim in AssuranceClaim.objects.filter(
            deployment=dep, fingerprint__in=[identity_fp for _, _, identity_fp in readings]
        ).current()
    }
    tokens = {identity_fp: ea.evidence_token(dep.pk, identity_fp) for _, _, identity_fp in readings}
    evidence = _evidence_by_identity(dep)
    plan.weighed_now()
    for derived, subject_key, identity_fp in readings:
        step = {"identity_fp": identity_fp, "derived": derived, "subject_key": subject_key}
        _plan_step(
            plan, step, current=currents.get(identity_fp), evidence=tokens[identity_fp],
            items=evidence.get(identity_fp, []), held=identity_fp in plan.held,
        )
        plan.steps.append(step)
    return plan


def _plan_again(plan: _Plan, moved: list[dict]) -> None:
    """Plan again, from what is committed now, only the ``moved`` steps (outside the
    write lock): each one's current version, then its evidence token, then its
    items, and whether a fired condition holds it. The deployment's inputs, the
    derivers' readings and the receipt stay as the plan read them."""
    held = held_by_fired_conditions(plan.dep)
    for step in moved:
        identity_fp = step["identity_fp"]
        current = (
            AssuranceClaim.objects.filter(deployment=plan.dep, fingerprint=identity_fp).current().first()
        )
        evidence = ea.evidence_token(plan.dep.pk, identity_fp)
        items = _evidence_by_identity(plan.dep, identity_fp).get(identity_fp, [])
        plan.weighed_now()
        _plan_step(plan, step, current=current, evidence=evidence, items=items, held=identity_fp in held)


def _plan_step(plan: _Plan, step: dict, *, current, evidence, items, held: bool) -> None:
    """What one claim identity becomes (``step``, updated in place), and what it was
    decided from: the current version as read (its token), the evidence token and
    items, and whether a fired condition holds the claim."""
    now, dep = plan.now, plan.dep
    derived, subject_key = step["derived"], step["subject_key"]
    input_fp = plan.input_fps.get(derived["claim_type"], plan.system_fp)
    if items and plan.route is None:
        # The route serving now, which each item must name: read off the prefetched
        # graph, no query per asset, and only once evidence is recorded at all.
        plan.route = served_route_fingerprint(dep)
    audit_subject = ea.Subject(
        deployment=str(dep.uuid),
        claim_type=derived["claim_type"],
        asset=subject_key,
        inputs=input_fp,
        route=plan.route or "",
    )
    for key in ("action", "audited", "human_status", "audit_context", "weighing_unchanged", "note", "carried_stop"):
        step.pop(key, None)
    step.update(
        input_fp=input_fp,
        held=held,
        token=None if current is None else ea.claim_token(current),
        evidence=evidence,
    )

    def audit_new(base_status, *, by_person=False):
        # The audit of a NEW version, read against what the deriver reads -- as a
        # fired latent condition leaves it, no better than STALE -- or against a
        # person's stop carried to it. Only ever holds it back.
        return ea.audit(
            base_status=base_status,
            vendor_asserted=derived["vendor_asserted"],
            evidence_class=derived["evidence_class"],
            subject=audit_subject,
            items=items,
            now=now,
            reading_by_person=by_person,
        )

    derived_base = _held_status(derived["status"]) if held else derived["status"]
    if current is None:
        step.update(action="create", audited=audit_new(derived_base))
        return

    # A human REVOKED claim is a withdrawal; a re-derive never touches it — not
    # its status, not its last_seen, not a supersede.
    if current.status == Status.REVOKED:
        step.update(action="keep")
        return

    # A claim is bound to BOTH the inputs it rests on and the policy it was
    # assessed under. It is refreshed in place only while both still hold; a
    # change to either supersedes it and opens a new current version bound to
    # the change. A change to an input this claim does not read is not a change
    # to this claim: it used to supersede every claim on the deployment at once.
    state_moved = claim_state_moved(current, system_fp=plan.system_fp, input_fps=plan.input_fps)
    policy_moved = current.policy_version != plan.pol_version
    # A person's verdict on this version -- a claim moved to CONTRADICTED with
    # "we know it leaks" -- is not the machine's reading drifting. It stands on
    # this version while the inputs and policy it was set against hold, and a
    # re-derivation refreshes the machine's fields around it. It used to be
    # overwritten in place, and for one round was superseded with a note
    # blaming a gap in CLAIM_INPUTS; neither was true. When the inputs or the
    # policy move, the version is superseded as always -- and a person's STOP
    # carries to the new version (:func:`_persons_stop`).
    human_status = _status_set_by_a_person(current)
    reading_moved = not (state_moved or policy_moved) and not _same_reading(
        current, derived, human_status=human_status
    )
    if not (state_moved or policy_moved or reading_moved):
        audited = _refresh_audit(
            current, derived, now, human_status=human_status, held=held, audit_context=(audit_subject, items),
        )
        step.update(
            action="refresh",
            human_status=human_status,
            audit_context=(audit_subject, items),
            audited=audited,
            # Read and compared here, outside the lock: a weighing the audit
            # leaves as it was is not written again (its size grows with the
            # evidence). The row's token guards it -- every writer of a
            # weighing writes its claim.
            weighing_unchanged=audited is not None and ea.stored_weighing(current) == ea.weighing_of(audited),
        )
        return

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
    stop = _persons_stop(current)
    step.update(
        action="supersede",
        note=note,
        carried_stop=stop,
        audited=audit_new(derived_base) if stop is None else audit_new(stop.to_status, by_person=True),
    )


def _moved_steps(plan: _Plan) -> list[dict]:
    """The steps of ``plan`` whose claim identity moved since they were planned, read
    under the write lock: its current version (or still none), the evidence recorded
    against it and every invalidation of it, and whether a fired condition holds it.
    Only the identities the plan WRITES are checked -- a REVOKED claim it keeps is
    never written -- and nothing else on the deployment is: a move on another claim
    moves only that claim's step. Keeps each locked row on its step; ``[]`` means the
    plan holds and may be written."""
    held_now = held_by_fired_conditions(plan.dep)
    moved = []
    for step in plan.steps:
        if step["action"] == "keep":
            continue
        identity_fp = step["identity_fp"]
        row = (
            AssuranceClaim.objects.select_for_update(of=("self",))
            .filter(deployment=plan.dep, fingerprint=identity_fp)
            .current()
            .first()
        )
        if (
            (None if row is None else ea.claim_token(row)) != step["token"]
            or ea.evidence_token(plan.dep.pk, identity_fp) != step["evidence"]
            or (identity_fp in held_now) != step["held"]
        ):
            moved.append(step)
            continue
        step["row"] = row
    if not moved:
        plan.held = held_now
    return moved


def _write_plan(plan: _Plan) -> dict:
    """Write ``plan`` (:func:`derive_claims`), under the write lock, onto the rows
    :func:`_moved_steps` found unmoved."""
    dep, now = plan.dep, plan.now
    counts = {"created": 0, "updated": 0, "superseded": 0, "stale": 0}
    for step in plan.steps:
        action, derived, row = step["action"], step["derived"], step.get("row")
        common = dict(
            identity_fp=step["identity_fp"],
            system_fp=plan.system_fp,
            input_fp=step["input_fp"],
            pol_version=plan.pol_version,
            receipt_digest=plan.receipt_digest,
            derived=derived,
            now=now,
            held=step["held"],
            audited=step["audited"] if action != "keep" else None,
        )
        if action == "create":
            _make_claim(dep, **common)
            counts["created"] += 1
        elif action == "refresh":
            if not row.input_fingerprint:
                # A legacy row whose state and reading both still hold: bind it to
                # its inputs now, so the next change is read per claim rather than
                # for the whole deployment.
                row.input_fingerprint = step["input_fp"]
            if _refresh_machine_fields(
                row, derived, plan.receipt_digest, now, human_status=step["human_status"], held=step["held"],
                audit_context=step["audit_context"], audited=step["audited"],
                weighing_unchanged=step["weighing_unchanged"],
            ):
                counts["updated"] += 1
        elif action == "supersede":
            _supersede(row, dep, note=step["note"], carried_stop=step["carried_stop"], **common)
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
        dep, system_fp=plan.system_fp, policy_version=plan.pol_version, now=now, input_fps=plan.input_fps,
        held=plan.held,
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


class ClaimChanged(IllegalClaimTransition):
    """A person's move decided from a read of the claim that is no longer the row
    as committed -- a stop, a supersession or another move landed in between.
    Nothing was written; the caller re-reads and decides again (a 409). Never
    raised for a stop: a stop is applied to the row as committed."""


def _locked_row(claim: AssuranceClaim) -> AssuranceClaim:
    """``claim``'s row as committed now, under the write lock: ``select_for_update``
    where the database has row locks, and on SQLite the database write lock the
    transaction took at BEGIN (IMMEDIATE, config.settings) -- so no other write
    lands between this read and the transition's own."""
    return AssuranceClaim.objects.select_for_update(of=("self",)).get(pk=claim.pk)


def _adopt(claim: AssuranceClaim, row: AssuranceClaim) -> None:
    """Bring the caller's copy of the claim to the row the transition wrote."""
    if claim is row:
        return
    deferred = row.get_deferred_fields()
    for field in row._meta.concrete_fields:
        if field.attname not in deferred:
            setattr(claim, field.attname, getattr(row, field.attname))


def _changed_since_read(read: AssuranceClaim, row: AssuranceClaim) -> str:
    """Why the caller's read of a claim is not the row as committed, or "" when it
    is: its status, whether it is still the current version, or the reading under
    its evidence hold moved since it was read."""
    def reads(claim):
        reading = ea.reading_status(claim)
        return claim.status if reading == claim.status else f"{claim.status} (reading {reading} under a hold)"

    if (read.status, ea.reading_status(read), read.valid_to) == (row.status, ea.reading_status(row), row.valid_to):
        return ""
    now = "a re-derive superseded this version" if row.valid_to is not None else f"it reads {reads(row)} now"
    return (
        f"The claim changed since it was read: it read {reads(read)}, and {now}. Nothing was "
        "written; re-read the claim and decide again."
    )


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
    evidence. Writes an attributed :class:`ClaimEvent`. Atomic so the change and
    its audit record land together or not at all.

    A STOP -- contradict, revoke -- is never refused, whatever the claim reads or
    its evidence holds it at (:func:`_take_down`). Every other move is a move of the
    claim's READING (:func:`assurance.evidence_audit.reading_status`: under an
    evidence hold, the reading under it), judged from that reading: a move at or
    below it is recorded, and the evidence goes on holding the claim back as far as
    it does; a move above it that the evidence would hold back at once is refused
    (:func:`assurance.evidence_audit.refusal_for_transition`)."""
    to_status = Status(to_status)

    if to_status in _MACHINE_ONLY_TARGETS:
        raise IllegalClaimTransition(
            f"{to_status} is a machine-only status, not a valid human transition target."
        )
    # Decided from the row as committed at the moment it is written, never from the
    # caller's earlier read. The transition route loaded the claim before its
    # transaction opened; a request that arrived while another write was open read
    # the claim as it was before that write, waited for the lock, and wrote its
    # decision over it -- a person's move landed on a revoke that had just
    # committed, and the claim read partially_verified, un-revoked (round 3, N2).
    row = _locked_row(claim)
    # A take-down (revoke, contradict) is a stop (safety.stops), and the evidence has
    # nothing to say to it: nothing ranks below CONTRADICTED, so the audit can never
    # hold one back, and a withdrawal is never audited. So it does no evidence work
    # at all -- no read of the items, of the route serving now, no classification --
    # and nothing the audit does can refuse it, fail it or make it wait: its cost
    # used to grow with every item recorded against the claim (400 ms at 3,000),
    # and an audit that raised refused it. It is applied to the row as committed,
    # whatever the caller read: a stop is never lost to a race and never refused.
    if to_status.value in ea.STOPS:
        event = _take_down(row, to_status, actor=actor, note=note)
        _adopt(claim, row)
        return event
    # A person's move is a judgment of what they read. Read before a stop, a
    # supersession or another move committed, it is not a judgment of the claim
    # as it is: refused, and nothing written over what landed.
    changed = _changed_since_read(claim, row)
    if changed:
        raise ClaimChanged(changed)
    event = _move(row, to_status, actor=actor, note=note)
    _adopt(claim, row)
    return event


def _move(claim: AssuranceClaim, to_status, *, actor, note: str) -> ClaimEvent:
    """A person's non-stop move of the locked, committed row ``claim``."""
    from_status = claim.status

    reading = ea.reading_status(claim)
    held = reading != from_status
    if held and to_status == reading:
        # Asks for nothing but the hold's release: refused with its reason.
        raise IllegalClaimTransition(ea.refusal_for_transition(claim, to_status))
    if not can_transition(reading, to_status):
        if held:
            raise IllegalClaimTransition(
                f"{reading} → {to_status} is not a legal claim transition: the claim reads "
                f"{reading} under the evidence hold at {from_status}."
            )
        raise IllegalClaimTransition(
            f"{from_status} → {to_status} is not a legal claim transition."
        )
    if to_status == Status.VERIFIED and not _can_verify(claim):
        raise IllegalClaimTransition(
            "Cannot verify a claim whose evidence is not configuration/technically "
            "verified, or that rests on vendor assertions."
        )
    # The evidence recorded against the claim (issue #333), read against the
    # person's status as the reading. A move above the reading that the audit would
    # hold back at once -- a pass over a contradiction, over a load-bearing failure,
    # or over adverse evidence it had to refuse -- is refused here, not made and then
    # undone: a person resolves the evidence, not the reading.
    now = timezone.now()
    audited = ea.audit_of(claim, base_status=to_status.value, now=now, reading_by_person=True)
    refusal = ea.refusal_for_transition(claim, to_status, now=now, audited=audited)
    if refusal:
        raise IllegalClaimTransition(refusal)
    return _move_reading(claim, to_status, audited, actor=actor, note=note, now=now)


def _take_down(claim: AssuranceClaim, stop: str, *, actor, note: str) -> ClaimEvent:
    """A person's contradict or revoke: never refused, and no evidence work.

    Whatever the claim reads, the stop is its reading now. Where the evidence was
    holding the claim, the stop is recorded as the reading under the hold
    (:func:`assurance.evidence_audit.taken_down`, from the stored audit in hand):
    a person's contradiction of a claim the evidence already held at CONTRADICTED
    was refused as "contradicted -> contradicted", never recorded, and a later
    release of the evidence lifted the claim to the reading the person had taken
    down. The stored audit is otherwise left as it was taken, and every reader marks
    it not current (:func:`assurance.evidence_audit.served_audit`) until the claim's
    next audit, which reads the stop as the reading.

    A claim already withdrawn stays withdrawn -- no stop outranks a withdrawal --
    and the stop is recorded on it, attributed.

    A stop addressed to a SUPERSEDED version is applied to the claim identity's
    CURRENT version, and the event says which version it was addressed to. It only
    lowers assurance, so there is nothing to ask the person first: it was a 400
    naming the version to stop instead, and the claim everything reads stayed
    un-stopped -- also when a re-derive superseded the version while the stop was
    in flight (round 3, R1/N1). With no current version to stop, it is recorded on
    the version it was addressed to, which stays closed history."""
    from_status = claim.status
    if from_status == Status.SUPERSEDED or claim.valid_to is not None:
        addressed = f"[addressed to superseded {claim.uuid}]"
        current = _current_row_of(claim)
        if current is None:
            return ClaimEvent.objects.create(
                claim=claim, from_status=from_status, to_status=from_status, actor=actor,
                cause=ClaimEvent.CAUSE_PERSON_READING,
                note=_clip(f"{note or ''} {addressed} [{stop} asked for; the claim has no current version.]"),
            )
        return _take_down(current, stop, actor=actor, note=_clip(f"{note or ''} {addressed}".strip()))
    if from_status == Status.REVOKED:
        return ClaimEvent.objects.create(
            claim=claim, from_status=from_status, to_status=from_status, actor=actor,
            cause=ClaimEvent.CAUSE_PERSON_READING,
            note=_clip(f"{note or ''} [{stop} asked for; the claim is already withdrawn, which no stop outranks.]"),
        )
    claim.status = stop
    # A stop carries no confidence, on every version: the deriver's CONTRADICTED
    # reads None, and a person's kept the machine's 0.88 until a carry dropped it
    # and a refresh brought it back (round 5, item 8).
    claim.confidence = None
    fields = ["status", "confidence", "updated_at"]
    audit = ea.taken_down(claim.evidence_audit, stop)
    if audit is not claim.evidence_audit:
        claim.evidence_audit = audit
        fields.append("evidence_audit")
    claim.save(update_fields=fields)
    return ClaimEvent.objects.create(
        claim=claim, from_status=from_status, to_status=stop, actor=actor, note=note or "",
        cause=ClaimEvent.CAUSE_PERSON_READING if from_status == stop else "",
    )


def _current_row_of(claim: AssuranceClaim) -> AssuranceClaim | None:
    """The current version of ``claim``'s identity -- the one every reader reads:
    believed now (``valid_to`` null) AND effective now (``effective_to`` null,
    :meth:`~assurance.models.AssuranceClaimQuerySet.current`) -- locked as
    :func:`_locked_row` locks. Never a retroactive version: it is believed now but
    about a window that has closed (``effective_to`` set), and a stop landing there
    would leave the claim everything reads un-stopped. Read again where a row lock
    waited on a writer that closed it (another database's re-derive; SQLite's
    transaction already holds the write lock)."""
    for _attempt in range(3):
        current = (
            AssuranceClaim.objects.select_for_update(of=("self",))
            .filter(deployment_id=claim.deployment_id, fingerprint=claim.fingerprint)
            .current()
            .first()
        )
        if current is not None:
            return current
        if not AssuranceClaim.objects.filter(
            deployment_id=claim.deployment_id, fingerprint=claim.fingerprint
        ).current().exists():
            return None
    return None


def _move_reading(claim: AssuranceClaim, to_status, audited, *, actor, note: str, now) -> ClaimEvent:
    """Record a person's move of the claim's reading to ``to_status``, with the
    evidence audit of it (``audited``, or None where nothing was recorded).

    Where the evidence holds ``to_status`` back -- a downgrade under a hold, which is
    never refused -- the claim stands where the audit holds it, and the person's
    status is the reading under the hold. The person's event is followed by the
    audit's own, so the history shows the person's reading and then what the evidence
    held it at, and the hold is never read as the person's.

    The confidence is the one the status the claim now stands at carries -- the
    person's, or the hold's -- for the claim's evidence class
    (:mod:`assurance.claim_confidence`), and the hold records the one the person's
    reading carries, which is what a release lands on. It used to be written only
    where a hold moved the status, so a person's move left the confidence the claim
    had before it: a claim moved to UNKNOWN kept the deriver's 0.88, and one moved
    back to SUPPORTED over a derived CONTRADICTED read None. Neither reading is above
    the same move with no evidence recorded: that move reads the confidence of the
    person's status, and a hold reads that of a status no higher."""
    from_status = claim.status
    new_status = to_status.value
    fields = ["status", "confidence", "updated_at"]
    held = audited is not None and audited["held"]
    if held:
        audited = {**audited, "base_confidence": claim_confidence(audited["base_status"], claim.evidence_class)}
        new_status = audited["status"]
    if audited is not None:
        fields += ea.store_audit(claim, audited)
    claim.confidence = claim_confidence(new_status, claim.evidence_class)
    claim.status = new_status
    if new_status == Status.VERIFIED:
        claim.verified_at = now
        fields.append("verified_at")
    claim.save(update_fields=fields)
    if audited is not None:
        ea.store_weighing(claim, audited)

    event = ClaimEvent.objects.create(
        claim=claim, from_status=from_status, to_status=to_status, actor=actor, note=note or "",
        cause=ClaimEvent.CAUSE_PERSON_READING if from_status == to_status else "",
    )
    if new_status != to_status:
        ClaimEvent.objects.create(
            claim=claim, from_status=to_status, to_status=new_status, actor=None,
            cause=ClaimEvent.CAUSE_EVIDENCE_AUDIT, note=ea.audit_note(audited),
        )
    return event
