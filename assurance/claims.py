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
  opens a new one when the system state has changed. It also marks a current,
  non-contradicted claim STALE once its evidence expires — never toward a pass.

- **:func:`apply_claim_transition`** — the attributed lifecycle state machine,
  mirroring :mod:`assurance.remediation`. It refuses illegal jumps, refuses to let
  STALE/SUPERSEDED be a human target, and HARD-refuses any move into VERIFIED that
  is not backed by configuration/technically-verified, non-vendor evidence.

The system_fingerprint-change → supersede seam is the cross-version mechanism
here; the temporal INVALIDATES backbone that turns a state change into an
attributed, durable *retest obligation* on the affected claims lives in
:mod:`assurance.invalidation` (SPINE Phase 2), which extends this module. Its one
tie-back into :func:`derive_claims` is at the end of the reconciler: once a
re-derivation has rebound a claim to the changed state, any open retest obligation
that rebinding satisfies is resolved (:func:`assurance.invalidation.resolve_satisfied_requirements`).
"""

from __future__ import annotations

import hashlib
from datetime import timedelta

from django.db import transaction
from django.utils import timezone

from . import observability as obs
from .access import assess_effective_access
from .bom import build_ai_bom
from .bom_drift import assess_bom_drift
from .boundary import assess_boundary
from .capability import RISK_HIGH
from .change import EVIDENCE_TTL_DAYS, age_days
from .fingerprint import compute_system_fingerprint, policy_version
from .models import AssuranceClaim, ClaimEvent, Deployment, EvidenceClass, evidence_strength
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
    gap ⇒ CONTRADICTED; nothing to assess (no principals) ⇒ UNKNOWN; otherwise
    SUPPORTED, promoted to VERIFIED only when the reach is configuration-verified
    and no high-risk gap of any kind remains. The reach is read from declared
    configuration, so its evidence class is ``configuration_verified``.

    **An unresolved reference caps the claim at SUPPORTED.** The reach is computed
    over the graph the inventory declares, and a dangling reference means part of
    that graph could not be placed: the assessment cannot have followed a hop into
    a component discovery never found. "No high-risk reach" over an incomplete
    graph is a measurement of what we could see, not a verification, and calling it
    VERIFIED would turn the hole into a clean bill of health."""
    result = assess_effective_access(deployment)
    principals = result["principals"]
    unresolved = result["unresolved"]

    if not principals:
        status = Status.UNKNOWN
        evidence_class = EvidenceClass.UNKNOWN.value
        vendor_asserted = True
        # An unplaceable reference on a graph with no principals is recorded in the
        # supporting digest rather than as contradicting evidence: there is no
        # positive claim here for it to contradict, and it is still the reason an
        # operator should not read "nothing to assess" as "nothing here".
    else:
        gaps = [g for p in principals for g in p["gaps"]]
        contradicting = [
            g for g in gaps if g["type"] in _CONTRADICTING_ACCESS_GAPS and g["risk"] == RISK_HIGH
        ]
        any_high_risk_gap = any(g["risk"] == RISK_HIGH for g in gaps)
        evidence_class = EvidenceClass.CONFIGURATION_VERIFIED.value
        vendor_asserted = False
        if contradicting:
            status = Status.CONTRADICTED
        elif not any_high_risk_gap and not unresolved:
            status = Status.VERIFIED
        else:
            status = Status.SUPPORTED

    summary = result["summary"]
    supporting = (
        f"{summary['principals']} principal(s) assessed; "
        f"{summary['privileged']} privileged, {summary['shadow']} shadow, {summary['over_broad']} over-broad."
    )
    if unresolved and not principals:
        supporting += (
            f" {len(sorted({(u['source'], u['reference']) for u in unresolved}))} declared "
            "reference(s) could not be placed, so this is what we could read of the "
            "inventory rather than all of it."
        )
    contradicting_bits: list[str] = []
    if unresolved and principals:
        # Counted over the SAME set it enumerates. It used to count len(unresolved)
        # and enumerate a set of "source → reference" pairs, so a duplicated
        # inventory line said "2 declared reference(s)" above one pair: an operator
        # told to chase two and handed one goes looking for a reference that does
        # not exist. Distinct pairs, counted and listed.
        #
        # Only on the `principals` branch. With nothing to assess the claim is
        # UNKNOWN and vendor_asserted, and appending measured contradicting
        # evidence there produced a claim that said "nothing to assess", "the
        # vendor asserted this" and "here is evidence we measured against it" at
        # once -- and vendor_asserted is flatly wrong for a finding this platform
        # produced itself.
        pairs = sorted({f"{u['source']} → {u['reference']}" for u in unresolved})
        contradicting_bits.append(
            f"{len(pairs)} declared reference(s) discovery could not place, so the "
            "reach was computed over an incomplete graph: " + ", ".join(pairs) + "."
        )
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


def _make_claim(deployment, *, identity_fp, system_fp, pol_version, receipt_digest, derived, now, human_owner=None) -> AssuranceClaim:
    """Create a new CURRENT claim version from a deriver's output, and seed its
    lifecycle with a ``∅ → status`` :class:`ClaimEvent`."""
    status = derived["status"]
    claim = AssuranceClaim.objects.create(
        deployment=deployment,
        asset=derived["subject"],
        claim_type=derived["claim_type"],
        statement=derived["statement"],
        fingerprint=identity_fp,
        system_fingerprint=system_fp,
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
        valid_from=now,
        first_seen=now,
        last_seen=now,
        verified_at=now if status == Status.VERIFIED else None,
        expiration=now + timedelta(days=EVIDENCE_TTL_DAYS),
    )
    ClaimEvent.objects.create(
        claim=claim, from_status="", to_status=status, actor=None, note="Derived"
    )
    return claim


def _refresh_machine_fields(claim: AssuranceClaim, derived, receipt_digest, now) -> bool:
    """Refresh a current claim's MACHINE fields in place (system state unchanged),
    preserving every human field. Writes a :class:`ClaimEvent` only on an actual
    status change. Returns whether the row was updated."""
    old_status = claim.status
    new_status = derived["status"]

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
            claim=claim, from_status=old_status, to_status=new_status, actor=None, note="Re-derived"
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


def _supersede(current: AssuranceClaim, deployment, *, identity_fp, system_fp, pol_version, receipt_digest, derived, now) -> None:
    """Close the current version (``valid_to`` set, status SUPERSEDED, its own
    ClaimEvent), open a new current version bound to the new system state, and link
    ``old.superseded_by = new``. The old version is closed BEFORE the new one is
    created so the partial unique constraint (one current version per identity) is
    never momentarily violated."""
    old_status = current.status
    current.valid_to = now
    current.status = Status.SUPERSEDED
    current.save(update_fields=["valid_to", "status", "updated_at"])
    ClaimEvent.objects.create(
        claim=current,
        from_status=old_status,
        to_status=Status.SUPERSEDED,
        actor=None,
        note="System fingerprint changed; version superseded.",
    )
    new_claim = _make_claim(
        deployment,
        identity_fp=identity_fp,
        system_fp=system_fp,
        pol_version=pol_version,
        receipt_digest=receipt_digest,
        derived=derived,
        now=now,
        human_owner=current.human_owner,
    )
    current.superseded_by = new_claim
    current.save(update_fields=["superseded_by", "updated_at"])


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
    fingerprint and the current system fingerprint; finds the current version
    (``valid_to`` null); then creates it, refreshes it in place (system state
    unchanged), or supersedes it (system state changed). A human REVOKED claim is
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
    pol_version = policy_version(dep)
    receipt_digest = build_assurance_receipt(dep)["digest"]

    counts = {"created": 0, "updated": 0, "superseded": 0, "stale": 0}

    for deriver in _DERIVERS:
        derived = deriver(dep)
        subject = derived["subject"]
        subject_key = str(subject.uuid) if subject is not None else ""
        identity_fp = _identity_fingerprint(dep, derived["claim_type"], subject_key)

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
                pol_version=pol_version,
                receipt_digest=receipt_digest,
                derived=derived,
                now=now,
            )
            counts["created"] += 1
            continue

        # A human REVOKED claim is a withdrawal; a re-derive never touches it — not
        # its status, not its last_seen, not a supersede.
        if current.status == Status.REVOKED:
            continue

        # A claim is bound to BOTH the system state and the policy it was assessed
        # under. It is refreshed in place only while both still hold; a change to
        # either the system fingerprint OR the policy version supersedes it and opens
        # a new current version bound to the change, so a policy change versions a
        # claim exactly as a state change does.
        if current.system_fingerprint == system_fp and current.policy_version == pol_version:
            if _refresh_machine_fields(current, derived, receipt_digest, now):
                counts["updated"] += 1
        else:
            _supersede(
                current,
                dep,
                identity_fp=identity_fp,
                system_fp=system_fp,
                pol_version=pol_version,
                receipt_digest=receipt_digest,
                derived=derived,
                now=now,
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

    resolve_satisfied_requirements(dep, system_fp=system_fp, policy_version=pol_version, now=now)
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
