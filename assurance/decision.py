"""Aggregate a deployment's findings AND its assurance claims into its six-state
deployment decision.

Phase 0.5 gave a Deployment a `decision` field and computed it from the live
findings so a scan culminates in a decision-support artifact, not a vulnerability
count. SPINE Stage 1C adds the other half of the loop: a decision now also depends
on the deployment's **current assurance claims**, so a "ready" decision stays
valid only while the claims that support it remain current. When a change
invalidates a claim (SPINE Phase 2 marks it stale and opens a retest obligation),
the decision drops on its own — "it passed six months ago" stops reading as "it is
safe now". Evidence for a human release decision, never the decision itself.

Two independent signals, combined worst-first:

- **Findings** (Phase 0.5) place the deployment by the worst active finding: a
  CRITICAL → NOT_RECOMMENDED, HIGH → NEEDS_REMEDIATION, MEDIUM/LOW →
  READY_RESTRICTED, only-unverified → NEEDS_MORE_EVIDENCE, nothing → READY. A
  deployment with no findings of any status is *unassessed by findings* (``None``).
  An **INVALIDATED** finding does not place the deployment by its recorded
  severity — that premise moved — but counts as a gap, so it reads as "needs more
  evidence" rather than as either a live severity or a clean pass.
- **Claims** (Stage 1C) cap the decision by claim health. A live CONTRADICTED claim
  (an assurance statement the current state falsifies) caps at NEEDS_REMEDIATION; a
  STALE or UNKNOWN claim, or any open retest obligation, caps at
  NEEDS_MORE_EVIDENCE. Supported/verified claims and a deployment with no claims add
  no cap.

The decision is the **worse** of the two. The claim cap can only hold a decision
back or leave it, never improve it (the same weakest-link discipline the evidence
model keeps): a green finding set cannot paper over a contradicted claim, and a
contradicted claim cannot make a critical finding look better. The decision is
``None`` — *no decision* — only when neither signal has assessed anything; an absent
decision is never READY. ``paused`` (the operator failsafe) still overrides
everything.
"""

from __future__ import annotations

from .models import (
    UNTRUSTED_SEVERITY_STATUSES,
    RESOLVED_FINDING_STATUSES,
    AssuranceClaim,
    Deployment,
    EvidenceClass,
    Finding,
    RetestRequirement,
    severity_rank,
)

# Findings in these states no longer count against a deployment's readiness.
# The one definition lives in ``assurance.models`` beside the statuses themselves.
# Seven modules each kept their own copy of this set, and every one of their
# comments said it "mirrors" the others so every view would agree on what "active"
# means -- which is precisely the arrangement that lets them stop agreeing. Adding
# a status meant editing eight places and silently disagreeing if you missed one.
_RESOLVED_STATUSES = RESOLVED_FINDING_STATUSES

# Evidence classes that mean "we genuinely do not know this" — they drive
# "Requires additional evidence" rather than a clean pass. This is deliberately
# NARROWER than the Unknowns Register's unverified set (which also includes
# ``partially_verified``): a partially-verified finding carries a severity that
# already places the deployment (READY_RESTRICTED and up), so it does not also
# need this info-severity fallback state — whereas the register still tracks it
# as a gap to confirm. The two serve different axes (how bad vs. how sure) and
# only truly-unknown evidence, with no severity to place it, lands here.
_UNVERIFIED = frozenset({EvidenceClass.UNKNOWN, EvidenceClass.NOT_DOCUMENTED})

# Readiness order, best (0) to worst. "Worse" wins when the two signals combine,
# and a cap is a floor on how bad the decision must be — never a ceiling that could
# improve it. PAUSED is worst because a paused engine is not deploying at all.
_READINESS_ORDER = (
    Deployment.Decision.READY,
    Deployment.Decision.READY_RESTRICTED,
    Deployment.Decision.NEEDS_MORE_EVIDENCE,
    Deployment.Decision.NEEDS_REMEDIATION,
    Deployment.Decision.NOT_RECOMMENDED,
    Deployment.Decision.PAUSED,
)
_READINESS_RANK = {state: rank for rank, state in enumerate(_READINESS_ORDER)}


def _worse(a: str | None, b: str | None) -> str | None:
    """The worse (less ready) of two decision states, ``None``-safe. ``None`` is
    "not assessed by this signal" and never wins over a real state."""
    if a is None:
        return b
    if b is None:
        return a
    return a if _READINESS_RANK[a] >= _READINESS_RANK[b] else b


def _decision_from_findings(deployment: Deployment) -> str | None:
    """The six-state decision implied by a deployment's active findings (Phase 0.5).

    ``None`` when the deployment has no findings of any status — unassessed by
    findings, which is not the same as a deployment whose findings are all resolved
    (genuinely READY)."""
    if not deployment.findings.exists():
        return None

    active = list(
        deployment.findings.exclude(status__in=_RESOLVED_STATUSES).prefetch_related("evidence")
    )

    worst_rank = -1
    has_unverified = False
    for f in active:
        if f.status in UNTRUSTED_SEVERITY_STATUSES:
            # An INVALIDATED finding was assessed and then the ground moved. Its
            # recorded severity is a number the evidence no longer supports, so it
            # does not place the deployment -- but it is not resolved either, and
            # dropping it would hand back a clean bill nobody established. It
            # counts as a gap: "needs more evidence", the same as truly unknown
            # evidence.
            has_unverified = True
            continue
        rank = severity_rank(f.severity)
        if rank > worst_rank:
            worst_rank = rank
        if f.evidence_class in _UNVERIFIED:
            has_unverified = True

    if worst_rank >= severity_rank("critical"):
        return Deployment.Decision.NOT_RECOMMENDED
    if worst_rank >= severity_rank("high"):
        return Deployment.Decision.NEEDS_REMEDIATION
    if worst_rank >= severity_rank("low"):
        # A medium or low active finding is deployable with named restrictions.
        return Deployment.Decision.READY_RESTRICTED
    # Nothing of low+ severity is open. If what remains is only unverified
    # (info-severity but unknown evidence), the honest answer is "need more
    # evidence", not a clean pass.
    if has_unverified:
        return Deployment.Decision.NEEDS_MORE_EVIDENCE
    return Deployment.Decision.READY


def claim_decision_signal(deployment: Deployment) -> dict:
    """How the deployment's CURRENT assurance claims bear on its decision (Stage 1C).

    Reads the current version of each claim (``valid_to`` null), excluding human
    REVOKED withdrawals (a claim the human took out of scope is neither support nor
    a mark against readiness), plus the deployment's open retest obligations. Returns
    the claims bucketed by how they bear on readiness and the cap they impose:

    - a live **CONTRADICTED** claim caps at NEEDS_REMEDIATION — the current state
      falsifies an assurance statement, and that is not deployable without work;
    - a **STALE** or **UNKNOWN** claim, or any **open retest obligation**, caps at
      NEEDS_MORE_EVIDENCE — the supporting evidence is expired, unproven, or pending
      a retest, so a clean pass is not earned;
    - SUPPORTED / VERIFIED / PARTIALLY_VERIFIED claims (and DRAFT, which is not yet
      an assessment) impose no cap.

    ``cap`` is ``None`` when no current claim holds the decision back — including a
    deployment with no claims at all, so the finding-based decision governs
    unchanged. The cap never *improves* a decision.
    """
    Status = AssuranceClaim.ClaimStatus
    current = list(
        deployment.assurance_claims.filter(valid_to__isnull=True).exclude(status=Status.REVOKED)
    )
    retest_pending = RetestRequirement.objects.filter(
        deployment=deployment, resolved_at__isnull=True
    ).exists()

    contradicted = [c for c in current if c.status == Status.CONTRADICTED]
    stale = [c for c in current if c.status == Status.STALE]
    unknown = [c for c in current if c.status == Status.UNKNOWN]
    supporting = [
        c
        for c in current
        if c.status in (Status.SUPPORTED, Status.VERIFIED, Status.PARTIALLY_VERIFIED)
    ]

    if contradicted:
        cap = Deployment.Decision.NEEDS_REMEDIATION
    elif stale or unknown or retest_pending:
        cap = Deployment.Decision.NEEDS_MORE_EVIDENCE
    else:
        cap = None

    return {
        "cap": cap,
        "has_claims": bool(current),
        "retest_pending": retest_pending,
        "contradicted": contradicted,
        "stale": stale,
        "unknown": unknown,
        "supporting": supporting,
    }


def _completed_scan_signal(deployment: Deployment) -> str | None:
    """READY once a scan has run to completion against this deployment, else ``None``.

    Folded into the finding signal with :func:`_worse`, so it is a floor and not a
    cap: it lifts an unassessed deployment to READY and cannot make any real state
    look better. The distinction it carries is the one the finding count cannot --
    "a scan finished and found nothing" versus "nothing has ever been scanned"."""
    if deployment.last_complete_scan_at is None:
        return None
    return Deployment.Decision.READY


def incomplete_evidence_cap(deployment: Deployment) -> str | None:
    """The cap a deployment's *unfinished* latest scan imposes, or ``None``.

    A scan the engine stopped early (the operator hit the failsafe, a ceiling
    tripped) leaves the deployment assessed by a fraction of the work, and the
    scanners that did not run are the ones that would have found the rest. So
    partial evidence caps at NEEDS_MORE_EVIDENCE: it can hold a decision back,
    never improve one. Nothing about it is a finding, which is why the finding
    signal alone could read a stopped scan as READY."""
    if deployment.evidence_incomplete:
        return Deployment.Decision.NEEDS_MORE_EVIDENCE
    return None


def compute_decision(deployment: Deployment, *, paused: bool = False) -> str | None:
    """The six-state decision implied by a deployment's active findings, its
    current assurance claims (Stage 1C), and whether its latest scan finished.

    The decision is the *worse* of the finding-based signal, the claim-based cap
    and the incomplete-evidence cap. ``paused`` (the operator failsafe, passed by
    the caller) overrides everything. Returns ``None`` — no decision — only when
    nothing has assessed the deployment; an absent decision is never READY."""
    if paused:
        return Deployment.Decision.PAUSED

    # A completed scan is an assessment even when it found nothing, so it enters
    # as READY and `_worse` does the rest: it can only turn "nothing has assessed
    # this" into READY, never improve a real finding-based state. Without it a
    # deployment scanned clean read as "not yet assessed", which is the same
    # answer as a deployment nobody ever scanned.
    base = _worse(_decision_from_findings(deployment), _completed_scan_signal(deployment))
    cap = claim_decision_signal(deployment)["cap"]
    scan_cap = incomplete_evidence_cap(deployment)
    if base is None and cap is None and scan_cap is None:
        # Assessed by nothing at all: genuinely no decision.
        return None
    return _worse(_worse(base, cap), scan_cap)


def _claim_brief(claim: AssuranceClaim) -> dict:
    """The minimal, non-sensitive identity of a claim for a decision-support view —
    what it is and where it stands, no raw evidence."""
    return {
        "uuid": str(claim.uuid),
        "claim_type": claim.claim_type,
        "status": claim.status,
        "statement": claim.statement,
    }


def decision_support(deployment: Deployment, *, paused: bool = False) -> dict:
    """The deployment's decision with *why* — the honest decision-support artifact
    (Stage 1C). Shows the final decision, the finding-based signal and the claim cap
    that combined into it, and exactly which current claims support or undermine it,
    so a reader can see that a READY decision stands only while its claims stay
    current.

    A read-only computed view; it does not persist anything."""
    # Lazy import: assurance.policy imports the decision rules from THIS module, so
    # a top-level import here would be circular.
    from .policy import policy_pin

    signal = claim_decision_signal(deployment)
    from_findings = None if paused else _decision_from_findings(deployment)
    scan_cap = None if paused else incomplete_evidence_cap(deployment)
    decision = compute_decision(deployment, paused=paused)

    if paused:
        note = "Operator failsafe is paused; the deployment is not deploying regardless of findings or claims."
    elif scan_cap is not None and _worse(from_findings, signal["cap"]) != decision:
        note = (
            "Held at 'needs more evidence' because the latest scan stopped before "
            "it finished; the scanners that did not run are not accounted for, so "
            "this is not a clean result."
        )
    elif signal["cap"] and _worse(from_findings, signal["cap"]) == signal["cap"] and from_findings != signal["cap"]:
        held = ", ".join(sorted({c.claim_type for c in signal["contradicted"] + signal["stale"] + signal["unknown"]}))
        if signal["contradicted"]:
            note = f"Held at 'needs remediation' by a contradicted assurance claim ({held}); a current claim's boundary does not hold."
        else:
            reason = "an open retest obligation" if signal["retest_pending"] and not (signal["stale"] or signal["unknown"]) else f"a stale or unproven claim ({held})"
            note = f"Held at 'needs more evidence' by {reason}; supporting evidence is not current."
    elif decision == Deployment.Decision.READY and signal["supporting"]:
        note = f"Ready, and supported by {len(signal['supporting'])} current assurance claim(s) with no open retest."
    elif decision is None:
        note = "Not yet assessed: no findings and no assurance claims."
    else:
        note = "Decision reflects the deployment's active findings; no current claim holds it back."

    return {
        "decision": decision,
        "decision_label": Deployment.Decision(decision).label if decision else None,
        "from_findings": from_findings,
        "claim_cap": signal["cap"],
        "paused": paused,
        # The assurance policy this decision is made under — pinned so a later
        # change to the rules can tell whether the policy still holds.
        "policy_version": policy_pin(deployment),
        "claims": {
            "has_claims": signal["has_claims"],
            "retest_pending": signal["retest_pending"],
            "contradicted": [_claim_brief(c) for c in signal["contradicted"]],
            "stale": [_claim_brief(c) for c in signal["stale"]],
            "unknown": [_claim_brief(c) for c in signal["unknown"]],
            "supporting": [_claim_brief(c) for c in signal["supporting"]],
        },
        "note": note,
    }


def recompute_decision(deployment: Deployment, *, paused: bool = False) -> str | None:
    """Compute and persist the deployment's decision. Returns the new decision
    (``None`` for a deployment neither findings nor claims have assessed)."""
    decision = compute_decision(deployment, paused=paused)
    if deployment.decision != decision:
        deployment.decision = decision
        deployment.save(update_fields=["decision", "updated_at"])
    return decision
