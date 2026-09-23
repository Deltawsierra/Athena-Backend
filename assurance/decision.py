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

from dataclasses import dataclass

from django.db import transaction

from .coverage import complete_audit_signal, coverage_decision_cap, coverage_manifest
from .models import (
    UNTRUSTED_SEVERITY_STATUSES,
    RESOLVED_FINDING_STATUSES,
    AssuranceClaim,
    Deployment,
    EvidenceClass,
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
    # Worse than NEEDS_MORE_EVIDENCE and better than NEEDS_REMEDIATION. Both of the
    # first two are "we do not know", and a coverage gap is the wider of them: weak
    # evidence at least has a subject, whereas an unassessed component could hold
    # anything. But "we found something bad" still outranks "we did not look
    # everywhere" -- a critical finding is a fact, not a gap.
    Deployment.Decision.AUDIT_INCOMPLETE,
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
        deployment.assurance_claims.current().exclude(status=Status.REVOKED)
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


@dataclass(frozen=True)
class DecisionParts:
    """Every input a decision is computed from, read once.

    This exists because reading them twice is a bug with no symptom. A caller that
    wants the decision *and* the reasoning behind it -- which is the whole job of
    :func:`decision_support` -- used to read each input once for the payload and
    then call :func:`compute_decision`, which read all of them again. Between the
    two reads a writer can land, and the answer is then stitched from two moments:
    ordinary-looking, internally impossible, and indistinguishable from a real one.

    Reproduced before this change: 81 samples of ``decision_support`` against a
    concurrent writer whose every write was atomic returned four distinct shapes,
    two of which no single database state can produce -- three contradicted claims
    beside ``decision=None`` (three contradicted claims force a cap), and a clean
    claim set beside ``needs_remediation`` (nothing was left to impose one).

    Frozen because these are facts as of one read, not a mutable scratchpad.
    """

    from_findings: str | None
    completed_scan: str | None
    complete_audit: str | None
    claim_signal: dict
    scan_cap: str | None
    coverage_cap: str | None


def read_decision_parts(deployment: Deployment) -> DecisionParts:
    """Read every decision input, in one pass.

    Wrapped in a transaction by callers that need the set to be consistent. The
    transaction narrows the window; reading each fact exactly once is what closes
    the demonstrated tear, and it does so at any isolation level -- on READ
    COMMITTED a second read of the same fact is a second moment even inside one
    transaction, so "read it once" is the load-bearing half.
    """
    return DecisionParts(
        from_findings=_decision_from_findings(deployment),
        completed_scan=_completed_scan_signal(deployment),
        complete_audit=complete_audit_signal(deployment),
        claim_signal=claim_decision_signal(deployment),
        scan_cap=incomplete_evidence_cap(deployment),
        coverage_cap=coverage_decision_cap(deployment),
    )


def decide(parts: DecisionParts) -> str | None:
    """The decision those parts imply. Pure: no reads, no writes, no clock."""
    # A completed scan is an assessment even when it found nothing, so it enters
    # as READY and `_worse` does the rest: it can only turn "nothing has assessed
    # this" into READY, never improve a real finding-based state. Without it a
    # deployment scanned clean read as "not yet assessed", which is the same
    # answer as a deployment nobody ever scanned.
    base = _worse(
        _worse(parts.from_findings, parts.completed_scan),
        # A complete audit that found nothing is an assessment too, and the reason
        # coverage is recorded rather than only reported: without it, a deployment
        # whose every declared component was assessed clean has no findings and so
        # reads as unassessed -- indistinguishable from one nobody has looked at.
        parts.complete_audit,
    )
    cap = parts.claim_signal["cap"]
    # Coverage of the system, not strength of the evidence: something the customer
    # declared, or something flagged high risk, was never assessed at all. Every
    # fact gathered can be genuine and the audit still be incomplete.
    if base is None and cap is None and parts.scan_cap is None and parts.coverage_cap is None:
        # Assessed by nothing at all: genuinely no decision.
        return None
    return _worse(_worse(_worse(base, cap), parts.scan_cap), parts.coverage_cap)


def compute_decision(
    deployment: Deployment,
    *,
    paused: bool = False,
    parts: DecisionParts | None = None,
) -> str | None:
    """The six-state decision implied by a deployment's active findings, its
    current assurance claims (Stage 1C), and whether its latest scan finished.

    The decision is the *worse* of the finding-based signal, the claim-based cap
    and the incomplete-evidence cap. ``paused`` (the operator failsafe, passed by
    the caller) overrides everything. Returns ``None`` — no decision — only when
    nothing has assessed the deployment; an absent decision is never READY.

    ``parts`` lets a caller that has already read the inputs hand them over
    instead of having them read a second time. That is not an optimisation: two
    reads of the same fact are two moments, and a caller reporting both the
    decision and its reasoning must report one moment or neither.
    """
    if paused:
        # Nothing is read at all: the failsafe decides, so no fact about the
        # deployment can change the answer.
        return Deployment.Decision.PAUSED
    return decide(parts if parts is not None else read_decision_parts(deployment))


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

    A read-only computed view; it does not persist anything.

    Every input is read ONCE, inside one transaction, and the decision is derived
    from that one read rather than recomputed from a second one. This function is
    the artifact the roadmap's "no torn read" bar is about -- it returns the
    decision *and the claims behind it*, which is exactly the pair that must not
    come from two moments -- and it was the one place doing it twice.

    The revision the parts were read at rides in the payload so a consumer can
    fence its own next read (``assurance.revision.read_decision(at_least=...)``).
    Before this, the fence existed only for in-process Python callers: nothing over
    HTTP could tell a fresh answer from a stale one.
    """
    # Lazy import: assurance.policy imports the decision rules from THIS module, so
    # a top-level import here would be circular.
    from .policy import policy_pin

    with transaction.atomic():
        parts = read_decision_parts(deployment)
        # Read inside the same transaction as the parts, so the revision names the
        # moment the parts describe rather than a later one.
        revision = (
            Deployment.objects.values_list("decision_revision", flat=True)
            .filter(pk=deployment.pk)
            .first()
        )
    signal = parts.claim_signal
    from_findings = None if paused else parts.from_findings
    scan_cap = None if paused else parts.scan_cap
    coverage_cap = None if paused else parts.coverage_cap
    decision = compute_decision(deployment, paused=paused, parts=parts)

    if paused:
        note = "Operator failsafe is paused; the deployment is not deploying regardless of findings or claims."
    elif coverage_cap is not None and decision == Deployment.Decision.AUDIT_INCOMPLETE:
        manifest = coverage_manifest(deployment)
        note = (
            f"Held at 'audit incomplete': {manifest['summary']}. Parts of the system "
            "were never assessed, so every fact gathered here can be genuine and the "
            "assessment still be short."
        )
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
        # The monotonic revision the whole payload was read at. A consumer that
        # acts on this answer can pass it back as `at_least` and be told, rather
        # than guess, whether what it is holding has been superseded.
        "revision": revision,
        "from_findings": from_findings,
        "claim_cap": signal["cap"],
        "coverage_cap": coverage_cap,
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
    (``None`` for a deployment neither findings nor claims have assessed).

    The write goes through :func:`assurance.revision.accept_transition` rather
    than a bare save, so the decision, its monotonic revision and the transition
    recording the move all commit together. Before that, the decision moved on its
    own: a consumer reading it alongside the claims behind it could catch the two
    from different moments, and the result was an ordinary-looking answer
    assembled from a state that never existed.
    """
    from .revision import accept_transition

    decision = compute_decision(deployment, paused=paused)
    accept_transition(deployment, to_decision=decision)
    return decision
