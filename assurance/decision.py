"""Aggregate a deployment's findings into its six-state deployment decision.

Phase 0.5 of the reconciled Athena roadmap. Phase 0.1 gave a Deployment a
`decision` field with the full six-state vocabulary; this computes it from the
deployment's live findings so a scan culminates in a decision-support artifact,
not a vulnerability count. Evidence for a human release decision, never the
decision itself.

Precedence, worst first (the deployment carries the worst active outcome):

    PAUSED               operator failsafe is paused (an override the caller passes)
    NOT_RECOMMENDED      an active CRITICAL finding
    NEEDS_REMEDIATION    an active HIGH finding
    READY_RESTRICTED     an active MEDIUM or LOW finding
    NEEDS_MORE_EVIDENCE  only unverified findings (evidence UNKNOWN / NOT_DOCUMENTED)
    READY                nothing active and unresolved

Only *active* findings drive the decision: a finding that is verified-closed,
accepted as risk, or a false positive no longer counts against readiness.
"""

from __future__ import annotations

from .models import Deployment, EvidenceClass, Finding, severity_rank

# Findings in these states no longer count against a deployment's readiness.
_RESOLVED_STATUSES = frozenset(
    {Finding.Status.CLOSED, Finding.Status.ACCEPTED, Finding.Status.FALSE_POSITIVE}
)

# Evidence classes that mean "we genuinely do not know this" — they drive
# "Requires additional evidence" rather than a clean pass. This is deliberately
# NARROWER than the Unknowns Register's unverified set (which also includes
# ``partially_verified``): a partially-verified finding carries a severity that
# already places the deployment (READY_RESTRICTED and up), so it does not also
# need this info-severity fallback state — whereas the register still tracks it
# as a gap to confirm. The two serve different axes (how bad vs. how sure) and
# only truly-unknown evidence, with no severity to place it, lands here.
_UNVERIFIED = frozenset({EvidenceClass.UNKNOWN, EvidenceClass.NOT_DOCUMENTED})


def compute_decision(deployment: Deployment, *, paused: bool = False) -> str | None:
    """The six-state decision implied by a deployment's active findings.

    Returns ``None`` — *no decision* — for a deployment that has never been
    assessed (no findings at all); an absent decision is never READY. ``paused``
    (the operator failsafe state, passed by the caller) overrides everything: a
    paused engine is not deploying regardless of findings."""
    if paused:
        return Deployment.Decision.PAUSED

    # A deployment with no findings of any status has not been assessed. That is
    # not the same as a deployment whose findings are all resolved (genuinely
    # READY) — so guard on the total, not the active set.
    if not deployment.findings.exists():
        return None

    active = list(
        deployment.findings.exclude(status__in=_RESOLVED_STATUSES).prefetch_related("evidence")
    )

    worst_rank = -1
    has_unverified = False
    for f in active:
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


def recompute_decision(deployment: Deployment, *, paused: bool = False) -> str | None:
    """Compute and persist the deployment's decision. Returns the new decision
    (``None`` for a deployment with no findings to assess)."""
    decision = compute_decision(deployment, paused=paused)
    if deployment.decision != decision:
        deployment.decision = decision
        deployment.save(update_fields=["decision", "updated_at"])
    return decision
