"""Operational / continuous-assurance roll-up — one operational-readiness view.

The operational-facing layer of the assurance spine. It ties the continuous-
assurance signals the rest of this package already computes into a single view of
where a deployment sits in the roadmap's continuous-assurance loop —
Discover → Assess → Remediate → Retest → Monitor-change → Reassess. Like its
siblings it is computed on read: a pure function of the stored graph, with no new
record, no migration, and no timestamp in the returned identity content.

**This is a REUSE-ONLY roll-up.** It does not re-implement change intelligence,
evidence expiration, or the remediation workflow — it *reads what already exists*:

- **Evidence freshness / staleness** is read from the existing evidence-expiration
  signal in :mod:`assurance.change`: :func:`~assurance.change.is_stale` and
  :data:`~assurance.change.EVIDENCE_TTL_DAYS`. A finding not re-observed within the
  TTL is stale — its evidence should not be read as current and a retest is due.
- **Change / drift needing reassessment** is read from the existing
  change-intelligence signal :func:`~assurance.change.change_status` (``new`` /
  ``recurring`` / ``cleared``). What changed since the last scan — the ``new`` and
  ``cleared`` findings — is what is flagged as needing reassessment; ``recurring``
  is steady state, not change. No new drift metric is invented here.
- **Remediation velocity** is the existing roll-up
  :func:`assurance.roi._remediation` (which reads ``remediation_state`` and the
  attributed :class:`~assurance.models.RemediationEvent` history), reused wholesale
  rather than re-counted. A ``resolved`` remediation state is a *process* claim
  that a human called the work done — never a security closure, which lives only in
  ``status`` and the decision.
- **The decision** is the standing six-state ``Deployment.decision``, None-safe.

What it refuses to be, mirroring :mod:`assurance.roi`:

- **No dollar figure, ROI amount, or realized-loss number** — value is counts,
  true ratios of real counts, and ordinal bands only.
- **Never green-by-default.** Nothing here reads "healthy", "all current", "up to
  date", "operationally ready", or "secure" as an unearned fact. An unassessed or
  stale deployment reads honestly — the readiness band lands in its weakest state
  (``stale``), never a clean pass. Every ratio is ``None`` when there is no basis
  to compute it, never a fabricated ``0%``.

Prefetch ``findings__evidence`` and ``findings__remediation_events`` on the caller
side to keep it query-light. Deterministic for a fixed ``now``.
"""

from __future__ import annotations

from .change import EVIDENCE_TTL_DAYS, change_status, is_stale

# Ordinal operational-readiness band — a qualitative read of how well the
# continuous-assurance loop is being sustained, derived only from real ratios
# (evidence freshness, change backlog, open remediation). The weakest of the three
# signals sets the floor, so an honest read never rounds up past its softest input.
# It describes the state of the assurance loop, never that a system is healthy,
# current, or secure. Best -> weakest.
READINESS_STEADY = "steady"
READINESS_ATTENTION = "attention"
READINESS_STALE = "stale"


def _ratio(numerator: int, denominator: int) -> float | None:
    """A true ratio of two real counts, rounded, or None when the denominator is
    zero. Never a fabricated percentage — None means "no basis to compute", not 0%."""
    if denominator <= 0:
        return None
    return round(numerator / denominator, 4)


def _latest_seen(findings) -> object | None:
    """The deployment's latest-scan boundary: the most recent ``last_seen`` across
    its findings. Computed in Python over the already-prefetched graph (the same
    aggregate :func:`assurance.change.latest_seen_by_deployment` performs in SQL for
    the serializer), so the roll-up stays a pure read of what was prefetched. A
    finding whose ``last_seen`` is behind this value was not in the latest scan."""
    seen = [f.last_seen for f in findings if f.last_seen is not None]
    return max(seen) if seen else None


def _evidence_freshness(findings, now) -> dict:
    """How much of the deployment's evidence is current versus stale/expired, read
    from the existing evidence-expiration signal (:func:`assurance.change.is_stale`
    against :data:`assurance.change.EVIDENCE_TTL_DAYS`). Surfaces the stale count
    rather than hiding it; the ratio is None when there are no findings to age —
    never a fake "100% current"."""
    total = stale = 0
    for finding in findings:
        total += 1
        if is_stale(finding, now):
            stale += 1
    current = total - stale
    return {
        "total": total,
        "current": current,
        "stale": stale,
        "ttl_days": EVIDENCE_TTL_DAYS,
        # Fraction of findings whose evidence is still current. None with no basis.
        "freshness_ratio": _ratio(current, total),
    }


def _change_backlog(findings, latest_seen) -> dict:
    """What changed since the last assessment and so needs reassessment, read from
    the existing change-intelligence signal (:func:`assurance.change.change_status`).
    ``new`` and ``cleared`` findings are what moved — the reassessment backlog;
    ``recurring`` is steady state. No new drift metric is invented — this only
    tallies the existing change states."""
    by_status: dict[str, int] = {"new": 0, "recurring": 0, "cleared": 0}
    total = 0
    for finding in findings:
        total += 1
        status = change_status(finding, latest_seen)
        by_status[status] = by_status.get(status, 0) + 1
    # What changed (appeared or stopped being reported) is what needs a fresh look;
    # recurring findings are unchanged and do not count as backlog.
    needs_reassessment = by_status["new"] + by_status["cleared"]
    return {
        "total": total,
        "new": by_status["new"],
        "recurring": by_status["recurring"],
        "cleared": by_status["cleared"],
        "by_status": by_status,
        "needs_reassessment": needs_reassessment,
        # Fraction of findings flagged as changed/needing reassessment. None with no basis.
        "needs_reassessment_ratio": _ratio(needs_reassessment, total),
    }


def _readiness(
    freshness_ratio: float | None,
    needs_reassessment_ratio: float | None,
    open_ratio: float | None,
    total_findings: int,
) -> str:
    """The ordinal operational-readiness band from the three real ratios: evidence
    freshness (higher is better), change backlog (lower is better), and open
    remediation (lower is better). The weakest signal sets the floor. A deployment
    with nothing to assess lands in the weakest band — honestly ``stale``, never a
    green-by-default clean pass."""
    if total_findings == 0:
        # Nothing has been assessed. The most honest read is the weakest band —
        # an empty deployment is not "current" or "ready".
        return READINESS_STALE
    fresh = freshness_ratio if freshness_ratio is not None else 0.0
    # Backlog and open work are "bad" ratios; convert to "good" signals.
    unchanged = 1.0 - (needs_reassessment_ratio if needs_reassessment_ratio is not None else 0.0)
    closed_out = 1.0 - (open_ratio if open_ratio is not None else 0.0)
    signal = min(fresh, unchanged, closed_out)
    if signal >= 0.8:
        return READINESS_STEADY
    if signal >= 0.4:
        return READINESS_ATTENTION
    return READINESS_STALE


def assess_operational(deployment, *, now=None) -> dict:
    """The operational / continuous-assurance roll-up for a deployment.

    Ties the existing continuous-assurance signals into one operational-readiness
    view: evidence freshness/staleness (reused from the evidence-expiration
    signal), the change/drift backlog needing reassessment (reused from the
    change-intelligence signal), remediation velocity (reused from
    :func:`assurance.roi._remediation`), the standing six-state decision (None-safe),
    and an ordinal readiness band derived from those real ratios.

    Prefetch ``findings__evidence`` and ``findings__remediation_events`` on the
    caller side. Pure and side-effect-free; deterministic for a fixed ``now``
    (``now`` defaults to :func:`django.utils.timezone.now`, used only to age
    evidence). No new record, no migration, no timestamp in the returned content.

    Every value is a real count, a true ratio of real counts, or an ordinal band.
    There is **no dollar figure, ROI amount, or realized-loss number** anywhere, and
    nothing reads "healthy", "current", or "secure" as an unearned fact — an
    unassessed or stale deployment reads honestly (its readiness band is ``stale``)."""
    # Lazy import to reuse the canonical remediation-velocity roll-up without a
    # module-level import cycle, exactly as roi.py reuses its siblings.
    from .roi import _remediation

    findings = list(deployment.findings.all())
    latest_seen = _latest_seen(findings)

    freshness = _evidence_freshness(findings, now)
    change_backlog = _change_backlog(findings, latest_seen)
    remediation = _remediation(deployment)

    total_findings = freshness["total"]
    open_ratio = _ratio(remediation["open"], total_findings)
    readiness = _readiness(
        freshness["freshness_ratio"],
        change_backlog["needs_reassessment_ratio"],
        open_ratio,
        total_findings,
    )

    return {
        "system": {
            "name": deployment.name,
            "uuid": str(deployment.uuid),
            "environment": deployment.environment,
            "environment_label": deployment.get_environment_display(),
        },
        # The standing six-state decision, None-safe: an unassessed deployment has
        # no decision, and an absent decision is never read as "ready".
        "decision": {
            "decision": deployment.decision,
            "decision_label": deployment.get_decision_display() if deployment.decision else None,
        },
        "evidence_freshness": freshness,
        "change_backlog": change_backlog,
        "remediation": remediation,
        "readiness": readiness,
        "summary": {
            "total_findings": total_findings,
            "current_evidence": freshness["current"],
            "stale_evidence": freshness["stale"],
            "freshness_ratio": freshness["freshness_ratio"],
            "needs_reassessment": change_backlog["needs_reassessment"],
            "needs_reassessment_ratio": change_backlog["needs_reassessment_ratio"],
            "open_remediation": remediation["open"],
            "resolved_remediation": remediation["resolved"],
            "decision": deployment.decision,
            "readiness": readiness,
        },
    }
