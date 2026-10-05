"""A retest-gated closure is recorded only against an incomplete repair that still fails.

FREEZE.md: "No closing remediation because a ticket status changed -- closure is
effect-backed only." A finding that carries ``retest_required`` ("a failure must
be proven fixed") could be moved to ``status=closed`` or
``remediation_state=resolved`` by a PATCH, the admin or the remediation workflow
with nothing behind it but the click. This module is the one gate every such move
goes through (:meth:`assurance.models.Finding.save` calls :func:`enforce`), and it
reads the effect, not the ticket: the latest :class:`RetestClosureEvidence`.

A retest is a check, and a check is believed only once it has been seen to tell
the cases apart. So a record names FOUR fixture classes:

- ``vulnerable``  -- the original defect. The check must FAIL on it (or it cannot
  see the defect at all, and a pass elsewhere means nothing).
- ``repaired``    -- the fix. The check must PASS.
- ``benign``      -- a case that never had the defect. The check must PASS.
- ``incomplete_repair`` -- a fixture engineered to LOOK repaired while leaving the
  forbidden effect reachable. The check must still FAIL on every one of the six
  named patterns, each its own fixture:

  ``restored_reachability``     the path reopens some other way;
  ``changed_defaults``          the fix works but flips a default users depend on;
  ``lost_compensating_control`` a workaround the patch removes without replacing;
  ``displaced_effects``         the behaviour moves to an adjacent code path;
  ``restored_persistence``      state that should have been purged survives;
  ``operational_breakage``      the fix is correct but breaks something unrelated.

An incomplete-repair fixture that PASSED is the gate being fooled: the check
accepts a cosmetic error-message change, a disabled logger or a partial endpoint
check as a repair, so its pass on the real fix proves nothing either.

Refused, with every reason named: no record; a record from an origin other than an
independent observer (the only origin that carries weight, as for claim evidence);
a record naming no artifact digest; a record older than the finding's last
observation (the scan saw the defect after the retest ran); and any fixture class
or pattern missing, not run, unreadable, or with the wrong outcome. A refused move
leaves the finding where it was. ACCEPTED, FALSE_POSITIVE and INVALIDATED are not
closures and never come here; nor does a finding without ``retest_required``.
"""

from __future__ import annotations

from django.utils import timezone

PASSED = "passed"
FAILED = "failed"
ERRORED = "errored"
OUTCOMES = frozenset({PASSED, FAILED, ERRORED})

VULNERABLE = "vulnerable"
REPAIRED = "repaired"
BENIGN = "benign"
INCOMPLETE_REPAIR = "incomplete_repair"
FIXTURE_CLASSES = (VULNERABLE, REPAIRED, BENIGN, INCOMPLETE_REPAIR)

INCOMPLETE_REPAIR_PATTERNS = (
    "restored_reachability",
    "changed_defaults",
    "lost_compensating_control",
    "displaced_effects",
    "restored_persistence",
    "operational_breakage",
)

# What each single-fixture class must have read for a closure to stand.
_EXPECTED = {VULNERABLE: FAILED, REPAIRED: PASSED, BENIGN: PASSED}


class ClosureRefused(ValueError):
    """A retest-gated closure the evidence does not carry. ``reasons`` names every
    class or pattern that is missing, not run, unreadable or wrong."""

    def __init__(self, reasons):
        self.reasons = list(reasons)
        super().__init__("Retest-gated closure refused: " + "; ".join(self.reasons))


def _run_reason(name, entry, expected):
    if entry is None:
        return f"{name}: not recorded"
    if not isinstance(entry, dict) or not isinstance(entry.get("ran"), bool):
        return f"{name}: unreadable"
    if not entry["ran"]:
        return f"{name}: not run"
    outcome = entry.get("outcome")
    if outcome not in OUTCOMES:
        return f"{name}: unreadable outcome {outcome!r}"
    if outcome == expected:
        return None
    if expected == FAILED and outcome == PASSED and name.startswith(INCOMPLETE_REPAIR):
        return (
            f"{name}: passed -- the check accepted a planted incomplete repair, so its "
            "pass on the real repair proves nothing; it must still fail"
        )
    return f"{name}: {outcome}, a closure needs it {expected}"


def fixture_reasons(fixtures) -> list[str]:
    """Every reason ``fixtures`` does not carry a closure; empty when it does."""
    if not isinstance(fixtures, dict):
        return ["fixtures: unreadable"]
    reasons = []
    for name, expected in _EXPECTED.items():
        reason = _run_reason(name, fixtures.get(name), expected)
        if reason:
            reasons.append(reason)
    patterns = fixtures.get(INCOMPLETE_REPAIR)
    if patterns is None:
        return [*reasons, f"{INCOMPLETE_REPAIR}: not recorded"]
    if not isinstance(patterns, dict):
        return [*reasons, f"{INCOMPLETE_REPAIR}: unreadable"]
    for pattern in INCOMPLETE_REPAIR_PATTERNS:
        reason = _run_reason(f"{INCOMPLETE_REPAIR}/{pattern}", patterns.get(pattern), FAILED)
        if reason:
            reasons.append(reason)
    return reasons


def refusal_reasons(finding, *, last_seen=None) -> list[str]:
    """Why ``finding`` may not be closed on its latest closure evidence; empty when
    it may. ``last_seen`` is the latest observation of the defect (defaults to the
    finding's own)."""
    from .models import ClaimEvidence, RetestClosureEvidence

    record = None
    if finding.pk is not None:
        record = (
            RetestClosureEvidence.objects.filter(finding_id=finding.pk).order_by("-created_at", "-pk").first()
        )
    if record is None:
        return [
            "no closure evidence recorded: a retest-gated closure needs the vulnerable, repaired, "
            "benign and incomplete_repair fixtures run"
        ]
    reasons = []
    if record.origin != ClaimEvidence.Origin.INDEPENDENT:
        reasons.append(f"origin: {record.origin}, only an independent observer's retest carries a closure")
    if not (record.content_digest or "").strip():
        reasons.append("content_digest: blank, the record names no retest artifact")
    last_seen = last_seen or finding.last_seen
    if last_seen is not None and record.created_at < last_seen:
        reasons.append("recorded before the finding was last observed: the defect was seen after the retest ran")
    return reasons + fixture_reasons(record.fixtures)


def enforce(finding, update_fields=None) -> None:
    """Refuse a save that moves a retest-required ``finding`` to CLOSED or its
    remediation to RESOLVED without complete closure evidence. Called from
    :meth:`Finding.save`, so every writer -- the API, the admin, the remediation
    workflow, a shell -- goes through it. A save that is not that move passes."""
    from .models import Finding

    closing = finding.status == Finding.Status.CLOSED
    resolving = finding.remediation_state == Finding.RemediationState.RESOLVED
    if update_fields is not None:
        fields = set(update_fields)
        closing = closing and "status" in fields
        resolving = resolving and "remediation_state" in fields
    if not (closing or resolving):
        return
    stored = None
    if finding.pk is not None:
        stored = (
            Finding.objects.filter(pk=finding.pk)
            .values("status", "remediation_state", "retest_required", "last_seen")
            .first()
        )
    if stored is not None:
        closing = closing and stored["status"] != Finding.Status.CLOSED
        resolving = resolving and stored["remediation_state"] != Finding.RemediationState.RESOLVED
        if not (closing or resolving):
            return
    # Either copy asking for a retest makes it one: a write that lowers the flag in
    # the same save as it closes is the hand-marked close this gate exists to stop.
    if not (finding.retest_required or (stored and stored["retest_required"])):
        return
    seen = [t for t in (finding.last_seen, stored and stored["last_seen"]) if t is not None]
    reasons = refusal_reasons(finding, last_seen=max(seen) if seen else None)
    if reasons:
        raise ClosureRefused(reasons)


def record_closure_evidence(
    finding, *, fixtures, origin, content_digest="", summary="", recorded_by=None, now=None
):
    """Record one retest run against ``finding``'s four fixture classes.

    ANYTHING WELL-FORMED IS RECORDED, as for claim evidence: a record whose
    incomplete repair passed is an honest record of a check that was fooled, and
    the gate reads it as such. Refused here only what cannot be a record: an
    unknown origin, or fixtures that are not a mapping. Like
    :func:`assurance.evidence_audit.record_claim_evidence`, this has no API route."""
    from .models import ClaimEvidence, RetestClosureEvidence

    if origin not in ClaimEvidence.Origin.values:
        raise ValueError(f"origin {origin!r} is not one of {sorted(ClaimEvidence.Origin.values)}")
    if not isinstance(fixtures, dict):
        raise ValueError("fixtures must be a mapping of fixture class to run")
    return RetestClosureEvidence.objects.create(
        finding=finding,
        fixtures=fixtures,
        origin=origin,
        content_digest=content_digest or "",
        summary=summary or "",
        recorded_by=recorded_by,
        created_at=now or timezone.now(),
    )
