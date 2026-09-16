"""Derive the Unknowns Register from a deployment's unverified findings.

Roadmap Phase 0.4. A finding whose honest evidence class is *unverified* — the
scan flagged something but could not confirm it, or nothing was documented — is
not a clean result and not a proven vulnerability. It is a gap: a specific
question the evidence does not answer. This module turns each such finding into a
managed :class:`~assurance.models.Unknown` so the gap is owned, dated, and shown,
instead of silently rounding down to "fine" or up to "broken".

It is **idempotent** and **non-destructive**, exactly like ingestion: an Unknown
is keyed within its deployment by a fingerprint derived from the finding, so a
re-derive updates the machine-owned fields and refreshes ``last_seen`` rather
than duplicating the row, and human-set state (status, owner, review date,
notes) is never clobbered. When a finding stops being unverified — it was
resolved, or fresh evidence upgraded its class — its still-open derived Unknown
is auto-resolved, because the question it asked has been answered. Nothing here
reaches the network.
"""

from __future__ import annotations

import hashlib

from django.utils import timezone

from .models import Deployment, EvidenceClass, Finding, Unknown, severity_rank

# The evidence classes that mean "we saw something but cannot stand behind it":
# a low-strength observation the scan could not confirm, an unknown, or nothing
# documented. These are the honest gaps — a technically- or configuration-verified
# finding is a known quantity and belongs in the decision, not the register.
# (This is intentionally broader than ``decision._UNVERIFIED``: the decision's
# NEEDS_MORE_EVIDENCE state is a whole-deployment verdict for the narrow "clean
# but unproven" case, whereas a gap is worth tracking per-finding the moment the
# evidence is merely partial.)
UNVERIFIED_CLASSES = frozenset(
    {
        EvidenceClass.PARTIALLY_VERIFIED.value,
        EvidenceClass.UNKNOWN.value,
        EvidenceClass.NOT_DOCUMENTED.value,
    }
)

# A finding is no longer a live gap once a human has dispositioned it.
_RESOLVED_FINDING_STATUSES = frozenset(
    {Finding.Status.CLOSED, Finding.Status.ACCEPTED, Finding.Status.FALSE_POSITIVE}
)


def _fingerprint(finding: Finding) -> str:
    """Tie the Unknown to the finding it derives from, stable across re-derives."""
    raw = f"finding:{finding.pk}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _impact_for(finding: Finding) -> str:
    """How much an unverified finding moves the deployment decision. A gap on a
    high/critical finding is a high-impact unknown (we cannot rule out the worst
    case); a medium is medium; anything lower is low."""
    rank = severity_rank(finding.severity)
    if rank >= severity_rank("high"):
        return Unknown.Impact.HIGH
    if rank >= severity_rank("medium"):
        return Unknown.Impact.MEDIUM
    return Unknown.Impact.LOW


def _question(finding: Finding) -> str:
    return f"Is '{finding.title}' real, and what is its true severity?"


def _why(finding: Finding) -> str:
    return (
        f"A {finding.severity} finding was reported but its evidence is unverified, "
        "so it can neither be counted as a confirmed risk nor cleared."
    )


def _evidence_needed(finding: Finding) -> str:
    return (
        "Reproduce the finding against the live system, or obtain configuration / "
        "vendor evidence that confirms or rules it out."
    )


def derive_unknowns(deployment: Deployment) -> list[Unknown]:
    """Reconcile the deployment's Unknowns register with its current findings.

    Creates or refreshes a derived Unknown for every active finding whose evidence
    is unverified, and auto-resolves derived Unknowns whose finding is no longer a
    live gap. Returns the Unknowns that are currently open after reconciliation.
    Manually raised Unknowns are never touched. Safe to call repeatedly."""
    now = timezone.now()

    active = deployment.findings.exclude(
        status__in=_RESOLVED_FINDING_STATUSES
    ).prefetch_related("evidence")

    live_fingerprints: set[str] = set()
    open_unknowns: list[Unknown] = []

    for finding in active:
        if finding.evidence_class not in UNVERIFIED_CLASSES:
            continue
        fingerprint = _fingerprint(finding)
        live_fingerprints.add(fingerprint)

        machine_fields = {
            "finding": finding,
            "question": _question(finding),
            "why_it_matters": _why(finding),
            "evidence_needed": _evidence_needed(finding),
            "deployment_impact": _impact_for(finding),
            "source": Unknown.Source.DERIVED,
            "last_seen": now,
        }

        unknown, created = Unknown.objects.get_or_create(
            deployment=deployment,
            fingerprint=fingerprint,
            defaults={**machine_fields, "first_seen": now},
        )
        if not created:
            # Refresh the machine-owned fields; never touch status/owner/review/notes.
            for key, value in machine_fields.items():
                setattr(unknown, key, value)
            unknown.save(update_fields=[*machine_fields.keys(), "updated_at"])
        if unknown.is_open:
            open_unknowns.append(unknown)

    # Auto-resolve derived Unknowns whose gap has closed (finding resolved or its
    # evidence upgraded). Manual Unknowns and already-closed ones are left alone.
    stale = deployment.unknowns.filter(
        source=Unknown.Source.DERIVED,
        status__in=[Unknown.Status.OPEN, Unknown.Status.INVESTIGATING],
    ).exclude(fingerprint__in=live_fingerprints)
    for unknown in stale:
        unknown.status = Unknown.Status.RESOLVED
        unknown.last_seen = now
        unknown.save(update_fields=["status", "last_seen", "updated_at"])

    return open_unknowns
