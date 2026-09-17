"""Change intelligence + evidence expiration — surfaced from what already exists.

Roadmap spine (EXPOSE). A finding is deduplicated within a deployment by its
fingerprint, so a re-scan *updates* the same row and moves its ``last_seen``
forward (see ``assurance.ingest``); a finding the latest scan no longer reports
is simply left untouched, its ``last_seen`` frozen at the last scan that saw it.
Those two timestamps already say everything change intelligence needs — this
module only reads them. Nothing new is detected here.

- **new** — the finding was seen for the first time in the latest scan
  (``first_seen == last_seen``).
- **recurring** — it was seen before and again in the latest scan.
- **cleared** — it was seen before but the latest scan did *not* report it
  (``last_seen`` is behind the deployment's most recent scan). This is
  deliberately **not** "fixed": a scanner no longer flagging something is the
  absence of a signal, not proof of a remediation. Only a retest that reached
  the target and came back clean may say fixed.

**Evidence expiration.** Evidence ages: a finding not re-observed within
``EVIDENCE_TTL_DAYS`` is *stale* — the last time anything actually checked it is
old enough that its evidence should not be read as current, and a retest is due.
This is measured from ``last_seen`` (when the finding was last observed), the
honest "when did we last look".
"""

from __future__ import annotations

from django.db.models import Max
from django.db.models.query import QuerySet
from django.utils import timezone

# How long a finding's evidence stays current without being re-observed. Past
# this, the finding is stale and its evidence is due a refresh (a retest).
EVIDENCE_TTL_DAYS = 90

# The change states and their human labels. "cleared" is worded to never imply a
# fix — absence of a signal is not remediation.
CHANGE_LABELS = {
    "new": "New this scan",
    "recurring": "Recurring",
    "cleared": "No longer reported",
}


def latest_seen_by_deployment(finding_qs: QuerySet) -> dict[int, object]:
    """The most recent ``last_seen`` per deployment — the deployment's latest
    scan boundary — computed in one aggregate query over the given (scoped, but
    NOT severity/status/deployment-filtered) finding set. A finding whose
    ``last_seen`` is behind its deployment's value was not in the latest scan."""
    rows = finding_qs.values("deployment_id").annotate(latest=Max("last_seen"))
    return {row["deployment_id"]: row["latest"] for row in rows}


def change_status(finding, latest_seen) -> str:
    """The finding's change state relative to its deployment's latest scan.

    ``latest_seen`` is the deployment's most recent ``last_seen`` (from
    :func:`latest_seen_by_deployment`); ``None`` when it could not be determined,
    in which case the finding is judged only by its own two timestamps."""
    if (
        latest_seen is not None
        and finding.last_seen is not None
        and finding.last_seen < latest_seen
    ):
        return "cleared"
    if finding.first_seen is not None and finding.first_seen == finding.last_seen:
        return "new"
    return "recurring"


def age_days(finding, now=None) -> int | None:
    """Whole days since the finding was last observed, or None if never seen."""
    if finding.last_seen is None:
        return None
    now = now or timezone.now()
    return max(0, (now - finding.last_seen).days)


def is_stale(finding, now=None) -> bool:
    """Whether the finding's evidence has expired: last observed longer ago than
    ``EVIDENCE_TTL_DAYS``, so a retest is due before it is read as current."""
    days = age_days(finding, now)
    return days is not None and days >= EVIDENCE_TTL_DAYS
