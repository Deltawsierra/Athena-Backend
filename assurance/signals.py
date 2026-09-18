"""Populate the assurance system of record when a scan completes (Phase 0.1b).

Phase 0.1 built the data model and an explicit ``ingest_scan`` callable. This
wires it in: when a ``PentestScan`` transitions to *completed* with an engine
response, its findings are ingested into structured Finding + Evidence rows.

Two deliberate safety choices keep this off the delicate scan path:

- **On commit, not inline.** Ingestion is scheduled with
  ``transaction.on_commit``, so it runs *after* the scan's transaction commits
  and never lengthens or contends with it. A side effect that matters here: in
  the test suite, where each test runs in a transaction that is rolled back,
  on-commit callbacks are discarded — so this signal is inert during the
  existing pentest/engagement tests and cannot interfere with them. It runs in
  production (and in transactional tests) only.
- **Never fatal.** The whole ingest is wrapped: an ingestion error is logged and
  swallowed, so recording a finding never breaks scan completion.

Disable entirely with ``ASSURANCE_INGEST_ON_COMPLETE = False``.
"""

from __future__ import annotations

import logging

from django.conf import settings
from django.db import transaction
from django.db.models.signals import post_save
from django.dispatch import receiver

logger = logging.getLogger(__name__)


@receiver(post_save, sender="pentest.PentestScan", dispatch_uid="assurance_ingest_on_complete")
def ingest_completed_scan(sender, instance, created, update_fields=None, **kwargs):
    """Ingest a scan's findings once it is marked completed.

    Fires only on the completion transition (a save that touches ``status``,
    which ``PentestScan.mark_completed`` does), for a completed scan that has an
    engine response. ``ingest_scan`` is idempotent, so a later save of the same
    completed scan re-ingests harmlessly rather than duplicating."""
    if not getattr(settings, "ASSURANCE_INGEST_ON_COMPLETE", True):
        return
    # Local imports: keep app loading order independent of import side effects.
    from pentest.models import PentestScan

    if created:
        return
    if instance.status != PentestScan.STATUS_COMPLETED:
        return
    # Only on the save that set the status (mark_completed uses update_fields);
    # a full save with update_fields=None also qualifies.
    if update_fields is not None and "status" not in update_fields:
        return
    if not instance.engine_response:
        return

    scan_pk = instance.pk

    def _do_ingest():
        from .ingest import ingest_scan

        try:
            ingest_scan(instance)
        except Exception:  # noqa: BLE001 - recording findings must never break completion
            logger.exception("assurance ingestion failed for scan %s", scan_pk)

    transaction.on_commit(_do_ingest)


@receiver(post_save, sender="assurance.Finding", dispatch_uid="assurance_auto_dispatch_finding")
def auto_dispatch_finding(sender, instance, created, update_fields=None, **kwargs):
    """Auto-dispatch a finding to its deployment's connectors once it is recorded
    (commercial spine, automated-dispatch policy).

    Inert by default and gated at every layer: it only ever *schedules* the
    dispatch (on commit, so it never lengthens the finding's transaction and is
    discarded in the rolled-back test transactions), and the scheduled work is a
    no-op unless the deployment has an admin-enabled
    :class:`~assurance.models.DispatchPolicy` the finding qualifies for AND at least
    one connector binding. With no policy — the default for every deployment —
    nothing happens. The dispatch itself is idempotent (a finding is never pushed to
    the same connector twice) and resilient (a connector error is recorded, never
    raised). Disable entirely with ``ASSURANCE_AUTO_DISPATCH_ENABLED = False``."""
    if not getattr(settings, "ASSURANCE_AUTO_DISPATCH_ENABLED", True):
        return
    from .dispatch import schedule_finding_dispatch

    schedule_finding_dispatch(instance)
