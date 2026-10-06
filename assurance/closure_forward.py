"""Each recorded closure document becomes a row of Minotaur's remediation-outcomes dataset.

Roadmap Phase 6 item 3: "the rows grow into a reusable asset: which remediation, for
which finding type, came to which outcome" (Minotaur-Backend
``minotaur_backend/remediation_outcomes.py``). The engine service's evidence
document (:mod:`assurance.closure_evidence`) IS that dataset's row, so after it is
stored here it is sent on, unchanged, to Minotaur-Backend's
``POST /remediation-outcomes`` as its runner. Minotaur computes the row's outcome
itself; nothing here tells it what the replay came to.

Why this backend pushes, rather than Minotaur pulling: the document arrives here,
once, already validated against the row's own shape; Minotaur already has the
authenticated write route for it and no client for this backend, and a pull would
need a new read route here, a credential for Minotaur, and a cursor over records on
its side. One outbound call per record, recorded where the record is, is the
smaller sound wiring.

It never stands in the store's way:

- **Off unless configured.** ``MINOTAUR_OUTCOMES_URL`` (Minotaur-Backend's base URL)
  and ``MINOTAUR_RUNNER_KEY`` (a key of the runner role, sent as ``X-Minotaur-Key``)
  must both be set. Without them nothing is queued and nothing is sent.
- **Never blocks or fails the store.** The forward is queued as a
  :class:`~assurance.models.ClosureEvidenceForward` row in the store's own
  transaction, and sent only after it commits, on a background thread: the engine
  service is answered before any call to Minotaur is made, and no answer from
  Minotaur -- slow, refused, down -- can undo or delay a record. Whatever the send
  raises is caught and recorded on the forward row.
- **Bounded.** A ``(connect, read)`` timeout and a total deadline
  (``RequestsTransport``, ``ASSURANCE_CONNECTOR_DEADLINE_SECONDS``).
- **Recorded for retry, at most once each.** A forward is claimed by a conditional
  update before it is sent, so two senders never both send it; once ``sent`` it is
  never sent again. ``failed`` -- certainly not recorded (a connection never made,
  or Minotaur answered with an error) -- is retried by
  ``manage.py retry_closure_forwards``, as is a forward left ``pending`` or
  ``sending`` by a process that died. ``unknown`` -- the request may have been
  recorded before its answer was lost -- is retried only when asked
  (``--unknown``): a second send can add a second row of the same document, under
  the same digest. ``refused`` -- Minotaur answered that the row cannot be read --
  is never retried: the same document would be refused again.

Nothing here is a stop, holds one back, or is read by one.
"""

from __future__ import annotations

import logging
import threading
from datetime import timedelta

from django.conf import settings
from django.db import connection, transaction
from django.db.models import F, Q
from django.utils import timezone

from .connectors.base import NotSent, RequestsTransport, classify_transport_error
from .models import ClosureEvidenceForward

logger = logging.getLogger(__name__)

#: Minotaur-Backend's route for one replay row, and its runner key's header.
ROUTE = "/remediation-outcomes"
KEY_HEADER = "X-Minotaur-Key"

#: How long a forward may sit ``pending`` or ``sending`` before the retry command
#: takes it as left behind by a process that died.
STALE_AFTER = timedelta(minutes=10)

#: ``(connect, read)`` seconds for the call to Minotaur.
TIMEOUT = (3.05, 10.0)


def configured() -> tuple[str, str] | None:
    """``(base_url, runner_key)``, or None when forwarding is off."""
    url = getattr(settings, "MINOTAUR_OUTCOMES_URL", None)
    key = getattr(settings, "MINOTAUR_RUNNER_KEY", None)
    if not isinstance(url, str) or not url.strip() or not isinstance(key, str) or not key:
        return None
    return url.strip().rstrip("/"), key


def _transport():
    """The production transport: ``requests`` under a timeout and a total deadline."""
    return RequestsTransport(timeout=TIMEOUT)


def _spawn(work) -> None:
    """Run ``work`` on its own thread, so nothing waits on it. The thread closes its
    own database connection when it is done."""

    def run():
        try:
            work()
        finally:
            connection.close()

    threading.Thread(target=run, name="closure-forward", daemon=True).start()


def queue(record) -> bool:
    """Queue ``record``'s document for the dataset, inside the caller's transaction,
    and send it once that commits. False -- nothing queued -- when forwarding is off
    or the record carries no document."""
    if configured() is None or not isinstance(record.document, dict):
        return False
    forward = ClosureEvidenceForward.objects.create(record=record)
    transaction.on_commit(lambda: _spawn(lambda: deliver(forward.pk)))
    return True


def _clip(text, limit: int = 500) -> str:
    text = str(text)
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _settle(pk: int, status: str, *, error: str = "", row_id=None) -> None:
    ClosureEvidenceForward.objects.filter(pk=pk).update(
        status=status, last_error=_clip(error), dataset_row_id=row_id, updated_at=timezone.now()
    )


def deliver(pk: int, *, transport=None, claimable=(ClosureEvidenceForward.Status.PENDING,), stale_before=None) -> str | None:
    """Send forward ``pk``'s document to Minotaur once, if it can be claimed: its
    status is one of ``claimable`` (or, with ``stale_before``, it was left
    ``pending`` or ``sending`` before then). Returns the status it was settled to,
    or None when it was not claimed -- already sent, being sent, or not due.
    Never raises."""
    Status = ClosureEvidenceForward.Status
    due = Q(status__in=list(claimable))
    if stale_before is not None:
        due |= Q(status__in=[Status.PENDING, Status.SENDING], updated_at__lt=stale_before)
    try:
        claimed = ClosureEvidenceForward.objects.filter(due, pk=pk).update(
            status=Status.SENDING, attempts=F("attempts") + 1, updated_at=timezone.now()
        )
    except Exception:  # noqa: BLE001 - a forward never raises into whoever ran it; it is retried
        logger.exception("closure forward %s could not be claimed", pk)
        return None
    if not claimed:
        return None
    try:
        return _send(pk, transport)
    except Exception as exc:  # noqa: BLE001 - recorded as failed and retried, never raised
        logger.exception("closure forward %s failed", pk)
        try:
            _settle(pk, Status.FAILED, error=f"{type(exc).__name__}: {exc}")
        except Exception:  # noqa: BLE001 - the row stays `sending`; the retry takes it once stale
            logger.exception("closure forward %s could not be recorded as failed", pk)
        return Status.FAILED


def _send(pk: int, transport) -> str:
    Status = ClosureEvidenceForward.Status
    target = configured()
    if target is None:
        _settle(pk, Status.FAILED, error="forwarding is not configured (MINOTAUR_OUTCOMES_URL, MINOTAUR_RUNNER_KEY)")
        return Status.FAILED
    url, key = target
    forward = ClosureEvidenceForward.objects.select_related("record").get(pk=pk)
    document = forward.record.document
    transport = transport or _transport()
    try:
        answer = transport.post(url + ROUTE, headers={KEY_HEADER: key}, json=document)
    except Exception as exc:  # noqa: BLE001 - every transport error is classified and recorded
        if classify_transport_error(exc) is NotSent:
            _settle(pk, Status.FAILED, error=f"not sent: {type(exc).__name__}: {exc}")
            return Status.FAILED
        _settle(pk, Status.UNKNOWN, error=f"outcome unknown: {type(exc).__name__}: {exc}")
        return Status.UNKNOWN
    code = getattr(answer, "status_code", None)
    if code == 201:
        try:
            body = answer.json()
            row_id = body.get("id") if isinstance(body, dict) else None
        except ValueError:
            row_id = None
        _settle(pk, Status.SENT, row_id=row_id if isinstance(row_id, int) and not isinstance(row_id, bool) else None)
        return Status.SENT
    detail = f"Minotaur answered {code}: {_clip(getattr(answer, 'text', ''), 300)}"
    if code in (400, 413, 415, 422):
        # The row cannot be read as sent: the same document would be refused again.
        _settle(pk, Status.REFUSED, error=detail)
        return Status.REFUSED
    _settle(pk, Status.FAILED, error=detail)
    return Status.FAILED


def retry_due(*, transport=None, unknown: bool = False, now=None) -> dict[str, int]:
    """Send every forward that is due again: ``failed`` ones, ``pending`` or
    ``sending`` ones left behind longer than :data:`STALE_AFTER`, and -- only with
    ``unknown`` -- ones whose outcome is unknown. Returns how many settled to each
    status."""
    Status = ClosureEvidenceForward.Status
    claimable = (Status.FAILED, Status.UNKNOWN) if unknown else (Status.FAILED,)
    stale_before = (now or timezone.now()) - STALE_AFTER
    due = ClosureEvidenceForward.objects.filter(
        Q(status__in=list(claimable))
        | Q(status__in=[Status.PENDING, Status.SENDING], updated_at__lt=stale_before)
    ).values_list("pk", flat=True)
    settled: dict[str, int] = {}
    for pk in list(due):
        status = deliver(pk, transport=transport, claimable=claimable, stale_before=stale_before)
        if status is not None:
            settled[status] = settled.get(status, 0) + 1
    return settled
