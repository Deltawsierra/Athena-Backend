"""Each recorded closure document becomes a row of Minotaur's remediation-outcomes dataset.

Roadmap Phase 6 item 3: "the rows grow into a reusable asset: which remediation, for
which finding type, came to which outcome" (Minotaur-Backend
``minotaur_backend/remediation_outcomes.py``). The engine service's evidence
document (:mod:`assurance.closure_evidence`) IS that dataset's row, so after it is
stored here it is sent on, unchanged, to Minotaur-Backend's
``POST /remediation-outcomes`` as Blue's outcome recorder. Minotaur computes the row's
outcome itself; nothing here tells it what the replay came to.

Why this backend pushes, rather than Minotaur pulling: the document arrives here,
once, already validated against the row's own shape; Minotaur already has the
authenticated write route for it and no client for this backend, and a pull would
need a new read route here, a credential for Minotaur, and a cursor over records on
its side. One outbound call per record, recorded where the record is, is the
smaller sound wiring.

It never stands in the store's way:

- **Off unless configured.** ``MINOTAUR_OUTCOMES_URL`` (Minotaur-Backend's base URL)
  and a credential, sent as ``X-Minotaur-Key``, must both be set. Without them nothing
  is queued and nothing is sent.
- **Its own credential (role separation).** The credential is ``MINOTAUR_OUTCOMES_KEY``:
  a key of Minotaur-Backend's ``outcome-recorder`` role, Blue's, which records
  remediation outcomes and nothing else -- it cannot drive a campaign, post a release
  decision, import a run or abort one. Read from the Django setting of that name, or
  from the environment when the settings name none.

  The LEGACY credential, ``MINOTAUR_RUNNER_KEY`` (a key of Minotaur-Backend's
  ``runner`` role), is still sent when it is the only one set, so a deployment that has
  not moved keeps forwarding. But that one key also drives campaigns, posts release
  decisions, imports runs and aborts, so role separation is NOT in force: ``manage.py
  check`` warns (``assurance.W304``), every process says so once at start, and
  :func:`credential` reports it. The same secret set as both is one credential for two
  roles: it is never sent (``assurance.E305``), and forwarding is off until they
  differ.
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

import hmac
import logging
import os
import threading
from dataclasses import dataclass, field
from datetime import timedelta

from django.conf import settings
from django.db import connection, transaction
from django.db.models import F, Q
from django.utils import timezone

from .connectors.base import NotSent, RequestsTransport, classify_transport_error
from .models import ClosureEvidenceForward

logger = logging.getLogger(__name__)

#: Minotaur-Backend's route for one replay row, and its credential's header.
ROUTE = "/remediation-outcomes"
KEY_HEADER = "X-Minotaur-Key"

#: The credential sent: a key of Minotaur-Backend's ``outcome-recorder`` role (Blue's
#: outcome recorder), which reaches ``POST /remediation-outcomes`` and nothing else.
OUTCOMES_KEY = "MINOTAUR_OUTCOMES_KEY"
#: The legacy credential: a key of Minotaur-Backend's ``runner`` role, which also drives
#: campaigns, posts release decisions, imports runs and aborts. Sent only when
#: :data:`OUTCOMES_KEY` is not set, and said loudly.
LEGACY_RUNNER_KEY = "MINOTAUR_RUNNER_KEY"

#: Whether the credential sent is one role's alone (:func:`credential`).
SEPARATION_IN_FORCE = "in force"
SEPARATION_NOT_IN_FORCE = "not in force"

#: How long a forward may sit ``pending`` or ``sending`` before the retry command
#: takes it as left behind by a process that died.
STALE_AFTER = timedelta(minutes=10)

#: ``(connect, read)`` seconds for the call to Minotaur.
TIMEOUT = (3.05, 10.0)


@dataclass(frozen=True)
class Credential:
    """The credential the forward sends, and what it says about role separation.

    ``key`` is None when none may be sent: none is set, or ``problem`` says why the one
    set is refused. ``setting`` names where the key came from. ``separation`` is
    :data:`SEPARATION_IN_FORCE` only for Blue's own outcome-recorder key.
    """

    #: Never in a repr: it is the credential.
    key: str | None = field(repr=False)
    setting: str | None
    separation: str
    problem: str = ""

    def report(self) -> str:
        """One line for an operator; never the key."""
        if self.problem:
            return f"closure forward credential refused: {self.problem}"
        if self.setting is None:
            return f"closure forward credential: none ({OUTCOMES_KEY} is not set)"
        if self.setting == LEGACY_RUNNER_KEY:
            return (
                f"closure forward credential: {LEGACY_RUNNER_KEY}, Minotaur-Backend's shared "
                f"runner key; role separation is {SEPARATION_NOT_IN_FORCE}"
            )
        return (
            f"closure forward credential: {OUTCOMES_KEY}, Minotaur-Backend's outcome-recorder "
            f"key; role separation is {SEPARATION_IN_FORCE}"
        )


def _setting(name: str, *, environment: bool = False) -> str | None:
    """A non-empty text setting; with ``environment``, the environment variable of the
    same name when the settings name none."""
    value = getattr(settings, name, None)
    if value is None and environment:
        value = os.environ.get(name)
    return value if isinstance(value, str) and value else None


def credential() -> Credential:
    """The credential the forward sends (:class:`Credential`). Blue's outcome-recorder
    key when it is set; else the legacy runner key, with separation not in force; and
    never a secret set as both, which is one credential for two roles."""
    outcomes = _setting(OUTCOMES_KEY, environment=True)
    legacy = _setting(LEGACY_RUNNER_KEY)
    if outcomes is not None and legacy is not None and hmac.compare_digest(outcomes, legacy):
        return Credential(
            key=None,
            setting=None,
            separation=SEPARATION_NOT_IN_FORCE,
            problem=(
                f"{OUTCOMES_KEY} is the same secret as {LEGACY_RUNNER_KEY}: one credential for "
                "two roles (Blue's outcome recorder and Minotaur-Backend's runner) is not "
                "separation, so nothing is sent until they differ"
            ),
        )
    if outcomes is not None:
        return Credential(key=outcomes, setting=OUTCOMES_KEY, separation=SEPARATION_IN_FORCE)
    if legacy is not None:
        return Credential(key=legacy, setting=LEGACY_RUNNER_KEY, separation=SEPARATION_NOT_IN_FORCE)
    return Credential(key=None, setting=None, separation=SEPARATION_NOT_IN_FORCE)


def configured() -> tuple[str, str] | None:
    """``(base_url, key)``, or None when forwarding is off. ``key`` is
    :func:`credential`'s."""
    url = getattr(settings, "MINOTAUR_OUTCOMES_URL", None)
    key = credential().key
    if not isinstance(url, str) or not url.strip() or key is None:
        return None
    return url.strip().rstrip("/"), key


def credential_problems() -> list[tuple[str, str, str]]:
    """``(level, id, message)`` for what :func:`credential` finds wrong: a secret set as
    both credentials (an error: nothing is sent), the legacy runner key forwarding alone
    (a warning: separation is not in force), or the legacy key set beside Blue's and
    unused (a warning). Empty when there is nothing to say."""
    found = credential()
    if found.problem:
        return [("error", "assurance.E305", found.problem)]
    if found.setting == LEGACY_RUNNER_KEY:
        return [
            (
                "warning",
                "assurance.W304",
                f"{LEGACY_RUNNER_KEY} is Minotaur-Backend's shared runner key: the one credential "
                "drives campaigns, records Blue's remediation outcomes, posts release decisions, "
                f"imports runs and aborts, so role separation is {SEPARATION_NOT_IN_FORCE} for the "
                "closure forward",
            )
        ]
    if found.setting == OUTCOMES_KEY and _setting(LEGACY_RUNNER_KEY) is not None:
        return [
            (
                "warning",
                "assurance.W304",
                f"{LEGACY_RUNNER_KEY} is set beside {OUTCOMES_KEY} and is not sent: unset it, so no "
                "shared runner key is held here",
            )
        ]
    return []


def say_credential() -> None:
    """Said once by each process at start (:meth:`AssuranceConfig.ready`): which
    credential forwards, and loudly when role separation is not in force. Never the
    key, never raises, and never in front of anything."""
    try:
        problems = credential_problems()
    except Exception:  # noqa: BLE001 - saying a setting never stops a process starting
        logger.exception("the closure forward's credential could not be read")
        return
    for level, ident, message in problems:
        log = logger.error if level == "error" else logger.warning
        log("ROLE SEPARATION: %s (%s)", message, ident)


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
        problem = credential().problem
        _settle(
            pk,
            Status.FAILED,
            error=problem or f"forwarding is not configured (MINOTAUR_OUTCOMES_URL, {OUTCOMES_KEY})",
        )
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
