"""The failsafe control plane.

Operators draft a command, sign it out of band, and submit signatures; when
enough distinct operators have signed, the command is `ready` and the engine
polls `/pending` for it. Guard (a) still holds: this plane holds no private key
and cannot itself make an engine act -- it relays operator-signed commands the
engine independently verifies. Guard (b): two distinct operator signatures are
required for stand-down and terminate.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import itertools
import json
import logging
import re
import secrets
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from datetime import timezone as dt_timezone

from django.conf import settings
from django.db import DEFAULT_DB_ALIAS, connection, connections, transaction
from django.db.models import Case, CharField, DateTimeField, F, Max, Q, UUIDField, Value, When
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from accounts.permissions import IsAdminOrAnalyst

from .models import LIFTED_ONLY_BY, FailsafeAuditEvent, FailsafeCommand, FailsafeStopMark
from .serializers import (
    DraftCommandSerializer,
    FailsafeAuditEventSerializer,
    FailsafeCommandSerializer,
    SubmitSignatureSerializer,
)
from .signing import (
    distinct_valid_signers,
    make_draft,
    operator_keyring,
    required_signatures,
    signing_bytes_hex,
)

# Terminate is irreversible, so only an admin may initiate one; pause/stand-down
# and the rest are available to analysts too. The cryptographic two-person rule
# is enforced separately, on the signatures.
_ADMIN_ONLY_ACTIONS = {"terminate"}

logger = logging.getLogger(__name__)

#: The most commands one page of the list returns besides the stops awaiting a
#: signature, what is in flight first (_Read). It was 100.
COMMAND_LIST_LIMIT = 50

#: The actions that stop an engine (safety.stops drafts them as stops), and
#: those that put one back to work.
STOP_ACTIONS = ("pause", "stand_down", "terminate")
START_ACTIONS = ("resume", "release")

#: The stop commands awaiting a signature that one read returns, before
#: everything else and never cut by COMMAND_LIST_LIMIT (see _awaiting_stops).
AWAITING_STOP_LIMIT = 500
#: How many of the newest unsigned drafts of each stop action one read ranks.
UNSIGNED_STOP_SCAN = 1000
#: The most commands one read marks expired, in one write.
EXPIRE_PER_READ = 200
#: The most drafts one new stop draft supersedes (see _supersede_past_limit):
#: past the limit there is normally exactly one; a backlog is superseded a
#: bounded few at a time by the drafts that follow.
SUPERSEDE_PER_DRAFT = 200


def _setting(name, default, least):
    """An integer setting, at least ``least``; the default when it is unset or
    not a number."""
    try:
        return max(least, int(getattr(settings, name, default)))
    except (TypeError, ValueError):
        return default


def unsigned_stop_drafts_per_account():
    """The most unsigned stop drafts one account has awaiting a signature
    (FAILSAFE_UNSIGNED_STOP_DRAFTS_PER_ACCOUNT, default 100, at least 1). A new
    stop draft past it is made -- a stop draft is never refused -- and the
    account's OLDEST unsigned stop drafts past it are superseded."""
    return _setting("FAILSAFE_UNSIGNED_STOP_DRAFTS_PER_ACCOUNT", 100, 1)


def stop_lane_read_bytes():
    """The most bytes of commands one stop-lane read returns
    (FAILSAFE_STOP_LANE_READ_BYTES, default 1,000,000, at least 64 KiB)."""
    return _setting("FAILSAFE_STOP_LANE_READ_BYTES", 1_000_000, 64 * 1024)


_AWAITING = FailsafeCommand.STATUS_AWAITING
_READY = FailsafeCommand.STATUS_READY
#: What is in flight: a command awaiting a signature, or ready for the engine.
#: Every other status is history (consumed, expired, canceled, superseded).
_IN_FLIGHT = (_AWAITING, _READY)
_STATUSES = tuple(value for value, _label in FailsafeCommand.STATUS_CHOICES)
_HISTORY = tuple(value for value in _STATUSES if value not in _IN_FLIGHT)

#: The most commands of each of the state read's other lists -- the starts
#: awaiting a signature, and the ready commands -- one page returns.
STATE_LIST_LIMIT = 20
#: The state read's ``recent``: its newest commands, on its first page only.
RECENT_LIMIT = 10


def _by_service_token(request):
    """Whether the failsafe service token authenticated ``request``. What it
    reads is limited to what stopping needs (safety.service_token)."""
    from safety.service_token import ServiceCredential

    return isinstance(request.auth, ServiceCredential)


def _due(expires_at, now):
    try:
        return now >= timezone.datetime.fromisoformat(expires_at)
    except (TypeError, ValueError):
        return False


class _Expiry:
    """The commands in flight past their window, marked expired a bounded few
    at a time by the stop-lane reads.

    A read never walks every command to expire it (round 3: a read after 3,000
    drafts expired took 3.8 s, a write per row). It drops what it finds due
    from what it shows as in flight -- each command has the same validity
    window, so the ones that are due are always the oldest, and a read that
    takes the newest rows of a status sees every command still in flight
    before any that is due -- and when it is done it marks at most
    EXPIRE_PER_READ due commands expired in ONE write: those it came across,
    then others found by the index on (status, expires_at). A backlog of any
    size is therefore marked over a few reads, never by one. A write that
    fails is logged, and the read is answered.

    That write is housekeeping, and it never waits for the database's write
    lock, from any read (AB-STOP-FIXES, D3): refused at once when another
    connection holds it, it is logged and the next read marks the commands.
    The state read, where the second operator finds the stand-down to
    co-sign, and the list waited on it before -- 3.05 s for a 3 s hold, up to
    busy_timeout -- whenever any command anywhere was past its window. Its
    PRAGMAs run only when there is something to mark: a read with nothing
    due makes no statement more.

    A stop in force is never due: it stays ready and is answered whatever its
    window, until a later signed start lifts it (FailsafeCommand.in_force)."""

    def __init__(self):
        self.now = timezone.now()
        self.pks = {}  # an ordered set: one row can be in more than one list

    def due(self, pk, status_, expires_at, in_force=False):
        if not in_force and status_ in _IN_FLIGHT and _due(expires_at, self.now):
            if len(self.pks) < EXPIRE_PER_READ:
                self.pks[pk] = None
            return True
        return False

    def mark(self):
        try:
            room = EXPIRE_PER_READ - len(self.pks)
            if room > 0:
                # The window's end is stored as the ISO string that was signed;
                # the index narrows the candidates and each is checked exactly.
                # In the index's own order, not the model's (newest first):
                # sorting by creation time read and sorted EVERY command past
                # its window to take the first few (a temp B-tree), so the
                # read grew with the backlog it is there to clear.
                candidates = (
                    FailsafeCommand.objects.filter(
                        status__in=_IN_FLIGHT, expires_at__lt=self.now.isoformat(), in_force=False
                    )
                    .exclude(pk__in=list(self.pks))
                    .order_by()
                    .values_list("pk", "expires_at")[:room]
                )
                self.pks.update((pk, None) for pk, end in candidates if _due(end, self.now))
            if not self.pks:
                return
            with _not_waiting_for_the_write_lock(), transaction.atomic():
                FailsafeCommand.objects.filter(pk__in=list(self.pks), status__in=_IN_FLIGHT, in_force=False).update(
                    status=FailsafeCommand.STATUS_EXPIRED, updated_at=self.now
                )
        except Exception:  # noqa: BLE001 - a failed read or write must not fail a stop-lane read
            logger.exception("could not mark %d failsafe commands expired", len(self.pks))


#: After this many rows in a row that cannot be read one by one, the rest of a
#: read's rows are not tried: each is unreadable, by its key alone.
UNREADABLE_IN_A_ROW = 8


class _Unreadable:
    """A command row that could not be read whole: what could still be read of
    it. Its primary key, and -- read by themselves, without the stored
    signatures -- its uuid, engine, action, status and creation time, each
    None when even that failed.

    Never served to an engine and never dropped unsaid: a read counts it
    (X-Failsafe-Unreadable), the console's reads name it, and every readable
    row beside it is answered as ever. One ready row a read could not turn
    into a command used to answer the whole poll 500, and a readable ready
    stand-down of the same engine was lost with it."""

    in_force = False
    expires_at = None
    ready_at = None
    lifted_by = None
    lifted_at = None

    def __init__(self, pk, why):
        self.pk, self.why = pk, why
        self.uuid = self.engine_id = self.action = self.created_at = None
        self.status = ""

    @classmethod
    def of(cls, pk, exc, read=True):
        row = cls(pk, type(exc).__name__)
        if read:
            try:
                found = (
                    FailsafeCommand.objects.filter(pk=pk)
                    .order_by()
                    .values_list("uuid", "engine_id", "action", "status", "created_at")
                    .first()
                )
            except Exception:  # noqa: BLE001 - what cannot be read is None, never a failed read
                found = None
            if found is not None:
                row.uuid, row.engine_id, row.action, row.status, row.created_at = found
        return row


def _named(command, why):
    """An unreadable row as a console read names it."""
    return {
        "uuid": None if getattr(command, "uuid", None) is None else str(command.uuid),
        "engine_id": getattr(command, "engine_id", None),
        "action": getattr(command, "action", None),
        "status": getattr(command, "status", None) or None,
        "unreadable": True,
        "why": f"this command's stored row could not be read ({why}); it is not served to its engine",
    }


def _fetch(pks):
    """The commands with these primary keys, in this order: one read. When
    that read fails, each row by itself: one that still cannot be read is an
    _Unreadable, and the others are read as ever."""
    try:
        rows = FailsafeCommand.objects.order_by().in_bulk(pks)
    except Exception:  # noqa: BLE001 - one row that cannot be read must not take the others with it
        logger.exception("could not read %d failsafe commands in one read; reading them one by one", len(pks))
        rows, failed = {}, 0
        for pk in pks:
            if failed >= UNREADABLE_IN_A_ROW:
                rows[pk] = _Unreadable.of(pk, RuntimeError("not tried"), read=False)
                continue
            try:
                rows[pk] = FailsafeCommand.objects.order_by().get(pk=pk)
                failed = 0
            except FailsafeCommand.DoesNotExist:
                continue
            except Exception as exc:  # noqa: BLE001 - counted and named, never raised
                rows[pk] = _Unreadable.of(pk, exc)
                failed += 1
    return [rows[pk] for pk in pks if pk in rows]


def _newest(qs, parts, limit, expiry, in_flight_only):
    """The newest ``limit`` commands of ``qs`` matching any of ``parts`` (each a
    filter an index serves in creation order), newest first; and whether any
    more matched than the limit let through.

    Each part is one index read of at most ``limit`` + 1 keys, then one read of
    the rows chosen, so the work is the limit and the number of parts, whatever
    the number of commands. A command in flight past its window is marked
    expired; ``in_flight_only`` drops it instead of showing it."""
    keys = []
    for part in parts:  # {} is every command, newest first, by the index on creation time
        keys.extend(qs.filter(**part).order_by("-created_at").values_list("pk", "created_at")[: limit + 1])
    keys.sort(key=lambda key: key[1], reverse=True)
    out = []
    for command in _fetch([pk for pk, _created in keys[:limit]]):
        if expiry.due(command.pk, command.status, command.expires_at, command.in_force):
            if in_flight_only:
                continue
            command.status = FailsafeCommand.STATUS_EXPIRED
        out.append(command)
    return out, len(keys) > limit


def _awaiting_parts(actions, signed=(True, False)):
    """Filters for the commands of ``actions`` awaiting a signature, each served
    by an index in creation order (see FailsafeCommand.Meta.indexes)."""
    return [{"status": _AWAITING, "action": action, "signed": one} for action in actions for one in signed]


def _ready_parts(actions):
    return [{"status": _READY, "action": action} for action in actions]


def _lane_keys(qs, tiers, limit, after):
    """The keys -- (tier, created_at, pk) -- of a lane's next ``limit`` + 1
    commands after the key ``after`` (None: from the lane's start), in the
    lane's order: tier by tier, and in each tier newest first, the primary key
    breaking a tie in creation time.

    A keyset, never an offset: a command drafted while a reader pages is
    newer than every key of its tier the reader has passed, so it never moves
    a page boundary -- no command is skipped or listed twice because others
    were added. Each part is one index read of at most ``limit`` + 1 keys, so
    the work is the limit and the number of parts, whatever the number of
    commands."""
    keys = []
    for tier, parts in enumerate(tiers):
        if after is not None and tier < after[0]:
            continue
        for part in parts:
            rows = qs.filter(**part)
            if after is not None and tier == after[0]:
                rows = rows.filter(created_at__lte=after[1]).exclude(created_at=after[1], pk__gte=after[2])
            keys += [
                (tier, created, pk)
                for pk, created in rows.order_by("-created_at", "-pk").values_list("pk", "created_at")[: limit + 1]
            ]
    keys.sort(key=lambda key: (-key[0], key[1], key[2]), reverse=True)
    return keys[: limit + 1]


def _lane(qs, tiers, limit, after, expiry):
    """A lane's next ``limit`` commands after ``after``: [(key, command)], in
    the lane's order, and whether more remain past them. A command in flight
    past its window is marked expired and passed over (command None), so a
    page is never held on it; one gone since its key was read is passed over
    too. A stop in force is never past its window (_Expiry)."""
    keys = _lane_keys(qs, tiers, limit, after)
    more = len(keys) > limit
    keys = keys[:limit]
    rows = {command.pk: command for command in _fetch([pk for _tier, _created, pk in keys])}
    entries = []
    for key in keys:
        command = rows.get(key[2])
        if command is not None and expiry.due(command.pk, command.status, command.expires_at, command.in_force):
            command = None
        entries.append((key, command))
    return entries, more


def _awaiting_stops(qs, expiry):
    """The stop commands in ``qs`` awaiting a signature, at most
    AWAITING_STOP_LIMIT, in the order a co-signer needs them; and whether any
    were left out.

    First those that already carry a signature -- a stand-down or terminate
    waiting for its second -- newest first: a signature needs an enrolled
    operator's key, so no flood of drafts is ahead of these. Then the unsigned
    drafts, taken in turn from each account: every account's newest, then
    every account's second newest, and so on. A flood of drafts from one
    account, or from the dashboard's one service account, therefore lies
    behind every other operator's newest draft rather than in front of it.

    Bounded: per stop action, one index read of at most AWAITING_STOP_LIMIT
    signed keys, one of at most UNSIGNED_STOP_SCAN newest unsigned ones, and one
    grouped read of every account's newest unsigned draft (at most
    AWAITING_STOP_LIMIT accounts), then one read of the rows chosen.

    Every account's newest unsigned stop draft is ranked, so no flood of other
    accounts can hide it (round 5, F5). Ranking only the newest UNSIGNED_STOP_SCAN
    dropped an account whose newest draft was older than that many newer drafts
    of others -- ten accounts of 100 distinct-reason drafts pushed a real
    stand-down out of every read, the engine-scoped one included. The grouped
    read (Max(id) per account -- id is monotonic with creation on SQLite) brings
    each account's newest back into the first round of the round robin. What is
    still left out, stated plainly: with more than AWAITING_STOP_LIMIT accounts
    awaiting a signature, the oldest accounts' newest drafts are past the page,
    and the read says "more" -- never silently dropped."""
    signed, unsigned, scans_full = [], [], False
    for action in STOP_ACTIONS:
        base = qs.filter(status=_AWAITING, action=action).order_by("-created_at")
        some_signed = list(base.filter(signed=True).values_list("pk", "created_at", "expires_at")[:AWAITING_STOP_LIMIT])
        recent = list(
            base.filter(signed=False).values_list("pk", "created_at", "expires_at", "initiator_id")[
                :UNSIGNED_STOP_SCAN
            ]
        )
        # Every account's newest unsigned draft, so no account is dropped even
        # when its newest is older than the newest UNSIGNED_STOP_SCAN of others.
        per_account_newest = [
            row["newest"]
            for row in qs.filter(status=_AWAITING, action=action, signed=False)
            .values("initiator_id")
            .annotate(newest=Max("id"))
            .order_by("-newest")[:AWAITING_STOP_LIMIT]
        ]
        recent_pks = {key[0] for key in recent}
        extra_pks = [pk for pk in per_account_newest if pk not in recent_pks]
        extra = (
            list(qs.filter(pk__in=extra_pks).values_list("pk", "created_at", "expires_at", "initiator_id"))
            if extra_pks
            else []
        )
        scans_full |= (
            len(some_signed) == AWAITING_STOP_LIMIT
            or len(recent) == UNSIGNED_STOP_SCAN
            or len(per_account_newest) == AWAITING_STOP_LIMIT
        )
        signed += some_signed
        unsigned += recent + extra

    def newest_in_flight(keys):
        live = [key for key in keys if not expiry.due(key[0], _AWAITING, key[2])]
        return sorted(live, key=lambda key: key[1], reverse=True)

    signed = [key[0] for key in newest_in_flight(signed)]
    per_account = {}
    for pk, _created, _expires, initiator in newest_in_flight(unsigned):
        per_account.setdefault(initiator, []).append(pk)
    in_turn = [pk for round_ in itertools.zip_longest(*per_account.values()) for pk in round_ if pk is not None]
    chosen = (signed + in_turn)[:AWAITING_STOP_LIMIT]
    return _fetch(chosen), scans_full or len(signed) + len(in_turn) > len(chosen)


class _Page:
    """What one stop-lane read returns: rows in the order given, serialized,
    until they come to stop_lane_read_bytes() -- and whether anything was left
    out, by that or by a row limit.

    Round 4 bounded a read in rows, not bytes: 500 drafts with 60,000-character
    reasons made one read of every engine 18.8 MB. A reason is at most
    REASON_LIMIT characters now, but rows drafted before that are not, so the
    read is bounded in bytes too. Rows are taken in priority order -- the stop
    commands awaiting a signature first, signed ones first among them -- and
    the first row that does not fit ends the page. ``more`` is what the read
    says about it: in the state read's body, and in both reads' X-Failsafe-More
    header."""

    def __init__(self, whole=None, row=None, names_unreadable=True):
        self.whole = self.left = stop_lane_read_bytes() if whole is None else whole
        #: A command as this page lists it: the console's row, or the engine's
        #: command document (pending).
        self._row = row or _console_row
        #: Whether a row that cannot be read is listed by what could be read
        #: of it (the console's reads) or only counted (the engine's poll,
        #: whose answer holds commands and nothing else).
        self.names_unreadable = names_unreadable
        #: The rows this page could not read or turn into a row, as _named, by
        #: primary key: a row two of a read's lists hold is one row.
        self.unreadable = {}
        self.more = False
        #: The uuid of a command passed over because it alone is larger than a
        #: whole page (take_lane), or None.
        self.too_large = None

    def cut(self, more):
        self.more = self.more or bool(more)

    @staticmethod
    def _size(row):
        return len(json.dumps(row, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")) + 1

    def _read(self, command):
        """``command`` as this page lists it, or None: it could not be read,
        and is noted in ``unreadable``. Never raises."""
        if isinstance(command, _Unreadable):
            self.unreadable[command.pk] = _named(command, command.why)
            return None
        try:
            return self._row(command)
        except Exception as exc:  # noqa: BLE001 - one row must not fail the read of the others
            logger.exception("failsafe command %s could not be listed; the rest of the read is answered", command.pk)
            self.unreadable[command.pk] = _named(command, type(exc).__name__)
            return None

    def take(self, commands):
        out = []
        if self.left <= 0:
            self.more = self.more or bool(commands)
            return out
        for command in commands:
            row = self._read(command)
            if row is None:
                if not self.names_unreadable:
                    continue
                row = self.unreadable[command.pk]
            size = self._size(row)
            if size > self.left:
                self.left = 0
                self.more = True
                break
            self.left -= size
            out.append(row)
        return out

    def take_lane(self, entries):
        """A lane's entries (_lane) in order until the page is full: (rows, the
        key of the last entry passed, whether every entry was passed). An entry
        is passed when it is listed, or passed over: past its window, gone, or
        -- once, and ending the page -- larger alone than a whole page, which
        no page could list. That one is named (``too_large``), never dropped
        unsaid, and the next page starts after it, so no reader following the
        cursor is held on it."""
        out, last = [], None
        for key, command in entries:
            if command is None:
                last = key
                continue
            if self.left <= 0:
                self.more = True
                return out, last, False
            row = self._read(command)
            if row is None:
                if not self.names_unreadable:
                    last = key
                    continue
                row = self.unreadable[command.pk]
            size = self._size(row)
            if size > self.whole:
                self.too_large, self.left, self.more = str(getattr(command, "uuid", None)), 0, True
                return out, key, key == entries[-1][0]
            if size > self.left:
                self.left, self.more = 0, True
                return out, last, False
            self.left -= size
            out.append(row)
            last = key
        return out, last, True


def _canonical_unsigned_draft(user, engine_id, action, reason, ttl, before=None):
    """``user``'s OLDEST fresh unsigned draft of ``action`` for ``engine_id``
    with the SAME reason -- the canonical row a set of identical drafts dedupes
    to -- made before the draft ``before`` names, when it names one, or None.

    The OLDEST such draft is the one every identical draft answers with (200),
    because it is the only one that finds no older identical draft than itself:
    it never takes itself back, so it is never a mid-deletion victim, and every
    200 names a row that stays live (round 5, F1). Round 4 answered with the
    NEWEST draft below the caller's pk, which under a burst was a row its own
    request deleted a moment later (GET/sign then 404).

    "Fresh" is at least half of ``ttl`` left, judged in Python on each row so a
    stale oldest draft never shadows a fresher identical one. ``id`` is
    monotonic with creation on SQLite, so ordering by it is the same order the
    take-back's ``pk`` comparison uses. One indexed read, and no lock; a read
    that fails is None, so the draft is made afresh -- a stop draft is never
    refused. The reason is in the signed bytes, so a draft with another reason
    is another draft: round 4 returned a "DRILL - do not sign" draft to the
    dashboard's real pause a second later."""
    try:
        drafts = FailsafeCommand.objects.filter(
            initiator=user, engine_id=engine_id, action=action, status=_AWAITING, signed=False, reason=reason
        )
        if before is not None:
            drafts = drafts.filter(pk__lt=before)
        now = timezone.now()
        for draft in drafts.order_by("id")[:UNSIGNED_STOP_SCAN]:
            try:
                left = (timezone.datetime.fromisoformat(draft.expires_at) - now).total_seconds()
            except (TypeError, ValueError):
                continue
            if left >= ttl / 2:
                return draft
    except Exception:  # noqa: BLE001 - a failed read makes a new draft; it never refuses one
        return None
    return None


class _SharedReads:
    """Identical stop-lane reads, made at once by one account, share one
    computation at a time instead of each making its own.

    A stop-lane read is exempt from the gateway and every throttle, so one
    account can send as many at once as it likes, and each ran on a thread of
    its own: eight threads reading state took a pause's latency from 0.013 s to
    0.231 s (round 3), because every read competed for the interpreter with the
    pause. Now a read of one kind (the route, the account, the credential, and
    the query parameters the view reads: _read_kind) waits while an identical
    one is being computed -- a wait on a lock,
    which competes for nothing -- and then either reuses a result whose
    computation STARTED after it arrived, or computes the next one itself. So a
    reader never gets a result older than its own arrival: it sees every command
    committed before it asked, its own draft included. And it never waits longer
    than SHARED_READ_WAIT (0.25 s): past that it computes its own, as it did
    before. The engine's live state is asked per read, outside this, as before."""

    def __init__(self):
        self._lock = threading.Lock()
        self._kinds = {}

    def read(self, kind, compute):
        with self._lock:
            entry = self._kinds.setdefault(kind, {"lock": threading.Lock(), "started": 0, "last": None, "users": 0})
            entry["users"] += 1
            arrived = entry["started"]
        try:
            if not entry["lock"].acquire(timeout=SHARED_READ_WAIT):
                return compute()
            try:
                last = entry["last"]
                if last is not None and last[0] > arrived:
                    return last[1]
                with self._lock:
                    entry["started"] += 1
                    mine = entry["started"]
                value = compute()
                entry["last"] = (mine, value)
                return value
            finally:
                entry["lock"].release()
        finally:
            with self._lock:
                entry["users"] -= 1
                if entry["users"] == 0:
                    self._kinds.pop(kind, None)


#: The longest a stop-lane read waits for an identical one (_SharedReads).
SHARED_READ_WAIT = 0.25
_SHARED_READS = _SharedReads()


def _read_kind(request, view):
    """What makes two stop-lane reads identical: the route, the account, the
    credential it presented, and the query parameters the view reads --
    engine_id, and for the list its status -- as the view reads them. Never
    the raw query string: round 4 made every read distinct by adding
    ``&n=<i>``, which the view ignores, and none was shared (a pause took
    0.33 s instead of 0.05 s). A page after the first is told apart by its
    cursor, as given."""
    params = request.query_params
    engine_id = params.get("engine_id") or ""
    status_ = ""
    if view == "commands":
        status_ = params.get("status") or ""
        if status_ and status_ not in _STATUSES:
            status_ = "(none)"  # every status the view does not know reads the same: no rows
    kind = (view, request.user.pk, _by_service_token(request), engine_id, status_)
    cursor = params.get(CURSOR_PARAM) or ""
    return (*kind, cursor) if cursor else kind


#: What an in-force stop's row says of itself in the console's reads, by action.
IN_FORCE_NOTES = {
    "pause": (
        "In force: answered to its engine on every poll, whatever its window, until a resume drafted and "
        "signed after it. Nothing else ends it: no window, no cancel, and no release -- after a pause, a "
        "stand-down and a release, this pause is still answered until a resume is signed."
    ),
    "stand_down": (
        "In force: answered to its engine on every poll, whatever its window, until a release drafted and "
        "signed after it. Nothing else ends it: no window, no cancel, and no resume."
    ),
    "terminate": (
        "In force: answered to its engine on every poll, whatever its window. Nothing ends a terminate. An "
        "engine applies one only inside its window; after it, the engine is told one is in force "
        "(X-Failsafe-In-Force)."
    ),
}

#: One serializer for every row a read lists (what a ListSerializer does with
#: its child): building one per row copied its fields per row.
_ROW = FailsafeCommandSerializer()


def _console_row(command):
    """A command as the console's reads list it. A stop in force says so, and
    what alone lifts it; every other row is as it always was."""
    row = _ROW.to_representation(command)
    if command.in_force:
        row["in_force"] = True
        row["ready_at"] = None if command.ready_at is None else command.ready_at.isoformat()
        row["lifted_only_by"] = LIFTED_ONLY_BY.get(command.action)
        row["in_force_note"] = IN_FORCE_NOTES.get(command.action, "")
    elif command.lifted_at is not None:
        row["lifted_by"] = None if command.lifted_by is None else str(command.lifted_by)
        row["lifted_at"] = command.lifted_at.isoformat()
    return row


def _event(command, event, request, **detail):
    """An audit event for ``command`` (a row, or its primary key), not yet written."""
    return FailsafeAuditEvent(
        **({"command": command} if isinstance(command, FailsafeCommand) else {"command_id": command}),
        event=event,
        actor=request.user if request.user.is_authenticated else None,
        detail={**getattr(request, "audit_metadata", {}), **detail},
    )


def _audit(command, event, request, **detail):
    _event(command, event, request, **detail).save(force_insert=True)


class _Count:
    """A count kept for the life of this process, and since when it counts
    (``since``: when this process made it, at its start). It lives in memory
    only, so a restart begins it again at 0: a reader is told since when, and
    reads a zero as "none since then", never as "none"."""

    def __init__(self):
        self._lock = threading.Lock()
        self._n = 0
        self.since = datetime.now(dt_timezone.utc)

    def add(self, n):
        with self._lock:
            self._n += n

    @property
    def value(self):
        return self._n


#: The audit rows of stops this process could not write (_audit_a_stop).
AUDIT_ROWS_MISSED = _Count()
#: The header a stop's answer carries when an audit row of it could not be
#: written: how many. The state read always carries this process's count so
#: far ("0" when none), and AUDIT_MISSED_SINCE_HEADER beside it.
AUDIT_MISSED_HEADER = "X-Failsafe-Audit-Missed"
#: The header the state read always carries beside AUDIT_MISSED_HEADER: since
#: when this process counts (its start, ISO 8601). The count is in memory and a
#: restart begins it again, so "0" reads "none missed since then".
AUDIT_MISSED_SINCE_HEADER = "X-Failsafe-Audit-Missed-Since"


def _audit_a_stop(events, one_insert=False, using=DEFAULT_DB_ALIAS):
    """Write a stop's audit rows on ``using``; never raise. Returns how many
    were missed. Each row is its own INSERT, as it was, unless ``one_insert``
    (a draft's rows, which were one INSERT before too).

    A stop's signature and its readiness were written in one transaction with
    their audit rows, with nothing around the inserts: an audit insert that
    failed rolled the signature back and answered 500 -- a failed write
    holding back a stop. Then a slow one held the stop's commit, and so its
    serving and its answer (3.04 s and 3.02 s for a 3 s hold). A stop's rows
    are written now once the stop has committed, never waiting for the
    database's write lock and adding no statement to the request's
    connection (_housekeeping_connection, at each caller), in a transaction
    of their own: a failure rolls back the audit rows alone.
    What is missing is never silent: it is logged as an error naming each
    event and command, counted (AUDIT_ROWS_MISSED), and said on the answer
    (AUDIT_MISSED_HEADER). A process that ends between the stop's commit and
    this insert loses the rows uncounted; the stop's row still holds its
    signers, their times and ``ready_at``."""
    try:
        with transaction.atomic(using=using):
            if one_insert:
                FailsafeAuditEvent.objects.db_manager(using).bulk_create(events)
            else:
                for event in events:
                    event.save(force_insert=True, using=using)
        return 0
    except Exception:  # noqa: BLE001 - a stop never fails on its audit rows
        AUDIT_ROWS_MISSED.add(len(events))
        logger.exception(
            "AUDIT ROWS MISSING: %d failsafe audit rows could not be written and the stop stands: %s",
            len(events),
            ", ".join(f"{event.event} of command {event.command_id}" for event in events),
        )
        return len(events)


def _saying(response, missed):
    """``response``, saying how many audit rows of this stop are missing."""
    if missed:
        response[AUDIT_MISSED_HEADER] = str(missed)
    return response


def _expire_if_due(command, now=None):
    """Lazily flip a past-its-window command to expired. Returns True if
    expired. A stop in force is never expired (FailsafeCommand.in_force)."""
    now = now or timezone.now()
    if not command.in_force and command.status in _IN_FLIGHT and _due(command.expires_at, now):
        command.mark_expired()
        return True
    return False


def _expire_if_due_without_waiting(command):
    """_expire_if_due, for a read outside any transaction of its own (a
    command's detail; a signature before its transaction): its write is
    housekeeping, so it never waits for the database's write lock (D3).
    Refused at once, it is logged, and the command is judged and shown by its
    window all the same -- expired, as it is: no signature counts on it and
    the engine would refuse it. The next read writes it. A command that is not
    due makes no statement."""
    now = timezone.now()
    if command.in_force or command.status not in _IN_FLIGHT or not _due(command.expires_at, now):
        return False
    try:
        with _not_waiting_for_the_write_lock():
            command.mark_expired()
    except Exception:  # noqa: BLE001 - housekeeping never fails the read; the command is past its window
        logger.warning("could not mark the failsafe command %s expired; the next read will", command.uuid,
                       exc_info=True)
        command.status = FailsafeCommand.STATUS_EXPIRED
    return True


@api_view(["GET", "POST"])
@permission_classes([IsAdminOrAnalyst])
def commands(request):
    if request.method == "GET":
        # A stop-lane read: no throttle counts it (safety.stops), so its work is
        # bounded by its row and byte limits, not by the number of commands.
        # The stop commands awaiting a signature come first (_awaiting_stops)
        # and are never cut by the row cap, so no flood of other drafts hides
        # one. X-Failsafe-More says whether anything was left out, and
        # X-Failsafe-Next which cursor reads the next page (_Read).
        try:
            read = _Read(request, "commands")
        except _BadCursor as exc:
            return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
        rows, more, following, too_large, unreadable = _SHARED_READS.read(
            _read_kind(request, "commands"), lambda: _list(request, read)
        )
        return Response(rows, headers=_page_headers(more, following, too_large, unreadable))

    serializer = DraftCommandSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    action = serializer.validated_data["action"]
    engine_id = serializer.validated_data["engine_id"]

    if action in _ADMIN_ONLY_ACTIONS and not request.user.is_admin:
        return Response(
            {"detail": f"{action} may only be initiated by an admin"},
            status=status.HTTP_403_FORBIDDEN,
        )

    ttl = int(getattr(settings, "FAILSAFE_COMMAND_TTL_SECONDS", 600))
    reason = serializer.validated_data.get("reason", "")
    # A stop is never refused for its reason length (round 5, F3): the dashboard
    # can send a reason up to draftCommandSchema's 2,000, and a stop judged a
    # stop by safety.stops (any text up to the 64 KiB body) must not then be
    # 400'd by this view. A reason past REASON_LIMIT is truncated and stored --
    # the signing bytes are for the stored reason, so a signature still matches.
    # A NON-stop draft (resume/release) past the bound is input validation.
    from .serializers import REASON_LIMIT

    if action in STOP_ACTIONS:
        return _stop_draft(request, action, engine_id, reason[:REASON_LIMIT], ttl)
    if len(reason) > REASON_LIMIT:
        return Response(
            {"reason": [f"A reason is at most {REASON_LIMIT:,} characters."]},
            status=status.HTTP_400_BAD_REQUEST,
        )

    command, draft = _new_draft(request, action, engine_id, reason, ttl)
    return _drafted(command, draft, status.HTTP_201_CREATED)


def _new_draft(request, action, engine_id, reason, ttl, audit=True):
    draft = make_draft(action, engine_id, reason, ttl)
    command = FailsafeCommand.objects.create(
        engine_id=draft["engine_id"],
        action=draft["action"],
        nonce=draft["nonce"],
        issued_at=draft["issued_at"],
        expires_at=draft["expires_at"],
        reason=draft["reason"],
        required_signatures=required_signatures(action),
        initiator=request.user,
    )
    if audit:
        _audit(command, FailsafeAuditEvent.EVENT_DRAFTED, request, action=action,
               engine_id=command.engine_id)
    return command, draft


def _drafted(command, draft, code):
    body = FailsafeCommandSerializer(command).data
    # The exact bytes the operator's CLI must sign for this command.
    body["signing_bytes"] = signing_bytes_hex(draft)
    return Response(body, status=code)


def _stop_draft(request, action, engine_id, reason, ttl):
    """A stop draft: never refused and never throttled (safety.stops).

    Made again by the same account for the same engine with the same reason
    while that draft is unsigned and has at least half its window left, it
    returns that draft (200) -- the same uuid, the same bytes to sign, and the
    window it has left, at least half of FAILSAFE_COMMAND_TTL_SECONDS -- so a
    signature already made out of band still counts. Any other draft is new
    (201): another reason, action, engine or account, or one signed, cancelled,
    expired, superseded or past half its window.

    Identical drafts sent at once are one row, where round 4 made up to four.
    Each inserts its row and looks for an identical fresh draft made before it
    (on SQLite, the one database this project configures, rows are numbered in
    the order they are written, so of any two the later finds the earlier) in
    ONE write transaction, and takes its own row back if it finds one -- so a
    taken-back row is deleted in the same transaction that inserted it and is
    never visible to a list read (round 5, F1/C4). The look-up returns the
    OLDEST identical draft, which never finds one older and so never takes
    itself back: every 200 names that row, which stays live. Only the insert,
    the look-up and the take-back are in the transaction; superseding and the
    audit are outside it, so the write lock is held for that dedupe alone and
    never across the superseding (which, inside it, delayed a pause 2.9 s during
    a draft flood). Outside it, neither waits for the write lock either: the
    answer with the bytes to sign is never held behind another writer for
    them.

    The account's unsigned stop drafts past unsigned_stop_drafts_per_account()
    -- its oldest -- are then superseded (_supersede_past_limit). Only the
    account's own: one account's flood never supersedes another's drafts. A
    superseded but unsigned real stop is never lost: a valid signature revives
    it (submit_signature), so a count never makes a pending stop unsignable."""
    existing = _canonical_unsigned_draft(request.user, engine_id, action, reason, ttl)
    if existing is not None:
        return _drafted(existing, existing.as_command_dict(), status.HTTP_200_OK)
    # Insert the row and settle whether it is a duplicate in ONE write
    # transaction (round 5, F1/C4): a row that is taken back is deleted in the
    # same transaction that inserted it, so a concurrent list read sees either
    # nothing or the committed canonical row -- never a mid-deletion victim it
    # would later find gone. Only the insert, one indexed look-up for an older
    # identical draft, and the conditional take-back are inside it; the reused-
    # draft fast path above, superseding and the audit run OUTSIDE, so the write
    # lock is never held across them (superseding inside it delayed a pause
    # 2.9 s -- round 5's lock test). The look-up returns the OLDEST identical
    # draft, which never takes itself back, so it is never another request's
    # canonical answer.
    command = earlier = None
    try:
        with transaction.atomic():
            command = _insert_draft(request, action, engine_id, reason, ttl)
            earlier = _canonical_unsigned_draft(request.user, engine_id, action, reason, ttl, before=command.pk)
            if earlier is not None:
                FailsafeCommand.objects.filter(pk=command.pk, status=_AWAITING, signed=False).delete()
    except Exception:  # noqa: BLE001 - a stop draft is never refused; on any error the row is made afresh
        logger.exception("could not settle a duplicate stop draft; making it afresh")
        command, earlier = _insert_draft(request, action, engine_id, reason, ttl), None
    if earlier is not None:
        return _drafted(earlier, earlier.as_command_dict(), status.HTTP_200_OK)
    # The draft is committed and signable. Superseding and its audit row are
    # housekeeping, and neither waits for the database's write lock (D4): the
    # bytes to sign came back 3.01 s after the row was signable, behind them.
    # Refused at once, a supersede is logged and the next draft makes it; a
    # missing audit row is counted and said, as one that fails is. The audit
    # row is made on a connection of their own (_housekeeping_connection), so
    # the draft's own connection makes no statement more; a supersede, made
    # only by a draft past its account's limit, on the draft's connection
    # (_supersede_past_limit).
    superseded = _supersede_past_limit(command)
    actor = request.user if request.user.is_authenticated else None
    metadata = getattr(request, "audit_metadata", {})
    events = [
        FailsafeAuditEvent(
            command=command, event=FailsafeAuditEvent.EVENT_DRAFTED, actor=actor,
            detail={**metadata, "action": action, "engine_id": command.engine_id,
                    **({"superseded": len(superseded)} if superseded else {})},
        )
    ]
    events += [
        FailsafeAuditEvent(
            command_id=pk, event=FailsafeAuditEvent.EVENT_SUPERSEDED, actor=actor,
            detail={**metadata, "by": str(command.uuid), "limit": unsigned_stop_drafts_per_account()},
        )
        for pk in superseded
    ]
    # The draft is made: an audit row that cannot be written never refuses it.
    with _housekeeping_connection() as using:
        missed = _audit_a_stop(events, one_insert=True, using=using)
    return _saying(_drafted(command, command.as_command_dict(), status.HTTP_201_CREATED), missed)


def _insert_draft(request, action, engine_id, reason, ttl):
    """A fresh command row for ``request``'s account. The nonce and window are
    server-set (make_draft); the audit is written by the caller."""
    draft = make_draft(action, engine_id, reason, ttl)
    return FailsafeCommand.objects.create(
        engine_id=draft["engine_id"],
        action=draft["action"],
        nonce=draft["nonce"],
        issued_at=draft["issued_at"],
        expires_at=draft["expires_at"],
        reason=draft["reason"],
        required_signatures=required_signatures(action),
        initiator=request.user,
    )


def _supersede_past_limit(newest):
    """Supersede ``newest``'s account's oldest unsigned stop drafts past
    unsigned_stop_drafts_per_account(): no longer awaiting a signature, and
    recorded as superseded -- the status, and an audit event naming the draft
    that superseded each (_stop_draft). A draft already carrying a signature is
    never superseded. One index read of the account's unsigned drafts past the
    limit (at most SUPERSEDE_PER_DRAFT of them), one write, and one read of
    what the write changed. Returns their primary keys.

    Why: a stop draft is never refused, so one account could draft without end
    -- 1,200 in 10 s to engines that do not exist, all awaiting a signature
    (round 4, H1). Its unsigned drafts are bounded now, never its right to draft.
    A failure here is logged; the new draft stands.

    Its write never waits for the database's write lock (D4): refused at
    once, it is logged and the next draft makes it. It is made on the
    draft's own connection, outside any transaction, as it was; so only a
    draft past its account's limit -- the one that writes -- adds the three
    PRAGMAs of _not_waiting_for_the_write_lock, and a draft within its limit
    makes the statements it made."""
    limit = unsigned_stop_drafts_per_account()
    commands = FailsafeCommand.objects
    try:
        pks = [
            pk
            for pk in commands.filter(
                initiator=newest.initiator_id, status=_AWAITING, signed=False, action__in=STOP_ACTIONS
            )
            .order_by("-created_at")
            .values_list("pk", flat=True)[limit : limit + SUPERSEDE_PER_DRAFT]
            if pk != newest.pk
        ]
        if not pks:
            return []
        now = timezone.now()
        with _not_waiting_for_the_write_lock():
            commands.filter(pk__in=pks, status=_AWAITING, signed=False).update(
                status=FailsafeCommand.STATUS_SUPERSEDED, updated_at=now
            )
            return list(
                commands.filter(pk__in=pks, status=FailsafeCommand.STATUS_SUPERSEDED, updated_at=now)
                .values_list("pk", flat=True)
            )
    except Exception:  # noqa: BLE001 - superseding is housekeeping; the new stop draft stands
        logger.exception("could not supersede drafts past the limit of account %s", newest.initiator_id)
        return []


#: The header both stop-lane reads carry: "true" when the read left out a
#: command it would otherwise have listed, by a row limit or the byte limit.
MORE_HEADER = "X-Failsafe-More"


#: The header both stop-lane reads carry when they say more: the cursor that
#: reads their next page, passed back as given in the query parameter
#: CURSOR_PARAM. The state read says it in its body's ``next`` too.
NEXT_HEADER = "X-Failsafe-Next"
CURSOR_PARAM = "cursor"
#: The header naming a command a page passed over because it alone is larger
#: than a whole page (_Page.take_lane). Open it by its uuid.
TOO_LARGE_HEADER = "X-Failsafe-Too-Large"
#: The longest cursor a read takes; a longer one is answered 400.
CURSOR_LIMIT = 1024
_CURSOR_VERSION = 1
_CURSOR_TEXT = re.compile(r"[A-Za-z0-9_-]+")
_PK_LIMIT = 2**63 - 1


class _BadCursor(ValueError):
    """A cursor this read cannot follow: answered 400, never 500."""


class _Read:
    """One stop-lane read: what it reads and in what order.

    Its first page is what it always was, in the order that matters: the stop
    commands awaiting a signature in a co-signer's order (_awaiting_stops),
    then each of its lanes. A lane is a keyset over tiers (_lane_keys); its
    first page is its first rows, and each page after reads the next. The
    lanes put everything in flight before any history, and the stops first:

    * the list (an operator's session): the ready stops; then the resumes and
      releases awaiting a signature or ready; then history -- consumed,
      expired, canceled and superseded -- at most COMMAND_LIST_LIMIT a page;
    * the list (the service token): the ready stops, at most AWAITING_STOP_LIMIT;
    * the state: the starts awaiting a signature (not for the service token),
      and the ready stops then (not for the service token) the ready starts,
      at most STATE_LIST_LIMIT a page each.

    When the first page's awaiting stops are cut -- more than
    AWAITING_STOP_LIMIT of them, or by the byte cap -- the pages after it read
    lane ``s``: every stop command awaiting a signature, signed ones first,
    newest first, once each. Those the first page listed are among them: the
    first page is a priority view, and a reader following the cursor may meet
    a stop twice, never not at all."""

    def __init__(self, request, view):
        self.view = view
        self.by_token = _by_service_token(request)
        engine_id = request.query_params.get("engine_id")
        self.qs = FailsafeCommand.objects.all()
        if engine_id:
            self.qs = self.qs.filter(engine_id=engine_id)
        if view == "commands":
            state_ = request.query_params.get("status")
            statuses = _STATUSES if not state_ else tuple(s for s in _STATUSES if s == state_)
        else:
            statuses = _IN_FLIGHT
        awaiting, ready = _AWAITING in statuses, _READY in statuses
        lanes = []
        if awaiting:
            lanes.append(("s", [_awaiting_parts(STOP_ACTIONS, (True,)), _awaiting_parts(STOP_ACTIONS, (False,))],
                          AWAITING_STOP_LIMIT))
        ready_stops = _ready_parts(STOP_ACTIONS) if ready else []
        if view == "commands" and self.by_token:
            lanes.append(("t", [ready_stops], AWAITING_STOP_LIMIT))
        elif view == "commands":
            starts = (_awaiting_parts(START_ACTIONS) if awaiting else []) + (_ready_parts(START_ACTIONS) if ready else [])
            history = [{"status": state_} for state_ in statuses if state_ in _HISTORY]
            lanes.append(("t", [ready_stops, starts, history], COMMAND_LIST_LIMIT))
        elif self.by_token:
            lanes.append(("r", [ready_stops], STATE_LIST_LIMIT))
        else:
            lanes.append(("a", [_awaiting_parts(START_ACTIONS)], STATE_LIST_LIMIT))
            lanes.append(("r", [ready_stops, _ready_parts(START_ACTIONS)], STATE_LIST_LIMIT))
        self.lanes = lanes
        # A cursor is for the read that gave it: the view, the credential, and
        # the parameters the view reads (never the account: it names no rows).
        _view, _account, *what = _read_kind(request, view)[:5]
        self.binding = hashlib.sha256(json.dumps([view, *what]).encode("utf-8")).hexdigest()[:16]
        self.after = self._cursor(request.query_params.get(CURSOR_PARAM) or "")

    def _cursor(self, text):
        """The lanes a cursor continues, each with the key it continues after
        (None: from its start); None for the first page. _BadCursor when it is
        not one this read gave."""
        if not text:
            return None
        if len(text) > CURSOR_LIMIT or not _CURSOR_TEXT.fullmatch(text):
            raise _BadCursor(f"the cursor is not one this read gives (at most {CURSOR_LIMIT} URL-safe base64 characters)")
        try:
            data = json.loads(base64.urlsafe_b64decode(text + "=" * (-len(text) % 4)).decode("utf-8"))
        except (ValueError, UnicodeDecodeError, RecursionError) as exc:
            raise _BadCursor("the cursor cannot be read") from exc
        if not isinstance(data, dict) or set(data) != {"v", "k", "l"}:
            raise _BadCursor("the cursor cannot be read")
        if type(data["v"]) is not int or data["v"] != _CURSOR_VERSION:
            raise _BadCursor("the cursor is of a version this read does not take")
        if data["k"] != self.binding:
            raise _BadCursor("the cursor is for another read: another view, engine, status or credential")
        lanes, tiers = data["l"], {name: len(tiers) for name, tiers, _limit in self.lanes}
        if not isinstance(lanes, dict) or not lanes or not set(lanes) <= set(tiers):
            raise _BadCursor("the cursor names no lane of this read")
        return {name: self._key(position, tiers[name]) for name, position in lanes.items()}

    @staticmethod
    def _key(position, tiers):
        if position is None:
            return None
        if not isinstance(position, list) or len(position) != 3:
            raise _BadCursor("the cursor holds a position that is not one")
        tier, created, pk = position
        if type(tier) is not int or not 0 <= tier < tiers or type(pk) is not int or not 0 < pk <= _PK_LIMIT:
            raise _BadCursor("the cursor holds a position that is not one")
        if not isinstance(created, str) or len(created) > 64:
            raise _BadCursor("the cursor holds a time that is not one")
        try:
            created = timezone.datetime.fromisoformat(created)
        except ValueError as exc:
            raise _BadCursor("the cursor holds a time that is not one") from exc
        # The read writes the time as stored: with its zone when the project
        # keeps zones, without one when it does not.
        if timezone.is_aware(created) != timezone.is_aware(timezone.now()):
            raise _BadCursor("the cursor holds a time that is not one")
        return (tier, created, pk)

    def encode(self, continuing):
        lanes = {
            name: None if key is None else [key[0], key[1].isoformat(), key[2]] for name, key in continuing.items()
        }
        text = json.dumps({"v": _CURSOR_VERSION, "k": self.binding, "l": lanes}, separators=(",", ":"))
        return base64.urlsafe_b64encode(text.encode("utf-8")).decode("ascii").rstrip("=")

    def page(self, expiry, page):
        """This page's rows, by lane, in lane order -- {name: rows} -- and the
        cursor of the next page, or None when nothing is left."""
        rows, continuing, first = {}, {}, self.after is None
        for name, tiers, limit in self.lanes:
            if first and name == "s":
                stops, stops_more = _awaiting_stops(self.qs, expiry)
                rows[name] = page.take(stops)
                if stops_more or len(rows[name]) < len(stops):
                    continuing[name] = None
                continue
            if not first and name not in self.after:
                continue  # a lane a page before this one finished
            after = None if first else self.after[name]
            entries, more = _lane(self.qs, tiers, limit, after, expiry)
            rows[name], last, passed = page.take_lane(entries)
            if more or not passed:
                continuing[name] = after if last is None else last
        return rows, (self.encode(continuing) if continuing else None)


def _list(request, read):
    """The list read: (rows, more, the next page's cursor, a command too large
    for any page)."""
    expiry = _Expiry()
    page = _Page()
    lanes, following = read.page(expiry, page)
    expiry.mark()
    rows = [row for name, _tiers, _limit in read.lanes for row in lanes.get(name, [])]
    return rows, following is not None, following, page.too_large, len(page.unreadable)


#: The header every stop-lane read and the engine's poll carry: how many
#: command rows the read came across that it could not read or turn into a
#: row. "0" when there were none. Such a row is not in the engine's answer;
#: every readable one is. An engine reads more than 0 as "not heard clean".
UNREADABLE_HEADER = "X-Failsafe-Unreadable"
#: The header the engine's poll carries when its page came across a stop in
#: force: the kinds in force there, the strongest first ("terminate",
#: "stand_down", "pause"). An engine applies a terminate only inside its
#: window, so past it this header is how the engine is told one is in force.
#: It names a stop in force whose row could not be turned into a command too
#: (X-Failsafe-Unreadable counts that one): in force, and not in the answer.
#: And a ready stop whose row could not be loaded at all, by its lane's action:
#: it may be in force (_PollRead.page). The names and the order are
#: mythos_core.failsafe.wire's (UNREADABLE_HEADER, IN_FORCE_HEADER,
#: IN_FORCE_ORDER), held to it by
#: tests/test_the_planes_polls_read_clean_through_the_core.py.
IN_FORCE_HEADER = "X-Failsafe-In-Force"


def _page_headers(more, following, too_large, unreadable=0):
    return {
        MORE_HEADER: "true" if more else "false",
        UNREADABLE_HEADER: str(unreadable),
        **({NEXT_HEADER: following} if following else {}),
        **({TOO_LARGE_HEADER: too_large} if too_large else {}),
    }


@api_view(["GET"])
@permission_classes([IsAdminOrAnalyst])
def command_detail(request, cmd_uuid):
    command = get_object_or_404(FailsafeCommand, uuid=cmd_uuid)
    _expire_if_due_without_waiting(command)
    if _by_service_token(request) and (command.action not in STOP_ACTIONS or command.status not in _IN_FLIGHT):
        # The service token reads a stop command in flight and its signing
        # bytes; nothing else, and no resume's or release's bytes.
        raise Http404
    body = _console_row(command)
    body["signing_bytes"] = signing_bytes_hex(command.as_command_dict())
    return Response(body)


def _signable(command, now=None):
    """Whether ``command`` may still take a signature: it is awaiting one, or it
    is a superseded but unsigned stop still inside its window.

    A superseded stop is signable so a count never makes a real pending stop
    unsignable (round 5, F2, SAFETY): supersession bounds an account's UNSIGNED
    stop drafts (queue bounding), but a flood -- or a fleet pause past the limit
    -- must not turn a genuine stop's signature into 409. A valid signature
    revives it (submit_signature). A superseded draft is always unsigned (a
    signed one is never superseded), and one past its window is not revived --
    its nonce and window are spent, so the engine would reject it anyway."""
    now = now or timezone.now()
    if command.status == FailsafeCommand.STATUS_AWAITING:
        return True
    if command.status == FailsafeCommand.STATUS_SUPERSEDED and not command.signed:
        return not _due(command.expires_at, now)
    return False


@api_view(["POST"])
@permission_classes([IsAdminOrAnalyst])
def submit_signature(request, cmd_uuid):
    command = get_object_or_404(FailsafeCommand, uuid=cmd_uuid)
    _expire_if_due_without_waiting(command)
    if not _signable(command):
        return Response(
            {"detail": f"command is {command.status}; not accepting signatures"},
            status=status.HTTP_409_CONFLICT,
        )

    serializer = SubmitSignatureSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    key_id = serializer.validated_data["key_id"]
    sig = serializer.validated_data["sig"]

    keyring = operator_keyring()
    fields = command.as_command_dict()
    from .signing import verify_signature

    if not verify_signature(fields, key_id, sig, keyring):
        _audit(command, FailsafeAuditEvent.EVENT_SIGNATURE_REJECTED, request,
               key_id=key_id, why="invalid or unknown-key signature")
        return Response(
            {"detail": "signature did not verify against an enrolled operator key"},
            status=status.HTTP_400_BAD_REQUEST,
        )

    # The append is made to the row as it is NOW, under the write lock: the
    # read above can be stale by the time it is written. Two operators signing
    # one stand-down at the same moment both read it with no signature, and
    # the second save overwrote the first's -- both answered 200, and the
    # stand-down stayed awaiting with one (round 4, M3: 6/20 on main). The
    # transaction takes SQLite's write lock at its start (IMMEDIATE,
    # config.settings) and the row's lock elsewhere (select_for_update); the
    # row is read again inside it and everything is judged on that.
    #
    # A stop gains nothing here. Its readiness is the one UPDATE it was, now
    # also saying when (ready_at) and that it is in force (mark_ready); its
    # mark is the one UPDATE it was, in the same transaction (it is what holds
    # an older start back); and its audit rows are the inserts they were, in a
    # transaction of their own, and never fail the signature (_audit_a_stop) --
    # written once the stop has committed, never waiting for the write lock (D2), so the
    # stop is served the moment it commits and a held lock never delays its
    # answer. Everything a START needs beyond that -- the read of its engine's
    # stops in force and the write that lifts them -- is on the start's path
    # only, and a start that cannot be made ready with its lift is not made
    # ready at all: its audit rows are still written in its transaction.
    owed = []
    try:
        with transaction.atomic():
            command = FailsafeCommand.objects.select_for_update().filter(pk=command.pk).first()
            if command is None:
                raise Http404
            _expire_if_due(command)
            if not _signable(command):
                return Response(
                    {"detail": f"command is {command.status}; not accepting signatures"},
                    status=status.HTTP_409_CONFLICT,
                )
            if key_id in command.distinct_signers():
                return Response(
                    {"detail": f"{key_id} has already signed"}, status=status.HTTP_409_CONFLICT
                )

            # A superseded but unsigned stop, validly signed, is revived here: it
            # returns to awaiting a signature and takes this one, so a count never
            # makes a real pending stop unsignable (round 5, F2, SAFETY). Now that
            # it carries a signature it is never superseded again.
            revived = command.status == FailsafeCommand.STATUS_SUPERSEDED
            if revived:
                command.status = FailsafeCommand.STATUS_AWAITING
            command.signatures.append({
                "key_id": key_id,
                "sig": sig,
                "submitted_by": request.user.username,
                "submitted_at": timezone.now().isoformat(),
            })
            command.signed = True
            command.save(update_fields=["signatures", "signed", "status", "updated_at"])
            is_stop = command.action in STOP_ACTIONS
            signed_ = _event(command, FailsafeAuditEvent.EVENT_SIGNED, request, key_id=key_id,
                             **({"revived": True} if revived else {}))
            events = [signed_]
            if not is_stop:
                signed_.save(force_insert=True)

            valid = distinct_valid_signers(command.as_command_dict(), command.signatures, keyring)
            if len(valid) >= command.required_signatures:
                if is_stop:
                    command.mark_ready()
                    _mark_stop_made_ready(command)
                    events.append(_event(command, FailsafeAuditEvent.EVENT_READY, request, signers=sorted(valid)))
                else:
                    try:
                        lifted, lifts_nothing = _make_start_ready(command)
                        for event in (
                            _event(command, FailsafeAuditEvent.EVENT_READY, request, signers=sorted(valid),
                                   lifted=[str(stop_uuid) for _pk, stop_uuid in lifted],
                                   **({"lifts_nothing": lifts_nothing} if lifts_nothing else {})),
                            *[
                                _event(pk, FailsafeAuditEvent.EVENT_LIFTED, request, by=str(command.uuid),
                                       by_action=command.action)
                                for pk, _stop_uuid in lifted
                            ],
                        ):
                            event.save(force_insert=True)
                    except Exception as exc:
                        raise _StartNotMadeReady from exc
            if is_stop:
                owed = events  # written once this transaction has committed (below)
    except _StartNotMadeReady:
        logger.exception("the %s %s was not made ready: what it lifts could not be read or written",
                         command.action, command.uuid)
        return Response(
            {"detail": f"Held, not done: this {command.action} was not made ready, because the stops it would "
                       "lift could not be read or recorded. Every stop in force stays in force. Sign it again."},
            status=status.HTTP_503_SERVICE_UNAVAILABLE,
        )

    # The stop has committed: it is ready, in force and served. Its audit rows
    # are housekeeping now, made on a connection of their own that never
    # waits for the write lock (_housekeeping_connection): refused at once on
    # a held lock, they are counted and said on this answer, and this
    # request's connection makes no statement more.
    missed = 0
    if owed:
        with _housekeeping_connection() as using:
            missed = _audit_a_stop(owed, using=using)
    return _saying(Response(_console_row(command)), missed)


class _StartNotMadeReady(Exception):
    """A resume or release whose readiness could not be written whole: its
    transaction is rolled back, signature and all (submit_signature)."""


#: The stop each start lifts, and no other (LIFTED_ONLY_BY, the other way round).
_LIFTS = {start: stop for stop, start in LIFTED_ONLY_BY.items() if start}


def _make_start_ready(start):
    """Make the resume or release ``start`` ready, and lift what it lifts:
    (the stops lifted, as (pk, uuid); why it lifts nothing, or "").

    Called in the transaction that signs it into force, and raises on any
    failure: that transaction is then rolled back, so a start is never ready
    with its lift unwritten. One read of its engine's mark, one of its
    engine's stops in force (a few rows, by fsc_eng_st_ct), its own UPDATE as
    before, and one UPDATE of the stops it lifts.

    What it lifts: the stops of its own kind -- a resume lifts pauses, a
    release lifts stand-downs, and nothing lifts a terminate -- in force for
    its engine and drafted before it. Every stop in force was made ready
    before this moment, so it is later than each in both orders. A stand-down
    is not lifted by a resume, nor a pause by a release: after a pause, a
    stand-down and a release, the pause is still in force until a resume is
    signed. That never under-holds.

    It lifts nothing when the poll will never deliver it (_PollRead._held):
    its engine has no mark, or a stop made ready for its engine -- the mark,
    or one in force -- was drafted at or after it.

    ``ready_at`` is strictly after the engine's last stop made ready, even on
    a clock that ties, so a start signed after a stop is never read as
    signed with it."""
    mark = FailsafeStopMark.objects.filter(engine_id=start.engine_id).first()
    in_force = list(
        FailsafeCommand.objects.filter(engine_id=start.engine_id, status=_READY, in_force=True)
        .order_by("-created_at")
        .values_list("pk", "uuid", "action", "created_at", "ready_at")[:POLL_STOP_LIMIT]
    )
    at = timezone.now()
    last = max(
        [mark.last_ready_at] * (mark is not None and mark.last_ready_at is not None)
        + [ready for *_rest, ready in in_force if ready is not None],
        default=None,
    )
    if last is not None and at <= last:
        at = last + timedelta(microseconds=1)
    start.mark_ready(at=at)
    if mark is None:
        return [], "no stop was ever made ready for its engine, so the poll holds every start of it back"
    newest = max([mark.created_at] + [created for _pk, _uuid, _action, created, _ready in in_force])
    if start.created_at <= newest:
        return [], "it was drafted at or before a stop made ready for its engine, so the poll never delivers it"
    # Every stop in force was drafted before it (the check above) and made
    # ready before it (now): it lifts those of its own kind, and no other.
    lifted = [
        (pk, stop_uuid) for pk, stop_uuid, action, _created, _ready in in_force if action == _LIFTS[start.action]
    ]
    if lifted:
        FailsafeCommand.objects.filter(pk__in=[pk for pk, _uuid in lifted], in_force=True).update(
            in_force=False, lifted_by=start.uuid, lifted_at=at, updated_at=at
        )
    return lifted, ""


def _put_back_in_force(start):
    """Put back in force the stops the cancelled start ``start`` lifted: each
    as (pk, uuid), or None when that could not be done (logged, and said).

    A start that was made ready lifted its stops then. Cancelled, it is no
    longer delivered, so an engine that had not heard it stays stopped -- and
    the plane must go on answering the stop. One read by fsc_lifted_by and,
    when it lifted any, one write, after the cancel itself is written: it
    never fails or delays the cancel."""
    try:
        with transaction.atomic():
            stops = list(FailsafeCommand.objects.filter(lifted_by=start.uuid).order_by().values_list("pk", "uuid"))
            if stops:
                FailsafeCommand.objects.filter(pk__in=[pk for pk, _uuid in stops]).update(
                    in_force=True, status=_READY, lifted_by=None, lifted_at=None, updated_at=timezone.now()
                )
        return [(pk, str(stop_uuid)) for pk, stop_uuid in stops]
    except Exception:  # noqa: BLE001 - the cancel stands; what could not be put back is said
        logger.exception("could not put back in force the stops the cancelled %s %s lifted", start.action, start.uuid)
        return None


#: The header a cancelled start's answer carries when that start had been made
#: ready: how many stops it had lifted are back in force, or "unknown" when
#: they could not be put back (logged as an error).
BACK_IN_FORCE_HEADER = "X-Failsafe-Back-In-Force"


def _back_in_force_note(start, back):
    """What the answer to the cancel of ``start``, a start that had been made
    ready, tells the operator. ``back`` is the uuids of the stops put back in
    force, or None when they could not be.

    Putting a stop back in force makes the plane answer it again; it does not
    stop an engine that is running. An engine that applied the stop and then
    the start holds the stop's nonce in the core's nonce ledger, and rejects
    it as a replay for as long as it runs. So the old stop stops such an
    engine again only when it restarts. What stops it now is a new stop,
    which nothing here holds back."""
    stop = _LIFTS[start.action]
    kind = stop.replace("_", "-")
    if back is None:
        what = (
            f"The stops this {start.action} had lifted could not be put back in force (logged as an error) and "
            f"are not answered, and an engine that had already applied the {start.action} is running."
        )
    elif not back:
        what = (
            f"This {start.action} had lifted no stop, so none was put back in force, and an engine that had "
            f"already applied it is running."
        )
    else:
        what = (
            f"Every {kind} this {start.action} had lifted is back in force and answered on every poll, but an "
            f"engine that had already applied the {start.action} is running, and while it keeps running it "
            f"rejects that old {kind} as a replay: the old {kind} stops it again only when it restarts."
        )
    return f"{what} To stop it now, sign a new {kind}."


@api_view(["POST"])
@permission_classes([IsAdminOrAnalyst])
def cancel_command(request, cmd_uuid):
    command = get_object_or_404(FailsafeCommand, uuid=cmd_uuid)
    if command.status not in (FailsafeCommand.STATUS_AWAITING, FailsafeCommand.STATUS_READY):
        return Response(
            {"detail": f"command is {command.status}; cannot cancel"},
            status=status.HTTP_409_CONFLICT,
        )
    if command.initiator_id != request.user.id and not request.user.is_admin:
        return Response(
            {"detail": "only the initiator or an admin may cancel"},
            status=status.HTTP_403_FORBIDDEN,
        )
    if command.action in STOP_ACTIONS and (command.in_force or command.status == FailsafeCommand.STATUS_READY):
        # A stop that was signed into force may be in force on its engine: a
        # cancel, which needs no operator's key, never ends it. It ended by
        # one before, for any engine that restarted.
        only = LIFTED_ONLY_BY.get(command.action)
        if not command.in_force and command.lifted_at is not None:
            # A start already lifted it: it is ready only until its window
            # passes, it is not in force and not answered. Telling the
            # operator to sign the start that was already signed would be wrong.
            by = f"the {only} {command.lifted_by}" if command.lifted_by else f"a {only} this row does not name"
            return Response(
                {"detail": (
                    f"this {command.action} was signed into force and was lifted by {by} at "
                    f"{command.lifted_at.isoformat()}: it is no longer in force and no longer answered, so "
                    f"nothing is left to cancel."
                )},
                status=status.HTTP_409_CONFLICT,
            )
        how = (
            f"Sign a {only} drafted after it: only that ends it."
            if only
            else "Nothing ends a terminate: neither a resume nor a release does."
        )
        return Response(
            {"detail": f"this {command.action} was signed into force, and a cancel never ends a stop in force. {how}"},
            status=status.HTTP_409_CONFLICT,
        )
    if command.action not in START_ACTIONS:
        command.mark_canceled()
        _audit(command, FailsafeAuditEvent.EVENT_CANCELED, request)
        return Response(_console_row(command))
    # Cancelling a start keeps an engine stopped (safety.stops): the cancel is
    # written first, as it was; then the stops that start had lifted, if it
    # had been made ready, are put back in force; and its audit row never
    # fails it.
    was_ready = command.status == FailsafeCommand.STATUS_READY
    command.mark_canceled()
    put_back = _put_back_in_force(command) if was_ready else []
    back = None if put_back is None else [stop_uuid for _pk, stop_uuid in put_back]
    # Each stop put back has the event on its own audit trail (the row's
    # primary key, already read: no statement more), naming the cancelled
    # start and why.
    missed = _audit_a_stop([
        _event(command, FailsafeAuditEvent.EVENT_CANCELED, request,
               **({"back_in_force": back} if back else {}),
               **({"back_in_force_failed": True} if back is None else {})),
        *[
            _event(pk, FailsafeAuditEvent.EVENT_IN_FORCE, request, stop=stop_uuid,
                   why=f"the {command.action} {command.uuid} that lifted it was cancelled")
            for pk, stop_uuid in put_back or []
        ],
    ])
    body = _console_row(command)
    if was_ready:
        body["back_in_force"] = back
        body["back_in_force_note"] = _back_in_force_note(command, back)
    response = _saying(Response(body), missed)
    if was_ready:
        response[BACK_IN_FORCE_HEADER] = "unknown" if back is None else str(len(back))
    return response


#: At most this many reads of the engine's live state run at once. A read the
#: state view stopped waiting for can still be running; one that finds every
#: slot taken is "not reported" at once.
_LIVE_STATE_SLOTS = threading.BoundedSemaphore(4)


def _ask_engine_for_state(deadline):
    """The engine's failsafe state payload, or None: waited for ``deadline``
    seconds in all, however slowly the engine answers.

    The state view is a stop-lane read (safety.stops): the dashboard's second
    operator finds the command awaiting their signature in it. Its commands
    are read from the database; only this part asks the engine, whose client
    allows 60 s a socket read. So the call runs on a thread of its own and the
    view waits for it only until the deadline, as the gateway does."""
    if not _LIVE_STATE_SLOTS.acquire(blocking=False):
        return None
    outcome = {}
    done = threading.Event()

    def call():
        try:
            from ai_engine.services.cyberengine_client import CyberEngineClient

            outcome["payload"] = CyberEngineClient.from_settings().failsafe_state()
        except Exception as exc:  # noqa: BLE001 - any failure to reach the engine is "not reported"
            outcome["error"] = exc.__class__.__name__
        finally:
            _LIVE_STATE_SLOTS.release()
            done.set()

    try:
        threading.Thread(target=call, name="failsafe-live-state", daemon=True).start()
    except RuntimeError:
        _LIVE_STATE_SLOTS.release()
        return None
    if not done.wait(deadline):
        return None
    return outcome.get("payload")


def _engine_live_state():
    """The engine's own governor state, proxied from the engine itself.

    Any failure -- no engine configured, unreachable, an error, no answer
    within FAILSAFE_STATE_ENGINE_SECONDS, or a failsafe that is disabled there
    -- is reported as "not available" rather than guessed. The console must
    show the truth (a state, or "not reported"), never a green light nobody
    checked, and the engine being down must not turn the control plane's own
    state view into a 500. Returns (state, available)."""
    try:
        deadline = max(0.0, float(getattr(settings, "FAILSAFE_STATE_ENGINE_SECONDS", 2.0)))
    except (TypeError, ValueError):
        deadline = 2.0
    payload = _ask_engine_for_state(deadline)
    if not isinstance(payload, dict) or not payload.get("enabled"):
        # enabled=false means the engine has no failsafe -- "not reported",
        # which a caller must not read as "running".
        return None, False
    value = payload.get("state")
    return (value, True) if isinstance(value, str) else (None, False)


@api_view(["GET"])
@permission_classes([IsAdminOrAnalyst])
def state(request):
    """A control-plane view of failsafe activity for an engine: commands in
    flight, the last ready/consumed one, and the engine's live governor state
    proxied from the engine itself (running/paused/stood-down/terminated), or
    "not reported" when the engine cannot be reached.

    A stop-lane read (safety.stops): no gateway or throttle holds it back, so
    its work is bounded by its row and byte limits and not by the number of
    commands. The stop commands awaiting a signature come first, at most
    AWAITING_STOP_LIMIT and never cut by the row cap (_awaiting_stops); every
    other list is an index read of its next few rows, the ready stops before
    the ready starts (_Read); the rows come to at most stop_lane_read_bytes(),
    in that order (_Page); ``more`` (and the X-Failsafe-More header) says
    whether an awaiting or ready command was left out by either limit, and
    ``next`` (and X-Failsafe-Next) the cursor that reads the next page --
    ``recent`` is the newest ten, on the first page only, and is not counted;
    commands found past their window are marked expired in one write, at most
    EXPIRE_PER_READ of them (_Expiry) -- a read never walks every command to
    expire it; and the engine is waited for FAILSAFE_STATE_ENGINE_SECONDS at
    most. Identical reads by one account at once share one computation at a
    time (_SharedReads), never one that started before they arrived. With the
    service token it shows the stop commands in flight and the engine's state:
    no resume or release, and no history."""
    try:
        read = _Read(request, "state")
    except _BadCursor as exc:
        return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
    commands_, too_large, unreadable = _SHARED_READS.read(
        _read_kind(request, "state"), lambda: _in_flight(request, read)
    )
    engine_state, engine_state_available = _engine_live_state()
    # This process's count of stop audit rows it could not write, always, and
    # since when it counts: the count is in memory, so after a restart "0"
    # means none since the restart, and the header says when that was (D6).
    missed = AUDIT_ROWS_MISSED
    return Response(
        {
            "engine_id": request.query_params.get("engine_id"),
            "engine_state": engine_state,
            "engine_state_available": engine_state_available,
            **commands_,
        },
        headers={
            **_page_headers(commands_["more"], commands_["next"], too_large, unreadable),
            AUDIT_MISSED_HEADER: str(missed.value),
            AUDIT_MISSED_SINCE_HEADER: missed.since.isoformat(),
        },
    )


def _in_flight(request, read):
    """The state view's commands: in flight, and on the first page the most
    recent; and a command too large for any page."""
    expiry = _Expiry()
    page = _Page()
    lanes, following = read.page(expiry, page)
    recent = []
    if read.after is None and not read.by_token:
        recent, _history = _newest(read.qs, [{}], RECENT_LIMIT, expiry, in_flight_only=False)
    expiry.mark()
    _supersede_listed_starts(lanes.get("r", []))
    # ``recent`` is the newest few and is not counted in ``more``.
    recent = page.take(recent)
    return {
        "awaiting_signatures": [*lanes.get("s", []), *lanes.get("a", [])],
        "ready": lanes.get("r", []),
        "recent": recent,
        "more": following is not None,
        "next": following,
    }, page.too_large, len(page.unreadable)


@api_view(["GET"])
@permission_classes([IsAdminOrAnalyst])
def audit(request):
    qs = FailsafeAuditEvent.objects.all()
    cmd_uuid = request.query_params.get("command")
    if cmd_uuid:
        qs = qs.filter(command__uuid=cmd_uuid)
    return Response(FailsafeAuditEventSerializer(qs[:200], many=True).data)


def poll_token_ok(request):
    """Whether ``request`` carries the engine's poll token.

    The one check. ``pending`` serves exactly what it passes, and the stop set
    (safety.stops) exempts exactly what it passes from the gateway and the
    throttles, so a poll that is served is never throttled and a guess at the
    token is throttled like any other anonymous request."""
    expected = getattr(settings, "FAILSAFE_POLL_TOKEN", None)
    provided = request.headers.get("X-Failsafe-Poll-Token")
    if not expected or provided is None:
        return False
    # Two digests of one length, compared in constant time. Comparing the raw
    # strings returned early on a length mismatch, which told a guesser the
    # token's length.
    return hmac.compare_digest(_poll_digest(provided), _poll_digest(expected))


#: A per-process key for the poll token's digests: it only has to make the two
#: sides the same length, so it never needs to be shared or kept.
_POLL_DIGEST_KEY = secrets.token_bytes(32)


def _poll_digest(value):
    return hmac.new(
        _POLL_DIGEST_KEY, str(value).encode("utf-8", "surrogatepass"), hashlib.sha256
    ).digest()


@api_view(["GET"])
@permission_classes([AllowAny])  # engine poll, authenticated by a shared poll token
# No JWT authentication either: the engine sends none, and a stale bearer header
# on its request was answered 401 before this view ran, holding back every
# command it polls for.
@authentication_classes([])
def pending(request):
    """The endpoint the engine polls (its control_url). Returns fully-signed,
    unexpired commands as mythos_core.failsafe.Command documents. Authenticated
    by a dedicated poll token, NOT an operator JWT -- the engine is not an
    operator. Re-serving is safe: the engine's nonce ledger applies each command
    at most once.

    A poll with the token is a stop (safety.stops): no throttle refuses or
    counts it. One without it is answered 401 and stays under the anonymous
    throttle, so the token cannot be guessed at speed.

    Its work is bounded, and the stops come first (_PollRead). The answer is
    the same JSON list of command documents as ever: every ready stop --
    terminate, then stand-down, then pause -- before any start, then at most
    POLL_START_LIMIT resumes and releases, newest first, in at most
    POLL_READ_BYTES. It walked every ready command of the engine before,
    newest first, so 10,000 ready resumes put a stand-down 10,000th, behind
    1.7 MB; and past the engine's 5 MiB read limit the engine cuts the body,
    cannot decode it, and drops every command in it, the stops with them.
    A start drafted at or before a ready or consumed stop of its engine is
    never delivered, and is marked superseded (_PollRead).
    X-Failsafe-More says whether anything was left out, and X-Failsafe-Next
    which ``cursor`` reads the rest (the engine's client reads the first page
    only, and every first page carries the stops). Commands past their window
    are passed over and marked expired, at most EXPIRE_PER_READ in one write
    that never fails the poll (_Expiry): it wrote each one, one by one.

    A stop in force is answered on every poll, however old (AB-STOP-STAYS-
    SERVED). A stop past its window was passed over, so ten minutes after a
    pause, a stand-down or a terminate was signed the poll answered ``[]``:
    an engine that restarted then, or a second engine with the same id, was
    told nothing. A stop made ready is in force until a later signed start
    lifts it -- a resume lifts a pause, a release a stand-down, nothing a
    terminate -- and while it is, it stays ready and is never past its
    window. It is answered as the row stores it: the nonce, times, reason and
    signatures the operators signed, which the engine verifies as ever. The
    engine applies a pause or a stand-down whatever its window, and rejects
    one it already applied as a replay; it applies a terminate only inside
    its window, so X-Failsafe-In-Force names the kinds in force in the answer
    ("terminate" among them) for the engine to hold on. A stop a later signed
    start has lifted is no longer answered, inside its window or out: the
    start is answered in its place (_PollRead.page).

    A row that cannot be read or turned into a command is left out and
    counted in X-Failsafe-Unreadable; every readable command is answered. It
    answered the whole poll 500, and the engine reads that as nothing
    pending. A poll whose lanes cannot be read at all is still not answered
    200.

    None of this adds a statement to the poll: the same index reads, the
    same row read, and no write for a stop in force."""
    if not poll_token_ok(request):
        return Response({"detail": "poll token required"}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        read = _PollRead(request)
    except _BadCursor as exc:
        return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
    expiry = _Expiry()
    page = _Page(POLL_READ_BYTES, FailsafeCommand.as_command_dict, names_unreadable=False)
    lanes, following = read.page(expiry, page)
    # The poll's only write, after its answer is built, and only when it
    # came across commands past their window: never waiting for the
    # database's write lock (a stop drafted or signed at the same moment
    # holds it). Refused at once, it is logged and the next poll tries again;
    # it never changes what the answer delivers. Held starts are NOT marked
    # here: the poll only reads, and the state read marks them (_supersede).
    with _not_waiting_for_the_write_lock():
        expiry.mark()
    out = [*lanes.get("p", []), *lanes.get("q", [])]
    headers = _page_headers(following is not None, following, page.too_large, len(page.unreadable))
    in_force = [action for action in POLL_STOP_ORDER if action in read.in_force]
    if in_force:
        headers[IN_FORCE_HEADER] = ", ".join(in_force)
    if page.unreadable:
        logger.error(
            "the engine poll left out %d command rows it could not read: %s",
            len(page.unreadable),
            ", ".join(
                f"{row['action']} {row['uuid']} of {row['engine_id']!r}" for row in list(page.unreadable.values())[:20]
            ),
        )
    return Response(out, headers=headers)


@contextmanager
def _not_waiting_for_the_write_lock():
    """Writes in this block are refused at once, never queued, when another
    connection holds the database's write lock (SQLite: busy_timeout 0 for
    the block, then put back as it was). Other databases: unchanged. A
    failure to set or put it back is logged and changes nothing else.

    Inside a block of its own on the same connection (the poll's expiry,
    _Expiry.mark), it does nothing more: no statement is added."""
    if getattr(connection, "_failsafe_not_waiting", False):
        yield
        return
    before = None
    if connection.vendor == "sqlite":
        try:
            with connection.cursor() as cursor:
                cursor.execute("PRAGMA busy_timeout")
                before = int(cursor.fetchone()[0])
                cursor.execute("PRAGMA busy_timeout = 0")
        except Exception:  # noqa: BLE001 - the poll is answered whatever this does
            logger.exception("could not stop the engine poll's writes waiting for the write lock")
            before = None
    connection._failsafe_not_waiting = True
    try:
        yield
    finally:
        connection._failsafe_not_waiting = False
        if before is not None:
            try:
                with connection.cursor() as cursor:
                    # The value read above, put back: an int under ":d", so this SQL
                    # is "PRAGMA busy_timeout = <digits>" and writes no table.
                    cursor.execute(f"PRAGMA busy_timeout = {before:d}")  # not-a-decision-writer: an int, put back
            except Exception:  # noqa: BLE001 - the poll is answered whatever this does
                logger.exception("could not put back the database's busy timeout after the engine poll")


#: The alias a stop's housekeeping writes are made on, beside the request's
#: own connection, while they are (_housekeeping_connection).
HOUSEKEEPING_ALIAS = "failsafe_housekeeping"


@contextmanager
def _housekeeping_connection():
    """The database alias a stop's housekeeping writes -- its audit rows -- are
    made on once the stop has committed: they never
    wait for the database's write lock, and they add no statement to the
    request's own connection (whose statements a stop's path is held to).

    * SQLite, the request's connection outside any transaction (the stop's
      own has committed): a connection of its own, opened for these writes
      with a busy timeout of 0 given at connect time -- no PRAGMA anywhere --
      and closed after them. When another connection holds the write lock
      each write is refused at once; the caller logs it, and counts and says
      a missing audit row.
    * Inside a transaction (an outer atomic block): the request's own
      connection, which already holds the write lock for what it wrote there,
      so nothing it writes can wait for it; a second connection could not
      even read the uncommitted stop.
    * Any other database: the request's connection, as before.

    If the second connection cannot be opened, the request's connection is
    used under _not_waiting_for_the_write_lock: refused at once all the same
    (logged)."""
    if connection.vendor != "sqlite" or connection.in_atomic_block:
        yield DEFAULT_DB_ALIAS
        return
    try:
        own = connections[DEFAULT_DB_ALIAS]  # the wrapper itself: ``connection`` is a proxy to it
        settings_dict = copy.deepcopy(own.settings_dict)
        options = settings_dict.setdefault("OPTIONS", {})
        options["timeout"] = 0
        if options.get("init_command"):
            # Commands configured to run at connect time run first; a busy
            # timeout among them is put back to 0, still at connect time.
            options["init_command"] = f"{options['init_command']};PRAGMA busy_timeout = 0"
        housekeeping = own.__class__(settings_dict, alias=HOUSEKEEPING_ALIAS)
        housekeeping.ensure_connection()
    except Exception:  # noqa: BLE001 - housekeeping falls back to the request's connection, never waiting
        logger.exception("could not open the failsafe housekeeping connection; writing on the request's")
        with _not_waiting_for_the_write_lock():
            yield DEFAULT_DB_ALIAS
        return
    connections[HOUSEKEEPING_ALIAS] = housekeeping
    try:
        yield HOUSEKEEPING_ALIAS
    finally:
        del connections[HOUSEKEEPING_ALIAS]
        try:
            housekeeping.close()
        except Exception:  # noqa: BLE001 - the stop is answered whatever this does
            logger.exception("could not close the failsafe housekeeping connection")


#: The stop actions in the order the engine's poll answers them: the strongest
#: first, so a page cut by its limits still carries the strongest stop asked
#: for. Any order of stops leaves an engine in the strongest of them (a pause
#: does nothing to an engine stood down, and nothing follows a terminate).
POLL_STOP_ORDER = ("terminate", "stand_down", "pause")
#: The most ready stops one poll answers. Each is signed by an enrolled
#: operator's key -- a draft flood makes none -- so this is far past any real
#: number; past it the poll says more and answers the rest on its next page.
POLL_STOP_LIMIT = AWAITING_STOP_LIMIT
#: The most ready resumes and releases one poll answers, after every stop. A
#: start needs an operator's signature too, and an engine has one or two in a
#: window; 50 (the list's page) covers any real number, keeps the work and the
#: bytes of a poll the same under a flood of them, and keeps what the engine
#: verifies and applies after the stops to at most 50 commands.
POLL_START_LIMIT = COMMAND_LIST_LIMIT
#: The most bytes of commands one poll answers. The engine reads at most
#: 5 MiB of an answer (mythos_core.http.safe_http.MAX_RESPONSE_BYTES, by
#: default) and decodes nothing of one it had to cut: every stop in it is lost.
POLL_READ_BYTES = 4_000_000
#: The value a start is held back by when its engine's mark cannot be read:
#: every start of that engine, on that poll (fail closed, for starts only).
_UNREADABLE = object()


def _mark_stop_made_ready(command):
    """Move ``command``'s engine's FailsafeStopMark forward to it, when it is a
    stop newer than the mark, and say when a stop was last made ready for the
    engine (``last_ready_at``), whichever stop that was: inside the
    transaction that signs it into force, ONE UPDATE by the primary key, and
    an INSERT the first time. It was a conditional UPDATE, a read of whether
    the mark existed when that moved nothing, and the INSERT: never more
    statements now than then. In a savepoint, and never raised: a failure is
    logged and the signature stands; the poll still holds back older starts
    by the ready stop itself while it is ready -- and a stop in force stays
    ready."""
    if command.action not in STOP_ACTIONS:
        return
    try:
        with transaction.atomic():
            fields = {"created_at": command.created_at, "stop_uuid": command.uuid, "action": command.action}
            newer = Q(created_at__lt=command.created_at)
            types = {"created_at": DateTimeField(), "stop_uuid": UUIDField(), "action": CharField()}
            said = {} if command.ready_at is None else {"last_ready_at": command.ready_at}
            moved = FailsafeStopMark.objects.filter(engine_id=command.engine_id).update(
                updated_at=timezone.now(),
                **said,
                **{
                    name: Case(When(newer, then=Value(value, output_field=types[name])), default=F(name))
                    for name, value in fields.items()
                },
            )
            if not moved:
                FailsafeStopMark.objects.create(engine_id=command.engine_id, **fields, **said)
    except Exception:  # noqa: BLE001 - a stop's signature must never fail on its mark
        logger.exception("could not move the stop mark of engine %r to %s", command.engine_id, command.uuid)


def _stop_marks(engines):
    """{engine_id: (created_at, stop uuid, action, last_ready_at)} of the marks
    of ``engines``: one read of their rows by the primary key. _UNREADABLE
    when the read fails."""
    try:
        return {
            mark.engine_id: (mark.created_at, str(mark.stop_uuid), mark.action, mark.last_ready_at)
            for mark in FailsafeStopMark.objects.filter(engine_id__in=sorted(engines))
        }
    except Exception:  # noqa: BLE001 - an unreadable mark holds every start back, never a stop
        logger.exception("could not read the stop marks of %d engines", len(engines))
        return _UNREADABLE


def _supersede(held):
    """Mark the starts ``held`` ({pk: (stop uuid, stop action, True when it is
    held for when it was made ready, not for when it was drafted)})
    superseded, each with an audit event naming the stop it was drafted or
    made ready before: one
    UPDATE of at most EXPIRE_PER_READ rows still ready, one read of the rows
    that write changed (its own ``updated_at``, so two reads at once never
    record one twice), and one insert, in one transaction that never waits
    for the write lock. A failure is logged, never raised."""
    held = dict(list(held.items())[:EXPIRE_PER_READ])
    if not held:
        return
    try:
        now = timezone.now()
        with _not_waiting_for_the_write_lock(), transaction.atomic():
            changed = FailsafeCommand.objects.filter(pk__in=list(held), status=_READY).update(
                status=FailsafeCommand.STATUS_SUPERSEDED, updated_at=now
            )
            if not changed:
                return
            mine = FailsafeCommand.objects.filter(
                pk__in=list(held), status=FailsafeCommand.STATUS_SUPERSEDED, updated_at=now
            ).order_by().values_list("pk", flat=True)
            FailsafeAuditEvent.objects.bulk_create([
                FailsafeAuditEvent(
                    command_id=pk,
                    event=FailsafeAuditEvent.EVENT_SUPERSEDED,
                    detail={
                        "by": "state read",
                        "superseded_by": held[pk][0],
                        "reason": (
                            f"made ready at or before a stop was made ready for its engine (its newest stop "
                            f"drafted is the {held[pk][1]} {held[pk][0]}): delivered after that stop, it would "
                            "undo it"
                            if held[pk][2]
                            else f"drafted at or before the {held[pk][1]} {held[pk][0]}, the newest stop made "
                                 "ready for its engine: delivered after it, it would undo that stop"
                        ),
                    },
                )
                for pk in mine
            ])
    except Exception:  # noqa: BLE001 - a failed write must not fail the read
        logger.warning("could not mark %d held-back failsafe starts superseded", len(held), exc_info=True)


def _supersede_listed_starts(rows):
    """The ready resumes and releases a state read listed that the newest stop
    made ready for their engine (its mark) was drafted at or after, or that
    were made ready at or before a stop was last made ready for it:
    superseded (_supersede). Only by a mark: a start of an engine with none is
    held back by the poll but never marked. At most STATE_LIST_LIMIT rows, by
    their uuid, then their engines' marks by the primary key."""
    uuids = [
        row["uuid"]
        for row in rows
        if row.get("action") in START_ACTIONS and row.get("status") == _READY and not row.get("unreadable")
    ]
    if not uuids:
        return
    try:
        starts = list(FailsafeCommand.objects.filter(uuid__in=uuids).order_by().values_list(
            "pk", "engine_id", "created_at", "ready_at"))
    except Exception:  # noqa: BLE001 - nothing here may fail the read
        logger.exception("could not read %d listed starts", len(uuids))
        return
    marks = _stop_marks({engine_id for _pk, engine_id, _created, _ready in starts})
    if marks is _UNREADABLE:
        return
    held = {}
    for pk, engine_id, created, ready in starts:
        if engine_id not in marks:
            continue
        drafted, stop_uuid, action, last_ready = marks[engine_id]
        if created <= drafted:
            held[pk] = (stop_uuid, action, False)
        elif ready is not None and last_ready is not None and ready <= last_ready:
            held[pk] = (stop_uuid, action, True)
    _supersede(held)


class _PollRead(_Read):
    """The engine's poll (pending): a keyset read in two lanes, as the
    console's reads are (_Read, _lane_keys).

    * ``p``, the ready stops: terminate, then stand-down, then pause (tiers),
      each newest first, at most POLL_STOP_LIMIT a page. Every first page --
      every poll the engine's client makes -- starts with them.
    * ``q``, the ready starts, resumes and releases, newest first, at most
      POLL_START_LIMIT a page, and only on a page that left no stop for the
      next: when the stops are cut, by their row limit or the bytes, the
      starts wait for the stops' last page. A page after the first reads only
      the lanes its cursor continues; a reader that follows them polls the
      first page again for any stop made ready since.

    A start drafted at or before the newest stop ever made ready for its
    engine is never delivered. That stop is the engine's FailsafeStopMark
    (moved forward in the transaction that signs a stop into force, and kept
    after the stop's window), or a ready stop on this page if newer. The
    engine applies an answer in its order, so a resume or release older than
    a stop, answered after it, would undo the stop that came after it: a
    release signed, then a stand-down, both first heard in one poll, left
    the engine running; and held back only while the stop was READY, it was
    delivered once the stop was not. The poll reads one mark row per engine
    on its page, by the primary key: its work does not grow with the starts
    or with the history of stops. An engine with no mark, or whose mark
    cannot be read, has every start held back (fail closed, for starts only:
    no stop is ever held). The poll writes nothing for it; the state read
    marks such starts superseded (_supersede_listed_starts). A start drafted
    after the stop is answered.

    Each part is one index read of at most its limit + 1 keys
    (fsc_st_act_ct, fsc_eng_st_act_ct): the work is the limits, whatever the
    number of ready commands."""

    def __init__(self, request):
        self.view = "pending"
        self.by_token = False
        engine_id = request.query_params.get("engine_id") or ""
        self.qs = FailsafeCommand.objects.filter(status=_READY)
        if engine_id:
            self.qs = self.qs.filter(engine_id=engine_id)
        self.lanes = [
            ("p", [[{"action": action}] for action in POLL_STOP_ORDER], POLL_STOP_LIMIT),
            ("q", [[{"action": action} for action in START_ACTIONS]], POLL_START_LIMIT),
        ]
        self.binding = hashlib.sha256(json.dumps(["pending", engine_id]).encode("utf-8")).hexdigest()[:16]
        self.after = self._cursor(request.query_params.get(CURSOR_PARAM) or "")
        #: The starts this read held back (pks).
        self.held = set()
        #: The kinds of stop in force this page answered.
        self.in_force = set()

    @staticmethod
    def _held(start, marks, ready_stops, made_ready=None):
        """Whether ``start`` is held back: its engine's mark is missing or
        unreadable; or the newer of its mark and the newest ready stop of its
        engine on this page was drafted at or after it; or a stop was made
        ready for its engine -- by its mark, or by a ready stop on this page
        -- at or after the start was made ready.

        The last is the order the two were SIGNED in. A stand-down drafted
        first and signed last, beside a release drafted after it and signed
        before it, was answered stand-down then release: the engine ended
        running, with a stand-down the operators had just signed. A start or
        a stop with no ``ready_at`` (made ready before migration 0006 and not
        backfilled) is judged by its drafting time alone, as before."""
        if marks is _UNREADABLE or start.engine_id not in marks:
            return True
        newest, _uuid, _action, last = marks[start.engine_id]
        ready = ready_stops.get(start.engine_id)
        if ready is not None and ready > newest:
            newest = ready
        if start.created_at <= newest:
            return True
        on_page = (made_ready or {}).get(start.engine_id)
        if on_page is not None and (last is None or on_page > last):
            last = on_page
        return start.ready_at is not None and last is not None and start.ready_at <= last

    def page(self, expiry, page):
        """This page's rows by lane, and the next page's cursor or None. No
        start is on a page that left a stop for the next one: the starts wait
        for the stops' last page."""
        rows, continuing, ready_stops, made_ready = {}, {}, {}, {}
        for name, tiers, limit in self.lanes:
            if self.after is not None and name not in self.after:
                continue  # a lane a page before this one finished
            after = None if self.after is None else self.after[name]
            if name == "q" and "p" in continuing:
                continuing[name] = after
                continue
            entries, more = _lane(self.qs, tiers, limit, after, expiry)
            if name == "p":
                for key, command in entries:
                    # A ready stop whose row cannot even be loaded is named in
                    # force by the action of the tier its key was read under
                    # (each tier of this lane is one action): it may be in
                    # force, it is not served, and X-Failsafe-In-Force is the
                    # one place its engine is told of it. It was counted in
                    # X-Failsafe-Unreadable and named nowhere, so a terminate
                    # in force whose row could not be loaded left the list of
                    # stops short. Unreadable is caution: never a shorter list.
                    if isinstance(command, _Unreadable):
                        self.in_force.add(tiers[key[0]][0]["action"])
                    # A ready stop whose row cannot be read still holds back
                    # the starts drafted before it, where its engine and its
                    # creation time could be read.
                    if command is None or command.engine_id is None or command.created_at is None:
                        continue
                    seen = ready_stops.get(command.engine_id)
                    if seen is None or command.created_at > seen:
                        ready_stops[command.engine_id] = command.created_at
                    seen = made_ready.get(command.engine_id)
                    if command.ready_at is not None and (seen is None or command.ready_at > seen):
                        made_ready[command.engine_id] = command.ready_at
                    if command.in_force:
                        self.in_force.add(command.action)
                # A stop a later signed start has lifted is not answered, even
                # inside its window: the start is answered in its place. With
                # the lifted stop answered first, a stand-down that a release
                # had lifted swallowed a pause still in force (an engine stood
                # down ignores a pause) and the release then left the engine
                # running. Without it the engine ends in the stop in force.
                entries = [
                    (key, None if command is not None and command.lifted_at is not None and not command.in_force
                     else command)
                    for key, command in entries
                ]
            if name == "q":
                starts = [
                    command for _key, command in entries if command is not None and not isinstance(command, _Unreadable)
                ]
                marks = _stop_marks({command.engine_id for command in starts}) if starts else {}
                self.held = {
                    command.pk for command in starts if self._held(command, marks, ready_stops, made_ready)
                }
                entries = [(key, None if command is not None and command.pk in self.held else command)
                           for key, command in entries]
            rows[name], last, passed = page.take_lane(entries)
            if more or not passed:
                continuing[name] = after if last is None else last
        return rows, (self.encode(continuing) if continuing else None)
