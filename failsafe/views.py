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
import hashlib
import hmac
import itertools
import json
import logging
import re
import secrets
import threading

from django.conf import settings
from django.db import transaction
from django.db.models import Max
from django.http import Http404
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from accounts.permissions import IsAdminOrAnalyst

from .models import FailsafeAuditEvent, FailsafeCommand
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
    fails is logged, and the read is answered."""

    def __init__(self):
        self.now = timezone.now()
        self.pks = {}  # an ordered set: one row can be in more than one list

    def due(self, pk, status_, expires_at):
        if status_ in _IN_FLIGHT and _due(expires_at, self.now):
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
                    FailsafeCommand.objects.filter(status__in=_IN_FLIGHT, expires_at__lt=self.now.isoformat())
                    .exclude(pk__in=list(self.pks))
                    .order_by()
                    .values_list("pk", "expires_at")[:room]
                )
                self.pks.update((pk, None) for pk, end in candidates if _due(end, self.now))
            if not self.pks:
                return
            with transaction.atomic():
                FailsafeCommand.objects.filter(pk__in=list(self.pks), status__in=_IN_FLIGHT).update(
                    status=FailsafeCommand.STATUS_EXPIRED, updated_at=self.now
                )
        except Exception:  # noqa: BLE001 - a failed read or write must not fail a stop-lane read
            logger.exception("could not mark %d failsafe commands expired", len(self.pks))


def _fetch(pks):
    """The commands with these primary keys, in this order: one read."""
    rows = FailsafeCommand.objects.order_by().in_bulk(pks)
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
        if expiry.due(command.pk, command.status, command.expires_at):
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
    too."""
    keys = _lane_keys(qs, tiers, limit, after)
    more = len(keys) > limit
    keys = keys[:limit]
    rows = {command.pk: command for command in _fetch([pk for _tier, _created, pk in keys])}
    entries = []
    for key in keys:
        command = rows.get(key[2])
        if command is not None and expiry.due(command.pk, command.status, command.expires_at):
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

    def __init__(self, whole=None, row=None):
        self.whole = self.left = stop_lane_read_bytes() if whole is None else whole
        #: A command as this page lists it (take_lane): the console's row, or
        #: the engine's command document (pending).
        self._row = row or (lambda command: FailsafeCommandSerializer(command).data)
        self.more = False
        #: The uuid of a command passed over because it alone is larger than a
        #: whole page (take_lane), or None.
        self.too_large = None

    def cut(self, more):
        self.more = self.more or bool(more)

    @staticmethod
    def _size(row):
        return len(json.dumps(row, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")) + 1

    def take(self, commands):
        out = []
        if self.left <= 0:
            self.more = self.more or bool(commands)
            return out
        for row in FailsafeCommandSerializer(commands, many=True).data:
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
            row = self._row(command)
            size = self._size(row)
            if size > self.whole:
                self.too_large, self.left, self.more = str(command.uuid), 0, True
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


def _audit(command, event, request, **detail):
    FailsafeAuditEvent.objects.create(
        command=command,
        event=event,
        actor=request.user if request.user.is_authenticated else None,
        detail={**getattr(request, "audit_metadata", {}), **detail},
    )


def _expire_if_due(command, now=None):
    """Lazily flip a past-its-window command to expired. Returns True if expired."""
    now = now or timezone.now()
    if command.status in _IN_FLIGHT and _due(command.expires_at, now):
        command.mark_expired()
        return True
    return False


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
        rows, more, following, too_large = _SHARED_READS.read(
            _read_kind(request, "commands"), lambda: _list(request, read)
        )
        return Response(rows, headers=_page_headers(more, following, too_large))

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
    a draft flood).

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
    FailsafeAuditEvent.objects.bulk_create(events)
    return _drafted(command, command.as_command_dict(), status.HTTP_201_CREATED)


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
    A failure here is logged; the new draft stands."""
    limit = unsigned_stop_drafts_per_account()
    try:
        pks = [
            pk
            for pk in FailsafeCommand.objects.filter(
                initiator=newest.initiator_id, status=_AWAITING, signed=False, action__in=STOP_ACTIONS
            )
            .order_by("-created_at")
            .values_list("pk", flat=True)[limit : limit + SUPERSEDE_PER_DRAFT]
            if pk != newest.pk
        ]
        if not pks:
            return []
        now = timezone.now()
        FailsafeCommand.objects.filter(pk__in=pks, status=_AWAITING, signed=False).update(
            status=FailsafeCommand.STATUS_SUPERSEDED, updated_at=now
        )
        return list(
            FailsafeCommand.objects.filter(pk__in=pks, status=FailsafeCommand.STATUS_SUPERSEDED, updated_at=now)
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
    return rows, following is not None, following, page.too_large


def _page_headers(more, following, too_large):
    return {
        MORE_HEADER: "true" if more else "false",
        **({NEXT_HEADER: following} if following else {}),
        **({TOO_LARGE_HEADER: too_large} if too_large else {}),
    }


@api_view(["GET"])
@permission_classes([IsAdminOrAnalyst])
def command_detail(request, cmd_uuid):
    command = get_object_or_404(FailsafeCommand, uuid=cmd_uuid)
    _expire_if_due(command)
    if _by_service_token(request) and (command.action not in STOP_ACTIONS or command.status not in _IN_FLIGHT):
        # The service token reads a stop command in flight and its signing
        # bytes; nothing else, and no resume's or release's bytes.
        raise Http404
    body = FailsafeCommandSerializer(command).data
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
    _expire_if_due(command)
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
        _audit(command, FailsafeAuditEvent.EVENT_SIGNED, request, key_id=key_id,
               **({"revived": True} if revived else {}))

        valid = distinct_valid_signers(command.as_command_dict(), command.signatures, keyring)
        if len(valid) >= command.required_signatures:
            command.mark_ready()
            _audit(command, FailsafeAuditEvent.EVENT_READY, request,
                   signers=sorted(valid))

    return Response(FailsafeCommandSerializer(command).data)


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
    command.mark_canceled()
    _audit(command, FailsafeAuditEvent.EVENT_CANCELED, request)
    return Response(FailsafeCommandSerializer(command).data)


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
    commands_, too_large = _SHARED_READS.read(_read_kind(request, "state"), lambda: _in_flight(request, read))
    engine_state, engine_state_available = _engine_live_state()
    return Response(
        {
            "engine_id": request.query_params.get("engine_id"),
            "engine_state": engine_state,
            "engine_state_available": engine_state_available,
            **commands_,
        },
        headers=_page_headers(commands_["more"], commands_["next"], too_large),
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
    # ``recent`` is the newest few and is not counted in ``more``.
    recent = page.take(recent)
    return {
        "awaiting_signatures": [*lanes.get("s", []), *lanes.get("a", [])],
        "ready": lanes.get("r", []),
        "recent": recent,
        "more": following is not None,
        "next": following,
    }, page.too_large


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
    X-Failsafe-More says whether anything was left out, and X-Failsafe-Next
    which ``cursor`` reads the rest (the engine's client reads the first page
    only, and every first page carries the stops). Commands past their window
    are passed over and marked expired, at most EXPIRE_PER_READ in one write
    that never fails the poll (_Expiry): it wrote each one, one by one."""
    if not poll_token_ok(request):
        return Response({"detail": "poll token required"}, status=status.HTTP_401_UNAUTHORIZED)

    try:
        read = _PollRead(request)
    except _BadCursor as exc:
        return Response({"detail": str(exc)}, status=status.HTTP_400_BAD_REQUEST)
    expiry = _Expiry()
    page = _Page(POLL_READ_BYTES, FailsafeCommand.as_command_dict)
    lanes, following = read.page(expiry, page)
    expiry.mark()
    out = [*lanes.get("p", []), *lanes.get("q", [])]
    return Response(out, headers=_page_headers(following is not None, following, page.too_large))


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

    A start is held back while a NEWER stop of its engine is ready (drafted at
    or after it). The engine applies an answer in its order, so a resume or
    release older than a stop, answered after it, would undo the stop that
    came after it: a release signed, then a stand-down, both first heard in
    one poll, left the engine running. It has nothing to undo while that stop
    is ready, and a start drafted after the stop is answered. A start is
    never a stop, so holding one back never holds back a stop.

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

    def _newest_stops(self, engines):
        """The creation time of the newest ready stop of each of ``engines``:
        one grouped read of their ready stops, by the index on (engine,
        status, action, creation time)."""
        rows = (
            FailsafeCommand.objects.filter(status=_READY, action__in=STOP_ACTIONS, engine_id__in=sorted(engines))
            .order_by()
            .values("engine_id")
            .annotate(newest=Max("created_at"))
        )
        return {row["engine_id"]: row["newest"] for row in rows}

    def page(self, expiry, page):
        """This page's rows by lane, and the next page's cursor or None. No
        start is on a page that left a stop for the next one: the starts wait
        for the stops' last page."""
        rows, continuing = {}, {}
        for name, tiers, limit in self.lanes:
            if self.after is not None and name not in self.after:
                continue  # a lane a page before this one finished
            after = None if self.after is None else self.after[name]
            if name == "q" and "p" in continuing:
                continuing[name] = after
                continue
            entries, more = _lane(self.qs, tiers, limit, after, expiry)
            if name == "q":
                engines = {command.engine_id for _key, command in entries if command is not None}
                newest = self._newest_stops(engines) if engines else {}
                entries = [
                    (key, None if command is not None and command.engine_id in newest
                     and command.created_at <= newest[command.engine_id] else command)
                    for key, command in entries
                ]
            rows[name], last, passed = page.take_lane(entries)
            if more or not passed:
                continuing[name] = after if last is None else last
        return rows, (self.encode(continuing) if continuing else None)
