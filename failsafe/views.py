"""The failsafe control plane.

Operators draft a command, sign it out of band, and submit signatures; when
enough distinct operators have signed, the command is `ready` and the engine
polls `/pending` for it. Guard (a) still holds: this plane holds no private key
and cannot itself make an engine act -- it relays operator-signed commands the
engine independently verifies. Guard (b): two distinct operator signatures are
required for stand-down and terminate.
"""

from __future__ import annotations

import hashlib
import hmac
import itertools
import json
import logging
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

#: The most commands one list read returns besides the stops awaiting a
#: signature. It was 100.
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
_IN_FLIGHT = (_AWAITING, _READY)
_STATUSES = tuple(value for value, _label in FailsafeCommand.STATUS_CHOICES)


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
                candidates = (
                    FailsafeCommand.objects.filter(status__in=_IN_FLIGHT, expires_at__lt=self.now.isoformat())
                    .exclude(pk__in=list(self.pks))
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


def _parts(statuses, actions):
    """Filters covering ``statuses`` x ``actions``, each served by an index in
    creation order (see FailsafeCommand.Meta.indexes)."""
    parts = []
    for state in statuses:
        if actions is None and state != _AWAITING:
            parts.append({"status": state})
            continue
        for action in actions or (*STOP_ACTIONS, *START_ACTIONS):
            if state == _AWAITING:
                parts += [{"status": state, "action": action, "signed": signed} for signed in (True, False)]
            else:
                parts.append({"status": state, "action": action})
    return parts


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

    def __init__(self):
        self.left = stop_lane_read_bytes()
        self.more = False

    def cut(self, more):
        self.more = self.more or bool(more)

    def take(self, commands):
        out = []
        if self.left <= 0:
            self.more = self.more or bool(commands)
            return out
        for row in FailsafeCommandSerializer(commands, many=True).data:
            size = len(json.dumps(row, ensure_ascii=False, separators=(",", ":"), default=str).encode("utf-8")) + 1
            if size > self.left:
                self.left = 0
                self.more = True
                break
            self.left -= size
            out.append(row)
        return out


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
    0.33 s instead of 0.05 s)."""
    params = request.query_params
    engine_id = params.get("engine_id") or ""
    status_ = ""
    if view == "commands":
        status_ = params.get("status") or ""
        if status_ and status_ not in _STATUSES:
            status_ = "(none)"  # every status the view does not know reads the same: no rows
    return (view, request.user.pk, _by_service_token(request), engine_id, status_)


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
        # one. X-Failsafe-More says whether anything was left out.
        rows, more = _SHARED_READS.read(_read_kind(request, "commands"), lambda: _list(request))
        return Response(rows, headers={MORE_HEADER: "true" if more else "false"})

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


def _list(request):
    """The list read: (rows, more)."""
    qs = FailsafeCommand.objects.all()
    engine_id = request.query_params.get("engine_id")
    state_ = request.query_params.get("status")
    if engine_id:
        qs = qs.filter(engine_id=engine_id)
    statuses = _STATUSES if not state_ else tuple(s for s in _STATUSES if s == state_)
    expiry = _Expiry()
    stops, stops_more = _awaiting_stops(qs, expiry) if _AWAITING in statuses else ([], False)
    if _by_service_token(request):
        # The service token reads the stop commands in flight, nothing else.
        rest, rest_more = _newest(qs, _parts([s for s in statuses if s == _READY], STOP_ACTIONS),
                                  AWAITING_STOP_LIMIT, expiry, in_flight_only=True)
    else:
        rest, rest_more = _newest(qs, _rest_parts(statuses), COMMAND_LIST_LIMIT, expiry, in_flight_only=False)
    expiry.mark()
    page = _Page()
    page.cut(stops_more or rest_more)
    rows = page.take([*stops, *rest])
    return rows, page.more


def _rest_parts(statuses):
    """Every command of ``statuses`` except the stop commands awaiting a
    signature, which _awaiting_stops reads."""
    parts = _parts([s for s in statuses if s != _AWAITING], None)
    if _AWAITING in statuses:
        parts += _parts([_AWAITING], START_ACTIONS)
    return parts


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
    other list is an index read of its few newest rows; the rows come to at
    most stop_lane_read_bytes(), in that order (_Page); ``more`` (and the
    X-Failsafe-More header) says whether an awaiting or ready command was left
    out by either limit -- ``recent`` is the newest ten and is not counted;
    commands found past their window are marked expired in one write, at most
    EXPIRE_PER_READ of them (_Expiry) -- a read never walks every command to
    expire it; and the engine is waited for FAILSAFE_STATE_ENGINE_SECONDS at
    most. Identical reads by one account at once share one computation at a
    time (_SharedReads), never one that started before they arrived. With the
    service token it shows the stop commands in flight and the engine's state:
    no resume or release, and no history."""
    commands_ = _SHARED_READS.read(_read_kind(request, "state"), lambda: _in_flight(request))
    engine_state, engine_state_available = _engine_live_state()
    return Response(
        {
            "engine_id": request.query_params.get("engine_id"),
            "engine_state": engine_state,
            "engine_state_available": engine_state_available,
            **commands_,
        },
        headers={MORE_HEADER: "true" if commands_["more"] else "false"},
    )


def _in_flight(request):
    """The state view's commands: in flight, and the most recent."""
    engine_id = request.query_params.get("engine_id")
    qs = FailsafeCommand.objects.all()
    if engine_id:
        qs = qs.filter(engine_id=engine_id)
    expiry = _Expiry()
    awaiting, more = _awaiting_stops(qs, expiry)
    if _by_service_token(request):
        ready, ready_more = _newest(qs, _parts([_READY], STOP_ACTIONS), 20, expiry, in_flight_only=True)
        recent = []
    else:
        starts, starts_more = _newest(qs, _parts([_AWAITING], START_ACTIONS), 20, expiry, in_flight_only=True)
        awaiting += starts
        more = more or starts_more
        ready, ready_more = _newest(qs, _parts([_READY], None), 20, expiry, in_flight_only=True)
        recent, _history = _newest(qs, [{}], 10, expiry, in_flight_only=False)
    expiry.mark()
    page = _Page()
    page.cut(more or ready_more)
    awaiting, ready = page.take(awaiting), page.take(ready)
    in_flight_more = page.more
    recent = page.take(recent)
    return {
        "awaiting_signatures": awaiting,
        "ready": ready,
        "recent": recent,
        "more": in_flight_more,
    }


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
    throttle, so the token cannot be guessed at speed."""
    if not poll_token_ok(request):
        return Response({"detail": "poll token required"}, status=status.HTTP_401_UNAUTHORIZED)

    engine_id = request.query_params.get("engine_id")
    qs = FailsafeCommand.objects.filter(status=FailsafeCommand.STATUS_READY)
    if engine_id:
        qs = qs.filter(engine_id=engine_id)
    now = timezone.now()
    out = []
    for command in qs:
        if _expire_if_due(command, now):
            continue
        out.append(command.as_command_dict())
    return Response(out)
