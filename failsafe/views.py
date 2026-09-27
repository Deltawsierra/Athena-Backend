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
import logging
import secrets
import threading

from django.conf import settings
from django.db import transaction
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
    filter an index serves in creation order), newest first.

    Each part is one index read of at most ``limit`` keys, then one read of the
    rows chosen, so the work is the limit and the number of parts, whatever
    the number of commands. A command in flight past its window is marked
    expired; ``in_flight_only`` drops it instead of showing it."""
    keys = []
    for part in parts:  # {} is every command, newest first, by the index on creation time
        keys.extend(qs.filter(**part).order_by("-created_at").values_list("pk", "created_at")[:limit])
    keys.sort(key=lambda key: key[1], reverse=True)
    out = []
    for command in _fetch([pk for pk, _created in keys[:limit]]):
        if expiry.due(command.pk, command.status, command.expires_at):
            if in_flight_only:
                continue
            command.status = FailsafeCommand.STATUS_EXPIRED
        out.append(command)
    return out


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
    AWAITING_STOP_LIMIT, in the order a co-signer needs them.

    First those that already carry a signature -- a stand-down or terminate
    waiting for its second -- newest first: a signature needs an enrolled
    operator's key, so no flood of drafts is ahead of these. Then the unsigned
    drafts, taken in turn from each account: every account's newest, then
    every account's second newest, and so on. A flood of drafts from one
    account, or from the dashboard's one service account, therefore lies
    behind every other operator's newest draft rather than in front of it.

    Bounded: per stop action, one index read of at most AWAITING_STOP_LIMIT
    signed keys and one of at most UNSIGNED_STOP_SCAN unsigned ones, then one
    read of the rows chosen. What that leaves out, stated plainly: an unsigned
    draft older than UNSIGNED_STOP_SCAN newer unsigned drafts of its action --
    or ranked below 500 others -- is not in a read of every engine. A read of
    one engine (the dashboard's state and list reads name the engine) never
    comes near that: a stop draft made again while an identical one is unsigned
    returns it (commands), so an account has at most one fresh unsigned draft
    of each stop action for an engine."""
    signed, unsigned = [], []
    for action in STOP_ACTIONS:
        base = qs.filter(status=_AWAITING, action=action).order_by("-created_at")
        signed.extend(base.filter(signed=True).values_list("pk", "created_at", "expires_at")[:AWAITING_STOP_LIMIT])
        unsigned.extend(
            base.filter(signed=False).values_list("pk", "created_at", "expires_at", "initiator_id")[
                :UNSIGNED_STOP_SCAN
            ]
        )
    def newest_in_flight(keys):
        live = [key for key in keys if not expiry.due(key[0], _AWAITING, key[2])]
        return sorted(live, key=lambda key: key[1], reverse=True)

    signed = [key[0] for key in newest_in_flight(signed)][:AWAITING_STOP_LIMIT]
    per_account = {}
    for pk, _created, _expires, initiator in newest_in_flight(unsigned):
        per_account.setdefault(initiator, []).append(pk)
    in_turn = [pk for round_ in itertools.zip_longest(*per_account.values()) for pk in round_ if pk is not None]
    return _fetch(signed + in_turn[: AWAITING_STOP_LIMIT - len(signed)])


def _fresh_unsigned_draft(user, engine_id, action, ttl):
    """``user``'s unsigned draft of ``action`` for ``engine_id`` with at least
    half its window left, or None. One indexed read; a read that fails is
    None, so the draft is made afresh -- a stop draft is never refused."""
    try:
        drafts = list(
            FailsafeCommand.objects.filter(
                initiator=user, engine_id=engine_id, action=action, status=_AWAITING, signed=False
            ).order_by("-created_at")[:1]
        )
    except Exception:  # noqa: BLE001 - a failed read makes a new draft; it never refuses one
        return None
    if not drafts:
        return None
    try:
        left = (timezone.datetime.fromisoformat(drafts[0].expires_at) - timezone.now()).total_seconds()
    except (TypeError, ValueError):
        return None
    return drafts[0] if left >= ttl / 2 else None


class _SharedReads:
    """Identical stop-lane reads, made at once by one account, share one
    computation at a time instead of each making its own.

    A stop-lane read is exempt from the gateway and every throttle, so one
    account can send as many at once as it likes, and each ran on a thread of
    its own: eight threads reading state took a pause's latency from 0.013 s to
    0.231 s (round 3), because every read competed for the interpreter with the
    pause. Now a read of one kind (the route, the account, the credential, the
    query) waits while an identical one is being computed -- a wait on a lock,
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
    credential it presented, and the query."""
    return (view, request.user.pk, _by_service_token(request), request.META.get("QUERY_STRING", ""))


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
        # bounded by its row limits, not by the number of commands. The stop
        # commands awaiting a signature come first (_awaiting_stops) and are
        # never cut by the row cap, so no flood of other drafts hides one.
        return Response(_SHARED_READS.read(_read_kind(request, "commands"), lambda: _list(request)))

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
    if action in STOP_ACTIONS:
        # A stop draft is never refused and never throttled (safety.stops). Made
        # again while this account's identical draft is unsigned and has at
        # least half its window left, it returns that draft (200) rather than
        # adding another: the same bytes to sign, so a signature already made
        # out of band still counts, and a flood of one draft is one row.
        existing = _fresh_unsigned_draft(request.user, engine_id, action, ttl)
        if existing is not None:
            body = FailsafeCommandSerializer(existing).data
            body["signing_bytes"] = signing_bytes_hex(existing.as_command_dict())
            return Response(body, status=status.HTTP_200_OK)

    draft = make_draft(action, engine_id, serializer.validated_data.get("reason", ""), ttl)
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
    _audit(command, FailsafeAuditEvent.EVENT_DRAFTED, request, action=action,
           engine_id=command.engine_id)
    body = FailsafeCommandSerializer(command).data
    # The exact bytes the operator's CLI must sign for this command.
    body["signing_bytes"] = signing_bytes_hex(draft)
    return Response(body, status=status.HTTP_201_CREATED)


def _list(request):
    qs = FailsafeCommand.objects.all()
    engine_id = request.query_params.get("engine_id")
    state_ = request.query_params.get("status")
    if engine_id:
        qs = qs.filter(engine_id=engine_id)
    statuses = _STATUSES if not state_ else tuple(s for s in _STATUSES if s == state_)
    expiry = _Expiry()
    stops = _awaiting_stops(qs, expiry) if _AWAITING in statuses else []
    if _by_service_token(request):
        # The service token reads the stop commands in flight, nothing else.
        rest = _newest(qs, _parts([s for s in statuses if s == _READY], STOP_ACTIONS), AWAITING_STOP_LIMIT,
                       expiry, in_flight_only=True)
    else:
        rest = _newest(qs, _rest_parts(statuses), COMMAND_LIST_LIMIT, expiry, in_flight_only=False)
    expiry.mark()
    return FailsafeCommandSerializer([*stops, *rest], many=True).data


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


@api_view(["POST"])
@permission_classes([IsAdminOrAnalyst])
def submit_signature(request, cmd_uuid):
    command = get_object_or_404(FailsafeCommand, uuid=cmd_uuid)
    if _expire_if_due(command) or command.status != FailsafeCommand.STATUS_AWAITING:
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

    if key_id in command.distinct_signers():
        return Response(
            {"detail": f"{key_id} has already signed"}, status=status.HTTP_409_CONFLICT
        )

    command.signatures.append({
        "key_id": key_id,
        "sig": sig,
        "submitted_by": request.user.username,
        "submitted_at": timezone.now().isoformat(),
    })
    command.signed = True
    command.save(update_fields=["signatures", "signed", "updated_at"])
    _audit(command, FailsafeAuditEvent.EVENT_SIGNED, request, key_id=key_id)

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
    its work is bounded by its row limits and not by the number of commands.
    The stop commands awaiting a signature come first, at most
    AWAITING_STOP_LIMIT and never cut by the row cap (_awaiting_stops); every
    other list is an index read of its few newest rows; commands found past
    their window are marked expired in one write, at most EXPIRE_PER_READ of
    them (_Expiry) -- a read never walks every command to expire it; and the
    engine is waited for FAILSAFE_STATE_ENGINE_SECONDS at most. Identical
    reads by one account at once share one computation at a time
    (_SharedReads), never one that started before they arrived. With the
    service token it shows the stop commands in flight and the engine's state:
    no resume or release, and no history."""
    commands_ = _SHARED_READS.read(_read_kind(request, "state"), lambda: _in_flight(request))
    engine_state, engine_state_available = _engine_live_state()
    return Response({
        "engine_id": request.query_params.get("engine_id"),
        "engine_state": engine_state,
        "engine_state_available": engine_state_available,
        **commands_,
    })


def _in_flight(request):
    """The state view's commands: in flight, and the most recent."""
    engine_id = request.query_params.get("engine_id")
    qs = FailsafeCommand.objects.all()
    if engine_id:
        qs = qs.filter(engine_id=engine_id)
    expiry = _Expiry()
    awaiting = _awaiting_stops(qs, expiry)
    if _by_service_token(request):
        ready = _newest(qs, _parts([_READY], STOP_ACTIONS), 20, expiry, in_flight_only=True)
        recent = []
    else:
        awaiting += _newest(qs, _parts([_AWAITING], START_ACTIONS), 20, expiry, in_flight_only=True)
        ready = _newest(qs, _parts([_READY], None), 20, expiry, in_flight_only=True)
        recent = _newest(qs, [{}], 10, expiry, in_flight_only=False)
    expiry.mark()
    return {
        "awaiting_signatures": FailsafeCommandSerializer(awaiting, many=True).data,
        "ready": FailsafeCommandSerializer(ready, many=True).data,
        "recent": FailsafeCommandSerializer(recent, many=True).data,
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
