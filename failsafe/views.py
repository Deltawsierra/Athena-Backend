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
import secrets
import threading

from django.conf import settings
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

#: The most commands one list read returns besides the stops awaiting a
#: signature. It was 100.
COMMAND_LIST_LIMIT = 50

#: The actions that stop an engine (safety.stops drafts them as stops).
STOP_ACTIONS = ("pause", "stand_down", "terminate")

#: The stop commands awaiting a signature that one read returns, listed before
#: everything else and never cut by COMMAND_LIST_LIMIT. Generous: each account
#: has at most FAILSAFE_MAX_OUTSTANDING_STOP_DRAFTS of them, and each expires
#: within FAILSAFE_COMMAND_TTL_SECONDS.
AWAITING_STOP_LIMIT = 500


def _awaiting_stops_first(qs, rest_limit):
    """The stop commands in ``qs`` awaiting a signature (newest first, at most
    AWAITING_STOP_LIMIT), then the rest of ``qs`` (at most ``rest_limit``).

    A co-signer finds a stand-down or terminate among these reads. On round 2
    fifty newer drafts pushed a real one out of the list, so however many
    other commands there are, the ones waiting for a signature come first."""
    awaiting = FailsafeCommand.STATUS_AWAITING
    stops = qs.filter(status=awaiting, action__in=STOP_ACTIONS)[:AWAITING_STOP_LIMIT]
    rest = qs.exclude(status=awaiting, action__in=STOP_ACTIONS)[:rest_limit]
    return [*stops, *rest]


def _outstanding_stop_drafts(user):
    """``user``'s stop drafts still awaiting a signature, expiring any that are
    due first; or None when they cannot be read, which refuses no draft.

    Bounded: every draft is checked against this cap, so an account never has
    more than the cap outstanding for this loop to expire."""
    try:
        outstanding = []
        mine = FailsafeCommand.objects.filter(
            initiator=user, status=FailsafeCommand.STATUS_AWAITING, action__in=STOP_ACTIONS
        )
        now = timezone.now()
        for command in mine:
            if not _expire_if_due(command, now):
                outstanding.append(command)
        return outstanding
    except Exception:  # noqa: BLE001 - a read that fails must not refuse a stop draft
        return None


def _max_outstanding_stop_drafts():
    try:
        return max(1, int(getattr(settings, "FAILSAFE_MAX_OUTSTANDING_STOP_DRAFTS", 20)))
    except (TypeError, ValueError):
        return 20


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
    if command.status in (FailsafeCommand.STATUS_AWAITING, FailsafeCommand.STATUS_READY):
        try:
            due = timezone.datetime.fromisoformat(command.expires_at)
        except ValueError:
            return False
        if now >= due:
            command.mark_expired()
            return True
    return False


@api_view(["GET", "POST"])
@permission_classes([IsAdminOrAnalyst])
def commands(request):
    if request.method == "GET":
        qs = FailsafeCommand.objects.all()
        engine_id = request.query_params.get("engine_id")
        state = request.query_params.get("status")
        if engine_id:
            qs = qs.filter(engine_id=engine_id)
        if state:
            qs = qs.filter(status=state)
        # A stop-lane read: no throttle counts it (safety.stops), so each one is
        # bounded. The stop commands awaiting a signature come first and are
        # never cut by the row cap, so no flood of other drafts hides one.
        rows = _awaiting_stops_first(qs, COMMAND_LIST_LIMIT)
        return Response(FailsafeCommandSerializer(rows, many=True).data)

    serializer = DraftCommandSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    action = serializer.validated_data["action"]

    if action in _ADMIN_ONLY_ACTIONS and not request.user.is_admin:
        return Response(
            {"detail": f"{action} may only be initiated by an admin"},
            status=status.HTTP_403_FORBIDDEN,
        )

    if action in STOP_ACTIONS:
        # A stop draft is never throttled (safety.stops), so the drafts one
        # account has awaiting a signature are capped instead: a flood of them
        # would otherwise bury a real command. The cap is at least one, so an
        # account's first draft is never refused, and a read that fails refuses
        # nothing. A refusal names the drafts awaiting, which the account can
        # sign, or cancel (a stop too, never refused) to draft again.
        outstanding = _outstanding_stop_drafts(request.user)
        cap = _max_outstanding_stop_drafts()
        if outstanding is not None and len(outstanding) >= cap:
            return Response(
                {
                    "detail": (
                        f"you have {len(outstanding)} stop commands awaiting signatures, the most "
                        f"one account may have outstanding; sign or cancel one of them"
                    ),
                    "outstanding": FailsafeCommandSerializer(outstanding, many=True).data,
                },
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )

    draft = make_draft(
        action,
        serializer.validated_data["engine_id"],
        serializer.validated_data.get("reason", ""),
        int(getattr(settings, "FAILSAFE_COMMAND_TTL_SECONDS", 600)),
    )
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


@api_view(["GET"])
@permission_classes([IsAdminOrAnalyst])
def command_detail(request, cmd_uuid):
    command = get_object_or_404(FailsafeCommand, uuid=cmd_uuid)
    _expire_if_due(command)
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
    command.save(update_fields=["signatures", "updated_at"])
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
    it is bounded -- the stop commands awaiting a signature come first and are
    never cut by the row cap (AWAITING_STOP_LIMIT), every other list is capped,
    and the engine is waited for FAILSAFE_STATE_ENGINE_SECONDS at most."""
    engine_id = request.query_params.get("engine_id")
    qs = FailsafeCommand.objects.all()
    if engine_id:
        qs = qs.filter(engine_id=engine_id)
    for command in qs.filter(status__in=[FailsafeCommand.STATUS_AWAITING, FailsafeCommand.STATUS_READY]):
        _expire_if_due(command)
    qs = qs.filter(engine_id=engine_id) if engine_id else FailsafeCommand.objects.all()
    awaiting = qs.filter(status=FailsafeCommand.STATUS_AWAITING)
    ready = qs.filter(status=FailsafeCommand.STATUS_READY)
    engine_state, engine_state_available = _engine_live_state()
    return Response({
        "engine_id": engine_id,
        "engine_state": engine_state,
        "engine_state_available": engine_state_available,
        "awaiting_signatures": FailsafeCommandSerializer(_awaiting_stops_first(awaiting, 20), many=True).data,
        "ready": FailsafeCommandSerializer(ready[:20], many=True).data,
        "recent": FailsafeCommandSerializer(qs[:10], many=True).data,
    })


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
