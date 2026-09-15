"""The failsafe control plane.

Operators draft a command, sign it out of band, and submit signatures; when
enough distinct operators have signed, the command is `ready` and the engine
polls `/pending` for it. Guard (a) still holds: this plane holds no private key
and cannot itself make an engine act -- it relays operator-signed commands the
engine independently verifies. Guard (b): two distinct operator signatures are
required for stand-down and terminate.
"""

from __future__ import annotations

from django.conf import settings
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.decorators import api_view, permission_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from accounts.permissions import IsAdmin, IsAdminOrAnalyst

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
        return Response(FailsafeCommandSerializer(qs[:100], many=True).data)

    serializer = DraftCommandSerializer(data=request.data)
    serializer.is_valid(raise_exception=True)
    action = serializer.validated_data["action"]

    if action in _ADMIN_ONLY_ACTIONS and not request.user.is_admin:
        return Response(
            {"detail": f"{action} may only be initiated by an admin"},
            status=status.HTTP_403_FORBIDDEN,
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


@api_view(["GET"])
@permission_classes([IsAdminOrAnalyst])
def state(request):
    """A control-plane view of failsafe activity for an engine: commands in
    flight and the last ready/consumed one. The engine's live governor state
    (running/paused/stood-down/terminated) is added here once the engine exposes
    it and this proxies it -- see the engine-wiring follow-up."""
    engine_id = request.query_params.get("engine_id")
    qs = FailsafeCommand.objects.all()
    if engine_id:
        qs = qs.filter(engine_id=engine_id)
    for command in qs.filter(status__in=[FailsafeCommand.STATUS_AWAITING, FailsafeCommand.STATUS_READY]):
        _expire_if_due(command)
    qs = qs.filter(engine_id=engine_id) if engine_id else FailsafeCommand.objects.all()
    awaiting = qs.filter(status=FailsafeCommand.STATUS_AWAITING)
    ready = qs.filter(status=FailsafeCommand.STATUS_READY)
    return Response({
        "engine_id": engine_id,
        "engine_state": None,  # filled by the engine-state proxy (follow-up)
        "engine_state_available": False,
        "awaiting_signatures": FailsafeCommandSerializer(awaiting[:20], many=True).data,
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


@api_view(["GET"])
@permission_classes([AllowAny])  # engine poll, authenticated by a shared poll token
def pending(request):
    """The endpoint the engine polls (its control_url). Returns fully-signed,
    unexpired commands as mythos_core.failsafe.Command documents. Authenticated
    by a dedicated poll token, NOT an operator JWT -- the engine is not an
    operator. Re-serving is safe: the engine's nonce ledger applies each command
    at most once."""
    expected = getattr(settings, "FAILSAFE_POLL_TOKEN", None)
    provided = request.headers.get("X-Failsafe-Poll-Token")
    if not expected or provided != expected:
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
