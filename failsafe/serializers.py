from rest_framework import serializers

from .models import FailsafeAuditEvent, FailsafeCommand

#: The longest reason a draft is stored with, in characters. The reason is in
#: the signed bytes and in every stop-lane read that lists the command, so
#: without a bound one account's drafts of 60,000-character reasons grew the
#: database 5 MB/s and made one read of every engine 18.8 MB (round 4, H1). The
#: bound matches what the dashboard's draftCommandSchema enforces (2,000), so a
#: stop the dashboard can send is never refused for its reason length (round 5,
#: F3). A STOP is never 400'd for reason length at all: a longer one is
#: truncated and stored (failsafe.views._stop_draft), never refused. Only a
#: NON-stop draft (resume/release) past the bound is 400 -- input validation,
#: like the engine_id's 200.
REASON_LIMIT = 2000


class DraftCommandSerializer(serializers.Serializer):
    """Input for drafting a command. The server, not the caller, sets the nonce
    and the validity window, so a caller cannot choose a stale or replayable
    nonce.

    The reason carries no ``max_length`` here: the reason-length bound is
    applied in the view, where a stop is truncated to REASON_LIMIT and never
    refused, and a non-stop past it is 400 (failsafe.views). The stop body is
    already bounded to 64 KiB by safety.stops, so a stop reason cannot be
    unboundedly large before it is truncated."""

    action = serializers.ChoiceField(choices=[a for a, _ in FailsafeCommand.ACTION_CHOICES])
    engine_id = serializers.CharField(max_length=200)
    reason = serializers.CharField(required=False, allow_blank=True, default="")


class SubmitSignatureSerializer(serializers.Serializer):
    """Input for adding one operator signature to a pending command."""

    key_id = serializers.CharField(max_length=128)
    sig = serializers.RegexField(r"^[0-9a-fA-F]+$", max_length=256)


class FailsafeCommandSerializer(serializers.ModelSerializer):
    signers = serializers.SerializerMethodField()

    class Meta:
        model = FailsafeCommand
        fields = (
            "uuid",
            "engine_id",
            "action",
            "nonce",
            "issued_at",
            "expires_at",
            "reason",
            "signers",
            "required_signatures",
            "status",
            "created_at",
            "updated_at",
        )
        read_only_fields = fields

    def get_signers(self, obj):
        # Distinct key_ids only; the raw signatures (with hex) are not echoed.
        return obj.distinct_signers()


class FailsafeAuditEventSerializer(serializers.ModelSerializer):
    command_uuid = serializers.SerializerMethodField()
    actor_username = serializers.SerializerMethodField()

    class Meta:
        model = FailsafeAuditEvent
        fields = ("uuid", "timestamp", "event", "command_uuid", "actor_username", "detail")
        read_only_fields = fields

    def get_command_uuid(self, obj):
        return str(obj.command.uuid) if obj.command_id else None

    def get_actor_username(self, obj):
        return obj.actor.username if obj.actor_id else None
