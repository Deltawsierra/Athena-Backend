from rest_framework import serializers

from .models import FailsafeAuditEvent, FailsafeCommand


class DraftCommandSerializer(serializers.Serializer):
    """Input for drafting a command. The server, not the caller, sets the nonce
    and the validity window, so a caller cannot choose a stale or replayable
    nonce."""

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
