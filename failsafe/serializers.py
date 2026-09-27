from rest_framework import serializers

from .models import FailsafeAuditEvent, FailsafeCommand

#: The longest reason a draft may carry, in characters. A longer one is
#: answered 400 naming this limit: input validation, like the engine_id's 200,
#: and not a count -- it refuses no stop that fits. The reason is in the signed
#: bytes and in every stop-lane read that lists the command, so without it one
#: account's drafts of 60,000-character reasons grew the database 5 MB/s and
#: made one read of every engine 18.8 MB (round 4, H1).
REASON_LIMIT = 1000


class DraftCommandSerializer(serializers.Serializer):
    """Input for drafting a command. The server, not the caller, sets the nonce
    and the validity window, so a caller cannot choose a stale or replayable
    nonce."""

    action = serializers.ChoiceField(choices=[a for a, _ in FailsafeCommand.ACTION_CHOICES])
    engine_id = serializers.CharField(max_length=200)
    reason = serializers.CharField(
        required=False,
        allow_blank=True,
        default="",
        max_length=REASON_LIMIT,
        error_messages={"max_length": f"A reason is at most {REASON_LIMIT:,} characters."},
    )


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
