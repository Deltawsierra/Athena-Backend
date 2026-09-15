"""Persistent state for the failsafe control plane.

Operators draft a command here, sign it out of band (the private key never
touches this server), and submit signatures; when enough distinct operators have
signed, the command becomes `ready` and the engine polls it. The engine is the
authoritative verifier -- it holds the verify-only keys and re-checks every
signature before obeying -- so this control plane can never, by itself, make an
engine act; it only relays operator-signed commands and records what happened.

The RFC3339 timestamps and the nonce are stored as the exact strings that go
into the signature, so the bytes an operator signs, the bytes this server shows,
and the bytes the engine verifies are identical.
"""

import uuid

from django.conf import settings
from django.db import models


class FailsafeCommand(models.Model):
    STATUS_AWAITING = "awaiting_signatures"
    STATUS_READY = "ready"
    STATUS_CONSUMED = "consumed"
    STATUS_EXPIRED = "expired"
    STATUS_CANCELED = "canceled"
    STATUS_CHOICES = (
        (STATUS_AWAITING, "Awaiting signatures"),
        (STATUS_READY, "Ready for the engine"),
        (STATUS_CONSUMED, "Consumed by the engine"),
        (STATUS_EXPIRED, "Expired"),
        (STATUS_CANCELED, "Canceled"),
    )

    # Mirrors mythos_core.failsafe.commands.Action; kept as plain strings so this
    # model does not import the enum for a field definition.
    ACTION_CHOICES = (
        ("pause", "Pause"),
        ("resume", "Resume"),
        ("stand_down", "Stand down"),
        ("release", "Release"),
        ("terminate", "Terminate"),
    )

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, db_index=True)

    engine_id = models.CharField(max_length=200)
    action = models.CharField(max_length=32, choices=ACTION_CHOICES)
    # The exact signed strings (see module docstring).
    nonce = models.CharField(max_length=128, unique=True)
    issued_at = models.CharField(max_length=64)
    expires_at = models.CharField(max_length=64)
    reason = models.TextField(blank=True, default="")

    # [{key_id, sig, submitted_by, submitted_at}]. Only distinct valid key_ids
    # count toward the threshold; the raw list is kept for the audit trail.
    signatures = models.JSONField(default=list, blank=True)
    required_signatures = models.PositiveSmallIntegerField(default=1)

    status = models.CharField(
        max_length=32, choices=STATUS_CHOICES, default=STATUS_AWAITING, db_index=True
    )

    initiator = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="drafted_failsafe_commands",
    )

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-created_at"]
        indexes = [
            models.Index(fields=["engine_id", "status"]),
            models.Index(fields=["status", "expires_at"]),
        ]

    def __str__(self):
        return f"{self.action} {self.engine_id} [{self.status}]"

    # ---- transitions (each saves only what it changed) ----
    def mark_ready(self):
        self.status = self.STATUS_READY
        self.save(update_fields=["status", "updated_at"])

    def mark_consumed(self):
        self.status = self.STATUS_CONSUMED
        self.save(update_fields=["status", "updated_at"])

    def mark_expired(self):
        self.status = self.STATUS_EXPIRED
        self.save(update_fields=["status", "updated_at"])

    def mark_canceled(self):
        self.status = self.STATUS_CANCELED
        self.save(update_fields=["status", "updated_at"])

    def distinct_signers(self):
        return sorted({s["key_id"] for s in self.signatures if s.get("key_id")})

    def as_command_dict(self):
        """The command as the engine consumes it (mythos_core.failsafe.Command
        shape): the signed fields plus the collected {key_id, sig} signatures."""
        return {
            "action": self.action,
            "engine_id": self.engine_id,
            "nonce": self.nonce,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "reason": self.reason,
            "signatures": [
                {"key_id": s["key_id"], "sig": s["sig"]} for s in self.signatures
            ],
        }


class FailsafeAuditEvent(models.Model):
    """A first-class audit trail for the failsafe. The repo's audit.AuditLog is
    email-alert shaped and never written by code, so the failsafe keeps its own
    -- every draft, signature, readiness, consumption, and refusal, with the
    acting operator and request metadata, next to the command it governed."""

    EVENT_DRAFTED = "drafted"
    EVENT_SIGNED = "signed"
    EVENT_READY = "ready"
    EVENT_SIGNATURE_REJECTED = "signature_rejected"
    EVENT_SERVED_TO_ENGINE = "served_to_engine"
    EVENT_CONSUMED = "consumed"
    EVENT_EXPIRED = "expired"
    EVENT_CANCELED = "canceled"
    EVENT_CHOICES = (
        (EVENT_DRAFTED, "Drafted"),
        (EVENT_SIGNED, "Signed"),
        (EVENT_READY, "Ready"),
        (EVENT_SIGNATURE_REJECTED, "Signature rejected"),
        (EVENT_SERVED_TO_ENGINE, "Served to engine"),
        (EVENT_CONSUMED, "Consumed"),
        (EVENT_EXPIRED, "Expired"),
        (EVENT_CANCELED, "Canceled"),
    )

    id = models.BigAutoField(primary_key=True)
    uuid = models.UUIDField(default=uuid.uuid4, editable=False, unique=True, db_index=True)
    timestamp = models.DateTimeField(auto_now_add=True, db_index=True)

    command = models.ForeignKey(
        FailsafeCommand,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="audit_events",
    )
    event = models.CharField(max_length=32, choices=EVENT_CHOICES)
    actor = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name="failsafe_audit_events",
    )
    # Free-form context: the action/engine_id, the signer key_id, a rejection
    # reason, request metadata (ip, request_id) from RequestMetadataMiddleware.
    detail = models.JSONField(default=dict, blank=True)

    class Meta:
        ordering = ["-timestamp"]
        indexes = [models.Index(fields=["event", "timestamp"])]

    def __str__(self):
        return f"{self.event} @ {self.timestamp:%Y-%m-%d %H:%M:%S}"
