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
from django.utils import timezone

#: The actions that stop an engine, and what alone lifts each once it is in
#: force: a pause only by a resume, a stand-down only by a release, and a
#: terminate by nothing (FailsafeCommand.in_force).
STOP_ACTIONS = ("pause", "stand_down", "terminate")
LIFTED_ONLY_BY = {"pause": "resume", "stand_down": "release", "terminate": None}


class FailsafeCommand(models.Model):
    STATUS_AWAITING = "awaiting_signatures"
    STATUS_READY = "ready"
    STATUS_CONSUMED = "consumed"
    STATUS_EXPIRED = "expired"
    STATUS_CANCELED = "canceled"
    # An unsigned stop draft set aside by a newer one of the same account, past
    # that account's limit of unsigned stop drafts (failsafe.views): no longer
    # signable; drafting it again makes a new one, which is never refused.
    STATUS_SUPERSEDED = "superseded"
    STATUS_CHOICES = (
        (STATUS_AWAITING, "Awaiting signatures"),
        (STATUS_READY, "Ready for the engine"),
        (STATUS_CONSUMED, "Consumed by the engine"),
        (STATUS_EXPIRED, "Expired"),
        (STATUS_CANCELED, "Canceled"),
        (STATUS_SUPERSEDED, "Superseded by a newer draft"),
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
    # Whether any operator has signed it yet: `signatures` is not empty. Kept
    # beside the list so the stop commands awaiting a signature can be read
    # with those already carrying one first, by an index, however many
    # unsigned drafts there are (failsafe.views).
    signed = models.BooleanField(default=False)

    status = models.CharField(
        max_length=32, choices=STATUS_CHOICES, default=STATUS_AWAITING, db_index=True
    )

    #: When enough distinct operators had signed it: set by mark_ready, in the
    #: one UPDATE that makes the command ready. None for a command never made
    #: ready. The order commands were SIGNED into force in, which their
    #: drafting times do not give.
    ready_at = models.DateTimeField(null=True, blank=True)
    #: A stop in force: a pause, stand-down or terminate that was made ready
    #: and that no later start has lifted. Set by mark_ready in that same
    #: UPDATE, so it cannot fail apart from the stop itself; never typed in.
    #: Cleared only by the transaction that signs a later resume (for a pause)
    #: or release (for a stand-down) into force, which names itself in
    #: ``lifted_by``; nothing clears a terminate's. While it is set the
    #: command stays ``ready`` and the engine's poll answers it whatever its
    #: window: no expiry, cancel or supersede touches it (failsafe.views).
    in_force = models.BooleanField(default=False)
    #: The uuid of the resume or release that lifted this stop, and when that
    #: start was made ready. None while in force, and for a command that is
    #: not a stop.
    lifted_by = models.UUIDField(null=True, blank=True)
    lifted_at = models.DateTimeField(null=True, blank=True)

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
            # The stop lane's reads (failsafe.views) each take the newest few
            # rows of one status -- or of one status, action and signed-ness --
            # in creation order, with or without an engine: each an index
            # range read in order, so a read's work is its row limit, not the
            # number of commands.
            models.Index(fields=["created_at"], name="fsc_ct"),
            models.Index(fields=["engine_id", "created_at"], name="fsc_eng_ct"),
            models.Index(fields=["status", "created_at"], name="fsc_st_ct"),
            models.Index(fields=["engine_id", "status", "created_at"], name="fsc_eng_st_ct"),
            models.Index(fields=["status", "action", "signed", "created_at"], name="fsc_st_act_sig_ct"),
            models.Index(
                fields=["engine_id", "status", "action", "signed", "created_at"], name="fsc_eng_st_act_sig_ct"
            ),
            # The ready commands of one action, newest first, with or without
            # an engine: the engine's poll reads the ready stops, action by
            # action, before a capped few ready starts, and the console's
            # reads list the ready stops before the ready starts. Without
            # these each was read by (status, created_at) and every ready
            # command of another action was stepped past -- a flood of ready
            # resumes, under a read for a ready stand-down (failsafe.views).
            models.Index(fields=["status", "action", "created_at"], name="fsc_st_act_ct"),
            models.Index(fields=["engine_id", "status", "action", "created_at"], name="fsc_eng_st_act_ct"),
            # An account's unsigned draft of one action for one engine: a stop
            # draft made again while it is unsigned returns it.
            models.Index(fields=["initiator", "engine_id", "action", "status", "signed"], name="fsc_draft_lookup"),
            # An account's unsigned drafts, newest first: those past the
            # account's limit are superseded by its newest (failsafe.views).
            models.Index(fields=["initiator", "status", "signed", "created_at"], name="fsc_init_st_sig_ct"),
            # The stops one start lifted: read only when that start is
            # cancelled, to put them back in force (failsafe.views). Partial,
            # so a row no start lifted -- every draft -- is not in it.
            models.Index(fields=["lifted_by"], name="fsc_lifted_by", condition=models.Q(lifted_by__isnull=False)),
        ]

    def __str__(self):
        return f"{self.action} {self.engine_id} [{self.status}]"

    # ---- transitions (each saves only what it changed) ----
    def mark_ready(self, at=None):
        """Ready for the engine, as of ``at`` (now). A stop is in force from
        this same write: one UPDATE, as it was, carrying two more columns."""
        self.status = self.STATUS_READY
        self.ready_at = at or timezone.now()
        self.in_force = self.action in STOP_ACTIONS
        self.save(update_fields=["status", "ready_at", "in_force", "updated_at"])

    # A stop in force stays ready: none of the three below moves it, and each
    # says so (False). It ends only by a signed start (failsafe.views).
    def mark_consumed(self):
        if self.in_force:
            return False
        self.status = self.STATUS_CONSUMED
        self.save(update_fields=["status", "updated_at"])
        return True

    def mark_expired(self):
        if self.in_force:
            return False
        self.status = self.STATUS_EXPIRED
        self.save(update_fields=["status", "updated_at"])
        return True

    def mark_canceled(self):
        if self.in_force:
            return False
        self.status = self.STATUS_CANCELED
        self.save(update_fields=["status", "updated_at"])
        return True

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


class FailsafeStopMark(models.Model):
    """The newest stop ever made ready for one engine: when it was drafted,
    and which it is.

    Written in the transaction that signs a stop into force (failsafe.views,
    submit_signature) and moved only forward; never deleted, so it outlives
    the stop's window. The engine's poll reads one row of it per engine on
    its page, and never delivers a resume or release drafted at or before it:
    delivered after that stop, the start would undo it. One row per engine,
    whatever the number of stops, starts or consumed history.

    And when a stop was last made ready for the engine (``last_ready_at``):
    a start made ready at or before that is never delivered either, however
    late it was drafted. A stand-down drafted first and signed last, beside a
    release drafted after it and signed before it, was answered stand-down
    then release, and the engine ended running.

    And the latest instant a stop made ready was SIGNED as issued
    (``issued``): a start issued at or before it is never delivered and lifts
    nothing, however late its row was made. ``created_at`` and ``issued_at``
    are two reads of the clock, and a start drafted within one tick of a stop
    could be later by the first and not by the second."""

    engine_id = models.CharField(max_length=200, primary_key=True)
    #: The stop's own creation time (FailsafeCommand.created_at).
    created_at = models.DateTimeField()
    stop_uuid = models.UUIDField()
    action = models.CharField(max_length=32)
    #: When a stop was last MADE READY for this engine (FailsafeCommand.
    #: ready_at), whichever stop that was: moved in the same UPDATE as the
    #: rest. The poll never delivers a start made ready at or before it. None
    #: until a stop is made ready after migration 0006 (or backfilled by it).
    last_ready_at = models.DateTimeField(null=True, blank=True)
    #: The latest SIGNED instant (FailsafeCommand.issued_at) of any stop made
    #: ready for this engine, whichever stop that was: moved forward, never
    #: back, in the same UPDATE as the rest. The engine orders by it: its
    #: governor refuses a resume or a release not issued strictly after the
    #: stops it accepted. So the plane never lifts a stop by, nor delivers, a
    #: start issued at or before it. None when it is not known (migration
    #: 0007 found no readable stop row): every start of the engine is then
    #: held back, until a stop with a readable ``issued_at`` is made ready.
    issued = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.engine_id}: {self.action} {self.stop_uuid} @ {self.created_at:%Y-%m-%d %H:%M:%S}"


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
    EVENT_SUPERSEDED = "superseded"
    #: A stop in force lifted by a later signed start, which the event names.
    EVENT_LIFTED = "lifted"
    #: A stop put (back) in force: its lifting start was cancelled, or the
    #: owner chose a historic stop (the failsafe_historic_stops command).
    EVENT_IN_FORCE = "in_force"
    EVENT_CHOICES = (
        (EVENT_DRAFTED, "Drafted"),
        (EVENT_SIGNED, "Signed"),
        (EVENT_READY, "Ready"),
        (EVENT_SIGNATURE_REJECTED, "Signature rejected"),
        (EVENT_SERVED_TO_ENGINE, "Served to engine"),
        (EVENT_CONSUMED, "Consumed"),
        (EVENT_EXPIRED, "Expired"),
        (EVENT_CANCELED, "Canceled"),
        (EVENT_SUPERSEDED, "Superseded by a newer draft"),
        (EVENT_LIFTED, "Lifted by a later start"),
        (EVENT_IN_FORCE, "Put in force"),
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
