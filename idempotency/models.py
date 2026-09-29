from django.conf import settings
from django.db import models
from django.utils import timezone


class IdempotencyRecord(models.Model):
    """One ``Idempotency-Key`` an account sent on one route, the request it came
    with (as a digest), and how that request was answered (:mod:`idempotency.layer`).

    ``state``: IN_FLIGHT from before the route runs until its answer is recorded;
    DONE with the answer, which a replay is given; UNKNOWN when the route raised
    before it answered, so whether it started anything was never observed. A row
    left IN_FLIGHT by a process that died reads the same way: never as done, never
    as failed."""

    class State(models.TextChoices):
        IN_FLIGHT = "in_flight", "In flight -- no answer recorded yet"
        DONE = "done", "Answered -- a replay is given this answer"
        UNKNOWN = "unknown", "Unknown -- ended without an answer this backend observed"

    id = models.BigAutoField(primary_key=True)
    # No foreign-key constraint and nothing done on delete, on purpose: removing an
    # operator is a stop (safety.stops), and it must not wait on this table. A
    # removed account's keys are forgotten with their TTL; it cannot replay them.
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL, on_delete=models.DO_NOTHING, db_constraint=False, related_name="+"
    )
    route = models.CharField(max_length=128)
    key = models.CharField(max_length=255)
    request_digest = models.CharField(max_length=64)
    state = models.CharField(max_length=16, choices=State.choices, default=State.IN_FLIGHT)
    response_status = models.PositiveSmallIntegerField(null=True, blank=True)
    response_body = models.TextField(blank=True, default="")
    created_at = models.DateTimeField(default=timezone.now)
    finished_at = models.DateTimeField(null=True, blank=True)
    expires_at = models.DateTimeField()

    class Meta:
        constraints = [
            models.UniqueConstraint(fields=["user", "route", "key"], name="uq_idempotency_key_per_account_route"),
        ]
        indexes = [
            models.Index(fields=["expires_at"]),
            models.Index(fields=["user", "created_at"]),
        ]

    def __str__(self) -> str:
        return f"{self.route} key {self.key!r} ({self.state})"
