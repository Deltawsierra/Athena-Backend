"""Automated-dispatch policy — a qualifying finding leaves the record on its own.

The connector framework (:mod:`assurance.connectors`) carries a finding OUT into a
customer's Jira / ServiceNow / GitHub / Splunk / webhook. Until now the only way to
fire that was the manual admin push. This module adds the *policy* for when a push
happens automatically, per tenant, and the auditable record of every attempt.

The shape mirrors the ingest signal (:mod:`assurance.signals`), on purpose:

- **Per-tenant and off by default.** Dispatch fires only for a deployment that has
  a :class:`~assurance.models.DispatchPolicy` that an admin has explicitly enabled.
  With no policy — the default for every deployment — nothing auto-dispatches, and
  the manual push stays the only outbound path, exactly as today. No policy is
  created implicitly.
- **Inert without configuration or a key, and honest about it.** A connector with
  no operational binding, or with a binding but no ``ASSURANCE_CREDENTIAL_KEY`` to
  decrypt its credential, is *skipped* — recorded as ``skipped_inert`` /
  ``skipped_no_key`` — and **no transport is ever touched**. A skip is never a
  fabricated success.
- **Idempotent.** One :class:`~assurance.models.DispatchAttempt` per
  ``(finding, connector)``. Once it is ``sent`` it is terminal: the same finding is
  never pushed to the same connector twice, however many times a signal re-fires.
- **Resilient.** Every connector is dispatched inside its own guard: an error is
  caught and recorded as ``failed`` — it never breaks the request path or the other
  connectors. Like ingest, the automatic entry point runs on
  ``transaction.on_commit`` so it never lengthens the transaction that produced the
  finding (and is naturally inert in the rolled-back test transactions).
- **The transport is injected.** :func:`dispatch_finding` takes a
  ``transport_factory``; production builds a :class:`~assurance.connectors.RequestsTransport`,
  tests pass a fake. The real transport is built **only** for an operational
  binding, which requires a configured key + credential, so nothing reaches the
  network by default or in tests.
"""

from __future__ import annotations

import logging

from django.conf import settings
from django.db import transaction

from .models import (
    RESOLVED_FINDING_STATUSES,
    ConnectorBinding,
    Deployment,
    DispatchAttempt,
    DispatchPolicy,
    Finding,
)

logger = logging.getLogger(__name__)

# Decisions that count as "blocking" for the decision-transition trigger — the
# states in which a deployment should not be shipping as-is.
_BLOCKING_DECISIONS = frozenset(
    {
        Deployment.Decision.NEEDS_REMEDIATION,
        Deployment.Decision.NOT_RECOMMENDED,
        Deployment.Decision.PAUSED,
    }
)

# Findings that are done — never dispatched on a decision transition.
# The one definition lives in ``assurance.models`` beside the statuses themselves.
# Seven modules each kept their own copy of this set, and every one of their
# comments said it "mirrors" the others so every view would agree on what "active"
# means -- which is precisely the arrangement that lets them stop agreeing. Adding
# a status meant editing eight places and silently disagreeing if you missed one.
_RESOLVED_STATUSES = RESOLVED_FINDING_STATUSES


def _default_transport_factory():
    """Build the production transport. Called **only** for an operational binding,
    so importing/constructing it here can never be mistaken for a default outbound
    call — nothing reaches this unless a key + credential are configured."""
    from .connectors import RequestsTransport

    return RequestsTransport()


def _record(finding, binding, *, trigger, outcome, detail, external_ref=None):
    """Create or update the single ``(finding, connector)`` attempt record. The
    detail is human-readable and never a secret; ``attempts`` counts retries of a
    not-yet-sent record."""
    ref = external_ref or ""
    obj, created = DispatchAttempt.objects.get_or_create(
        finding=finding,
        connector=binding.connector,
        defaults={
            "deployment": finding.deployment,
            "binding": binding,
            "outcome": outcome,
            "trigger": trigger,
            "detail": detail,
            "external_ref": ref,
        },
    )
    if not created:
        obj.deployment = finding.deployment
        obj.binding = binding
        obj.outcome = outcome
        obj.trigger = trigger
        obj.detail = detail
        obj.external_ref = ref
        obj.attempts = (obj.attempts or 0) + 1
        obj.save(
            update_fields=[
                "deployment",
                "binding",
                "outcome",
                "trigger",
                "detail",
                "external_ref",
                "attempts",
                "updated_at",
            ]
        )
    return obj


def _dispatch_one(finding, binding, *, trigger, key_ok, transport_factory):
    """Dispatch one finding to one connector binding, honestly. Returns the
    resulting :class:`~assurance.models.DispatchAttempt`. Records a skip (and
    touches no transport) when the binding is disabled, there is no key, or the
    binding is not operational; performs the push only for an operational binding."""
    existing = DispatchAttempt.objects.filter(
        finding=finding, connector=binding.connector
    ).first()
    if existing is not None and existing.is_terminal:
        # Already accepted by the external system — never push the same finding to
        # the same connector twice.
        return existing

    if not binding.enabled:
        return _record(
            finding,
            binding,
            trigger=trigger,
            outcome=DispatchAttempt.Outcome.SKIPPED_DISABLED,
            detail=f"{binding.connector} binding is disabled",
        )
    if not key_ok:
        return _record(
            finding,
            binding,
            trigger=trigger,
            outcome=DispatchAttempt.Outcome.SKIPPED_NO_KEY,
            detail=(
                f"{binding.connector} has a binding but no encryption key is "
                "configured, so its credential cannot be read — nothing was sent"
            ),
        )
    if not binding.is_operational():
        return _record(
            finding,
            binding,
            trigger=trigger,
            outcome=DispatchAttempt.Outcome.SKIPPED_INERT,
            detail=f"{binding.connector} not configured",
        )

    # Operational: build the real (or injected) transport and push. push_finding
    # never raises — a transport error comes back as ok=False.
    factory = transport_factory or _default_transport_factory
    transport = factory()
    connector = binding.build_connector()
    result = connector.push_finding(finding, transport=transport)
    outcome = (
        DispatchAttempt.Outcome.SENT if result.ok else DispatchAttempt.Outcome.FAILED
    )
    return _record(
        finding,
        binding,
        trigger=trigger,
        outcome=outcome,
        detail=result.detail,
        external_ref=result.external_ref,
    )


def dispatch_finding(finding, *, trigger, transport_factory=None):
    """Dispatch one finding to every connector bound to its deployment.

    Returns the list of :class:`~assurance.models.DispatchAttempt` records (one per
    binding). Never raises: each connector is dispatched in its own guard, so one
    connector's failure is recorded as ``failed`` and never affects the others or
    the caller. This is the low-level worker — the policy gate (is the policy
    enabled, does the finding qualify) lives in the callers below, so this stays
    directly testable."""
    from .crypto import encryption_available

    key_ok = encryption_available()
    attempts = []
    for binding in ConnectorBinding.objects.filter(deployment=finding.deployment):
        try:
            attempts.append(
                _dispatch_one(
                    finding,
                    binding,
                    trigger=trigger,
                    key_ok=key_ok,
                    transport_factory=transport_factory,
                )
            )
        except Exception as exc:  # noqa: BLE001 — a binding error is recorded, never raised
            logger.exception(
                "connector dispatch failed for finding %s -> %s",
                getattr(finding, "pk", "?"),
                binding.connector,
            )
            try:
                attempts.append(
                    _record(
                        finding,
                        binding,
                        trigger=trigger,
                        outcome=DispatchAttempt.Outcome.FAILED,
                        detail=f"{binding.connector} dispatch error: {exc}",
                    )
                )
            except Exception:  # noqa: BLE001 — even recording must not raise out
                logger.exception("failed to record a failed dispatch attempt")
    return attempts


def maybe_dispatch_finding(finding, *, transport_factory=None):
    """The policy-gated entry point for the severity trigger: dispatch a finding
    only when its deployment has an enabled policy the finding qualifies for, and
    the deployment actually has connector bindings. A no-op otherwise (no records,
    no outbound) — the inert-by-default behaviour."""
    if not getattr(settings, "ASSURANCE_AUTO_DISPATCH_ENABLED", True):
        return []
    policy = DispatchPolicy.objects.filter(
        deployment=finding.deployment, enabled=True
    ).first()
    if policy is None or not policy.finding_qualifies(finding):
        return []
    if not ConnectorBinding.objects.filter(deployment=finding.deployment).exists():
        return []
    return dispatch_finding(
        finding,
        trigger=DispatchAttempt.Trigger.SEVERITY,
        transport_factory=transport_factory,
    )


def dispatch_for_blocking_decision(deployment, *, transport_factory=None):
    """The decision trigger: when a deployment's decision has entered a blocking
    state and its policy opts into it, dispatch the deployment's active qualifying
    findings. Idempotent and inert-by-default like the severity trigger."""
    if not getattr(settings, "ASSURANCE_AUTO_DISPATCH_ENABLED", True):
        return []
    policy = DispatchPolicy.objects.filter(deployment=deployment, enabled=True).first()
    if policy is None or not policy.on_blocking_decision:
        return []
    if deployment.decision not in _BLOCKING_DECISIONS:
        return []
    if not ConnectorBinding.objects.filter(deployment=deployment).exists():
        return []
    attempts = []
    findings = (
        deployment.findings.exclude(status__in=_RESOLVED_STATUSES).order_by("pk")
    )
    for finding in findings:
        if not policy.finding_qualifies(finding):
            continue
        attempts.extend(
            dispatch_finding(
                finding,
                trigger=DispatchAttempt.Trigger.BLOCKING_DECISION,
                transport_factory=transport_factory,
            )
        )
    return attempts


def schedule_finding_dispatch(finding):
    """Schedule :func:`maybe_dispatch_finding` on transaction commit, wrapped so it
    can never break the caller. On-commit means it runs after the finding's
    transaction lands (and is discarded in the rolled-back test transactions, so it
    stays inert there), mirroring the ingest signal."""

    finding_pk = finding.pk

    def _run():
        try:
            fresh = Finding.objects.select_related("deployment").get(pk=finding_pk)
            maybe_dispatch_finding(fresh)
        except Finding.DoesNotExist:
            return
        except Exception:  # noqa: BLE001 — dispatch must never break finding writes
            logger.exception("auto-dispatch failed for finding %s", finding_pk)

    transaction.on_commit(_run)
