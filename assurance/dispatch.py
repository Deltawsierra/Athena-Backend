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

import hashlib
import logging

from django.conf import settings
from django.db import transaction
from django.utils import timezone

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


# Domain tag for the operation identity, so an id from this scheme can never be
# mistaken for one from another.
_OPERATION_DOMAIN = "athena.dispatch_operation/1"


def operation_id(finding, connector: str) -> str:
    """The durable identity of "push THIS finding to THIS connector".

    Deterministic, so the same operation retried is the same operation and the
    provider can deduplicate it; distinct per (finding, connector), so one
    operation is never mistaken for another. Derived from the finding's UUID rather
    than its primary key, because the UUID is the identity that survives export and
    re-import.
    """
    raw = f"{_OPERATION_DOMAIN}\x1f{finding.uuid}\x1f{connector}"
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def policy_epoch(deployment) -> str:
    """The authority this dispatch is made under, as a short stable string.

    Today the deployment's standing decision is the whole of it: a dispatch
    authorized while a deployment was NOT_RECOMMENDED was authorized under a
    different posture than one authorized while it was READY, and a retry that
    crosses that boundary is executing an old decision.

    It is now enforced as well as recorded -- see :func:`_epoch_moved`. An unset
    decision reads as ``"unassessed"`` rather than blank, so a live deployment
    never produces the empty epoch that means "nobody wrote one down".
    """
    return str(getattr(deployment, "decision", "") or "unassessed")


def _epoch_moved(existing, finding) -> tuple[str, str] | None:
    """The (authorized, now) pair when a retry would cross an authority boundary.

    ``None`` means it would not, and there are three ways for that to be true:

    * there is no earlier attempt -- a first dispatch records the epoch in force,
      it does not judge it;
    * the earlier attempt has no epoch recorded. Rows predate the field, and blank
      is not an epoch that moved, it is one nobody wrote down. Refusing on it would
      block every retry of every historical attempt, which is a bigger outage than
      the defect;
    * the epoch is the same, which is the ordinary retry the FAILED outcome exists
      to license.

    Only the *automatic* triggers are held. A MANUAL dispatch is a person deciding
    to push under the authority in force now, which is exactly what
    re-authorization is -- and without that escape hatch the refusal would be
    permanent, because the recorded epoch and the current one would disagree
    forever. A permanent block nobody can clear is a worse failure than the one
    this closes.
    """
    if existing is None or not existing.policy_epoch:
        return None
    now = policy_epoch(finding.deployment)
    if existing.policy_epoch == now:
        return None
    return existing.policy_epoch, now


def reconcile_attempt(attempt, *, readback=None) -> DispatchAttempt:
    """Resolve an uncertain attempt against the provider. Returns the attempt.

    ``readback`` is called with the attempt's ``operation_id`` and must return
    ``True`` (the provider has it), ``False`` (it does not), or ``None`` (it cannot
    say). Only the first two resolve the attempt; ``None`` -- and no readback at
    all -- leaves it UNKNOWN, because a reconciliation that cannot reach the
    provider has learned nothing, and writing an answer anyway is the failure this
    whole state exists to prevent.

    An attempt that is not uncertain is returned untouched: reconciliation is not a
    way to move a SENT or FAILED attempt.
    """
    if not attempt.is_uncertain:
        return attempt
    if readback is None:
        return attempt
    try:
        answer = readback(attempt.operation_id)
    except Exception as exc:  # noqa: BLE001 - a failed readback resolves nothing
        logger.warning("readback failed for operation %s: %s", attempt.operation_id, exc)
        return attempt
    if answer is None:
        return attempt

    attempt.outcome = (
        DispatchAttempt.Outcome.SENT if answer else DispatchAttempt.Outcome.FAILED
    )
    attempt.reconciled_at = timezone.now()
    attempt.reconciled_detail = (
        f"reconciled against the provider by operation id: "
        f"{'the provider has it' if answer else 'the provider does not have it'}"
    )
    attempt.save(
        update_fields=["outcome", "reconciled_at", "reconciled_detail", "updated_at"]
    )
    return attempt


def _record(finding, binding, *, trigger, outcome, detail, external_ref=None, reauthorize=False):
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
            "operation_id": operation_id(finding, binding.connector),
            "policy_epoch": policy_epoch(finding.deployment),
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
        # The operation id is the durable identity of this operation and never
        # changes -- that is the whole point of it. Backfilled if the row predates
        # it, so an old attempt can still be reconciled.
        if not obj.operation_id:
            obj.operation_id = operation_id(finding, binding.connector)
        # The epoch is the AUTHORIZING one and is not rewritten by the attempt it
        # authorizes. This used to assign unconditionally, on the reasoning that a
        # retry happens under whatever authority holds now -- true about the retry,
        # and it destroyed the only record that anything had moved, in the same
        # save that crossed the boundary. `_epoch_moved` compares against this
        # field, so a field the retry overwrites cannot be evidence about the retry.
        #
        # Backfilled when blank, like `operation_id` above, so a row predating the
        # field gets one; advanced only when the caller says this attempt IS the
        # re-authorization.
        if reauthorize or not obj.policy_epoch:
            obj.policy_epoch = policy_epoch(finding.deployment)
        obj.save(
            update_fields=[
                "deployment",
                "binding",
                "outcome",
                "trigger",
                "detail",
                "external_ref",
                "operation_id",
                "policy_epoch",
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
    if existing is not None and existing.blocks_retry:
        # Either already accepted (never push the same finding to the same
        # connector twice) or in an UNRESOLVED uncertain state, where the provider
        # may have committed it and a retry would create a second ticket nobody
        # asked for. The second case used to be retried on every qualifying
        # trigger, because "not accepted" and "safe to retry" were the same test.
        return existing

    # The authority check, before anything is built or sent. An operation
    # authorized under one epoch and retried under another is executing a decision
    # that was withdrawn -- the rule `DispatchAttempt.policy_epoch` states on the
    # field itself, and which nothing enforced: the field was written in two places
    # and read in none.
    #
    # The reachable sequence is ordinary operation throughout. A push is authorized
    # while the deployment is READY; the answer is lost, so the attempt is UNKNOWN
    # and held. An operator moves the deployment to NOT_RECOMMENDED. Reconciliation
    # finds the provider does not have it, so the attempt resolves to FAILED --
    # neither terminal nor uncertain, so retryable again. The next trigger then
    # created the ticket on the customer's system under an authority that had been
    # withdrawn, and overwrote the epoch in the same save, so nothing recorded that
    # it had moved.
    moved = _epoch_moved(existing, finding)
    if moved is not None and trigger != DispatchAttempt.Trigger.MANUAL:
        authorized, now = moved
        return _record(
            finding,
            binding,
            trigger=trigger,
            outcome=DispatchAttempt.Outcome.SKIPPED_EPOCH_MOVED,
            detail=(
                f"authorized under policy epoch {authorized!r}, which is now "
                f"{now!r} — this retry would execute a decision made under an "
                "authority that no longer holds. Dispatch it manually to "
                "re-authorize it under the epoch in force."
            ),
        )

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
    if result.ok:
        outcome = DispatchAttempt.Outcome.SENT
    elif result.uncertain:
        # The request may have been received and committed before the answer was
        # lost. Calling this FAILED would license a retry that double-executes on
        # the customer's system; calling it SENT would claim a ticket that may not
        # exist. It is neither, and it says so until somebody reconciles it.
        outcome = DispatchAttempt.Outcome.UNKNOWN
    else:
        outcome = DispatchAttempt.Outcome.FAILED
    return _record(
        finding,
        binding,
        trigger=trigger,
        outcome=outcome,
        detail=result.detail,
        # A manual dispatch across a moved epoch is a person choosing to push under
        # the authority in force now, which is what re-authorization is. Only then
        # does the recorded epoch advance -- an automatic retry never reaches here
        # with a moved epoch, and one under the SAME epoch has nothing to advance.
        reauthorize=moved is not None,
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
        except Exception as exc:  # a binding error is recorded, never raised
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
            except Exception:  # even recording must not raise out
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
        except Exception:  # dispatch must never break finding writes
            logger.exception("auto-dispatch failed for finding %s", finding_pk)

    transaction.on_commit(_run)
