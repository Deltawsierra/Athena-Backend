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
  finding (and is naturally inert in the rolled-back test transactions). The
  decision trigger a pause fires goes further: it runs on a background thread
  after the pause has answered, and what it has not finished stays recorded until
  it has (see the end of this module).
- **The transport is injected.** :func:`dispatch_finding` takes a
  ``transport_factory``; production builds a :class:`~assurance.connectors.RequestsTransport`,
  tests pass a fake. The real transport is built **only** for an operational
  binding, which requires a configured key + credential, so nothing reaches the
  network by default or in tests.
"""

from __future__ import annotations

import hashlib
import logging
import threading
import time
import uuid
from datetime import timedelta

from django.conf import settings
from django.db import connections, transaction
from django.db.models import F, Q
from django.utils import timezone

from .models import (
    RESOLVED_FINDING_STATUSES,
    ConnectorBinding,
    DecisionDispatchDue,
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
    # The epoch in force is the RECONCILED decision. A keyring rotation can leave
    # the stored one stale, and every surface that publishes the decision
    # reconciles first -- so without this the fence compared against a decision
    # the receipt no longer reported, and whether a retry was held depended on
    # whether some reader had happened to come by first.
    from .decision import current_decision

    current_decision(finding.deployment)
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
    # The operation's durable id travels with it wherever the system can
    # deduplicate on one, so a second push of it is not a second ticket there.
    result = connector.push_finding(
        finding, transport=transport, operation_id=operation_id(finding, binding.connector)
    )
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


def dispatch_finding(finding, *, trigger, transport_factory=None, before_push=None):
    """Dispatch one finding to every connector bound to its deployment.

    Returns the list of :class:`~assurance.models.DispatchAttempt` records (one per
    binding). Never raises: each connector is dispatched in its own guard, so one
    connector's failure is recorded as ``failed`` and never affects the others or
    the caller. This is the low-level worker — the policy gate (is the policy
    enabled, does the finding qualify) lives in the callers below, so this stays
    directly testable.

    ``before_push``: asked before each connector, and when it answers false nothing
    more is dispatched -- the decision trigger's check that the decision which asked
    for the push still holds. It must not raise."""
    from .crypto import encryption_available

    key_ok = encryption_available()
    attempts = []
    for binding in ConnectorBinding.objects.filter(deployment=finding.deployment):
        if before_push is not None and not before_push():
            break
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


def _blocking_decision_policy(deployment, decision=None):
    """The policy the decision trigger dispatches ``deployment`` under, or ``None``
    when it does not: auto-dispatch off, no enabled policy opting into the trigger,
    a decision that is not blocking, or no connector bound. ``decision``: the one
    to judge, when it is not yet the instance's own."""
    if not _auto_dispatch_enabled():
        return None
    if (deployment.decision if decision is None else decision) not in _BLOCKING_DECISIONS:
        return None
    policy = DispatchPolicy.objects.filter(deployment=deployment, enabled=True).first()
    if policy is None or not policy.on_blocking_decision:
        return None
    if not ConnectorBinding.objects.filter(deployment=deployment).exists():
        return None
    return policy


def dispatch_for_blocking_decision(deployment, *, transport_factory=None, before_push=None):
    """The decision trigger: when a deployment's decision has entered a blocking
    state and its policy opts into it, dispatch the deployment's active qualifying
    findings. Idempotent and inert-by-default like the severity trigger.

    Synchronous, and as slow as the connectors it pushes to. No stop calls it: the
    recompute route schedules it to run after its answer
    (:func:`schedule_blocking_decision_dispatch`). ``before_push`` is asked before
    every push (:func:`dispatch_finding`); once it has answered false, nothing more
    is pushed."""
    policy = _blocking_decision_policy(deployment)
    if policy is None:
        return []
    attempts = []
    findings = (
        deployment.findings.exclude(status__in=_RESOLVED_STATUSES).order_by("pk")
    )
    for finding in findings:
        if before_push is not None and getattr(before_push, "halted", None):
            break
        if not policy.finding_qualifies(finding):
            continue
        attempts.extend(
            dispatch_finding(
                finding,
                trigger=DispatchAttempt.Trigger.BLOCKING_DECISION,
                transport_factory=transport_factory,
                before_push=before_push,
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


# ---------------------------------------------------------------------------
# The decision trigger after a stop: answered first, dispatched after, never lost
# ---------------------------------------------------------------------------
#
# A pause is a stop, and the pause route used to answer only after this dispatch
# had pushed every qualifying finding to every connector. It was scheduled "on
# commit", but the route runs in autocommit, where a commit hook runs at once, in
# the request: a pause of a deployment with three findings and a connector that
# hangs for five seconds answered after fifteen. With the transport's (3.05, 10)
# second timeout, one hung ticketing system held a pause for thirteen seconds per
# finding -- and nothing may delay a stop.
#
# Now the stop only RECORDS that the dispatch is owed -- a `DecisionDispatchDue`
# row, written in the stop's own transaction, in a savepoint whose failure is
# logged and swallowed -- and schedules it. After the stop commits, the dispatch
# runs on a background thread, one per deployment at a time in a process; the stop
# has already answered by then, and nothing the stop does waits on the thread, a
# connector, or anything the run writes.
#
# A run CLAIMS the row before it pushes anything (`running_until`, `run_token`), so
# the thread and `manage.py retry_blocking_dispatches` -- or two processes -- never
# push for one deployment at once, and a claim a crashed runner left lapses. Before
# every push the run checks that its claim still holds and that the decision which
# asked for the dispatch still does; once either does not, it pushes nothing more.
# It deletes the row only once a run finishes with no push left failed and no stop
# has asked again since it began. Every push keeps its own `DispatchAttempt`.

#: Seconds to wait before each retry, in the background thread, of a run that did
#: not settle. After the last one the row stays for ``retry_blocking_dispatches``.
RETRY_DELAYS: tuple[float, ...] = (2.0, 8.0)

#: How long a run's claim on an owed dispatch lasts unless renewed. A run renews it
#: before a push once :data:`CLAIM_RENEW_AFTER` seconds have passed since it last
#: did, and between two such checks it makes one push -- at most the transport's
#: (3.05, 10) seconds, plus the database's 20 second busy timeout to record it -- so
#: only a runner that has died lets it lapse. A process that exits mid-run leaves
#: its claim, and the next runner takes the dispatch back at most this long after.
CLAIM_SECONDS = 120.0
CLAIM_RENEW_AFTER = 30.0

#: The name every background dispatch thread starts with, then the deployment id.
THREAD_PREFIX = "assurance-dispatch-"

#: What a run reports for a deployment.
SETTLED = "settled"  #: nothing is owed any more
OWED = "owed"  #: still owed: a push failed, or the run raised
ELSEWHERE = "running elsewhere"  #: another runner holds the claim and settles it
DISABLED = "owed; auto-dispatch is disabled"  #: kept, untouched, until it is enabled

#: Deployments with a background dispatch thread in this process, mapped to whether
#: a stop asked again while it ran -- so a flood of stops of one deployment starts
#: one thread, which runs once more for all of them, rather than one per stop.
_JOBS: dict[int, bool] = {}
_JOBS_LOCK = threading.Lock()

#: How many background runs push at once in one process. A flood of stops across
#: many deployments starts a thread for each, and each run competes with the
#: process's requests -- stops among them -- for the interpreter and the database's
#: one writer. The rest wait here, asleep, their dispatch already recorded as owed.
MAX_CONCURRENT_RUNS = 4
_RUN_SLOTS = threading.BoundedSemaphore(MAX_CONCURRENT_RUNS)

#: The longest ``last_error`` kept on a row.
_ERROR_LIMIT = 2000


def _auto_dispatch_enabled() -> bool:
    return bool(getattr(settings, "ASSURANCE_AUTO_DISPATCH_ENABLED", True))


def record_blocking_dispatch_owed(deployment, decision) -> None:
    """Record, in the stop's own transaction, that ``decision`` owes the decision
    trigger's dispatch -- so that it is durable the moment the stop is, and a
    process that exits right after the stop answers cannot lose it.

    Passed by the recompute route to :func:`~assurance.decision.recompute_decision`,
    which calls it under the row lock after the decision is written. It adds a few
    indexed reads and one write to a transaction that already holds the write lock,
    and waits on nothing else: no connector, no thread. Written in a savepoint, and
    any failure is logged and swallowed -- a stop never fails, or waits, because its
    dispatch could not be recorded; the background run records it then, and says so
    if it cannot either. Never raises.
    """
    try:
        if not _auto_dispatch_enabled() or decision not in _BLOCKING_DECISIONS:
            return
        with transaction.atomic():
            if _blocking_decision_policy(deployment, decision) is None:
                return
            asked = DecisionDispatchDue.objects.filter(deployment_id=deployment.pk).update(
                requests=F("requests") + 1
            )
            if not asked:
                DecisionDispatchDue.objects.create(
                    deployment_id=deployment.pk, owed_since=timezone.now(), requests=1
                )
    except Exception:  # noqa: BLE001 - a stop never fails on its dispatch's record
        logger.exception(
            "could not record the blocking-decision dispatch for deployment %s in its stop's "
            "transaction; the stop stands, and the background run records it",
            getattr(deployment, "pk", "?"),
        )


def _owed_row(deployment_id):
    return DecisionDispatchDue.objects.filter(deployment_id=deployment_id)


class _Claim:
    """One run's claim on a deployment's owed dispatch, and the check made before
    every push under it (``before_push``): the claim is still this run's, auto-
    dispatch is still on, and the decision that asked for the dispatch still holds.

    ``halted`` says why the run stopped pushing: :data:`WITHDRAWN` (the decision no
    longer asks for it), :data:`LOST` (another runner holds the row now, or it is
    gone), :data:`DISABLED`, or what went wrong making the check. The check never
    raises: a check that cannot be made halts the run -- a push is never made on an
    authority nobody could confirm.
    """

    WITHDRAWN = "withdrawn"
    LOST = "lost"

    def __init__(self, deployment, token, until):
        self.deployment = deployment
        self.token = token
        self.until = until
        self.halted = None

    def mine(self):
        return _owed_row(self.deployment.pk).filter(run_token=self.token)

    def __call__(self) -> bool:
        if self.halted:
            return False
        try:
            now = timezone.now()
            if (self.until - now).total_seconds() < CLAIM_SECONDS - CLAIM_RENEW_AFTER:
                until = now + timedelta(seconds=CLAIM_SECONDS)
                if not self.mine().update(running_until=until):
                    self.halted = self.LOST
                    return False
                self.until = until
            if not _auto_dispatch_enabled():
                self.halted = DISABLED
                return False
            # One read: the claim is still this run's, and the decision and the
            # policy as they stand now.
            state = (
                self.mine()
                .values_list(
                    "deployment__decision",
                    "deployment__dispatch_policy__enabled",
                    "deployment__dispatch_policy__on_blocking_decision",
                )
                .first()
            )
            if state is None:
                self.halted = self.LOST
                return False
            decision, enabled, opted_in = state
            if decision not in _BLOCKING_DECISIONS or not (enabled and opted_in):
                self.halted = self.WITHDRAWN
                return False
            if decision != self.deployment.decision:
                # Moved between blocking decisions: the instance every finding in
                # this run shares is refreshed whole, so each push records the
                # authority in force.
                self.deployment.refresh_from_db()
        except Exception as exc:  # noqa: BLE001 - halts the run; recorded on the row
            logger.exception(
                "the check before a blocking-decision push for deployment %s failed", self.deployment.pk
            )
            self.halted = f"the check before a push raised {type(exc).__name__}: {exc}"
            return False
        return True

    def release(self) -> None:
        self.mine().update(running_until=None, run_token="")

    def still_owed(self, detail: str) -> None:
        """Record that this run finished without settling it, and let the claim go."""
        self.mine().update(
            runs=F("runs") + 1,
            last_run_at=timezone.now(),
            last_error=detail[:_ERROR_LIMIT],
            running_until=None,
            run_token="",
        )

    def settle(self, asked) -> bool:
        """Delete the row if no stop has asked again since this run began."""
        deleted, _ = self.mine().filter(requests=asked).delete()
        return bool(deleted)


def _claim(deployment, token):
    """Claim ``deployment``'s owed dispatch for the runner ``token``: a conditional
    write that succeeds only when no other runner's claim is live. ``None`` when one
    is. A runner may claim again what it already holds (its own earlier run)."""
    now = timezone.now()
    until = now + timedelta(seconds=CLAIM_SECONDS)
    claimed = (
        _owed_row(deployment.pk)
        .filter(Q(running_until__isnull=True) | Q(running_until__lte=now) | Q(run_token=token))
        .update(running_until=until, run_token=token)
    )
    return _Claim(deployment, token, until) if claimed else None


_RERUN = "rerun"


def _run_claimed(claim, asked, transport_factory) -> str:
    try:
        attempts = dispatch_for_blocking_decision(
            claim.deployment, transport_factory=transport_factory, before_push=claim
        )
    except Exception as exc:  # noqa: BLE001 - recorded on the row and retried, never lost
        logger.exception("blocking-decision dispatch failed for deployment %s", claim.deployment.pk)
        claim.still_owed(f"the dispatch raised {type(exc).__name__}: {exc}")
        return OWED
    if claim.halted == _Claim.LOST:
        return ELSEWHERE
    if claim.halted == DISABLED or not _auto_dispatch_enabled():
        claim.release()
        return DISABLED
    failed = [a for a in attempts if a.outcome == DispatchAttempt.Outcome.FAILED]
    if claim.halted not in (None, _Claim.WITHDRAWN):
        claim.still_owed(claim.halted)
        return OWED
    if failed and claim.halted is None:
        detail = f"{len(failed)} push(es) failed: " + "; ".join(
            f"{a.connector} for finding {a.finding_id}: {a.detail}" for a in failed
        )
        logger.error("blocking-decision dispatch for deployment %s: %s", claim.deployment.pk, detail)
        claim.still_owed(detail)
        return OWED
    # Done -- every push sent, skipped, or UNKNOWN (which waits for reconciliation
    # rather than a retry) -- or no longer asked for. Settled, unless a stop asked
    # again while it ran: then it runs again for that stop.
    if claim.settle(asked):
        return SETTLED
    claim.release()
    return _RERUN


def run_blocking_decision_dispatch(deployment_id, *, transport_factory=None, token=None) -> str:
    """Run the decision trigger for one deployment, as it stands now, and record
    whether it is still owed. Returns :data:`SETTLED`, :data:`OWED`,
    :data:`ELSEWHERE` or :data:`DISABLED`.

    The row is claimed before any push, so two runners never push for one
    deployment at once; ``token`` names the runner (a fresh one when omitted). A
    row the stop could not write is written here first. Nothing owed under the
    decision in force (lifted, the policy switched off, the deployment gone)
    settles it -- checked before every push, not only at the start, so a run stops
    pushing once the decision that asked for it is withdrawn. With auto-dispatch
    switched off nothing is pushed and nothing owed is dropped. A run that raises,
    or leaves a push FAILED, keeps the row with what went wrong; an UNKNOWN push is
    not retried here -- it waits for reconciliation, as every uncertain push does.
    """
    token = token or uuid.uuid4().hex
    deployment = Deployment.objects.filter(pk=deployment_id).first()
    if deployment is None:
        return SETTLED  # its row went with it
    while True:
        asked = _owed_row(deployment_id).values_list("requests", flat=True).first()
        if not _auto_dispatch_enabled():
            return SETTLED if asked is None else DISABLED
        if _blocking_decision_policy(deployment) is None:
            # Asked for under a decision that no longer holds: settled -- unless a
            # stop has asked again since this read, which a changed count shows.
            if asked is None or _owed_row(deployment_id).filter(requests=asked).delete()[0]:
                return SETTLED
            deployment.refresh_from_db()
            continue
        if asked is None:
            # Its stop could not record it, or `--deployment` asked for one nobody did.
            DecisionDispatchDue.objects.get_or_create(
                deployment_id=deployment_id, defaults={"owed_since": timezone.now(), "requests": 1}
            )
            continue
        claim = _claim(deployment, token)
        if claim is None:
            return ELSEWHERE
        outcome = _run_claimed(claim, asked, transport_factory)
        if outcome != _RERUN:
            return outcome
        deployment.refresh_from_db()


def _log_still_owed(deployment_id, runs: int) -> None:
    """The last word on a dispatch the background runs did not settle -- true in
    every case, because it looks before it says the dispatch is recorded."""
    try:
        recorded = _owed_row(deployment_id).exists()
    except Exception:  # noqa: BLE001 - reported below as not confirmed
        recorded = None
    if recorded:
        logger.error(
            "blocking-decision dispatch for deployment %s is still owed after %d run(s); it stays "
            "recorded and `manage.py retry_blocking_dispatches` retries it",
            deployment_id,
            runs,
        )
    else:
        logger.error(
            "blocking-decision dispatch for deployment %s is still owed after %d run(s), and %s: "
            "run `manage.py retry_blocking_dispatches --deployment %s`",
            deployment_id,
            runs,
            "no record of it could be written" if recorded is False else "whether it is recorded could not be read",
            deployment_id,
        )


def _run_until_settled(deployment_id, token) -> None:
    """Run it, and again after each of :data:`RETRY_DELAYS` while it is owed. Stops
    when it is settled, when another runner holds it, or when auto-dispatch is off."""
    runs = 0
    for delay in (0.0, *RETRY_DELAYS):
        if delay:
            time.sleep(delay)
        runs += 1
        try:
            with _RUN_SLOTS:
                outcome = run_blocking_decision_dispatch(deployment_id, token=token)
        except Exception:  # noqa: BLE001 - e.g. the database is unreachable; retried
            logger.exception(
                "blocking-decision dispatch run for deployment %s did not complete", deployment_id
            )
            continue
        if outcome in (SETTLED, ELSEWHERE):
            return
        if outcome == DISABLED:
            logger.warning(
                "blocking-decision dispatch for deployment %s is owed and auto-dispatch is disabled; "
                "it stays recorded and runs once it is enabled again",
                deployment_id,
            )
            return
    _log_still_owed(deployment_id, runs)


def _blocking_dispatch_job(deployment_id) -> None:
    """The background thread: run until settled, and once more for every stop that
    asked while it ran."""
    token = uuid.uuid4().hex
    finished = False
    try:
        while True:
            _run_until_settled(deployment_id, token)
            with _JOBS_LOCK:
                if not _JOBS.get(deployment_id):
                    _JOBS.pop(deployment_id, None)
                    finished = True
                    return
                _JOBS[deployment_id] = False
    finally:
        if not finished:
            with _JOBS_LOCK:
                _JOBS.pop(deployment_id, None)
        # This thread's own connections, which nothing else would close.
        connections.close_all()


def start_blocking_decision_dispatch(deployment_id) -> None:
    """Start the background run for ``deployment_id`` -- or, when one is running,
    ask it to run once more. Returns at once and never raises: it is called in a
    stop's request, after the stop has committed.

    A daemon thread, on purpose: it never holds a worker's exit, and it need not,
    because the stop has already recorded the dispatch as owed. A process that exits
    mid-run leaves the row, and the claim lapses for the next runner."""
    try:
        with _JOBS_LOCK:
            if deployment_id in _JOBS:
                _JOBS[deployment_id] = True
                return
            _JOBS[deployment_id] = False
        thread = threading.Thread(
            target=_blocking_dispatch_job,
            args=(deployment_id,),
            name=f"{THREAD_PREFIX}{deployment_id}",
            daemon=True,
        )
        thread.start()
    except Exception:  # noqa: BLE001 - a stop has committed; it must still answer
        with _JOBS_LOCK:
            _JOBS.pop(deployment_id, None)
        logger.exception(
            "could not start the blocking-decision dispatch for deployment %s; it did not run -- "
            "`manage.py retry_blocking_dispatches --deployment %s` runs it",
            deployment_id,
            deployment_id,
        )


class _BlockingDispatchAfterCommit:
    """One deployment's blocking-decision dispatch, started when its stop commits.

    A class rather than a closure so a test can find it among the commit hooks and
    ask which deployment it is for.
    """

    __slots__ = ("deployment_id",)

    def __init__(self, deployment_id):
        self.deployment_id = deployment_id

    def __call__(self):
        start_blocking_decision_dispatch(self.deployment_id)


def schedule_blocking_decision_dispatch(deployment_id) -> None:
    """Run the decision trigger for ``deployment_id`` after the current transaction
    commits, in the background: the caller never waits on a connector.

    The one call the recompute route makes -- pause, lift, or a plain recompute --
    after its decision has committed. Nothing with auto-dispatch switched off.
    Never raises."""
    if not _auto_dispatch_enabled():
        return
    try:
        transaction.on_commit(_BlockingDispatchAfterCommit(deployment_id))
    except Exception:  # noqa: BLE001 - a stop has committed; it must still answer
        logger.exception(
            "could not schedule the blocking-decision dispatch for deployment %s -- "
            "`manage.py retry_blocking_dispatches --deployment %s` runs it",
            deployment_id,
            deployment_id,
        )


def retry_owed_blocking_dispatches(deployment_ids=None, *, transport_factory=None) -> dict:
    """Run every blocking-decision dispatch still owed -- or those of
    ``deployment_ids``, owed or not -- here and now, as one runner. Returns
    ``{deployment id: outcome}`` (:data:`SETTLED`, :data:`OWED`, :data:`ELSEWHERE`,
    :data:`DISABLED`); a run that raises counts as :data:`OWED` and does not stop
    the rest. One another runner holds is left to it: never pushed twice at once."""
    token = uuid.uuid4().hex
    if deployment_ids is None:
        deployment_ids = list(
            DecisionDispatchDue.objects.order_by("owed_since").values_list("deployment_id", flat=True)
        )
    outcomes = {}
    for deployment_id in deployment_ids:
        try:
            outcomes[deployment_id] = run_blocking_decision_dispatch(
                deployment_id, transport_factory=transport_factory, token=token
            )
        except Exception:  # noqa: BLE001 - reported per deployment; the rest still run
            logger.exception("blocking-decision dispatch retry for deployment %s did not complete", deployment_id)
            outcomes[deployment_id] = OWED
    return outcomes
