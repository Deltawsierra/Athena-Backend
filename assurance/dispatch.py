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
import math
import os
import threading
import time
import uuid
from datetime import timedelta

from django.conf import settings
from django.db import connections, transaction
from django.db.models import F, Q
from django.utils import timezone

from .markers import MARKER_VERSION, Marker
from .models import (
    RESOLVED_FINDING_STATUSES,
    ConnectorBinding,
    DecisionDispatchDue,
    Deployment,
    DispatchAttempt,
    DispatchPolicy,
    Finding,
)
from . import oplog as _oplog
from .oplog import emit_now, log_later

__all__ = ["emit_now", "log_later"]

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


def _record(finding, binding, *, trigger, outcome, detail, external_ref=None, reauthorize=False, marker=None):
    """Create or update the single ``(finding, connector)`` attempt record. The
    detail is human-readable and never a secret; ``attempts`` counts retries of a
    not-yet-sent record. ``marker``: the :class:`~assurance.markers.Marker` the push
    about to be made carries, recorded with its version."""
    ref = external_ref or ""
    marked = {} if marker is None else {"marker": marker.text, "marker_version": marker.version}
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
            **marked,
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
        fields = [
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
        for name, value in marked.items():
            setattr(obj, name, value)
            fields.append(name)
        if outcome in DispatchAttempt.UNCERTAIN_OUTCOMES:
            # Uncertain again -- a new request whose end nobody has reconciled, or a
            # hold -- so an earlier reconciliation of this attempt says nothing
            # about it: it is cleared, which is what lets a person reconcile it
            # again and makes the next run look before anything is pushed. In the
            # same statement, so no crash can leave one beside a stale one.
            obj.reconciled_at, obj.reconciled_detail = None, ""
            fields += ["reconciled_at", "reconciled_detail"]
        obj.save(update_fields=fields)
    return obj


def _note_ignored(look, finding, connector_name) -> None:
    """Name, at WARNING, the issues a look matched that are not this installation's."""
    if look.ignored:
        refs = ", ".join(str(r) for r in look.ignored[:20])
        more = f" and {len(look.ignored) - 20} more" if len(look.ignored) > 20 else ""
        logger.warning(
            "%s: %d issue(s) matched finding %s but are not this installation's -- a copied label, a "
            "planted or edited body, another installation's marker, or an older format created after "
            "this one began tagging -- and were ignored: %s%s",
            connector_name, len(look.ignored), finding.uuid, refs, more,
        )


def _possible_note(look, connector_name) -> str:
    """The line a ticket filed beside possible duplicates carries: which issues an
    earlier release may have made for the finding. Empty when there are none."""
    if not look.possible:
        return ""
    refs = ", ".join(str(r) for r in look.possible[:20])
    more = f" and {len(look.possible) - 20} more" if len(look.possible) > 20 else ""
    return (
        f"Possible duplicate: {connector_name} issue(s) {refs}{more}, in an older Athena marker format that "
        "cannot be verified, mention this finding and may be an earlier release's ticket for it. Close one of them."
    )


def _hold(attempt, why: str):
    """Keep an uncertain attempt held, and say why on it (without touching its age)."""
    detail = (
        f"held, not pushed again: {why}; reconcile it (manage.py reconcile_dispatch_attempt {attempt.uuid} "
        "--provider-has-it --external-ref REF | --provider-lacks-it, --by NAME)"
    )[:_ERROR_LIMIT]
    if attempt.detail != detail:
        DispatchAttempt.objects.filter(pk=attempt.pk, outcome=attempt.outcome).update(detail=detail)
        attempt.detail = detail
    return attempt


def _resolve_uncertain(attempt, connector, transport, finding):
    """Settle an attempt whose push may have reached the provider -- one whose
    answer was lost (UNKNOWN), or one recorded as SENDING by a runner that never
    recorded how it ended -- by looking for the issue itself. Returns
    ``(attempt, closed_ref, look)``: the attempt SENT with the issue it found,
    FAILED when the provider certainly has none, or unchanged (held) when the look
    could not tell; ``closed_ref`` when the issue was found and the tracker has
    closed it, which the caller records; and the look, whose possible duplicates
    the push that follows names.

    It looks for the marker the push CARRIED (recorded on the attempt), and for
    this connector's marker under every id this installation has used. "None
    found" is trusted only when the push carried the current, verifiable format. A
    push made by an earlier release -- no marker recorded -- is looked for in every
    format this code has written; an issue in an older format is never adopted
    (only a recorded one or a verified one is), so when the look names possible
    duplicates it is pushed again, long enough after, as a ticket that names them;
    when it finds nothing at all it is held, never pushed again blind."""
    carried = Marker.parse(attempt.marker or "") if attempt.marker_version == MARKER_VERSION else None
    look = connector.find_existing(
        finding, transport=transport, known_ref=attempt.external_ref or None, expected=carried, legacy=carried is None
    )
    _note_ignored(look, finding, attempt.connector)
    if look.state == look.FOUND:
        if look.closed:
            return attempt, look.external_ref, look
        # This installation's issue for it (its marker verifies, or it is the one
        # recorded): the push landed.
        attempt.outcome = DispatchAttempt.Outcome.SENT
        attempt.external_ref = look.external_ref or attempt.external_ref
    elif look.state == look.ABSENT and carried is None and not look.possible:
        return _hold(
            attempt,
            "it was pushed by an earlier release, whose marker cannot be verified, and no issue of it was "
            f"found ({look.detail})",
        ), None, look
    elif look.state == look.ABSENT and timezone.now() - attempt.updated_at > timedelta(seconds=CLAIM_SECONDS):
        # Absent, and long enough after the request that it is not still on its
        # way (a request the transport stopped waiting for can still arrive): it
        # certainly never landed, so it may be pushed again. An earlier release's
        # push whose look named possible duplicates is pushed again too -- as a
        # ticket that names them -- never held on issues anyone could have edited.
        attempt.outcome = DispatchAttempt.Outcome.FAILED
    else:
        return attempt, None, look
    attempt.reconciled_at = timezone.now()
    attempt.reconciled_detail = f"reconciled by looking for the issue: {look.detail}"
    attempt.save(update_fields=["outcome", "external_ref", "reconciled_at", "reconciled_detail", "updated_at"])
    return attempt, None, look


def _closed_issue(finding, binding, connector, transport, ref, *, trigger, before_push, reauthorize=False):
    """The finding's issue ``ref`` exists and the tracker has closed it -- it says
    the work is done -- while the finding is dispatched again. It is not reopened
    (a person's call) and no second issue is filed: it is told, by a comment, and
    the attempt is recorded SENT_TO_CLOSED, with a WARNING, so the operator sees
    that the tracker and the decision disagree. ``None`` when ``before_push`` stopped
    it before the comment (nothing is recorded then)."""
    if before_push is not None and not before_push():
        return None
    deployment = finding.deployment
    decision = policy_epoch(deployment)
    if trigger == DispatchAttempt.Trigger.BLOCKING_DECISION:
        situation = f"while deployment {deployment.name}'s decision ({decision}) blocks on this finding"
    else:
        situation = "while the finding is dispatched again"
    text = (
        f"Athena: finding {finding.uuid} ({getattr(finding, 'title', '')}) is being dispatched again: "
        f"deployment {deployment.name} ({decision}). This issue is closed; it is not reopened automatically."
    )
    result = connector.comment_on(ref, text, transport=transport)
    if result is None:
        said = f"{binding.connector} takes no comment here, so it was not told"
    elif result.ok:
        said = "commented on it; it is not reopened"
    else:
        said = f"the comment on it failed ({result.detail}); it is not reopened -- look at it"
    detail = f"the tracker says this is done: {binding.connector} issue {ref} is closed, {situation}; {said}"
    attempt = _record(
        finding,
        binding,
        trigger=trigger,
        outcome=DispatchAttempt.Outcome.SENT_TO_CLOSED,
        detail=detail,
        external_ref=ref,
        reauthorize=reauthorize,
    )
    logger.warning("finding %s on deployment %s: %s", finding.uuid, deployment.pk, detail)
    return attempt


def _dispatch_one(finding, binding, *, trigger, key_ok, transport_factory, before_push=None):
    """Dispatch one finding to one connector binding, honestly. Returns the
    resulting :class:`~assurance.models.DispatchAttempt`, or ``None`` when
    ``before_push`` stopped it before anything was sent. Records a skip (and
    touches no transport) when the binding is disabled, there is no key, or the
    binding is not operational; performs the push only for an operational binding.

    Never twice blind. The attempt is recorded SENDING, with its operation id,
    BEFORE the request goes out, so a runner that finds it later -- a second
    runner, or the next one after a crash -- knows a request may have landed. An
    attempt whose outcome is uncertain is settled by looking for the issue
    (:meth:`~assurance.connectors.Connector.find_existing`) before anything else;
    a system that deduplicates on the operation id is simply sent it again; any
    other stays uncertain, and held, until someone reconciles it."""
    existing = DispatchAttempt.objects.filter(
        finding=finding, connector=binding.connector
    ).first()
    if existing is not None and existing.is_terminal:
        # Already accepted: never push the same finding to the same connector twice.
        return existing
    operational = binding.enabled and key_ok and binding.is_operational()
    transport = connector = None
    # The line the created issue's body carries when the look named possible
    # duplicates (issues in an older format, never adopted).
    note = ""
    if existing is not None and existing.is_uncertain:
        # In an UNRESOLVED uncertain state the provider may have committed it, and a
        # blind retry would create a second ticket nobody asked for. That case used
        # to be retried on every qualifying trigger, because "not accepted" and
        # "safe to retry" were the same test; then it was held forever, because
        # nothing looked. Now it is looked for.
        if not operational:
            return existing
        transport = (transport_factory or _default_transport_factory)()
        connector = binding.build_connector()
        existing, closed_ref, look = _resolve_uncertain(existing, connector, transport, finding)
        note = _possible_note(look, binding.connector)
        if closed_ref is not None:
            # The push landed, and the tracker has closed its issue since.
            return _closed_issue(
                finding, binding, connector, transport, closed_ref, trigger=trigger, before_push=before_push
            )
        if existing.is_terminal:
            return existing
        if existing.is_uncertain and not connector.redelivery_is_idempotent:
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
    # The decision trigger re-authorizes by itself: its run exists because the
    # decision IN FORCE is blocking and the policy asks for this push under it
    # (the run's check confirms both before the push). So an attempt made under
    # an earlier blocking decision -- a pause lifted onto NEEDS_REMEDIATION -- is
    # pushed under the one in force, and the recorded epoch advances to it, rather
    # than being set aside with nothing pushed while the deployment still blocks.
    reauthorized_by_decision = (
        moved is not None
        and trigger == DispatchAttempt.Trigger.BLOCKING_DECISION
        and policy_epoch(finding.deployment) in _BLOCKING_DECISIONS
    )
    if moved is not None and trigger != DispatchAttempt.Trigger.MANUAL and not reauthorized_by_decision:
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
    if transport is None:
        transport = (transport_factory or _default_transport_factory)()
        connector = binding.build_connector()
        if existing is None or existing.outcome == DispatchAttempt.Outcome.FAILED:
            # Before creating anything, look: an issue this installation made for
            # this finding by a push nobody recorded (a manual push, a restored
            # database, an earlier release) is reused, not duplicated. Only this
            # installation's issue is reused -- see `assurance.markers`; a copy or a
            # planted one is ignored, and named. A look that cannot tell does not
            # stop a first push.
            look = connector.find_existing(
                finding, transport=transport, known_ref=(existing.external_ref or None) if existing else None
            )
            _note_ignored(look, finding, binding.connector)
            note = _possible_note(look, binding.connector)
            if look.state == look.FOUND and not look.closed:
                return _record(
                    finding,
                    binding,
                    trigger=trigger,
                    outcome=DispatchAttempt.Outcome.SENT,
                    detail=f"not pushed again: {look.detail}",
                    reauthorize=moved is not None,
                    external_ref=look.external_ref,
                )
            if look.state == look.FOUND:
                return _closed_issue(
                    finding, binding, connector, transport, look.external_ref,
                    trigger=trigger, before_push=before_push, reauthorize=moved is not None,
                )

    op = operation_id(finding, binding.connector)
    marker = connector.marker(finding)
    prior = None
    if existing is not None:
        prior = {
            f: getattr(existing, f)
            for f in (
                "outcome", "detail", "attempts", "trigger", "policy_epoch", "reconciled_at", "reconciled_detail",
                "marker", "marker_version",
            )
        }
    sending = _record(
        finding,
        binding,
        trigger=trigger,
        outcome=DispatchAttempt.Outcome.SENDING,
        detail=f"sending since {timezone.now().isoformat()}: no answer recorded yet",
        # A manual dispatch across a moved epoch is a person choosing to push under
        # the authority in force now, which is what re-authorization is; so is the
        # decision trigger under a blocking decision in force (above). Only then
        # does the recorded epoch advance -- an automatic retry never reaches here
        # with a moved epoch otherwise, and one under the SAME epoch has nothing to
        # advance.
        reauthorize=moved is not None,
        # The marker this push carries: what the look for it, if its answer is
        # lost, searches for and verifies.
        marker=marker,
    )
    # The last check, as close to the request as it can be: the decision that
    # asked for this push still holds. Made after every step that can wait -- the
    # reconciled decision above, the look, the record just written -- so a lift
    # that committed during any of them is seen here, and nothing is sent.
    if before_push is not None and not before_push():
        if prior is None:
            DispatchAttempt.objects.filter(pk=sending.pk, outcome=DispatchAttempt.Outcome.SENDING).delete()
        else:
            DispatchAttempt.objects.filter(pk=sending.pk).update(**prior)
        return None
    # The operation's durable id travels with it wherever the system can
    # deduplicate on one, so a second push of it is not a second ticket there.
    fields = ["outcome", "detail", "external_ref", "updated_at"]
    if before_push is not None and sending.policy_epoch != policy_epoch(finding.deployment):
        # The check just confirmed the decision in force (refreshing it if it had
        # moved): that is the authority this push is made under.
        sending.policy_epoch = policy_epoch(finding.deployment)
        fields.append("policy_epoch")
    if note:
        # Filed beside issues an earlier release may have made -- never adopted,
        # since anyone who can edit an old issue can make it mention the finding:
        # a possible duplicate, named in the new issue and here, never a lost one.
        logger.warning("finding %s: %s", finding.uuid, note)
    result = connector.push_finding(finding, transport=transport, operation_id=op, note=note)
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
    # The same attempt, finished: the SENDING record above already counted it.
    sending.outcome = outcome
    sending.detail = (f"{result.detail}; {note}" if note else result.detail)[:_ERROR_LIMIT]
    sending.external_ref = result.external_ref or ""
    sending.save(update_fields=fields)
    return sending


def dispatch_finding(finding, *, trigger, transport_factory=None, before_push=None):
    """Dispatch one finding to every connector bound to its deployment.

    Returns the list of :class:`~assurance.models.DispatchAttempt` records (one per
    binding). Never raises: each connector is dispatched in its own guard, so one
    connector's failure is recorded as ``failed`` and never affects the others or
    the caller. This is the low-level worker — the policy gate (is the policy
    enabled, does the finding qualify) lives in the callers below, so this stays
    directly testable.

    ``before_push``: asked immediately before each request goes out, and once it
    has answered false nothing more is dispatched -- the decision trigger's check
    that the decision which asked for the push still holds. It must not raise."""
    from .crypto import encryption_available

    key_ok = encryption_available()
    attempts = []
    for binding in ConnectorBinding.objects.filter(deployment=finding.deployment):
        if before_push is not None and getattr(before_push, "halted", None):
            break
        try:
            attempt = _dispatch_one(
                finding,
                binding,
                trigger=trigger,
                key_ok=key_ok,
                transport_factory=transport_factory,
                before_push=before_push,
            )
            if attempt is not None:
                attempts.append(attempt)
        except Exception as exc:  # a binding error is recorded, never raised
            logger.exception(
                "connector dispatch failed for finding %s -> %s",
                getattr(finding, "pk", "?"),
                binding.connector,
            )
            try:
                current = DispatchAttempt.objects.filter(finding=finding, connector=binding.connector).first()
                if current is not None and current.outcome in DispatchAttempt.UNCERTAIN_OUTCOMES:
                    # SENDING (the request may have gone out -- the error came from
                    # recording how it ended) or UNKNOWN: never rewritten as FAILED,
                    # which would license a push nobody knows did not land. It stays
                    # uncertain, to be settled by looking.
                    attempts.append(current)
                    continue
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
# row, written in the stop's own transaction, in a savepoint -- and, when something
# is owed, schedules it. If writing the record ends the stop's transaction, the
# stop is committed again without it (`TransactionLostInHook`), so the record can
# never undo or hide the stop. After the stop commits, the dispatch runs on a
# background thread, one per deployment at a time in a process; the stop has
# already answered by then, and nothing the stop does waits on the thread, a
# connector, or anything the run writes.
#
# A run CLAIMS the row before it pushes anything (`running_until`, `run_token`), so
# the thread, the process's sweeper and `manage.py retry_blocking_dispatches` -- in
# any number of processes -- never push for one deployment at once, and a claim a
# crashed runner left lapses. Immediately before every request it checks that its
# claim still holds and that the decision which asked for the dispatch still does;
# once either does not, it sends nothing more. Every push is recorded SENDING
# before the request goes out, so no runner ever repeats one blind. The row is
# deleted only once a run finishes with nothing left undone (see `_UNDONE`) and no
# stop has asked again since it began.

#: Seconds to wait before each retry, in the background thread, of a run that did
#: not settle. After the last one the row stays for the sweeper and the command.
RETRY_DELAYS: tuple[float, ...] = (2.0, 8.0)

#: How long a run's claim on an owed dispatch lasts unless renewed. A run renews it
#: in its check before a request once :data:`CLAIM_RENEW_AFTER` seconds have passed
#: since it last did. Between two checks it does, at worst: bring the decision
#: current and look for an existing issue (a database wait and a request), record
#: the push SENDING, check, send, and record the end -- see :func:`worst_step_seconds`,
#: about 140 s at the defaults. Kept well inside the claim, so only a runner that
#: has died lets its claim lapse; and even then the SENDING record keeps the next
#: runner from repeating the push blind.
CLAIM_SECONDS = 300.0
CLAIM_RENEW_AFTER = 30.0

#: The name every background dispatch thread starts with, then the deployment id.
THREAD_PREFIX = "assurance-dispatch-"

#: What a run reports for a deployment.
SETTLED = "settled"  #: nothing is owed any more
OWED = "owed"  #: still owed: something is left undone, or the run raised
ELSEWHERE = "running elsewhere"  #: another runner holds the claim and settles it
DISABLED = "owed; auto-dispatch is disabled"  #: kept, untouched, until it is enabled
MISSING = "no such deployment"  #: asked for by id, and there is none

#: Outcomes that leave a dispatch owed: nothing confirms the finding reached the
#: system, and something can still be done about it. FAILED is retried;
#: UNKNOWN/SENDING wait for the issue to be found (or not) by looking, or for a
#: person (`manage.py reconcile_dispatch_attempt`); SKIPPED_NO_KEY needs the key
#: configured; SKIPPED_EPOCH_MOVED needs a manual dispatch to re-authorize it. The
#: others settle: SENT, and a binding an operator disabled or never configured
#: (SKIPPED_DISABLED, SKIPPED_INERT).
_UNDONE = frozenset(
    {
        DispatchAttempt.Outcome.FAILED,
        DispatchAttempt.Outcome.UNKNOWN,
        DispatchAttempt.Outcome.SENDING,
        DispatchAttempt.Outcome.SKIPPED_NO_KEY,
        DispatchAttempt.Outcome.SKIPPED_EPOCH_MOVED,
    }
)

#: Deployments with a background dispatch thread in this process, mapped to whether
#: a stop asked again while it ran -- so a flood of stops of one deployment starts
#: one thread, which runs once more for all of them, rather than one per stop.
_JOBS: dict[int, bool] = {}
_JOBS_LOCK = threading.Lock()

#: How many background runs push at once in one process
#: (``ASSURANCE_DISPATCH_MAX_CONCURRENT_RUNS``). Each run competes with the
#: process's requests -- stops among them -- for the interpreter and the database's
#: one writer, so the rest wait asleep, their dispatch already recorded as owed.
DEFAULT_MAX_CONCURRENT_RUNS = 4
#: How many more threads may wait for a slot (``ASSURANCE_DISPATCH_MAX_WAITING_RUNS``).
#: Past that, no thread is started: the dispatch is already recorded as owed, and
#: the sweeper or the command runs it.
DEFAULT_MAX_WAITING_RUNS = 32
_SLOTS: dict[int, threading.BoundedSemaphore] = {}
_SLOTS_LOCK = threading.Lock()

#: Seconds between two sweeps of owed dispatches no runner holds
#: (``ASSURANCE_DISPATCH_SWEEP_SECONDS``; 0 turns the sweeper off), and before the
#: first one after a process starts serving.
DEFAULT_SWEEP_SECONDS = 300.0
FIRST_SWEEP_AFTER = 5.0
SWEEPER_THREAD = "assurance-sweeper"
#: This process's sweeper, as ``[(pid, thread)]``.
_SWEEPER: list = []
#: Held while a thread of this process starts the sweeper (never waited on).
_SWEEPER_STARTING = threading.Lock()
_SWEEP_STOP = threading.Event()
#: Most owed rows one sweep reads; it claims and starts as many as the bound allows.
_SWEEP_BATCH = 1000

#: Dispatches a stop could not start because the bound was full: counted, never
#: logged in the stop's request, and reported by the next sweep.
_NOT_STARTED = [0]

#: What :func:`start_blocking_decision_dispatch` did.
STARTED = "started"
COALESCED = "coalesced"  #: one was running here; it runs once more
FULL = "full"  #: the bound was full; nothing started
NOT_STARTED = "not started"  #: the thread could not start; logged at ERROR

#: The longest ``last_error`` kept on a row.
_ERROR_LIMIT = 2000

#: Dispatches a stop could not record, that were not started either because this
#: process already runs this many times its bound in dispatch threads: counted, and
#: each named at ERROR at once.
UNRECORDED_BOUND_FACTOR = 2
_UNRECORDED_REFUSED = [0]

#: The sweeper's start, retried after a failure: ``{"pid", "failures", "next"}``.
_SWEEPER_RETRY: dict = {}
SWEEPER_RETRY_MAX_SECONDS = 300.0


def _after_fork_in_child() -> None:
    """A forked child (a pre-forking server's worker) inherits this module's state
    as it was at the fork: locks another thread may have held -- held for ever in
    the child, where that thread does not exist -- run slots others had taken, the
    parent's jobs and the parent's sweeper, which are not running here. All of it
    starts afresh (:mod:`assurance.oplog` does the same for the log queue)."""
    global _JOBS, _JOBS_LOCK, _SLOTS, _SLOTS_LOCK, _SWEEP_STOP, _SWEEPER_STARTING
    _JOBS = {}
    _JOBS_LOCK = threading.Lock()
    _SLOTS = {}
    _SLOTS_LOCK = threading.Lock()
    _SWEEPER.clear()
    _SWEEPER_RETRY.clear()
    _SWEEP_STOP = threading.Event()
    _SWEEPER_STARTING = threading.Lock()
    _NOT_STARTED[0] = 0
    _UNRECORDED_REFUSED[0] = 0


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


#: Settings already read, by (name, value as given): each is parsed once, and a
#: value that is not a number is reported once, not on every use.
_SETTINGS_READ: dict = {}


def _number_setting(name: str, default, cast, minimum, *, log=log_later):
    """``settings.<name>`` as a number no less than ``minimum``. A value that is
    not one is an error, logged once (and by ``manage.py check``); the default is
    used in its place."""
    raw = getattr(settings, name, default)
    key = (name, repr(raw))
    known = _SETTINGS_READ.get(key)
    if known is not None:
        return known
    problem = setting_problem(name, raw, cast, minimum)
    if problem:
        log(logging.ERROR, "%s; %s is used instead", problem, default)
        value = default
    else:
        value = cast(raw)
    _SETTINGS_READ[key] = value
    return value


def setting_problem(name: str, raw, cast, minimum) -> str | None:
    """What is wrong with ``raw`` as the value of ``name``, or ``None``."""
    try:
        value = cast(raw)
    except (TypeError, ValueError, OverflowError):
        return f"{name}={raw!r} is not a number"
    if isinstance(value, float) and not math.isfinite(value):
        return f"{name}={raw!r} is not a finite number"
    if value < minimum:
        return f"{name}={raw!r} is below its minimum, {minimum}"
    return None


#: The settings this module reads: (name, default, type, minimum).
NUMBER_SETTINGS = (
    ("ASSURANCE_DISPATCH_MAX_CONCURRENT_RUNS", DEFAULT_MAX_CONCURRENT_RUNS, int, 1),
    ("ASSURANCE_DISPATCH_MAX_WAITING_RUNS", DEFAULT_MAX_WAITING_RUNS, int, 0),
    ("ASSURANCE_DISPATCH_SWEEP_SECONDS", DEFAULT_SWEEP_SECONDS, float, 0),
    # connectors.base.DEFAULT_DEADLINE_SECONDS
    ("ASSURANCE_CONNECTOR_DEADLINE_SECONDS", 30.0, float, 0.001),
)


def read_settings() -> None:
    """Read every one of :data:`NUMBER_SETTINGS`, so one that is not a number is
    logged once, at start (:meth:`~assurance.apps.AssuranceConfig.ready`)."""
    for name, default, cast, minimum in NUMBER_SETTINGS:
        _number_setting(name, default, cast, minimum, log=logger.log)


def settings_problems() -> list[str]:
    """Every one of :data:`NUMBER_SETTINGS` that is set to something it cannot be."""
    problems = []
    for name, default, cast, minimum in NUMBER_SETTINGS:
        problem = setting_problem(name, getattr(settings, name, default), cast, minimum)
        if problem:
            problems.append(problem)
    return problems


def _auto_dispatch_enabled() -> bool:
    return bool(getattr(settings, "ASSURANCE_AUTO_DISPATCH_ENABLED", True))


def _max_concurrent_runs() -> int:
    return _number_setting("ASSURANCE_DISPATCH_MAX_CONCURRENT_RUNS", DEFAULT_MAX_CONCURRENT_RUNS, int, 1)


def _max_waiting_runs() -> int:
    return _number_setting("ASSURANCE_DISPATCH_MAX_WAITING_RUNS", DEFAULT_MAX_WAITING_RUNS, int, 0)


def _sweep_interval() -> float:
    return _number_setting("ASSURANCE_DISPATCH_SWEEP_SECONDS", DEFAULT_SWEEP_SECONDS, float, 0)


def connector_deadline() -> float:
    from .connectors.base import DEFAULT_DEADLINE_SECONDS

    return _number_setting("ASSURANCE_CONNECTOR_DEADLINE_SECONDS", DEFAULT_DEADLINE_SECONDS, float, 0.001)


def _run_slots() -> threading.BoundedSemaphore:
    """The process's run slots at the configured size. A run holds the semaphore it
    took, so a changed setting sizes only runs that start after it."""
    size = _max_concurrent_runs()
    with _SLOTS_LOCK:
        if size not in _SLOTS:
            _SLOTS[size] = threading.BoundedSemaphore(size)
        return _SLOTS[size]


def worst_step_seconds() -> float:
    """The longest a run can go between two checks, at the configured limits: a
    look for an existing issue -- which starts no new request once one deadline has
    passed, so at most two deadlines -- the create or the comment, one more, and
    four database waits at its busy timeout (bring the decision current, record
    SENDING, renew the claim, record the end)."""
    deadline = connector_deadline()
    db_timeout = float(settings.DATABASES["default"].get("OPTIONS", {}).get("timeout", 20))
    return 3 * deadline + 4 * db_timeout


def record_blocking_dispatch_owed(deployment, decision):
    """Record, in the stop's own transaction, that ``decision`` owes the decision
    trigger's dispatch -- so that it is durable the moment the stop is, and a
    process that exits right after the stop answers cannot lose it. Returns whether
    a dispatch is owed now (``True``: recorded, or already recorded and to be
    settled by a run; ``False``: nothing owed), or ``None`` when that could not be
    established.

    Passed by the recompute route to :func:`~assurance.decision.recompute_decision`
    (through :class:`OwedRecorder`), which calls it under the row lock after the
    decision is written. It adds a few indexed reads and at most one write to a
    transaction that already holds the write lock, and waits on nothing else: no
    connector, no thread. Written in a savepoint, and a failure is logged and
    swallowed. If the failure ended the whole transaction -- SQLite does that on
    some I/O, full-disk, memory and busy errors -- ``recompute_decision`` sees it
    and raises :class:`~assurance.decision.TransactionLostInHook`, and the route
    commits the stop again without the record: the record can never undo the stop.
    """
    try:
        if not _auto_dispatch_enabled():
            return False
        with transaction.atomic():
            if decision in _BLOCKING_DECISIONS and _blocking_decision_policy(deployment, decision) is not None:
                asked = DecisionDispatchDue.objects.filter(deployment_id=deployment.pk).update(
                    requests=F("requests") + 1
                )
                if not asked:
                    DecisionDispatchDue.objects.create(
                        deployment_id=deployment.pk, owed_since=timezone.now(), requests=1
                    )
                return True
            # Not owed by this decision; one owed before (a lift, a policy switched
            # off) is still there for a run to settle.
            return DecisionDispatchDue.objects.filter(deployment_id=deployment.pk).exists()
    except Exception:  # noqa: BLE001 - a stop never fails on its dispatch's record
        # Logged later, elsewhere: this is inside the stop's transaction, which
        # holds the database's write lock.
        log_later(
            logging.ERROR,
            "could not record the blocking-decision dispatch for deployment %s in its stop's "
            "transaction; the background run records it",
            getattr(deployment, "pk", "?"),
            exc=True,
        )
        return None


class OwedRecorder:
    """:func:`record_blocking_dispatch_owed` as the recompute route passes it, keeping
    what it found: ``owed`` is ``True``, ``False``, or ``None`` (not established --
    including when it never ran). The route starts a background run only unless it
    is ``False``."""

    def __init__(self):
        self.owed = None

    def __call__(self, deployment, decision):
        self.owed = record_blocking_dispatch_owed(deployment, decision)


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
    if claim.halted not in (None, _Claim.WITHDRAWN):
        claim.still_owed(claim.halted)
        return OWED
    undone = [a for a in attempts if a.outcome in _UNDONE]
    if undone and claim.halted is None:
        detail = f"{len(undone)} push(es) not done: " + "; ".join(
            f"{a.connector} for finding {a.finding_id}: {a.outcome}: {a.detail}" for a in undone
        )
        logger.error("blocking-decision dispatch for deployment %s: %s", claim.deployment.pk, detail)
        claim.still_owed(detail)
        return OWED
    # Done -- every push sent, or its binding disabled or unconfigured -- or no
    # longer asked for. Settled, unless a stop asked again while it ran: then it
    # runs again for that stop.
    if claim.settle(asked):
        return SETTLED
    claim.release()
    return _RERUN


def run_blocking_decision_dispatch(deployment_id, *, transport_factory=None, token=None) -> str:
    """Run the decision trigger for one deployment, as it stands now, and record
    whether it is still owed. Returns :data:`SETTLED`, :data:`OWED`,
    :data:`ELSEWHERE`, :data:`DISABLED` or :data:`MISSING`.

    The row is claimed before any push, so two runners never push for one
    deployment at once; ``token`` names the runner (a fresh one when omitted). A
    row the stop could not write is written here first. Nothing owed under the
    decision in force -- lifted to a decision that does not block, the policy
    switched off or no longer opting in, the last binding removed, the deployment
    gone -- settles it, checked immediately before every request, so a run sends
    nothing more once the decision that asked for it is withdrawn. With
    auto-dispatch switched off nothing is pushed and nothing owed is dropped. A run
    that raises, or leaves anything in :data:`_UNDONE`, keeps the row with what is
    left and why.
    """
    token = token or uuid.uuid4().hex
    deployment = Deployment.objects.filter(pk=deployment_id).first()
    if deployment is None:
        return MISSING  # a row it had went with it
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
            "recorded, and the sweeper and `manage.py retry_blocking_dispatches` retry it",
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
            with _run_slots():
                outcome = run_blocking_decision_dispatch(deployment_id, token=token)
        except Exception:  # noqa: BLE001 - e.g. the database is unreachable; retried
            logger.exception(
                "blocking-decision dispatch run for deployment %s did not complete", deployment_id
            )
            continue
        if outcome in (SETTLED, ELSEWHERE, MISSING):
            return
        if outcome == DISABLED:
            logger.warning(
                "blocking-decision dispatch for deployment %s is owed and auto-dispatch is disabled; "
                "it stays recorded and runs once it is enabled again",
                deployment_id,
            )
            return
    _log_still_owed(deployment_id, runs)


def _record_owed_if_missing(deployment_id) -> None:
    """The first thing a run does for a dispatch its stop could not record: record
    it -- before waiting for a run slot -- so that from here on it is owed on the
    record, whatever becomes of this process."""
    try:
        deployment = Deployment.objects.filter(pk=deployment_id).first()
        if deployment is not None and _blocking_decision_policy(deployment) is not None:
            DecisionDispatchDue.objects.get_or_create(
                deployment_id=deployment_id, defaults={"owed_since": timezone.now(), "requests": 1}
            )
    except Exception:  # noqa: BLE001 - the run itself writes it too, and says so if it cannot
        logger.exception("could not record the blocking-decision dispatch for deployment %s", deployment_id)


def _blocking_dispatch_job(deployment_id, unrecorded=False, token=None) -> None:
    """The background thread: run until settled, and once more for every stop that
    asked while it ran."""
    token = token or uuid.uuid4().hex
    finished = False
    try:
        if unrecorded:
            _record_owed_if_missing(deployment_id)
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


def _unrecorded_not_started(deployment_id, why: str) -> None:
    """The one line an operator must see for a dispatch that is neither recorded
    nor started: written here and now, to stderr and the logger, depending on no
    thread (:func:`~assurance.oplog.emit_now`)."""
    emit_now(
        logging.ERROR,
        "blocking-decision dispatch for deployment %s is NOT recorded as owed and did not start (%s): "
        "run `manage.py retry_blocking_dispatches --deployment %s`",
        deployment_id,
        why,
        deployment_id,
    )


def start_blocking_decision_dispatch(deployment_id, *, unrecorded=False, token=None) -> str:
    """Start the background run for ``deployment_id`` -- or, when one is running,
    ask it to run once more. Returns at once and never raises: it is called in a
    stop's request, after the stop has committed. Returns :data:`STARTED`,
    :data:`COALESCED`, :data:`FULL` or :data:`NOT_STARTED`.

    A daemon thread, on purpose: it never holds a worker's exit, and it need not,
    because the stop has already recorded the dispatch as owed. A process that exits
    mid-run leaves the row, and the sweeper or the command runs it once the claim
    lapses. No more than the run slots plus ``ASSURANCE_DISPATCH_MAX_WAITING_RUNS``
    threads exist at once for dispatches that are recorded: past that none is
    started (they are counted, and the next sweep reports and runs them).
    ``unrecorded``: the stop could not record this one, so no sweep would ever find
    it -- it is started past that bound, and its run records it first; but never
    past :data:`UNRECORDED_BOUND_FACTOR` times it. Past that, or when its thread
    cannot start, it is named at ERROR at once, in this thread
    (:func:`_unrecorded_not_started`). Anything else it has to say is logged later,
    from another thread. ``token``: a claim the caller already holds for it (the
    sweeper)."""
    try:
        with _JOBS_LOCK:
            if deployment_id in _JOBS:
                _JOBS[deployment_id] = True
                return COALESCED
            bound = _max_concurrent_runs() + _max_waiting_runs()
            if not unrecorded and len(_JOBS) >= bound:
                _NOT_STARTED[0] += 1
                return FULL
            refused = unrecorded and len(_JOBS) >= UNRECORDED_BOUND_FACTOR * bound
            if refused:
                _UNRECORDED_REFUSED[0] += 1
            else:
                _JOBS[deployment_id] = False
        if refused:
            _unrecorded_not_started(
                deployment_id, f"this process already runs {len(_JOBS)} dispatch threads, its hard bound"
            )
            return FULL
        thread = threading.Thread(
            target=_blocking_dispatch_job,
            args=(deployment_id,),
            kwargs={"unrecorded": unrecorded, "token": token},
            name=f"{THREAD_PREFIX}{deployment_id}",
            daemon=True,
        )
        thread.start()
        return STARTED
    except Exception as exc:  # noqa: BLE001 - a stop has committed; it must still answer
        with _JOBS_LOCK:
            _JOBS.pop(deployment_id, None)
        if unrecorded:
            _unrecorded_not_started(deployment_id, f"its thread could not start: {type(exc).__name__}: {exc}")
        else:
            log_later(
                logging.ERROR,
                "could not start the blocking-decision dispatch for deployment %s; it did not run -- it is "
                "recorded as owed, and the sweeper or `manage.py retry_blocking_dispatches --deployment %s` "
                "runs it",
                deployment_id,
                deployment_id,
                exc=True,
            )
        return NOT_STARTED


class _BlockingDispatchAfterCommit:
    """One deployment's blocking-decision dispatch, started when its stop commits.

    A class rather than a closure so a test can find it among the commit hooks and
    ask which deployment it is for.
    """

    __slots__ = ("deployment_id", "unrecorded")

    def __init__(self, deployment_id, unrecorded=False):
        self.deployment_id = deployment_id
        self.unrecorded = unrecorded

    def __call__(self):
        if self.unrecorded:
            start_blocking_decision_dispatch(self.deployment_id, unrecorded=True)
        else:
            start_blocking_decision_dispatch(self.deployment_id)


def schedule_blocking_decision_dispatch(deployment_id, *, unrecorded=False) -> None:
    """Run the decision trigger for ``deployment_id`` after the current transaction
    commits, in the background: the caller never waits on a connector.

    Called by the recompute route -- pause, lift, or a plain recompute -- after its
    decision has committed, when something is (or may be) owed; ``unrecorded`` when
    the stop could not record it. Nothing with auto-dispatch switched off. Never
    raises; logs in the caller's thread only what :func:`_unrecorded_not_started`
    must say at once."""
    if not _auto_dispatch_enabled():
        return
    try:
        transaction.on_commit(_BlockingDispatchAfterCommit(deployment_id, unrecorded))
    except Exception as exc:  # noqa: BLE001 - a stop has committed; it must still answer
        if unrecorded:
            _unrecorded_not_started(deployment_id, f"it could not be scheduled: {type(exc).__name__}: {exc}")
        else:
            log_later(
                logging.ERROR,
                "could not schedule the blocking-decision dispatch for deployment %s; it is recorded as owed, "
                "and the sweeper or `manage.py retry_blocking_dispatches --deployment %s` runs it",
                deployment_id,
                deployment_id,
                exc=True,
            )


def retry_owed_blocking_dispatches(deployment_ids=None, *, transport_factory=None) -> dict:
    """Run every blocking-decision dispatch still owed -- or those of
    ``deployment_ids``, owed or not -- here and now, as one runner. Returns
    ``{deployment id: outcome}`` (:data:`SETTLED`, :data:`OWED`, :data:`ELSEWHERE`,
    :data:`DISABLED`, :data:`MISSING`); a run that raises counts as :data:`OWED` and
    does not stop the rest. One another runner holds is left to it: never pushed
    twice at once."""
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


def sweep_owed_blocking_dispatches() -> list:
    """Claim and start the owed dispatches no live runner holds -- ones a process
    left behind when it exited, whose runs all failed, or that a full bound kept a
    stop from starting -- up to this process's bound. Returns the deployment ids it
    started, and only those.

    Each row is claimed before it is started (the claim a run takes, conditional on
    no live claim), so sweepers in N processes start N different sets of rows
    rather than all the oldest ones. One summary line, at most, per sweep. Never
    raises, and never logs while holding a lock."""
    if not _auto_dispatch_enabled():
        return []
    started, left = [], 0
    try:
        now = timezone.now()
        due = list(
            DecisionDispatchDue.objects.filter(Q(running_until__isnull=True) | Q(running_until__lte=now))
            .order_by("owed_since")
            .values_list("deployment_id", flat=True)[:_SWEEP_BATCH]
        )
        bound = _max_concurrent_runs() + _max_waiting_runs()
        for i, deployment_id in enumerate(due):
            with _JOBS_LOCK:
                full = len(_JOBS) >= bound
                here = deployment_id in _JOBS
            if full:
                left = len(due) - i
                break
            if here:
                continue
            token = uuid.uuid4().hex
            now = timezone.now()
            claimed = (
                _owed_row(deployment_id)
                .filter(Q(running_until__isnull=True) | Q(running_until__lte=now))
                .update(running_until=now + timedelta(seconds=CLAIM_SECONDS), run_token=token)
            )
            if not claimed:
                continue  # another process's sweeper, or a run, has it
            if start_blocking_decision_dispatch(deployment_id, token=token) == STARTED:
                started.append(deployment_id)
            else:
                _owed_row(deployment_id).filter(run_token=token).update(running_until=None, run_token="")
    except Exception:  # noqa: BLE001 - the next sweep tries again
        logger.exception("the sweep of owed blocking-decision dispatches did not complete")
    not_started, _NOT_STARTED[0] = _NOT_STARTED[0], 0
    if left or not_started:
        logger.warning(
            "owed blocking-decision dispatches: %d started by this sweep, %d left for the next (this "
            "process's %d-run bound is full), %d not started by stops since the last sweep",
            len(started),
            left,
            _max_concurrent_runs() + _max_waiting_runs(),
            not_started,
        )
    return started


def _sweeper(interval: float, stop) -> None:
    # A first sweep shortly after start, then every `interval` seconds, for the
    # life of the process. Its own connection is closed after each sweep; nothing
    # in the loop can end it.
    if stop.wait(min(interval, FIRST_SWEEP_AFTER)):
        return
    while True:
        if _oplog._BUF:
            # Records queued while no thread could start (a stop's ERROR among
            # them): the log thread is started again to write them.
            _oplog.start_pump()
        try:
            sweep_owed_blocking_dispatches()
        except Exception:  # noqa: BLE001 - it never raises; if it did, sweep again next time
            logger.exception("the sweeper's sweep raised")
        try:
            connections.close_all()
        except Exception:  # noqa: BLE001 - a connection that will not close is not a reason to stop sweeping
            logger.exception("the sweeper could not close its database connection")
        if stop.wait(interval):
            return


def start_owed_sweeper() -> bool:
    """Start this process's sweeper, once per process: a daemon thread that runs
    :func:`sweep_owed_blocking_dispatches` :data:`FIRST_SWEEP_AFTER` seconds after
    it starts and then every ``ASSURANCE_DISPATCH_SWEEP_SECONDS`` (default 300; 0
    turns it off). Keyed on the process id, so a process forked from one that
    started it starts its own. A start that fails is tried again on a later call,
    after a backoff that doubles up to :data:`SWEEPER_RETRY_MAX_SECONDS`, and each
    failure is logged once. Starts the log pump too, so it exists before any
    shortage of threads. Never blocks and never raises. One start at a time per
    process: a caller that finds another starting it returns at once, so requests
    arriving together start one sweeper, not one each."""
    if not _SWEEPER_STARTING.acquire(blocking=False):
        return False  # another thread of this process is starting it now
    try:
        return _start_owed_sweeper()
    finally:
        _SWEEPER_STARTING.release()


def _start_owed_sweeper() -> bool:
    pid = os.getpid()
    try:
        interval = _sweep_interval()
        with _JOBS_LOCK:
            current = _SWEEPER[0] if _SWEEPER else None
            if current is not None and current[0] == pid and current[1] is not None and current[1].is_alive():
                return False
            if interval <= 0:
                _SWEEPER[:] = [(pid, None)]  # off, and known to be: the fast path applies
                return False
            if _SWEEP_STOP.is_set():
                return False
            thread = threading.Thread(
                target=_sweeper, args=(interval, _SWEEP_STOP), name=SWEEPER_THREAD, daemon=True
            )
            _SWEEPER[:] = [(pid, thread)]
        thread.start()
        _SWEEPER_RETRY.clear()
        start_log_pump()
        return True
    except Exception:  # noqa: BLE001 - serving never waits on the sweeper
        failures = (_SWEEPER_RETRY.get("failures", 0) if _SWEEPER_RETRY.get("pid") == pid else 0) + 1
        wait = min(SWEEPER_RETRY_MAX_SECONDS, 2.0 ** (failures - 1))
        _SWEEPER_RETRY.update(pid=pid, failures=failures, next=time.monotonic() + wait)
        log_later(
            logging.ERROR,
            "could not start the sweeper of owed blocking-decision dispatches (failure %d); tried again in %g s",
            failures,
            wait,
            exc=True,
        )
        return False


def start_log_pump() -> bool:
    from .oplog import start_pump

    return start_pump()


def ensure_owed_sweeper() -> None:
    """Start this process's sweeper if it has none running: called on every request
    by the WSGI and ASGI entry points, so it starts in the process that serves -- a
    pre-forking server's worker, never its master -- on that process's first
    request. One that died, or could not start, is started again (after a backoff,
    for a start that failed). Costs a comparison and a liveness check after that."""
    if _oplog._BUF:
        # Records a shortage of threads left queued: the log thread is started
        # again (a check, when it is running).
        _oplog.start_pump()
    current = _SWEEPER[0] if _SWEEPER else None
    if current is not None and current[0] == os.getpid() and (current[1] is None or current[1].is_alive()):
        return
    if _SWEEPER_RETRY.get("pid") == os.getpid() and time.monotonic() < _SWEEPER_RETRY.get("next", 0):
        return
    start_owed_sweeper()
