"""Which approval was in force when: the history an effect is read against, as of dispatch.

:class:`assurance.models.ApprovedWorkflow` is the approval as it stands now -- its
description is rewritten in place, its tool bindings are released and re-bound, and
withdrawing it deletes it. An authority chain's ``under_policy`` and ``invokes`` hops
used to be read against that, live: a re-approval after an effect unproved an effect
that was properly authorised, and an effect dispatched under an approval since
superseded read proven once the approval came back.

Part 5 of the owner's 7 Oct decision reads those hops AS OF DISPATCH
(:mod:`assurance.authority_chain`): against the approval, the contracts and the route
in force at the instant the effect's dispatch left, which Achilles signs into the
observed effect (``mythos.observed-effect/v2``). This module keeps the approvals'
half of that history -- :class:`assurance.models.ApprovalVersion`, append-only -- and
reads it back. The contracts' half already exists (:class:`assurance.models.ToolContract`,
append-only, ``recorded_at``); the route's is bound per observed effect when it is
recorded (``WorkflowChainOutcome.dispatch_route_fingerprint``).

WHEN A VERSION IS NOTED (:func:`note_approvals`). In the same transaction as every
write that can move an approval -- an approved workflow saved or deleted, a tool
binding of one saved (:mod:`assurance.signals`) -- and again at every decision
refresh (:func:`note_approvals_quietly`, beside the served route's note), so an
approval no write moved since this history began is noted too. ``in_force_from`` is
when the platform NOTICED: at or after the change. A dispatch before the first note
of an approval reads as one whose state nothing recorded, never as covered.

Never on a stop path. No stop writes an approval, and the refresh's note never
raises: a failure is logged and the next note takes it.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable

from django.db import transaction
from django.utils import timezone

logger = logging.getLogger(__name__)


def approvals_now(deployment) -> dict[str, tuple[str, list[list[str]]]]:
    """Every approved workflow of ``deployment`` as it stands now: ``slug -> (digest,
    tools)``, ``tools`` the sorted ``[kind, identifier, contract digest]`` of its live
    bindings -- exactly what :func:`assurance.authority_chain_records.approval_digest`
    covers of them. Two queries."""
    from django.db.models import Prefetch

    from .authority_chain_records import approval_digest
    from .models import ToolContractBinding

    out: dict[str, tuple[str, list[list[str]]]] = {}
    for workflow in deployment.approved_workflows.prefetch_related(
        Prefetch(
            "tool_contract_bindings",
            queryset=ToolContractBinding.objects.filter(released_at__isnull=True).order_by("tool_kind", "tool_identifier"),
            to_attr="history_bindings",
        )
    ):
        live = workflow.history_bindings
        tools = sorted([str(b.tool_kind), str(b.tool_identifier), str(b.contract_digest)] for b in live)
        out[workflow.slug] = (approval_digest(workflow, live), tools)
    return out


def latest_versions(deployment) -> dict[str, object]:
    """The newest recorded version of each workflow's approval, by slug."""
    from .models import ApprovalVersion

    latest: dict[str, object] = {}
    for row in ApprovalVersion.objects.filter(deployment=deployment).order_by("in_force_from", "id"):
        latest[row.workflow] = row
    return latest


def note_approvals(deployment, *, now=None) -> list:
    """Append an :class:`~assurance.models.ApprovalVersion` for every approval of
    ``deployment`` whose digest differs from the last one recorded for it (or that has
    none recorded), and a withdrawn version (blank digest) for every workflow whose last
    recorded version is an approval that no longer exists. Idempotent: an unchanged
    approval appends nothing. Returns the rows appended. Runs in the caller's
    transaction."""
    from .models import ApprovalVersion

    now = now or timezone.now()
    current = approvals_now(deployment)
    latest = latest_versions(deployment)
    appended = []
    for slug in sorted(set(current) | set(latest)):
        digest, tools = current.get(slug, ("", []))
        last = latest.get(slug)
        if last is None and not digest:
            continue
        if last is not None and last.digest == digest and (not digest or last.tools == tools):
            continue
        # Never before the version it follows: a clock that stepped back must not
        # place the new version before the old one in the history.
        instant = now if last is None or now >= last.in_force_from else last.in_force_from
        appended.append(
            ApprovalVersion.objects.create(
                deployment=deployment, workflow=slug, digest=digest, tools=tools, in_force_from=instant
            )
        )
    return appended


def note_approvals_quietly(deployment, *, now=None) -> None:
    """:func:`note_approvals`, for the decision refresh, which must not fail for it.
    A failure is logged and rolled back to before the note, and costs only that: the
    next note sees the change instead, and a late note only ever leaves a dispatch
    before it unrecorded. Never raises."""
    try:
        with transaction.atomic():
            note_approvals(deployment, now=now)
    except Exception:
        logger.exception(
            "the approvals of deployment %s were not noted; the next approval write or "
            "decision refresh notes them instead",
            deployment.pk,
        )


def history(deployment, workflows: Iterable[str]) -> dict[str, list]:
    """Every recorded version of each of ``workflows``' approvals, oldest first: one
    query, none for no workflow."""
    from .models import ApprovalVersion

    slugs = sorted({w for w in workflows if w})
    if not slugs:
        return {}
    out: dict[str, list] = {}
    for row in ApprovalVersion.objects.filter(deployment=deployment, workflow__in=slugs).order_by(
        "in_force_from", "id"
    ):
        out.setdefault(row.workflow, []).append(row)
    return out
