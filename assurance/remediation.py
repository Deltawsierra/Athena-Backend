"""The finding remediation workflow — the human process of getting a fix landed.

Phase 2.3 of the reconciled Athena roadmap. The roadmap already had the security
disposition (``Finding.status``: is the risk still live?) and attributed
approvals; what was missing was the *process* layer — assignment and an ordered,
enforced review-state machine that tracks a finding from raised to fixed.

This module is that state machine. It is deliberately **orthogonal** to the
security disposition: moving a finding to ``RESOLVED`` here is a human's claim
that the remediation work is done, and it never changes ``status`` or the
deployment decision. A finding is only *securely* resolved through ``status``
(CLOSED / ACCEPTED / FALSE_POSITIVE); conflating the two would let a process
click mark a live risk as closed, which is exactly the honesty failure the rest
of the assurance layer is built to avoid.

Every move is attributed: :func:`apply_transition` and :func:`assign` each write
a :class:`~assurance.models.RemediationEvent`, reusing the actor + note +
ordered-timestamp trail the failsafe control plane already established rather
than inventing a parallel one. Illegal transitions are rejected, not coerced.
"""

from __future__ import annotations

from django.db import transaction

from .models import Finding, RemediationEvent

State = Finding.RemediationState

# The legal moves, keyed by the state you are in. The forward spine is
# NEW → TRIAGED → IN_PROGRESS → IN_REVIEW → RESOLVED; on top of that, review can
# bounce work back (IN_REVIEW → IN_PROGRESS), a regression can reopen a resolved
# finding (RESOLVED → IN_PROGRESS), any live state can be closed as WONT_FIX, and
# a WONT_FIX can be reconsidered. Anything not listed here — including a no-op
# self-transition — is rejected, so a caller can never skip triage or jump
# straight to RESOLVED.
LEGAL_TRANSITIONS: dict[str, frozenset[str]] = {
    State.NEW: frozenset({State.TRIAGED, State.WONT_FIX}),
    State.TRIAGED: frozenset({State.IN_PROGRESS, State.WONT_FIX}),
    State.IN_PROGRESS: frozenset({State.IN_REVIEW, State.WONT_FIX}),
    State.IN_REVIEW: frozenset({State.RESOLVED, State.IN_PROGRESS, State.WONT_FIX}),
    State.RESOLVED: frozenset({State.IN_PROGRESS}),
    State.WONT_FIX: frozenset({State.TRIAGED}),
}


class IllegalTransition(ValueError):
    """A remediation move the state machine forbids. A caller turns this into a
    clean 400 rather than letting an illegal jump be silently coerced."""


def can_transition(from_state: str, to_state: str) -> bool:
    """Whether ``from_state → to_state`` is a legal remediation move."""
    return to_state in LEGAL_TRANSITIONS.get(from_state, frozenset())


@transaction.atomic
def apply_transition(
    finding: Finding, to_state: str, *, actor, note: str = ""
) -> RemediationEvent:
    """Move ``finding`` along its remediation workflow and record who did it.

    Validates the move against :data:`LEGAL_TRANSITIONS` (raising
    :class:`IllegalTransition` on an illegal jump), updates only
    ``remediation_state`` — never ``status`` or the deployment decision — and
    writes an attributed :class:`~assurance.models.RemediationEvent`. Atomic so
    the state change and its audit record land together or not at all."""
    to_state = State(to_state)
    from_state = finding.remediation_state
    if not can_transition(from_state, to_state):
        raise IllegalTransition(
            f"{from_state} → {to_state} is not a legal remediation transition."
        )
    finding.remediation_state = to_state
    finding.save(update_fields=["remediation_state", "updated_at"])
    return RemediationEvent.objects.create(
        finding=finding,
        from_state=from_state,
        to_state=to_state,
        actor=actor,
        note=note or "",
    )


@transaction.atomic
def assign(
    finding: Finding, assignee, *, actor, note: str = ""
) -> RemediationEvent | None:
    """Set (or clear, with ``assignee=None``) who does the remediation work.

    An assignment does not move the workflow, so a real change records a
    :class:`~assurance.models.RemediationEvent` at the current state
    (``from_state == to_state``) — the trail stays complete and attributed
    without pretending a state change happened. Touches ``assignee`` only; never
    ``status``, ``owner``, or the decision.

    **Idempotent.** If the finding is already assigned to exactly this user (or
    already unassigned when clearing), nothing is written: no save, no duplicate
    ``RemediationEvent``, and the call returns ``None``. This keeps attribution
    honest — the trail records only assignments that actually happened, never a
    no-op re-click. A real change behaves exactly as before and returns the new
    event."""
    current_id = finding.assignee_id
    target_id = assignee.pk if assignee is not None else None
    if current_id == target_id:
        # Already in the requested state — no change, no duplicate event.
        return None
    finding.assignee = assignee
    finding.save(update_fields=["assignee", "updated_at"])
    state = finding.remediation_state
    default_note = f"Assigned to {assignee.username}" if assignee else "Unassigned"
    return RemediationEvent.objects.create(
        finding=finding,
        from_state=state,
        to_state=state,
        actor=actor,
        note=note or default_note,
    )
