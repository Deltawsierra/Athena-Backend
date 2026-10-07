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

**No fix before agreement** (Roadmap Phase 6: a repair contract before any
candidate patch). A finding's remediation cannot move into a working state --
:data:`WORKING_STATES`: ``in_progress``, ``in_review``, ``resolved`` -- unless the
finding has a current agreed :class:`~assurance.models.RepairContract` naming the
prohibited effect the repair must eliminate and the behaviours it must preserve
(:mod:`assurance.repair_contract`). :func:`enforce_contract` is that gate, and it
runs in :meth:`Finding.save` and :meth:`Finding.clean`, beside the retest-closure
gate, so every path is covered: this module's :func:`apply_transition` (the API's
``remediation/transition`` route), the admin's change and add forms, and any other
save. A finding cannot be created already in a working state, since no contract can
be agreed for a finding that does not exist yet. The refusal
(:class:`ContractRequired`) names what is missing.

A finding already in a working state when the gate landed is not rewritten: it
stays where it is and may still be moved to ``wont_fix``; any further move into a
working state needs a contract, and its closure, like every retest-gated closure,
is held to the current contract (:mod:`assurance.retest_closure`).
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


#: The states in which a fix is being worked on, reviewed or called done. None is
#: entered without a current repair contract (:func:`enforce_contract`).
WORKING_STATES: frozenset[str] = frozenset({State.IN_PROGRESS, State.IN_REVIEW, State.RESOLVED})


class IllegalTransition(ValueError):
    """A remediation move the state machine forbids. A caller turns this into a
    clean 400 rather than letting an illegal jump be silently coerced."""


class ContractRequired(IllegalTransition):
    """A move into a working state on a finding with no agreed repair contract.
    ``reasons`` names what is missing."""

    def __init__(self, reasons):
        self.reasons = list(reasons)
        super().__init__("Remediation move refused: " + "; ".join(self.reasons))


def enforce_contract(finding, update_fields=None) -> None:
    """Refuse a save that moves ``finding``'s remediation into one of
    :data:`WORKING_STATES` -- from any other state, from a different working state,
    or by creating the finding in one -- when the finding has no current repair
    contract. Called from :meth:`Finding.save` and :meth:`Finding.clean`. A save that
    is not such a move passes; so does every move out to ``triaged``, ``new`` or
    ``wont_fix``, which no contract is needed to stop working on."""
    from .repair_contract import current_contract

    target = finding.remediation_state
    if target not in WORKING_STATES:
        return
    if update_fields is not None and "remediation_state" not in set(update_fields):
        return
    stored = None
    if finding.pk is not None:
        stored = Finding.objects.filter(pk=finding.pk).values_list("remediation_state", flat=True).first()
    if stored == target:
        return
    if current_contract(finding) is not None:
        return
    if finding.pk is None or stored is None:
        raise ContractRequired(
            [
                f"repair contract: a finding cannot be created already {target}; create it, agree "
                "its repair contract (the prohibited effect the repair must eliminate and the "
                "behaviours it must preserve), then move it"
            ]
        )
    raise ContractRequired(
        [
            f"repair contract: none agreed for this finding, so its remediation cannot move to "
            f"{target}; agree one first (POST repair-contracts/): the prohibited effect the repair "
            "must eliminate, and the legitimate behaviours it must preserve"
        ]
    )


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
    try:
        # A move into a working state passes the repair-contract gate in the save
        # (enforce_contract), and RESOLVED on a retest-required finding the
        # retest-closure gate too (assurance.retest_closure); a refusal leaves the
        # caller's copy where the row is.
        finding.save(update_fields=["remediation_state", "updated_at"])
    except Exception:
        finding.remediation_state = from_state
        raise
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
