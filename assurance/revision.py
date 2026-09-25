"""Revision-fenced decisions, and the accepted-change boundary (Phase 2 item 5).

The decision and the claims behind it are separate rows. A consumer that reads
them in two queries can take the decision from after a transition and the claims
from before it, and what comes back is not an error -- it is a perfectly ordinary
looking answer assembled from two different moments. Nothing in the record makes
that seam visible, and nothing anywhere in ``assurance/`` fenced against it.

Two mechanisms, and they only work together.

**A monotonic revision.** ``Deployment.decision_revision`` advances by exactly one
on every accepted transition and never otherwise. It is what makes a read
checkable: "I acted on revision 7" can be verified later, "I acted on
NOT_RECOMMENDED" cannot, because a decision can be reached, left, and reached
again, and the second visit is a different fact about a different system state.

**One commit boundary.** The transition and its downstream record commit
together, in one transaction, under a row lock on the deployment. Either the
decision moved and the transition exists, or neither happened. A reader can
therefore never see a decision whose transition has not been written, which is
the torn state the bar names.

What the lock does and does not do
----------------------------------
``select_for_update`` serialises concurrent recomputes on PostgreSQL, which is
what deployments run. On SQLite -- which the test suite uses -- Django issues it
and the engine ignores it, because SQLite serialises writers at the database
level anyway. So the concurrency test in this repository proves the INVARIANTS
hold under threading (no duplicate revision, no gap, every transition matching
the decision it recorded); it does not prove the row lock works, because on
SQLite there is nothing for it to do. Saying which of the two is being
demonstrated matters more than the green tick: a test that quietly proved the
weaker thing while reading as the stronger one is the failure this module is
about.
"""

from __future__ import annotations

import logging

from django.db import transaction
from django.utils import timezone

from .models import DecisionTransition, Deployment

logger = logging.getLogger(__name__)


class StaleDecisionRead(RuntimeError):
    """A fenced read found a revision older than the one the caller requires.

    Raised rather than returned, and rather than quietly returning the stale
    value. A consumer that asked to be fenced at revision 7 and was handed
    revision 6 has been handed the answer it specifically said it could not use;
    returning it with a flag attached would make ignoring the flag the easy path.
    """


def read_decision(deployment: Deployment, *, at_least: int | None = None) -> dict:
    """The decision and the revision it belongs to, read as one fact.

    ``at_least`` is the fence: a consumer that has already acted on revision N
    passes ``at_least=N`` and gets :class:`StaleDecisionRead` if it is handed
    anything older -- which happens on a read replica that has not caught up, or
    from a cache. Without it a consumer cannot tell a stale read from a current
    one, because both are well-formed.

    Reads the row fresh. A ``Deployment`` instance held across a transition
    carries the old values, and this is exactly the call where that matters.
    """
    # Reconciled first, like every surface that publishes the decision: the
    # revision is only a fence if the decision it names is the one in force.
    from .decision import current_decision

    current_decision(Deployment.objects.get(pk=deployment.pk))
    row = Deployment.objects.values("decision", "decision_revision").get(pk=deployment.pk)
    revision = row["decision_revision"]
    if at_least is not None and revision < at_least:
        raise StaleDecisionRead(
            f"decision revision {revision} is older than the required {at_least}; "
            "this read is behind the state the caller has already acted on"
        )
    return {"decision": row["decision"], "revision": revision}


def accept_transition(deployment: Deployment, *, to_decision, basis_digest: str = "") -> dict:
    """Move the decision and record the move, atomically. Returns the new state.

    The accepted-change boundary. Everything inside happens or none of it does:
    the deployment's decision and revision are written, and the
    :class:`~assurance.models.DecisionTransition` recording the move is inserted,
    in one transaction under a row lock.

    A no-op transition -- recomputing to the decision already in force -- does
    NOT advance the revision and writes no transition row. That is deliberate:
    the revision means "the decision changed", and bumping it when nothing
    changed would make every consumer's fence fire on reassessments that decided
    nothing, training them to ignore it.

    ``basis_digest`` is what the decision was computed from (a receipt digest, a
    claim-state digest). It is recorded on the transition so a later reader can
    tell whether two decisions that agree were computed from the same evidence --
    a question the decision value alone cannot answer.

    The revision issued is the next one after BOTH the locked row and the
    transition log. A row found behind its log was written back over by something
    other than this function; it is repaired from the log and logged at ERROR (see
    :func:`_in_force`), never crashed on -- a crash here is a deployment no
    recompute can bring current again.
    """
    with transaction.atomic():
        # Serialises concurrent recomputes on PostgreSQL; a no-op on SQLite, which
        # serialises writers itself. See the module docstring.
        locked = Deployment.objects.select_for_update().get(pk=deployment.pk)
        stored = (locked.decision, locked.decision_revision)
        current, at = _in_force(locked)

        if current == to_decision:
            if (current, at) != stored:
                # The row was behind its log and the log already records this
                # decision: bring the row up to it, and record nothing new -- the
                # move was recorded when it happened.
                _write(locked, to_decision, at)
                deployment.decision = to_decision
                deployment.decision_revision = at
            return {
                "decision": to_decision,
                "revision": at,
                # What the stored decision did, which is what a caller asks.
                "changed": stored[0] != to_decision,
            }

        # The next revision after BOTH the row and its log. The row alone was
        # trusted, and a row written back beneath its log computed a revision that
        # was already taken, collided with it, and failed on every recompute after.
        revision = at + 1
        _write(locked, to_decision, revision)

        # In the SAME transaction, which is the whole mechanism: a decision whose
        # transition is missing, or a transition whose decision never landed,
        # cannot both exist and be observed.
        DecisionTransition.objects.create(
            deployment=locked,
            revision=revision,
            from_decision=current or "",
            to_decision=to_decision or "",
            basis_digest=basis_digest,
        )

    # Keep the caller's in-memory instance honest rather than leaving it holding
    # values the database no longer has.
    deployment.decision = to_decision
    deployment.decision_revision = revision
    return {"decision": to_decision, "revision": revision, "changed": True}


def _in_force(locked: Deployment):
    """The decision in force and its revision: the LOCKED row's, unless the row is
    behind its own transition log -- then the log's, loudly.

    The log is what every consumer draining :func:`transitions_since` was told, and
    a row whose revision is below the log's latest is a row something wrote back
    over (a stale instance's full save did, before ``Deployment.save`` stopped
    writing the decision columns). Crashing on it left the deployment unrepairable
    through any recompute; trusting the row would issue a revision the log already
    holds. Repairing from the log keeps the sequence the consumers have seen
    continuous: the next transition runs FROM what the log last recorded.
    """
    latest = (
        DecisionTransition.objects.filter(deployment_id=locked.pk)
        .order_by("-revision")
        .values_list("revision", "to_decision")
        .first()
    )
    if latest is None or latest[0] <= locked.decision_revision:
        return locked.decision, locked.decision_revision
    logger.error(
        "deployment %s: stored decision %r at revision %s is behind its transition log "
        "(revision %s recorded %r); repairing the row from the log",
        locked.pk,
        locked.decision,
        locked.decision_revision,
        latest[0],
        latest[1],
    )
    return latest[1] or None, latest[0]


def _write(locked: Deployment, decision, revision) -> None:
    """Write the decision columns: the refresh's own write, and the only one.

    A QuerySet update under the row lock the caller holds. ``Deployment.save``
    refuses these columns (see :data:`~assurance.models.DECISION_OWNED_FIELDS`), so
    no instance loaded before a transition can write the decision it holds back
    over this one.
    """
    Deployment.objects.filter(pk=locked.pk).update(
        decision=decision, decision_revision=revision, updated_at=timezone.now()
    )
    locked.decision = decision
    locked.decision_revision = revision


def transitions_since(deployment: Deployment, revision: int):
    """Every accepted transition after ``revision``, oldest first.

    What a downstream consumer drains: it records the revision it has processed
    and asks for what came after. Ordered by revision rather than by timestamp,
    because two transitions can share a clock reading and the revision is the
    thing that is actually ordered.
    """
    return DecisionTransition.objects.filter(
        deployment=deployment, revision__gt=revision
    ).order_by("revision")
