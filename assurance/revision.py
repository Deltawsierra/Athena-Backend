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
from typing import NamedTuple

from django.db import DatabaseError, transaction
from django.db.models import OuterRef, Subquery
from django.utils import timezone

from .models import DecisionTransition, Deployment

logger = logging.getLogger(__name__)


class StaleDecisionRead(RuntimeError):
    """A fenced read found a revision older than the one the caller requires.

    Raised rather than returned, and rather than quietly returning the stale
    value. A consumer that asked to be fenced at revision 7 and was handed
    revision 6 has been handed the answer it specifically said it could not use;
    returning it with a flag attached would make ignoring the flag the easy path.

    Also raised by :func:`accept_transition` when it is handed a reading of the
    decision in force (:class:`InForce`) taken from a row that has moved since.
    """


class InForce(NamedTuple):
    """The decision in force for one deployment and its revision, read under the
    deployment's row lock by :func:`decision_in_force`.

    ``read_from`` is the row it was read from, ``(pk, decision, revision)``.
    :func:`accept_transition` checks the row it locks against it, so a reading
    taken before the row moved is refused rather than moved FROM.
    """

    decision: str | None
    revision: int
    read_from: tuple


def read_decision(deployment: Deployment, *, at_least: int | None = None) -> dict:
    """The decision and the revision it belongs to, read as one fact.

    ``at_least`` is the fence: a consumer that has already acted on revision N
    passes ``at_least=N`` and gets :class:`StaleDecisionRead` if it is handed
    anything older -- which happens on a read replica that has not caught up, or
    from a cache. Without it a consumer cannot tell a stale read from a current
    one, because both are well-formed.

    Reads the row fresh. A ``Deployment`` instance held across a transition
    carries the old values, and this is exactly the call where that matters.

    The decision IN FORCE, not merely the row's: a row behind its own transition
    log (:func:`hold_to_its_log`) is published as the log records it. The row's
    stale revision was a fence no consumer that had drained the log could pass --
    told PAUSED at revision 2, it asked for ``at_least=2`` and was refused, for as
    long as nothing happened to recompute the deployment.
    """
    # Reconciled first, like every surface that publishes the decision: the
    # revision is only a fence if the decision it names is the one in force.
    # `current_decision` holds the instance to its log and to the keyring, so what
    # it leaves on the instance is what is published.
    from .decision import current_decision

    fresh = Deployment.objects.annotate(**logged_head()).get(pk=deployment.pk)
    current_decision(fresh)
    revision = fresh.decision_revision
    if at_least is not None and revision < at_least:
        raise StaleDecisionRead(
            f"decision revision {revision} is older than the required {at_least}; "
            "this read is behind the state the caller has already acted on"
        )
    return {"decision": fresh.decision, "revision": revision}


def accept_transition(
    deployment: Deployment,
    *,
    to_decision,
    basis_digest: str = "",
    in_force: InForce | None = None,
) -> dict:
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
    :func:`decision_in_force`), never crashed on -- a crash here is a deployment no
    recompute can bring current again.

    ``in_force``: the caller's own :func:`decision_in_force`, read under this row
    lock in the transaction this call joins. ``recompute_decision`` passes the one
    it took the operator's pause from, so the decision computed and the decision
    it moves FROM are the same reading, and a repair is logged once, not twice. A
    reading of a row that has moved since (or of another deployment) is refused
    with :class:`StaleDecisionRead`: moving from it would write the row back
    beneath its log, which is the wedge the repair exists to undo. Omitted, it is
    read here.
    """
    with transaction.atomic():
        # Serialises concurrent recomputes on PostgreSQL; a no-op on SQLite, which
        # serialises writers itself. See the module docstring.
        locked = Deployment.objects.select_for_update().get(pk=deployment.pk)
        stored = (locked.decision, locked.decision_revision)
        if in_force is None:
            in_force = decision_in_force(locked)
        elif in_force.read_from != (locked.pk, *stored):
            raise StaleDecisionRead(
                f"the decision in force was read from deployment {in_force.read_from[0]} "
                f"at {in_force.read_from[1:]!r}, but the row locked is deployment "
                f"{locked.pk} at {stored!r}; read it again under this lock"
            )
        current, at = in_force.decision, in_force.revision

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


def decision_in_force(locked: Deployment) -> InForce:
    """The decision in force and its revision: the LOCKED row's, unless the row is
    behind its own transition log -- then the log's, loudly.

    The log is what every consumer draining :func:`transitions_since` was told, and
    a row whose revision is below the log's latest is a row something wrote back
    over (a stale instance's full save did, before ``Deployment.save`` stopped
    writing the decision columns). Crashing on it left the deployment unrepairable
    through any recompute; trusting the row would issue a revision the log already
    holds. Repairing from the log keeps the sequence the consumers have seen
    continuous: the next transition runs FROM what the log last recorded.

    The operator's pause is part of that decision (PAUSED is a decision), so it is
    read from here too, never from the row alone: a row written back beneath a
    logged pause holds the decision from before the pause, and reading the pause
    off it recorded a lift no operator made. Call it once per lock and pass the
    reading on (``accept_transition(in_force=...)``); each call is a query, and on
    a row behind its log, an ERROR.
    """
    read_from = (locked.pk, locked.decision, locked.decision_revision)
    latest = (
        DecisionTransition.objects.filter(deployment_id=locked.pk)
        .order_by("-revision")
        .values_list("revision", "to_decision")
        .first()
    )
    decision, revision = in_force_of(
        locked.decision, locked.decision_revision, *(latest or (None, None))
    )
    if revision == locked.decision_revision:
        return InForce(decision, revision, read_from)
    logger.error(
        "deployment %s: stored decision %r at revision %s is behind its transition log "
        "(revision %s recorded %r); repairing the row from the log",
        locked.pk,
        locked.decision,
        locked.decision_revision,
        latest[0],
        latest[1],
    )
    return InForce(decision, revision, read_from)


def in_force_of(decision, revision, logged_revision, logged_decision) -> tuple[str | None, int]:
    """``(decision, revision)`` in force for a row and the head of its transition
    log: the row's, unless the row is behind the log -- then the log's.

    The one rule, for :func:`decision_in_force` under the row lock and for every
    read that takes no lock and writes nothing (:func:`published_decision`, the
    admin's list). ``logged_revision`` is ``None`` for a deployment with no
    transition; ``logged_decision`` is the log's ``to_decision``, which stores an
    unassessed decision as ``""``.
    """
    if logged_revision is not None and logged_revision > revision:
        return logged_decision or None, logged_revision
    return decision, revision


def logged_head() -> dict:
    """The head of each deployment's transition log, as annotations to read WITH
    the row: ``logged_revision`` and ``logged_decision``.

    In the statement that reads the row, so the two are one moment: read apart, a
    transition committed between them makes a current row look behind its log. And
    in a list's one query, so reconciling every row the list publishes does not
    cost a query per row to ask whether it is behind.
    """
    latest = DecisionTransition.objects.filter(deployment_id=OuterRef("pk")).order_by("-revision")
    return {
        "logged_revision": Subquery(latest.values("revision")[:1]),
        "logged_decision": Subquery(latest.values("to_decision")[:1]),
    }


def published_decision(pk) -> tuple[str | None, int] | None:
    """The decision in force for deployment ``pk`` and its revision, as a read
    publishes it: the row and the head of its log in ONE statement, no lock, no
    write. ``None`` for no such deployment."""
    row = (
        Deployment.objects.filter(pk=pk)
        .annotate(**logged_head())
        .values_list("decision", "decision_revision", "logged_revision", "logged_decision")
        .first()
    )
    return None if row is None else in_force_of(*row)


#: ``logged_revision`` was not read with this instance.
_UNREAD = object()


def hold_to_its_log(deployment: Deployment) -> None:
    """Bring a row found behind its transition log up to it -- and ``deployment``,
    the instance a surface is about to publish, with it.

    A row behind its log (legacy data: the stale full save before
    ``Deployment.save`` stopped writing the decision columns, or ``loaddata`` of a
    fixture dumped before its log moved) was repaired only by the next recompute.
    Until one came, every surface published the stale row: the log -- what every
    consumer draining :func:`transitions_since` was told -- said PAUSED at revision
    2, and the detail, the receipt, decision-support and the dispatch fence said
    READY at 1. A pause read as READY.

    The repair is :func:`bring_up_to_its_log`: it writes the row up to the log and
    records nothing, and it is not a recompute -- a read brings the row to what was
    decided, it decides nothing. Where the row cannot be written (a lock not granted
    in time, a read-only connection), or the one writer refuses the reading
    (:class:`StaleDecisionRead`), the instance is still brought to what the log
    records, read in one statement, and the failure is logged at ERROR: a read that
    cannot repair the row must not publish it, and must not fail on the pause the
    log holds either -- a refusal raised out of here was a 500 on a GET.

    ``logged_revision`` on the instance -- the :func:`logged_head` annotation, or
    set by the writer that just brought the row level -- answers "is it behind"
    without a query; an instance read without it costs one.
    """
    logged = getattr(deployment, "logged_revision", _UNREAD)
    if logged is _UNREAD:
        logged = (
            DecisionTransition.objects.filter(deployment_id=deployment.pk)
            .order_by("-revision")
            .values_list("revision", flat=True)
            .first()
        )
        # Kept on the instance, as the annotation would be: asked once per instance.
        deployment.logged_revision = logged
    if logged is None or logged <= deployment.decision_revision:
        return
    try:
        decision, revision = bring_up_to_its_log(deployment.pk)
    except (DatabaseError, StaleDecisionRead):
        logger.exception(
            "deployment %s: stored decision is behind its transition log and could not "
            "be brought up to it; publishing the decision the log records",
            deployment.pk,
        )
        in_force = published_decision(deployment.pk)
        if in_force is None:
            raise
        decision, revision = in_force
    deployment.decision = decision
    deployment.decision_revision = revision
    # Level with its log, as far as this instance goes: reconciling it again asks
    # nothing.
    deployment.logged_revision = revision


def bring_up_to_its_log(pk) -> tuple[str | None, int]:
    """Bring deployment ``pk``'s row up to its transition log; return the decision
    in force and its revision.

    Through the one writer, :func:`accept_transition`, as the no-op move TO the
    decision the log records. That decision is read under the row lock, in the
    transaction the move commits in -- its own: on PostgreSQL a read runs in
    autocommit, where a row lock outside a transaction is refused, and a reading
    taken off an unlocked row can be moved from after the row has moved, which
    ``accept_transition`` refuses. A row level with its log is left as it stands; a
    row behind it is written up to it, and nothing new is recorded -- the move was
    recorded when it was made.

    Not a recompute: it decides nothing, so it reads nothing the decision rule
    reads -- not the findings, and not the outcome keyring.
    """
    with transaction.atomic():
        locked = Deployment.objects.select_for_update().get(pk=pk)
        in_force = decision_in_force(locked)
        accept_transition(locked, to_decision=in_force.decision, in_force=in_force)
    return locked.decision, locked.decision_revision


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
