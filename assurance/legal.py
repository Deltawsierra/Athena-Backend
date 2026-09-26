"""Legal staleness — the second invalidation axis, and the human gate (Phase 2 item 6).

:mod:`assurance.invalidation` tracks one kind of drift: the system changed, so a
claim about it is due a retest. It has no notion of the other kind — the rule
changed while the deployment sat still — and no way to say that a config edit was
legally material as opposed to merely real.

The roadmap names why both halves matter, and the sentence is worth keeping in
front of a reader: *treating every config edit as automatically legally material
(or automatically not) is dishonest in both directions.* An automatic yes floods a
review queue until nobody reads it; an automatic no means the axis never fires and
the record quietly claims a legal currency nobody checked.

So there are two mechanisms here and neither one decides on its own.

**A trigger that flags and never judges.** When an obligation moves — a new
version, a new operative date — every current claim on every bound deployment
moves to ``REVIEW_PENDING``. Not to ``STALE``. The trigger has observed that
something changed; it has not established that the change matters here, and those
are different facts. :func:`supersede_obligation` is what a rule moving *is*, and
it is the trigger's call site: it links the versions, carries the previous
version's bindings forward so a replacement never silently binds nothing, and
flags. A trigger with no caller would be decoration.

**A gate that requires a person.** Only
:func:`record_materiality_decision` may set ``CURRENT`` or ``STALE``, and it
refuses without a user and a written rationale. A judgment with nobody behind it
is not a human judgment, and one with no reasoning cannot be defended later by
whoever has to defend it.

Independence
------------
``AssuranceClaim.status`` and ``AssuranceClaim.legal_status`` are separate fields
because all four combinations are real and each means something different:

- technically current, legally current — the ordinary good state;
- technically STALE, legally current — the system moved, the law did not;
- technically current, legally STALE — the system sat still and the rule beneath
  it changed, which is precisely the case the old single axis could not express;
- both stale — two independent reasons to re-assess, and a reader needs to know
  it is two.

Binding is explicit
-------------------
An obligation names the deployments it binds. Nothing here infers that an EU data
boundary implies a particular regulation, or that a US region implies a state
statute. Those are legal judgments about scope, and a module that guessed them
would be making exactly the call the materiality gate exists to keep with a human.
"""

from __future__ import annotations

import re

from django.db import transaction

from . import observability as obs
from .models import AssuranceClaim, ClaimEvent, LegalObligation, MaterialityDecision


class MaterialityDecisionRefused(ValueError):
    """A materiality decision was attempted without what makes it one.

    Raised rather than recording a partial decision. A row with no decider or no
    rationale would sit in the table looking exactly like a real judgment, and the
    whole point of the gate is that a legal position can be traced to the person
    who took it.
    """


def _legal(value: str) -> str:
    """One LegalStatus value by name, read off the enum so this module and the
    schema cannot drift apart on spelling."""
    from .models import LegalStatus

    return getattr(LegalStatus, value).value


def obligations_for(deployment) -> list[LegalObligation]:
    """The obligations explicitly bound to this deployment, newest rule first.

    Explicit membership only. See the module docstring: inferring scope from a
    region code is a legal judgment, and this layer does not make those.
    """
    return list(
        deployment.legal_obligations.all().order_by("-operative_date", "source")
    )


@transaction.atomic
def flag_for_materiality_review(obligation: LegalObligation, *, note: str = "") -> dict:
    """An obligation moved: flag every current claim on every bound deployment for
    review. Returns what was flagged.

    Flags. Does not judge. The claims land in ``REVIEW_PENDING``, which is neither
    legally current nor legally stale, because at this moment nobody has decided
    whether this change touches these claims and the record should say so rather
    than pick a side.

    Claims already ``STALE`` on the legal axis are left alone: a claim a human has
    already ruled legally stale does not become less stale because a second
    obligation moved, and re-flagging it would lose the decision that put it
    there. Claims already ``REVIEW_PENDING`` are left alone for the same reason —
    they are already in the queue.
    """
    pending = _legal("REVIEW_PENDING")
    stale = _legal("STALE")

    flagged: list[str] = []
    with obs.span(
        obs.PLAN, component="flag_for_materiality_review", subject=str(obligation.pk)
    ):
        for deployment in obligation.deployments.all():
            claims = (
                AssuranceClaim.objects.filter(deployment=deployment)
                .current()
                .exclude(legal_status__in=[pending, stale])
                .exclude(status=AssuranceClaim.ClaimStatus.REVOKED)
            )
            for claim in claims:
                previous = claim.legal_status
                claim.legal_status = pending
                claim.save(update_fields=["legal_status", "updated_at"])
                ClaimEvent.objects.create(
                    claim=claim,
                    from_status=claim.status,
                    to_status=claim.status,
                    actor=None,
                    note=(
                        f"Legal axis {previous} -> {pending}: {obligation} moved "
                        f"(operative {obligation.operative_date}). "
                        f"No materiality judgment has been made.{(' ' + note) if note else ''}"
                    ),
                )
                flagged.append(str(claim.uuid))

    return {
        "obligation": str(obligation.uuid),
        "flagged": flagged,
        "flagged_count": len(flagged),
        # Said out loud on every call: the trigger's whole contract is that it
        # produced a queue, not a verdict.
        "judged": False,
    }


@transaction.atomic
def supersede_obligation(
    previous: LegalObligation,
    replacement: LegalObligation,
    *,
    note: str = "",
) -> dict:
    """Record that one version of a rule has replaced another, and flag what that
    touches.

    This is what "the rule moved" actually is, and it is the reason
    :func:`flag_for_materiality_review` exists rather than being a function nobody
    reaches. Superseding does three things and no more: it links the versions so
    the chain is walkable, it carries the previous version's deployment bindings
    forward so a replacement does not silently bind nothing, and it flags the
    affected claims for review.

    It does not judge. Every claim it touches lands in ``REVIEW_PENDING``; whether
    the new version changes anything for a given claim is the materiality
    question, and that stays with a person.

    Bindings are carried forward, never invented: the replacement binds the union
    of what it already bound and what the previous version bound. A regulator
    amending a rule does not narrow its scope by amending it, and a replacement
    that quietly bound fewer deployments than the rule it replaced would move
    claims out of scope with nobody deciding to.
    """
    if previous.pk == replacement.pk:
        raise ValueError("an obligation cannot supersede itself")

    previous.superseded_by = replacement
    previous.save(update_fields=["superseded_by", "updated_at"])

    carried = [
        deployment
        for deployment in previous.deployments.all()
        if not replacement.deployments.filter(pk=deployment.pk).exists()
    ]
    if carried:
        replacement.deployments.add(*carried)

    flagged = flag_for_materiality_review(
        replacement,
        note=(
            f"Supersedes {previous} (v{previous.source_version})."
            f"{(' ' + note) if note else ''}"
        ),
    )
    return {
        "previous": str(previous.uuid),
        "replacement": str(replacement.uuid),
        "bindings_carried_forward": [str(d.uuid) for d in carried],
        **flagged,
    }


def record_materiality_decision(
    claim: AssuranceClaim,
    obligation: LegalObligation,
    *,
    decided_by,
    material: bool,
    rationale: str,
) -> MaterialityDecision:
    """The gate: a person judges whether this obligation makes this claim stale.

    The ONLY path to ``CURRENT`` or ``STALE`` on the legal axis. ``material=True``
    moves the claim to legally STALE; ``material=False`` moves it to legally
    CURRENT — which is a positive finding, not a default, and is why it takes a
    decision too. A claim nobody has judged stays ``NOT_ASSESSED`` or
    ``REVIEW_PENDING``, and neither of those reads as legally sound.

    Refuses without a decider or a rationale. Both are what make this a human
    judgment rather than a row: the first says who is accountable, the second says
    what they concluded and why, which is the part a regulator or a customer will
    actually ask about.

    The technical axis is untouched. A claim can be legally stale and technically
    current, and flattening the second into the first would lose the distinction
    this whole item exists to draw.
    """
    if decided_by is None:
        raise MaterialityDecisionRefused(
            "a materiality decision needs the person who made it: an unattributed "
            "legal judgment is not a human decision"
        )
    if not (rationale or "").strip():
        raise MaterialityDecisionRefused(
            "a materiality decision needs a written rationale: a conclusion nobody "
            "can review is not one anybody can defend"
        )

    with transaction.atomic():
        decision = MaterialityDecision.objects.create(
            claim=claim,
            obligation=obligation,
            decided_by=decided_by,
            material=bool(material),
            rationale=rationale.strip(),
        )

        previous = claim.legal_status
        claim.legal_status = _legal("STALE") if material else _legal("CURRENT")
        claim.save(update_fields=["legal_status", "updated_at"])

        ClaimEvent.objects.create(
            claim=claim,
            # The TECHNICAL status is unchanged on both sides, recorded so the
            # event does not read as a status move it is not.
            from_status=claim.status,
            to_status=claim.status,
            actor=decided_by,
            note=(
                f"Legal axis {previous} -> {claim.legal_status}: {obligation} judged "
                f"{'material' if material else 'not material'} by "
                f"{getattr(decided_by, 'username', decided_by)}. {decision.rationale}"
            ),
        )

    return decision


def ruling_for_next_version(previous: AssuranceClaim) -> str:
    """The legal axis a claim's next version starts with: the one its predecessor is
    in, unchanged.

    A re-derive is technical -- the system moved, or the claim was re-read -- and the
    rule beneath the claim did not move because of it. So a person's ruling stands
    for the new version exactly as recorded, and a review still pending stays
    pending. The new version used to start "not assessed", which erased a legally
    STALE ruling with no person behind the erasure and dropped a pending review
    unreviewed: a legal judgment made by code, the thing this module's gate exists
    to prevent. Decided here, beside the gate, so nothing outside this module
    chooses what the legal axis is.

    The status AS IT STANDS WHEN THE VERSION CLOSES, and nothing after: a ruling
    recorded on a version after a re-derive closed it applies to that version, which
    is what the person ruled on, and is not carried to the one that replaced it.
    :func:`carried_legal_statuses` and migration 0037 replay the record by this same
    rule."""
    return previous.legal_status


# ---------------------------------------------------------------------------
# The carry, replayed from the record: what a release that did not carry left
# ---------------------------------------------------------------------------
#
# A re-derive by the release before this one opened every new version "not
# assessed". Mid-rollout that release is still writing, after 0037 has run, so the
# ruling it drops is dropped after the one-shot repair: nothing brought it back, and
# the claim a person judged legally stale read unjudged -- capping nothing -- for
# good. The decision therefore reads the legal axis as the carry leaves it
# (:func:`carried_legal_statuses`), whatever wrote the rows, and
# :func:`carry_rulings_to_current` writes it back where it was dropped, wherever
# that release's writes are next seen (``assurance.carry``).

#: The prefix of the event :func:`carry_rulings_to_current` writes for each status it
#: moves, read back as the move it records so a second pass finds it explained.
CARRIED_NOTE = "Legal axis carried forward to this version: "
_CARRIED = re.compile(
    r"^Legal axis carried forward (?:by migration 0037|to this version): (\S+) -> (\S+)\."
)
#: The event :func:`flag_for_materiality_review` writes when it flags a claim.
_FLAGGED = re.compile(r"^Legal axis \S+ -> legal_review_pending: ")

# One moment's moves are replayed in this order: a person's ruling, then an event.
_RULING, _EVENT = 0, 1
_SET, _FLAG = "set", "flag"


def _replay(start: str, moves) -> str:
    """The legal status ``moves`` leave a version in, from ``start``: a ruling (or a
    carry the record names) sets it; a review flag moves it to pending unless it is
    already stale or pending, as :func:`flag_for_materiality_review` does."""
    carried = start
    for kind, status in moves:
        if kind == _FLAG:
            if carried not in (_legal("STALE"), _legal("REVIEW_PENDING")):
                carried = _legal("REVIEW_PENDING")
        else:
            carried = status
    return carried


def _as_left(status: str) -> list:
    """A stored status the record does not explain -- set by hand, or its ruling's
    obligation since deleted -- as the move that would leave it: "not assessed" is
    how a version opens and says nothing happened, a pending review reads as a flag,
    a ruling sets the axis."""
    if status == _legal("NOT_ASSESSED"):
        return []
    if status == _legal("REVIEW_PENDING"):
        return [(_FLAG, None)]
    return [(_SET, status)]


def replay_lineage(versions) -> str:
    """The legal status the carry leaves the LAST of ``versions`` in.

    ``versions`` are one claim's, oldest first, each ``(stored_status, closed_at,
    moves)``: ``closed_at`` is ``None`` for the current version, and ``moves`` are
    ``(moment, kind, status)`` in the order they happened. Pure.

    Each version starts from what its predecessor stood at WHEN IT CLOSED, and moves
    by what was recorded on it. A move recorded on a version after it closed applies
    to that version only: the carry happens at the close (:func:`ruling_for_next_version`).
    A stored status is explained if its version's own moves lead to it from what was
    carried in -- or from "not assessed", which is how a release that did not carry
    opened it. One the record does not explain stands as the version left it, at its
    close.
    """
    carried = _legal("NOT_ASSESSED")
    for stored, closed_at, moves in versions:
        steps = [(kind, status) for _at, kind, status in moves]
        explained = stored in (_replay(carried, steps), _replay(_legal("NOT_ASSESSED"), steps))
        standing = _replay(
            carried, [(kind, status) for at, kind, status in moves if closed_at is None or at <= closed_at]
        )
        if not explained:
            standing = _replay(standing, _as_left(stored))
        carried = standing
    return carried


def _recorded_moves(claim_pks) -> dict:
    """What the record says happened on the legal axis of each claim version named:
    ``{pk: [(moment, kind, status), ...]}``, in the order it happened. Two queries."""
    moves: dict = {pk: [] for pk in claim_pks}
    for claim_id, decided_at, pk, material in MaterialityDecision.objects.filter(
        claim_id__in=claim_pks
    ).values_list("claim_id", "decided_at", "pk", "material"):
        status = _legal("STALE") if material else _legal("CURRENT")
        moves[claim_id].append((decided_at, _RULING, pk, _SET, status))
    for claim_id, created_at, pk, note in ClaimEvent.objects.filter(
        claim_id__in=claim_pks, note__startswith="Legal axis "
    ).values_list("claim_id", "created_at", "pk", "note"):
        carried = _CARRIED.match(note)
        if carried is not None:
            moves[claim_id].append((created_at, _EVENT, pk, _SET, carried.group(2)))
        elif _FLAGGED.match(note):
            moves[claim_id].append((created_at, _EVENT, pk, _FLAG, None))
    return {
        pk: [(at, kind, status) for at, _order, _pk, kind, status in sorted(recorded, key=lambda m: m[:3])]
        for pk, recorded in moves.items()
    }


def _lineages(deployment_id, fingerprints) -> dict:
    """Every version of each claim identity named, oldest first, with what was
    recorded on each: ``{fingerprint: [(claim, moves), ...]}``. Three queries.

    Oldest first in the order the re-derives made them: back from the current version
    along ``superseded_by``, as 0037 reads a lineage -- not by ``valid_from``, which a
    clock that stepped back between two re-derives (two hosts mid-rollout) reorders,
    and the ruling a person made on the first version was then replayed onto no
    current version at all. A version no re-derive links to the current one is not in
    its lineage; an identity with no current version keeps the ``valid_from`` order,
    and nothing reads its carry (``carried_legal_statuses``)."""
    versions = list(
        AssuranceClaim.objects.filter(deployment_id=deployment_id, fingerprint__in=fingerprints)
        .filter(effective_to__isnull=True)
        .only("pk", "fingerprint", "legal_status", "valid_from", "valid_to", "status", "superseded_by_id")
        .order_by("valid_from", "pk")
    )
    moves = _recorded_moves([v.pk for v in versions])
    by_identity: dict = {}
    for version in versions:
        by_identity.setdefault(version.fingerprint, []).append(version)
    lineages: dict = {}
    for fingerprint, chain in by_identity.items():
        head = next((v for v in chain if v.valid_to is None), None)
        if head is not None:
            previous = {v.superseded_by_id: v for v in chain if v.superseded_by_id is not None}
            walked, seen = [head], {head.pk}
            while walked[-1].pk in previous and previous[walked[-1].pk].pk not in seen:
                walked.append(previous[walked[-1].pk])
                seen.add(walked[-1].pk)
            chain = walked[::-1]
        lineages[fingerprint] = [(v, moves[v.pk]) for v in chain]
    return lineages


def _carry_candidates(deployment_id, current) -> set:
    """The identities among ``current`` whose legal axis the carry may have left
    somewhere other than where the row stands: a current version still "not assessed"
    or "pending", with a closed version of the same claim that is neither. One query,
    none when there is no such current version."""
    open_axis = {_legal("NOT_ASSESSED"), _legal("REVIEW_PENDING")}
    wanted = {c.fingerprint for c in current if c.legal_status in open_axis}
    if not wanted:
        return set()
    return set(
        AssuranceClaim.objects.closed()
        .filter(deployment_id=deployment_id, fingerprint__in=wanted)
        .exclude(legal_status=_legal("NOT_ASSESSED"))
        .values_list("fingerprint", flat=True)
        .distinct()
    )


def carried_legal_statuses(deployment_id, current) -> dict:
    """The legal status each claim in ``current`` (current versions of one deployment)
    stands at as the carry leaves it: ``{claim_pk: status}``, for the ones where
    that is not what the row holds.

    What the decision reads, so a ruling a release that did not carry dropped still
    caps it -- whatever wrote the rows and whether or not anything has repaired them
    yet. Only a version "not assessed" or "pending" can differ: one a person ruled on
    is theirs. One query when nothing can differ; four when something might."""
    candidates = _carry_candidates(deployment_id, current)
    if not candidates:
        return {}
    by_pk = {c.pk: c for c in current if c.fingerprint in candidates}
    carried = {}
    for fingerprint, lineage in _lineages(deployment_id, candidates).items():
        head, _moves = lineage[-1]
        if head.pk not in by_pk:
            continue  # the lineage ends on a version that is not current
        status = replay_lineage([(v.legal_status, v.valid_to, moves) for v, moves in lineage])
        if status != by_pk[head.pk].legal_status:
            carried[head.pk] = status
    return carried


def carry_rulings_to_current(deployment, *, now=None) -> int:
    """Write the legal axis back onto each current version of ``deployment``'s claims
    where a release that did not carry dropped it; the number of versions moved.

    What :func:`carried_legal_statuses` reads, made the row: each status moved in its
    own short transaction, only if the row still holds what was read (a person's
    ruling landing meanwhile stands), with an event on the claim's lifecycle naming
    the move. Idempotent: the event is read back as the move it records. No
    materiality judgment is made here, and no refresh is scheduled -- the caller
    brings the decision current (``assurance.carry``)."""
    from django.utils import timezone

    now = now or timezone.now()
    current = list(
        AssuranceClaim.objects.filter(deployment=deployment)
        .current()
        .exclude(status=AssuranceClaim.ClaimStatus.REVOKED)
        .only("pk", "fingerprint", "legal_status", "status")
    )
    carried = carried_legal_statuses(deployment.pk, current)
    moved = 0
    for claim in current:
        status = carried.get(claim.pk)
        if status is None:
            continue
        with transaction.atomic():
            if not AssuranceClaim.objects.filter(pk=claim.pk, legal_status=claim.legal_status).update(
                legal_status=status, updated_at=now
            ):
                continue
            ClaimEvent.objects.create(
                claim_id=claim.pk,
                from_status=claim.status,
                to_status=claim.status,
                actor=None,
                note=(
                    f"{CARRIED_NOTE}{claim.legal_status} -> {status}. A re-derive by a release "
                    "that did not carry the legal axis opened this version without it; replayed "
                    "from the rulings and review flags on record across the claim's versions, it "
                    f"stands at {status}. No materiality judgment was made here."
                ),
            )
        moved += 1
    return moved


def legal_posture(deployment) -> dict:
    """What the deployment's claims look like on the legal axis, counted honestly.

    ``not_assessed`` is reported separately from ``current`` rather than summed
    into a percentage. A deployment where nine claims are legally current and one
    was never reviewed is not "90% compliant": it has an unexamined claim, and the
    number that hides it is the one a reader would quote.
    """
    claims = list(AssuranceClaim.objects.filter(deployment=deployment).current())
    counts = {
        value: 0
        for value, _label in AssuranceClaim._meta.get_field("legal_status").choices
    }
    for claim in claims:
        counts[claim.legal_status] = counts.get(claim.legal_status, 0) + 1

    pending = counts.get(_legal("REVIEW_PENDING"), 0)
    stale = counts.get(_legal("STALE"), 0)
    unassessed = counts.get(_legal("NOT_ASSESSED"), 0)

    return {
        "obligations": [str(o.uuid) for o in obligations_for(deployment)],
        "claim_count": len(claims),
        "by_legal_status": counts,
        # Three separate numbers, never one score. Each calls for different work:
        # a pending review needs a person, a stale claim needs re-assessment, an
        # unassessed one needs somebody to look at it for the first time.
        "awaiting_materiality_review": pending,
        "legally_stale": stale,
        "never_legally_assessed": unassessed,
        "summary": (
            f"{len(claims)} current claim(s): {stale} legally stale, "
            f"{pending} awaiting review, {unassessed} never assessed"
        ),
    }
