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
