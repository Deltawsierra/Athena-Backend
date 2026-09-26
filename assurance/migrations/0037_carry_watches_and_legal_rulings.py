from django.db import migrations

#: ``LatentCondition.State`` values when this migration was written: a condition
#: still watched. Spelled here, not imported: a migration records what it did.
WATCHED = ("pending", "unobservable")
#: ``LatentCondition.State.WITHDRAWN``.
WITHDRAWN = "withdrawn"
#: ``LegalStatus`` values when this migration was written.
NOT_ASSESSED = "legally_not_assessed"
REVIEW_PENDING = "legal_review_pending"
LEGALLY_STALE = "legally_stale"


def _merged(into, observation):
    """The note an orphan is withdrawn with when the watch it carries is already on
    the current version. Written to ``fired_observation``, where a withdrawal's
    note was kept when this migration was written."""
    note = (
        f"Merged into the same declaration on the claim's current version ({into.uuid}, "
        f"{into.state}) when migration 0037 carried forward the watches a re-derive had "
        "left behind; withdrawn here so one watch is not counted as two."
    )
    return f"{note} Last observation here: {observation}" if observation else note


def _current_version(AssuranceClaim, claim):
    """The current version of ``claim``'s chain (``superseded_by`` to the end), or
    None if the chain ends on a closed version or loops."""
    seen = set()
    while claim.superseded_by_id is not None and claim.pk not in seen:
        seen.add(claim.pk)
        claim = AssuranceClaim.objects.filter(pk=claim.superseded_by_id).first()
        if claim is None:
            return None
    return claim if claim.valid_to is None else None


def carry_forward(apps, schema_editor):
    """What a re-derive left behind on the version it closed, brought to the current
    version of the same claim.

    Until now a re-derive opened the new version without the watches declared on
    the old one, and without its legal ruling. The watches stayed on the closed
    version, where nothing evaluates them, while the posture counted them watched;
    the ruling was simply gone -- a claim a person had judged legally stale came
    back "not assessed". The code now carries both at the re-derive; this carries
    what was left behind before it did.
    """
    AssuranceClaim = apps.get_model("assurance", "AssuranceClaim")
    LatentCondition = apps.get_model("assurance", "LatentCondition")

    # Read whole before any row moves, and newest first: where two orphans of one
    # watch sit on one chain, the most recent statement of it is the one carried.
    orphaned = list(
        LatentCondition.objects.filter(state__in=WATCHED, claim__valid_to__isnull=False)
        .select_related("claim")
        .order_by("-declared_at", "-pk")
    )
    for condition in orphaned:
        current = _current_version(AssuranceClaim, condition.claim)
        if current is None or current.pk == condition.claim_id:
            continue
        # The current version may already carry this declaration: an operator who
        # saw the watch left behind re-declared it there, or a second orphan of it
        # further up the chain was carried a moment ago. The constraint allows one
        # row per declaration per claim, so the move raised IntegrityError and the
        # whole migration aborted. The watch is on the current version already;
        # this row is kept, withdrawn, with a note saying where it went.
        already = (
            LatentCondition.objects.filter(
                claim_id=current.pk,
                kind=condition.kind,
                subject=condition.subject,
                expected=condition.expected,
            )
            .exclude(pk=condition.pk)
            .first()
        )
        if already is not None:
            condition.fired_observation = _merged(already, condition.fired_observation)
            condition.state = WITHDRAWN
            condition.save(update_fields=["state", "fired_observation"])
            continue
        condition.claim = current
        condition.save(update_fields=["claim"])

    # The legal axis, replayed. Every re-derive opened its version "not assessed",
    # so each version's legal_status records only what happened ON it: a review
    # flagged (pending), or a person's ruling (current, stale). Replaying a chain
    # oldest first under the rule the code now applies -- the next version carries
    # its predecessor's status; a flag leaves stale and pending as they are
    # (`legal.flag_for_materiality_review`) and moves anything else to pending; a
    # ruling sets the status -- gives what the current version would say had the
    # carry always happened. Only a current version still "not assessed" or
    # "pending" is corrected: one a person ruled on is theirs.
    #
    # Restoring onto "not assessed" alone missed a stale ruling whose version a
    # review was later flagged on: the flag landed on the version that had lost the
    # ruling, left it "pending", and the person's STALE -- which a flag leaves alone
    # -- stayed lost, with no cap on the decision.
    for claim in AssuranceClaim.objects.filter(
        valid_to__isnull=True, legal_status__in=(NOT_ASSESSED, REVIEW_PENDING)
    ).iterator():
        chain = [claim.legal_status]
        seen = {claim.pk}
        previous = AssuranceClaim.objects.filter(superseded_by_id=claim.pk).first()
        while previous is not None and previous.pk not in seen:
            chain.append(previous.legal_status)
            seen.add(previous.pk)
            previous = AssuranceClaim.objects.filter(superseded_by_id=previous.pk).first()
        replayed = _replayed(reversed(chain))
        if replayed != claim.legal_status:
            claim.legal_status = replayed
            claim.save(update_fields=["legal_status"])


def _replayed(statuses) -> str:
    """The legal status the newest version carries, given each version's own
    recorded status oldest first, under carry-forward."""
    carried = NOT_ASSESSED
    for recorded in statuses:
        if recorded == NOT_ASSESSED:
            continue
        if recorded == REVIEW_PENDING:
            if carried not in (LEGALLY_STALE, REVIEW_PENDING):
                carried = REVIEW_PENDING
            continue
        carried = recorded
    return carried

class Migration(migrations.Migration):
    dependencies = [
        ("assurance", "0036_accepted_risk_expires"),
    ]

    operations = [
        # Not reversed: moving a watch back onto a closed version, or erasing a
        # restored ruling, would recreate the defect this repairs.
        migrations.RunPython(carry_forward, migrations.RunPython.noop),
    ]
