import re

from django.db import migrations

#: ``LegalStatus`` values when this migration was written. Spelled here, not
#: imported: a migration records what it did.
NOT_ASSESSED = "legally_not_assessed"
REVIEW_PENDING = "legal_review_pending"
LEGALLY_STALE = "legally_stale"
LEGALLY_CURRENT = "legally_current"

#: The event ``legal.flag_for_materiality_review`` writes when a moved obligation
#: flags a claim for review, as it was written when this migration was.
_FLAG = re.compile(r"^Legal axis \S+ -> legal_review_pending: ")
#: The event this migration writes for each status it moves -- read back as the move
#: it records, so a second pass finds the status explained and changes nothing.
_MOVED_BY_THIS = "Legal axis carried forward by migration 0037: "
_MOVED = re.compile(r"^Legal axis carried forward by migration 0037: (\S+) -> (\S+)\.")

# The order one moment's events are replayed in: a person's ruling, then a flag or a
# move recorded as an event.
_RULING, _EVENT = 0, 1


def carry_forward(apps, schema_editor):
    """The legal axis a re-derive dropped, brought to the current version of each
    claim: what that version would say had the ruling always been carried.

    Until now a re-derive opened each new version "not assessed", so a claim a
    person had judged legally stale came back unjudged, and a review still pending
    was dropped. The code now carries the axis at the re-derive; this carries what
    was dropped before it did.

    Replayed from the record, in the order it happened, across every version of
    the claim: each person's ruling (a ``MaterialityDecision``: material is STALE,
    not material is CURRENT) sets the axis, and each review flag (the "Legal axis
    ... -> legal_review_pending" event) moves it to pending unless it is already
    stale or pending (``legal.flag_for_materiality_review``). A replay from each
    version's final status alone read a version ruled STALE and then its successor
    flagged -- and restored STALE over the person's own later ruling on the
    successor that it was NOT material: a legal judgment nobody made.

    Where the record does not explain a version's status -- set by hand, or its
    ruling's obligation since deleted -- that status stands as the version left it,
    at the moment it closed. Only a current version still "not assessed" or
    "pending" is corrected: one a person ruled on is theirs. Every status moved is
    recorded as an event on the claim's own lifecycle, naming this migration.

    Watches left behind on a closed version are carried by 0038, after the
    declaration constraint allows a withdrawn watch beside a live one.
    """
    AssuranceClaim = apps.get_model("assurance", "AssuranceClaim")
    ClaimEvent = apps.get_model("assurance", "ClaimEvent")
    MaterialityDecision = apps.get_model("assurance", "MaterialityDecision")

    for claim in AssuranceClaim.objects.filter(
        valid_to__isnull=True, legal_status__in=(NOT_ASSESSED, REVIEW_PENDING)
    ).iterator():
        versions = [claim]
        seen = {claim.pk}
        previous = AssuranceClaim.objects.filter(superseded_by_id=claim.pk).first()
        while previous is not None and previous.pk not in seen:
            versions.append(previous)
            seen.add(previous.pk)
            previous = AssuranceClaim.objects.filter(superseded_by_id=previous.pk).first()
        if len(versions) == 1:
            # A first version: no re-derive dropped anything from it.
            continue
        versions.reverse()  # oldest first
        events = []
        for index, version in enumerate(versions):
            own = _recorded_on(version, ClaimEvent, MaterialityDecision)
            events += own
            if _replay(e[-2:] for e in own) != version.legal_status:
                events.append(_as_it_closed(version, index))
        replayed = _replay(e[-2:] for e in sorted(events, key=lambda e: e[:-2]))
        if replayed == claim.legal_status:
            continue
        ClaimEvent.objects.create(
            claim_id=claim.pk,
            from_status=claim.status,
            to_status=claim.status,
            actor=None,
            note=(
                f"{_MOVED_BY_THIS}{claim.legal_status} -> {replayed}. A re-derive before this "
                "release opened each version of a claim not assessed on the legal axis; "
                "replayed from the rulings and review flags on record across its versions, "
                f"in the order they happened, it stands at {replayed}. No materiality "
                "judgment was made here."
            ),
        )
        claim.legal_status = replayed
        claim.save(update_fields=["legal_status"])


def _recorded_on(version, ClaimEvent, MaterialityDecision) -> list:
    """What the record says happened on ``version``'s legal axis, as sortable
    ``(phase, moment, order, pk, kind, status)`` events."""
    events = [
        (0, decided_at, _RULING, pk, "set", LEGALLY_STALE if material else LEGALLY_CURRENT)
        for decided_at, pk, material in MaterialityDecision.objects.filter(claim_id=version.pk).values_list(
            "decided_at", "pk", "material"
        )
    ]
    for created_at, pk, note in ClaimEvent.objects.filter(
        claim_id=version.pk, note__startswith="Legal axis "
    ).values_list("created_at", "pk", "note"):
        moved = _MOVED.match(note)
        if moved is not None:
            events.append((0, created_at, _EVENT, pk, "set", moved.group(2)))
        elif _FLAG.match(note):
            events.append((0, created_at, _EVENT, pk, "flag", None))
    return sorted(events, key=lambda e: e[:-2])


def _as_it_closed(version, index) -> tuple:
    """A version's own status, as an event at the moment it closed -- after
    everything else, for the current version -- for a status the record does not
    explain."""
    if version.valid_to is None:
        return (1, index, 0, 0, "as_left", version.legal_status)
    return (0, version.valid_to, _EVENT, 0, "as_left", version.legal_status)


def _replay(events) -> str:
    """The legal status ``events`` leave a claim in, from "not assessed", each a
    ``(kind, status)`` in the order it happened."""
    carried = NOT_ASSESSED
    for kind, status in events:
        if kind == "as_left":
            # A version's own status the record does not explain: "not assessed" is
            # how every re-derive opened a version, and says nothing happened; a
            # pending review reads as a flag; a ruling sets the axis.
            if status == NOT_ASSESSED:
                continue
            kind = "flag" if status == REVIEW_PENDING else "set"
        if kind == "flag":
            if carried not in (LEGALLY_STALE, REVIEW_PENDING):
                carried = REVIEW_PENDING
            continue
        carried = status
    return carried


class Migration(migrations.Migration):
    dependencies = [
        ("assurance", "0036_accepted_risk_expires"),
    ]

    operations = [
        # Irreversible. Undoing it would erase a restored ruling and the event that
        # records it, recreating the defect this repairs; a reverse that did nothing
        # would claim an undo that did not happen.
        migrations.RunPython(carry_forward),
    ]
