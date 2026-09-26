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

# The order one moment's moves are replayed in: a person's ruling, then an event.
_RULING, _EVENT = 0, 1


def carry_forward(apps, schema_editor):
    """The legal axis a re-derive dropped, brought to the current version of each
    claim: what that version would say had the ruling always been carried.

    Until now a re-derive opened each new version "not assessed", so a claim a
    person had judged legally stale came back unjudged, and a review still pending
    was dropped. The code now carries the axis at the re-derive; this carries what
    was dropped before it did.

    Replayed from the record, version by version, oldest first, by the rule the
    carry follows (``legal.ruling_for_next_version``): each version starts from what
    its predecessor stood at WHEN IT CLOSED, and moves by what was recorded on it --
    each person's ruling (a ``MaterialityDecision``: material is STALE, not material
    is CURRENT) sets the axis, and each review flag (the "Legal axis ... ->
    legal_review_pending" event) moves it to pending unless it is already stale or
    pending (``legal.flag_for_materiality_review``), in the order they happened. A
    ruling recorded on a version after a re-derive closed it applies to that
    version, which is what the person ruled on, and is not carried: replayed in one
    time order across every version, such a ruling reached the current version here
    while the running code, from the same history, left it where it was made -- the
    two disagreed about what a person had ruled on.

    Where the record does not explain a version's status -- set by hand, or its
    ruling's obligation since deleted -- that status stands as the version left it,
    at the moment it closed. Only a current version still "not assessed" or
    "pending" is corrected: one a person ruled on is theirs. Every status moved is
    recorded as an event on the claim's own lifecycle, naming this migration.

    The running code reads and repairs the axis by the same replay
    (``legal.replay_lineage``) wherever a release that did not carry it wrote after
    this ran; a test holds the two to one answer over the same histories.

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
        replayed = _replay_lineage(
            [
                (version.legal_status, version.valid_to, _recorded_on(version, ClaimEvent, MaterialityDecision))
                for version in versions
            ]
        )
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
                f"each carried at its close, it stands at {replayed}. No materiality "
                "judgment was made here."
            ),
        )
        claim.legal_status = replayed
        claim.save(update_fields=["legal_status"])


def _recorded_on(version, ClaimEvent, MaterialityDecision) -> list:
    """What the record says happened on ``version``'s legal axis, as ``(moment,
    kind, status)`` moves in the order they happened."""
    events = [
        (decided_at, _RULING, pk, "set", LEGALLY_STALE if material else LEGALLY_CURRENT)
        for decided_at, pk, material in MaterialityDecision.objects.filter(claim_id=version.pk).values_list(
            "decided_at", "pk", "material"
        )
    ]
    for created_at, pk, note in ClaimEvent.objects.filter(
        claim_id=version.pk, note__startswith="Legal axis "
    ).values_list("created_at", "pk", "note"):
        moved = _MOVED.match(note)
        if moved is not None:
            events.append((created_at, _EVENT, pk, "set", moved.group(2)))
        elif _FLAG.match(note):
            events.append((created_at, _EVENT, pk, "flag", None))
    return [(at, kind, status) for at, _order, _pk, kind, status in sorted(events, key=lambda e: e[:3])]


def _replay(start, moves) -> str:
    """The legal status ``moves`` -- ``(kind, status)`` in the order they happened --
    leave a version in, from ``start``."""
    carried = start
    for kind, status in moves:
        if kind == "flag":
            if carried not in (LEGALLY_STALE, REVIEW_PENDING):
                carried = REVIEW_PENDING
            continue
        carried = status
    return carried


def _as_left(status) -> list:
    """A version's own status the record does not explain, as the move that leaves
    it: "not assessed" is how every re-derive opened a version, and says nothing
    happened; a pending review reads as a flag; a ruling sets the axis."""
    if status == NOT_ASSESSED:
        return []
    if status == REVIEW_PENDING:
        return [("flag", None)]
    return [("set", status)]


def _replay_lineage(versions) -> str:
    """The legal status the carry leaves the last of ``versions`` in: each
    ``(stored_status, closed_at, moves)``, oldest first, ``closed_at`` None for the
    current one. Each starts from what its predecessor stood at when it closed."""
    carried = NOT_ASSESSED
    for stored, closed_at, moves in versions:
        steps = [(kind, status) for _at, kind, status in moves]
        explained = stored in (_replay(carried, steps), _replay(NOT_ASSESSED, steps))
        standing = _replay(
            carried, [(kind, status) for at, kind, status in moves if closed_at is None or at <= closed_at]
        )
        if not explained:
            standing = _replay(standing, _as_left(stored))
        carried = standing
    return carried


class Migration(migrations.Migration):
    dependencies = [
        ("assurance", "0036_accepted_risk_expires"),
    ]

    operations = [
        # Irreversible. Undoing it would erase a restored ruling and the event that
        # records it, recreating the defect this repairs; a reverse that did nothing
        # would claim an undo that did not happen. A `migrate` whose plan would
        # reverse it is refused before anything is unapplied
        # (`assurance.signals.refuse_a_reverse_past_an_irreversible_step`).
        migrations.RunPython(carry_forward),
    ]
