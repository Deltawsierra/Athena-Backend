from django.db import migrations

#: ``LatentCondition.State`` values when this migration was written: a condition
#: still watched. Spelled here, not imported: a migration records what it did.
WATCHED = ("pending", "unobservable")
#: ``LegalStatus.NOT_ASSESSED``.
NOT_ASSESSED = "legally_not_assessed"


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

    orphaned = LatentCondition.objects.filter(state__in=WATCHED, claim__valid_to__isnull=False).select_related("claim")
    for condition in orphaned.iterator():
        current = _current_version(AssuranceClaim, condition.claim)
        if current is not None and current.pk != condition.claim_id:
            condition.claim = current
            condition.save(update_fields=["claim"])

    # A current version still "not assessed" whose predecessor carried a ruling: the
    # ruling of the nearest predecessor that had one.
    for claim in AssuranceClaim.objects.filter(valid_to__isnull=True, legal_status=NOT_ASSESSED).iterator():
        seen = {claim.pk}
        previous = AssuranceClaim.objects.filter(superseded_by_id=claim.pk).first()
        while previous is not None and previous.pk not in seen:
            if previous.legal_status != NOT_ASSESSED:
                claim.legal_status = previous.legal_status
                claim.save(update_fields=["legal_status"])
                break
            seen.add(previous.pk)
            previous = AssuranceClaim.objects.filter(superseded_by_id=previous.pk).first()


class Migration(migrations.Migration):
    dependencies = [
        ("assurance", "0036_accepted_risk_expires"),
    ]

    operations = [
        # Not reversed: moving a watch back onto a closed version, or erasing a
        # restored ruling, would recreate the defect this repairs.
        migrations.RunPython(carry_forward, migrations.RunPython.noop),
    ]
