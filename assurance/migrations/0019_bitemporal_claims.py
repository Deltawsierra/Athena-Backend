"""Split the claim's single temporal axis into two (Phase 2 item 5).

``valid_from``/``valid_to`` were labelled "bitemporal" and were one axis: they
record when Mythos *held* a version, and nothing recorded when the state it
describes actually *held*. This adds the effective axis and re-cuts the
"one current version" constraint to mean both.

The backfill is the part worth reading.
"""

import django.utils.timezone
from django.conf import settings
from django.db import migrations, models


def backfill_effective_window(apps, schema_editor):
    """Every existing row's effective window is copied from its recorded window.

    Django's ``AddField`` default would stamp ``effective_from`` with the moment
    the migration runs, which would assert that every claim ever made became
    effective at deploy time. That is a fact nobody observed.

    What we actually know about a historical row is when we recorded it, so the
    honest reading is "it began holding when we first saw it, and stopped when we
    stopped believing it" -- effective mirrors recorded. It may understate how
    long a state really held (we cannot know we were late), and understating is
    the safe direction: it never claims knowledge of a period nobody looked at.

    A current row (``valid_to`` null) gets ``effective_to`` null and stays
    current; a superseded row gets both set and stays history. So the constraint
    added after this step matches exactly the rows it matched before.
    """
    AssuranceClaim = apps.get_model("assurance", "AssuranceClaim")
    for claim in AssuranceClaim.objects.all().iterator(chunk_size=500):
        AssuranceClaim.objects.filter(pk=claim.pk).update(
            effective_from=claim.valid_from,
            effective_to=claim.valid_to,
        )


def unbackfill(apps, schema_editor):
    """Reversing drops the effective axis with the columns; nothing to undo."""


class Migration(migrations.Migration):
    dependencies = [
        ("assurance", "0018_asset_assessed_at_asset_assessed_by_and_more"),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.RemoveConstraint(
            model_name="assuranceclaim",
            name="uq_current_claim",
        ),
        migrations.AddField(
            model_name="assuranceclaim",
            name="effective_from",
            field=models.DateTimeField(default=django.utils.timezone.now),
        ),
        migrations.AddField(
            model_name="assuranceclaim",
            name="effective_to",
            field=models.DateTimeField(blank=True, null=True),
        ),
        # Between the columns and the constraint, deliberately: the constraint
        # must be built over backfilled data, and the backfill must not be able to
        # move a row into or out of the current slot.
        migrations.RunPython(backfill_effective_window, unbackfill),
        migrations.AddConstraint(
            model_name="assuranceclaim",
            constraint=models.UniqueConstraint(
                condition=models.Q(
                    ("valid_to__isnull", True), ("effective_to__isnull", True)
                ),
                fields=("deployment", "fingerprint"),
                name="uq_current_claim",
            ),
        ),
    ]
