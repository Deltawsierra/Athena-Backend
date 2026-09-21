"""Give an Unknown a readable subject, and a second machine source.

``subject`` names what a gap is *about* as a slug unique within its deployment,
so a consumer outside this database can ask for one specific gap without carrying
a fingerprint hash or an auto-increment id. Existing rows are backfilled from the
finding they derive from, which is the same identity the deriver now writes, so a
re-derive after this migration updates those rows rather than orphaning them.

The new ``posture`` source marks the gaps derived from provider postures nobody
declared. No existing row can be one, so nothing is re-labelled here.
"""

from django.db import migrations, models
from django.utils.text import slugify


def backfill_subjects(apps, schema_editor):
    """Name every existing gap the way the deriver now names it.

    A derived gap's subject is its finding's type, slugified, so a re-derive
    after this migration matches these rows instead of leaving them nameless
    until their next refresh. Done in chunks rather than one UPDATE because the
    value comes from a joined table, which ``QuerySet.update`` cannot reference.
    """
    Unknown = apps.get_model("assurance", "Unknown")
    rows = (
        Unknown.objects.filter(subject="")
        .exclude(finding_id=None)
        .select_related("finding")
        .only("id", "finding__finding_type")
    )
    batch = []
    for row in rows.iterator(chunk_size=500):
        row.subject = slugify((row.finding.finding_type or "").replace("_", "-")) or (
            f"finding-{row.finding_id}"
        )
        batch.append(row)
        if len(batch) >= 500:
            Unknown.objects.bulk_update(batch, ["subject"])
            batch.clear()
    if batch:
        Unknown.objects.bulk_update(batch, ["subject"])
    # A manually raised gap, and a derived one whose finding has since been
    # trimmed, keep an empty subject. There is no honest identity to invent for
    # them, and a made-up one could collide with a real gap later.


def drop_subjects(apps, schema_editor):
    """Reversing only drops the column, which AddField already undoes."""



class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0013_asset_classification_source"),
    ]

    operations = [
        migrations.AddField(
            model_name="unknown",
            name="subject",
            field=models.CharField(blank=True, db_index=True, max_length=200),
        ),
        migrations.RunPython(backfill_subjects, drop_subjects),
        migrations.AlterField(
            model_name="unknown",
            name="source",
            field=models.CharField(
                choices=[
                    ("derived", "Derived from a finding"),
                    ("posture", "Derived from an undeclared provider posture"),
                    ("manual", "Raised manually"),
                ],
                default="derived",
                max_length=16,
            ),
        ),
    ]
