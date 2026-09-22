"""Finding.confidence becomes nullable, and two dispositions are added.

The schema change is mechanical. The data migration is not, so it is spelled out:

Every existing row carries ``confidence = 0.5`` where the ingest had nothing to
put there, because the old field defaulted to 0.5 and the old ingest coerced an
absent or unparseable value to the same number. That makes a measured 0.5 and an
invented one indistinguishable *in the column* -- but not in the row: each
Finding keeps the engine's raw payload in ``raw``, and whether that payload
carried a usable ``confidence`` is exactly the question.

So the backfill reads the evidence rather than guessing: a row whose ``raw`` has
no usable numeric ``confidence`` had one invented for it, and becomes NULL. A row
whose ``raw`` carries a number keeps its value, whatever that number is --
including a genuine 0.5. Rewriting every 0.5 to NULL would discard real
measurements; leaving them all at 0.5 would keep asserting a figure nobody
computed. Neither is honest, and the raw payload is what tells them apart.

Reversible: going back writes 0.5 into the rows this nulled, because that is what
the column meant before. It does not pretend to recover which ones were real.
"""

from django.db import migrations, models


def _null_the_invented_confidences(apps, schema_editor):
    Finding = apps.get_model("assurance", "Finding")
    fixed = 0
    for finding in Finding.objects.exclude(confidence=None).iterator():
        raw = finding.raw if isinstance(finding.raw, dict) else {}
        reported = raw.get("confidence")
        usable = False
        if reported is not None:
            try:
                float(reported)
                usable = True
            except (TypeError, ValueError):
                usable = False
        if not usable:
            finding.confidence = None
            finding.save(update_fields=["confidence"])
            fixed += 1
    if fixed:
        print(f"  nulled {fixed} confidence value(s) the ingest had invented")


def _restore_the_default(apps, schema_editor):
    Finding = apps.get_model("assurance", "Finding")
    Finding.objects.filter(confidence=None).update(confidence=0.5)


class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0015_deployment_evidence_incomplete_and_more"),
    ]

    operations = [
        migrations.AlterField(
            model_name="finding",
            name="confidence",
            field=models.FloatField(blank=True, null=True),
        ),
        migrations.AlterField(
            model_name="finding",
            name="status",
            field=models.CharField(
                choices=[
                    ("open", "Open"),
                    ("triaged", "Triaged"),
                    ("remediating", "Remediating"),
                    ("retesting", "Retesting"),
                    ("contained", "Contained (defect not removed)"),
                    ("invalidated", "Invalidated (premise no longer holds)"),
                    ("closed", "Verified closed"),
                    ("accepted", "Accepted risk"),
                    ("false_positive", "False positive"),
                ],
                db_index=True,
                default="open",
                max_length=24,
            ),
        ),
        # After the column can hold NULL, and not before.
        migrations.RunPython(_null_the_invented_confidences, _restore_the_default),
    ]
