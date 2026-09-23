"""Null the 0.9 the AI-BOM drift deriver invented for every finding it created.

Migration 0016 made ``Finding.confidence`` nullable and nulled every value the
ingest had invented, reading each row's ``raw`` payload to tell a measured 0.5
from a defaulted one. It did its job. Then ``bom_drift._reconcile_finding`` went
on writing ``confidence=0.9`` into every machine-managed drift finding it
created, so the column filled back up with a number nobody computed -- and this
time with a figure high enough to read as near-certainty in a report.

Nothing measured 0.9. Drift is a set difference: a declared component that was
not observed, or an observed one that was not declared. That is either right
about what it compared or the inputs were wrong. It has no confidence.

The backfill uses 0016's rule, unchanged, so the two agree about what makes a
number real: read the row's own ``raw`` payload, and null the value only where
that payload carries no usable numeric ``confidence`` of its own. A drift
finding's ``raw`` carries ``machine_managed``, ``auto_resolved`` and ``drift``
and never a confidence, so every one of them is nulled -- but the rule is
written as the rule rather than as ``filter(confidence=0.9)``, because a row
that genuinely measured 0.9 would be indistinguishable to the latter and this
migration would silently discard the one real measurement it met.

Scoped to ``machine_managed`` rows. A finding some other deriver or a human
touched is not this migration's to edit.

Reversible in the only honest way available: going back does nothing. 0.9 was
never a measurement, so there is nothing to restore, and writing it again would
re-create the defect this removes. Django needs a callable to call the migration
reversible at all; this one is a no-op that says why.
"""

from django.db import migrations


def _null_the_invented_drift_confidences(apps, schema_editor):
    Finding = apps.get_model("assurance", "Finding")
    fixed = 0
    for finding in Finding.objects.exclude(confidence=None).iterator():
        raw = finding.raw if isinstance(finding.raw, dict) else {}
        if not raw.get("machine_managed"):
            continue
        reported = raw.get("confidence")
        usable = False
        if reported is not None:
            try:
                float(reported)
                usable = True
            except (TypeError, ValueError):
                usable = False
        if usable:
            continue
        finding.confidence = None
        finding.save(update_fields=["confidence"])
        fixed += 1
    if fixed:
        print(f"  nulled {fixed} machine-managed confidence value(s) nobody computed")


def _do_not_put_it_back(apps, schema_editor):
    """Deliberately a no-op. See this migration's docstring."""


class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0025_alter_latentcondition_kind"),
    ]

    operations = [
        migrations.RunPython(_null_the_invented_drift_confidences, _do_not_put_it_back),
    ]
