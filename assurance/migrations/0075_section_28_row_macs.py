# Section 28 hardening, review round 1 of #169, M1 (docs/economics/spec-v1.md,
# section 35.9): a simulation result and its Validity Card each record a MAC under
# the row key (ATHENA_ECONOMICS_ROW_KEY), which the database never holds. Two
# AddFields, empty by default; no backfill here: a migration runs where the key may
# not be set, and a row is bound only where its digests verify, by
# `manage.py bind_economics_rows` once the key is provisioned (assurance.economics.
# row_mac.bind_stored_rows).

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0074_section_28_hardening"),
    ]

    operations = [
        migrations.AddField(
            model_name="financialvaliditycard",
            name="row_mac",
            field=models.CharField(blank=True, default="", max_length=80),
        ),
        migrations.AddField(
            model_name="simulationresult",
            name="row_mac",
            field=models.CharField(blank=True, default="", max_length=80),
        ),
    ]
