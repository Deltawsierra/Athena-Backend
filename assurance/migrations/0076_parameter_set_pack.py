# SPINE Economic Exposure, E7: industry packs (docs/economics/spec-v1.md, section 37).
# One new column: the industry pack a customer parameter-set version answers, blank
# for the banking pack. Every version recorded before this answers the banking pack
# and reads blank, so nothing is backfilled and no recorded version's digest moves.
# Numbered 0076 behind #169's 0074 and #170's 0075; until both are merged it depends
# on 0073, the last migration on master, and is re-pointed at 0075 when they are.

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("assurance", "0073_exposure_assurance"),
    ]

    operations = [
        migrations.AddField(
            model_name="customerparameterset",
            name="pack",
            field=models.CharField(blank=True, default="", max_length=100),
        ),
    ]
