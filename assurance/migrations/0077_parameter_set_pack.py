# SPINE Economic Exposure, E7: industry packs (docs/economics/spec-v1.md, section 37).
# One new column: the industry pack a customer parameter-set version answers, blank
# for the banking pack. Every version recorded before this answers the banking pack
# and reads blank, so nothing is backfilled and no recorded version's digest moves.
# Numbered 0077 behind #169's 0074_section_28_hardening and 0075_section_28_row_macs
# (merged) and #170's 0076_figure_normalizations, on which it depends.

from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [
        ("assurance", "0076_figure_normalizations"),
    ]

    operations = [
        migrations.AddField(
            model_name="customerparameterset",
            name="pack",
            field=models.CharField(blank=True, default="", max_length=100),
        ),
    ]
