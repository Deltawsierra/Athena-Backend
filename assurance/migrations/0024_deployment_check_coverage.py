"""The second axis of coverage: which checks a scan ran.

`Asset.assessed_at` records that something assessed a component. It cannot say
which questions were asked of it, so a deployment whose every declared component
was assessed reads complete even when the engine never ran whole checks. This
stores the engine's own statement of that, verbatim, per deployment.
"""

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0023_chain_birth_registry"),
    ]

    operations = [
        migrations.AddField(
            model_name="deployment",
            name="check_coverage",
            field=models.JSONField(
                blank=True,
                default=dict,
                help_text="The latest scan's coverage manifest: which checks ran, "
                          "which did not, and why. Empty means none was reported.",
            ),
        ),
        migrations.AddField(
            model_name="deployment",
            name="check_coverage_at",
            field=models.DateTimeField(
                blank=True,
                null=True,
                help_text="When the stored check coverage was reported.",
            ),
        ),
    ]
