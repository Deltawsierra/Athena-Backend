# SPINE SP-4, part 2a: what a recovery step and a scope revision record from now on so
# that the record says only what a recovery receipt (mythos_core.recovery_receipt) could
# say. Five columns, each nullable and with no default: no stored row is written, and a
# read takes null for "recorded before this migration" (assurance.recovery_record.served).

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0087_incident_scope_revision"),
    ]

    operations = [
        migrations.AddField(
            model_name="recoveryrecord",
            name="held_back_from",
            field=models.CharField(blank=True, max_length=32, null=True),
        ),
        migrations.AddField(
            model_name="recoveryrecord",
            name="support",
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="recoveryrecord",
            name="recorded_by_ref",
            field=models.CharField(blank=True, max_length=40, null=True),
        ),
        migrations.AddField(
            model_name="recoveryrecord",
            name="accepted_by_ref",
            field=models.CharField(blank=True, max_length=40, null=True),
        ),
        migrations.AddField(
            model_name="incidentscoperevision",
            name="declared_by_ref",
            field=models.CharField(blank=True, max_length=40, null=True),
        ),
    ]
