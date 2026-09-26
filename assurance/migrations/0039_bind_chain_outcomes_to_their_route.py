import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0038_latent_conditions_stay_watched"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="risk_accepted_severity",
            field=models.CharField(blank=True, default="", max_length=16),
        ),
        migrations.AddField(
            model_name="workflowchainoutcome",
            name="route_fingerprint",
            field=models.CharField(blank=True, default="", max_length=64),
        ),
        migrations.CreateModel(
            name="ServedRouteNote",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("fingerprint", models.CharField(max_length=64)),
                ("since", models.DateTimeField()),
                (
                    "deployment",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="served_route_note",
                        to="assurance.deployment",
                    ),
                ),
            ],
        ),
        # Which rules each stored decision was computed under. NULL on every row
        # here -- none was stamped -- so each is recomputed under the rules this
        # release adds, by the refresh, at migrate and at its first publishing read.
        migrations.AddField(
            model_name="deployment",
            name="decision_policy",
            field=models.CharField(blank=True, default=None, editable=False, max_length=80, null=True),
        ),
    ]
