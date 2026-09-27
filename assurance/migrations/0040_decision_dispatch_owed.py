import django.db.models.deletion
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0039_bind_chain_outcomes_to_their_route"),
    ]

    operations = [
        migrations.CreateModel(
            name="DecisionDispatchDue",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("owed_since", models.DateTimeField()),
                ("runs", models.PositiveIntegerField(default=0)),
                ("last_run_at", models.DateTimeField(blank=True, null=True)),
                ("last_error", models.TextField(blank=True)),
                (
                    "deployment",
                    models.OneToOneField(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="decision_dispatch_due",
                        to="assurance.deployment",
                    ),
                ),
            ],
        ),
    ]
