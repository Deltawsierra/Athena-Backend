# Reconciliation receipts (F1, owner decision 1 Nov: best product). One new table and
# nothing else: each mythos.effect-reconciliation/v1 receipt Achilles' observed-effect key
# signs for a readback of a dispatch whose effect was unknown, stored once per receipt id,
# with the envelope it rests on kept whole (assurance.effect_reconciliation). Nothing is
# backfilled: no receipt was recorded before this table. Indexed by gate decision and by
# dispatch, the two ways an authority chain's produces hop finds its receipts. Rolling it
# back drops the table.

import django.db.models.deletion
import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0083_approval_version_declared_by"),
    ]

    operations = [
        migrations.CreateModel(
            name="EffectReconciliationReceipt",
            fields=[
                ("id", models.BigAutoField(primary_key=True, serialize=False)),
                ("receipt_id", models.CharField(max_length=32, unique=True)),
                ("dispatch_id", models.CharField(max_length=32)),
                ("attempt", models.PositiveIntegerField()),
                ("gate_outcome_id", models.CharField(max_length=32)),
                ("workflow", models.CharField(max_length=200)),
                ("answer", models.CharField(max_length=16)),
                ("conclusion", models.CharField(max_length=16)),
                ("provider", models.CharField(max_length=200)),
                ("read_at", models.DateTimeField()),
                ("observer_key_id", models.CharField(max_length=64)),
                ("envelope_digest", models.CharField(max_length=71)),
                ("envelope", models.JSONField()),
                (
                    "recorded_at",
                    models.DateTimeField(default=django.utils.timezone.now),
                ),
                (
                    "deployment",
                    models.ForeignKey(
                        on_delete=django.db.models.deletion.CASCADE,
                        related_name="effect_reconciliations",
                        to="assurance.deployment",
                    ),
                ),
            ],
            options={
                "ordering": ["deployment", "id"],
                "indexes": [
                    models.Index(
                        fields=["deployment", "gate_outcome_id"],
                        name="assurance_reconcile_gate",
                    ),
                    models.Index(
                        fields=["deployment", "dispatch_id"],
                        name="assurance_reconcile_dispatch",
                    ),
                ],
            },
        ),
    ]
