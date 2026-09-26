from django.db import migrations, models


class Migration(migrations.Migration):
    """An accepted risk names when its acceptance ends, and the stored decision
    records the first moment one lapses (owner decision Q6)."""

    dependencies = [
        ("assurance", "0035_named_by_hand_from_admin_log"),
    ]

    operations = [
        migrations.AddField(
            model_name="finding",
            name="risk_accepted_until",
            field=models.DateTimeField(blank=True, null=True),
        ),
        migrations.AddField(
            model_name="deployment",
            name="decision_valid_until",
            field=models.DateTimeField(blank=True, default=None, editable=False, null=True),
        ),
        # No data step. The decisions stored under the rule before this one are
        # recomputed by the policy stamp (Deployment.decision_policy, 0038): a
        # migration that wrote a decision column would move the decision with no
        # transition recorded, which nothing but the refresh may do.
    ]
