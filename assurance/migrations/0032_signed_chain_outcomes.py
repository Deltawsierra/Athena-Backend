from django.db import migrations, models


def typed_in_demonstrated_is_attested(apps, schema_editor):
    """Every row that says ``demonstrated`` before this migration was typed in:
    until now an operator POST was the only writer of a chain outcome, and it could
    set that word. A person asserted those rows, so they are recorded as attested.
    Nothing produced them that this platform can show, and the column that exists
    to say so should not keep saying otherwise."""
    WorkflowChainOutcome = apps.get_model("assurance", "WorkflowChainOutcome")
    WorkflowChainOutcome.objects.filter(basis="demonstrated").update(basis="attested")


class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0031_retest_claim_seen_at"),
    ]

    operations = [
        migrations.AddField(
            model_name="workflowchainoutcome",
            name="outcome_id",
            field=models.CharField(blank=True, max_length=32, null=True, unique=True),
        ),
        migrations.AddField(
            model_name="workflowchainoutcome",
            name="observer_engine",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="workflowchainoutcome",
            name="observer_key_id",
            field=models.CharField(blank=True, max_length=64),
        ),
        migrations.AddField(
            model_name="workflowchainoutcome",
            name="evidence_digest",
            field=models.CharField(blank=True, max_length=71),
        ),
        migrations.AddField(
            model_name="workflowchainoutcome",
            name="envelope",
            field=models.JSONField(blank=True, null=True),
        ),
        migrations.RunPython(typed_in_demonstrated_is_attested, migrations.RunPython.noop),
    ]
