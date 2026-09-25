from django.db import migrations, models


def typed_in_demonstrated_is_attested(apps, schema_editor):
    """Every row that says ``demonstrated`` before this migration was typed in:
    until now an operator POST was the only writer of a chain outcome, and it could
    set that word. A person asserted those rows, so they are recorded as attested.
    Nothing produced them that this platform can show, and the column that exists
    to say so should not keep saying otherwise."""
    WorkflowChainOutcome = apps.get_model("assurance", "WorkflowChainOutcome")
    WorkflowChainOutcome.objects.filter(basis="demonstrated", outcome_id__isnull=True).update(
        basis="attested"
    )


def refuse_to_drop_signed_evidence(apps, schema_editor):
    """Reversing drops the envelope columns, and with them the only evidence a run
    produced any outcome here. A signed row would survive as a bare
    ``demonstrated`` that nothing backs, and re-applying this migration would then
    -- correctly, and irreversibly -- demote it to attested. Losing signed evidence
    is not something a rollback should do quietly, so it does not do it at all
    while any exists: export or delete those rows first, on purpose."""
    WorkflowChainOutcome = apps.get_model("assurance", "WorkflowChainOutcome")
    signed = WorkflowChainOutcome.objects.filter(outcome_id__isnull=False).count()
    if signed:
        raise RuntimeError(
            f"refusing to reverse 0032: {signed} chain outcome(s) rest on signed "
            "evidence, and reversing would drop it; remove them deliberately first"
        )


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
        migrations.RunPython(typed_in_demonstrated_is_attested, refuse_to_drop_signed_evidence),
    ]
