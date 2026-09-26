import django.db.models.deletion
from django.db import migrations, models


def recompute_under_the_route_rule(apps, schema_editor):
    """Mark every stored decision with chain outcomes under it as computed under
    another rule, so it is recomputed under this one.

    From here a ``held`` counts only when it was taken against the route serving
    now, and every row written before this migration has no route bound: each reads
    ``unrecorded``, which on an approved workflow floors exactly as a moved route
    does. A decision stored READY on those rows is no longer the one its inputs
    imply, and nothing writes to it to say so. A NULL ``decision_keyring`` is the
    mark the post-migrate receiver
    (``assurance.signals.recompute_decisions_computed_under_another_rule``) and
    every publishing read (``assurance.decision.current_decision``) already
    reconcile, so it is set here rather than a second mechanism built beside it.
    """
    Deployment = apps.get_model("assurance", "Deployment")
    WorkflowChainOutcome = apps.get_model("assurance", "WorkflowChainOutcome")
    with_chains = WorkflowChainOutcome.objects.values_list("deployment_id", flat=True).distinct()
    Deployment.objects.filter(pk__in=with_chains).update(decision_keyring=None)


class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0037_carry_watches_and_legal_rulings"),
    ]

    operations = [
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
        # Not reversed: un-marking would leave decisions computed under this rule
        # stamped as though nothing had changed, and a reversal that drops the
        # column already returns every row to the rule before it.
        migrations.RunPython(recompute_under_the_route_rule, migrations.RunPython.noop),
    ]
