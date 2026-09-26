from datetime import datetime, timezone

import django.db.models.deletion
from django.db import migrations, models


#: An instant every clock has passed. ``decision_valid_until`` at or before now makes
#: the first read of the stored decision recompute it (``decision.current_decision``),
#: the mechanism 0036 used for the accepted-risk rule.
_ALREADY_PASSED = datetime(1970, 1, 1, tzinfo=timezone.utc)


def recompute_under_the_rules_this_release_adds(apps, schema_editor):
    """Mark every stored decision as due for a recompute under the rules that now
    compose it.

    Several rules change what the same stored inputs imply, and none of them is a
    write: a held that rests on an authorization check alone reads READY_RESTRICTED;
    a claim a person ruled legally stale -- rulings 0037 carried back onto current
    versions -- reads NEEDS_MORE_EVIDENCE; a held taken against any route but the one
    serving now, and every held recorded before routes were bound, reads as not yet
    exercised. A decision stored READY under the old rules went on being published
    READY by every surface that reads the stored value, while decision-support,
    computing live, said otherwise under the same revision.

    Every deployment with a stored decision, not a guess at which ones moved: a
    recompute that changes nothing records no transition, and one that does is the
    point. Lazily, on the first read, because the recompute takes the row lock and a
    migration holding every deployment's lock at once is the wrong place to take it.
    """
    Deployment = apps.get_model("assurance", "Deployment")
    Deployment.objects.filter(decision__isnull=False).update(decision_valid_until=_ALREADY_PASSED)


class Migration(migrations.Migration):

    dependencies = [
        ("assurance", "0037_carry_watches_and_legal_rulings"),
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
        # Not reversed: the mark is cleared by the recompute it asks for, and a
        # reversal that drops the column returns every row to the rules before.
        migrations.RunPython(recompute_under_the_rules_this_release_adds, migrations.RunPython.noop),
    ]
