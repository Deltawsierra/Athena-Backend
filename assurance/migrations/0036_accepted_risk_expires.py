from datetime import datetime, timezone

from django.db import migrations, models

#: A moment every clock has passed. Stamped as the stored decision's
#: ``decision_valid_until`` on a deployment that carries an accepted risk, so the
#: first read of it recomputes the decision under the accepted-risk rule
#: (``decision.current_decision``) instead of publishing the READY the old rule
#: computed while leaving accepted findings out altogether.
_ALREADY_PASSED = datetime(1970, 1, 1, tzinfo=timezone.utc)


def mark_decisions_resting_on_accepted_risk(apps, schema_editor):
    """Every deployment with an accepted finding has a decision computed as though
    the finding were gone. Its acceptance names no end -- nothing could, before
    this migration -- so under the rule it now lapsed and needs more evidence;
    the stored decision says otherwise until something recomputes it. Stamped
    stale here and recomputed at its first read, by the one writer, under the row
    lock -- the recompute is not done here because a migration runs against the
    historical models and the decision rule is the live code's."""
    Deployment = apps.get_model("assurance", "Deployment")
    Finding = apps.get_model("assurance", "Finding")
    ids = Finding.objects.filter(status="accepted").values_list("deployment_id", flat=True).distinct()
    Deployment.objects.filter(pk__in=list(ids)).update(decision_valid_until=_ALREADY_PASSED)


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
        migrations.RunPython(mark_decisions_resting_on_accepted_risk, migrations.RunPython.noop),
    ]
