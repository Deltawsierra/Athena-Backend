"""The stop mark keeps the signed instant of the latest stop made ready for its
engine (FailsafeStopMark.issued): a start lifts a stop only when it was issued
strictly after it, which is the engine's order (Mythos-Core #88)."""

from datetime import datetime

from django.db import migrations, models


def _instant(text):
    """The signed instant ``text`` names, or None: not ISO 8601, or no offset."""
    try:
        value = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    return value if value.tzinfo is not None else None


def backfill(apps, schema_editor):
    """Each mark's ``issued``: the signed instant (``issued_at``) of the stop
    the mark names, read from that stop's row.

    A mark whose stop row is gone, or whose ``issued_at`` cannot be read, is
    left unknown (None). The plane then holds every start of that engine back
    until a stop is made ready again, which moves the mark: unknown is never
    read as "no stop". No command, and no column that was here before, is
    written. One read of the marks, one read of their stops' rows, one UPDATE
    per mark."""
    Mark = apps.get_model("failsafe", "FailsafeStopMark")
    Command = apps.get_model("failsafe", "FailsafeCommand")
    marks = list(Mark.objects.values_list("engine_id", "stop_uuid"))
    issued = dict(
        Command.objects.filter(uuid__in=[stop_uuid for _engine, stop_uuid in marks]).values_list("uuid", "issued_at")
    )
    for engine_id, stop_uuid in marks:
        instant = _instant(issued.get(stop_uuid))
        if instant is not None:
            Mark.objects.filter(engine_id=engine_id).update(issued=instant)


class Migration(migrations.Migration):

    dependencies = [
        ("failsafe", "0006_a_stop_in_force"),
    ]

    operations = [
        migrations.AddField(
            model_name="failsafestopmark",
            name="issued",
            field=models.DateTimeField(blank=True, null=True),
        ),
        # Backwards: nothing to undo but the column itself, which the
        # operation above removes. No command and no earlier column is written.
        migrations.RunPython(backfill, migrations.RunPython.noop),
    ]
