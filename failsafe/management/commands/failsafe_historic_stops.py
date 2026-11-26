"""List the historic stops that are not in force, and put in force the ones the
owner names.

A stop made ready since migration 0006 is in force until a later signed start
lifts it (failsafe.models.FailsafeCommand.in_force). A stop made ready BEFORE
it, and already past its window when it ran, was not put in force: until then
a stop lapsed after ten minutes, and an engine stood down and then restarted
to clear it has no release on record. Putting every such stop in force would
stand that engine down again at its next poll.

So this lists them and changes nothing. Per engine, each kind's newest stop
that was made ready, is not in force and was not lifted, with whether a later
start of its own kind was made ready after it -- a resume for a pause, a
release for a stand-down, and nothing for a terminate -- which is the rule
that would have lifted it.

    manage.py failsafe_historic_stops                      # the list (a dry run)
    manage.py failsafe_historic_stops --engine athena-1    # one engine's
    manage.py failsafe_historic_stops --apply --engine athena-1 --stop <uuid> [--stop <uuid>]

``--apply`` puts in force exactly the stops named, each of which must be one
this command lists for the engine named as WOULD BE IN FORCE. It writes
``in_force`` and makes the stop ready again, with an audit event; the engine's
next poll is answered with it. It never lifts or ends a stop. Without
``--apply`` nothing is written, whatever else is given.
"""

from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from failsafe.models import LIFTED_ONLY_BY, STOP_ACTIONS, FailsafeAuditEvent, FailsafeCommand

#: The most historic stops read for one listing.
LIMIT = 5000


def historic(engine_id=None):
    """[(stop, would be in force, why)]: per engine and kind, the newest stop
    made ready that is neither in force nor lifted."""
    stops = FailsafeCommand.objects.filter(
        action__in=STOP_ACTIONS, ready_at__isnull=False, in_force=False, lifted_at__isnull=True
    )
    if engine_id:
        stops = stops.filter(engine_id=engine_id)
    newest = {}
    for stop in stops.order_by("-created_at", "-pk")[:LIMIT]:
        newest.setdefault((stop.engine_id, stop.action), stop)
    out = []
    for (_engine, action), stop in sorted(newest.items(), key=lambda item: (item[0][0], STOP_ACTIONS.index(item[0][1]))):
        only = LIFTED_ONLY_BY[action]
        if only is None:
            out.append((stop, True, "nothing ends a terminate"))
            continue
        later = (
            FailsafeCommand.objects.filter(
                engine_id=stop.engine_id, action=only, ready_at__gt=stop.ready_at, created_at__gt=stop.created_at
            )
            .order_by("ready_at")
            .first()
        )
        if later is None:
            out.append((stop, True, f"no {only} drafted and made ready after it is on record"))
        else:
            out.append((stop, False, f"the {only} {later.uuid}, made ready {later.ready_at.isoformat()}, came after it"))
    return out


class Command(BaseCommand):
    help = "List the historic failsafe stops that are not in force (a dry run); put in force only those named."

    def add_arguments(self, parser):
        parser.add_argument("--engine", help="the engine id to list, or to apply to")
        parser.add_argument("--stop", action="append", default=[], help="the uuid of a stop to put in force (repeatable)")
        parser.add_argument("--apply", action="store_true", help="write: put the named stops in force")

    def handle(self, *args, engine=None, stop=(), apply=False, **options):
        rows = historic(engine)
        if not rows:
            self.stdout.write("No historic stop is waiting on a choice.")
        for row, would, why in rows:
            self.stdout.write(
                f"{row.engine_id}\t{row.action}\t{row.uuid}\tdrafted {row.created_at.isoformat()}\t"
                f"made ready {row.ready_at.isoformat()}\tstatus {row.status}\t"
                f"{'WOULD BE IN FORCE' if would else 'not in force'}: {why}"
            )
        if not apply:
            self.stdout.write("Dry run: nothing was changed. --apply --engine <id> --stop <uuid> puts a listed stop in force.")
            return
        if not engine or not stop:
            raise CommandError("--apply needs --engine and at least one --stop: nothing is put in force unnamed")
        allowed = {str(row.uuid): row for row, would, _why in rows if would and row.engine_id == engine}
        unknown = [name for name in stop if name not in allowed]
        if unknown:
            raise CommandError(
                f"not listed as WOULD BE IN FORCE for engine {engine!r}: {', '.join(unknown)}. Nothing was changed."
            )
        with transaction.atomic():
            for name in stop:
                row = allowed[name]
                FailsafeCommand.objects.filter(pk=row.pk, in_force=False, lifted_at__isnull=True).update(
                    in_force=True, status=FailsafeCommand.STATUS_READY
                )
                FailsafeAuditEvent.objects.create(
                    command=row,
                    event=FailsafeAuditEvent.EVENT_IN_FORCE,
                    detail={"by": "failsafe_historic_stops", "engine_id": engine, "was": row.status},
                )
                self.stdout.write(f"IN FORCE: {row.action} {row.uuid} of {engine}")
