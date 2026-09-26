"""Run every blocking-decision dispatch still owed.

A pause (or any recompute) whose decision is blocking records the deployment's
blocking-decision dispatch as owed, in the pause's own transaction, and dispatches
the qualifying findings in the background after the pause has answered. What a
run did not settle -- a push failed, the run raised, or the process exited before
it finished -- keeps its ``DecisionDispatchDue`` row; the background thread retries
it a few times, and this command retries every one still there. Run it on a
schedule: a run claims a row before it pushes, so this never pushes for a
deployment the background thread (or another run of this command) is pushing for
-- that one is reported as running elsewhere and left to it.

``--deployment`` runs only the deployments named, whether or not a row says they
are owed: the way to run one whose dispatch could not even be recorded or started,
which the log names. The exit status then covers those deployments only, and the
output says so. Without it, the command exits non-zero while anything at all is
still owed -- including a dispatch another runner holds, and every one kept while
``ASSURANCE_AUTO_DISPATCH_ENABLED`` is off, which this never drops -- so a scheduler
reports it.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from assurance.dispatch import SETTLED, retry_owed_blocking_dispatches
from assurance.models import DecisionDispatchDue


class Command(BaseCommand):
    help = "Retry every blocking-decision dispatch still owed (or only the deployments named)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--deployment",
            type=int,
            action="append",
            dest="deployments",
            help="A deployment id to run the dispatch for, owed or not. Repeatable. The exit "
            "status then covers only the deployments named.",
        )

    def handle(self, *args, **options):
        named = options.get("deployments")
        outcomes = retry_owed_blocking_dispatches(named)
        for pk, outcome in sorted(outcomes.items()):
            self.stdout.write(f"deployment {pk}: {outcome}")
        if named:
            unsettled = sorted(pk for pk, outcome in outcomes.items() if outcome != SETTLED)
            self.stdout.write(
                f"ran the blocking-decision dispatch for deployment(s) {sorted(set(named))} only; "
                f"{len(unsettled)} of them still owed; no other deployment was checked"
            )
            if unsettled:
                raise CommandError(
                    f"still owed for deployment(s) {unsettled}; see each one's dispatch-attempts"
                )
            return
        owed = sorted(DecisionDispatchDue.objects.values_list("deployment_id", flat=True))
        self.stdout.write(f"ran {len(outcomes)} blocking-decision dispatch(es); {len(owed)} still owed")
        if owed:
            raise CommandError(f"still owed for deployment(s) {owed}; see each one's dispatch-attempts")
