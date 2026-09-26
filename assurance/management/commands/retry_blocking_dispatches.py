"""Run every blocking-decision dispatch still owed.

A pause (or any recompute) whose decision is blocking dispatches the deployment's
qualifying findings in the background, after the pause has answered. A run that
raised, left a push failed, or died with its process leaves a
``DecisionDispatchDue`` row; the background thread retries it a few times, and this
command retries every one still there -- run it on a schedule. ``--deployment``
runs one deployment's dispatch whether or not a row says it is owed: the way to
run one whose background run could not even be started, which the log names.

Exits non-zero while anything is still owed, so a scheduler reports it.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from assurance.dispatch import retry_owed_blocking_dispatches


class Command(BaseCommand):
    help = "Retry every blocking-decision dispatch still owed (or one deployment's)."

    def add_arguments(self, parser):
        parser.add_argument(
            "--deployment",
            type=int,
            action="append",
            dest="deployments",
            help="A deployment id to run the dispatch for, owed or not. Repeatable.",
        )

    def handle(self, *args, **options):
        settled = retry_owed_blocking_dispatches(options.get("deployments"))
        owed = sorted(pk for pk, done in settled.items() if not done)
        self.stdout.write(f"ran {len(settled)} blocking-decision dispatch(es); {len(owed)} still owed")
        if owed:
            raise CommandError(f"still owed for deployment(s) {owed}; see each one's dispatch-attempts")
