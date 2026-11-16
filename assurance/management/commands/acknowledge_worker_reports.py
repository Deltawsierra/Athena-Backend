"""List every worker's report, or acknowledge the ones that have stopped moving.

Each serving worker publishes what it lost or refused (``assurance.worker_reports``),
and ``GET /api/health/`` sums them all. A worker that exited keeps its last counts in
that sum -- health reads "degraded" -- and one that stopped publishing without
exiting (killed outright) reads "unknown", until an operator acknowledges its report
here. Run on the host, by whoever operates it: there is no route for this.

With no report named, lists each report: its id (the one health shows), state, host,
pid, when it was published, and its non-zero counts. ``REPORT_ID ... --by NAME`` (or
``--all --by NAME``) acknowledges exited, stale and unreadable reports: each is kept,
with who acknowledged it (the name given, and the account that ran the command) and
when, under ``acknowledged/`` in the report directory, logged at WARNING, and leaves
health's sums. A live worker's report is refused: its counts are still moving.
"""

from __future__ import annotations

import logging
import time

from django.core.management.base import BaseCommand, CommandError

from assurance import worker_reports

logger = logging.getLogger("assurance.worker_reports")


class Command(BaseCommand):
    help = "List every worker's report, or acknowledge exited, stale and unreadable ones (--by is required)."

    def add_arguments(self, parser):
        parser.add_argument("report_ids", nargs="*", help="The reports to acknowledge, by id.")
        parser.add_argument(
            "--all", action="store_true", help="Acknowledge every exited, stale and unreadable report."
        )
        parser.add_argument("--by", default="", help="Who acknowledges them: recorded with each.")

    def handle(self, *args, **options):
        directory = worker_reports.report_directory()
        now = time.time()
        readable, unknown = worker_reports.reports(directory, now=now)
        if not options["report_ids"] and not options["all"]:
            self.stdout.write(f"worker reports in {directory}:")
            for report_id, state, report in readable:
                counts = ", ".join(f"{name}={n}" for name, n in sorted(report["counts"].items()) if n) or "nothing counted"
                self.stdout.write(
                    f"{report_id}: {state}, host {report.get('host')}, pid {report.get('pid')}, "
                    f"published {now - report['published']:.0f} s ago; {counts}"
                )
            for report_id, why in sorted(unknown.items()):
                if not any(report_id == seen for seen, _state, _report in readable):
                    self.stdout.write(f"{report_id}: {why}")
            return
        if not options["by"].strip():
            raise CommandError("say who acknowledges them: --by NAME")
        if options["all"]:
            named = sorted(
                {report_id for report_id, state, _report in readable if state != worker_reports.LIVE}
                | {report_id for report_id in unknown if report_id != "directory"}
            )
        else:
            named = options["report_ids"]
        refused = []
        for report_id in named:
            try:
                record = worker_reports.acknowledge(report_id, by=options["by"], directory=directory, now=now)
            except (worker_reports.NotAcknowledged, OSError) as exc:
                refused.append(f"{report_id}: {exc}")
                continue
            line = (
                f"worker report {report_id} ({record['state']}) acknowledged by {record['acknowledged_by']} "
                f"(account {record['acknowledged_by_account']}) at {record['acknowledged_at']}"
            )
            logger.warning("%s", line)
            self.stdout.write(line)
        if not named:
            self.stdout.write("nothing to acknowledge")
        if refused:
            raise CommandError("not acknowledged: " + "; ".join(refused))
