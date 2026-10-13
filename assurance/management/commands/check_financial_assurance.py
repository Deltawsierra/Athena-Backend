"""Check Economic Exposure for stale runs, from the operator's shell (E6, continuous
financial assurance; ``docs/economics/spec-v1.md``, section 34):

    manage.py check_financial_assurance [--deployment <uuid>]

For each deployment (or the one named), every current scenario version's latest
completed exposure run is read against what it was recorded as depending on
(:func:`assurance.economics.continuous_service.check`), and each stale one is recorded
with the refresh it owes, once per set of reasons. An operator runs it after a deploy,
or on a schedule the owner sets: nothing in this repository runs it (spec, section 34,
choice 15). Every read detects a change of the engine release regardless; this records
it, with the refresh it owes.

It RECOMPUTES NOTHING: no Monte Carlo is run here or by anything it calls, and it
takes no economics run slot. A refresh is made only when an analyst asks for it, on
the scenario's refresh route. It prints, per deployment, how many runs it read, how
many are stale and how many obligations it recorded. It is on no stop path, reads
SPINE's rows without a transaction and writes none of them, and no first-party module
imports it.
"""

from __future__ import annotations

import uuid as _uuid

from django.core.management.base import BaseCommand, CommandError

from assurance.economics import continuous_service
from assurance.models import Deployment


class Command(BaseCommand):
    help = "Record each stale Economic Exposure run with the refresh it owes (no Monte Carlo is run)."

    def add_arguments(self, parser):
        parser.add_argument("--deployment", dest="deployment", help="one deployment's uuid (default: every one)")

    def handle(self, *args, **options):
        deployments = Deployment.objects.order_by("id")
        if options["deployment"] is not None:
            try:
                wanted = _uuid.UUID(options["deployment"])
            except ValueError:
                raise CommandError(f"refused: --deployment {options['deployment']!r} is not a uuid") from None
            deployments = deployments.filter(uuid=wanted)
            if not deployments.exists():
                raise CommandError(f"refused: no deployment {wanted}")
        for deployment in deployments:
            found = continuous_service.check(deployment)
            self.stdout.write(
                f"{deployment.uuid}: {found['checked']} run(s) read, {found['stale']} stale, "
                f"{found['obligations_recorded']} obligation(s) recorded"
            )
