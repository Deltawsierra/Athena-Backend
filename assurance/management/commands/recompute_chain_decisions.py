"""Recompute the stored decision of every deployment that has chain outcomes.

Run after rotating or withdrawing an outcome signing key. Each stored decision
records the keyring it was computed under and is reconciled when next published,
so nothing is reported stale without this; the command brings every stored
decision current at once rather than one read at a time. An operator's pause is
kept as each locked row holds it.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand

from assurance.decision import recompute_decision
from assurance.models import Deployment, WorkflowChainOutcome


class Command(BaseCommand):
    help = "Recompute every stored decision that rests on workflow chain outcomes."

    def handle(self, *args, **options):
        deployment_ids = WorkflowChainOutcome.objects.values_list("deployment_id", flat=True).distinct()
        moved = 0
        total = 0
        for deployment in Deployment.objects.filter(pk__in=deployment_ids):
            before = deployment.decision
            after = recompute_decision(deployment)
            total += 1
            if after != before:
                moved += 1
                self.stdout.write(f"{deployment.name}: {before} -> {after}")
        self.stdout.write(f"recomputed {total} deployment(s); {moved} decision(s) moved")
