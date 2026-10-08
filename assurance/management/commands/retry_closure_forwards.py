"""Send again every closure document that has not reached Minotaur's dataset.

A recorded closure document is sent on to Minotaur-Backend's remediation-outcomes
dataset after its record commits (``assurance.closure_forward``). A send that
certainly did not land (``failed``) or that a dead process left ``pending`` or
``sending`` is retried here; one whose outcome is unknown -- it may have been
recorded -- only with ``--unknown``, since sending it again can add a second row of
the same document. One Minotaur refused is never retried. A forward is claimed before
it is sent, so this never sends one another sender is sending, and never one already
sent. Exits non-zero while any forward is still not sent, so a scheduler reports it.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from assurance.closure_forward import OUTCOMES_KEY, configured, credential, retry_due
from assurance.models import ClosureEvidenceForward


class Command(BaseCommand):
    help = "Send again every closure document not yet recorded in Minotaur's dataset."

    def add_arguments(self, parser):
        parser.add_argument(
            "--unknown",
            action="store_true",
            help="also send forwards whose outcome is unknown (each may add a second row of its document)",
        )

    def handle(self, *args, **options):
        found = credential()
        if configured() is None:
            why = found.problem or f"MINOTAUR_OUTCOMES_URL, {OUTCOMES_KEY}"
            self.stdout.write(f"forwarding to Minotaur is off ({why}): nothing sent")
            return
        self.stdout.write(found.report())
        settled = retry_due(unknown=options["unknown"])
        for status, count in sorted(settled.items()):
            self.stdout.write(f"{status}: {count}")
        left = ClosureEvidenceForward.objects.exclude(status=ClosureEvidenceForward.Status.SENT).count()
        if left:
            raise CommandError(f"{left} closure forward(s) not sent")
