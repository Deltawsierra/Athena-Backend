"""Settle, by hand, a dispatch attempt whose push may or may not have arrived.

An attempt is UNKNOWN when the answer to its push was lost, or SENDING when the
runner that sent it never recorded how it ended. The dispatcher settles those
itself where the system can be asked -- Jira, GitHub and ServiceNow are searched
for the finding's issue -- and resends where the system deduplicates (the webhook's
``Idempotency-Key``). Where it can do neither (Splunk HEC, or a system that could
not be reached), the attempt is held and the blocking-decision dispatch that
contains it stays owed until a person has looked:

    manage.py reconcile_dispatch_attempt <attempt uuid> --provider-has-it [--external-ref REF]
    manage.py reconcile_dispatch_attempt <attempt uuid> --provider-lacks-it

The first records it SENT; the second records it FAILED, so the next run pushes it
again. The attempt's uuid is in the deployment's ``dispatch-attempts`` read.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from assurance.dispatch import reconcile_attempt
from assurance.models import DispatchAttempt


class Command(BaseCommand):
    help = "Record whether an UNKNOWN or SENDING dispatch attempt reached the provider."

    def add_arguments(self, parser):
        parser.add_argument("attempt", help="The attempt's uuid.")
        answer = parser.add_mutually_exclusive_group(required=True)
        answer.add_argument("--provider-has-it", action="store_true", dest="has_it")
        answer.add_argument("--provider-lacks-it", action="store_true", dest="lacks_it")
        parser.add_argument("--external-ref", default="", help="The issue id the provider holds, if known.")

    def handle(self, *args, **options):
        attempt = DispatchAttempt.objects.filter(uuid=options["attempt"]).first()
        if attempt is None:
            raise CommandError(f"no dispatch attempt {options['attempt']}")
        if not attempt.is_uncertain:
            raise CommandError(f"attempt {attempt.uuid} is {attempt.outcome}, not uncertain: nothing to reconcile")
        has_it = bool(options["has_it"])
        reconcile_attempt(attempt, readback=lambda _operation_id: has_it)
        if has_it and options["external_ref"]:
            DispatchAttempt.objects.filter(pk=attempt.pk).update(external_ref=options["external_ref"])
        attempt.refresh_from_db()
        self.stdout.write(
            f"attempt {attempt.uuid} ({attempt.connector}, finding {attempt.finding_id}) is now {attempt.outcome}"
        )
