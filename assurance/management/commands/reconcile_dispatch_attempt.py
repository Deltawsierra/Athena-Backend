"""Settle, by hand, a dispatch attempt whose push may or may not have arrived.

An attempt is UNKNOWN when the answer to its push was lost, or SENDING when the
runner that sent it never recorded how it ended. The dispatcher settles those
itself where the system can be asked -- Jira, GitHub and ServiceNow are searched
for the finding's issue -- and resends where the system deduplicates (the webhook's
``Idempotency-Key``). Where it can do neither (Splunk HEC, a system that could not
be reached, or an earlier release's push of which no issue is found), the attempt is held
and the blocking-decision dispatch that contains it stays owed until a person has
looked:

    manage.py reconcile_dispatch_attempt <attempt uuid> --provider-has-it --by <who> [--external-ref REF]
    manage.py reconcile_dispatch_attempt <attempt uuid> --provider-lacks-it --by <who>

The first records it SENT; the second records it FAILED, so the next run pushes it
again. Either is recorded as operator-attested, with who said so. The write is
conditional: if a runner settled the attempt meanwhile, nothing is changed and the
command says so. The attempt's uuid is in the deployment's ``dispatch-attempts`` read.
"""

from __future__ import annotations

import uuid

from django.core.management.base import BaseCommand, CommandError
from django.utils import timezone

from assurance.models import DispatchAttempt


class Command(BaseCommand):
    help = "Record, as an operator, whether an UNKNOWN or SENDING dispatch attempt reached the provider."

    def add_arguments(self, parser):
        parser.add_argument("attempt", help="The attempt's uuid.")
        answer = parser.add_mutually_exclusive_group(required=True)
        answer.add_argument("--provider-has-it", action="store_true", dest="has_it")
        answer.add_argument("--provider-lacks-it", action="store_true", dest="lacks_it")
        parser.add_argument("--external-ref", default="", help="The issue id the provider holds (with --provider-has-it).")
        parser.add_argument("--by", required=True, help="Who is attesting this: recorded on the attempt.")

    def handle(self, *args, **options):
        try:
            attempt_uuid = uuid.UUID(str(options["attempt"]))
        except ValueError:
            raise CommandError(f"{options['attempt']!r} is not an attempt uuid") from None
        has_it = bool(options["has_it"])
        ref = options["external_ref"] or ""
        if ref and not has_it:
            raise CommandError("--external-ref names the issue the provider has; it cannot go with --provider-lacks-it")
        by = (options["by"] or "").strip()
        if not by:
            raise CommandError("--by must name who is attesting this")
        attempt = DispatchAttempt.objects.filter(uuid=attempt_uuid).first()
        if attempt is None:
            raise CommandError(f"no dispatch attempt {attempt_uuid}")
        if not attempt.is_uncertain:
            raise CommandError(f"attempt {attempt.uuid} is {attempt.outcome}, not uncertain: nothing to reconcile")
        outcome = DispatchAttempt.Outcome.SENT if has_it else DispatchAttempt.Outcome.FAILED
        changes = {
            "outcome": outcome,
            "reconciled_at": timezone.now(),
            "reconciled_detail": (
                f"operator-attested by {by}: the provider "
                + ("has it" if has_it else "does not have it")
                + (f" ({ref})" if ref else "")
            ),
            "updated_at": timezone.now(),
        }
        if ref:
            changes["external_ref"] = ref
        # Only while it is still the uncertain attempt that was read: a runner that
        # settled it meanwhile (SENT, say) is never overwritten.
        updated = DispatchAttempt.objects.filter(
            pk=attempt.pk, outcome=attempt.outcome, reconciled_at__isnull=True
        ).update(**changes)
        if not updated:
            attempt.refresh_from_db()
            raise CommandError(
                f"attempt {attempt.uuid} changed while this ran (it is now {attempt.outcome}); nothing was written"
            )
        attempt.refresh_from_db()
        self.stdout.write(
            f"attempt {attempt.uuid} ({attempt.connector}, finding {attempt.finding_id}) is now {attempt.outcome}, "
            f"operator-attested by {by}"
        )
