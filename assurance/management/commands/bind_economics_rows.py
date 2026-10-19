"""Bind the Economic Exposure rows recorded without a MAC, once the row key is
provisioned (review round 1 of #169, M1; ``docs/economics/spec-v1.md``, section 35.9):

    manage.py bind_economics_rows [--dry-run]

With ``ATHENA_ECONOMICS_ROW_KEY`` set, a simulation result or Validity Card with no
MAC fails its check (``result_mac``, ``card_mac``) like a rewritten row. Rows recorded
while there was no key -- before it was provisioned -- are bound here, once: each one
whose digests still verify is given its MAC (:func:`assurance.economics.row_mac.bind_stored_rows`),
and every other row is left as it is, a refusal. Without the key it refuses and binds
nothing. It prints the counts. It is on no stop path, and no first-party module
imports it.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from assurance.economics import row_mac


class Command(BaseCommand):
    help = "Give the Economic Exposure rows recorded without a MAC theirs, where their digests verify."

    def add_arguments(self, parser):
        parser.add_argument("--dry-run", action="store_true", help="count what would be bound; write nothing")

    def handle(self, *args, **options):
        try:
            counts = row_mac.bind_stored_rows(dry_run=options["dry_run"])
        except RuntimeError as refused:
            raise CommandError(f"refused: {refused}") from None
        self.stdout.write(
            f"{counts['results_bound']} result(s) and {counts['cards_bound']} card(s) bound"
            f"{' (dry run: nothing written)' if options['dry_run'] else ''}; "
            f"{counts['left_unbound']} row(s) whose digests fail left unbound"
        )
