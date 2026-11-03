"""Re-assert each role still held before its record's lease ends; revoke what is no longer held.

A role grant's signed record (assurance.identity_emitter) proves for one lease
(assurance.role_grant_lease, 24 h). This command is what keeps a held role proven: for
every account whose latest promotion it still holds, it signs a new lease once the
current one has less than half a lease left; for every lease still running of a grant
no longer held -- a role taken away by a path that announced nothing -- it signs the
revocation now. Schedule it hourly (Windows Task Scheduler or cron); it runs in its
own process, never on a request, so never on a stop.

It never extends a lease on a failure: with no key, no keyring or no database it signs
nothing and exits non-zero, so the scheduler reports it, and every lease runs out where
it stands -- the hop reads ``unproven``. With the emitter off (its key not set) there is
nothing to reconcile, and it says so and exits 0.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from assurance import identity_emitter


class Command(BaseCommand):
    help = "Re-assert each held role grant's record before its lease ends, and revoke any no longer held."

    def handle(self, *args, **options):
        result = identity_emitter.reconcile()
        if not result.ran:
            if result.off:
                self.stdout.write(f"the role-grant reconcile is off ({result.why}): nothing to reconcile")
                return
            raise CommandError(
                f"the role-grant reconcile could not run ({result.why}): nothing was re-asserted, and every "
                "role grant's record lapses at the end of its lease"
            )
        self.stdout.write(f"re-asserted: {result.reasserted}")
        self.stdout.write(f"revoked: {result.revoked}")
        if result.unknown:
            raise CommandError(
                f"{result.unknown} account(s) could not be read: their grants were neither re-asserted nor revoked, "
                "and lapse at the end of their lease"
            )
