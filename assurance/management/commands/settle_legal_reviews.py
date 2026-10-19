"""Flag every legal review still owed.

A supersession of a legal obligation (the legal-obligations route) records the new
version and owes each deployment it binds the review flag the move calls for, in its
own short transaction, and writes the flags once it commits: one deployment per
transaction, each with that deployment's decision refreshed in it
(:func:`assurance.legal.settle_reviews_owed`). A process that died before the last of
them, or a flag that failed, leaves those deployments' ``LegalReviewOwed`` rows. This
command settles every one still there, now; run it on a schedule too (see the
README). A row another runner settles meanwhile is skipped, never flagged twice.

It exits non-zero while anything is still owed after it ran -- including when a flag
fails, which stops the run where it is -- so a scheduler reports it. It makes no
materiality judgment: every claim it flags lands in review pending.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand, CommandError

from assurance.legal import settle_reviews_owed
from assurance.models import LegalReviewOwed
from assurance.views import _refresh_stored_decision


class Command(BaseCommand):
    help = "Flag every legal review a supersession still owes, one deployment per transaction."

    def handle(self, *args, **options):
        try:
            done = settle_reviews_owed(_refresh_stored_decision)
        except Exception as exc:
            left = LegalReviewOwed.objects.count()
            raise CommandError(
                f"settling stopped on {type(exc).__name__}: {left} legal review(s) still owed"
            ) from exc
        self.stdout.write(
            f"settled {done['settled']} owed review(s); {done['flagged_count']} claim(s) moved to review "
            f"pending, none judged; {done['owed_left']} still owed"
        )
        if done["owed_left"]:
            raise CommandError(f"{done['owed_left']} legal review(s) still owed")
