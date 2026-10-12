"""Raise a financial source's trust tier, as an admin, from the operator's shell.

The same rules and the same record as the trust-raise routes
(``assurance.economics.api``; ``docs/economics/spec-v1.md``, section 6.1), through
the same model methods:

    manage.py raise_source_trust request <source version uuid> --to <tier> --reason <why> --as <username>
    manage.py raise_source_trust approve <raise uuid> --as <username>
    manage.py raise_source_trust withdraw <raise uuid> --as <username>

``--as`` names the account the raise is recorded under, and it must be an active
admin (role admin, or a superuser): anyone else is refused (``admin_required``) and
nothing is written. Below ``authoritative`` a request records the new version at
once; ``authoritative`` is recorded pending, for an admin OTHER than the requester
to approve (``second_person_required``). Every refusal is a CommandError naming its
code, and writes nothing.

It prints the raise's uuid, its state, the source's key and versions, the tiers and
who requested and approved it; never the reason. It is on no stop path and reads
nothing a stop reads.
"""

from __future__ import annotations

import uuid

from django.contrib.auth import get_user_model
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError

from assurance.economics.models import EconomicsRefused, FinancialSource, FinancialSourceTrustRaise

ACTIONS = ("request", "approve", "withdraw")


def _uuid(value: str, what: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except ValueError:
        raise CommandError(f"{value!r} is not a {what} uuid") from None


def _summary(raised: FinancialSourceTrustRaise) -> str:
    source = raised.from_version
    line = (
        f"raise {raised.uuid}: {raised.state}; source {source.source_key} v{source.version} "
        f"{raised.from_tier} -> {raised.to_tier}"
    )
    if raised.to_version_id is not None:
        line += f", recorded as v{raised.to_version.version}"
    line += f"; requested by {raised.requested_by_username or '-'}"
    if raised.approved_by_username:
        line += f", approved by {raised.approved_by_username}"
    return line


class Command(BaseCommand):
    help = "Request, approve or withdraw a raise of a financial source's trust tier, as an admin."

    def add_arguments(self, parser):
        parser.add_argument("action", choices=ACTIONS)
        parser.add_argument("target", help="request: the source version's uuid; approve, withdraw: the raise's uuid.")
        parser.add_argument("--to", dest="to_tier", default=None, help="request: the tier to raise the source to.")
        parser.add_argument("--reason", default=None, help="request: why the source is trusted that far.")
        parser.add_argument(
            "--as", dest="as_user", required=True, help="The admin account the raise is recorded under."
        )

    def handle(self, *args, **options):
        action = options["action"]
        if action != "request" and (options["to_tier"] is not None or options["reason"] is not None):
            raise CommandError("--to and --reason go with request only")
        username = (options["as_user"] or "").strip()
        account = get_user_model().objects.filter(username=username).first() if username else None
        if account is None:
            raise CommandError(f"no account {username!r}")
        try:
            if action == "request":
                source = FinancialSource.objects.filter(uuid=_uuid(options["target"], "source version")).first()
                if source is None:
                    raise CommandError(f"no source version {options['target']}")
                raised = FinancialSourceTrustRaise.request(
                    source, options["to_tier"], options["reason"], by=account
                )
            else:
                found = FinancialSourceTrustRaise.objects.filter(uuid=_uuid(options["target"], "raise")).first()
                if found is None:
                    raise CommandError(f"no trust raise {options['target']}")
                raised = found.approve(by=account) if action == "approve" else found.withdraw(by=account)
        except EconomicsRefused as refused:
            raise CommandError(f"refused, nothing was written: {refused}") from None
        except IntegrityError:
            raise CommandError(
                "another version of this source was recorded at the same moment; nothing was written"
            ) from None
        self.stdout.write(_summary(FinancialSourceTrustRaise.objects.get(pk=raised.pk)))
