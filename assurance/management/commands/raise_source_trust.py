"""Raise a financial source's trust tier, as an admin, from the operator's shell.

The same rules and the same record as the trust-raise routes
(``assurance.economics.api``; ``docs/economics/spec-v1.md``, section 6.1), through
the same model methods, each raise recorded with channel ``command``:

    manage.py raise_source_trust request <source version uuid> --to <tier> --reason <why> --as <username>
    manage.py raise_source_trust withdraw <raise uuid> --as <username>

``--as`` names the account the raise is recorded under, and the operator proves they
hold it: the command reads that account's password with getpass, at a terminal only
-- never from its arguments or the environment -- and refuses unless
``django.contrib.auth.authenticate`` accepts it, and unless the account is an active
admin (role admin, or a superuser). Anyone else is refused and nothing is written.

Below ``authoritative`` a request records the new version at once.
``authoritative`` is recorded pending, and this command NEVER approves it
(``second_person_required``): a second person approves through the signed-in route,
``POST /api/assurance/economics/trust-raises/<uuid>/approve/``, where the approver is
the account the request authenticated rather than a name typed at a shell.
``approve`` is refused before any password is asked. Any active admin may withdraw a
pending request. A pending request expires 30 days after its request
(``trust_raise_expired``), and an expired one is not withdrawn
(``trust_raise_not_pending``). Every refusal is a CommandError naming its code, and
writes nothing.

It prints the raise's uuid, its state, the source's key and versions, the tiers and
who requested, approved or withdrew it; never the reason, and never the password. It
is on no stop path and reads nothing a stop reads.
"""

from __future__ import annotations

import getpass
import sys
import uuid

from django.contrib.auth import authenticate
from django.core.management.base import BaseCommand, CommandError
from django.db import IntegrityError, OperationalError

from assurance.economics.engine import governance
from assurance.economics.models import EconomicsRefused, FinancialSource, FinancialSourceTrustRaise

ACTIONS = ("request", "approve", "withdraw")
CHANNEL = "command"


def _uuid(value: str, what: str) -> uuid.UUID:
    try:
        return uuid.UUID(str(value))
    except ValueError:
        raise CommandError(f"{value!r} is not a {what} uuid") from None


def _typed_password(username: str) -> str:
    """The ``--as`` account's password, typed at the terminal. Never an argument and
    never the environment; and not a pipe either, which is how one would be read
    from a file or a variable."""
    if not sys.stdin.isatty():
        raise CommandError(
            "refused, nothing was written: the --as account's password is typed at a terminal, and stdin is not one"
        )
    try:
        return getpass.getpass(f"Password for {username}: ")
    except (EOFError, KeyboardInterrupt):
        raise CommandError("refused, nothing was written: no password was typed") from None


def _signed_in(username: str):
    """The ``--as`` account, once its password authenticates it."""
    password = _typed_password(username)
    account = authenticate(username=username, password=password)
    if account is None:
        raise CommandError(
            "refused, nothing was written: the --as account and the password typed do not authenticate "
            "(no such account, the wrong password, or an account that is not active)"
        )
    return account


def _summary(raised: FinancialSourceTrustRaise) -> str:
    source = raised.from_version
    line = (
        f"raise {raised.uuid}: {raised.current_state()}; source {source.source_key} v{source.version} "
        f"{raised.from_tier} -> {raised.to_tier}"
    )
    if raised.to_version_id is not None:
        line += f", recorded as v{raised.to_version.version}"
    line += f"; requested by {raised.requested_by_username or '-'} via {raised.channel}"
    if raised.approved_by_username:
        line += f", approved by {raised.approved_by_username}"
    if raised.withdrawn_by_username:
        line += f", withdrawn by {raised.withdrawn_by_username} via {raised.withdrawn_via}"
    return line


class Command(BaseCommand):
    help = "Request or withdraw a raise of a financial source's trust tier, as an admin whose password you type."

    def add_arguments(self, parser):
        parser.add_argument("action", choices=ACTIONS)
        parser.add_argument("target", help="request: the source version's uuid; withdraw: the raise's uuid.")
        parser.add_argument("--to", dest="to_tier", default=None, help="request: the tier to raise the source to.")
        parser.add_argument("--reason", default=None, help="request: why the source is trusted that far.")
        parser.add_argument(
            "--as",
            dest="as_user",
            required=True,
            help="The admin account the raise is recorded under; its password is asked for at the terminal.",
        )

    def handle(self, *args, **options):
        action = options["action"]
        if action != "request" and (options["to_tier"] is not None or options["reason"] is not None):
            raise CommandError("--to and --reason go with request only")
        if action == "approve":
            # Before any password is asked: this command is never the second person.
            refusal = governance.trust_raise_approval_channel_refusal(CHANNEL)
            if refusal is not None:
                raise CommandError(
                    f"refused, nothing was written: {EconomicsRefused(refusal, 'approve through the signed-in route')}"
                )
        username = (options["as_user"] or "").strip()
        if not username:
            raise CommandError("--as names the admin account the raise is recorded under")
        try:
            if action == "request":
                source = FinancialSource.objects.filter(uuid=_uuid(options["target"], "source version")).first()
                if source is None:
                    raise CommandError(f"no source version {options['target']}")
                account = _signed_in(username)
                raised = FinancialSourceTrustRaise.request(
                    source, options["to_tier"], options["reason"], by=account, channel=CHANNEL
                )
            else:
                found = FinancialSourceTrustRaise.objects.filter(uuid=_uuid(options["target"], "raise")).first()
                if found is None:
                    raise CommandError(f"no trust raise {options['target']}")
                account = _signed_in(username)
                if action == "approve":
                    raised = found.approve(by=account, channel=CHANNEL)
                else:
                    raised = found.withdraw(by=account, channel=CHANNEL)
        except EconomicsRefused as refused:
            raise CommandError(f"refused, nothing was written: {refused}") from None
        except IntegrityError:
            raise CommandError(
                "another version of this source was recorded at the same moment; nothing was written"
            ) from None
        except OperationalError:
            raise CommandError("the database was busy and nothing was written; run the same command again") from None
        self.stdout.write(_summary(FinancialSourceTrustRaise.objects.get(pk=raised.pk)))
