"""The marker an issue carries so this installation can find it again -- and tell
it from one somebody else wrote.

A push that lost its answer, or a second runner, looks for the issue a finding may
already have before it creates one (:meth:`~assurance.connectors.Connector.find_existing`).
What it looks for is the finding's MARKER, and each created issue carries it twice:

- the LABEL ``athena-<installation>-<finding uuid>`` (50 characters, GitHub's limit
  for a label), which the provider can search on; and
- the body line ``Athena marker: <label> <tag>``, where the TAG is an HMAC over the
  installation id, the finding and its deployment, keyed by a secret only this
  backend holds (:class:`~assurance.models.AssuranceInstallation`).

A label anyone with triage rights can copy, and a body line anyone who can open an
issue can write. The tag is what they cannot write: it is never published before
the issue that carries it exists, so an issue whose body carries it is this
installation's push -- or a copy of it, made later, from it (a Jira clone, a
pasted body). The look therefore adopts only an issue whose tag verifies, or the
issue already recorded for the attempt; of several that verify, the one the
provider created first, since a copy is always made after what it copies. Every
other issue that matches -- a copied label, a planted body, another
installation's issue -- is ignored and named in a WARNING. None of them can hold a
dispatch or be adopted.

Formats this code has written before, each still recognised:

- master: no marker at all, only ``Athena finding: <uuid>`` in the body (and
  ServiceNow's ``correlation_id``);
- round 2 of #303: the label ``athena-<uuid>``;
- round 3 of #303: the label ``athena-<6 hex of SECRET_KEY>-<uuid>``, no tag.

None of them can be verified. An issue in one of them is taken as this code's only
if the provider says it was created before this installation began writing tags
(:attr:`~assurance.models.AssuranceInstallation.created_at`): nobody can create
one in the past. One such issue is adopted; several are held for a person
(``manage.py reconcile_dispatch_attempt``); one created later is a copy, and
ignored.
"""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
from dataclasses import dataclass
from datetime import datetime
from typing import Any

#: The version of the marker format below, recorded on every attempt that pushes.
MARKER_VERSION = 4

_TAG_DOMAIN = "athena.finding_marker/4"

#: ``Athena marker: <label> <tag>`` as the body carries it.
BODY_PREFIX = "Athena marker: "
_TAGGED = re.compile(r"Athena marker: (athena-[0-9a-f]{6}-[0-9a-f-]{36}) ([0-9a-f]{32})")


@dataclass(frozen=True)
class Identity:
    """Who this installation is when it writes a marker."""

    installation_id: str
    secret: str
    #: When it began writing verifiable markers.
    since: datetime | None


def _row():
    from django.db import IntegrityError, transaction

    from .models import AssuranceInstallation

    row = AssuranceInstallation.objects.filter(pk=1).first()
    if row is not None:
        return row
    try:
        with transaction.atomic():
            return AssuranceInstallation.objects.create(
                pk=1, installation_id=secrets.token_hex(16), marker_secret=secrets.token_hex(32)
            )
    except IntegrityError:  # another process created it first
        return AssuranceInstallation.objects.get(pk=1)


def identity() -> Identity:
    """This installation's identity: its persisted random id -- or
    ``ASSURANCE_INSTALLATION_ID`` when that is set, which overrides it -- and its
    persisted secret. Created on first use if the migration has not."""
    from django.conf import settings

    row = _row()
    configured = str(getattr(settings, "ASSURANCE_INSTALLATION_ID", "") or "").strip()
    return Identity(configured or row.installation_id, row.marker_secret, row.created_at)


@dataclass(frozen=True)
class Marker:
    """One finding's marker, as this installation writes it."""

    label: str
    tag: str
    version: int = MARKER_VERSION

    @property
    def text(self) -> str:
        """What an issue's body carries after :data:`BODY_PREFIX`, and what the
        attempt records."""
        return f"{self.label} {self.tag}"

    @property
    def body_line(self) -> str:
        return f"{BODY_PREFIX}{self.text}"

    def verifies(self, text: str) -> bool:
        """Whether ``text`` (an issue's body and fields) carries this marker's tag."""
        return bool(text) and self.body_line in text

    @classmethod
    def parse(cls, recorded: str) -> Marker | None:
        """The marker an attempt recorded, or ``None`` for none (or another format)."""
        parts = (recorded or "").split()
        if len(parts) != 2 or not re.fullmatch(r"[0-9a-f]{32}", parts[1]):
            return None
        return cls(parts[0], parts[1])


def label_prefix(installation_id: str) -> str:
    return hashlib.sha256(f"athena-installation\x1f{installation_id}".encode()).hexdigest()[:6]


def marker_for(finding: Any, ident: Identity | None = None) -> Marker:
    """``finding``'s marker under this installation's identity."""
    ident = ident or identity()
    deployment_uuid = getattr(getattr(finding, "deployment", None), "uuid", "")
    message = f"{_TAG_DOMAIN}\x1f{ident.installation_id}\x1f{finding.uuid}\x1f{deployment_uuid}"
    tag = hmac.new(ident.secret.encode(), message.encode(), hashlib.sha256).hexdigest()[:32]
    return Marker(f"athena-{label_prefix(ident.installation_id)}-{finding.uuid}", tag)


def carries_a_tag(text: str) -> bool:
    """Whether ``text`` carries a tagged marker of any installation -- one that,
    not verifying, is another installation's or a forgery, and in no older format."""
    return bool(text) and _TAGGED.search(text) is not None


def legacy_labels(finding: Any) -> list[str]:
    """Labels older releases put on a finding's issue that can be searched for by
    name: round 2's ``athena-<uuid>``, and the bare uuid."""
    return [f"athena-{finding.uuid}", str(finding.uuid)]
