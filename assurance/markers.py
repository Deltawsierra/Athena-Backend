"""The marker an issue carries so this installation can find it again -- and tell
it from one somebody else wrote.

A push that lost its answer, or a second runner, looks for the issue a finding may
already have before it creates one (:meth:`~assurance.connectors.Connector.find_existing`).
What it looks for is the finding's MARKER, and each created issue carries it twice:

- the LABEL ``athena-<installation>-<finding uuid>`` (50 characters, GitHub's limit
  for a label), which the provider can search on; and
- the body line ``Athena marker: <label> <tag>``, where the TAG is an HMAC over the
  installation id, the CONNECTOR AND ITS DESTINATION (base URL plus repository,
  project or table), the finding and its deployment, keyed by a secret only this
  backend holds (:class:`~assurance.models.AssuranceInstallation`).

A label anyone with triage rights can copy, and a body line anyone who can open an
issue can write. The tag is what they cannot write: it is never published before
the issue that carries it exists, and a tag read in one tracker does not verify in
another, because the destination is part of what it signs. An issue whose body
carries a tag that verifies is therefore this installation's push to THIS
destination -- or a copy of it, made later, from it (a Jira clone, a pasted body).
The look adopts only such an issue, or the issue already recorded for the attempt;
of several that verify, the one the provider created first, since a copy is always
made after what it copies. Every other issue that matches -- a copied label, a
planted body, another installation's or another tracker's tag -- is ignored and
named in a WARNING. None of them can hold a dispatch or be adopted.

Every installation id this database has ever written markers under is kept
(:class:`~assurance.models.AssuranceInstallationId`), and a marker made under any
of them verifies: setting or changing ``ASSURANCE_INSTALLATION_ID`` after go-live
never files a second ticket for an issue made under the id before.

Formats this code has written before, none of them verifiable:

- master: no marker at all, only ``Athena finding: <uuid>`` in the body (and
  ServiceNow's ``correlation_id``);
- round 2 of #303: the label ``athena-<uuid>``;
- round 3 of #303: the label ``athena-<6 hex of SECRET_KEY>-<uuid>``, no tag.

An issue in one of them is never adopted: its text can be edited by anyone who can
edit it, today, whenever it was created. One the provider says was created before
this installation began writing tags
(:attr:`~assurance.models.AssuranceInstallation.created_at`) is a POSSIBLE
duplicate: the ticket filed for the finding names it, in its body and in a
WARNING, so a person can close one of the two. Only an issue the attempt already
records (its ``external_ref``) is taken without a tag.
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
MARKER_VERSION = 5

_TAG_DOMAIN = "athena.finding_marker/5"

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
    #: Every installation id this database has written markers under; a marker made
    #: under any of them is this installation's.
    known_ids: tuple[str, ...] = ()

    def all_ids(self) -> tuple[str, ...]:
        """The current id first, then every other id this database has used."""
        return (self.installation_id, *(i for i in self.known_ids if i != self.installation_id))


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


def _remember(installation_id: str) -> tuple[str, ...]:
    """Every installation id this database has used, ``installation_id`` among them:
    recorded here the first time it is used, and never forgotten."""
    from django.db import IntegrityError, transaction

    from .models import AssuranceInstallationId

    known = list(AssuranceInstallationId.objects.order_by("first_used_at", "pk").values_list("installation_id", flat=True))
    if installation_id not in known:
        try:
            with transaction.atomic():
                AssuranceInstallationId.objects.create(installation_id=installation_id)
        except IntegrityError:  # another process recorded it first
            pass
        known.append(installation_id)
    return tuple(known)


def identity() -> Identity:
    """This installation's identity: its persisted random id -- or
    ``ASSURANCE_INSTALLATION_ID`` when that is set, which overrides it -- its
    persisted secret, and every id this database has used before. Created on first
    use if the migration has not."""
    from django.conf import settings

    row = _row()
    configured = str(getattr(settings, "ASSURANCE_INSTALLATION_ID", "") or "").strip()
    current = configured or row.installation_id
    return Identity(current, row.marker_secret, row.created_at, _remember(current))


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


def marker_for(finding: Any, ident: Identity | None = None, *, scope: str, installation_id: str | None = None) -> Marker:
    """``finding``'s marker under this installation's identity (or under
    ``installation_id``, one of its ids), for the destination ``scope`` names --
    the connector and where it writes (:meth:`~assurance.connectors.Connector.marker_scope`).
    The same finding's marker for another tracker, or another repository, carries
    another tag."""
    ident = ident or identity()
    installation = installation_id or ident.installation_id
    deployment_uuid = getattr(getattr(finding, "deployment", None), "uuid", "")
    message = f"{_TAG_DOMAIN}\x1f{installation}\x1f{scope}\x1f{finding.uuid}\x1f{deployment_uuid}"
    tag = hmac.new(ident.secret.encode(), message.encode(), hashlib.sha256).hexdigest()[:32]
    return Marker(f"athena-{label_prefix(installation)}-{finding.uuid}", tag)


def markers_for(finding: Any, ident: Identity | None = None, *, scope: str) -> list[Marker]:
    """``finding``'s marker for ``scope`` under every id this installation has used,
    the current one first: any of them is this installation's."""
    ident = ident or identity()
    return [marker_for(finding, ident, scope=scope, installation_id=i) for i in ident.all_ids()]


def carries_a_tag(text: str) -> bool:
    """Whether ``text`` carries a tagged marker of any installation -- one that,
    not verifying, is another installation's or a forgery, and in no older format."""
    return bool(text) and _TAGGED.search(text) is not None


def legacy_labels(finding: Any) -> list[str]:
    """Labels older releases put on a finding's issue that can be searched for by
    name: round 2's ``athena-<uuid>``, and the bare uuid."""
    return [f"athena-{finding.uuid}", str(finding.uuid)]
