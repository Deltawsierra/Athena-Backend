"""Every chain outcome can be read, one page after another.

``GET .../chain-outcomes/`` answered the newest hundred outcomes and took nothing
that asked for the rest, so an outcome older than the hundredth was recorded and
could be read by nobody through the API. This module is the rest: the order the
read walks in, the cursor that names a place in it, and the one filter the
database can apply.

THE ORDER is newest first by the instant the chain was exercised, undated rows
last, then by when the row was recorded, then by the row's id:
``observed_at DESC NULLS LAST, created_at DESC, id DESC``. The first two are the
model's own ordering; the id is added here, in the query, because a place in a
walk has to be exact and two rows can share both instants (one batch, one
clock tick).

THE CURSOR is a keyset, never an offset. It names the last row a page served, and
the next page is the rows that sort after it. A row recorded while a reader is
between pages therefore moves nothing: no row already read is served again, and
none still to come is passed over. The new row itself is read on the page where
it sorts; one that sorts before the cursor (a newer exercise) is at the head of
the next walk from the first page. An offset counts rows from the head, so every
arrival there shifts each later page by one.

IT HOLDS NOTHING THE PAGE DID NOT ALREADY SERVE: the row's two instants and its
uuid. Not its id. The id is one counter over every deployment's outcomes, and a
cursor can be read by whoever holds it (it is signed, not sealed), so an id in it
would tell a reader of one deployment how many outcomes the others have recorded.
The query finds the id from the uuid itself, in the same statement.

The cursor is signed (:class:`django.core.signing.Signer`), and the signature is
salted with the deployment's uuid and the filter it was issued under. One made
for another deployment or another filter, an edited one and one this route never
made all fail the same check and are refused with the same words
(:data:`BAD_CURSOR`), so the refusal says nothing of any other deployment. It is
refused, never read as "no more": an empty page is an answer about the record.

THE FILTER is named for what the database can filter, ``recorded_as``, and has
one value, ``observed_effect``. What kind of evidence a row IS has no column on
purpose (:class:`assurance.models.WorkflowChainOutcome`): the kind in force
follows from a signature that is checked on every read, which no query can do.
What a row was RECORDED AS is two columns: its basis is ``demonstrated`` and its
observer is a signer :data:`assurance.composition.SIGNER_EVIDENCE` maps to an
observed effect. Every observed effect in force is among those rows. A row
recorded as one whose signature no longer checks is among them too, and says so
itself: its ``evidence_kind`` reads ``attested`` and its ``effect_reading`` is
null, exactly as on the unfiltered read.

A read. Nothing here writes, and nothing here is on a stop's path.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from uuid import UUID

from django.core import signing
from django.db import transaction
from django.db.models import BigIntegerField, Count, F, Q, Subquery, Value
from django.db.models.functions import Coalesce

from . import composition

#: The query parameter that carries a cursor: the page of rows that sort after it.
BEFORE = "before"
#: The query parameter that carries the filter.
RECORDED_AS = "recorded_as"

#: The refusal codes, each a ``400``.
BAD_CURSOR = "bad_cursor"
UNKNOWN_RECORDED_AS = "unknown_recorded_as"

#: The longest cursor this route reads. One it issued is about 160 characters;
#: anything longer is not one, and is refused before any signature is computed.
MAX_CURSOR_CHARS = 512

_SALT = "assurance.outcome_pages.cursor"

#: The id a cursor's row is read as when the row is no longer there: above every
#: id. Rows that share both of its instants are then served again, never passed
#: over -- a row read twice is a reader's to notice, a row never read is not.
_ABOVE_EVERY_ID = 2**63 - 1


def effect_signers() -> tuple[str, ...]:
    """The observers whose outcomes are recorded as observed effects, read from the
    composition's own map each time so the filter cannot name a different set."""
    return tuple(
        sorted(
            signer
            for signer, kind in composition.SIGNER_EVIDENCE.items()
            if kind == composition.EVIDENCE_OBSERVED_EFFECT
        )
    )


def _recorded_as_observed_effect() -> Q:
    return Q(basis=composition.BASIS_DEMONSTRATED, observer_engine__in=effect_signers())


#: Every value ``recorded_as`` takes, and the condition each one is in the query.
FILTERS: Mapping[str, Callable[[], Q]] = {
    composition.EVIDENCE_OBSERVED_EFFECT: _recorded_as_observed_effect,
}


class Refused(ValueError):
    """A request this read cannot answer. ``body`` is the ``400`` it is told."""

    def __init__(self, code: str, error: str):
        self.code = code
        self.body = {"error": error, "code": code}
        super().__init__(error)


@dataclass(frozen=True)
class Asked:
    """What one read asks for: the filter, and the place the page starts after --
    ``(observed_at, created_at, uuid)`` of the last row already served, or ``None``
    for the first page."""

    recorded_as: str | None = None
    after: tuple[datetime | None, datetime, UUID] | None = None


#: The first page of every outcome: what a request with no parameters asks for.
FIRST_PAGE = Asked()


@dataclass(frozen=True)
class Page:
    """One page: its rows in order, the cursor for the page after it (``None`` on the
    last), and the two whole counts beside it."""

    rows: list
    next: str | None
    recorded_count: int
    matching_count: int


def _bad_cursor() -> Refused:
    return Refused(
        BAD_CURSOR,
        f"{BEFORE} is not a cursor this read issued. A cursor is the `next` of an earlier "
        "answer for the same deployment and the same filter; read the first page again "
        "without it.",
    )


def _signer(deployment_uuid: str, recorded_as: str | None) -> signing.Signer:
    return signing.Signer(salt=f"{_SALT}|{deployment_uuid}|{recorded_as or ''}")


def _stamp(instant: datetime | None) -> str | None:
    return None if instant is None else instant.isoformat()


def _instant(text: str) -> datetime:
    instant = datetime.fromisoformat(text)
    if instant.tzinfo is None:
        raise ValueError("an instant with no zone")
    return instant


def cursor_for(row, deployment_uuid: str, recorded_as: str | None) -> str:
    """The cursor that names ``row`` as the last one served, for this deployment and
    this filter and no other. What it holds, the page has already served."""
    return _signer(deployment_uuid, recorded_as).sign_object(
        [_stamp(row.observed_at), _stamp(row.created_at), row.uuid.hex]
    )


def _place(value: str, deployment_uuid: str, recorded_as: str | None) -> tuple[datetime | None, datetime, UUID]:
    """The place ``value`` names, or :class:`Refused`. One refusal for every way a
    cursor can be wrong: which way is not the caller's to learn."""
    if not value or len(value) > MAX_CURSOR_CHARS:
        raise _bad_cursor()
    try:
        named = _signer(deployment_uuid, recorded_as).unsign_object(value)
        observed_at, created_at, row = named
        if not isinstance(created_at, str) or not isinstance(row, str) or len(row) != 32:
            raise ValueError("not a place in the walk")
        return (None if observed_at is None else _instant(observed_at), _instant(created_at), UUID(hex=row))
    except (signing.BadSignature, ValueError, TypeError):
        raise _bad_cursor() from None


def requested(query_params, deployment) -> Asked:
    """What a GET's query string asks for, or :class:`Refused`.

    Called after the deployment is resolved, so a person who cannot see it is
    answered about the deployment (``404``) before anything is said about a cursor.
    A parameter given twice is refused like a wrong one: which of the two was meant
    is not this read's to guess.
    """
    recorded_as = None
    if RECORDED_AS in query_params:
        values = query_params.getlist(RECORDED_AS)
        if len(values) != 1 or values[0] not in FILTERS:
            raise Refused(
                UNKNOWN_RECORDED_AS,
                f"{RECORDED_AS} names what a row was recorded as; the only value is "
                + " or ".join(repr(name) for name in sorted(FILTERS)),
            )
        recorded_as = values[0]
    after = None
    if BEFORE in query_params:
        values = query_params.getlist(BEFORE)
        if len(values) != 1:
            raise _bad_cursor()
        after = _place(values[0], str(deployment.uuid), recorded_as)
    return Asked(recorded_as=recorded_as, after=after)


def _order() -> tuple:
    return (F("observed_at").desc(nulls_last=True), "-created_at", "-id")


def _after(recorded, observed_at: datetime | None, created_at: datetime, row: UUID) -> Q:
    """The rows that sort after the one these three values name, among ``recorded``
    (the deployment's outcomes). The row's id is read from its uuid inside the
    statement, and only among this deployment's rows."""
    row_id = Coalesce(
        Subquery(recorded.filter(uuid=row).order_by().values("id")[:1]),
        Value(_ABOVE_EVERY_ID),
        output_field=BigIntegerField(),
    )
    later_recorded = Q(created_at__lt=created_at) | Q(created_at=created_at, id__lt=row_id)
    if observed_at is None:
        # Undated rows are last, so only undated rows follow an undated one.
        return Q(observed_at__isnull=True) & later_recorded
    return (
        Q(observed_at__lt=observed_at)
        | Q(observed_at__isnull=True)
        | (Q(observed_at=observed_at) & later_recorded)
    )


def read(deployment, asked: Asked = FIRST_PAGE, *, page_size: int) -> Page:
    """One page of ``deployment``'s chain outcomes.

    Two queries whatever the page holds: the counts (one statement for both), and
    the page, which asks for one row more than it serves so that "is there a
    further page" is read off the answer and never off a count taken at another
    moment. Inside one transaction, so the counts and the page are of one moment
    wherever the database gives a transaction one.
    """
    # The deployment's own related manager, so each row already knows its
    # deployment and reading it costs no query per row.
    recorded = deployment.chain_outcomes.all()
    matching = recorded
    with transaction.atomic():
        if asked.recorded_as is None:
            recorded_count = matching_count = recorded.count()
        else:
            condition = FILTERS[asked.recorded_as]()
            counts = recorded.aggregate(
                recorded=Count("id"), matching=Count("id", filter=condition)
            )
            recorded_count, matching_count = counts["recorded"], counts["matching"]
            matching = recorded.filter(condition)
        if asked.after is not None:
            matching = matching.filter(_after(recorded, *asked.after))
        rows = list(matching.order_by(*_order())[: page_size + 1])
    further = len(rows) > page_size
    rows = rows[:page_size]
    return Page(
        rows=rows,
        next=cursor_for(rows[-1], str(deployment.uuid), asked.recorded_as) if further else None,
        recorded_count=recorded_count,
        matching_count=matching_count,
    )
