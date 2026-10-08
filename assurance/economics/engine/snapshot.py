"""An observation snapshot: a committed file of FX and cost-index observations,
the source it is registered as, and its hash.

Phase E1 reads no feed (``docs/economics/spec-v1.md``, section 13). Every rate and
index value comes from a snapshot file, and the snapshot's identity is the SHA-256
of its bytes (``sha256:`` and 64 lowercase hex): every observation read from it
carries that hash, and the :class:`~assurance.economics.models.FinancialSource` it
is registered as records it. An edit to the file is a new hash, and so a new
source version.

The document (schema :data:`SNAPSHOT_SCHEMA`) holds exactly ``schema``, ``label``,
``synthetic``, ``source`` (what the source is registered as), ``calendars`` (each
provider's non-publication dates), ``fx`` and ``cost_index``. Every rate and value
is a decimal STRING: a JSON number is refused (``not_decimal``), because a reader
that parses it as a float has already changed it.

A synthetic snapshot says so where it cannot be missed: ``synthetic`` is true,
its ``label`` and its source's dataset both begin ``SYNTHETIC TEST DATA``, and its
trust tier is ``unverified`` -- made-up numbers are never trusted above that.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime
from types import MappingProxyType

from .cost_index import IndexBook, IndexPoint
from .fx import FXBook, FXRate
from .money import MoneyRefused, check_instant, check_text, parse_decimal
from .provenance import LicenseClass, TrustTier

SNAPSHOT_SCHEMA = "mythos.economics.observation-snapshot/v1"
SYNTHETIC_LABEL = "SYNTHETIC TEST DATA"

_DOCUMENT = frozenset({"schema", "label", "synthetic", "source", "calendars", "fx", "cost_index"})
_SOURCE = frozenset(
    {"source_key", "provider", "dataset", "url", "license_class", "trust_tier", "retrieved_at", "schema_version"}
)
_FX = frozenset({"base", "quote", "rate", "rate_type", "provider", "observed_at", "effective_date"})
_INDEX = frozenset({"series_id", "geography", "category", "period", "value", "vintage_date"})


def snapshot_hash(data: bytes) -> str:
    """``sha256:`` and the SHA-256 of the snapshot's bytes."""
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _object(value, fields: frozenset, what: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise MoneyRefused("snapshot_malformed", f"{what} has exactly the fields {sorted(fields)}")
    return value


def _date(value, what: str) -> date:
    try:
        if not isinstance(value, str) or len(value) != 10:
            raise ValueError
        return date.fromisoformat(value)
    except ValueError:
        raise MoneyRefused("date_malformed", f"{what} {value!r} is not YYYY-MM-DD") from None


def _instant(value, what: str) -> datetime:
    try:
        if not isinstance(value, str):
            raise ValueError
        return datetime.fromisoformat(value)
    except ValueError:
        raise MoneyRefused("date_malformed", f"{what} {value!r} is not an ISO 8601 date and time") from None


@dataclass(frozen=True)
class Snapshot:
    snapshot_hash: str
    label: str
    synthetic: bool
    #: What the snapshot is registered as: a FinancialSource's fields.
    source: Mapping
    holidays: Mapping[str, frozenset[date]]
    fx_rates: tuple[FXRate, ...]
    index_points: tuple[IndexPoint, ...]

    def fx_book(self) -> FXBook:
        return FXBook(self.fx_rates, self.holidays)

    def index_book(self) -> IndexBook:
        return IndexBook(self.index_points)


def parse_snapshot(data: bytes) -> Snapshot:
    """Read and check a snapshot's bytes. Raises :class:`.money.MoneyRefused` on
    any broken rule; nothing is half-read."""
    if not isinstance(data, bytes):
        raise TypeError("a snapshot is read from its bytes")
    digest = snapshot_hash(data)
    try:
        document = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeError):
        raise MoneyRefused("snapshot_malformed", "not UTF-8 JSON") from None
    _object(document, _DOCUMENT, "the snapshot")
    if document["schema"] != SNAPSHOT_SCHEMA:
        raise MoneyRefused("snapshot_malformed", f"the schema is {SNAPSHOT_SCHEMA!r}")
    check_text(label=document["label"])
    if type(document["synthetic"]) is not bool:
        raise MoneyRefused("snapshot_malformed", "synthetic is true or false")
    source = _object(document["source"], _SOURCE, "source")
    for key in _SOURCE - {"url"}:
        check_text(**{f"source.{key}": source[key]})
    if not isinstance(source["url"], str):
        raise MoneyRefused("snapshot_malformed", "source.url is text, empty for none")
    if source["license_class"] not in {c.value for c in LicenseClass}:
        raise MoneyRefused("snapshot_malformed", f"source.license_class {source['license_class']!r}")
    if source["trust_tier"] not in {t.value for t in TrustTier}:
        raise MoneyRefused("snapshot_malformed", f"source.trust_tier {source['trust_tier']!r}")
    retrieved_at = check_instant(_instant(source["retrieved_at"], "source.retrieved_at"), "source.retrieved_at")
    if document["synthetic"] and not (
        document["label"].startswith(SYNTHETIC_LABEL)
        and source["dataset"].startswith(SYNTHETIC_LABEL)
        and source["trust_tier"] == TrustTier.UNVERIFIED.value
    ):
        raise MoneyRefused(
            "snapshot_malformed",
            f"a synthetic snapshot's label and dataset begin {SYNTHETIC_LABEL!r}, and its trust tier is unverified",
        )
    calendars = document["calendars"]
    if not isinstance(calendars, dict):
        raise MoneyRefused("snapshot_malformed", "calendars maps each provider to its non-publication dates")
    holidays = {}
    for provider, calendar in calendars.items():
        calendar = _object(calendar, frozenset({"non_publication_dates"}), f"calendar {provider}")
        if not isinstance(calendar["non_publication_dates"], list):
            raise MoneyRefused("snapshot_malformed", f"calendar {provider} lists its dates")
        holidays[provider] = frozenset(_date(d, f"{provider} holiday") for d in calendar["non_publication_dates"])
    if not isinstance(document["fx"], list) or not isinstance(document["cost_index"], list):
        raise MoneyRefused("snapshot_malformed", "fx and cost_index are lists")
    key = source["source_key"]
    rates = tuple(
        FXRate(
            base=entry["base"],
            quote=entry["quote"],
            rate=parse_decimal(entry["rate"], "rate"),
            rate_type=entry["rate_type"],
            provider=entry["provider"],
            observed_at=_instant(entry["observed_at"], "observed_at"),
            effective_date=_date(entry["effective_date"], "effective_date"),
            source_snapshot_hash=digest,
            source_key=key,
        )
        for entry in (_object(raw, _FX, "an fx observation") for raw in document["fx"])
    )
    points = tuple(
        IndexPoint(
            series_id=entry["series_id"],
            geography=entry["geography"],
            category=entry["category"],
            period=entry["period"],
            value=parse_decimal(entry["value"], "index value"),
            vintage_date=_date(entry["vintage_date"], "vintage_date"),
            source_snapshot_hash=digest,
            source_key=key,
        )
        for entry in (_object(raw, _INDEX, "a cost-index observation") for raw in document["cost_index"])
    )
    snapshot = Snapshot(
        snapshot_hash=digest,
        label=document["label"],
        synthetic=document["synthetic"],
        source=MappingProxyType({**source, "retrieved_at": retrieved_at}),
        holidays=MappingProxyType(holidays),
        fx_rates=rates,
        index_points=points,
    )
    # Building the books checks for duplicates and mixed series before anything
    # reads the snapshot.
    snapshot.fx_book()
    snapshot.index_book()
    return snapshot
