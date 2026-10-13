"""The live-feed adapters, the feed registry and the freshness table (MVP step 10;
``docs/economics/spec-v1.md``, section 28).

Four official publishers, each read from its own documented response format into
the existing observation-snapshot shape (:class:`.snapshot.Snapshot`):

- **ECB SDMX** (``ecb``): the euro foreign exchange reference rates, daily, as
  SDMX-CSV (``format=csvdata``). Each rate is ``1 EUR = rate <currency>``, rate type
  ``reference``: an INFORMATIONAL AVERAGE, NOT A TRANSACTION PRICE, which the source's
  dataset says.
- **Federal Reserve H.10** (``h10``): the noon buying rates in New York, daily
  values published weekly, as the Data Download Program's CSV. H.10 quotes most
  currencies per US dollar (``RXI_N.B.JA``: yen per dollar) and a few in US dollars
  per unit (``RXI$US_N.B.EU``: dollars per euro); each series' convention is in the
  registry and checked against the unit the response names, so a rate is never read
  the wrong way round.
- **FRED / ALFRED** (``fred``): one monthly series' observations as JSON, with the
  real-time window pinned to the as-of date (``realtime_start = realtime_end =
  as_of``): the values as they were known on that date, each recorded with that date
  as its vintage, so a run can reproduce what was known then.
- **BLS Public Data API** (``bls``): one monthly PPI or wage series as JSON (v1 and v2
  answer in the same shape; v2 needs the registration key). BLS serves current
  values only, so it cannot be asked what was known on an earlier date
  (``as_of_unsupported``); each value's vintage is the date it was fetched.

Each adapter is all or nothing: a response that is not the provider's documented
format, is for another series, currency, unit or window than was asked, holds fewer
observations than it says, or holds a value that is not in the documented form, is
refused with a code (:data:`FEED_REFUSALS`, or the money engine's code for a value
the observation contract refuses) and nothing of it is kept. A value the provider
marks as missing (ECB never, H.10 ``ND``, FRED ``.``, BLS ``-``, and BLS's annual
average ``M13``) is skipped, never read as zero.

**The response hash** a source version records, and that the snapshot store
deduplicates on, is the SHA-256 of the NORMALISED payload (:func:`payload_hash`):

- ECB and H.10: the response's bytes as they came; both CSVs carry no clock;
- FRED: its JSON re-serialised canonically (sorted keys, no whitespace), nothing
  dropped. Its real-time window is pinned to the as-of date in the request, so the
  same values asked for the same date are the same payload, and another date is
  another vintage;
- BLS: its JSON re-serialised canonically with ``responseTime`` dropped: BLS times
  every answer, so the same values fetched twice differ only there.

The **freshness table** (:data:`FRESHNESS_SLA_DAYS`) gives each publisher's SLA in
days by its cadence: ECB daily 3, H.10's weekly release 10, FRED and BLS monthly
series 45. A source whose newest observation known at the as-of date is older than
its SLA is ``stale``; older than twice its SLA, ``blocked``; with none, ``missing``
(:func:`freshness_state`).

Pure: no Django, no I/O. Nothing here sends a request: :func:`request_for` says
what to send, without any key, and the Django half sends it.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta, timezone
from types import MappingProxyType
from urllib.parse import urlencode

from .cost_index import IndexPoint, period_end
from .fx import FXRate
from .money import MoneyRefused, parse_decimal
from .provenance import LicenseClass, TrustTier
from .snapshot import Snapshot

#: Every code an adapter, the registry or a fetch refuses with, besides the money
#: engine's own (a value the observation contract refuses keeps its code).
FEED_REFUSALS: Mapping[str, str] = MappingProxyType(
    {
        "source_unrecognised": "the source is not in the feed registry: nothing was sent or written",
        "source_key_missing": (
            "the source needs its provider's key, and the setting that holds it is empty: nothing was sent or written"
        ),
        "live_feeds_disabled": (
            "live fetching is switched off (ECONOMICS_LIVE_FEEDS_ENABLED is not True): nothing was sent or written"
        ),
        "as_of_unsupported": (
            "the provider serves current values only, so it cannot say what was known on an earlier date: nothing "
            "was sent or written"
        ),
        "as_of_in_future": "the as-of date is after today: nothing was sent or written",
        "fetch_failed": "the request was not answered: the connection, TLS or the time allowed failed",
        "fetch_http_error": "the provider answered with a status other than 200",
        "response_too_large": "the answer is larger than a feed's answer may be, and was not read",
        "feed_malformed": (
            "the answer is not the provider's documented format: its encoding, its CSV or JSON, or a field or column "
            "it must have"
        ),
        "feed_provider_error": "the provider's answer says the request failed",
        "feed_mismatch": (
            "the answer is for another series, currency, frequency, unit or window than was asked, or names one "
            "twice"
        ),
        "feed_partial": (
            "the answer holds fewer observations or series than it says or than was asked, or a line is cut short"
        ),
        "feed_value_malformed": "a date, period or value in the answer is not in the provider's documented form",
        "feed_empty": "the answer holds no observation",
        "fetch_conflict": "another fetch of the same source recorded a version at the same moment: nothing was written",
    }
)

#: The banner every source of a publisher of reference rates carries.
REFERENCE_RATE_LABEL = "informational average, not a transaction price"

#: The freshness SLA of each publisher, in days, by its cadence (one table).
FRESHNESS_SLA_DAYS: Mapping[tuple[str, str], int] = MappingProxyType(
    {
        ("ECB", "daily"): 3,
        ("FRB-H10", "weekly"): 10,
        ("FRED", "monthly"): 45,
        ("BLS", "monthly"): 45,
    }
)

FRESH, STALE, BLOCKED, MISSING = "fresh", "stale", "blocked", "missing"
STATES = (FRESH, STALE, BLOCKED, MISSING)
#: The states that lower the grade of every figure a source feeds one step.
DOWNGRADING = frozenset({STALE, BLOCKED, MISSING})
#: The states that block a "current" claim: the card says stale, and a receipt is refused.
BLOCKING = frozenset({BLOCKED, MISSING})

FX, COST_INDEX = "fx", "cost_index"

#: The largest answer a feed may give, in bytes; a larger one is not read.
MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class FeedRefused(ValueError):
    """A response, request or source this module refuses. ``code`` is one of
    :data:`FEED_REFUSALS`."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        super().__init__(f"{code}: {FEED_REFUSALS[code]}{suffix}")


@dataclass(frozen=True)
class FeedSource:
    """One source in the feed registry: what it is, where it is read from, and how."""

    key: str
    adapter: str
    provider: str
    dataset: str
    kind: str
    cadence: str
    base_url: str
    path: str
    schema_version: str
    #: The settings name holding the provider's key, or "" for a provider that needs none.
    key_setting: str = ""
    #: Every source is ``unreviewed`` until the owner's licensing review of its
    #: provider's terms (FREEZE.md, owner exception 9): no production run may use it.
    license_class: str = LicenseClass.UNREVIEWED.value
    config: Mapping = field(default_factory=lambda: MappingProxyType({}))

    @property
    def sla_days(self) -> int:
        return FRESHNESS_SLA_DAYS[(self.provider, self.cadence)]

    @property
    def endpoint(self) -> str:
        return self.base_url + self.path


def _frozen(**values) -> Mapping:
    return MappingProxyType(values)


#: The feed registry: every source ``manage.py fetch_financial_source`` reads.
REGISTRY: Mapping[str, FeedSource] = MappingProxyType(
    {
        "ecb-eur-reference-rates": FeedSource(
            key="ecb-eur-reference-rates",
            adapter="ecb",
            provider="ECB",
            dataset=(
                f"ECB euro foreign exchange reference rates, daily (EXR D.*.EUR.SP00.A: GBP, JPY, USD): "
                f"{REFERENCE_RATE_LABEL}"
            ),
            kind=FX,
            cadence="daily",
            base_url="https://data-api.ecb.europa.eu",
            path="/service/data/EXR/D.GBP+JPY+USD.EUR.SP00.A",
            schema_version="ecb.sdmx-csv.exr/1",
            config=_frozen(currencies=("GBP", "JPY", "USD"), observations=10),
        ),
        "fed-h10-daily-rates": FeedSource(
            key="fed-h10-daily-rates",
            adapter="h10",
            provider="FRB-H10",
            dataset=(
                "Federal Reserve H.10 foreign exchange rates, noon buying rates in New York, daily values released "
                f"weekly (EUR and GBP in US dollars per unit, JPY per US dollar): {REFERENCE_RATE_LABEL}"
            ),
            kind=FX,
            cadence="weekly",
            base_url="https://www.federalreserve.gov",
            path="/datadownload/Output.aspx",
            schema_version="frb.ddp-csv.h10/1",
            config=_frozen(
                package="60f32914ab61dfab590e0e470153e3ae",
                observations=10,
                # mnemonic: (currency, convention, the unit the DDP names): "usd_per" is
                # 1 <currency> = rate USD; "per_usd" is 1 USD = rate <currency>.
                series=MappingProxyType(
                    {
                        "RXI$US_N.B.EU": ("EUR", "usd_per", "USD:_Per_EUR"),
                        "RXI_N.B.JA": ("JPY", "per_usd", "JPY:_Per_USD"),
                        "RXI$US_N.B.UK": ("GBP", "usd_per", "USD:_Per_GBP"),
                    }
                ),
            ),
        ),
        "fred-cpiaucsl": FeedSource(
            key="fred-cpiaucsl",
            adapter="fred",
            provider="FRED",
            dataset=(
                "FRED/ALFRED CPIAUCSL: Consumer Price Index for All Urban Consumers, all items in U.S. city average, "
                "seasonally adjusted, monthly, as known on the as-of date"
            ),
            kind=COST_INDEX,
            cadence="monthly",
            base_url="https://api.stlouisfed.org",
            path="/fred/series/observations",
            schema_version="fred.series-observations.json/1",
            key_setting="ECONOMICS_FRED_API_KEY",
            config=_frozen(
                series_id="CPIAUCSL",
                geography="US",
                category="consumer prices, all items, U.S. city average, seasonally adjusted (CPI-U)",
                base="1982-1984=100",
                months=13,
            ),
        ),
        "bls-ppi-final-demand": FeedSource(
            key="bls-ppi-final-demand",
            adapter="bls",
            provider="BLS",
            dataset="BLS PPI WPUFD4: Producer Price Index, final demand, monthly, as known on the fetch date",
            kind=COST_INDEX,
            cadence="monthly",
            base_url="https://api.bls.gov",
            path="/publicAPI/v2/timeseries/data/",
            schema_version="bls.timeseries-data.json/2",
            key_setting="ECONOMICS_BLS_API_KEY",
            config=_frozen(
                series_id="WPUFD4", geography="US", category="producer prices, final demand", base="2009-11=100"
            ),
        ),
        "bls-ahe-total-private": FeedSource(
            key="bls-ahe-total-private",
            adapter="bls",
            provider="BLS",
            dataset=(
                "BLS CES CES0500000003: average hourly earnings of all employees, total private, seasonally adjusted, "
                "monthly, as known on the fetch date"
            ),
            kind=COST_INDEX,
            cadence="monthly",
            base_url="https://api.bls.gov",
            path="/publicAPI/v2/timeseries/data/",
            schema_version="bls.timeseries-data.json/2",
            key_setting="ECONOMICS_BLS_API_KEY",
            config=_frozen(
                series_id="CES0500000003",
                geography="US",
                category="wages, average hourly earnings of all employees, total private",
                # A level, not an index: the ratio of two months' earnings is the wage change.
                base="USD per hour, level",
            ),
        ),
    }
)


def source(key: str) -> FeedSource:
    """The registry's source ``key``, or ``source_unrecognised``."""
    found = REGISTRY.get(key) if isinstance(key, str) else None
    if found is None:
        raise FeedRefused("source_unrecognised", repr(key))
    return found


# ---------------------------------------------------------------- freshness


def freshness_state(age_days: int | None, sla_days: int) -> str:
    """``fresh`` up to the SLA, ``stale`` above it, ``blocked`` above twice it, and
    ``missing`` with no observation to age (``age_days`` None)."""
    if age_days is None:
        return MISSING
    if age_days <= sla_days:
        return FRESH
    if age_days <= 2 * sla_days:
        return STALE
    return BLOCKED


#: How a parameter names the feed source it rests on, in its ``evidence_ref``: the
#: prefix, the registry key, then the end or a space and anything at all.
EVIDENCE_PREFIX = "financial-source:"
_EVIDENCE = re.compile(r"financial-source:([a-z0-9][a-z0-9-]*)(?:\s|$)")


def feed_reference(evidence_ref) -> str | None:
    """The source key ``evidence_ref`` names (``financial-source:<key>``, then the end
    or a space), or None where it names none. A key the registry does not hold is
    returned too: a reference to it fails closed (``missing``), never silently."""
    if not isinstance(evidence_ref, str):
        return None
    match = _EVIDENCE.match(evidence_ref)
    return match.group(1) if match else None


def referenced_keys(parameters) -> dict[str, list[str]]:
    """``{source key: [parameter names]}`` for every parameter of a run's canonical
    inputs (``{name: {"evidence_ref": ...}}``) whose evidence names a feed source."""
    found: dict[str, list[str]] = {}
    for name, held in sorted((parameters or {}).items()):
        key = feed_reference((held or {}).get("evidence_ref"))
        if key is not None:
            found.setdefault(key, []).append(name)
    return found


# ------------------------------------------------------------------ requests


@dataclass(frozen=True)
class FeedRequest:
    """What to send, WITHOUT the key: the method, the endpoint, the query and the
    JSON body; and where the key goes (a query parameter or a body field), if the
    source needs one. :attr:`recorded_url` is what a source version records."""

    method: str
    url: str
    params: tuple[tuple[str, str], ...] = ()
    body: Mapping | None = None
    key_in: str = ""
    key_name: str = ""

    @property
    def recorded_url(self) -> str:
        return self.url + ("?" + urlencode(self.params) if self.params else "")


def request_for(feed: FeedSource, *, as_of: date, explicit: bool, today: date, base_url: str | None = None) -> FeedRequest:
    """The request for ``feed`` as known on ``as_of``. ``explicit``: the operator
    named the date (``--as-of``); otherwise it is today, and the request asks for
    the latest observations, so a fetch with nothing new answers the same payload.
    ``base_url`` replaces the registry's (a test's loopback service)."""
    if as_of > today:
        raise FeedRefused("as_of_in_future", f"{as_of} is after {today}")
    url = (base_url if base_url is not None else feed.base_url) + feed.path
    config = feed.config
    if feed.adapter == "ecb":
        params = [("format", "csvdata"), ("lastNObservations", str(config["observations"]))]
        if explicit:
            params.append(("endPeriod", as_of.isoformat()))
        return FeedRequest("GET", url, tuple(params))
    if feed.adapter == "h10":
        params = [("rel", "H10"), ("series", config["package"])]
        if explicit:
            start = as_of - timedelta(days=31)
            params += [("lastobs", ""), ("from", start.strftime("%m/%d/%Y")), ("to", as_of.strftime("%m/%d/%Y"))]
        else:
            params += [("lastobs", str(config["observations"])), ("from", ""), ("to", "")]
        params += [("filetype", "csv"), ("label", "include"), ("layout", "seriescolumn"), ("type", "package")]
        return FeedRequest("GET", url, tuple(params))
    if feed.adapter == "fred":
        months = int(config["months"])
        index = as_of.year * 12 + (as_of.month - 1) - months
        start = date(index // 12, index % 12 + 1, 1)
        params = (
            ("series_id", config["series_id"]),
            ("file_type", "json"),
            ("realtime_start", as_of.isoformat()),
            ("realtime_end", as_of.isoformat()),
            ("observation_start", start.isoformat()),
        )
        return FeedRequest("GET", url, params, key_in="query", key_name="api_key")
    if feed.adapter == "bls":
        if as_of != today:
            raise FeedRefused("as_of_unsupported", f"BLS serves current values only, not those known on {as_of}")
        body = MappingProxyType(
            {
                "seriesid": (config["series_id"],),
                "startyear": str(as_of.year - 1),
                "endyear": str(as_of.year),
                "catalog": False,
            }
        )
        return FeedRequest("POST", url, (), body, key_in="body", key_name="registrationkey")
    raise FeedRefused("source_unrecognised", f"{feed.key} names no adapter this module has")


# ------------------------------------------------------------ normalising


def _strict_json(raw: bytes):
    """The JSON document of ``raw``: UTF-8, no key twice in one object, no bare
    NaN or Infinity, and no number with a fraction or an exponent (no float)."""

    def pairs(items):
        document = {}
        for key, value in items:
            if key in document:
                raise FeedRefused("feed_malformed", f"the key {key!r} appears twice in one object")
            document[key] = value
        return document

    def constant(name):
        raise FeedRefused("feed_malformed", f"{name} is not JSON")

    def number(text):
        raise FeedRefused("feed_malformed", f"the number {text} is not a whole number")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant, parse_float=number)
    except FeedRefused:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise FeedRefused("feed_malformed", "not UTF-8 JSON") from None


def _canonical(document) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


#: What each adapter drops before its payload is hashed (spec, section 28.3).
NORMALISATION: Mapping[str, str] = MappingProxyType(
    {
        "ecb": "nothing: the response's bytes as they came (SDMX-CSV carries no clock)",
        "h10": "nothing: the response's bytes as they came (the DDP's CSV carries no clock)",
        "fred": (
            "nothing dropped: the JSON re-serialised canonically (sorted keys, no whitespace); its real-time window "
            "is pinned to the as-of date in the request, so another date is another vintage"
        ),
        "bls": "responseTime dropped, then the JSON re-serialised canonically (sorted keys, no whitespace)",
    }
)


def payload_hash(feed: FeedSource, raw: bytes) -> str:
    """``sha256:`` and the SHA-256 of the normalised payload (:data:`NORMALISATION`):
    the response hash a source version records, and that the store deduplicates on."""
    if not isinstance(raw, bytes):
        raise TypeError("a response is read from its bytes")
    if feed.adapter in ("ecb", "h10"):
        normalised = raw
    elif feed.adapter == "fred":
        normalised = _canonical(_strict_json(raw))
    elif feed.adapter == "bls":
        document = _strict_json(raw)
        if isinstance(document, dict):
            document = {name: value for name, value in document.items() if name != "responseTime"}
        normalised = _canonical(document)
    else:
        raise FeedRefused("source_unrecognised", feed.key)
    return "sha256:" + hashlib.sha256(normalised).hexdigest()


# ------------------------------------------------------------------- dates


def _last_sunday(year: int, month: int) -> date:
    following = date(year + 1, 1, 1) if month == 12 else date(year, month + 1, 1)
    day = following - timedelta(days=1)
    return day - timedelta(days=(day.weekday() + 1) % 7)


def _nth_sunday(year: int, month: int, n: int) -> date:
    first = date(year, month, 1)
    return first + timedelta(days=(6 - first.weekday()) % 7 + 7 * (n - 1))


def ecb_fixing_time(day: date) -> datetime:
    """When the ECB's reference rate for ``day`` is set: 14:15 Central European Time
    (CET, UTC+1; CEST, UTC+2 from the last Sunday of March to the last Sunday of
    October), as the series' title says. Computed, never read from a time-zone
    database, so every platform records the same instant."""
    summer = _last_sunday(day.year, 3) <= day < _last_sunday(day.year, 10)
    offset = timezone(timedelta(hours=2 if summer else 1))
    return datetime(day.year, day.month, day.day, 14, 15, tzinfo=offset)


def h10_noon(day: date) -> datetime:
    """Noon in New York on ``day`` (EST, UTC-5; EDT, UTC-4 from the second Sunday of
    March to the first Sunday of November): the H.10 noon buying rate's instant."""
    summer = _nth_sunday(day.year, 3, 2) <= day < _nth_sunday(day.year, 11, 1)
    offset = timezone(timedelta(hours=-4 if summer else -5))
    return datetime(day.year, day.month, day.day, 12, 0, tzinfo=offset)


_DAY = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


def _day(text, what: str) -> date:
    if not isinstance(text, str) or not _DAY.fullmatch(text):
        raise FeedRefused("feed_value_malformed", f"{what} {text!r} is not YYYY-MM-DD")
    try:
        return date.fromisoformat(text)
    except ValueError:
        raise FeedRefused("feed_value_malformed", f"{what} {text!r} is not a date") from None


def _value(text, what: str):
    try:
        return parse_decimal(text, what)
    except MoneyRefused:
        raise FeedRefused("feed_value_malformed", f"{what} {text!r} is not a plain decimal") from None


# ---------------------------------------------------------------------- CSV


def _csv(raw: bytes) -> list[list[str]]:
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise FeedRefused("feed_malformed", "not UTF-8") from None
    if text.startswith("﻿"):
        text = text[1:]
    try:
        rows = list(csv.reader(io.StringIO(text, newline=""), strict=True))
    except csv.Error as error:
        raise FeedRefused("feed_malformed", f"not CSV: {error}") from None
    rows = [row for row in rows if row != []]
    if not rows:
        raise FeedRefused("feed_empty", "no line at all")
    return rows


#: The SDMX-CSV columns the ECB adapter reads. Every other column is the dataset's
#: attributes, kept by the provider and not read here.
ECB_COLUMNS = ("KEY", "FREQ", "CURRENCY", "CURRENCY_DENOM", "EXR_TYPE", "EXR_SUFFIX", "TIME_PERIOD", "OBS_VALUE",
               "OBS_STATUS", "UNIT_MULT")


def _ecb(feed: FeedSource, raw: bytes, as_of: date, digest: str) -> list[FXRate]:
    rows = _csv(raw)
    header, lines = rows[0], rows[1:]
    if len(set(header)) != len(header):
        raise FeedRefused("feed_malformed", "a column is named twice")
    missing = [name for name in ECB_COLUMNS if name not in header]
    if missing:
        raise FeedRefused("feed_malformed", f"no column {missing}")
    at = {name: header.index(name) for name in ECB_COLUMNS}
    wanted = set(feed.config["currencies"])
    rates, seen = [], set()
    for number, line in enumerate(lines, start=2):
        if len(line) != len(header):
            raise FeedRefused("feed_partial", f"line {number} has {len(line)} of {len(header)} columns")
        cell = {name: line[at[name]] for name in ECB_COLUMNS}
        expected_key = ".".join(
            ("EXR", cell["FREQ"], cell["CURRENCY"], cell["CURRENCY_DENOM"], cell["EXR_TYPE"], cell["EXR_SUFFIX"])
        )
        if cell["KEY"] != expected_key:
            raise FeedRefused("feed_mismatch", f"line {number}: KEY {cell['KEY']!r} is not its dimensions'")
        if (cell["FREQ"], cell["CURRENCY_DENOM"], cell["EXR_TYPE"], cell["EXR_SUFFIX"]) != ("D", "EUR", "SP00", "A"):
            raise FeedRefused("feed_mismatch", f"line {number}: {cell['KEY']} is not a daily euro reference rate")
        if cell["CURRENCY"] not in wanted:
            raise FeedRefused("feed_mismatch", f"line {number}: {cell['CURRENCY']} was not asked for")
        if cell["UNIT_MULT"] != "0" or cell["OBS_STATUS"] != "A":
            raise FeedRefused(
                "feed_value_malformed",
                f"line {number}: unit multiplier {cell['UNIT_MULT']!r} or status {cell['OBS_STATUS']!r} is not "
                "a plain normal value",
            )
        day = _day(cell["TIME_PERIOD"], f"line {number} TIME_PERIOD")
        if day > as_of:
            raise FeedRefused("feed_mismatch", f"line {number}: {day} is after the as-of date {as_of}")
        rates.append(
            FXRate(
                base="EUR",
                quote=cell["CURRENCY"],
                rate=_value(cell["OBS_VALUE"], f"line {number} OBS_VALUE"),
                rate_type="reference",
                provider=feed.provider,
                observed_at=ecb_fixing_time(day),
                effective_date=day,
                source_snapshot_hash=digest,
                source_key=feed.key,
            )
        )
        seen.add(cell["CURRENCY"])
    if not rates:
        raise FeedRefused("feed_empty", "no observation")
    if seen != wanted:
        raise FeedRefused("feed_partial", f"no rate for {sorted(wanted - seen)}")
    return rates


#: The labels of the DDP CSV's six heading lines, in order (read with their
#: surrounding spaces stripped).
H10_HEADINGS = ("Series Description", "Unit:", "Multiplier:", "Currency:", "Unique Identifier:", "Time Period")
#: What the DDP writes for a day with no rate (a holiday).
H10_NO_DATA = "ND"


def _h10(feed: FeedSource, raw: bytes, as_of: date, digest: str) -> list[FXRate]:
    rows = _csv(raw)
    if len(rows) < len(H10_HEADINGS):
        raise FeedRefused("feed_partial", "fewer heading lines than the DDP writes")
    headings, lines = rows[: len(H10_HEADINGS)], rows[len(H10_HEADINGS):]
    width = len(headings[0])
    if [row[0].strip() if row else "" for row in headings] != list(H10_HEADINGS) or width < 2:
        raise FeedRefused("feed_malformed", f"the heading lines are not {list(H10_HEADINGS)}")
    if any(len(row) != width for row in headings):
        raise FeedRefused("feed_malformed", "a heading line has another number of columns")
    configured = feed.config["series"]
    columns = []
    for column in range(1, width):
        mnemonic = headings[5][column]
        if mnemonic not in configured:
            raise FeedRefused("feed_mismatch", f"series {mnemonic!r} was not asked for")
        if headings[4][column] != f"H10/H10/{mnemonic}":
            raise FeedRefused("feed_mismatch", f"series {mnemonic}: identifier {headings[4][column]!r}")
        currency, convention, unit = configured[mnemonic]
        if headings[1][column] != unit:
            raise FeedRefused("feed_mismatch", f"series {mnemonic}: unit {headings[1][column]!r}, not {unit!r}")
        if headings[2][column] != "1":
            raise FeedRefused("feed_mismatch", f"series {mnemonic}: multiplier {headings[2][column]!r}, not 1")
        columns.append((column, mnemonic, currency, convention))
    named = [mnemonic for _c, mnemonic, _cur, _conv in columns]
    if len(set(named)) != len(named):
        raise FeedRefused("feed_mismatch", "a series is named twice")
    if set(named) != set(configured):
        raise FeedRefused("feed_partial", f"no column for {sorted(set(configured) - set(named))}")
    rates = []
    for number, line in enumerate(lines, start=len(H10_HEADINGS) + 1):
        if len(line) != width:
            raise FeedRefused("feed_partial", f"line {number} has {len(line)} of {width} columns")
        day = _day(line[0], f"line {number} date")
        if day > as_of:
            raise FeedRefused("feed_mismatch", f"line {number}: {day} is after the as-of date {as_of}")
        for column, mnemonic, currency, convention in columns:
            text = line[column]
            if text == H10_NO_DATA:
                continue
            base, quote = ("USD", currency) if convention == "per_usd" else (currency, "USD")
            rates.append(
                FXRate(
                    base=base,
                    quote=quote,
                    rate=_value(text, f"line {number} {mnemonic}"),
                    rate_type="reference",
                    provider=feed.provider,
                    observed_at=h10_noon(day),
                    effective_date=day,
                    source_snapshot_hash=digest,
                    source_key=feed.key,
                )
            )
    if not rates:
        raise FeedRefused("feed_empty", "no observation")
    return rates


# --------------------------------------------------------------------- JSON


#: The fields of FRED's series/observations answer, and of each observation.
FRED_FIELDS = frozenset(
    {
        "realtime_start", "realtime_end", "observation_start", "observation_end", "units", "output_type",
        "file_type", "order_by", "sort_order", "count", "offset", "limit", "observations",
    }
)
FRED_OBSERVATION_FIELDS = frozenset({"realtime_start", "realtime_end", "date", "value"})
#: What FRED writes for a date with no value.
FRED_MISSING = "."


def _fred(feed: FeedSource, raw: bytes, as_of: date, digest: str) -> list[IndexPoint]:
    document = _strict_json(raw)
    if isinstance(document, dict) and "error_code" in document:
        raise FeedRefused("feed_provider_error", f"FRED error_code {document.get('error_code')!r}")
    if not isinstance(document, dict) or set(document) != FRED_FIELDS:
        raise FeedRefused("feed_malformed", f"FRED's answer has exactly the fields {sorted(FRED_FIELDS)}")
    pinned = as_of.isoformat()
    if (document["realtime_start"], document["realtime_end"]) != (pinned, pinned):
        raise FeedRefused("feed_mismatch", f"the real-time window is not pinned to {pinned}")
    if (document["units"], document["file_type"], document["output_type"]) != ("lin", "json", 1):
        raise FeedRefused("feed_mismatch", "units lin, file type json and output type 1 were asked")
    observations = document["observations"]
    if not isinstance(observations, list) or not all(isinstance(document[k], int) for k in ("count", "offset")):
        raise FeedRefused("feed_malformed", "observations is a list, count and offset whole numbers")
    if document["offset"] != 0 or document["count"] != len(observations):
        raise FeedRefused(
            "feed_partial", f"the answer says {document['count']} observations from {document['offset']}, and holds "
            f"{len(observations)}"
        )
    config = feed.config
    points, periods = [], set()
    for number, entry in enumerate(observations):
        if not isinstance(entry, dict) or set(entry) != FRED_OBSERVATION_FIELDS:
            raise FeedRefused("feed_malformed", f"observation {number} has exactly {sorted(FRED_OBSERVATION_FIELDS)}")
        if (entry["realtime_start"], entry["realtime_end"]) != (pinned, pinned):
            raise FeedRefused("feed_mismatch", f"observation {number} is outside the pinned window")
        day = _day(entry["date"], f"observation {number} date")
        if day.day != 1:
            raise FeedRefused("feed_mismatch", f"observation {number} dated {day} is not a month: a monthly series")
        period = entry["date"][:7]
        if period in periods:
            raise FeedRefused("feed_mismatch", f"the month {period} is listed twice")
        periods.add(period)
        if entry["value"] == FRED_MISSING:
            continue
        points.append(
            IndexPoint(
                series_id=config["series_id"],
                geography=config["geography"],
                category=config["category"],
                base=config["base"],
                period=period,
                value=_value(entry["value"], f"observation {number} value"),
                vintage_date=as_of,
                source_snapshot_hash=digest,
                source_key=feed.key,
            )
        )
    if not points:
        raise FeedRefused("feed_empty", "no observation with a value")
    return points


#: The fields of a BLS timeseries answer, of its series and of each value.
BLS_FIELDS = frozenset({"status", "responseTime", "message", "Results"})
BLS_SERIES_FIELDS = frozenset({"seriesID", "data"})
BLS_DATA_REQUIRED = frozenset({"year", "period", "periodName", "value", "footnotes"})
BLS_DATA_OPTIONAL = frozenset({"latest"})
BLS_SUCCEEDED = "REQUEST_SUCCEEDED"
#: BLS's annual average, which is not a month; and its mark for no value.
BLS_ANNUAL = "M13"
BLS_MISSING = "-"
_BLS_PERIOD = re.compile(r"M(0[1-9]|1[0-3])")
_YEAR = re.compile(r"[0-9]{4}")


def _bls(feed: FeedSource, raw: bytes, as_of: date, digest: str) -> list[IndexPoint]:
    document = _strict_json(raw)
    if not isinstance(document, dict) or set(document) != BLS_FIELDS:
        raise FeedRefused("feed_malformed", f"the BLS answer has exactly the fields {sorted(BLS_FIELDS)}")
    if document["status"] != BLS_SUCCEEDED:
        raise FeedRefused("feed_provider_error", f"BLS status {document['status']!r}")
    results = document["Results"]
    if not isinstance(results, dict) or set(results) != {"series"} or not isinstance(results["series"], list):
        raise FeedRefused("feed_malformed", "Results holds exactly a list of series")
    config = feed.config
    series = results["series"]
    if len(series) != 1:
        raise FeedRefused("feed_partial" if not series else "feed_mismatch", f"{len(series)} series, one was asked")
    (one,) = series
    if not isinstance(one, dict) or set(one) != BLS_SERIES_FIELDS or not isinstance(one["data"], list):
        raise FeedRefused("feed_malformed", f"a series has exactly {sorted(BLS_SERIES_FIELDS)}, its data a list")
    if one["seriesID"] != config["series_id"]:
        raise FeedRefused("feed_mismatch", f"series {one['seriesID']!r}, not {config['series_id']}")
    points, periods = [], set()
    years = {str(as_of.year - 1), str(as_of.year)}
    for number, entry in enumerate(one["data"]):
        if not isinstance(entry, dict) or not BLS_DATA_REQUIRED <= set(entry) <= BLS_DATA_REQUIRED | BLS_DATA_OPTIONAL:
            raise FeedRefused("feed_malformed", f"value {number} has {sorted(BLS_DATA_REQUIRED)}, and maybe latest")
        year, month = entry["year"], entry["period"]
        if not (isinstance(year, str) and _YEAR.fullmatch(year)) or not (
            isinstance(month, str) and _BLS_PERIOD.fullmatch(month)
        ):
            raise FeedRefused("feed_value_malformed", f"value {number}: year {year!r}, period {month!r}")
        if year not in years:
            raise FeedRefused("feed_mismatch", f"value {number}: year {year} was not asked for")
        if month == BLS_ANNUAL or entry["value"] == BLS_MISSING:
            continue
        period = f"{year}-{month[1:]}"
        if period in periods:
            raise FeedRefused("feed_mismatch", f"the month {period} is listed twice")
        periods.add(period)
        if period_end(period) > as_of:
            raise FeedRefused("feed_mismatch", f"value {number}: {period} has not ended on {as_of}")
        points.append(
            IndexPoint(
                series_id=config["series_id"],
                geography=config["geography"],
                category=config["category"],
                base=config["base"],
                period=period,
                value=_value(entry["value"], f"value {number}"),
                vintage_date=as_of,
                source_snapshot_hash=digest,
                source_key=feed.key,
            )
        )
    if not points:
        raise FeedRefused("feed_empty", "no monthly value")
    return points


# ------------------------------------------------------------------ parsing

_ADAPTERS = {"ecb": _ecb, "h10": _h10, "fred": _fred, "bls": _bls}


def parse(feed: FeedSource, raw: bytes, *, as_of: date, retrieved_at: datetime, url: str) -> Snapshot:
    """``raw``, ``feed``'s answer for ``as_of``, as an observation snapshot: the
    source version it is registered as (trust tier ``unverified``, the registry's
    licence class, retrieved at ``retrieved_at`` from ``url``), and every observation,
    each carrying the payload's hash. Raises :class:`FeedRefused` (or the money
    engine's :class:`.money.MoneyRefused` for a value the observation contract
    refuses) on any broken rule: nothing is half-read."""
    if not isinstance(raw, bytes):
        raise TypeError("a response is read from its bytes")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise FeedRefused("response_too_large", f"{len(raw)} bytes")
    digest = payload_hash(feed, raw)
    observations = _ADAPTERS[feed.adapter](feed, raw, as_of, digest)
    rates = tuple(o for o in observations if isinstance(o, FXRate))
    points = tuple(o for o in observations if isinstance(o, IndexPoint))
    snapshot = Snapshot(
        snapshot_hash=digest,
        label=f"{feed.provider} feed {feed.key}, as known on {as_of.isoformat()}",
        synthetic=False,
        source=MappingProxyType(
            {
                "source_key": feed.key,
                "provider": feed.provider,
                "dataset": feed.dataset,
                "url": url,
                "license_class": feed.license_class,
                # A fetched source is never trusted above unverified by its fetch: a
                # person raises it (spec, section 6.1).
                "trust_tier": TrustTier.UNVERIFIED.value,
                "retrieved_at": retrieved_at,
                "schema_version": feed.schema_version,
            }
        ),
        holidays=MappingProxyType({}),
        fx_rates=rates,
        index_points=points,
    )
    # The books check for a day or a month held twice before anything reads them.
    snapshot.fx_book()
    snapshot.index_book()
    return snapshot


__all__ = [
    "BLOCKED",
    "BLOCKING",
    "COST_INDEX",
    "DOWNGRADING",
    "EVIDENCE_PREFIX",
    "FEED_REFUSALS",
    "FRESH",
    "FRESHNESS_SLA_DAYS",
    "FX",
    "MAX_RESPONSE_BYTES",
    "MISSING",
    "NORMALISATION",
    "REFERENCE_RATE_LABEL",
    "REGISTRY",
    "STALE",
    "STATES",
    "FeedRefused",
    "FeedRequest",
    "FeedSource",
    "ecb_fixing_time",
    "feed_reference",
    "freshness_state",
    "h10_noon",
    "parse",
    "payload_hash",
    "referenced_keys",
    "request_for",
    "source",
]
