"""Economic Exposure, MVP step 10: the live-feed adapters, the fetch, the snapshot
store, freshness, the production receipt's authority rule and the data-health route
(``docs/economics/spec-v1.md``, section 28).

Every answer here is a FIXTURE (``tests/fixtures/economics_feeds``), and nothing
reaches a real host: a socket guard refuses every connection and every name lookup
that is not loopback, for every test in this module, and a test drives the real
outbound transport into it. The fixtures are format-faithful, NOT recorded
responses; replace each with a recording (owner). Each adapter has a structure test
that pins the format a fixture is written in, so a recording that differs fails
there, loudly. The value tests read each fixture's own values with a reader of their
own and compare the adapter's output against them, so a recording needs no edit to
the tests.
"""

from __future__ import annotations

import csv
import dataclasses
import io
import ipaddress
import json
import os
import socket
import subprocess
import sys
import textwrap
import uuid
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings
from mythos_core import exposure_receipt as core
from rest_framework.test import APIClient

from assurance.economics import builder, feeds, receipt_service, snapshots, validity_service
from assurance.economics.engine import feeds as engine
from assurance.economics.engine import grade as g
from assurance.economics.engine import scenario_simulation as ss
from assurance.economics.engine.cost_index import IndexSelector
from assurance.economics.models import (
    CausalEffect,
    CostIndexObservation,
    CustomerParameterSet,
    EconomicsRefused,
    EconomicsRewriteRefused,
    EffectFinding,
    FinancialExposureReceipt,
    FinancialParameter,
    FinancialScenario,
    FinancialSource,
    FinancialSourceFetch,
    FinancialSourceTrustRaise,
    FXObservation,
    LossComponent,
    LossEvent,
    ScenarioBuild,
)
from assurance.models import Asset, Deployment, Finding
from tests.test_economics_scenarios import _entry
from tests.test_economics_validity_card import _raw, _signer, simulated

pytestmark = pytest.mark.django_db
User = get_user_model()

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures" / "economics_feeds"
SPEC = REPO / "docs" / "economics" / "spec-v1.md"
#: The first line of a format-faithful fixture; a recording has none.
LABEL = b"# format-faithful, NOT a recorded response; replace with a recording (owner)"
NOW = datetime(2026, 10, 13, 18, 0, tzinfo=timezone.utc)
TODAY = NOW.date()
FRED_KEY = "test-fred-key-not-a-real-key-0001"
BLS_KEY = "test-bls-key-not-a-real-key-0002"
LIVE = {"ECONOMICS_LIVE_FEEDS_ENABLED": True, "ECONOMICS_FRED_API_KEY": FRED_KEY, "ECONOMICS_BLS_API_KEY": BLS_KEY}
ECB, H10, FRED, PPI, AHE = (
    "ecb-eur-reference-rates", "fed-h10-daily-rates", "fred-cpiaucsl", "bls-ppi-final-demand", "bls-ahe-total-private",
)
FILES = {
    ECB: "ecb-eur-reference-rates.csv",
    H10: "fed-h10-daily-rates.csv",
    FRED: "fred-cpiaucsl-2026-10-13.json",
    PPI: "bls-ppi-final-demand.json",
    AHE: "bls-ahe-total-private.json",
}
FRED_EARLIER = "fred-cpiaucsl-2026-06-30.json"


def fixture(name: str) -> bytes:
    """A fixture's bytes as the provider would answer: the format-faithful note on
    its first line, where there is one, taken off. A recording is read as it is."""
    raw = (FIXTURES / name).read_bytes()
    first, newline, rest = raw.partition(b"\n")
    return rest if newline and first.rstrip(b"\r") == LABEL else raw


def faithful(name: str) -> bool:
    return (FIXTURES / name).read_bytes().startswith(LABEL)


# ------------------------------------------------------------- no network


class NetworkRefused(OSError):
    """What the socket guard raises for anything that is not loopback."""


def _loopback(host) -> bool:
    if host in (None, "localhost"):
        return True
    try:
        return ipaddress.ip_address(str(host).split("%")[0]).is_loopback
    except ValueError:
        return False


@pytest.fixture(autouse=True)
def guard(monkeypatch):
    """No test here reaches a real host: every connect and every name lookup that is
    not loopback is refused and listed."""
    attempts: list[str] = []
    connect, connect_ex, getaddrinfo = socket.socket.connect, socket.socket.connect_ex, socket.getaddrinfo

    def refused(host):
        attempts.append(str(host))
        return NetworkRefused(f"the socket guard refuses {host}")

    def guarded_connect(self, address):
        host = address[0] if isinstance(address, tuple) else None
        if self.family == getattr(socket, "AF_UNIX", object()) or _loopback(host):
            return connect(self, address)
        raise refused(host)

    def guarded_connect_ex(self, address):
        host = address[0] if isinstance(address, tuple) else None
        if self.family == getattr(socket, "AF_UNIX", object()) or _loopback(host):
            return connect_ex(self, address)
        raise refused(host)

    def guarded_getaddrinfo(host, *args, **kwargs):
        if _loopback(host):
            return getaddrinfo(host, *args, **kwargs)
        raise refused(host)

    monkeypatch.setattr(socket.socket, "connect", guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", guarded_connect_ex)
    monkeypatch.setattr(socket, "getaddrinfo", guarded_getaddrinfo)
    return attempts


class Answer:
    """A transport that answers every request with ``raw``, and keeps what it was
    asked: the request (never carrying the key) and the key it was handed."""

    def __init__(self, raw: bytes):
        self.raw = raw
        self.sent: list[tuple[engine.FeedRequest, str]] = []

    def send(self, request, key):
        self.sent.append((request, key))
        return self.raw


def _fetch(key, raw=None, *, as_of=None, now=NOW, transport=None):
    transport = transport or Answer(fixture(FILES[key]) if raw is None else raw)
    with override_settings(**LIVE):
        return feeds.fetch(key, as_of=as_of, transport=transport, now=now), transport


def _nothing_written():
    return (
        FinancialSource.objects.count(), FXObservation.objects.count(), CostIndexObservation.objects.count(),
    ) == (0, 0, 0)


@pytest.fixture
def reviewed(monkeypatch):
    """The registry with ``keys``' licence reviewed (``open``), as the owner's
    licensing review would record it: until then every feed is ``unreviewed``."""

    def review(*keys):
        registry = dict(engine.REGISTRY)
        for key in keys:
            registry[key] = dataclasses.replace(registry[key], license_class="open")
        monkeypatch.setattr(engine, "REGISTRY", MappingProxyType(registry))

    return review


# ====================================================================
# The structure each fixture is written in (a recording that differs fails here)
# ====================================================================

ECB_HEADER = [
    "KEY", "FREQ", "CURRENCY", "CURRENCY_DENOM", "EXR_TYPE", "EXR_SUFFIX", "TIME_PERIOD", "OBS_VALUE", "OBS_STATUS",
    "OBS_CONF", "OBS_PRE_BREAK", "OBS_COM", "TIME_FORMAT", "BREAKS", "COLLECTION", "COMPILING_ORG", "DISS_ORG",
    "DOM_SER_IDS", "PUBL_ECB", "PUBL_MU", "PUBL_PUBLIC", "UNIT_INDEX_BASE", "COMPILATION", "COVERAGE", "DECIMALS",
    "NAT_TITLE", "SOURCE_AGENCY", "SOURCE_PUB", "TITLE", "TITLE_COMPL", "UNIT", "UNIT_MULT",
]


def _rows(raw: bytes) -> list[list[str]]:
    return [row for row in csv.reader(io.StringIO(raw.decode("utf-8"), newline="")) if row]


def test_ecb_fixture_structure():
    """The ECB Data Portal's SDMX-CSV for EXR: its 32 columns in their documented
    order, one line per daily observation of a euro reference rate, ordered by
    series and date, every asked currency present."""
    rows = _rows(fixture(FILES[ECB]))
    assert rows[0] == ECB_HEADER
    at = {name: rows[0].index(name) for name in ECB_HEADER}
    keys = []
    for row in rows[1:]:
        assert len(row) == len(ECB_HEADER)
        assert row[at["KEY"]] == f"EXR.D.{row[at['CURRENCY']]}.EUR.SP00.A"
        assert (row[at["FREQ"]], row[at["CURRENCY_DENOM"]], row[at["EXR_TYPE"]], row[at["EXR_SUFFIX"]]) == (
            "D", "EUR", "SP00", "A")
        assert (row[at["OBS_STATUS"]], row[at["UNIT_MULT"]], row[at["TIME_FORMAT"]]) == ("A", "0", "P1D")
        assert row[at["TITLE_COMPL"]].startswith("ECB reference exchange rate, ")
        date.fromisoformat(row[at["TIME_PERIOD"]])
        keys.append((row[at["KEY"]], row[at["TIME_PERIOD"]]))
    assert keys == sorted(keys)
    assert {k.split(".")[2] for k, _ in keys} == set(engine.REGISTRY[ECB].config["currencies"])


def test_h10_fixture_structure():
    """The Federal Reserve DDP's CSV for the H.10 package: six labelled heading lines,
    then one line per business day; each series' unit and identifier as the registry
    names them, its multiplier 1, and ``ND`` the only value that is not a number."""
    rows = _rows(fixture(FILES[H10]))
    assert [row[0].strip() for row in rows[:6]] == list(engine.H10_HEADINGS)
    configured = engine.REGISTRY[H10].config["series"]
    mnemonics = rows[5][1:]
    assert set(mnemonics) == set(configured)
    for column, mnemonic in enumerate(mnemonics, start=1):
        assert rows[1][column] == configured[mnemonic][2]
        assert rows[2][column] == "1"
        assert rows[4][column] == f"H10/H10/{mnemonic}"
        # The convention is in the mnemonic: RXI$US_ is US dollars per unit.
        assert (configured[mnemonic][1] == "usd_per") == mnemonic.startswith("RXI$US_")
    for row in rows[6:]:
        assert len(row) == len(rows[0])
        date.fromisoformat(row[0])
        assert all(value == "ND" or Decimal(value) > 0 for value in row[1:])


def test_fred_fixture_structure():
    """FRED's ``series/observations`` JSON: its 13 fields, every observation's four,
    the real-time window pinned to one date throughout, a monthly series, and ``.``
    the only value that is not a number."""
    for name in (FILES[FRED], FRED_EARLIER):
        document = json.loads(fixture(name))
        assert set(document) == engine.FRED_FIELDS
        assert document["realtime_start"] == document["realtime_end"]
        assert (document["units"], document["file_type"], document["output_type"], document["offset"]) == (
            "lin", "json", 1, 0)
        assert document["count"] == len(document["observations"]) > 0
        for entry in document["observations"]:
            assert set(entry) == engine.FRED_OBSERVATION_FIELDS
            assert entry["realtime_start"] == entry["realtime_end"] == document["realtime_start"]
            assert date.fromisoformat(entry["date"]).day == 1
            assert entry["value"] == "." or Decimal(entry["value"]) > 0


def test_bls_fixture_structure():
    """The BLS Public Data API's ``timeseries/data`` JSON (v1 and v2 answer in it):
    status, responseTime, message and Results; one series, the one asked; each
    value's year, period, period name, value and footnotes, and ``latest`` on the
    newest only."""
    for key in (PPI, AHE):
        document = json.loads(fixture(FILES[key]))
        assert set(document) == engine.BLS_FIELDS and document["status"] == engine.BLS_SUCCEEDED
        assert isinstance(document["responseTime"], int) and isinstance(document["message"], list)
        (series,) = document["Results"]["series"]
        assert set(series) == engine.BLS_SERIES_FIELDS
        assert series["seriesID"] == engine.REGISTRY[key].config["series_id"]
        for number, entry in enumerate(series["data"]):
            assert engine.BLS_DATA_REQUIRED <= set(entry) <= engine.BLS_DATA_REQUIRED | engine.BLS_DATA_OPTIONAL
            assert ("latest" in entry) == (number == 0)
            assert entry["period"][0] == "M" and entry["year"].isdigit()


def test_every_fixture_is_named_in_the_readme_with_its_status():
    readme = (FIXTURES / "README.md").read_text(encoding="utf-8")
    for path in sorted(FIXTURES.iterdir()):
        if path.name == "README.md":
            continue
        line = next(row for row in readme.splitlines() if f"`{path.name}`" in row)
        if faithful(path.name):
            assert "format-faithful, NOT a recorded response; replace with a recording (owner)" in line


# ====================================================================
# Each fixture parses to its known values
# ====================================================================


def _parse(key, raw=None, as_of=TODAY):
    feed = engine.REGISTRY[key]
    request = engine.request_for(feed, as_of=as_of, explicit=False, today=as_of)
    return engine.parse(
        feed, fixture(FILES[key]) if raw is None else raw, as_of=as_of, retrieved_at=NOW, url=request.recorded_url
    )


def test_the_ecb_answer_parses_to_its_values():
    rows = _rows(fixture(FILES[ECB]))
    at = {name: rows[0].index(name) for name in ECB_HEADER}
    expected = {
        (row[at["CURRENCY"]], date.fromisoformat(row[at["TIME_PERIOD"]])): Decimal(row[at["OBS_VALUE"]])
        for row in rows[1:]
    }
    snapshot = _parse(ECB)
    got = {(rate.quote, rate.effective_date): rate.rate for rate in snapshot.fx_rates}
    assert got == expected
    for rate in snapshot.fx_rates:
        # 1 EUR = rate <currency>: an informational average, never a price dealt at.
        assert (rate.base, rate.rate_type, rate.provider) == ("EUR", "reference", "ECB")
        assert rate.observed_at == engine.ecb_fixing_time(rate.effective_date)
        assert rate.source_snapshot_hash == snapshot.snapshot_hash
    assert engine.REFERENCE_RATE_LABEL in snapshot.source["dataset"]
    assert engine.REFERENCE_RATE_LABEL == "informational average, not a transaction price"
    assert snapshot.source["trust_tier"] == "unverified" and snapshot.source["license_class"] == "unreviewed"
    assert engine.ecb_fixing_time(date(2026, 10, 13)).isoformat() == "2026-10-13T14:15:00+02:00"
    assert engine.ecb_fixing_time(date(2026, 12, 1)).isoformat() == "2026-12-01T14:15:00+01:00"
    if faithful(FILES[ECB]):
        assert got[("USD", date(2026, 10, 13))] == Decimal("1.1768") and len(got) == 30


def test_the_h10_answer_parses_with_its_quotation_conventions():
    """H.10 quotes the euro and the pound in US dollars per unit and the yen per US
    dollar: each is stored as quoted, ``1 base = rate quote``, never inverted, and
    the convention is the series' own."""
    rows = _rows(fixture(FILES[H10]))
    configured = engine.REGISTRY[H10].config["series"]
    expected = {}
    for row in rows[6:]:
        for column, mnemonic in enumerate(rows[5][1:], start=1):
            if row[column] == "ND":
                continue
            currency, convention, _unit = configured[mnemonic]
            pair = ("USD", currency) if convention == "per_usd" else (currency, "USD")
            expected[(*pair, date.fromisoformat(row[0]))] = Decimal(row[column])
    snapshot = _parse(H10)
    got = {(r.base, r.quote, r.effective_date): r.rate for r in snapshot.fx_rates}
    assert got == expected
    assert {(r.base, r.quote) for r in snapshot.fx_rates} == {("EUR", "USD"), ("USD", "JPY"), ("GBP", "USD")}
    assert all(r.observed_at == engine.h10_noon(r.effective_date) and r.provider == "FRB-H10" for r in snapshot.fx_rates)
    assert engine.h10_noon(date(2026, 10, 9)).isoformat() == "2026-10-09T12:00:00-04:00"
    assert engine.h10_noon(date(2026, 12, 9)).isoformat() == "2026-12-09T12:00:00-05:00"
    if faithful(FILES[H10]):
        assert got[("USD", "JPY", date(2026, 9, 28))] == Decimal("147.32")
        assert got[("EUR", "USD", date(2026, 9, 28))] == Decimal("1.1695")
    # A day with no rate (ND) is skipped, never read as zero.
    raw = fixture(FILES[H10]).replace(f"{rows[6][0]},{rows[6][1]},".encode(), f"{rows[6][0]},ND,".encode(), 1)
    assert ("EUR", "USD", date.fromisoformat(rows[6][0])) not in {
        (r.base, r.quote, r.effective_date) for r in _parse(H10, raw).fx_rates
    }


def test_the_fred_answer_parses_to_its_values_as_known_on_its_date():
    document = json.loads(fixture(FILES[FRED]))
    expected = {e["date"][:7]: Decimal(e["value"]) for e in document["observations"] if e["value"] != "."}
    snapshot = _parse(FRED, as_of=date.fromisoformat(document["realtime_start"]))
    assert {p.period: p.value for p in snapshot.index_points} == expected
    config = engine.REGISTRY[FRED].config
    for point in snapshot.index_points:
        assert (point.series_id, point.geography, point.base) == ("CPIAUCSL", "US", config["base"])
        assert point.vintage_date == date.fromisoformat(document["realtime_start"])
    if faithful(FILES[FRED]):
        assert expected["2026-08"] == Decimal("328.519") and "2025-10" not in expected  # "." is no value


@pytest.mark.parametrize("key", [PPI, AHE])
def test_a_bls_answer_parses_to_its_values(key):
    document = json.loads(fixture(FILES[key]))
    (series,) = document["Results"]["series"]
    expected = {
        f"{e['year']}-{e['period'][1:]}": Decimal(e["value"])
        for e in series["data"]
        if e["period"] != "M13" and e["value"] != "-"
    }
    snapshot = _parse(key)
    assert {p.period: p.value for p in snapshot.index_points} == expected
    assert all(p.vintage_date == TODAY and p.series_id == series["seriesID"] for p in snapshot.index_points)
    if faithful(FILES[key]):
        assert expected["2026-08"] == (Decimal("151.8") if key == PPI else Decimal("37.42"))


def test_bls_annual_averages_and_missing_values_are_skipped():
    document = json.loads(fixture(FILES[PPI]))
    data = document["Results"]["series"][0]["data"]
    data.append({"year": "2025", "period": "M13", "periodName": "Annual", "value": "148.0", "footnotes": [{}]})
    data[1]["value"] = "-"
    periods = {p.period for p in _parse(PPI, json.dumps(document).encode()).index_points}
    assert f"{data[1]['year']}-{data[1]['period'][1:]}" not in periods
    assert not any(period.endswith("-13") for period in periods)


# ====================================================================
# Requests: the key goes only where its provider reads it
# ====================================================================


def test_the_key_goes_into_the_request_and_nowhere_it_is_recorded():
    outcome, transport = _fetch(FRED)
    ((request, key),) = transport.sent
    assert key == FRED_KEY and (request.key_in, request.key_name) == ("query", "api_key")
    assert ("realtime_start", "2026-10-13") in request.params and ("realtime_end", "2026-10-13") in request.params
    assert FRED_KEY not in request.recorded_url and "api_key" not in request.recorded_url
    assert outcome.version.url == request.recorded_url
    outcome, transport = _fetch(PPI)
    ((request, key),) = transport.sent
    assert key == BLS_KEY and request.method == "POST" and (request.key_in, request.key_name) == (
        "body", "registrationkey")
    assert "registrationkey" not in request.body
    for row in FinancialSource.objects.all():
        assert FRED_KEY not in json.dumps(row.url) and BLS_KEY not in json.dumps(row.url)


def test_the_outbound_transport_puts_the_key_in_the_request_only(monkeypatch):
    """The real transport, its two calls to safety.outbound captured: the FRED key as
    the ``api_key`` query parameter, the BLS key as ``registrationkey`` in the body;
    each also withheld from any error; no redirect followed (safety.outbound); no
    proxy unless ECONOMICS_FEED_PROXY names one."""
    calls = []

    class Answered:
        status_code = 200

        def iter_content(self, _size):
            yield b"{}"

        def close(self):
            return None

    def capture(method):
        def send(url, **kwargs):
            calls.append((method, url, kwargs))
            return Answered()
        return send

    monkeypatch.setattr(feeds.outbound, "get", capture("GET"))
    monkeypatch.setattr(feeds.outbound, "post", capture("POST"))
    fred = engine.request_for(engine.REGISTRY[FRED], as_of=TODAY, explicit=False, today=TODAY)
    bls = engine.request_for(engine.REGISTRY[PPI], as_of=TODAY, explicit=False, today=TODAY)
    with override_settings(ECONOMICS_FEED_PROXY=""):
        assert feeds.OutboundTransport().send(fred, FRED_KEY) == b"{}"
        assert feeds.OutboundTransport().send(bls, BLS_KEY) == b"{}"
    (get_method, get_url, get_kwargs), (post_method, _post_url, post_kwargs) = calls
    assert (get_method, post_method) == ("GET", "POST")
    assert ("api_key", FRED_KEY) in get_kwargs["params"] and FRED_KEY not in get_url
    assert post_kwargs["json"]["registrationkey"] == BLS_KEY and post_kwargs["json"]["seriesid"] == ["WPUFD4"]
    assert FRED_KEY in get_kwargs["also_withhold"] and BLS_KEY in post_kwargs["also_withhold"]
    assert "proxies" not in get_kwargs and get_kwargs["timeout"] == feeds.TIMEOUT
    with override_settings(ECONOMICS_FEED_PROXY="http://egress.internal:3128"):
        feeds.OutboundTransport().send(fred, FRED_KEY)
    assert calls[-1][2]["proxies"] == {"http": "http://egress.internal:3128", "https": "http://egress.internal:3128"}


# ====================================================================
# Fails safe: a malformed or partial answer is refused, and nothing half-loads
# ====================================================================


def _cut(raw: bytes) -> bytes:
    """A JSON answer cut off two thirds of the way through."""
    return raw[: len(raw) * 2 // 3]


def _cut_line(raw: bytes) -> bytes:
    """A CSV answer whose last line is cut off after its second column."""
    body = raw.rstrip(b"\r\n")
    start = body.rfind(b"\n") + 1
    last = body[start:]
    return body[:start] + last[: last.index(b",", last.index(b",") + 1)]


def _json_edit(key, edit):
    document = json.loads(fixture(FILES[key]))
    edit(document)
    return json.dumps(document).encode()


def _ecb_lines(drop_currency=None, value=None):
    rows = _rows(fixture(FILES[ECB]))
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\r\n")
    writer.writerow(rows[0])
    for number, row in enumerate(rows[1:]):
        if drop_currency and row[2] == drop_currency:
            continue
        if value is not None and number == 0:
            row = list(row)
            row[7] = value
        writer.writerow(row)
    return out.getvalue().encode()


MALFORMED = {
    "ecb-cut-short": (ECB, lambda: _cut_line(fixture(FILES[ECB])), "feed_partial"),
    "ecb-a-currency-missing": (ECB, lambda: _ecb_lines(drop_currency="JPY"), "feed_partial"),
    "ecb-a-value-not-a-decimal": (ECB, lambda: _ecb_lines(value="NaN"), "feed_value_malformed"),
    "ecb-not-utf8": (ECB, lambda: b"\xff\xfe" + fixture(FILES[ECB]), "feed_malformed"),
    "ecb-a-day-twice": (
        ECB, lambda: fixture(FILES[ECB]) + fixture(FILES[ECB]).split(b"\r\n")[1] + b"\r\n", "observation_duplicate"
    ),
    "h10-a-unit-reversed": (
        H10, lambda: fixture(FILES[H10]).replace(b'"USD:_Per_EUR"', b'"EUR:_Per_USD"'), "feed_mismatch"
    ),
    "h10-cut-short": (H10, lambda: _cut_line(fixture(FILES[H10])), "feed_partial"),
    "h10-a-value-not-a-decimal": (
        H10, lambda: fixture(FILES[H10]).replace(b"\r\n2", b"\r\nx2", 1), "feed_value_malformed"
    ),
    "fred-count-says-more": (FRED, lambda: _json_edit(FRED, lambda d: d.update(count=d["count"] + 1)), "feed_partial"),
    "fred-another-window": (
        FRED, lambda: _json_edit(FRED, lambda d: d.update(realtime_start="2026-10-12", realtime_end="2026-10-12")),
        "feed_mismatch",
    ),
    "fred-an-error": (
        FRED, lambda: b'{"error_code": 400, "error_message": "Bad Request."}', "feed_provider_error"
    ),
    "fred-cut-short": (FRED, lambda: _cut(fixture(FILES[FRED])), "feed_malformed"),
    "fred-a-number-not-a-string": (
        FRED, lambda: _json_edit(FRED, lambda d: d["observations"][0].update(value=3)), "feed_value_malformed"
    ),
    "fred-a-float": (FRED, lambda: _json_edit(FRED, lambda d: d.update(limit=1.5)), "feed_malformed"),
    "bls-not-processed": (
        PPI, lambda: _json_edit(PPI, lambda d: d.update(status="REQUEST_NOT_PROCESSED")), "feed_provider_error"
    ),
    "bls-no-series": (PPI, lambda: _json_edit(PPI, lambda d: d["Results"].update(series=[])), "feed_partial"),
    "bls-another-series": (
        PPI, lambda: _json_edit(PPI, lambda d: d["Results"]["series"][0].update(seriesID="WPU000000")),
        "feed_mismatch",
    ),
    "bls-a-value-not-a-decimal": (
        PPI, lambda: _json_edit(PPI, lambda d: d["Results"]["series"][0]["data"][3].update(value="1,5")),
        "feed_value_malformed",
    ),
    "bls-cut-short": (PPI, lambda: _cut(fixture(FILES[PPI])), "feed_malformed"),
}


@pytest.mark.parametrize("case", sorted(MALFORMED))
def test_a_malformed_or_partial_answer_is_refused_and_nothing_half_loads(case):
    key, make, code = MALFORMED[case]
    outcome, _transport = _fetch(key, make())
    assert (outcome.outcome, outcome.code) == ("refused", code), outcome
    assert _nothing_written(), "a refused answer wrote a source version or an observation"
    (row,) = FinancialSourceFetch.objects.all()
    assert (row.source_key, row.outcome, row.code, row.source) == (key, "refused", code, None)


def test_a_float_in_a_json_answer_is_refused_as_malformed():
    with pytest.raises(engine.FeedRefused) as refused:
        _parse(FRED, b'{"count": 1.5}')
    assert refused.value.code == "feed_malformed"


def test_an_answer_too_large_is_not_read():
    with pytest.raises(engine.FeedRefused) as refused:
        _parse(ECB, b"x" * (engine.MAX_RESPONSE_BYTES + 1))
    assert refused.value.code == "response_too_large"


# ====================================================================
# The snapshot store: append-only, a new version per new payload
# ====================================================================


def test_a_fetch_is_a_new_unverified_platform_wide_version_with_its_observations():
    outcome, _ = _fetch(ECB)
    assert outcome.outcome == "recorded" and outcome.code is None
    version = outcome.version
    assert (version.deployment, version.source_key, version.version) == (None, ECB, 1)
    assert (version.trust_tier, version.license_class, version.synthetic) == ("unverified", "unreviewed", False)
    assert version.snapshot_hash == outcome.payload_hash == engine.payload_hash(engine.REGISTRY[ECB], fixture(FILES[ECB]))
    assert version.retrieved_at == NOW and version.provider == "ECB"
    assert FXObservation.objects.filter(source=version).count() == outcome.observations == len(_parse(ECB).fx_rates)
    assert set(FXObservation.objects.values_list("source_snapshot_hash", flat=True)) == {version.snapshot_hash}
    (row,) = FinancialSourceFetch.objects.all()
    assert (row.outcome, row.source, row.payload_hash, row.as_of, row.code) == (
        "recorded", version, version.snapshot_hash, TODAY, "")
    # The fetch record is append-only, as every economics record is.
    with pytest.raises(EconomicsRewriteRefused):
        row.save()
    with pytest.raises(EconomicsRewriteRefused):
        FinancialSourceFetch.objects.all().delete()


def test_a_duplicate_answer_gives_no_new_version():
    first, _ = _fetch(ECB)
    again, _ = _fetch(ECB, now=NOW + timedelta(hours=2))
    assert (again.outcome, again.version) == ("unchanged", first.version)
    assert FinancialSource.objects.count() == 1 and FXObservation.objects.count() == first.observations
    assert list(FinancialSourceFetch.objects.order_by("id").values_list("outcome", "source")) == [
        ("recorded", first.version.pk), ("unchanged", first.version.pk)]


def test_a_changed_value_is_a_new_version_and_a_changed_timestamp_is_not():
    """BLS times every answer (``responseTime``), which the payload drops: the same
    values timed differently are one version, a changed value a new one. FRED's
    answer is re-serialised canonically: its key order and spacing are not a
    change, a value is, and so is another as-of date (another vintage)."""
    v1, _ = _fetch(PPI)
    retimed, _ = _fetch(PPI, _json_edit(PPI, lambda d: d.update(responseTime=d["responseTime"] + 857)))
    assert (retimed.outcome, retimed.version) == ("unchanged", v1.version)

    def bump(document):
        entry = document["Results"]["series"][0]["data"][0]
        entry["value"] = str(Decimal(entry["value"]) + Decimal("0.1"))

    revised, _ = _fetch(PPI, _json_edit(PPI, bump))
    assert (revised.outcome, revised.version.version) == ("recorded", 2)

    f1, _ = _fetch(FRED)
    document = json.loads(fixture(FILES[FRED]))
    respaced = json.dumps(dict(reversed(list(document.items()))), indent=7).encode()
    again, _ = _fetch(FRED, respaced)
    assert (again.outcome, again.version) == ("unchanged", f1.version)
    document["observations"][0]["value"] = str(Decimal(document["observations"][0]["value"]) + 1)
    changed, _ = _fetch(FRED, json.dumps(document).encode())
    assert (changed.outcome, changed.version.version) == ("recorded", 2)
    # A changed ECB rate is a new version; its bytes are hashed as they came.
    e1, _ = _fetch(ECB)
    raw = fixture(FILES[ECB])
    rows = _rows(raw)
    e2, _ = _fetch(ECB, raw.replace(f",{rows[1][7]},".encode(), b",0.99999,", 1))
    assert (e1.outcome, e2.outcome, e2.version.version) == ("recorded", "recorded", 2)


def test_what_each_adapter_normalises_is_written_down():
    assert set(engine.NORMALISATION) == {"ecb", "h10", "fred", "bls"}
    assert "responseTime" in engine.NORMALISATION["bls"]
    assert "pinned to the as-of date" in engine.NORMALISATION["fred"]


def test_alfred_vintages_reproduce_what_was_known_at_a_date():
    """FRED with its real-time window pinned to the as-of date: each fetch records
    the values as they were known that day. Read together, a run as of the earlier
    date reads the earlier vintage, a run as of the later date the later one, and
    nothing published after its date."""
    earlier_document = json.loads(fixture(FRED_EARLIER))
    later_document = json.loads(fixture(FILES[FRED]))
    earlier_date = date.fromisoformat(earlier_document["realtime_start"])
    later_date = date.fromisoformat(later_document["realtime_start"])
    old, _ = _fetch(FRED, fixture(FRED_EARLIER), as_of=earlier_date)
    new, _ = _fetch(FRED, fixture(FILES[FRED]), as_of=later_date)
    assert (old.outcome, new.outcome) == ("recorded", "recorded")
    book = snapshots.index_book([old.version, new.version], deployment=None)
    config = engine.REGISTRY[FRED].config
    selector = IndexSelector("CPIAUCSL", config["geography"], config["category"], config["base"], "USD")

    def values(document):
        return {e["date"][:7]: Decimal(e["value"]) for e in document["observations"] if e["value"] != "."}

    then, later = values(earlier_document), values(later_document)
    for period, value in then.items():
        assert book.value(selector, period, earlier_date).value == value
    for period, value in later.items():
        assert book.value(selector, period, later_date).value == value
    for period in set(later) - set(then):
        assert book.value(selector, period, earlier_date) is None  # not yet known then
    if faithful(FRED_EARLIER) and faithful(FILES[FRED]):
        assert then["2026-03"] != later["2026-03"]  # a revision between the two vintages


def test_bls_cannot_be_asked_what_was_known_earlier():
    outcome, transport = _fetch(PPI, as_of=TODAY - timedelta(days=1))
    assert (outcome.code, outcome.row, transport.sent) == ("as_of_unsupported", None, [])
    outcome, transport = _fetch(ECB, as_of=TODAY + timedelta(days=1))
    assert (outcome.code, outcome.row, transport.sent) == ("as_of_in_future", None, [])
    assert not FinancialSourceFetch.objects.exists() and _nothing_written()


# ====================================================================
# No key, no switch, no fetch
# ====================================================================


@pytest.mark.parametrize("key, setting", [(FRED, "ECONOMICS_FRED_API_KEY"), (PPI, "ECONOMICS_BLS_API_KEY"),
                                          (AHE, "ECONOMICS_BLS_API_KEY")])
def test_a_missing_key_refuses_and_does_nothing(key, setting, guard):
    transport = Answer(fixture(FILES[key]))
    for empty in ("", "   ", None):
        with override_settings(**{**LIVE, setting: empty}):
            outcome = feeds.fetch(key, transport=transport, now=NOW)
        assert (outcome.outcome, outcome.code, outcome.row) == ("refused", "source_key_missing", None)
    assert transport.sent == [] and guard == []
    assert not FinancialSourceFetch.objects.exists() and _nothing_written()
    assert engine.REGISTRY[key].key_setting == setting


def test_live_fetching_is_off_unless_its_one_setting_is_true():
    transport = Answer(fixture(FILES[ECB]))
    for value in (False, None, "True", 1):
        with override_settings(**{**LIVE, "ECONOMICS_LIVE_FEEDS_ENABLED": value}):
            outcome = feeds.fetch(ECB, transport=transport, now=NOW)
        assert outcome.code == "live_feeds_disabled"
    with override_settings(ECONOMICS_FRED_API_KEY=FRED_KEY):
        assert feeds.fetch(ECB, transport=transport, now=NOW).code == "live_feeds_disabled"
    assert transport.sent == [] and not FinancialSourceFetch.objects.exists() and _nothing_written()
    # ECB and H.10 need no key: the switch alone.
    assert engine.REGISTRY[ECB].key_setting == engine.REGISTRY[H10].key_setting == ""
    assert feeds.fetch("no-such-source", transport=transport).code == "source_unrecognised"


def test_the_command_fetches_and_says_what_came_of_it(monkeypatch, capsys):
    class Fixed(feeds.OutboundTransport):
        def send(self, request, key):
            return fixture(FILES[FRED])

    monkeypatch.setattr(feeds, "OutboundTransport", Fixed)
    monkeypatch.setattr(feeds.timezone, "now", lambda: NOW)
    out = io.StringIO()
    with override_settings(**LIVE):
        call_command("fetch_financial_source", FRED, stdout=out)
        call_command("fetch_financial_source", FRED, stdout=out)
    said = out.getvalue()
    assert f"{FRED}: recorded, version 1 (unverified)" in said and f"{FRED}: unchanged, version 1" in said
    assert FRED_KEY not in said + capsys.readouterr().out
    with override_settings(**{**LIVE, "ECONOMICS_FRED_API_KEY": ""}):
        with pytest.raises(CommandError, match="source_key_missing.*nothing was written"):
            call_command("fetch_financial_source", FRED, stdout=io.StringIO())
    with pytest.raises(CommandError, match="not YYYY-MM-DD"):
        call_command("fetch_financial_source", FRED, "--as-of", "13/10/2026", stdout=io.StringIO())
    listed = io.StringIO()
    call_command("fetch_financial_source", "--list", stdout=listed)
    assert all(key in listed.getvalue() for key in engine.REGISTRY)


def test_a_fetch_failure_is_recorded_by_its_code_alone():
    class Down:
        def send(self, request, key):
            raise feeds.TransportFailed("fetch_failed")

    outcome, _ = _fetch(FRED, transport=Down())
    assert (outcome.code, outcome.row.outcome, outcome.row.code) == ("fetch_failed", "refused", "fetch_failed")
    assert _nothing_written()


# ====================================================================
# The socket guard, and nothing at import
# ====================================================================


def test_the_socket_guard_refuses_anything_but_loopback(guard):
    with pytest.raises(NetworkRefused):
        socket.create_connection(("192.0.2.10", 443), timeout=1)
    with pytest.raises(NetworkRefused):
        socket.getaddrinfo("api.stlouisfed.org", 443)
    assert guard == ["192.0.2.10", "api.stlouisfed.org"]


def test_the_real_transport_reaches_no_real_host(guard):
    """With the keys set and live fetching on, the real outbound transport tries the
    provider's host -- and the guard refuses it: the fetch is ``fetch_failed``,
    recorded by its code, nothing else is written, and nothing left the machine."""
    with override_settings(**LIVE, ECONOMICS_FEED_PROXY=""):
        outcome = feeds.fetch(FRED, now=NOW)
    assert (outcome.code, outcome.row.code) == ("fetch_failed", "fetch_failed")
    assert guard and set(guard) <= {"api.stlouisfed.org"}
    assert _nothing_written()


def test_importing_the_feed_modules_reaches_no_host():
    """A fresh interpreter whose sockets refuse to connect or look a name up: Django
    loads, and the feed modules, the data-health route and the fetch command import,
    with no attempt at the network."""
    script = textwrap.dedent(
        """
        import socket
        tried = []
        def refuse(*args, **kwargs):
            tried.append(repr(args[:2]))
            raise OSError("no network at import")
        socket.socket.connect = refuse
        socket.socket.connect_ex = refuse
        socket.getaddrinfo = refuse
        socket.create_connection = refuse
        import django
        django.setup()
        from django.urls import reverse
        import assurance.economics.engine.feeds, assurance.economics.feeds, assurance.economics.health_api
        import assurance.management.commands.fetch_financial_source
        reverse("deployment-economics-data-health", kwargs={"uuid": "11111111-2222-4333-8444-555555555555"})
        assert tried == [], tried
        print("no network")
        """
    )
    env = dict(os.environ, DJANGO_SECRET_KEY=os.environ.get("DJANGO_SECRET_KEY", "ci-secret-key-not-used-outside-ci"))
    result = subprocess.run([sys.executable, "-c", script], cwd=REPO, env=env, capture_output=True, text=True,
                            timeout=120, check=False)
    assert result.returncode == 0 and result.stdout.strip() == "no network", result.stderr[-3000:]


# ====================================================================
# Freshness: one table, and each transition
# ====================================================================


def test_one_table_gives_every_source_its_sla():
    assert dict(engine.FRESHNESS_SLA_DAYS) == {
        ("ECB", "daily"): 3, ("FRB-H10", "weekly"): 10, ("FRED", "monthly"): 45, ("BLS", "monthly"): 45,
    }
    assert {key: feed.sla_days for key, feed in engine.REGISTRY.items()} == {
        ECB: 3, H10: 10, FRED: 45, PPI: 45, AHE: 45,
    }
    assert all(feed.license_class == "unreviewed" for feed in engine.REGISTRY.values())


@pytest.mark.parametrize("age, state", [(None, "missing"), (0, "fresh"), (3, "fresh"), (4, "stale"), (6, "stale"),
                                        (7, "blocked"), (40, "blocked")])
def test_the_freshness_states(age, state):
    assert engine.freshness_state(age, 3) == state


@pytest.fixture
def people():
    return {
        "admin": User.objects.create_user(username="ada", password="x", role="admin"),
        "second": User.objects.create_user(username="bea", password="x", role="admin"),
        "analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
        "owner": User.objects.create_user(username="vic", password="x", role="viewer"),
        "stranger": User.objects.create_user(username="sam", password="x", role="viewer"),
    }


@pytest.fixture
def deployment(people):
    return Deployment.objects.create(name="payments-agent", owner=people["owner"])


@pytest.fixture
def staging(people):
    return Deployment.objects.create(name="payments-agent-staging", owner=people["owner"], environment="staging")


def test_each_freshness_transition_of_a_fetched_source(reviewed, staging, deployment):
    """The ECB rates fetched on 13 Oct (data through that day), read by a staging
    run (the gate takes a reviewed, unverified version there): fresh to its SLA of 3
    days, stale past it, blocked past twice it. A production run may not use an
    unverified version at all: missing, with the gate's reason."""
    reviewed(ECB)
    _fetch(ECB)
    through = max(FXObservation.objects.values_list("effective_date", flat=True))
    for days, state in ((0, "fresh"), (3, "fresh"), (4, "stale"), (6, "stale"), (7, "blocked"), (30, "blocked")):
        seen = feeds.source_state(ECB, deployment=staging, as_of=through + timedelta(days=days))
        assert (seen["state"], seen["age_days"], seen["sla_days"]) == (state, days, 3), days
        assert seen["used_version"]["version"] == 1 and seen["gate"] is None
    production = feeds.source_state(ECB, deployment=deployment, as_of=through)
    assert (production["state"], production["used_version"], production["gate"]) == (
        "missing", None, "source_unverified")
    assert feeds.source_state("not-a-feed", deployment=staging, as_of=through)["state"] == "missing"
    # Before the source's first observation there is nothing to age: missing.
    assert feeds.source_state(ECB, deployment=staging, as_of=date(2020, 1, 1))["state"] == "missing"


def test_an_unreviewed_licence_leaves_a_source_unusable_everywhere(staging):
    _fetch(ECB)
    seen = feeds.source_state(ECB, deployment=staging, as_of=TODAY)
    assert (seen["state"], seen["gate"]) == ("missing", "unreviewed_license")


def test_a_newer_version_waiting_for_a_raise_is_not_used(reviewed, deployment, people):
    """The conservative default: a run uses the latest version the gate passes; a
    newer fetch, unverified, waits for a raise and is never inherited a tier."""
    reviewed(ECB)
    first, _ = _fetch(ECB)
    raised = FinancialSourceTrustRaise.request(first.version, "benchmark", "the official publisher",
                                               by=people["admin"], channel="api")
    raw = fixture(FILES[ECB])
    newer, _ = _fetch(ECB, raw.replace(f",{_rows(raw)[1][7]},".encode(), b",0.99999,", 1), now=NOW + timedelta(hours=1))
    assert newer.version.trust_tier == "unverified"  # never inherits the raised tier
    seen = feeds.source_state(ECB, deployment=deployment, as_of=TODAY)
    assert seen["used_version"]["version"] == raised.to_version.version == 2
    assert seen["latest_version"]["version"] == 3 and seen["gate"] == "source_unverified"


# ====================================================================
# The card and the grade: a stale source lowers every figure it feeds
# ====================================================================

GAMMA = {"id": "gamma", "version": 1, "params": {"shape": "4", "scale": "25000"}}
POISSON = {"id": "poisson", "version": 1, "params": {"rate": "2"}}


def _scenario(deployment, author, *, as_of, evidence, title="Cross-customer exposure"):
    """A scenario version as rows (as ``tests/test_economics_validity_card.py``
    builds one): a lump-sum regulatory figure whose evidence is ``evidence`` and a
    notification cost, at ``as_of``. SYNTHETIC / ILLUSTRATIVE."""
    variables = {
        "notification_unit_cost": _entry("money_per_unit", "2"),
        "notification_fixed_cost": _entry("money", "40000"),
    }
    pset = CustomerParameterSet.record(deployment, "bank_prod_2026q4", {"variables": variables}, author=author)
    scenario = FinancialScenario.objects.create(deployment=deployment, title=title, author=author,
                                                system_fingerprint="ab" * 32)

    def parameter(name, unit, low, base, high, source, ref, distribution=None):
        return FinancialParameter.objects.create(
            scenario=scenario, name=name, unit=unit, source_type=source, currency="USD" if unit == "money" else "",
            low=low, base=base, high=high, evidence_ref=ref, effective_date=date(2026, 9, 1), distribution=distribution,
        )

    affected = parameter("exposure.affected_customers", "count", "20000", "50000", "120000", "EXPERT_ESTIMATE",
                         "SYNTHETIC / ILLUSTRATIVE: made up")
    amount = parameter("exposure.regulatory_response_cost", "money", "0", "100000", "500000", "OFFICIAL_PUBLIC",
                       evidence, GAMMA)
    parameter(ss.FREQUENCY_PARAMETER, "count", "1", "2", "4", "INDUSTRY_BENCHMARK", "SYNTHETIC: made up", POISSON)
    rows = {row.name: row for row in pset.parameter_rows()}
    event = LossEvent.objects.create(scenario=scenario, event_key="ev-exposure", currency="USD",
                                     trigger="cross_customer_disclosure", business_process="customer_service")
    LossComponent.objects.create(
        loss_event=event, component_key="notification", family="notification", formula_id="per_affected_plus_fixed",
        formula_version=1, as_of=as_of,
        cited_parameters={"affected": str(affected.uuid), "unit_cost": str(rows["notification_unit_cost"].uuid),
                          "fixed_cost": str(rows["notification_fixed_cost"].uuid)},
    )
    LossComponent.objects.create(loss_event=event, component_key="regulatory", family="regulatory_compliance",
                                 formula_id="lump_sum", formula_version=1, as_of=as_of,
                                 cited_parameters={"amount": str(amount.uuid)})
    asset = Asset.objects.create(deployment=deployment, kind="agent", name="support-agent",
                                 identifier=f"agent://support-{uuid.uuid4().hex[:6]}")
    finding = Finding.objects.create(deployment=deployment, fingerprint=f"fp-{uuid.uuid4().hex[:8]}",
                                     finding_type="tenant_isolation_missing", title="tenant isolation", severity="high")
    effect = CausalEffect.objects.create(
        scenario=scenario, loss_event=event, effect_key="exposure", origin="hypothetical",
        effect_type="cross_customer_disclosure", asset=str(asset.uuid), business_process="customer_service",
        template_id="cross_customer_data_exposure", template_version=1,
        in_scope_of=[["cross_customer_data_exposure", 1]],
    )
    EffectFinding.objects.create(effect=effect, finding=str(finding.uuid), role="prerequisite")
    inputs = {"fixture": str(scenario.uuid), "label": "SYNTHETIC / ILLUSTRATIVE"}
    ScenarioBuild.objects.create(
        scenario=scenario, deployment=deployment, parameter_set=pset, build_digest=builder.build_digest(inputs),
        builder_version="test-fixture", grouping_version="test-fixture", pack="test-fixture", currency="USD",
        as_of=as_of, inputs=inputs,
    )
    return scenario


def _carded(deployment, people, *, as_of, evidence):
    result = simulated(_scenario(deployment, people["analyst"], as_of=as_of, evidence=evidence), draws=5_000)
    outcome = validity_service.issue_card(result)
    assert outcome.card is not None, (outcome.code, outcome.detail)
    return result, outcome.card


@pytest.fixture
def keys():
    receipt = Ed25519PrivateKey.generate()
    return {"receipt": receipt, "ring": core.receipt_keyring([_raw(receipt)], other_roles={})}


def _receipt(result, keys):
    return receipt_service.issue_receipt(result, signer=_signer(keys["receipt"]), keyring=keys["ring"])


FED_BY_ECB = f"financial-source:{ECB} the euro reference rates the figure is converted at"


def test_a_figure_resting_on_a_fresh_source_keeps_its_grade(reviewed, staging, people, keys):
    reviewed(ECB)
    _fetch(ECB)
    _, plain = _carded(staging, people, as_of=TODAY, evidence="a regulator's published schedule")
    other = Deployment.objects.create(name="second", owner=people["owner"], environment="staging")
    result, fed = _carded(other, people, as_of=TODAY, evidence=FED_BY_ECB)
    assert fed.confidence_grade == plain.confidence_grade
    freshness = fed.card["fields"]["data_freshness"]
    (source,) = freshness["sources"]
    assert (source["source_key"], source["state"], source["feeds"]) == (ECB, "fresh", ["exposure.regulatory_response_cost"])
    assert freshness["stale_sources"] == [] and freshness["claim"] == "current"
    assert fed.card["freshness"]["claim"] == "current"
    assert fed.card["issued"]["feed_sources"][ECB]["used_version"]["version"] == 1
    assert validity_service.reproduces(fed)
    # A staging run's receipt needs no more than the gate.
    issued = _receipt(result, keys)
    assert issued.code is None and issued.receipt is not None, (issued.code, issued.detail)


@pytest.mark.parametrize("days, state", [(5, "stale"), (12, "blocked")])
def test_a_stale_source_lowers_the_grade_one_step_for_every_figure_it_feeds(reviewed, staging, people, keys, days,
                                                                           state):
    reviewed(ECB)
    _fetch(ECB)
    through = max(FXObservation.objects.values_list("effective_date", flat=True))
    as_of = through + timedelta(days=days)
    _, plain = _carded(staging, people, as_of=as_of, evidence="a regulator's published schedule")
    other = Deployment.objects.create(name="second", owner=people["owner"], environment="staging")
    result, fed = _carded(other, people, as_of=as_of, evidence=FED_BY_ECB)
    grade = fed.card["fields"]["confidence_grade"]
    assert g.STALE_SOURCE in [d["rule"] for d in grade["downgrades"]]
    assert grade["stale_source_parameters"] == ["exposure.regulatory_response_cost"]
    ladder = ["A", "B", "C", "D"]
    assert fed.confidence_grade == ladder[min(ladder.index(plain.confidence_grade) + 1, 3)]
    freshness = fed.card["fields"]["data_freshness"]
    assert freshness["sources"][0]["state"] == state and freshness["sources"][0]["age_days"] == days
    assert validity_service.reproduces(fed)
    receipt = _receipt(result, keys)
    if state == "stale":
        # Stale lowers the grade; only past twice the SLA is a current claim blocked.
        assert fed.card["freshness"]["claim"] == "current"
        assert receipt.code is None and receipt.receipt is not None, (receipt.code, receipt.detail)
    else:
        # Past twice its SLA: the card says stale, and the receipt is refused.
        assert fed.card["freshness"]["claim"] == "stale" and freshness["claim"] == "stale"
        assert (receipt.receipt, receipt.code) == (None, "source_stale")
        assert not FinancialExposureReceipt.objects.exists()


def test_a_missing_source_blocks_the_claim_and_the_receipt(staging, people, keys):
    """Never fetched: the figure it feeds is lowered, the card says stale, and the
    receipt is refused (source_missing). So is a key the registry does not hold."""
    for evidence in (FED_BY_ECB, "financial-source:no-such-feed a typo"):
        deployment = Deployment.objects.create(name=f"d-{uuid.uuid4().hex[:6]}", owner=people["owner"],
                                               environment="staging")
        result, card = _carded(deployment, people, as_of=TODAY, evidence=evidence)
        assert card.card["freshness"]["claim"] == "stale"
        assert g.STALE_SOURCE in [d["rule"] for d in card.card["fields"]["confidence_grade"]["downgrades"]]
        receipt = _receipt(result, keys)
        assert (receipt.receipt, receipt.code) == (None, "source_missing")


def test_the_grade_names_the_rule_and_it_fires_once():
    weighted = [g.Weighted("a", ("OFFICIAL_PUBLIC",), Decimal("0.5")), g.Weighted("b", ("CUSTOMER_PROVIDED",),
                                                                                    Decimal("0.5"))]
    fresh = g.grade(refusal=None, unknown_cash_components=[], weighted=weighted)
    stale = g.grade(refusal=None, unknown_cash_components=[], weighted=weighted, stale_sources=["a", "b"])
    assert (fresh.grade.value, stale.grade.value) == ("A", "B")
    assert stale.downgrades == (g.STALE_SOURCE,) and stale.stale_sources == ("a", "b")
    assert "stale_source" in g.version_record()["downgrades"] and g.VERSION.endswith("/v3")


# ====================================================================
# The owner's decision of 13 Oct: an FX or cost-index source behind a production
# receipt is authoritative
# ====================================================================


def test_a_production_run_on_a_benchmark_fx_source_works_and_its_receipt_is_refused(reviewed, deployment, people,
                                                                                     keys):
    """The production gate is unchanged: a benchmark-raised FX source is usable by a
    production run, and the run, its card and its grade go ahead. Its receipt is
    refused (``source_not_authoritative``) and nothing is recorded, until two admins
    raise the source to authoritative; then the receipt is issued."""
    reviewed(ECB)
    fetched, _ = _fetch(ECB)
    raise_ = FinancialSourceTrustRaise.request(fetched.version, "benchmark", "the ECB publishes it",
                                               by=people["admin"], channel="api")
    benchmark = raise_.to_version
    benchmark.check_usable_for_production(deployment)  # the gate takes it
    result, card = _carded(deployment, people, as_of=TODAY, evidence=FED_BY_ECB)
    assert result.status == "completed"
    assert card.card["freshness"]["claim"] == "current"
    assert card.card["issued"]["feed_sources"][ECB]["used_version"]["trust_tier"] == "benchmark"
    assert g.STALE_SOURCE not in [d["rule"] for d in card.card["fields"]["confidence_grade"]["downgrades"]]
    refused = _receipt(result, keys)
    assert (refused.receipt, refused.code) == (None, "source_not_authoritative")
    assert "benchmark" in refused.detail and not FinancialExposureReceipt.objects.exists()

    pending = FinancialSourceTrustRaise.request(benchmark, "authoritative", "the official publisher",
                                                by=people["admin"], channel="api")
    pending.approve(by=people["second"], channel="api")
    issued = _receipt(result, keys)
    assert issued.code is None and issued.receipt is not None, (issued.code, issued.detail)


def test_the_authority_rule_is_for_production_runs_only(reviewed, staging, people, keys):
    reviewed(ECB)
    _fetch(ECB)  # unverified: a staging run takes it, and its receipt needs no more
    result, _card = _carded(staging, people, as_of=TODAY, evidence=FED_BY_ECB)
    assert _receipt(result, keys).code is None


def test_the_authority_rule_reads_what_a_source_holds(reviewed, deployment, people):
    """It applies to FX and cost-index observations: the version's own rows, as
    stored (a raised version reads those of the version it was raised from)."""
    reviewed(FRED)
    fetched, _ = _fetch(FRED)
    FinancialSourceTrustRaise.request(fetched.version, "licensed_vendor", "FRED redistributes it",
                                      by=people["admin"], channel="api")
    code, detail = feeds.receipt_refusal([FRED], deployment)
    assert code == "source_not_authoritative" and "licensed_vendor" in detail
    assert feeds.receipt_refusal([FRED], Deployment.objects.create(name="dev", environment="dev")) is None


def test_the_rule_is_published_and_a_production_gate_rule():
    from assurance.economics.engine import governance

    assert governance.production_authority_refusal("authoritative") is None
    for tier in ("benchmark", "licensed_vendor", "customer", "unverified", "AUTHORITATIVE", None):
        assert governance.production_authority_refusal(tier) == "source_not_authoritative"
    assert "source_not_authoritative" in governance.REFUSALS
    assert receipt_service.REFUSALS["source_not_authoritative"]


# ====================================================================
# GET deployments/<uuid>/economics/data-health/
# ====================================================================


def _health(client, deployment, query=""):
    return client.get(f"/api/assurance/deployments/{deployment.uuid}/economics/data-health/{query}")


def _client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def test_data_health_lists_every_feed_with_its_state(reviewed, staging, people, monkeypatch):
    reviewed(ECB, H10)
    monkeypatch.setattr(feeds.timezone, "now", lambda: NOW)
    _fetch(ECB)
    _fetch(H10)

    class Down:
        def send(self, request, key):
            raise feeds.TransportFailed("fetch_http_error")

    _fetch(FRED, transport=Down())
    pset = CustomerParameterSet.record(
        staging, "rates", {"variables": {"notification_fixed_cost": _entry(
            "money", "40000", evidence_ref=f"financial-source:{FRED} CPI for the notification cost")}},
        author=people["analyst"],
    )
    assert pset.version == 1
    answer = _health(_client(people["owner"]), staging)
    assert answer.status_code == 200, answer.content
    body = json.loads(answer.content)
    assert answer.content == json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert (body["deployment"], body["as_of"], body["production_run"]) == (str(staging.uuid), "2026-10-13", False)
    sources = {s["source_key"]: s for s in body["sources"]}
    assert set(sources) == set(engine.REGISTRY)
    assert sources[ECB]["state"] == "fresh" and sources[ECB]["used_version"]["version"] == 1
    assert sources[H10]["state"] == "fresh" and sources[H10]["sla_days"] == 10
    fred = sources[FRED]
    assert (fred["state"], fred["latest_version"], fred["last_fetch_failure"]["code"]) == (
        "missing", None, "fetch_http_error")
    assert set(fred["last_fetch_failure"]) == {"code", "at"}  # the code only
    assert fred["unknowns"] == [
        {"parameter": "notification_fixed_cost", "in": "parameter-set:rates:v1", "because": "source_missing"}]
    assert sources[PPI]["unknowns"] == [] and sources[ECB]["unknowns"] == []
    assert body["freshness_sla_days"] == {"BLS monthly": 45, "ECB daily": 3, "FRB-H10 weekly": 10, "FRED monthly": 45}


def test_data_health_tenancy(staging, people, monkeypatch):
    monkeypatch.setattr(feeds.timezone, "now", lambda: NOW)
    theirs = Deployment.objects.create(name="theirs", owner=people["stranger"])
    CustomerParameterSet.record(
        theirs, "rates", {"variables": {"notification_fixed_cost": _entry(
            "money", "40000", evidence_ref=f"financial-source:{ECB} theirs")}}, author=people["analyst"],
    )
    # The owner sees their own deployment, never another's: 404 whether or not it exists.
    assert _health(_client(people["owner"]), staging).status_code == 200
    assert _health(_client(people["owner"]), theirs).status_code == 404
    gone = Deployment(name="never-saved")
    assert _health(_client(people["owner"]), gone).status_code == 404
    assert APIClient().get(f"/api/assurance/deployments/{staging.uuid}/economics/data-health/").status_code == 401
    # Another tenant's parameters are never this one's Unknowns.
    mine = {s["source_key"]: s for s in json.loads(_health(_client(people["analyst"]), staging).content)["sources"]}
    seen = {s["source_key"]: s for s in json.loads(_health(_client(people["analyst"]), theirs).content)["sources"]}
    assert mine[ECB]["unknowns"] == []
    assert seen[ECB]["unknowns"] == [{"parameter": "notification_fixed_cost", "in": "parameter-set:rates:v1",
                                      "because": "source_missing"}]


def test_data_health_is_deterministic_and_strict(reviewed, staging, people, monkeypatch):
    reviewed(ECB)
    monkeypatch.setattr(feeds.timezone, "now", lambda: NOW)
    _fetch(ECB)
    client = _client(people["owner"])
    first, second = _health(client, staging), _health(client, staging)
    assert first.status_code == second.status_code == 200 and first.content == second.content
    monkeypatch.setattr(feeds.timezone, "now", lambda: NOW + timedelta(days=4))
    later = {s["source_key"]: s for s in json.loads(_health(client, staging).content)["sources"]}
    assert (later[ECB]["state"], later[ECB]["age_days"]) == ("stale", 4)
    refused = _health(client, staging, "?as_of=2026-10-01")
    assert refused.status_code == 400 and refused.json()["code"] == "field_malformed"
    assert client.post(f"/api/assurance/deployments/{staging.uuid}/economics/data-health/", {}).status_code == 405
    assert not FinancialSourceFetch.objects.exclude(outcome="recorded").exists()  # a read writes nothing


def test_data_health_is_not_a_stop():
    from safety import stops

    name = "deployment-economics-data-health"
    assert name in stops.NOT_STOPS and set(stops.NOT_STOPS[name]) == {"GET"}
    assert name not in stops.STOP_ROUTES and name not in stops.EXEMPT_ROUTES


# ====================================================================
# The spec
# ====================================================================


def test_the_spec_names_every_feed_code_and_the_rules():
    text = " ".join(SPEC.read_text(encoding="utf-8").split())
    for code in [*engine.FEED_REFUSALS, "source_stale", "source_missing", "source_not_authoritative", "stale_source",
                 "deployment-economics-data-health", *engine.REGISTRY]:
        assert f"`{code}`" in text, code
    for phrase in (
        "informational average, not a transaction price",
        "format-faithful, NOT a recorded response; replace with a recording (owner)",
        "A run uses the latest version of the key that passes the gate",
        "never inherit",
        "`responseTime`",
    ):
        assert phrase in text, phrase


def test_a_refused_fetch_names_its_code_and_nothing_else():
    with pytest.raises(EconomicsRefused):
        FinancialSourceFetch(source_key=ECB, as_of=TODAY, outcome="refused", code="").save()
    with pytest.raises(EconomicsRefused):
        FinancialSourceFetch(source_key=ECB, as_of=TODAY, outcome="refused", code="not a code").save()
    FinancialSourceFetch(source_key=ECB, as_of=TODAY, outcome="refused", code="fetch_failed").save()


def test_a_feed_fault_never_takes_down_a_stop():
    """SAFETY. A fresh pytest, under a plugin that makes the feed module raise at
    import, before Django loads, runs ``tests/economics_fault_cases.py``: Django
    loads, the scan's Stop is answered (202) and saved, ``deliver_owed_stops`` reaches
    its handler, ``manage.py check`` passes, and every other economics route is
    served; the data-health route answers an error."""
    env = dict(
        os.environ,
        DJANGO_SECRET_KEY=os.environ.get("DJANGO_SECRET_KEY", "ci-secret-key-not-used-outside-ci"),
        ECONOMICS_FAULT="feeds",
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-p", "tests.economics_broken_feeds",
         "-q", "tests/economics_fault_cases.py"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600, check=False,
    )
    assert result.returncode == 0, (result.stdout[-4000:], result.stderr[-2000:])
    assert "4 passed" in result.stdout, result.stdout[-2000:]
