"""Economic Exposure, MVP step 11: the cloud price catalogs, SEC EDGAR and the
regulators' enforcement listings, on fixtures (``docs/economics/spec-v1.md``,
section 30).

Every answer here is a FIXTURE (``tests/fixtures/economics_catalogs``): format-faithful,
NOT a recorded response; replace each with a recording (owner). Every company,
respondent and amount in them is fictitious. Nothing reaches a real host: step 10's
socket guard is autouse here too, and refuses every connection and name lookup that is
not loopback.

What is tested, by the brief's numbering:

1. each adapter's structure (a recording that differs fails there), its values (read
   by a reader of the test's own), and that a malformed, partial or over-long answer
   is refused whole, with nothing written but the fetch's record of its code;
2. the store: a fetch is an append-only, unverified, unreviewed version, deduplicated
   on its normalised payload;
3. CONTEXT ONLY: a prefill is a suggestion a person accepts, never written by the
   suggestion; an enforcement record is precedent with its citation, never a figure,
   and no code path writes an enforcement amount into a loss component;
4. freshness: cloud 7 days and gating, EDGAR 1 day and informational, enforcement 7
   days and context; a context source never stops a receipt;
5. data health lists them.

And the safety rule: no fetch or prefill is on a stop path, and no transaction is
open while a request is in flight.
"""

from __future__ import annotations

import ast
import csv
import dataclasses
import io
import json
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import date, datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from types import MappingProxyType

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import connection
from django.test import override_settings
from mythos_core import exposure_receipt as core
from rest_framework.test import APIClient

from assurance.economics import builder, context_service, feeds, receipt_service, snapshots, validity_service
from assurance.economics import models as econ_models
from assurance.economics.engine import catalogs
from assurance.economics.engine import context as rules
from assurance.economics.engine import feeds as engine
from assurance.economics.engine import grade as g
from assurance.economics.engine import scenario_simulation as ss
from assurance.economics.models import (
    CausalEffect,
    CustomerParameterSet,
    EconomicsRefused,
    EconomicsRewriteRefused,
    EffectFinding,
    FinancialExposureReceipt,
    FinancialParameter,
    FinancialScenario,
    FinancialSource,
    FinancialSourceFetch,
    FinancialSourceRecords,
    FinancialSourceTrustRaise,
    LossComponent,
    LossEvent,
    ScenarioBuild,
)
from assurance.models import Asset, Deployment, Finding
from tests.test_economics_feeds import guard  # noqa: F401 - the socket guard, autouse here too
from tests.test_economics_scenarios import _entry
from tests.test_economics_validity_card import _raw, _signer, simulated

pytestmark = pytest.mark.django_db
User = get_user_model()

REPO = Path(__file__).resolve().parent.parent
FIXTURES = REPO / "tests" / "fixtures" / "economics_catalogs"
SPEC = REPO / "docs" / "economics" / "spec-v1.md"
ECONOMICS = REPO / "assurance" / "economics"
LABEL = b"# format-faithful, NOT a recorded response; replace with a recording (owner)"
NOW = datetime(2026, 10, 13, 18, 0, tzinfo=timezone.utc)
TODAY = NOW.date()
GCP_KEY = "test-gcp-key-not-a-real-key-0003"
SEC_AGENT = "Fixture Owner fixture-owner@example.invalid"
LIVE = {
    "ECONOMICS_LIVE_FEEDS_ENABLED": True,
    "ECONOMICS_GCP_BILLING_API_KEY": GCP_KEY,
    "ECONOMICS_SEC_USER_AGENT": SEC_AGENT,
}
CIK = "0009999999"
AWS, AZURE, GCP = "aws-price-list-s3-us-east-1", "azure-retail-prices-site-recovery-eastus", "gcp-billing-catalog-cloud-storage"
SUBMISSIONS, FACTS, SEGMENTS = (f"sec-edgar-{family}-cik{CIK}" for family in catalogs.EDGAR_FAMILIES)
CFPB, FTC, SEC, HHS = "cfpb-enforcement-actions", "ftc-privacy-security-cases", "sec-litigation-releases", "hhs-ocr-hipaa-enforcement"
OCC, FDIC, FRB = "occ-enforcement-actions", "fdic-enforcement-orders", "frb-enforcement-actions"
ENFORCEMENT = (CFPB, FTC, SEC, HHS, OCC, FDIC, FRB)
FILES = {
    AWS: ["aws-price-list-s3-us-east-1.json"],
    AZURE: ["azure-retail-prices-site-recovery-eastus-p1.json", "azure-retail-prices-site-recovery-eastus-p2.json"],
    GCP: ["gcp-billing-catalog-cloud-storage-p1.json", "gcp-billing-catalog-cloud-storage-p2.json"],
    SUBMISSIONS: [f"{SUBMISSIONS}.json"],
    FACTS: [f"{FACTS}.json"],
    SEGMENTS: [f"{SEGMENTS}.xml"],
    CFPB: ["cfpb-enforcement-actions.xml"],
    FTC: ["ftc-privacy-security-cases.xml"],
    SEC: ["sec-litigation-releases.xml"],
    HHS: ["hhs-ocr-hipaa-enforcement.xml"],
    OCC: ["occ-enforcement-actions.csv"],
    FDIC: ["fdic-enforcement-orders.csv"],
    FRB: ["frb-enforcement-actions.csv"],
}


def fixture(name: str) -> bytes:
    """A fixture's bytes as the provider would answer: its first line, the
    format-faithful note, taken off. A recording is read as it is."""
    raw = (FIXTURES / name).read_bytes()
    first, newline, rest = raw.partition(b"\n")
    return rest if newline and first.rstrip(b"\r") == LABEL else raw


def pages_of(key: str) -> list[bytes]:
    return [fixture(name) for name in FILES[key]]


class Pages:
    """A transport answering each request with the next answer in turn (an exception
    is raised), keeping what it was asked: the request (never with the key) and the
    key it was handed."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.sent: list[tuple[engine.FeedRequest, str]] = []

    def send(self, request, key):
        self.sent.append((request, key))
        answer = self.answers[len(self.sent) - 1]
        if isinstance(answer, Exception):
            raise answer
        return answer


def _fetch(key, answers=None, *, now=NOW, as_of=None, transport=None, live=None):
    transport = transport or Pages(*(pages_of(key) if answers is None else answers))
    with override_settings(**(LIVE if live is None else live)):
        return feeds.fetch(key, as_of=as_of, transport=transport, now=now), transport


def _parse(key, answers=None, *, filing=None):
    feed = catalogs.source(key)
    answers = pages_of(key) if answers is None else answers
    request = catalogs.request_for(feed, as_of=TODAY, explicit=False, today=TODAY, filing=filing)
    requests = [request]
    for page in answers[:-1]:
        request = catalogs.next_request(feed, request, page)
        requests.append(request)
    return catalogs.parse(feed, answers, as_of=TODAY, retrieved_at=NOW, requests=requests, filing=filing)


def _nothing_kept():
    return FinancialSource.objects.count() == 0 and FinancialSourceRecords.objects.count() == 0


@pytest.fixture
def reviewed(monkeypatch):
    """The registry with ``keys``' licence reviewed (``open``), as the owner's
    licensing review would record it: until then every source is ``unreviewed``."""
    opened: set[str] = set()
    original = catalogs.known

    def known(key):
        found = original(key)
        if found is not None and key in opened:
            return dataclasses.replace(found, license_class="open")
        return found

    monkeypatch.setattr(catalogs, "known", known)

    def review(*keys):
        opened.update(keys)

    return review


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


def _client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


# ====================================================================
# 1. The structure each fixture is written in (a recording that differs fails here)
# ====================================================================


def test_aws_fixture_structure():
    """The AWS Price List bulk offer file: ``formatVersion`` v1.0, the offer code, its
    products by SKU, and on-demand terms by SKU and offer term, each price dimension
    naming its rate code under its term, a USD price as a decimal string, and a
    begin and end range ("Inf" for none)."""
    document = json.loads(fixture(FILES[AWS][0]))
    assert set(document) == catalogs.AWS_FIELDS
    assert (document["formatVersion"], document["offerCode"]) == ("v1.0", "AmazonS3")
    for sku, product in document["products"].items():
        assert product["sku"] == sku and set(product) <= catalogs.AWS_PRODUCT | catalogs.AWS_PRODUCT_OPTIONAL
        assert product["attributes"]["regionCode"] == "us-east-1"
    assert set(document["terms"]) == {"OnDemand"}
    for sku, offers in document["terms"]["OnDemand"].items():
        for term_key, term in offers.items():
            assert set(term) == catalogs.AWS_TERM and term_key == f"{sku}.{term['offerTermCode']}"
            for rate, dimension in term["priceDimensions"].items():
                assert set(dimension) == catalogs.AWS_DIMENSION and rate.startswith(term_key + ".")
                assert re.fullmatch(r"[0-9]+\.[0-9]{10}", dimension["pricePerUnit"]["USD"])
                assert dimension["endRange"] == "Inf" or dimension["endRange"].isdigit()


def test_azure_fixture_structure():
    """The Azure Retail Prices API's pages: their six fields, ``Count`` the number of
    items, prices as JSON numbers, every item of the service, region and price type
    asked, and ``NextPageLink`` the same endpoint and query with a ``$skip`` (null on
    the last page)."""
    first, last = (json.loads(raw, parse_float=Decimal) for raw in pages_of(AZURE))
    for page in (first, last):
        assert set(page) == catalogs.AZURE_PAGE and page["Count"] == len(page["Items"])
        assert (page["BillingCurrency"], page["CustomerEntityType"]) == ("USD", "Retail")
        for item in page["Items"]:
            assert catalogs.AZURE_ITEM <= set(item) <= catalogs.AZURE_ITEM | catalogs.AZURE_ITEM_OPTIONAL
            assert isinstance(item["retailPrice"], Decimal) and isinstance(item["tierMinimumUnits"], Decimal)
            assert (item["serviceName"], item["armRegionName"], item["type"]) == ("Azure Site Recovery", "eastus",
                                                                                 "Consumption")
    assert first["NextPageLink"].startswith("https://prices.azure.com:443/api/retail/prices?")
    assert "$skip=" in first["NextPageLink"] and last["NextPageLink"] is None


def test_gcp_fixture_structure():
    """The Cloud Billing Catalog's SKU pages: each SKU's fields, named under the
    service, its pricing a ``google.type.Money`` (``units`` as text and ``nanos``, each
    absent at zero), and a ``nextPageToken`` on every page but the last."""
    first, last = (json.loads(raw) for raw in pages_of(GCP))
    assert first["nextPageToken"] and last["nextPageToken"] == ""
    for page in (first, last):
        for sku in page["skus"]:
            assert catalogs.GCP_SKU <= set(sku) <= catalogs.GCP_SKU | catalogs.GCP_SKU_OPTIONAL
            assert sku["name"] == f"services/95FF-2EF5-5EA1/skus/{sku['skuId']}"
            (info,) = sku["pricingInfo"]
            assert set(info["pricingExpression"]) == catalogs.GCP_EXPRESSION
            for rate in info["pricingExpression"]["tieredRates"]:
                assert set(rate["unitPrice"]) <= {"currencyCode", "units", "nanos"}
                assert rate["unitPrice"]["currencyCode"] == "USD"


def test_edgar_fixture_structure():
    """EDGAR's submissions JSON (the company, its tickers, ``filings.recent`` as
    columns of one length), its companyfacts JSON (taxonomy, concept, unit, facts with
    the form, filing date and accession number), and a periodic filing's XBRL
    instance (contexts, units, facts by contextRef and unitRef)."""
    watch = json.loads(fixture(FILES[SUBMISSIONS][0]))
    assert catalogs.SUBMISSIONS_FIELDS <= set(watch) <= catalogs.SUBMISSIONS_FIELDS | catalogs.SUBMISSIONS_OPTIONAL
    recent = watch["filings"]["recent"]
    assert catalogs.RECENT_COLUMNS <= set(recent) and len({len(column) for column in recent.values()}) == 1
    assert all(re.fullmatch(r"[0-9]{10}-[0-9]{2}-[0-9]{6}", a) for a in recent["accessionNumber"])
    facts = json.loads(fixture(FILES[FACTS][0]))
    assert set(facts) == catalogs.FACTS_FIELDS and isinstance(facts["cik"], int)
    for concepts in facts["facts"].values():
        for held in concepts.values():
            assert set(held) == catalogs.CONCEPT_FIELDS
            for unit_facts in held["units"].values():
                for one in unit_facts:
                    assert catalogs.FACT_FIELDS <= set(one) <= catalogs.FACT_FIELDS | catalogs.FACT_OPTIONAL
    root = ET.fromstring(fixture(FILES[SEGMENTS][0]))
    assert root.tag == f"{{{catalogs.XBRLI}}}xbrl"
    contexts = {c.get("id") for c in root.findall(f"{{{catalogs.XBRLI}}}context")}
    units = {u.get("id") for u in root.findall(f"{{{catalogs.XBRLI}}}unit")}
    for element in root:
        if element.get("contextRef") and element.get("unitRef"):
            assert element.get("contextRef") in contexts and element.get("unitRef") in units


def test_rss_fixture_structure():
    """RSS 2.0, one channel, every item a title, a link on the agency's host, an RFC
    822 pubDate and a guid."""
    for key in (CFPB, FTC, SEC, HHS):
        root = ET.fromstring(fixture(FILES[key][0]))
        assert (root.tag, root.get("version")) == ("rss", "2.0")
        (channel,) = root.findall("channel")
        items = channel.findall("item")
        assert items
        for item in items:
            assert item.findtext("title") and item.findtext("guid")
            assert item.findtext("link").startswith(f"https://{catalogs.CATALOG_REGISTRY[key].config['host']}/")
            assert re.fullmatch(r"[A-Z][a-z]{2}, [0-9]{2} [A-Z][a-z]{2} [0-9]{4} [0-9:]{8} [-+][0-9]{4}",
                                item.findtext("pubDate"))


def test_csv_fixture_structure():
    """Each CSV export's header is the registry's, and every line has as many cells,
    a MM/DD/YYYY date and an https URL on the agency's host."""
    for key in (OCC, FDIC, FRB):
        config = catalogs.CATALOG_REGISTRY[key].config
        rows = [row for row in csv.reader(io.StringIO(fixture(FILES[key][0]).decode(), newline="")) if row]
        assert tuple(rows[0]) == config["header"]
        for row in rows[1:]:
            cell = dict(zip(rows[0], row, strict=True))
            assert re.fullmatch(r"[0-9]{2}/[0-9]{2}/[0-9]{4}", cell[config["date"]])
            assert cell[config["url"]].startswith(f"https://{config['host']}/")


def test_every_fixture_is_named_in_the_readme_with_its_status():
    readme = (FIXTURES / "README.md").read_text(encoding="utf-8")
    assert "format-faithful, NOT a recorded response; replace with a recording (owner)" in readme
    names = sorted(p.name for p in FIXTURES.iterdir() if p.name != "README.md")
    assert names == sorted(name for files in FILES.values() for name in files)
    for name in names:
        assert (FIXTURES / name).read_bytes().startswith(LABEL), name
        stem = name.rsplit("-p", 1)[0] if "-p1." in name or "-p2." in name else name
        assert stem.split(".")[0] in readme, name
    assert "FICTITIOUS" in readme and "ASSUMED" in readme


# ====================================================================
# 1. The values each answer parses to, by a reader of the test's own
# ====================================================================


def test_the_aws_offer_parses_to_its_prices():
    document = json.loads(fixture(FILES[AWS][0]))
    expected = {
        rate: (sku, Decimal(d["pricePerUnit"]["USD"]), d["unit"], Decimal(d["beginRange"]))
        for sku, offers in document["terms"]["OnDemand"].items()
        for term in offers.values()
        for rate, d in term["priceDimensions"].items()
    }
    snapshot = _parse(AWS)
    seen = {r.observation_id: (r.sku, r.usd_price, r.unit, r.tier_start) for r in snapshot.records}
    assert seen == expected
    assert {r.region for r in snapshot.records} == {"us-east-1"} and snapshot.record_kind == "cloud_price"
    assert {r.effective_date for r in snapshot.records} == {date(2026, 9, 1)}
    assert (snapshot.fx_rates, snapshot.index_points) == ((), ())


def test_the_azure_pages_parse_to_their_prices_across_pages():
    expected = {}
    for raw in pages_of(AZURE):
        for item in json.loads(raw, parse_float=Decimal)["Items"]:
            expected[item["meterId"]] = (item["skuId"], Decimal(item["retailPrice"]), item["unitOfMeasure"])
    snapshot = _parse(AZURE)
    assert {r.observation_id.split("/")[0]: (r.sku, r.usd_price, r.unit) for r in snapshot.records} == expected
    assert len(snapshot.records) == 3 and "$skip" not in snapshot.source["url"]


def test_the_gcp_pages_parse_to_their_prices_in_the_regions_asked():
    """``units`` plus ``nanos`` billionths, each zero where absent; one price per
    configured region a SKU is offered in (Belgium is not asked), per tier."""
    snapshot = _parse(GCP)
    by_id = {r.observation_id: r for r in snapshot.records}
    assert by_id["F1X7-0001-AAAA@us-central1#0@2026-10-12"].usd_price == Decimal("0.02")
    assert by_id["F1X7-0004-DDDD@us-central1#0@2026-10-12"].usd_price == Decimal("0.0012")
    egress = sorted((r.region, r.tier_start, r.usd_price) for r in snapshot.records if r.sku == "F1X7-0005-EEEE")
    assert egress == [(region, Decimal(t), Decimal(p)) for region in ("us-central1", "us-east1")
                      for t, p in (("0", "0"), ("1", "0.12"), ("1024", "0.11"))]
    assert not any(r.sku == "F1X7-0003-CCCC" for r in snapshot.records)
    assert {r.unit for r in snapshot.records} == {"GiBy.mo", "GiBy"}


def test_the_edgar_watch_and_facts_parse_with_form_date_and_accession():
    watch = json.loads(fixture(FILES[SUBMISSIONS][0]))
    snapshot = _parse(SUBMISSIONS)
    (entity,) = [r for r in snapshot.records if r.TYPE == "entity"]
    assert (entity.cik, entity.name, entity.tickers, entity.listed) == (CIK, watch["name"], ("FXMP",), True)
    filings = {r.accession: r for r in snapshot.records if r.TYPE == "filing"}
    recent = watch["filings"]["recent"]
    assert sorted(filings) == sorted(recent["accessionNumber"])
    for row, accession in enumerate(recent["accessionNumber"]):
        assert (filings[accession].form, filings[accession].filing_date.isoformat()) == (
            recent["form"][row], recent["filingDate"][row])
    facts = json.loads(fixture(FILES[FACTS][0]))["facts"]["us-gaap"]
    expected = {
        (f"us-gaap:{concept}", one["start"], one["end"], one["accn"]): (Decimal(one["val"]), one["form"], one["filed"])
        for concept in (*catalogs.REVENUE_CONCEPTS, *catalogs.OPERATING_INCOME_CONCEPTS) if concept in facts
        for one in facts[concept]["units"]["USD"] if "start" in one
    }
    parsed = _parse(FACTS)
    assert {(r.concept, r.period_start.isoformat(), r.period_end.isoformat(), r.accession):
            (r.value, r.form, r.filed.isoformat()) for r in parsed.records} == expected
    assert not any("Assets" in r.concept for r in parsed.records)  # an instant: not a period's figure


def test_segment_revenue_is_read_from_the_newest_periodic_filings_instance():
    watch = _parse(SUBMISSIONS).records
    filing = catalogs.newest_periodic_filing(watch, TODAY)
    assert (filing.form, filing.accession, filing.primary_document) == ("10-Q", "0009999999-26-000033",
                                                                        "exmp-20260627.htm")
    request = catalogs.request_for(catalogs.source(SEGMENTS), as_of=TODAY, explicit=False, today=TODAY, filing=filing)
    assert request.url == "https://www.sec.gov/Archives/edgar/data/9999999/000999999926000033/exmp-20260627_htm.xml"
    assert (request.key_in, request.key_name) == ("header", "User-Agent")
    records = _parse(SEGMENTS, filing=filing).records
    segments = {(r.segment_member, r.period_start.isoformat()): r.value for r in records if r.segment_member}
    assert segments == {
        ("exmp:PlatformSegmentMember", "2026-03-29"): Decimal("259700000"),
        ("exmp:ServicesSegmentMember", "2026-03-29"): Decimal("111300000"),
        ("exmp:PlatformSegmentMember", "2025-09-28"): Decimal("771400000"),
    }
    (company,) = [r for r in records if not r.segment_member]
    assert company.value == Decimal("371000000") and company.entity == "FIXTURE EXAMPLE CORP"
    assert {(r.form, r.accession, r.fiscal_period) for r in records} == {("10-Q", filing.accession, "Q3")}
    assert all(r.segment_axis in ("", "us-gaap:StatementBusinessSegmentsAxis") for r in records)


def test_the_enforcement_listings_parse_to_their_records():
    """RSS items: agency, date, respondent (the title, for CFPB, FTC and SEC; none for
    HHS OCR), the citation; no amount, which no RSS field states. CSV lines: the
    amounts each states, by its own columns, and none read out of prose."""
    for key in (CFPB, FTC, SEC, HHS):
        root = ET.fromstring(fixture(FILES[key][0]))
        items = {i.findtext("link"): i.findtext("title") for i in root.find("channel").findall("item")}
        records = _parse(key).records
        assert {r.citation_url: r.citation_text for r in records} == items
        for record in records:
            assert record.respondent == (None if key == HHS else record.citation_text)
            assert (record.civil_money_penalty, record.restitution, record.settlement) == (None, None, None)
    occ = {r.category: r for r in _parse(OCC).records}
    assert occ["bank supervision: Civil Money Penalty"].civil_money_penalty == Decimal("1250000")
    assert occ["bank supervision: Restitution"].restitution == Decimal("300000.00")
    assert occ["bank supervision: Prohibition Order"].respondent == "Fixture Person One"
    assert occ["bank supervision: Formal Agreement"].civil_money_penalty is None
    fdic = {r.respondent: r for r in _parse(FDIC).records}
    assert fdic["Fixture State Bank"].civil_money_penalty == Decimal("185000")
    assert fdic["Fixture Savings Bank"].restitution == Decimal("2100000.00")
    (frb,) = [r for r in _parse(FRB).records if r.civil_money_penalty is not None]
    assert (frb.respondent, frb.civil_money_penalty, frb.action_date) == ("Fixture Bancorp, Inc.", Decimal("4500000"),
                                                                         date(2026, 10, 8))


# ====================================================================
# 1. A malformed, partial or over-long answer is refused whole
# ====================================================================


def _json_edit(raw: bytes, edit) -> bytes:
    document = json.loads(raw, parse_float=Decimal)
    edit(document)
    # A number stays a number (the fixtures' are exact as floats).
    return json.dumps(document, default=float).encode()


def _aws(edit):
    return [_json_edit(pages_of(AWS)[0], edit)]


def _azure(edit, page=0):
    answers = pages_of(AZURE)
    document = json.loads(answers[page], parse_float=Decimal)
    edit(document)
    answers[page] = json.dumps(document, default=float).encode()
    return answers


def _gcp(edit, page=0):
    answers = pages_of(GCP)
    answers[page] = _json_edit(answers[page], edit)
    return answers


def _first_term(document):
    offers = document["terms"]["OnDemand"]["FIXTURESKUSTD0001"]
    return next(iter(next(iter(offers.values()))["priceDimensions"].values()))


def _csv_cell(key, line, column, value):
    rows = [row for row in csv.reader(io.StringIO(fixture(FILES[key][0]).decode(), newline="")) if row]
    rows[line][rows[0].index(column)] = value
    out = io.StringIO()
    csv.writer(out, lineterminator="\r\n").writerows(rows)
    return [out.getvalue().encode()]


MALFORMED = {
    "aws-not-json": (AWS, lambda: [b"<html>"], "feed_malformed"),
    "aws-another-offer": (AWS, lambda: _aws(lambda d: d.update(offerCode="AmazonEC2")), "feed_mismatch"),
    "aws-a-term-for-no-product": (AWS, lambda: _aws(lambda d: d["products"].pop("FIXTURESKUGLC0002")),
                                  "feed_mismatch"),
    "aws-a-price-not-in-usd": (AWS, lambda: _aws(lambda d: _first_term(d).update(pricePerUnit={"CNY": "0.1"})),
                               "feed_mismatch"),
    "aws-a-price-not-a-decimal": (AWS, lambda: _aws(lambda d: _first_term(d).update(pricePerUnit={"USD": "1e-3"})),
                                  "feed_value_malformed"),
    "aws-another-region": (AWS, lambda: _aws(lambda d: d["products"]["FIXTURESKUPUT0003"]["attributes"].update(
        regionCode="eu-west-1")), "feed_mismatch"),
    "aws-a-duplicate-key": (AWS, lambda: [pages_of(AWS)[0].replace(b'"formatVersion"', b'"offerCode": "x", '
                                                                                        b'"formatVersion"', 1)],
                            "feed_malformed"),
    "azure-a-count-that-is-not-its-items": (AZURE, lambda: _azure(lambda d: d.update(Count=5)), "feed_partial"),
    "azure-another-region": (AZURE, lambda: _azure(lambda d: d["Items"][0].update(armRegionName="westus"), 1),
                             "feed_mismatch"),
    "azure-a-field-unknown": (AZURE, lambda: _azure(lambda d: d["Items"][1].update(surprise=1)), "feed_malformed"),
    "azure-not-in-usd": (AZURE, lambda: _azure(lambda d: d.update(BillingCurrency="EUR")), "feed_mismatch"),
    "gcp-a-price-in-another-currency": (GCP, lambda: _gcp(lambda d: d["skus"][0]["pricingInfo"][0][
        "pricingExpression"]["tieredRates"][0]["unitPrice"].update(currencyCode="EUR")), "feed_mismatch"),
    "gcp-nanos-out-of-range": (GCP, lambda: _gcp(lambda d: d["skus"][0]["pricingInfo"][0]["pricingExpression"][
        "tieredRates"][0]["unitPrice"].update(nanos=1000000000)), "feed_value_malformed"),
    "gcp-a-sku-of-another-service": (GCP, lambda: _gcp(lambda d: d["skus"][1].update(
        name="services/6F81-5844-456A/skus/F1X7-0002-BBBB"), 1), "feed_mismatch"),
    "submissions-another-company": (SUBMISSIONS, lambda: [_json_edit(pages_of(SUBMISSIONS)[0],
                                                                     lambda d: d.update(cik="320193"))],
                                    "feed_mismatch"),
    "submissions-a-column-cut-short": (SUBMISSIONS, lambda: [_json_edit(
        pages_of(SUBMISSIONS)[0], lambda d: d["filings"]["recent"]["form"].pop())], "feed_partial"),
    "facts-a-bad-accession": (FACTS, lambda: [_json_edit(pages_of(FACTS)[0], lambda d: d["facts"]["us-gaap"][
        "Revenues"]["units"]["USD"][0].update(accn="not-an-accession"))], "feed_value_malformed"),
    "facts-another-company": (FACTS, lambda: [_json_edit(pages_of(FACTS)[0], lambda d: d.update(cik=320193))],
                              "feed_mismatch"),
    "rss-not-rss": (CFPB, lambda: [b"<?xml version='1.0'?><feed/>"], "feed_malformed"),
    "rss-a-doctype": (CFPB, lambda: [b"<?xml version='1.0'?><!DOCTYPE rss [<!ENTITY x 'y'>]><rss version='2.0'/>"],
                      "feed_malformed"),
    "rss-a-link-elsewhere": (SEC, lambda: [pages_of(SEC)[0].replace(b"https://www.sec.gov/enforcement-litigation/"
                                                                    b"litigation-releases/2026/lr99887",
                                                                    b"https://evil.invalid/lr", 1)],
                             "feed_mismatch"),
    "rss-a-date-not-rfc822": (FTC, lambda: [pages_of(FTC)[0].replace(b"Mon, 05 Oct 2026 12:00:00 -0400",
                                                                     b"2026-10-05")], "feed_value_malformed"),
    "rss-no-item": (HHS, lambda: [b"<?xml version='1.0'?><rss version='2.0'><channel><title>t</title></channel></rss>"],
                    "feed_empty"),
    "csv-another-header": (OCC, lambda: [pages_of(OCC)[0].replace(b"Amount", b"Penalty", 1)], "feed_malformed"),
    "csv-a-line-cut-short": (FDIC, lambda: [pages_of(FDIC)[0].rsplit(b",", 1)[0] + b"\r\n"], "feed_partial"),
    "csv-an-amount-in-prose": (FRB, lambda: _csv_cell(FRB, 1, "Civil Money Penalty", "about $4.5 million"),
                               "feed_value_malformed"),
    "csv-an-amount-on-an-action-that-states-none": (OCC, lambda: _csv_cell(OCC, 3, "Amount", "$5,000"),
                                                    "feed_value_malformed"),
    "csv-two-respondents": (OCC, lambda: _csv_cell(OCC, 1, "Individual Name", "Fixture Person Two"),
                            "feed_value_malformed"),
}


@pytest.mark.parametrize("case", sorted(MALFORMED))
def test_a_malformed_or_partial_answer_is_refused_and_nothing_half_loads(case):
    key, answers, code = MALFORMED[case]
    outcome, _ = _fetch(key, answers())
    assert (outcome.outcome, outcome.code) == ("refused", code), outcome.meaning
    assert _nothing_kept()
    (row,) = FinancialSourceFetch.objects.all()
    assert (row.source_key, row.outcome, row.code, row.source) == (key, "refused", code, None)


def test_a_malformed_item_on_a_later_page_refuses_every_page():
    """All or nothing across pages: page 1 is well formed, page 2's one item is not;
    nothing of page 1 is kept either."""
    outcome, transport = _fetch(AZURE, _azure(lambda d: d["Items"][0].update(retailPrice=None), 1))
    assert (outcome.outcome, outcome.code) == ("refused", "feed_value_malformed")
    assert len(transport.sent) == 2 and _nothing_kept()


def test_a_page_that_fails_refuses_the_whole_answer():
    first = pages_of(GCP)[0]
    outcome, transport = _fetch(GCP, [first, feeds.TransportFailed("fetch_http_error")])
    assert (outcome.outcome, outcome.code) == ("refused", "fetch_http_error")
    assert len(transport.sent) == 2 and _nothing_kept()


def test_a_next_page_link_is_never_followed_elsewhere():
    elsewhere = _azure(lambda d: d.update(NextPageLink=d["NextPageLink"].replace("prices.azure.com",
                                                                               "prices.example.invalid")))
    outcome, transport = _fetch(AZURE, elsewhere)
    assert (outcome.code, len(transport.sent)) == ("feed_mismatch", 1) and _nothing_kept()
    another = _azure(lambda d: d.update(NextPageLink=d["NextPageLink"].replace("eastus", "westus")))
    outcome, transport = _fetch(AZURE, another)
    assert (outcome.code, len(transport.sent)) == ("feed_mismatch", 1)


def test_more_pages_than_a_source_is_read_across_are_refused(monkeypatch):
    feed = catalogs.CATALOG_REGISTRY[GCP]
    registry = dict(catalogs.CATALOG_REGISTRY)
    registry[GCP] = dataclasses.replace(feed, config=MappingProxyType({**feed.config, "max_pages": 1}))
    monkeypatch.setattr(catalogs, "CATALOG_REGISTRY", MappingProxyType(registry))
    outcome, transport = _fetch(GCP)
    assert (outcome.code, len(transport.sent)) == ("feed_over_limit", 1) and _nothing_kept()


@pytest.mark.parametrize("key", [AZURE, GCP])
def test_a_page_that_says_more_follows_but_is_last_is_partial(key):
    """An answer cut after a page that names a next one is partial: each adapter reads
    its own pages' links, whatever the fetch did."""
    feed = catalogs.source(key)
    request = catalogs.request_for(feed, as_of=TODAY, explicit=False, today=TODAY)
    with pytest.raises(engine.FeedRefused) as refused:
        catalogs.parse(feed, pages_of(key)[:1], as_of=TODAY, retrieved_at=NOW, requests=[request])
    assert refused.value.code == "feed_partial"
    # And the last page alone, asked as the first, names none it should.
    last = pages_of(key)[-1]
    snapshot = catalogs.parse(feed, [last], as_of=TODAY, retrieved_at=NOW, requests=[request])
    assert snapshot.records


def test_more_records_than_a_version_holds_are_refused(monkeypatch):
    monkeypatch.setattr(catalogs, "MAX_RECORDS", 5)
    outcome, _ = _fetch(AWS)
    assert (outcome.code, outcome.outcome) == ("feed_over_limit", "refused") and _nothing_kept()


def test_an_answer_too_large_is_not_read():
    feed = catalogs.source(CFPB)
    request = catalogs.request_for(feed, as_of=TODAY, explicit=False, today=TODAY)
    with pytest.raises(engine.FeedRefused) as refused:
        catalogs.parse(feed, [b"x" * (engine.MAX_RESPONSE_BYTES + 1)], as_of=TODAY, retrieved_at=NOW,
                       requests=[request])
    assert refused.value.code == "response_too_large"
    assert catalogs.source(AWS).config["max_bytes"] == request.max_bytes * 8 == catalogs.CATALOG_MAX_BYTES


# ====================================================================
# 2. The snapshot store: append-only versions, unverified, deduplicated
# ====================================================================


def test_a_fetch_is_a_new_unverified_unreviewed_version_with_its_records():
    outcome, transport = _fetch(GCP)
    assert (outcome.outcome, outcome.code, outcome.observations) == ("recorded", None, 9)
    version = outcome.version
    assert (version.deployment, version.source_key, version.version) == (None, GCP, 1)
    assert (version.trust_tier, version.license_class, version.synthetic) == ("unverified", "unreviewed", False)
    assert version.snapshot_hash == outcome.payload_hash == catalogs.payload_hash(catalogs.source(GCP), pages_of(GCP))
    assert version.url.endswith("/v1/services/95FF-2EF5-5EA1/skus?currencyCode=USD&pageSize=5000")
    (held,) = FinancialSourceRecords.objects.all()
    assert (held.source, held.kind, held.record_count) == (version, "cloud_price", 9)
    assert snapshots.records_of(version) == _parse(GCP).records
    (row,) = FinancialSourceFetch.objects.all()
    assert (row.outcome, row.source, row.payload_hash) == ("recorded", version, version.snapshot_hash)
    with pytest.raises(EconomicsRewriteRefused):
        held.save()
    with pytest.raises(EconomicsRewriteRefused):
        FinancialSourceRecords.objects.all().delete()
    assert {request.url for request, _key in transport.sent} == {
        "https://cloudbilling.googleapis.com/v1/services/95FF-2EF5-5EA1/skus"}


def test_every_family_fetches_into_the_store():
    for key in (AWS, AZURE, GCP, SUBMISSIONS, FACTS, *ENFORCEMENT):
        outcome, _ = _fetch(key)
        assert (outcome.outcome, outcome.code) == ("recorded", None), (key, outcome.code)
        assert snapshots.records_of(outcome.version) == _parse(key).records
    outcome, transport = _fetch(SEGMENTS)
    assert (outcome.outcome, outcome.observations) == ("recorded", 4)
    ((request, key),) = transport.sent
    assert request.url.endswith("/Archives/edgar/data/9999999/000999999926000033/exmp-20260627_htm.xml")
    assert key == SEC_AGENT


def test_segment_revenue_needs_a_filing_watch_first():
    outcome, transport = _fetch(SEGMENTS)
    assert (outcome.code, outcome.row, transport.sent) == ("filing_unknown", None, [])
    assert not FinancialSourceFetch.objects.exists()


def test_a_duplicate_answer_gives_no_new_version():
    for key in (AWS, AZURE, GCP, SUBMISSIONS, CFPB, OCC):
        first, _ = _fetch(key)
        again, _ = _fetch(key, now=NOW + timedelta(hours=3))
        assert (again.outcome, again.version) == ("unchanged", first.version), key
    assert FinancialSourceRecords.objects.count() == 6


def test_what_the_payload_hash_drops_and_keeps():
    """A GCP page token (an opaque cursor) and an RSS channel's own build date are
    not the payload; a changed price or a new item is."""
    first, _ = _fetch(GCP)
    token = _gcp(lambda d: d.update(nextPageToken="another-opaque-cursor"))
    again, _ = _fetch(GCP, token, now=NOW + timedelta(hours=1))
    assert (again.outcome, again.version) == ("unchanged", first.version)
    price = _gcp(lambda d: d["skus"][0]["pricingInfo"][0]["pricingExpression"]["tieredRates"][0]["unitPrice"].update(
        nanos=21000000))
    changed, _ = _fetch(GCP, price, now=NOW + timedelta(hours=2))
    assert (changed.outcome, changed.version.version) == ("recorded", 2)
    rss, _ = _fetch(CFPB)
    rebuilt = [pages_of(CFPB)[0].replace(b"Tue, 13 Oct 2026 06:00:00 -0400", b"Tue, 13 Oct 2026 07:00:00 -0400")]
    again, _ = _fetch(CFPB, rebuilt, now=NOW + timedelta(hours=1))
    assert (again.outcome, again.version) == ("unchanged", rss.version)
    assert set(catalogs.NORMALISATION) == set(catalogs._ADAPTERS)


def test_a_raised_version_reads_the_records_its_payload_was_registered_with(people):
    fetched, _ = _fetch(OCC)
    raised = FinancialSourceTrustRaise.request(fetched.version, "benchmark", "the OCC publishes it",
                                               by=people["admin"], channel="api").to_version
    assert raised.version == 2 and FinancialSourceRecords.objects.count() == 1
    assert snapshots.records_of(raised) == snapshots.records_of(fetched.version)


def test_a_records_row_is_held_to_its_records():
    fetched, _ = _fetch(FRB)
    entries = catalogs.records_json(_parse(FRB).records)
    good = {"kind": "enforcement", "records": entries, "record_count": len(entries),
            "records_digest": catalogs.records_digest(entries)}
    other, _ = _fetch(FDIC)
    with pytest.raises(EconomicsRefused) as refused:  # one row per version
        FinancialSourceRecords(source=fetched.version, **good).save()
    assert refused.value.code == "duplicate_id"
    for bad in (
        {**good, "record_count": 1},
        {**good, "records_digest": "sha256:" + "0" * 64},
        {**good, "kind": "cloud_price"},
        {**good, "records": [{**entries[0], "civil_money_penalty": 4500000}]},
        {**good, "records": [{**entries[0], "surprise": "x"}]},
    ):
        with pytest.raises(EconomicsRefused) as refused:
            FinancialSourceRecords(source=FinancialSource.objects.create(
                source_key="frb-enforcement-actions", provider="FRB", dataset="d", retrieved_at=NOW,
                snapshot_hash="sha256:" + uuid.uuid4().hex * 2, schema_version="s"), **bad).save()
        assert refused.value.code == "catalog_record_malformed"
    assert other.version.version == 1


def test_the_registry_names_every_source_unreviewed_with_its_terms_and_sla():
    sources = {**catalogs.CATALOG_REGISTRY, **{k: catalogs.known(k) for k in (SUBMISSIONS, FACTS, SEGMENTS)}}
    assert all(feed.license_class == "unreviewed" for feed in sources.values())
    assert all(feed.licence_terms and feed.age_basis == "retrieval" for feed in sources.values())
    assert dict(catalogs.CATALOG_SLA_DAYS) == {
        ("AWS", "weekly"): 7, ("Azure", "weekly"): 7, ("GCP", "weekly"): 7, ("SEC-EDGAR", "daily"): 1,
        ("CFPB", "weekly"): 7, ("FTC", "weekly"): 7, ("SEC", "weekly"): 7, ("HHS-OCR", "weekly"): 7,
        ("OCC", "weekly"): 7, ("FDIC", "weekly"): 7, ("FRB", "weekly"): 7,
    }
    assert {k: (f.sla_days, f.use, f.freshness) for k, f in sources.items()} == {
        AWS: (7, "prefill", "gating"), AZURE: (7, "prefill", "gating"), GCP: (7, "prefill", "gating"),
        SUBMISSIONS: (1, "context", "informational"), FACTS: (1, "prefill", "informational"),
        SEGMENTS: (1, "context", "informational"),
        **{key: (7, "context", "informational") for key in ENFORCEMENT},
    }
    # Step 10's table and registry are unchanged, and no key is in both.
    assert not set(engine.REGISTRY) & set(catalogs.CATALOG_REGISTRY)
    assert all(catalogs.FORMAT_ASSUMED in f.dataset for k, f in sources.items() if k in ENFORCEMENT)
    # Each fits the source version's dataset column.
    assert all(len(f.dataset) <= FinancialSource._meta.get_field("dataset").max_length for f in sources.values())
    assert catalogs.known("sec-edgar-companyfacts-cik123") is None and catalogs.known(None) is None


# ====================================================================
# Keys, the switch, the as-of date
# ====================================================================


def test_the_gcp_key_and_the_sec_user_agent_go_into_the_request_only():
    outcome, transport = _fetch(GCP)
    for request, key in transport.sent:
        assert (request.key_in, request.key_name, key) == ("query", "key", GCP_KEY)
        assert GCP_KEY not in request.recorded_url
    assert GCP_KEY not in outcome.version.url
    outcome, transport = _fetch(SUBMISSIONS)
    ((request, key),) = transport.sent
    assert (request.key_in, request.key_name, key) == ("header", "User-Agent", SEC_AGENT)
    assert SEC_AGENT not in outcome.version.url


def test_the_outbound_transport_puts_a_header_key_in_its_header(monkeypatch):
    seen = {}

    class Response:
        status_code = 200

        def iter_content(self, size):
            yield b"{}"

        def close(self):
            pass

    def get(url, **kwargs):
        seen.update(url=url, **kwargs)
        return Response()

    monkeypatch.setattr(feeds.outbound, "get", get)
    request = catalogs.request_for(catalogs.source(SUBMISSIONS), as_of=TODAY, explicit=False, today=TODAY)
    assert feeds.OutboundTransport().send(request, SEC_AGENT) == b"{}"
    assert seen["headers"]["User-Agent"] == SEC_AGENT and SEC_AGENT in seen["also_withhold"]
    assert seen["params"] == [] and SEC_AGENT not in seen["url"]


@pytest.mark.parametrize("key, setting", [(GCP, "ECONOMICS_GCP_BILLING_API_KEY"), (FACTS, "ECONOMICS_SEC_USER_AGENT")])
def test_a_missing_key_refuses_and_does_nothing(key, setting, guard):  # noqa: F811 - step 10's guard, asked by name
    transport = Pages()
    outcome, _ = _fetch(key, transport=transport, live={**LIVE, setting: ""})
    assert (outcome.code, outcome.row) == ("source_key_missing", None)
    assert transport.sent == [] and guard == [] and not FinancialSourceFetch.objects.exists()


def test_live_fetching_is_off_unless_its_one_setting_is_true():
    for key in (AWS, CFPB, SUBMISSIONS):
        transport = Pages()
        outcome, _ = _fetch(key, transport=transport, live={**LIVE, "ECONOMICS_LIVE_FEEDS_ENABLED": "true"})
        assert (outcome.code, transport.sent) == ("live_feeds_disabled", [])
    assert not FinancialSourceFetch.objects.exists()


def test_a_catalog_serves_today_only():
    transport = Pages()
    outcome, _ = _fetch(AWS, transport=transport, as_of=TODAY - timedelta(days=3))
    assert (outcome.code, transport.sent) == ("as_of_unsupported", [])
    outcome, _ = _fetch(AWS, transport=transport, as_of=TODAY + timedelta(days=1))
    assert (outcome.code, transport.sent) == ("as_of_in_future", [])


def test_the_command_lists_and_fetches_the_catalogs(monkeypatch):
    class Fixed(feeds.OutboundTransport):
        def send(self, request, key):
            return pages_of(OCC)[0]

    monkeypatch.setattr(feeds, "OutboundTransport", Fixed)
    monkeypatch.setattr(feeds.timezone, "now", lambda: NOW)
    out = io.StringIO()
    with override_settings(**LIVE):
        call_command("fetch_financial_source", OCC, stdout=out)
    assert f"{OCC}: recorded, version 1 (unverified)" in out.getvalue() and "4 observation(s)" in out.getvalue()
    listed = io.StringIO()
    call_command("fetch_financial_source", "--list", stdout=listed)
    assert all(key in listed.getvalue() for key in (*engine.REGISTRY, *catalogs.CATALOG_REGISTRY))
    assert "sec-edgar-companyfacts-cik<10-digit CIK>" in listed.getvalue()


# ====================================================================
# SAFETY: no transaction is open while a request is in flight, and nothing is
# written before the last page is read
# ====================================================================


def test_no_transaction_is_open_while_a_page_is_asked():
    depth = len(connection.savepoint_ids)
    seen = []

    class Watched(Pages):
        def send(self, request, key):
            seen.append((len(connection.savepoint_ids), FinancialSource.objects.count(),
                         FinancialSourceFetch.objects.count()))
            return super().send(request, key)

    for key in (GCP, SUBMISSIONS):
        outcome, _ = _fetch(key, transport=Watched(*pages_of(key)))
        assert outcome.outcome == "recorded"
    _fetch(SEGMENTS, transport=Watched(*pages_of(SEGMENTS)))
    assert [d for d, _s, _f in seen] == [depth] * 4
    # GCP's second page was asked before anything of the first was written.
    assert seen[:2] == [(depth, 0, 0), (depth, 0, 0)]


def test_the_feed_modules_import_with_no_network():
    cases = (REPO / "tests" / "economics_no_network_cases.py").read_text(encoding="utf-8")
    for module in ("assurance.economics.engine.catalogs", "assurance.economics.engine.context",
                   "assurance.economics.context_service"):
        assert f'"{module}"' in cases, module


# ====================================================================
# 4. Freshness: cloud gating, EDGAR informational, enforcement context
# ====================================================================


@pytest.mark.parametrize("days, state", [(0, "fresh"), (7, "fresh"), (8, "stale"), (14, "stale"), (15, "blocked")])
def test_a_cloud_catalogs_age_runs_from_its_retrieval(reviewed, staging, days, state):
    reviewed(AWS)
    _fetch(AWS)
    seen = feeds.source_state(AWS, deployment=staging, as_of=TODAY + timedelta(days=days))
    assert (seen["state"], seen["age_days"], seen["sla_days"], seen["data_through"]) == (state, days, 7,
                                                                                         TODAY.isoformat())
    assert (seen["use"], seen["freshness"], seen["age_basis"]) == ("prefill", "gating", "retrieval")
    # Before it was retrieved, nothing covers the date.
    assert feeds.source_state(AWS, deployment=staging, as_of=TODAY - timedelta(days=1))["state"] == "missing"


def test_edgar_freshness_is_informational(reviewed, staging):
    reviewed(FACTS)
    _fetch(FACTS)
    for days, age_state in ((0, "fresh"), (1, "fresh"), (2, "stale"), (30, "blocked")):
        seen = feeds.source_state(FACTS, deployment=staging, as_of=TODAY + timedelta(days=days))
        assert (seen["state"], seen["age_state"], seen["age_days"], seen["sla_days"]) == (
            "informational", age_state, days, 1)
    # A source with no version a run may use is still missing.
    assert feeds.source_state(SUBMISSIONS, deployment=staging, as_of=TODAY)["state"] == "missing"
    # And the receipt check takes an informational source as it stands.
    assert feeds.receipt_refusal([FACTS], staging, TODAY + timedelta(days=30)) is None


def test_an_informational_source_never_lowers_a_grade_or_makes_a_claim_stale():
    inputs = {"parameters": {"annual_revenue": {"evidence_ref": f"financial-source:{FACTS} v1"}}}
    roles = {"annual_revenue": set(validity_service.GRADED_ROLES)}
    held = {FACTS: {"source_key": FACTS, "state": "informational", "age_state": "blocked"}}
    sources, lowered, claim = validity_service._feed_freshness(inputs, roles, {"feed_sources": held})
    assert (lowered, claim, sources[0]["age_state"]) == ([], "current", "blocked")


def test_a_context_source_never_stops_a_receipt_it_is_not_cited_by(reviewed, staging):
    reviewed(CFPB, SUBMISSIONS)
    _fetch(CFPB)
    _fetch(SUBMISSIONS)
    later = TODAY + timedelta(days=60)
    for key in (CFPB, SUBMISSIONS):
        seen = feeds.source_state(key, deployment=staging, as_of=later)
        assert (seen["state"], seen["age_state"], seen["use"]) == ("informational", "blocked", "context")
    # A figure never rests on one: one that does anyway fails closed.
    assert feeds.receipt_refusal([CFPB], staging, TODAY)[0] == "context_only_source"
    assert feeds.states_for([CFPB], deployment=staging, as_of=TODAY)[CFPB]["reason"] == "context_only_source"


# ====================================================================
# 3. CONTEXT ONLY: a prefill is a suggestion a person accepts
# ====================================================================


def _rows():
    return (CustomerParameterSet.objects.count(), FinancialParameter.objects.count(), LossComponent.objects.count(),
            FinancialSource.objects.count(), FinancialSourceRecords.objects.count(),
            FinancialSourceFetch.objects.count())


AWS_STORAGE = ["FIXTURESKUSTD0001.JRTCKXETXF.6YS6EN2CT7", "FIXTURESKUSTD0001.JRTCKXETXF.PGHJ3S3EYE",
               "FIXTURESKUSTD0001.JRTCKXETXF.D42MF2PVJS"]


def _suggest(deployment, **query):
    return context_service.suggest(deployment, {k: v if isinstance(v, list) else [v] for k, v in query.items()},
                                   now=NOW)


def test_a_cloud_cost_suggestion_reads_the_prices_and_writes_nothing(reviewed, staging):
    reviewed(AWS)
    fetched, _ = _fetch(AWS)
    before = _rows()
    answer = _suggest(staging, source=AWS, target="remediation_license_cost_per_year", observation=AWS_STORAGE,
                      quantity="120000")
    assert _rows() == before  # a suggestion writes nothing
    assert answer["status"] == "suggestion" and answer["statement"] == rules.SUGGESTION_STATEMENT
    entry = answer["entry"]
    # 120,000 GB-months a year at the lowest, median and highest of the three tiers.
    assert (entry["low"], entry["base"], entry["high"], entry["currency"]) == ("2520", "2640", "2760", "USD")
    assert (entry["unit"], entry["source_type"], entry["effective_date"]) == ("money_per_year", "EXPERT_ESTIMATE",
                                                                             TODAY.isoformat())
    assert entry["evidence_ref"].startswith(f"financial-source:{AWS} v1 {fetched.version.snapshot_hash} ")
    assert engine.feed_reference(entry["evidence_ref"]) == AWS
    assert [p["observation_id"] for p in answer["rests_on"]] == sorted(AWS_STORAGE)
    assert answer["version"]["license_class"] == "open" and answer["version"]["age_days"] == 0


def test_a_suggestion_is_refused_for_what_it_cannot_rest_on(reviewed, staging):
    reviewed(AWS)
    _fetch(AWS)
    cases = [
        ({"source": AWS, "target": "annual_revenue", "observation": AWS_STORAGE[0], "quantity": "1"},
         "suggestion_target_unrecognised"),
        ({"source": AWS, "target": "vendor_exit_cost", "observation": [AWS_STORAGE[0],
                                                                       "FIXTURESKUPUT0003.JRTCKXETXF.6YS6EN2CT7"],
          "quantity": "1"}, "suggestion_units_differ"),
        ({"source": AWS, "target": "vendor_exit_cost", "observation": "no-such-price", "quantity": "1"},
         "suggestion_observation_missing"),
        ({"source": AWS, "target": "vendor_exit_cost", "observation": AWS_STORAGE[0], "quantity": "1e3"},
         "suggestion_quantity_malformed"),
        ({"source": AWS, "target": "vendor_exit_cost", "observation": AWS_STORAGE[0], "quantity": "0"},
         "suggestion_quantity_malformed"),
        ({"source": CFPB, "target": "vendor_exit_cost"}, "suggestion_source_unrecognised"),
        ({"source": AZURE, "target": "vendor_exit_cost", "observation": "x", "quantity": "1"}, "source_missing"),
        ({"source": AWS, "target": "vendor_exit_cost", "observation": AWS_STORAGE[0], "quantity": "1",
          "as_of": "2026-01-01"}, "suggestion_malformed"),
    ]
    before = _rows()
    for query, code in cases:
        with pytest.raises(context_service.Refused) as refused:
            _suggest(staging, **query)
        assert refused.value.code == code, (query, refused.value)
    assert _rows() == before


def test_an_unreviewed_licence_gives_no_suggestion(staging):
    _fetch(AWS)
    with pytest.raises(context_service.Refused) as refused:
        _suggest(staging, source=AWS, target="vendor_exit_cost", observation=AWS_STORAGE[0], quantity="1")
    assert refused.value.code == "unreviewed_license"


def test_a_person_accepts_a_suggestion_by_recording_it(reviewed, staging, people):
    """Accepted: the entry recorded, signed in, as an EXPERT_ESTIMATE variable of a
    parameter-set version whose evidence names the snapshot version. Nothing else
    may hold a figure resting on a cloud price."""
    reviewed(AWS)
    _fetch(AWS)
    entry = _suggest(staging, source=AWS, target="vendor_exit_cost", observation=AWS_STORAGE, quantity="5000")["entry"]
    version = CustomerParameterSet.record(staging, "q4", {"variables": {"vendor_exit_cost": entry}},
                                          author=people["analyst"])
    (row,) = version.parameter_rows()
    assert (row.source_type, row.evidence_ref, row.low, row.high) == ("EXPERT_ESTIMATE", entry["evidence_ref"],
                                                                      "105", "115")
    assert version.author_username == "ann"
    refusals = [
        # No person records it: a machine never accepts a suggestion.
        (lambda: CustomerParameterSet.record(staging, "q5", {"variables": {"vendor_exit_cost": entry}}, author=None),
         "prefill_not_accepted"),
        # Another source type than the person's own estimate.
        (lambda: CustomerParameterSet.record(staging, "q5", {"variables": {"vendor_exit_cost": {
            **entry, "source_type": "OFFICIAL_PUBLIC"}}}, author=people["analyst"]), "prefill_not_accepted"),
        # A variable the catalog does not prefill.
        (lambda: CustomerParameterSet.record(staging, "q5", {"variables": {"legal_retainer": {
            **entry, "unit": "money"}}}, author=people["analyst"]), "prefill_not_accepted"),
    ]
    for write, code in refusals:
        with pytest.raises(EconomicsRefused) as refused:
            write()
        assert refused.value.code == code
    scenario = FinancialScenario.objects.create(deployment=staging, title="s", author=people["analyst"])
    with pytest.raises(EconomicsRefused) as refused:  # never a scenario parameter
        FinancialParameter.objects.create(scenario=scenario, name="recovery.cost", unit="money", currency="USD",
                                          source_type="EXPERT_ESTIMATE", low="1", base="2", high="3",
                                          evidence_ref=entry["evidence_ref"], effective_date=TODAY)
    assert refused.value.code == "prefill_not_accepted"
    assert CustomerParameterSet.objects.count() == 1


def test_a_person_accepts_through_the_parameter_set_route(reviewed, staging, people):
    reviewed(AWS)
    _fetch(AWS)
    client = _client(people["analyst"])
    url = f"/api/assurance/deployments/{staging.uuid}/economics/suggestions/"
    query = f"?source={AWS}&target=vendor_exit_cost&quantity=5000&" + "&".join(f"observation={o}" for o in AWS_STORAGE)
    with override_settings():
        shown = client.get(url + query)
    assert shown.status_code == 200, shown.content
    assert shown.content == json.dumps(json.loads(shown.content), sort_keys=True, separators=(",", ":"),
                                       ensure_ascii=False).encode()
    assert not CustomerParameterSet.objects.exists()  # shown, not recorded
    entry = json.loads(shown.content)["entry"]
    recorded = client.post(f"/api/assurance/deployments/{staging.uuid}/economics/parameter-sets/q4/versions/",
                           {"variables": {"vendor_exit_cost": entry}}, format="json")
    assert recorded.status_code == 201, recorded.content
    (row,) = FinancialParameter.objects.all()
    assert (row.source_type, row.evidence_ref) == ("EXPERT_ESTIMATE", entry["evidence_ref"])


def test_edgar_suggests_a_listed_companys_revenue_and_margin(reviewed, staging):
    reviewed(FACTS, SUBMISSIONS)
    _fetch(SUBMISSIONS)
    fetched, _ = _fetch(FACTS)
    before = _rows()
    revenue = _suggest(staging, source=FACTS, target="annual_revenue")
    margin = _suggest(staging, source=FACTS, target="operating_margin")
    assert _rows() == before
    # FY2025, FY2024 (as restated in the FY2025 10-K) and FY2023 (Revenues: the only
    # revenue concept that year reports); the newest is the base.
    assert (revenue["entry"]["low"], revenue["entry"]["base"], revenue["entry"]["high"]) == (
        "1200000000", "1410000000", "1410000000")
    assert revenue["entry"]["effective_date"] == "2025-11-07" and revenue["entry"]["unit"] == "money_per_year"
    assert {p["period_end"]: p["value"] for p in revenue["rests_on"]} == {
        "2025-09-27": "1410000000", "2024-09-28": "1348500000", "2023-09-30": "1200000000"}
    # 239.7/1410 = 0.17; 216/1348.5 = 0.1602; 180/1200 = 0.15.
    assert (margin["entry"]["low"], margin["entry"]["base"], margin["entry"]["high"]) == ("0.15", "0.17", "0.17")
    assert "currency" not in margin["entry"] and margin["company"]["tickers"] == ["FXMP"]
    assert margin["entry"]["evidence_ref"].startswith(f"financial-source:{FACTS} v1 {fetched.version.snapshot_hash}")


def test_edgar_prefills_a_public_company_only(reviewed, staging):
    reviewed(FACTS, SUBMISSIONS)
    _fetch(FACTS)
    with pytest.raises(context_service.Refused) as refused:  # no filing watch: nothing says it is listed
        _suggest(staging, source=FACTS, target="annual_revenue")
    assert refused.value.code == "suggestion_not_public"
    _fetch(SUBMISSIONS, [_json_edit(pages_of(SUBMISSIONS)[0], lambda d: d.update(tickers=[], exchanges=[]))])
    with pytest.raises(context_service.Refused) as refused:
        _suggest(staging, source=FACTS, target="annual_revenue")
    assert refused.value.code == "suggestion_not_public"


def test_a_negative_margin_is_never_suggested():
    facts = [f for f in _parse(FACTS).records if f.concept != "us-gaap:OperatingIncomeLoss"]
    loss = [dataclasses.replace(f, concept="us-gaap:OperatingIncomeLoss", value=-f.value)
            for f in facts if f.form == "10-K"]
    entity = catalogs.CompanyEntity(CIK, "FIXTURE EXAMPLE CORP", "operating", ("FXMP",), ("Nasdaq",))
    with pytest.raises(rules.SuggestionRefused) as refused:
        rules.suggest_from_facts("operating_margin", facts + loss, entity, source_key=FACTS, version=1,
                                 snapshot_hash="sha256:" + "0" * 64)
    assert refused.value.code == "suggestion_out_of_range"


# ====================================================================
# 3. CONTEXT ONLY: an enforcement record is precedent, never a figure
# ====================================================================


def _with_penalty(people, deployment, evidence):
    """A scenario whose regulatory lump sum would take an enforcement record's stated
    penalty as its amount, citing it."""
    scenario = FinancialScenario.objects.create(deployment=deployment, title="precedent", author=people["analyst"])
    return FinancialParameter.objects.create(
        scenario=scenario, name="fine.amount", unit="money", currency="USD", source_type="OFFICIAL_PUBLIC",
        low="1250000", base="1250000", high="1250000", evidence_ref=evidence, effective_date=TODAY,
    )


@pytest.mark.parametrize("evidence", [
    f"financial-source:{OCC} the OCC's stated civil money penalty",
    f"financial-source:{CFPB}",
    f"the stated penalty, per {OCC} line 1",
    f"Financial-Source:{FRB} as stated",
    f"see {SUBMISSIONS}",
    f"financial-source:{SEGMENTS} segment revenue",
])
def test_no_figure_rests_on_or_names_a_context_source(people, staging, evidence):
    with pytest.raises(EconomicsRefused) as refused:
        _with_penalty(people, staging, evidence)
    assert refused.value.code == "context_only_source"
    with pytest.raises(EconomicsRefused) as refused:
        CustomerParameterSet.record(staging, "q4", {"variables": {"legal_retainer": _entry(
            "money", "1250000", source_type="EXPERT_ESTIMATE", evidence_ref=evidence)}}, author=people["analyst"])
    assert refused.value.code == "context_only_source"
    assert not FinancialParameter.objects.exists() and not CustomerParameterSet.objects.exists()


def test_the_parameter_set_route_refuses_an_enforcement_figure(people, staging):
    answer = _client(people["analyst"]).post(
        f"/api/assurance/deployments/{staging.uuid}/economics/parameter-sets/q4/versions/",
        {"variables": {"legal_retainer": _entry("money", "1250000", evidence_ref=f"financial-source:{OCC}")}},
        format="json",
    )
    assert answer.status_code == 400 and answer.json()["code"] == "context_only_source"
    assert not CustomerParameterSet.objects.exists()


GAMMA = {"id": "gamma", "version": 1, "params": {"shape": "4", "scale": "25000"}}
POISSON = {"id": "poisson", "version": 1, "params": {"rate": "2"}}


def _scenario(deployment, author, *, as_of, variables=None, recovery_cost=None, set_author=None):
    """A scenario version as rows (as step 10's tests build one): a notification
    component, a regulatory lump sum, and, where ``recovery_cost`` names a variable, a
    recovery component reading it as each vendor's exit cost. SYNTHETIC /
    ILLUSTRATIVE."""
    held = {
        "notification_unit_cost": _entry("money_per_unit", "2", effective_date="2026-09-01"),
        "notification_fixed_cost": _entry("money", "40000", effective_date="2026-09-01"),
        **(variables or {}),
    }
    pset = CustomerParameterSet.record(deployment, "bank_prod_2026q4", {"variables": held},
                                       author=set_author or author)
    scenario = FinancialScenario.objects.create(deployment=deployment, title="Cross-customer exposure", author=author,
                                                system_fingerprint="ab" * 32)

    def parameter(name, unit, low, base, high, source, ref, distribution=None):
        return FinancialParameter.objects.create(
            scenario=scenario, name=name, unit=unit, source_type=source, currency="USD" if unit == "money" else "",
            low=low, base=base, high=high, evidence_ref=ref, effective_date=date(2026, 9, 1), distribution=distribution,
        )

    affected = parameter("exposure.affected_customers", "count", "20000", "50000", "120000", "EXPERT_ESTIMATE",
                         "SYNTHETIC / ILLUSTRATIVE: made up")
    amount = parameter("exposure.regulatory_response_cost", "money", "0", "100000", "500000", "OFFICIAL_PUBLIC",
                       "a regulator's published schedule (SYNTHETIC)", GAMMA)
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
    if recovery_cost is not None:
        vendors = parameter("exposure.vendors", "count", "1", "2", "3", "EXPERT_ESTIMATE", "SYNTHETIC: made up")
        LossComponent.objects.create(
            loss_event=event, component_key="recovery", family="recovery", formula_id="per_affected_plus_fixed",
            formula_version=1, as_of=as_of,
            cited_parameters={"affected": str(vendors.uuid), "unit_cost": str(rows[recovery_cost].uuid),
                              "fixed_cost": str(rows["notification_fixed_cost"].uuid)},
        )
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


def _loss(scenario):
    return [
        (component.component_key, component.status, component.low, component.base, component.high)
        for component in LossComponent.objects.filter(loss_event__scenario=scenario).order_by("component_key")
    ]


def test_no_code_path_writes_an_enforcement_amount_into_a_loss_component(reviewed, staging, people):
    """The behaviour: a scenario's loss components and its simulated result are the
    same with every enforcement listing fetched, its records stored and listed as the
    scenario's precedents, as without; nothing the listing reads is written; and the
    only way an amount could reach a component -- a figure resting on the record --
    is refused at every writer (``test_no_figure_rests_on_or_names_a_context_source``)."""
    before_scenario = _scenario(staging, people["analyst"], as_of=TODAY)
    before = simulated(before_scenario, draws=2_000)
    loss_before = _loss(before_scenario)
    reviewed(*ENFORCEMENT)
    for key in ENFORCEMENT:
        assert _fetch(key)[0].outcome == "recorded"
    penalties = [r.civil_money_penalty for k in ENFORCEMENT for r in _parse(k).records if r.civil_money_penalty]
    assert penalties  # the listings do state amounts
    rows = _rows()
    listed = context_service.precedents(staging, before_scenario, now=NOW)
    assert listed["precedents"] and _rows() == rows
    assert _loss(before_scenario) == loss_before
    # The same run asked again is the run recorded: its inputs did not move.
    again = simulated(before_scenario, draws=2_000)
    assert (again.pk, again.input_digest, again.result_digest) == (before.pk, before.input_digest, before.result_digest)
    stated = {str(p) for p in penalties}
    for component in LossComponent.objects.all():
        assert not {component.low, component.base, component.high} & stated


#: The modules that compute a loss, a run, a card, a receipt or a report: none of
#: them may read a catalog's records, the context rules or the precedent listing.
LOSS_PATH = (
    "engine/formulas.py", "engine/loss.py", "engine/simulation.py", "engine/scenario_simulation.py", "engine/twins.py",
    "engine/sensitivity.py", "engine/remediation.py", "engine/parameters.py", "engine/parameter_set.py",
    "engine/templates.py", "engine/grade.py", "engine/charts.py", "builder.py", "simulation_service.py", "report.py",
    "remediation_service.py", "charts_service.py", "validity_service.py", "receipt_service.py", "scenario_api.py",
    "report_api.py", "remediation_api.py", "api.py",
)
#: Names only the context path may use.
CONTEXT_NAMES = ("EnforcementRecord", "civil_money_penalty", "stated_amounts", "precedent", "FinancialSourceRecords",
                 "records_of", "suggest_cloud_cost", "suggest_from_facts")


def _names(path: Path) -> set[str]:
    """Every name and attribute ``path`` uses, and every name it imports."""
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Name):
            found.add(node.id)
        elif isinstance(node, ast.Attribute):
            found.add(node.attr)
        elif isinstance(node, ast.alias):
            found.add(node.name.split(".")[-1])
    return found


def _imported(path: Path) -> set[str]:
    """Every module ``path`` imports, by its last part, and every name it imports
    from one (``from .engine import catalogs`` gives ``engine`` and ``catalogs``)."""
    found = set()
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            found |= {alias.name.split(".")[-1] for alias in node.names}
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                found.add(node.module.split(".")[-1])
            found |= {alias.name for alias in node.names}
    return found


def test_no_loss_path_module_reads_an_enforcement_record():
    """Read, not run: no module on the path to a loss, a run, a card, a receipt or a
    report imports the catalogs, the context rules or the context service, or names
    an enforcement record, its amounts, a records row or the precedent listing. The
    only modules that name an enforcement record are the catalogs (which read one),
    the context rules (which list one) and the context service (which serves the
    list)."""
    for relative in LOSS_PATH:
        assert not _imported(ECONOMICS / relative) & {"catalogs", "context", "context_service"}, relative
        names = _names(ECONOMICS / relative)
        assert not names & set(CONTEXT_NAMES), (relative, names & set(CONTEXT_NAMES))
    naming = set()
    for path in sorted(ECONOMICS.rglob("*.py")):
        if {"EnforcementRecord", "civil_money_penalty"} & _names(path):
            naming.add(path.relative_to(ECONOMICS).as_posix())
    assert naming == {"engine/catalogs.py", "engine/context.py", "context_service.py"}
    holders = {p.relative_to(ECONOMICS).as_posix() for p in sorted(ECONOMICS.rglob("*.py"))
               if "FinancialSourceRecords" in _names(p)}
    assert holders == {"models.py", "snapshots.py"}


def test_a_figure_written_past_the_model_that_rests_on_enforcement_never_gets_a_receipt(reviewed, staging, people):
    """The base manager writes past every check (spec, section 10). A figure written
    that way, resting on an enforcement listing, fails closed: the card records the
    source missing, the grade is lowered, and the receipt is refused
    (``context_only_source``)."""
    reviewed(OCC)
    _fetch(OCC)
    scenario = _scenario(staging, people["analyst"], as_of=TODAY)
    amount = FinancialParameter.objects.get(scenario=scenario, name="exposure.regulatory_response_cost")
    FinancialParameter._base_manager.filter(pk=amount.pk).update(evidence_ref=f"financial-source:{OCC} line 1")
    result = simulated(scenario, draws=2_000)
    outcome = validity_service.issue_card(result)
    card = outcome.card
    assert card.card["issued"]["feed_sources"][OCC]["reason"] == "context_only_source"
    assert card.card["freshness"]["claim"] == "stale"
    assert g.STALE_SOURCE in [d["rule"] for d in card.card["fields"]["confidence_grade"]["downgrades"]]
    receipt = _issue(result)
    assert (receipt.receipt, receipt.code) == (None, "context_only_source")
    assert not FinancialExposureReceipt.objects.exists()


def _issue(result):
    key = Ed25519PrivateKey.generate()
    ring = core.receipt_keyring([_raw(key)], other_roles={})
    return receipt_service.issue_receipt(result, signer=_signer(key), keyring=ring)


def test_a_scenario_lists_its_precedents_with_their_citations(reviewed, staging, people):
    reviewed(CFPB, FTC, OCC, FDIC)  # SEC, HHS OCR and the Fed stay unreviewed
    for key in (CFPB, FTC, SEC, HHS, OCC, FDIC, FRB):
        _fetch(key)
    scenario = _scenario(staging, people["analyst"], as_of=TODAY)
    rows = _rows()
    listed = context_service.precedents(staging, scenario, now=NOW + timedelta(days=9))
    assert _rows() == rows
    assert listed["statement"] == rules.PRECEDENT_STATEMENT and "never summed into a loss" in listed["statement"]
    assert listed["families"] == ["notification", "regulatory_compliance"]
    keys = {entry["source"]["key"] for entry in listed["precedents"]}
    assert keys == {CFPB, FTC, OCC, FDIC}
    assert {w["key"]: w["because"] for w in listed["withheld"]} == {
        SEC: "unreviewed_license", HHS: "unreviewed_license", FRB: "unreviewed_license"}
    dates = [entry["date"] for entry in listed["precedents"]]
    assert dates == sorted(dates, reverse=True)
    penalty = next(e for e in listed["precedents"]
                   if e["source"]["key"] == OCC and e["stated_amounts"]["civil_money_penalty"])
    assert penalty["stated_amounts"] == {"currency": "USD", "civil_money_penalty": "1250000", "restitution": None,
                                         "settlement": None, "as": "stated by the listing, not a figure of this scenario"}
    assert penalty["citation"] == {"url": "https://www.occ.gov/static/enforcement-actions/ea2026-099.pdf",
                                   "text": "OCC Civil Money Penalty, Fixture National Bank, 2026-09-17"}
    assert all(isinstance(v, (str, type(None))) for e in listed["precedents"] for v in e["stated_amounts"].values())
    ages = {s["key"]: (s["age_days"], s["age_state"]) for s in listed["sources"]}
    assert ages[CFPB] == (9, "stale")  # shown, never acted on


def test_a_scenario_with_no_regulatory_family_lists_none(reviewed, staging, people):
    reviewed(*ENFORCEMENT)
    _fetch(OCC)
    scenario = FinancialScenario.objects.create(deployment=staging, title="none", author=people["analyst"])
    listed = context_service.precedents(staging, scenario, now=NOW)
    assert (listed["families"], listed["precedents"], listed["sources"]) == ([], [], [])


def test_the_context_rules_are_the_models():
    """The models spell the context codes (their module is not on Django's load path);
    they are the engine's, word for word. The kinds too. The model's cheap filter
    lets through every step-11 key's evidence."""
    for code in ("context_only_source", "prefill_not_accepted"):
        assert econ_models.CONTEXT_RECORD_REFUSALS[code] == rules.REFUSALS[code]
    assert econ_models.CATALOG_KINDS == catalogs.KINDS
    for key in (*catalogs.CATALOG_REGISTRY, SUBMISSIONS, FACTS, SEGMENTS):
        assert econ_models._MAY_NAME_A_CATALOG.search(key), key
    assert set(rules.context_keys()) == set(ENFORCEMENT)


# ====================================================================
# The card and the receipt: a cloud-prefilled figure feeds them, as step 10's do
# ====================================================================


def _prefilled(reviewed, deployment, people, *, as_of):
    reviewed(AWS)
    _fetch(AWS)
    entry = _suggest(deployment, source=AWS, target="vendor_exit_cost", observation=AWS_STORAGE,
                     quantity="5000")["entry"]
    scenario = _scenario(deployment, people["analyst"], as_of=as_of, variables={"vendor_exit_cost": entry},
                         recovery_cost="vendor_exit_cost")
    result = simulated(scenario, draws=5_000)
    outcome = validity_service.issue_card(result)
    assert outcome.card is not None, (outcome.code, outcome.detail)
    return result, outcome.card


def test_a_fresh_cloud_prefilled_figure_keeps_its_grade_and_its_receipt(reviewed, staging, people):
    result, card = _prefilled(reviewed, staging, people, as_of=TODAY)
    freshness = card.card["fields"]["data_freshness"]
    (source,) = freshness["sources"]
    assert (source["source_key"], source["state"], source["feeds"]) == (AWS, "fresh", ["vendor_exit_cost"])
    assert freshness["claim"] == "current" and validity_service.reproduces(card)
    issued = _issue(result)
    assert issued.code is None and issued.receipt is not None, (issued.code, issued.detail)


def test_a_blocked_cloud_catalog_stops_the_receipt_of_a_figure_resting_on_it(reviewed, staging, people):
    result, card = _prefilled(reviewed, staging, people, as_of=TODAY + timedelta(days=15))
    (source,) = card.card["fields"]["data_freshness"]["sources"]
    assert (source["state"], source["age_days"]) == ("blocked", 15)
    assert card.card["freshness"]["claim"] == "stale"
    assert g.STALE_SOURCE in [d["rule"] for d in card.card["fields"]["confidence_grade"]["downgrades"]]
    receipt = _issue(result)
    assert (receipt.receipt, receipt.code) == (None, "source_stale")


# ====================================================================
# The routes
# ====================================================================


def _suggestions(client, deployment, query=""):
    return client.get(f"/api/assurance/deployments/{deployment.uuid}/economics/suggestions/{query}")


def _precedents(client, deployment, scenario, query=""):
    return client.get(
        f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario.uuid}/precedents/{query}")


def test_the_suggestion_route_reads_and_refuses_with_a_code(reviewed, staging, people):
    reviewed(AWS)
    _fetch(AWS)
    viewer = _client(people["owner"])
    query = f"?source={AWS}&target=vendor_exit_cost&quantity=1&observation={AWS_STORAGE[0]}"
    answer = _suggestions(viewer, staging, query)  # a viewer reads
    assert answer.status_code == 200 and json.loads(answer.content)["entry"]["base"] == "0.02"
    refused = _suggestions(viewer, staging, query + "&quantity=2")
    assert refused.status_code == 400 and json.loads(refused.content)["code"] == "suggestion_malformed"
    refused = _suggestions(viewer, staging, f"?source={OCC}&target=annual_revenue")
    body = json.loads(refused.content)
    assert (refused.status_code, body["code"]) == (400, "suggestion_source_unrecognised") and body["meaning"]
    theirs = Deployment.objects.create(name="theirs", owner=people["stranger"])
    assert _suggestions(viewer, theirs, query).status_code == 404
    assert APIClient().get(f"/api/assurance/deployments/{staging.uuid}/economics/suggestions/{query}").status_code == 401
    assert viewer.post(f"/api/assurance/deployments/{staging.uuid}/economics/suggestions/", {}).status_code == 405
    assert not CustomerParameterSet.objects.exists()


def test_the_precedents_route(reviewed, staging, people):
    reviewed(OCC)
    _fetch(OCC)
    scenario = _scenario(staging, people["analyst"], as_of=TODAY)
    viewer = _client(people["owner"])
    first, second = _precedents(viewer, staging, scenario), _precedents(viewer, staging, scenario)
    assert first.status_code == 200 and first.content == second.content
    body = json.loads(first.content)
    assert first.content == json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    assert body["scenario"] == str(scenario.uuid) and len(body["precedents"]) == 4
    assert _precedents(viewer, staging, scenario, "?agency=OCC").status_code == 400
    theirs = Deployment.objects.create(name="theirs", owner=people["stranger"])
    assert _precedents(viewer, theirs, scenario).status_code == 404
    elsewhere = FinancialScenario.objects.create(deployment=theirs, title="x", author=people["analyst"])
    assert _precedents(viewer, staging, elsewhere).status_code == 404


def test_the_context_routes_are_not_stops():
    from safety import stops

    for name in ("deployment-economics-suggestions", "deployment-economics-scenario-precedents"):
        assert name in stops.NOT_STOPS and set(stops.NOT_STOPS[name]) == {"GET"}
        assert name not in stops.STOP_ROUTES and name not in stops.EXEMPT_ROUTES


# ====================================================================
# 5. Data health lists them
# ====================================================================


def test_data_health_lists_the_catalogs_with_what_each_may_do(reviewed, staging, people, monkeypatch):
    reviewed(AWS, FACTS, CFPB)
    monkeypatch.setattr(feeds.timezone, "now", lambda: NOW + timedelta(days=10))
    _fetch(AWS)
    _fetch(FACTS)
    _fetch(CFPB)
    _fetch(OCC, [b"not,the,header\r\n"])
    entry = {**_entry("money_per_unit", "100", source_type="EXPERT_ESTIMATE"),
             "evidence_ref": f"financial-source:{GCP} v1"}
    CustomerParameterSet.record(staging, "q4", {"variables": {"vendor_exit_cost": entry}}, author=people["analyst"])
    answer = _client(people["owner"]).get(f"/api/assurance/deployments/{staging.uuid}/economics/data-health/")
    assert answer.status_code == 200
    body = json.loads(answer.content)
    listed = {s["source_key"]: s for s in body["catalog_sources"]}
    assert set(listed) == {*catalogs.CATALOG_REGISTRY, FACTS}
    assert (listed[AWS]["state"], listed[AWS]["age_days"], listed[AWS]["effect"]) == (
        "stale", 10, feeds.EFFECTS["stale"])
    assert (listed[FACTS]["state"], listed[FACTS]["age_state"], listed[FACTS]["effect"]) == (
        "informational", "blocked", feeds.INFORMATIONAL_EFFECT)
    assert (listed[CFPB]["state"], listed[CFPB]["effect"]) == ("informational", feeds.CONTEXT_EFFECT)
    assert listed[OCC]["last_fetch_failure"]["code"] == "feed_malformed"
    assert listed[GCP]["unknowns"] == [{"parameter": "vendor_exit_cost", "in": "parameter-set:q4:v1",
                                        "because": "source_missing"}]
    assert all(s["licence_terms"] for s in body["catalog_sources"])
    assert body["catalog_freshness_sla_days"]["AWS weekly"] == 7
    assert body["catalog_freshness_sla_days"]["SEC-EDGAR daily"] == 1
    assert body["unregistered_citations"] == []  # a catalog citation is a registered one
    # Step 10's list is unchanged.
    assert {s["source_key"] for s in body["sources"]} == set(engine.REGISTRY)


# ====================================================================
# The spec
# ====================================================================


def test_the_spec_names_every_code_route_and_source():
    text = " ".join(SPEC.read_text(encoding="utf-8").split())
    codes = [
        "feed_over_limit", "filing_unknown", *rules.REFUSALS, "catalog_record_malformed",
        "deployment-economics-suggestions", "deployment-economics-scenario-precedents",
        *catalogs.CATALOG_REGISTRY, "sec-edgar-submissions-cik", "ECONOMICS_GCP_BILLING_API_KEY",
        "ECONOMICS_SEC_USER_AGENT", "informational", "catalog_sources", "0072_financial_source_records",
    ]
    for code in codes:
        assert f"`{code}" in text, code
    for phrase in (
        "## 30. The cloud price catalogs, SEC EDGAR and enforcement (MVP step 11)",
        "never automatic penalty prediction",
        "format-faithful, NOT a recorded response; replace with a recording (owner)",
        "no transaction is open while a request is in flight",
        "a suggestion, not a parameter",
    ):
        assert phrase in text, phrase
