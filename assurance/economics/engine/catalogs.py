"""The cloud price catalogs, SEC EDGAR and the regulators' enforcement listings
(MVP step 11; ``docs/economics/spec-v1.md``, section 30).

Step 10's feed framework, extended to three more families of source, each read
from its provider's published format into a list of RECORDS that a source version
holds (:class:`.snapshot.Snapshot`'s ``records``), never into FX or cost-index
observations a run reads:

- **Cloud price catalogs** (``cloud_price``): the AWS Price List bulk offer file
  (``aws``), the Azure Retail Prices API's JSON pages (``azure``) and the Google
  Cloud Billing Catalog's SKU pages (``gcp``). Each gives a
  :class:`PriceObservation`: provider, SKU, region, unit, the USD price per unit,
  the date it is effective from, and the usage tier it starts at.
- **SEC EDGAR** (one company per source, by CIK): the submissions JSON, a FILING
  WATCH (``filing_watch``: the company, its tickers and every recent filing with its
  form, filing date and accession number); the XBRL ``companyfacts`` JSON
  (``company_fact``: revenue and operating income by period, each as filed, with
  the form, filing date and accession number); and segment revenue by period, read
  from the newest periodic filing's own XBRL instance (``companyfacts`` holds no
  dimensioned fact, so no segment).
- **Enforcement** (``enforcement``): CFPB, FTC privacy and security cases, SEC
  litigation releases, HHS OCR, OCC, FDIC and the Federal Reserve. Each gives an
  :class:`EnforcementRecord`: agency, date, respondent, category, the civil money
  penalty, restitution and settlement amounts the listing STATES in a field of its
  own (never read out of prose: ``None`` where it states none), and the citation's
  URL and text.

What each may do is the source's ``use`` (spec, section 30.5): a cloud price or an
EDGAR fact may PREFILL a parameter only as a suggestion a person accepts
(:mod:`.context`); a filing watch, segment revenue and every enforcement record are
CONTEXT, never a figure. Enforcement amounts are never a fine or penalty figure
and never reach a loss (:func:`.context.citation_refusal`).

Every adapter is all or nothing, as step 10's are: an answer that is not its
documented (or, where the README says so, ASSUMED) format, is for another offer,
service, region, company or unit than was asked, says the request failed, holds a
value not in its documented form, is cut short, or holds more than one version may
(:data:`MAX_RECORDS`; ``feed_over_limit``), is refused with a code and nothing of
it is kept. A multi-page answer (Azure, GCP) is read whole -- every page, at most
:data:`MAX_PAGES` -- before anything is parsed, and refused whole.

The response hash, which the store deduplicates on, is the SHA-256 of the
normalised payload (:data:`NORMALISATION`). JSON numbers here are read as
``Decimal`` from their own text (a price is never a float), and a JSON document is
re-serialised canonically. Pure: no Django, no I/O.
"""

from __future__ import annotations

import email.utils
import hashlib
import io
import json
import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from urllib.parse import parse_qsl, urlsplit

from .feeds import MAX_RESPONSE_BYTES, FeedRefused, FeedRequest, FeedSource, _csv, _day
from .money import MoneyRefused, decimal_text, parse_decimal
from .provenance import TrustTier
from .snapshot import Snapshot

# ------------------------------------------------------------------ vocabulary

#: The kind of record a source holds.
CLOUD_PRICE, COMPANY_FACT, FILING_WATCH, ENFORCEMENT = "cloud_price", "company_fact", "filing_watch", "enforcement"
KINDS = (CLOUD_PRICE, COMPANY_FACT, FILING_WATCH, ENFORCEMENT)
#: What a figure may do with a source (``FeedSource.use``).
FIGURE, PREFILL, CONTEXT = "figure", "prefill", "context"
USES = (FIGURE, PREFILL, CONTEXT)
#: Whether a source's freshness acts on the figures resting on it.
GATING, INFORMATIONAL = "gating", "informational"
#: What a source's age runs from.
OBSERVATION, RETRIEVAL = "observation", "retrieval"

#: The freshness SLA of each step-11 publisher, in days, by its cadence (the brief:
#: cloud 7, EDGAR 1 for a filing watch, enforcement 7). Step 10's table
#: (``feeds.FRESHNESS_SLA_DAYS``) is unchanged.
CATALOG_SLA_DAYS: Mapping[tuple[str, str], int] = MappingProxyType(
    {
        ("AWS", "weekly"): 7,
        ("Azure", "weekly"): 7,
        ("GCP", "weekly"): 7,
        ("SEC-EDGAR", "daily"): 1,
        ("CFPB", "weekly"): 7,
        ("FTC", "weekly"): 7,
        ("SEC", "weekly"): 7,
        ("HHS-OCR", "weekly"): 7,
        ("OCC", "weekly"): 7,
        ("FDIC", "weekly"): 7,
        ("FRB", "weekly"): 7,
    }
)

#: The most records one source version holds: a larger answer is ``feed_over_limit``
#: (the registry narrows the source instead). One version's records are one row, so
#: registering it writes one row however many it holds.
MAX_RECORDS = 5000
#: The most pages a paginated catalog is read across.
MAX_PAGES = 20
#: The largest answer a catalog's request may be given (an offer file, a company's
#: facts), in bytes; the whole of a paginated answer is held to it too.
CATALOG_MAX_BYTES = 32 * 1024 * 1024
#: The schema of the records a version holds, as stored.
RECORDS_SCHEMA = "mythos.economics.catalog-records/v1"
#: What every step-11 registry entry whose endpoint and format the builder could not
#: confirm says, in its dataset: nothing here was fetched while it was built.
FORMAT_ASSUMED = "endpoint and format assumed: confirm with a recording (owner)"


# --------------------------------------------------------------------- records


def _blank_or_text(value, what: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise FeedRefused("feed_value_malformed", f"{what} is blank or not text")


def _plain_date(value, what: str) -> date:
    if not isinstance(value, date) or isinstance(value, datetime):
        raise FeedRefused("feed_value_malformed", f"{what} is not a date")
    return value


def _decimal(value, what: str, *, signed: bool = False) -> Decimal:
    if not isinstance(value, Decimal) or not value.is_finite():
        raise FeedRefused("feed_value_malformed", f"{what} is not a finite Decimal")
    if not signed and value < 0:
        raise FeedRefused("feed_value_malformed", f"{what} {value} is negative")
    return value


_CIK = re.compile(r"[0-9]{10}")
_ACCESSION = re.compile(r"[0-9]{10}-[0-9]{2}-[0-9]{6}")
_HTTPS_HOST = re.compile(r"[a-z0-9.-]+")


def _https_url(value, what: str) -> str:
    _blank_or_text(value, what)
    parts = urlsplit(value)
    if parts.scheme != "https" or not parts.hostname or not _HTTPS_HOST.fullmatch(parts.hostname):
        raise FeedRefused("feed_value_malformed", f"{what} {value[:120]!r} is not an https URL")
    return value


@dataclass(frozen=True)
class PriceObservation:
    """One price of one cloud SKU: ``usd_price`` per ``unit`` (the provider's own
    spelling of it), in ``region``, effective from ``effective_date``, for usage from
    ``tier_start`` units. ``observation_id`` is unique within its version."""

    provider: str
    sku: str
    observation_id: str
    region: str
    unit: str
    usd_price: Decimal
    effective_date: date
    tier_start: Decimal
    product: str
    description: str

    TYPE = "price"

    def __post_init__(self):
        for name, value in (
            ("provider", self.provider), ("sku", self.sku), ("observation_id", self.observation_id),
            ("region", self.region), ("unit", self.unit), ("product", self.product), ("description", self.description),
        ):
            _blank_or_text(value, name)
        _decimal(self.usd_price, f"{self.observation_id} usd_price")
        _decimal(self.tier_start, f"{self.observation_id} tier_start")
        _plain_date(self.effective_date, f"{self.observation_id} effective_date")

    @property
    def identity(self) -> str:
        return self.observation_id

    def as_record(self) -> dict:
        return {
            "type": self.TYPE,
            "provider": self.provider,
            "sku": self.sku,
            "observation_id": self.observation_id,
            "region": self.region,
            "unit": self.unit,
            "usd_price": decimal_text(self.usd_price),
            "effective_date": self.effective_date.isoformat(),
            "tier_start": decimal_text(self.tier_start),
            "product": self.product,
            "description": self.description,
        }


@dataclass(frozen=True)
class CompanyFact:
    """One reported figure of one company for one period, as filed: the XBRL
    concept, the period, the value in ``unit`` (USD), and the filing it came from
    (form, filing date, accession number). ``segment_axis`` and ``segment_member``
    name the business segment where the figure is one (both blank: the company)."""

    cik: str
    entity: str
    concept: str
    period_start: date
    period_end: date
    value: Decimal
    unit: str
    form: str
    filed: date
    accession: str
    fiscal_year: str = ""
    fiscal_period: str = ""
    segment_axis: str = ""
    segment_member: str = ""

    TYPE = "fact"

    def __post_init__(self):
        if not isinstance(self.cik, str) or not _CIK.fullmatch(self.cik):
            raise FeedRefused("feed_value_malformed", f"cik {self.cik!r} is not ten digits")
        for name, value in (("entity", self.entity), ("concept", self.concept), ("unit", self.unit),
                            ("form", self.form)):
            _blank_or_text(value, name)
        if not isinstance(self.accession, str) or not _ACCESSION.fullmatch(self.accession):
            raise FeedRefused("feed_value_malformed", f"accession {self.accession!r}")
        _plain_date(self.period_start, "period_start")
        _plain_date(self.period_end, "period_end")
        _plain_date(self.filed, "filed")
        if self.period_end < self.period_start:
            raise FeedRefused("feed_value_malformed", f"{self.concept} ends {self.period_end} before it starts")
        _decimal(self.value, f"{self.concept} value", signed=True)
        for name, value in (("fiscal_year", self.fiscal_year), ("fiscal_period", self.fiscal_period),
                            ("segment_axis", self.segment_axis), ("segment_member", self.segment_member)):
            if not isinstance(value, str):
                raise FeedRefused("feed_value_malformed", f"{name} is not text")
        if bool(self.segment_axis) != bool(self.segment_member):
            raise FeedRefused("feed_value_malformed", "a segment names both its axis and its member, or neither")

    @property
    def identity(self) -> str:
        return "|".join(
            (self.concept, self.period_start.isoformat(), self.period_end.isoformat(), self.accession,
             self.segment_axis, self.segment_member)
        )

    def as_record(self) -> dict:
        return {
            "type": self.TYPE,
            "cik": self.cik,
            "entity": self.entity,
            "concept": self.concept,
            "period_start": self.period_start.isoformat(),
            "period_end": self.period_end.isoformat(),
            "value": decimal_text(self.value),
            "unit": self.unit,
            "form": self.form,
            "filed": self.filed.isoformat(),
            "accession": self.accession,
            "fiscal_year": self.fiscal_year,
            "fiscal_period": self.fiscal_period,
            "segment_axis": self.segment_axis,
            "segment_member": self.segment_member,
        }


@dataclass(frozen=True)
class CompanyFiling:
    """One filing a company made: form, filing date, the period it reports on (where
    it names one), its accession number and primary document, and whether it is
    inline XBRL."""

    cik: str
    accession: str
    form: str
    filing_date: date
    report_date: date | None
    primary_document: str
    inline_xbrl: bool

    TYPE = "filing"

    def __post_init__(self):
        if not isinstance(self.cik, str) or not _CIK.fullmatch(self.cik):
            raise FeedRefused("feed_value_malformed", f"cik {self.cik!r} is not ten digits")
        if not isinstance(self.accession, str) or not _ACCESSION.fullmatch(self.accession):
            raise FeedRefused("feed_value_malformed", f"accession {self.accession!r}")
        _blank_or_text(self.form, "form")
        _plain_date(self.filing_date, "filing_date")
        if self.report_date is not None:
            _plain_date(self.report_date, "report_date")
        if not isinstance(self.primary_document, str):
            raise FeedRefused("feed_value_malformed", f"primary document {self.primary_document!r}")
        if type(self.inline_xbrl) is not bool:
            raise FeedRefused("feed_value_malformed", "inline_xbrl is true or false")

    @property
    def identity(self) -> str:
        return self.accession

    def as_record(self) -> dict:
        return {
            "type": self.TYPE,
            "cik": self.cik,
            "accession": self.accession,
            "form": self.form,
            "filing_date": self.filing_date.isoformat(),
            "report_date": self.report_date.isoformat() if self.report_date else None,
            "primary_document": self.primary_document,
            "inline_xbrl": self.inline_xbrl,
        }


@dataclass(frozen=True)
class CompanyEntity:
    """The company a filing watch is of: its CIK, name, entity type, and the tickers
    and exchanges its shares are listed under (none: not listed)."""

    cik: str
    name: str
    entity_type: str
    tickers: tuple[str, ...]
    exchanges: tuple[str, ...]

    TYPE = "entity"

    def __post_init__(self):
        if not isinstance(self.cik, str) or not _CIK.fullmatch(self.cik):
            raise FeedRefused("feed_value_malformed", f"cik {self.cik!r} is not ten digits")
        _blank_or_text(self.name, "name")
        if not isinstance(self.entity_type, str):
            raise FeedRefused("feed_value_malformed", "entity_type is not text")
        for name, values in (("tickers", self.tickers), ("exchanges", self.exchanges)):
            if not isinstance(values, tuple) or not all(isinstance(v, str) and v.strip() for v in values):
                raise FeedRefused("feed_value_malformed", f"{name} is a list of names")

    @property
    def identity(self) -> str:
        return "entity:" + self.cik

    @property
    def listed(self) -> bool:
        """Whether the company's shares are listed: a ticker on an exchange."""
        return bool(self.tickers) and bool(self.exchanges)

    def as_record(self) -> dict:
        return {
            "type": self.TYPE,
            "cik": self.cik,
            "name": self.name,
            "entity_type": self.entity_type,
            "tickers": list(self.tickers),
            "exchanges": list(self.exchanges),
        }


@dataclass(frozen=True)
class EnforcementRecord:
    """One enforcement action as a regulator's listing states it: the agency, the
    date, the respondent (``None`` where the listing names none in a field), the
    category, the amounts it STATES in fields of its own (the civil money penalty,
    restitution, a settlement; ``None``: not stated there -- never read out of
    prose), and the citation's URL and text.

    CONTEXT ONLY (spec, section 30.5): never a fine or penalty figure, never summed
    into a loss."""

    agency: str
    record_id: str
    action_date: date
    respondent: str | None
    category: str
    civil_money_penalty: Decimal | None
    restitution: Decimal | None
    settlement: Decimal | None
    citation_url: str
    citation_text: str
    currency: str = "USD"

    TYPE = "enforcement"
    AMOUNTS = ("civil_money_penalty", "restitution", "settlement")

    def __post_init__(self):
        for name, value in (("agency", self.agency), ("record_id", self.record_id), ("category", self.category),
                            ("citation_text", self.citation_text)):
            _blank_or_text(value, name)
        _plain_date(self.action_date, "action_date")
        if self.respondent is not None:
            _blank_or_text(self.respondent, "respondent")
        for name, value in self.amounts().items():
            if value is not None:
                _decimal(value, name)
        _https_url(self.citation_url, "citation_url")
        if self.currency != "USD":
            raise FeedRefused("feed_value_malformed", f"currency {self.currency!r}: the listings state USD")

    @property
    def identity(self) -> str:
        return self.record_id

    def amounts(self) -> dict[str, Decimal | None]:
        """The amounts the listing stated, by name (``None``: not stated in a field)."""
        return {
            "civil_money_penalty": self.civil_money_penalty,
            "restitution": self.restitution,
            "settlement": self.settlement,
        }

    def as_record(self) -> dict:
        record = {
            "type": self.TYPE,
            "agency": self.agency,
            "record_id": self.record_id,
            "action_date": self.action_date.isoformat(),
            "respondent": self.respondent,
            "category": self.category,
            "citation_url": self.citation_url,
            "citation_text": self.citation_text,
            "currency": self.currency,
        }
        for name, value in self.amounts().items():
            record[name] = None if value is None else decimal_text(value)
        return record


RECORD_TYPES = {cls.TYPE: cls for cls in (PriceObservation, CompanyFact, CompanyFiling, CompanyEntity, EnforcementRecord)}
#: The record types each kind of source holds.
KIND_RECORDS: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        CLOUD_PRICE: frozenset({PriceObservation.TYPE}),
        COMPANY_FACT: frozenset({CompanyFact.TYPE}),
        FILING_WATCH: frozenset({CompanyFiling.TYPE, CompanyEntity.TYPE}),
        ENFORCEMENT: frozenset({EnforcementRecord.TYPE}),
    }
)


def _stored_date(value, what: str) -> date:
    if not isinstance(value, str):
        raise FeedRefused("feed_value_malformed", f"{what} is not text")
    return _day(value, what)


def _stored_decimal(value, what: str, *, optional: bool = False) -> Decimal | None:
    if value is None and optional:
        return None
    try:
        return parse_decimal(value, what)
    except MoneyRefused:
        raise FeedRefused("feed_value_malformed", f"{what} is not a decimal string") from None


def read_record(entry) -> PriceObservation | CompanyFact | CompanyFiling | CompanyEntity | EnforcementRecord:
    """The record a stored entry holds, read exactly: its ``type``, then exactly that
    type's fields, each in its stored spelling. Raises :class:`.feeds.FeedRefused`
    (``feed_value_malformed``) on anything else."""
    if not isinstance(entry, dict) or entry.get("type") not in RECORD_TYPES:
        raise FeedRefused("feed_value_malformed", "a record is an object naming its type")
    cls = RECORD_TYPES[entry["type"]]
    sample = {"type"} | set(_FIELDS[cls])
    if set(entry) != sample:
        raise FeedRefused("feed_value_malformed", f"a {cls.TYPE} record has exactly {sorted(sample)}")
    values = dict(entry)
    del values["type"]
    if cls is PriceObservation:
        values.update(
            usd_price=_stored_decimal(values["usd_price"], "usd_price"),
            tier_start=_stored_decimal(values["tier_start"], "tier_start"),
            effective_date=_stored_date(values["effective_date"], "effective_date"),
        )
    elif cls is CompanyFact:
        values.update(
            period_start=_stored_date(values["period_start"], "period_start"),
            period_end=_stored_date(values["period_end"], "period_end"),
            filed=_stored_date(values["filed"], "filed"),
            value=_stored_decimal(values["value"], "value"),
        )
    elif cls is CompanyFiling:
        values.update(
            filing_date=_stored_date(values["filing_date"], "filing_date"),
            report_date=None if values["report_date"] is None else _stored_date(values["report_date"], "report_date"),
        )
    elif cls is CompanyEntity:
        for name in ("tickers", "exchanges"):
            if not isinstance(values[name], list):
                raise FeedRefused("feed_value_malformed", f"{name} is a list")
            values[name] = tuple(values[name])
    else:
        values["action_date"] = _stored_date(values["action_date"], "action_date")
        for name in EnforcementRecord.AMOUNTS:
            values[name] = _stored_decimal(values[name], name, optional=True)
    return cls(**values)


_FIELDS = {
    PriceObservation: ("provider", "sku", "observation_id", "region", "unit", "usd_price", "effective_date",
                       "tier_start", "product", "description"),
    CompanyFact: ("cik", "entity", "concept", "period_start", "period_end", "value", "unit", "form", "filed",
                  "accession", "fiscal_year", "fiscal_period", "segment_axis", "segment_member"),
    CompanyFiling: ("cik", "accession", "form", "filing_date", "report_date", "primary_document", "inline_xbrl"),
    CompanyEntity: ("cik", "name", "entity_type", "tickers", "exchanges"),
    EnforcementRecord: ("agency", "record_id", "action_date", "respondent", "category", "civil_money_penalty",
                        "restitution", "settlement", "citation_url", "citation_text", "currency"),
}


def check_records(kind: str, records) -> tuple:
    """``records`` (engine records), held to their kind: every one of a type the kind
    holds, no identity twice, at least one and at most :data:`MAX_RECORDS`."""
    if kind not in KIND_RECORDS:
        raise FeedRefused("feed_value_malformed", f"kind {kind!r}")
    records = tuple(records)
    if not records:
        raise FeedRefused("feed_empty", "no record")
    if len(records) > MAX_RECORDS:
        raise FeedRefused("feed_over_limit", f"{len(records)} records; one version holds at most {MAX_RECORDS}")
    seen = set()
    for record in records:
        if getattr(record, "TYPE", None) not in KIND_RECORDS[kind]:
            raise FeedRefused("feed_value_malformed", f"a {kind} source holds no {getattr(record, 'TYPE', record)!r}")
        if record.identity in seen:
            raise FeedRefused("feed_mismatch", f"{record.identity[:200]} is listed twice")
        seen.add(record.identity)
    if kind == FILING_WATCH and sum(1 for r in records if r.TYPE == CompanyEntity.TYPE) != 1:
        raise FeedRefused("feed_malformed", "a filing watch names its company once")
    return records


def read_records(kind: str, entries) -> tuple:
    """The records a stored list of entries holds (:func:`read_record` each), held to
    ``kind`` (:func:`check_records`)."""
    if not isinstance(entries, list):
        raise FeedRefused("feed_value_malformed", "records are a list")
    return check_records(kind, (read_record(entry) for entry in entries))


def records_json(records) -> list[dict]:
    """The stored form of ``records``: each one's record, in order."""
    return [record.as_record() for record in records]


def records_digest(entries: list) -> str:
    """``sha256:`` and the SHA-256 of the stored entries' canonical JSON."""
    text = json.dumps(entries, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


# -------------------------------------------------------------------- registry


def _catalog(key: str, **fields) -> FeedSource:
    return FeedSource(
        key=key, age_basis=RETRIEVAL, sla_override=CATALOG_SLA_DAYS[(fields["provider"], fields["cadence"])], **fields
    )


def _frozen(**values) -> Mapping:
    return MappingProxyType(values)


#: What the owner's licensing review reads, per provider, before a licence class
#: leaves ``unreviewed``. Text only: the builder read none of these terms.
LICENCE_TERMS: Mapping[str, str] = MappingProxyType(
    {
        "AWS": "the AWS Site Terms and the AWS Price List service's terms of use",
        "Azure": "the Microsoft terms of use of the Azure Retail Prices API",
        "GCP": "the Google Cloud Billing Catalog API's terms of service and the Google APIs Terms of Service",
        "SEC-EDGAR": "the SEC's EDGAR access and fair-access policy (sec.gov's privacy and security policy)",
        "CFPB": "consumerfinance.gov's terms of use",
        "FTC": "ftc.gov's terms of use",
        "SEC": "sec.gov's terms of use",
        "HHS-OCR": "hhs.gov's terms of use",
        "OCC": "occ.gov's terms of use",
        "FDIC": "fdic.gov's terms of use",
        "FRB": "federalreserve.gov's terms of use",
    }
)

#: The step-11 registry: every static source ``manage.py fetch_financial_source``
#: reads beside step 10's. EDGAR's sources are one per company (:func:`edgar_source`).
#: Every licence class is ``unreviewed`` (owner).
CATALOG_REGISTRY: Mapping[str, FeedSource] = MappingProxyType(
    {
        "aws-price-list-s3-us-east-1": _catalog(
            "aws-price-list-s3-us-east-1",
            adapter="aws",
            provider="AWS",
            dataset="AWS Price List bulk offer file, Amazon S3, us-east-1, on-demand prices in USD",
            kind=CLOUD_PRICE,
            cadence="weekly",
            base_url="https://pricing.us-east-1.amazonaws.com",
            path="/offers/v1.0/aws/AmazonS3/current/us-east-1/index.json",
            schema_version="aws.price-list-offer.json/v1.0",
            use=PREFILL,
            freshness=GATING,
            licence_terms=LICENCE_TERMS["AWS"],
            config=_frozen(offer_code="AmazonS3", region="us-east-1", max_bytes=CATALOG_MAX_BYTES),
        ),
        "azure-retail-prices-site-recovery-eastus": _catalog(
            "azure-retail-prices-site-recovery-eastus",
            adapter="azure",
            provider="Azure",
            dataset="Azure Retail Prices API, Azure Site Recovery, eastus, consumption prices in USD",
            kind=CLOUD_PRICE,
            cadence="weekly",
            base_url="https://prices.azure.com",
            path="/api/retail/prices",
            schema_version="azure.retail-prices.json/2023-01-01-preview",
            use=PREFILL,
            freshness=GATING,
            licence_terms=LICENCE_TERMS["Azure"],
            config=_frozen(
                api_version="2023-01-01-preview",
                service="Azure Site Recovery",
                region="eastus",
                max_pages=MAX_PAGES,
                max_bytes=CATALOG_MAX_BYTES,
            ),
        ),
        "gcp-billing-catalog-cloud-storage": _catalog(
            "gcp-billing-catalog-cloud-storage",
            adapter="gcp",
            provider="GCP",
            dataset="Google Cloud Billing Catalog API, Cloud Storage SKUs in us-central1 and us-east1, list prices in USD",
            kind=CLOUD_PRICE,
            cadence="weekly",
            base_url="https://cloudbilling.googleapis.com",
            path="/v1/services/95FF-2EF5-5EA1/skus",
            schema_version="gcp.cloudbilling.skus.json/v1",
            key_setting="ECONOMICS_GCP_BILLING_API_KEY",
            use=PREFILL,
            freshness=GATING,
            licence_terms=LICENCE_TERMS["GCP"],
            config=_frozen(
                service_id="95FF-2EF5-5EA1",
                service="Cloud Storage",
                regions=("us-central1", "us-east1"),
                page_size="5000",
                max_pages=MAX_PAGES,
                max_bytes=CATALOG_MAX_BYTES,
            ),
        ),
        "cfpb-enforcement-actions": _catalog(
            "cfpb-enforcement-actions",
            adapter="rss",
            provider="CFPB",
            dataset=f"CFPB enforcement actions, RSS 2.0 (context only; {FORMAT_ASSUMED})",
            kind=ENFORCEMENT,
            cadence="weekly",
            base_url="https://www.consumerfinance.gov",
            path="/enforcement/actions/feed/",
            schema_version="rss.2.0/cfpb-enforcement",
            use=CONTEXT,
            freshness=INFORMATIONAL,
            licence_terms=LICENCE_TERMS["CFPB"],
            config=_frozen(
                host="www.consumerfinance.gov",
                agency="CFPB",
                category="consumer financial protection",
                respondent_from="title",
                families=("legal", "regulatory_compliance", "customer_restitution"),
            ),
        ),
        "ftc-privacy-security-cases": _catalog(
            "ftc-privacy-security-cases",
            adapter="rss",
            provider="FTC",
            dataset=f"FTC cases and proceedings, privacy and security, RSS 2.0 (context only; {FORMAT_ASSUMED})",
            kind=ENFORCEMENT,
            cadence="weekly",
            base_url="https://www.ftc.gov",
            path="/feeds/cases-proceedings/privacy-security.xml",
            schema_version="rss.2.0/ftc-privacy-security",
            use=CONTEXT,
            freshness=INFORMATIONAL,
            licence_terms=LICENCE_TERMS["FTC"],
            config=_frozen(
                host="www.ftc.gov",
                agency="FTC",
                category="privacy and data security",
                respondent_from="title",
                families=("legal", "regulatory_compliance", "notification"),
            ),
        ),
        "sec-litigation-releases": _catalog(
            "sec-litigation-releases",
            adapter="rss",
            provider="SEC",
            dataset=f"SEC litigation releases, RSS 2.0 (context only; {FORMAT_ASSUMED})",
            kind=ENFORCEMENT,
            cadence="weekly",
            base_url="https://www.sec.gov",
            path="/enforcement-litigation/litigation-releases/rss",
            schema_version="rss.2.0/sec-litigation-releases",
            use=CONTEXT,
            freshness=INFORMATIONAL,
            licence_terms=LICENCE_TERMS["SEC"],
            config=_frozen(
                host="www.sec.gov",
                agency="SEC",
                category="securities enforcement",
                respondent_from="title",
                families=("legal", "regulatory_compliance"),
            ),
        ),
        "hhs-ocr-hipaa-enforcement": _catalog(
            "hhs-ocr-hipaa-enforcement",
            adapter="rss",
            provider="HHS-OCR",
            dataset=(
                "HHS Office for Civil Rights, HIPAA enforcement announcements (resolution agreements and civil money "
                f"penalties), RSS 2.0 (context only; {FORMAT_ASSUMED})"
            ),
            kind=ENFORCEMENT,
            cadence="weekly",
            base_url="https://www.hhs.gov",
            path="/hipaa/for-professionals/compliance-enforcement/agreements/rss.xml",
            schema_version="rss.2.0/hhs-ocr-hipaa",
            use=CONTEXT,
            freshness=INFORMATIONAL,
            licence_terms=LICENCE_TERMS["HHS-OCR"],
            config=_frozen(
                host="www.hhs.gov",
                agency="HHS OCR",
                category="health information privacy and security (HIPAA)",
                # An announcement's title is prose, not the covered entity's name.
                respondent_from="",
                families=("legal", "regulatory_compliance", "notification"),
            ),
        ),
        "occ-enforcement-actions": _catalog(
            "occ-enforcement-actions",
            adapter="enforcement_csv",
            provider="OCC",
            dataset=f"OCC enforcement action search, CSV export (context only; {FORMAT_ASSUMED})",
            kind=ENFORCEMENT,
            cadence="weekly",
            base_url="https://apps.occ.gov",
            path="/EASearch/Search/ExportCsv",
            schema_version="csv/occ-enforcement-actions",
            use=CONTEXT,
            freshness=INFORMATIONAL,
            licence_terms=LICENCE_TERMS["OCC"],
            config=_frozen(
                host="www.occ.gov",
                agency="OCC",
                category="bank supervision",
                header=("Bank Name", "Individual Name", "Charter Number", "Docket Number", "Type of Action", "Amount",
                        "Start Date", "Termination Date", "Document URL"),
                date="Start Date",
                respondent=("Bank Name", "Individual Name"),
                record_id="Docket Number",
                action="Type of Action",
                amounts=(("civil_money_penalty", "Amount", "Civil Money Penalty"),
                         ("restitution", "Amount", "Restitution")),
                url="Document URL",
                families=("regulatory_compliance",),
            ),
        ),
        "fdic-enforcement-orders": _catalog(
            "fdic-enforcement-orders",
            adapter="enforcement_csv",
            provider="FDIC",
            dataset=f"FDIC enforcement decisions and orders, CSV export (context only; {FORMAT_ASSUMED})",
            kind=ENFORCEMENT,
            cadence="weekly",
            base_url="https://orders.fdic.gov",
            path="/s/enforcement-orders.csv",
            schema_version="csv/fdic-enforcement-orders",
            use=CONTEXT,
            freshness=INFORMATIONAL,
            licence_terms=LICENCE_TERMS["FDIC"],
            config=_frozen(
                host="orders.fdic.gov",
                agency="FDIC",
                category="bank supervision",
                header=("Institution Name", "Docket Number", "Order Type", "Issued Date", "Civil Money Penalty",
                        "Restitution", "Order URL"),
                date="Issued Date",
                respondent=("Institution Name",),
                record_id="Docket Number",
                action="Order Type",
                amounts=(("civil_money_penalty", "Civil Money Penalty", ""), ("restitution", "Restitution", "")),
                url="Order URL",
                families=("regulatory_compliance", "customer_restitution"),
            ),
        ),
        "frb-enforcement-actions": _catalog(
            "frb-enforcement-actions",
            adapter="enforcement_csv",
            provider="FRB",
            dataset=f"Federal Reserve Board enforcement actions, CSV export (context only; {FORMAT_ASSUMED})",
            kind=ENFORCEMENT,
            cadence="weekly",
            base_url="https://www.federalreserve.gov",
            path="/supervisionreg/files/enforcementactions.csv",
            schema_version="csv/frb-enforcement-actions",
            use=CONTEXT,
            freshness=INFORMATIONAL,
            licence_terms=LICENCE_TERMS["FRB"],
            config=_frozen(
                host="www.federalreserve.gov",
                agency="Federal Reserve Board",
                category="bank supervision",
                header=("Effective Date", "Banking Organization", "Action", "Civil Money Penalty", "Termination Date",
                        "URL"),
                date="Effective Date",
                respondent=("Banking Organization",),
                record_id="",
                action="Action",
                amounts=(("civil_money_penalty", "Civil Money Penalty", ""),),
                url="URL",
                families=("regulatory_compliance",),
            ),
        ),
    }
)

#: EDGAR's three sources of one company, by family: ``sec-edgar-<family>-cik<CIK>``.
EDGAR_FAMILIES = ("submissions", "companyfacts", "segments")
_EDGAR_KEY = re.compile(r"sec-edgar-(submissions|companyfacts|segments)-cik([0-9]{10})")
#: The XBRL concepts read as revenue, in the order a period's revenue is taken
#: (the first one a period reports), and as operating income.
REVENUE_CONCEPTS = (
    "RevenueFromContractWithCustomerExcludingAssessedTax",
    "Revenues",
    "SalesRevenueNet",
)
OPERATING_INCOME_CONCEPTS = ("OperatingIncomeLoss",)
#: The axis a business segment's revenue is reported on.
SEGMENT_AXIS = "StatementBusinessSegmentsAxis"
#: The periodic reports whose XBRL instance segment revenue is read from.
PERIODIC_FORMS = ("10-K", "10-Q")


def edgar_key(family: str, cik: str) -> str:
    """The source key of ``family``'s EDGAR source for the company ``cik`` (ten
    digits, as SEC pads it)."""
    if family not in EDGAR_FAMILIES or not isinstance(cik, str) or not _CIK.fullmatch(cik):
        raise FeedRefused("source_unrecognised", f"EDGAR {family!r} for CIK {cik!r}")
    return f"sec-edgar-{family}-cik{cik}"


def edgar_source(family: str, cik: str) -> FeedSource:
    """The EDGAR source of ``family`` for the company ``cik``. SEC's fair-access policy
    asks every request to declare who sends it: the declared User-Agent is held in
    ``ECONOMICS_SEC_USER_AGENT`` and sent as that header, as a provider's key is."""
    key = edgar_key(family, cik)
    common = dict(
        provider="SEC-EDGAR",
        cadence="daily",
        key_setting="ECONOMICS_SEC_USER_AGENT",
        freshness=INFORMATIONAL,
        licence_terms=LICENCE_TERMS["SEC-EDGAR"],
    )
    if family == "submissions":
        return _catalog(
            key, adapter="edgar_submissions",
            dataset=f"SEC EDGAR submissions, CIK {cik}: the company's recent filings (a filing watch, context only)",
            kind=FILING_WATCH, base_url="https://data.sec.gov", path=f"/submissions/CIK{cik}.json",
            schema_version="sec.edgar.submissions.json/1", use=CONTEXT,
            config=_frozen(cik=cik, max_bytes=CATALOG_MAX_BYTES), **common,
        )
    if family == "companyfacts":
        return _catalog(
            key, adapter="edgar_companyfacts",
            dataset=f"SEC EDGAR XBRL companyfacts, CIK {cik}: revenue and operating income by period, as filed",
            kind=COMPANY_FACT, base_url="https://data.sec.gov", path=f"/api/xbrl/companyfacts/CIK{cik}.json",
            schema_version="sec.edgar.companyfacts.json/1", use=PREFILL,
            config=_frozen(cik=cik, max_bytes=CATALOG_MAX_BYTES), **common,
        )
    return _catalog(
        key, adapter="edgar_instance",
        dataset=(
            f"SEC EDGAR, CIK {cik}: segment revenue by period, from the newest periodic filing's XBRL instance "
            "(context only)"
        ),
        kind=COMPANY_FACT, base_url="https://www.sec.gov", path=f"/Archives/edgar/data/{int(cik)}/",
        schema_version="xbrl.2.1.instance/us-gaap-segments", use=CONTEXT,
        config=_frozen(cik=cik, max_bytes=CATALOG_MAX_BYTES), **common,
    )


def known(key) -> FeedSource | None:
    """The step-11 source ``key`` names: a registry entry, or an EDGAR company
    source; ``None`` for any other."""
    if not isinstance(key, str):
        return None
    found = CATALOG_REGISTRY.get(key)
    if found is not None:
        return found
    match = _EDGAR_KEY.fullmatch(key)
    if match is None:
        return None
    return edgar_source(match.group(1), match.group(2))


def source(key) -> FeedSource:
    """:func:`known`, or ``source_unrecognised``."""
    found = known(key)
    if found is None:
        raise FeedRefused("source_unrecognised", repr(key))
    return found


def edgar_cik(key: str) -> str | None:
    """The CIK an EDGAR source key names, or ``None``."""
    match = _EDGAR_KEY.fullmatch(key) if isinstance(key, str) else None
    return match.group(2) if match else None


# -------------------------------------------------------------------- requests


def _instance_name(primary_document: str) -> str:
    """The XBRL instance EDGAR extracts from an inline-XBRL primary document:
    ``aapl-20250927.htm`` gives ``aapl-20250927_htm.xml``."""
    if not primary_document.endswith(".htm") or "/" in primary_document:
        raise FeedRefused("filing_unknown", f"primary document {primary_document!r} is not an inline-XBRL .htm")
    return primary_document[: -len(".htm")] + "_htm.xml"


def request_for(
    feed: FeedSource,
    *,
    as_of: date,
    explicit: bool,
    today: date,
    base_url: str | None = None,
    provider_today: date | None = None,
    filing: CompanyFiling | None = None,
) -> FeedRequest:
    """The first request for ``feed``, without any key. Every step-11 provider serves
    its current listing only, so ``as_of`` is today (UTC, or the provider's own date,
    ``provider_today``): another date is ``as_of_unsupported``. EDGAR's segment source
    asks for ``filing``'s XBRL instance (``filing_unknown`` without one)."""
    del explicit  # every step-11 provider serves today's listing, asked or not
    if as_of > today:
        raise FeedRefused("as_of_in_future", f"{as_of} is after {today}")
    if as_of not in {today, provider_today or today}:
        raise FeedRefused("as_of_unsupported", f"{feed.provider} serves its current listing only, not that of {as_of}")
    base = base_url if base_url is not None else feed.base_url
    config = feed.config
    size = int(config.get("max_bytes", MAX_RESPONSE_BYTES))
    if feed.adapter == "azure":
        query = f"serviceName eq '{config['service']}' and armRegionName eq '{config['region']}' and priceType eq 'Consumption'"
        params = (("api-version", config["api_version"]), ("$filter", query))
        return FeedRequest("GET", base + feed.path, params, max_bytes=size)
    if feed.adapter == "gcp":
        params = (("currencyCode", "USD"), ("pageSize", config["page_size"]))
        return FeedRequest("GET", base + feed.path, params, key_in="query", key_name="key", max_bytes=size)
    if feed.adapter in ("edgar_submissions", "edgar_companyfacts"):
        return FeedRequest("GET", base + feed.path, key_in="header", key_name="User-Agent", max_bytes=size)
    if feed.adapter == "edgar_instance":
        if filing is None or filing.cik != config["cik"]:
            raise FeedRefused("filing_unknown", f"CIK {config['cik']}: no periodic inline-XBRL filing to read")
        path = f"{feed.path}{filing.accession.replace('-', '')}/{_instance_name(filing.primary_document)}"
        return FeedRequest("GET", base + path, key_in="header", key_name="User-Agent", max_bytes=size)
    if feed.adapter in ("aws", "rss", "enforcement_csv"):
        return FeedRequest("GET", base + feed.path, max_bytes=size)
    raise FeedRefused("source_unrecognised", f"{feed.key} names no adapter this module has")


def next_request(feed: FeedSource, request: FeedRequest, raw: bytes) -> FeedRequest | None:
    """The request for the page after ``raw`` (``request``'s answer), or ``None`` on
    the last page. Azure names it (``NextPageLink``: the same endpoint and query, and
    a ``$skip``); GCP gives a ``nextPageToken``. Another host, path or query is
    ``feed_mismatch``: a next-page link is never followed anywhere else."""
    if feed.adapter == "azure":
        page = _json(raw)
        if not isinstance(page, dict) or "NextPageLink" not in page:
            raise FeedRefused("feed_malformed", "an Azure page names its NextPageLink")
        link = page["NextPageLink"]
        if link is None:
            return None
        if not isinstance(link, str):
            raise FeedRefused("feed_malformed", "NextPageLink is a URL or null")
        parts = urlsplit(link)
        if (parts.scheme, parts.hostname, parts.port or 443, parts.path) != (
            "https", urlsplit(feed.base_url).hostname, 443, feed.path
        ):
            raise FeedRefused("feed_mismatch", "NextPageLink leaves the endpoint asked")
        params = tuple(parse_qsl(parts.query, keep_blank_values=True))
        asked = {name: value for name, value in request.params if name != "$skip"}
        given = {name: value for name, value in params if name != "$skip"}
        skips = [value for name, value in params if name == "$skip"]
        if given != asked or len(skips) != 1 or not skips[0].isdigit():
            raise FeedRefused("feed_mismatch", "NextPageLink asks another query, or no single $skip")
        ordered = tuple((name, value) for name, value in request.params if name != "$skip") + (("$skip", skips[0]),)
        return FeedRequest("GET", request.url, ordered, max_bytes=request.max_bytes)
    if feed.adapter == "gcp":
        page = _json(raw)
        if not isinstance(page, dict):
            raise FeedRefused("feed_malformed", "a GCP page is an object")
        token = page.get("nextPageToken", "")
        if not isinstance(token, str):
            raise FeedRefused("feed_malformed", "nextPageToken is text")
        if not token:
            return None
        params = tuple((name, value) for name, value in request.params if name != "pageToken") + (("pageToken", token),)
        return FeedRequest(
            "GET", request.url, params, key_in=request.key_in, key_name=request.key_name, max_bytes=request.max_bytes
        )
    return None


# --------------------------------------------------------------------- reading


def _json(raw: bytes):
    """The JSON document of ``raw``: UTF-8, no key twice in one object, no bare NaN
    or Infinity, and every number with a fraction or an exponent read as a
    ``Decimal`` from its own text (never a float)."""

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
        try:
            value = Decimal(text)
        except InvalidOperation:
            raise FeedRefused("feed_malformed", f"the number {text!r}") from None
        if not value.is_finite():
            raise FeedRefused("feed_malformed", f"the number {text!r} is not finite")
        return value

    if not isinstance(raw, bytes):
        raise TypeError("a response is read from its bytes")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant, parse_float=number)
    except FeedRefused:
        raise
    except (ValueError, UnicodeError, RecursionError):
        raise FeedRefused("feed_malformed", "not UTF-8 JSON") from None


def _canonical(document) -> bytes:
    """One spelling of a JSON document read by :func:`_json`: sorted keys, no
    whitespace, UTF-8, and a ``Decimal`` in plain notation."""

    def write(value) -> str:
        if isinstance(value, dict):
            return "{" + ",".join(json.dumps(k, ensure_ascii=False) + ":" + write(value[k]) for k in sorted(value)) + "}"
        if isinstance(value, list):
            return "[" + ",".join(write(item) for item in value) + "]"
        if isinstance(value, Decimal):
            return decimal_text(value)
        if isinstance(value, bool) or value is None or isinstance(value, (int, str)):
            return json.dumps(value, ensure_ascii=False)
        raise TypeError(type(value).__name__)

    return write(document).encode("utf-8")


def _fields(document, required: frozenset, optional: frozenset, what: str) -> dict:
    if not isinstance(document, dict) or not required <= set(document) <= required | optional:
        raise FeedRefused("feed_malformed", f"{what} has the fields {sorted(required)}, and maybe {sorted(optional)}")
    return document


def _text(value, what: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FeedRefused("feed_malformed", f"{what} is text")
    return value


def _number(value, what: str) -> Decimal:
    """A JSON number (or a decimal string) as a ``Decimal``."""
    if isinstance(value, bool):
        raise FeedRefused("feed_value_malformed", f"{what} is not a number")
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, Decimal):
        return value
    if isinstance(value, str):
        try:
            return parse_decimal(value, what)
        except MoneyRefused:
            raise FeedRefused("feed_value_malformed", f"{what} {value!r} is not a plain decimal") from None
    raise FeedRefused("feed_value_malformed", f"{what} is not a number")


_INSTANT = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2})T[0-9]{2}:[0-9]{2}:[0-9]{2}(\.[0-9]{1,9})?(Z|[+-][0-9]{2}:[0-9]{2})")


def _instant_date(text, what: str) -> date:
    """The date of an ISO 8601 instant as the provider writes it
    (``2026-10-01T00:00:00Z``), in its own offset."""
    match = _INSTANT.fullmatch(text) if isinstance(text, str) else None
    if match is None:
        raise FeedRefused("feed_value_malformed", f"{what} {str(text)[:40]!r} is not an ISO 8601 instant")
    return _day(match.group(1), what)


# ------------------------------------------------------------------- AWS


AWS_FIELDS = frozenset({"formatVersion", "disclaimer", "offerCode", "version", "publicationDate", "products", "terms"})
AWS_OPTIONAL = frozenset({"attributesList"})
AWS_PRODUCT = frozenset({"sku", "attributes"})
AWS_PRODUCT_OPTIONAL = frozenset({"productFamily"})
AWS_TERM = frozenset({"offerTermCode", "sku", "effectiveDate", "priceDimensions", "termAttributes"})
AWS_DIMENSION = frozenset({"rateCode", "description", "beginRange", "endRange", "unit", "pricePerUnit", "appliesTo"})


def _aws(feed: FeedSource, pages, as_of, requests, filing) -> list:
    (raw,) = pages
    document = _fields(_json(raw), AWS_FIELDS, AWS_OPTIONAL, "an AWS offer file")
    config = feed.config
    if document["formatVersion"] != "v1.0" or document["offerCode"] != config["offer_code"]:
        raise FeedRefused("feed_mismatch", f"offer {document['offerCode']!r} {document['formatVersion']!r}")
    _instant_date(document["publicationDate"], "publicationDate")
    products, terms = document["products"], document["terms"]
    if not isinstance(products, dict) or not isinstance(terms, dict) or "OnDemand" not in terms:
        raise FeedRefused("feed_malformed", "products and terms are objects, and terms hold OnDemand")
    families = {}
    for sku, product in products.items():
        _fields(product, AWS_PRODUCT, AWS_PRODUCT_OPTIONAL, f"product {sku}")
        attributes = product["attributes"]
        if product["sku"] != sku or not isinstance(attributes, dict):
            raise FeedRefused("feed_malformed", f"product {sku} names itself and holds its attributes")
        if not all(isinstance(k, str) and isinstance(v, str) for k, v in attributes.items()):
            raise FeedRefused("feed_malformed", f"product {sku}'s attributes are text")
        if attributes.get("regionCode", config["region"]) != config["region"]:
            raise FeedRefused("feed_mismatch", f"product {sku} is in {attributes['regionCode']}, not {config['region']}")
        families[sku] = product.get("productFamily", "")
    for term_type, offers in terms.items():
        if not isinstance(offers, dict) or not all(isinstance(v, dict) for v in offers.values()):
            raise FeedRefused("feed_malformed", f"terms {term_type} map each SKU to its offers")
    prices = []
    for sku, offers in terms["OnDemand"].items():
        if sku not in products:
            raise FeedRefused("feed_mismatch", f"an on-demand term names {sku}, which is no product")
        for term_key, term in offers.items():
            _fields(term, AWS_TERM, frozenset(), f"term {term_key}")
            if term["sku"] != sku or term_key != f"{sku}.{term['offerTermCode']}":
                raise FeedRefused("feed_malformed", f"term {term_key} names its SKU and offer term")
            effective = _instant_date(term["effectiveDate"], f"term {term_key} effectiveDate")
            if not isinstance(term["priceDimensions"], dict) or not term["priceDimensions"]:
                raise FeedRefused("feed_malformed", f"term {term_key} holds its price dimensions")
            for rate_code, dimension in term["priceDimensions"].items():
                _fields(dimension, AWS_DIMENSION, frozenset(), f"rate {rate_code}")
                if dimension["rateCode"] != rate_code or not rate_code.startswith(term_key + "."):
                    raise FeedRefused("feed_malformed", f"rate {rate_code} names itself under its term")
                price = dimension["pricePerUnit"]
                if not isinstance(price, dict) or "USD" not in price:
                    raise FeedRefused("feed_mismatch", f"rate {rate_code} states no USD price")
                begin = _number(dimension["beginRange"], f"rate {rate_code} beginRange")
                if dimension["endRange"] != "Inf" and _number(dimension["endRange"], f"rate {rate_code} endRange") < begin:
                    raise FeedRefused("feed_value_malformed", f"rate {rate_code} ends before it begins")
                prices.append(
                    PriceObservation(
                        provider=feed.provider,
                        sku=sku,
                        observation_id=rate_code,
                        region=config["region"],
                        unit=_text(dimension["unit"], f"rate {rate_code} unit"),
                        usd_price=_number(price["USD"], f"rate {rate_code} USD"),
                        effective_date=effective,
                        tier_start=begin,
                        product=" ".join(filter(None, (document["offerCode"], families[sku]))),
                        description=_text(dimension["description"], f"rate {rate_code} description"),
                    )
                )
    return prices


# ------------------------------------------------------------------- Azure


AZURE_PAGE = frozenset({"BillingCurrency", "CustomerEntityId", "CustomerEntityType", "Items", "NextPageLink", "Count"})
AZURE_ITEM = frozenset(
    {
        "currencyCode", "tierMinimumUnits", "retailPrice", "unitPrice", "armRegionName", "location",
        "effectiveStartDate", "meterId", "meterName", "productId", "skuId", "productName", "skuName", "serviceName",
        "serviceId", "serviceFamily", "unitOfMeasure", "type", "isPrimaryMeterRegion", "armSkuName",
    }
)
AZURE_ITEM_OPTIONAL = frozenset({"availabilityId", "reservationTerm", "savingsPlan", "effectiveEndDate"})


def _azure(feed: FeedSource, pages, as_of, requests, filing) -> list:
    config = feed.config
    prices = []
    for number, raw in enumerate(pages, start=1):
        page = _fields(_json(raw), AZURE_PAGE, frozenset(), f"Azure page {number}")
        if (page["BillingCurrency"], page["CustomerEntityType"]) != ("USD", "Retail"):
            raise FeedRefused("feed_mismatch", f"page {number} is not retail prices in USD")
        items = page["Items"]
        if not isinstance(items, list) or not isinstance(page["Count"], int) or page["Count"] != len(items):
            raise FeedRefused("feed_partial", f"page {number} says {page['Count']} items and holds {len(items)}")
        last = number == len(pages)
        if (page["NextPageLink"] is None) != last:
            raise FeedRefused("feed_partial", f"page {number} of {len(pages)} names a next page, or the last does not")
        for position, item in enumerate(items):
            _fields(item, AZURE_ITEM, AZURE_ITEM_OPTIONAL, f"page {number} item {position}")
            if (item["serviceName"], item["armRegionName"], item["type"], item["currencyCode"]) != (
                config["service"], config["region"], "Consumption", "USD"
            ):
                raise FeedRefused("feed_mismatch", f"page {number} item {position} is not what was asked")
            tier = _number(item["tierMinimumUnits"], f"page {number} item {position} tierMinimumUnits")
            meter, sku = _text(item["meterId"], "meterId"), _text(item["skuId"], "skuId")
            prices.append(
                PriceObservation(
                    provider=feed.provider,
                    sku=sku,
                    observation_id=f"{meter}/{sku}/{decimal_text(tier)}",
                    region=item["armRegionName"],
                    unit=_text(item["unitOfMeasure"], "unitOfMeasure"),
                    usd_price=_number(item["retailPrice"], f"page {number} item {position} retailPrice"),
                    effective_date=_instant_date(item["effectiveStartDate"], "effectiveStartDate"),
                    tier_start=tier,
                    product=_text(item["productName"], "productName"),
                    description=_text(item["meterName"], "meterName"),
                )
            )
    return prices


# ------------------------------------------------------------------- GCP


GCP_PAGE_OPTIONAL = frozenset({"nextPageToken"})
GCP_SKU = frozenset({"name", "skuId", "description", "category", "serviceRegions", "pricingInfo", "serviceProviderName"})
GCP_SKU_OPTIONAL = frozenset({"geoTaxonomy"})
GCP_CATEGORY = frozenset({"serviceDisplayName", "resourceFamily", "resourceGroup", "usageType"})
GCP_PRICING = frozenset({"summary", "pricingExpression", "currencyConversionRate", "effectiveTime"})
GCP_PRICING_OPTIONAL = frozenset({"aggregationInfo"})
GCP_EXPRESSION = frozenset({"usageUnit", "usageUnitDescription", "baseUnit", "baseUnitDescription",
                            "baseUnitConversionFactor", "displayQuantity", "tieredRates"})
GCP_RATE_OPTIONAL = frozenset({"startUsageAmount", "unitPrice"})
GCP_MONEY = frozenset({"currencyCode"})
GCP_MONEY_OPTIONAL = frozenset({"units", "nanos"})
_UNITS = re.compile(r"[0-9]{1,18}")
NANOS = Decimal(10) ** 9


def _gcp_price(money, what: str) -> Decimal:
    """A ``google.type.Money`` as a ``Decimal``: ``units`` (a whole number, as text,
    absent for zero) plus ``nanos`` billionths (absent for zero)."""
    _fields(money, GCP_MONEY, GCP_MONEY_OPTIONAL, what)
    if money["currencyCode"] != "USD":
        raise FeedRefused("feed_mismatch", f"{what} is in {money['currencyCode']!r}, not USD")
    units, nanos = money.get("units", "0"), money.get("nanos", 0)
    if not isinstance(units, str) or not _UNITS.fullmatch(units) or type(nanos) is not int or not 0 <= nanos < 10**9:
        raise FeedRefused("feed_value_malformed", f"{what} units {units!r}, nanos {nanos!r}")
    return Decimal(units) + Decimal(nanos) / NANOS


def _gcp(feed: FeedSource, pages, as_of, requests, filing) -> list:
    config = feed.config
    wanted = set(config["regions"])
    prices = []
    for number, raw in enumerate(pages, start=1):
        page = _fields(_json(raw), frozenset({"skus"}), GCP_PAGE_OPTIONAL, f"GCP page {number}")
        if not isinstance(page["skus"], list):
            raise FeedRefused("feed_malformed", f"page {number}'s skus are a list")
        if bool(page.get("nextPageToken", "")) == (number == len(pages)):
            raise FeedRefused("feed_partial", f"page {number} of {len(pages)} names a next page, or the last does not")
        for position, sku in enumerate(page["skus"]):
            _fields(sku, GCP_SKU, GCP_SKU_OPTIONAL, f"page {number} SKU {position}")
            sku_id = _text(sku["skuId"], "skuId")
            if sku["name"] != f"services/{config['service_id']}/skus/{sku_id}":
                raise FeedRefused("feed_mismatch", f"SKU {sku_id} is not of service {config['service_id']}")
            category = _fields(sku["category"], GCP_CATEGORY, frozenset(), f"SKU {sku_id} category")
            if category["serviceDisplayName"] != config["service"]:
                raise FeedRefused("feed_mismatch", f"SKU {sku_id} is of {category['serviceDisplayName']!r}")
            regions = sku["serviceRegions"]
            if not isinstance(regions, list) or not all(isinstance(r, str) and r for r in regions):
                raise FeedRefused("feed_malformed", f"SKU {sku_id}'s serviceRegions are names")
            if not isinstance(sku["pricingInfo"], list) or not sku["pricingInfo"]:
                raise FeedRefused("feed_malformed", f"SKU {sku_id} holds its pricing")
            for info in sku["pricingInfo"]:
                _fields(info, GCP_PRICING, GCP_PRICING_OPTIONAL, f"SKU {sku_id} pricingInfo")
                if _number(info["currencyConversionRate"], "currencyConversionRate") != 1:
                    raise FeedRefused("feed_mismatch", f"SKU {sku_id} is converted from another currency")
                effective = _instant_date(info["effectiveTime"], f"SKU {sku_id} effectiveTime")
                expression = _fields(info["pricingExpression"], GCP_EXPRESSION, frozenset(), f"SKU {sku_id} expression")
                unit = _text(expression["usageUnit"], f"SKU {sku_id} usageUnit")
                rates = expression["tieredRates"]
                if not isinstance(rates, list) or not rates:
                    raise FeedRefused("feed_malformed", f"SKU {sku_id} holds its tiered rates")
                for rate in rates:
                    _fields(rate, frozenset(), GCP_RATE_OPTIONAL, f"SKU {sku_id} rate")
                    if "unitPrice" not in rate:
                        raise FeedRefused("feed_malformed", f"SKU {sku_id} rate states no unitPrice")
                    start = _number(rate.get("startUsageAmount", 0), f"SKU {sku_id} startUsageAmount")
                    price = _gcp_price(rate["unitPrice"], f"SKU {sku_id} unitPrice")
                    for region in sorted(wanted & set(regions)):
                        prices.append(
                            PriceObservation(
                                provider=feed.provider,
                                sku=sku_id,
                                observation_id=f"{sku_id}@{region}#{decimal_text(start)}@{effective.isoformat()}",
                                region=region,
                                unit=unit,
                                usd_price=price,
                                effective_date=effective,
                                tier_start=start,
                                product=category["serviceDisplayName"],
                                description=_text(sku["description"], f"SKU {sku_id} description"),
                            )
                        )
    return prices


# ------------------------------------------------------------------- EDGAR


SUBMISSIONS_FIELDS = frozenset({"cik", "entityType", "sic", "sicDescription", "name", "tickers", "exchanges", "filings"})
SUBMISSIONS_OPTIONAL = frozenset(
    {
        "ein", "lei", "description", "website", "investorWebsite", "category", "fiscalYearEnd", "stateOfIncorporation",
        "stateOfIncorporationDescription", "addresses", "phone", "flags", "formerNames", "ownerOrg",
        "insiderTransactionForOwnerExists", "insiderTransactionForIssuerExists",
    }
)
RECENT_COLUMNS = frozenset(
    {
        "accessionNumber", "filingDate", "reportDate", "acceptanceDateTime", "act", "form", "fileNumber", "filmNumber",
        "items", "size", "isXBRL", "isInlineXBRL", "primaryDocument", "primaryDocDescription",
    }
)
RECENT_OPTIONAL = frozenset({"core_type"})


def _cik_of(value, what: str) -> str:
    text = str(value) if isinstance(value, int) and not isinstance(value, bool) else value
    if not isinstance(text, str) or not text.isdigit() or len(text) > 10:
        raise FeedRefused("feed_malformed", f"{what} {value!r} is not a CIK")
    return text.zfill(10)


def _edgar_submissions(feed: FeedSource, pages, as_of, requests, filing) -> list:
    (raw,) = pages
    document = _fields(_json(raw), SUBMISSIONS_FIELDS, SUBMISSIONS_OPTIONAL, "an EDGAR submissions document")
    cik = feed.config["cik"]
    if _cik_of(document["cik"], "cik") != cik:
        raise FeedRefused("feed_mismatch", f"the submissions are of CIK {document['cik']}, not {cik}")
    tickers, exchanges = document["tickers"], document["exchanges"]
    if not isinstance(tickers, list) or not isinstance(exchanges, list):
        raise FeedRefused("feed_malformed", "tickers and exchanges are lists")
    entity = CompanyEntity(
        cik=cik,
        name=_text(document["name"], "name"),
        entity_type=document["entityType"] if isinstance(document["entityType"], str) else "",
        tickers=tuple(tickers),
        exchanges=tuple(e for e in exchanges if e is not None),
    )
    filings = _fields(document["filings"], frozenset({"recent", "files"}), frozenset(), "filings")
    recent = _fields(filings["recent"], RECENT_COLUMNS, RECENT_OPTIONAL, "filings.recent")
    lengths = {name: len(column) if isinstance(column, list) else -1 for name, column in recent.items()}
    if min(lengths.values()) < 0 or len(set(lengths.values())) != 1:
        raise FeedRefused("feed_partial", f"the recent filings' columns are lists of one length: {lengths}")
    records: list = [entity]
    for row in range(lengths["accessionNumber"]):
        accession = recent["accessionNumber"][row]
        report = recent["reportDate"][row]
        inline = recent["isInlineXBRL"][row]
        if inline not in (0, 1) or isinstance(inline, bool):
            raise FeedRefused("feed_value_malformed", f"filing {accession!r} isInlineXBRL {inline!r}")
        if not isinstance(report, str):
            raise FeedRefused("feed_value_malformed", f"filing {accession!r} reportDate {report!r}")
        records.append(
            CompanyFiling(
                cik=cik,
                accession=accession,
                form=recent["form"][row],
                filing_date=_day(recent["filingDate"][row], f"filing {accession} filingDate"),
                report_date=_day(report, f"filing {accession} reportDate") if report else None,
                primary_document=recent["primaryDocument"][row],
                inline_xbrl=inline == 1,
            )
        )
    return records


FACTS_FIELDS = frozenset({"cik", "entityName", "facts"})
CONCEPT_FIELDS = frozenset({"label", "description", "units"})
FACT_FIELDS = frozenset({"end", "val", "accn", "fy", "fp", "form", "filed"})
FACT_OPTIONAL = frozenset({"start", "frame"})


def _edgar_companyfacts(feed: FeedSource, pages, as_of, requests, filing) -> list:
    (raw,) = pages
    document = _fields(_json(raw), FACTS_FIELDS, frozenset(), "an EDGAR companyfacts document")
    cik = feed.config["cik"]
    if _cik_of(document["cik"], "cik") != cik:
        raise FeedRefused("feed_mismatch", f"the facts are of CIK {document['cik']}, not {cik}")
    entity = _text(document["entityName"], "entityName")
    taxonomies = document["facts"]
    if not isinstance(taxonomies, dict):
        raise FeedRefused("feed_malformed", "facts map each taxonomy to its concepts")
    wanted = set(REVENUE_CONCEPTS) | set(OPERATING_INCOME_CONCEPTS)
    records = []
    for taxonomy, concepts in taxonomies.items():
        if not isinstance(concepts, dict):
            raise FeedRefused("feed_malformed", f"taxonomy {taxonomy} maps each concept to its facts")
        for concept, held in concepts.items():
            _fields(held, CONCEPT_FIELDS, frozenset(), f"{taxonomy}:{concept}")
            if not isinstance(held["units"], dict):
                raise FeedRefused("feed_malformed", f"{taxonomy}:{concept} maps each unit to its facts")
            for unit, facts in held["units"].items():
                if not isinstance(facts, list):
                    raise FeedRefused("feed_malformed", f"{taxonomy}:{concept} {unit} is a list of facts")
                for fact in facts:
                    _fields(fact, FACT_FIELDS, FACT_OPTIONAL, f"a {taxonomy}:{concept} fact")
                    value = _number(fact["val"], f"{concept} val")
                    end = _day(fact["end"], f"{concept} end")
                    filed = _day(fact["filed"], f"{concept} filed")
                    start = _day(fact["start"], f"{concept} start") if "start" in fact else None
                    if not isinstance(fact["accn"], str) or not _ACCESSION.fullmatch(fact["accn"]):
                        raise FeedRefused("feed_value_malformed", f"{concept} accn {fact['accn']!r}")
                    if not (fact["fy"] is None or (isinstance(fact["fy"], int) and not isinstance(fact["fy"], bool))):
                        raise FeedRefused("feed_value_malformed", f"{concept} fy {fact['fy']!r}")
                    if not (fact["fp"] is None or isinstance(fact["fp"], str)):
                        raise FeedRefused("feed_value_malformed", f"{concept} fp {fact['fp']!r}")
                    if (
                        taxonomy != "us-gaap" or concept not in wanted or unit != "USD" or start is None
                    ):
                        continue
                    records.append(
                        CompanyFact(
                            cik=cik,
                            entity=entity,
                            concept=f"us-gaap:{concept}",
                            period_start=start,
                            period_end=end,
                            value=value,
                            unit=unit,
                            form=_text(fact["form"], f"{concept} form"),
                            filed=filed,
                            accession=fact["accn"],
                            fiscal_year="" if fact["fy"] is None else str(fact["fy"]),
                            fiscal_period=fact["fp"] or "",
                        )
                    )
    return records


XBRLI = "http://www.xbrl.org/2003/instance"
XBRLDI = "http://xbrl.org/2006/xbrldi"
ISO4217 = "http://www.xbrl.org/2003/iso4217"
SEC_CIK_SCHEME = "http://www.sec.gov/CIK"
_US_GAAP = re.compile(r"http://fasb\.org/us-gaap/[0-9]{4}")
_DEI = re.compile(r"http://xbrl\.sec\.gov/dei/[0-9]{4}")
_NIL = "{http://www.w3.org/2001/XMLSchema-instance}nil"


def _xml(raw: bytes):
    """The root element of ``raw`` and its namespace prefixes, ``{prefix: uri}``.
    A document type or an entity declaration is refused outright: nothing here
    expands an entity or reads a DTD. A prefix bound to two namespaces is refused,
    since the QNames read here are resolved document-wide."""
    if not isinstance(raw, bytes):
        raise TypeError("a response is read from its bytes")
    if b"<!DOCTYPE" in raw or b"<!ENTITY" in raw:
        raise FeedRefused("feed_malformed", "a document type or an entity declaration")
    prefixes: dict[str, str] = {}
    root = None
    try:
        for event, item in ET.iterparse(io.BytesIO(raw), events=("start-ns", "start")):
            if event == "start-ns":
                prefix, uri = item
                if prefixes.setdefault(prefix, uri) != uri:
                    raise FeedRefused("feed_malformed", f"the prefix {prefix!r} names two namespaces")
            elif root is None:
                root = item
    except ET.ParseError:
        raise FeedRefused("feed_malformed", "not well-formed XML") from None
    if root is None:
        raise FeedRefused("feed_malformed", "no element")
    return root, prefixes


def _qname(text, prefixes: dict[str, str], what: str) -> tuple[str, str]:
    if not isinstance(text, str) or text.strip().count(":") != 1:
        raise FeedRefused("feed_malformed", f"{what} {text!r} is not a prefixed name")
    prefix, local = text.strip().split(":")
    if prefix not in prefixes:
        raise FeedRefused("feed_malformed", f"{what} {text!r}: the prefix is not declared")
    return prefixes[prefix], local


def _split(tag: str) -> tuple[str, str]:
    if tag.startswith("{"):
        uri, _, local = tag[1:].partition("}")
        return uri, local
    return "", tag


def _edgar_instance(feed: FeedSource, pages, as_of, requests, filing) -> list:
    (raw,) = pages
    root, prefixes = _xml(raw)
    if root.tag != f"{{{XBRLI}}}xbrl":
        raise FeedRefused("feed_malformed", "not an XBRL instance")
    cik = feed.config["cik"]
    contexts: dict[str, tuple] = {}
    for context in root.findall(f"{{{XBRLI}}}context"):
        name = context.get("id")
        identifier = context.find(f"{{{XBRLI}}}entity/{{{XBRLI}}}identifier")
        period = context.find(f"{{{XBRLI}}}period")
        if not name or identifier is None or period is None or name in contexts:
            raise FeedRefused("feed_malformed", f"context {name!r} has one id, its entity and its period")
        if identifier.get("scheme") != SEC_CIK_SCHEME or _cik_of((identifier.text or "").strip(), "identifier") != cik:
            raise FeedRefused("feed_mismatch", f"context {name} is not of CIK {cik}")
        segment = context.find(f"{{{XBRLI}}}entity/{{{XBRLI}}}segment")
        members = []
        if segment is not None:
            for member in segment:
                if member.tag != f"{{{XBRLDI}}}explicitMember":
                    members.append(None)  # a typed member: not a segment this reads
                    continue
                members.append(
                    (_qname(member.get("dimension"), prefixes, "dimension"), (member.text or "").strip(),
                     member.get("dimension").strip())
                )
        start, end = period.find(f"{{{XBRLI}}}startDate"), period.find(f"{{{XBRLI}}}endDate")
        dates = None
        if start is not None and end is not None:
            dates = (_day((start.text or "").strip(), f"context {name} startDate"),
                     _day((end.text or "").strip(), f"context {name} endDate"))
        contexts[name] = (dates, members)
    units: dict[str, bool] = {}
    for unit in root.findall(f"{{{XBRLI}}}unit"):
        measures = unit.findall(f"{{{XBRLI}}}measure")
        if not unit.get("id"):
            raise FeedRefused("feed_malformed", "a unit has its id")
        units[unit.get("id")] = len(measures) == 1 and _qname(measures[0].text, prefixes, "measure") == (ISO4217, "USD")
    document_type, fiscal_year, fiscal_period, registrant = None, "", "", ""
    seen: dict[tuple, Decimal] = {}
    records = []
    for element in root:
        uri, local = _split(element.tag)
        if _DEI.fullmatch(uri):
            text = (element.text or "").strip()
            if local == "DocumentType":
                document_type = text
            elif local == "DocumentFiscalYearFocus":
                fiscal_year = text
            elif local == "DocumentFiscalPeriodFocus":
                fiscal_period = text
            elif local == "EntityRegistrantName":
                registrant = text
            continue
        if not _US_GAAP.fullmatch(uri) or local not in REVENUE_CONCEPTS or element.get(_NIL) == "true":
            continue
        context, unit = element.get("contextRef"), element.get("unitRef")
        if context not in contexts or unit not in units:
            raise FeedRefused("feed_malformed", f"{local} names a context or unit the instance does not hold")
        dates, members = contexts[context]
        if not units[unit] or dates is None:
            continue
        if members and (len(members) != 1 or members[0] is None or members[0][0] != (uri, SEGMENT_AXIS)):
            continue  # another axis (a product, a geography): not segment revenue
        try:
            value = parse_decimal((element.text or "").strip(), f"{local} in {context}")
        except MoneyRefused:
            raise FeedRefused("feed_value_malformed", f"{local} in {context} is not a plain decimal") from None
        axis, member = (members[0][2], members[0][1]) if members else ("", "")
        if members:
            _qname(member, prefixes, "member")
        key = (local, dates, axis, member)
        if key in seen:
            if seen[key] != value:
                raise FeedRefused("feed_mismatch", f"{local} {dates} {member or 'company'} is stated twice, differently")
            continue
        seen[key] = value
        records.append((local, dates, value, axis, member))
    if document_type != filing.form:
        raise FeedRefused("feed_mismatch", f"the instance is a {document_type!r}, the filing a {filing.form}")
    entity = registrant or f"CIK {cik}"
    return [
        CompanyFact(
            cik=cik, entity=entity, concept=f"us-gaap:{local}", period_start=dates[0], period_end=dates[1], value=value,
            unit="USD", form=filing.form, filed=filing.filing_date, accession=filing.accession,
            fiscal_year=fiscal_year, fiscal_period=fiscal_period, segment_axis=axis, segment_member=member,
        )
        for local, dates, value, axis, member in records
    ]


# ------------------------------------------------------------- enforcement


def _child_text(item, name: str, what: str, *, required: bool = True) -> str | None:
    found = item.findall(name)
    if len(found) > 1:
        raise FeedRefused("feed_malformed", f"{what} has two {name} elements")
    if not found:
        if required:
            raise FeedRefused("feed_malformed", f"{what} has no {name}")
        return None
    return (found[0].text or "").strip()


def _rss_items(raw: bytes) -> list[dict]:
    """Every item of an RSS 2.0 channel, as its text: title, link, pubDate, guid,
    description and categories. One channel; its own dates are not read."""
    root, _prefixes = _xml(raw)
    if root.tag != "rss" or root.get("version") != "2.0":
        raise FeedRefused("feed_malformed", "not RSS 2.0")
    channels = root.findall("channel")
    if len(channels) != 1:
        raise FeedRefused("feed_malformed", "an RSS document holds one channel")
    items = []
    for number, item in enumerate(channels[0].findall("item")):
        what = f"item {number}"
        items.append(
            {
                "title": _child_text(item, "title", what),
                "link": _child_text(item, "link", what),
                "pubDate": _child_text(item, "pubDate", what),
                "guid": _child_text(item, "guid", what, required=False),
                "description": _child_text(item, "description", what, required=False),
                "category": sorted((c.text or "").strip() for c in item.findall("category")),
            }
        )
    return items


def _host(url: str, host: str, what: str) -> str:
    _https_url(url, what)
    if urlsplit(url).hostname != host:
        raise FeedRefused("feed_mismatch", f"{what} {url[:120]!r} is not on {host}")
    return url


def _rss(feed: FeedSource, pages, as_of, requests, filing) -> list:
    (raw,) = pages
    config = feed.config
    records = []
    for number, item in enumerate(_rss_items(raw)):
        if not item["title"] or not item["link"] or not item["pubDate"]:
            raise FeedRefused("feed_malformed", f"item {number} has a title, a link and a pubDate")
        try:
            published = email.utils.parsedate_to_datetime(item["pubDate"])
        except (TypeError, ValueError, IndexError):
            raise FeedRefused("feed_value_malformed", f"item {number} pubDate {item['pubDate'][:40]!r}") from None
        if published is None or published.tzinfo is None:
            raise FeedRefused("feed_value_malformed", f"item {number} pubDate names no offset")
        records.append(
            EnforcementRecord(
                agency=config["agency"],
                record_id=item["guid"] or item["link"],
                action_date=published.date(),
                respondent=item["title"] if config["respondent_from"] == "title" else None,
                category=config["category"],
                civil_money_penalty=None,
                restitution=None,
                settlement=None,
                citation_url=_host(item["link"], config["host"], f"item {number} link"),
                citation_text=item["title"],
            )
        )
    return records


_US_DATE = re.compile(r"(0[1-9]|1[0-2])/(0[1-9]|[12][0-9]|3[01])/([0-9]{4})")
_AMOUNT = re.compile(r"\$?([0-9]{1,3}(?:,[0-9]{3})+|[0-9]+)(\.[0-9]{2})?")


def _us_date(text: str, what: str) -> date:
    match = _US_DATE.fullmatch(text)
    if match is None:
        raise FeedRefused("feed_value_malformed", f"{what} {text[:20]!r} is not MM/DD/YYYY")
    try:
        return date(int(match.group(3)), int(match.group(1)), int(match.group(2)))
    except ValueError:
        raise FeedRefused("feed_value_malformed", f"{what} {text!r} is not a date") from None


def _amount(text: str, what: str) -> Decimal | None:
    """An amount the listing states (``$1,250,000``, ``1250000.00``), or ``None`` for a
    blank cell. Anything else is refused: never read out of prose."""
    if not text.strip():
        return None
    match = _AMOUNT.fullmatch(text.strip())
    if match is None:
        raise FeedRefused("feed_value_malformed", f"{what} {text[:30]!r} is not an amount")
    return parse_decimal(match.group(1).replace(",", "") + (match.group(2) or ""), what)


def _enforcement_csv(feed: FeedSource, pages, as_of, requests, filing) -> list:
    (raw,) = pages
    config = feed.config
    rows = _csv(raw)
    header, lines = rows[0], rows[1:]
    if tuple(header) != tuple(config["header"]):
        raise FeedRefused("feed_malformed", f"the columns are not {list(config['header'])}")
    records = []
    for number, line in enumerate(lines, start=2):
        if len(line) != len(header):
            raise FeedRefused("feed_partial", f"line {number} has {len(line)} of {len(header)} columns")
        cell = dict(zip(header, line, strict=True))
        respondents = [cell[name].strip() for name in config["respondent"] if cell[name].strip()]
        if len(respondents) != 1:
            raise FeedRefused("feed_value_malformed", f"line {number} names {len(respondents)} respondents, not one")
        action = cell[config["action"]].strip()
        if not action:
            raise FeedRefused("feed_value_malformed", f"line {number} names no action")
        acted = _us_date(cell[config["date"]], f"line {number} {config['date']}")
        stated = {name: None for name in EnforcementRecord.AMOUNTS}
        used = set()
        for field_name, column, when in config["amounts"]:
            if when and action != when:
                continue
            stated[field_name] = _amount(cell[column], f"line {number} {column}")
            used.add(column)
        for _field, column, _when in config["amounts"]:
            if column not in used and cell[column].strip():
                raise FeedRefused(
                    "feed_value_malformed", f"line {number} states an amount for a {action!r}, which states none"
                )
        url = _host(cell[config["url"]].strip(), config["host"], f"line {number} {config['url']}")
        identity = cell[config["record_id"]].strip() if config["record_id"] else url
        if not identity:
            raise FeedRefused("feed_value_malformed", f"line {number} names no {config['record_id']}")
        records.append(
            EnforcementRecord(
                agency=config["agency"],
                record_id="|".join((identity, action, acted.isoformat())),
                action_date=acted,
                respondent=respondents[0],
                category=f"{config['category']}: {action}",
                civil_money_penalty=stated["civil_money_penalty"],
                restitution=stated["restitution"],
                settlement=stated["settlement"],
                citation_url=url,
                citation_text=f"{config['agency']} {action}, {respondents[0]}, {acted.isoformat()}",
            )
        )
    return records


# ----------------------------------------------------------------- the payload


#: What each adapter's payload hash normalises (spec, section 30.3).
NORMALISATION: Mapping[str, str] = MappingProxyType(
    {
        "aws": "nothing dropped: the offer file's JSON re-serialised canonically (sorted keys, no whitespace)",
        "azure": "nothing dropped: every page's JSON re-serialised canonically, in page order",
        "gcp": "each page's nextPageToken dropped (an opaque cursor), then every page re-serialised canonically",
        "edgar_submissions": "nothing dropped: the JSON re-serialised canonically",
        "edgar_companyfacts": "nothing dropped: the JSON re-serialised canonically",
        "edgar_instance": "nothing: the instance's bytes as they came",
        "rss": (
            "the channel's own elements (its lastBuildDate and pubDate, which move on every build) dropped: each "
            "item's title, link, pubDate, guid, description and categories, re-serialised canonically"
        ),
        "enforcement_csv": "nothing: the export's bytes as they came",
    }
)


def payload_hash(feed: FeedSource, pages) -> str:
    """``sha256:`` and the SHA-256 of the normalised payload of ``pages`` (one answer
    per page): the response hash a source version records, and the store
    deduplicates on."""
    pages = list(pages)
    if not pages or not all(isinstance(page, bytes) for page in pages):
        raise TypeError("an answer is read from its bytes, page by page")
    if feed.adapter in ("aws", "edgar_submissions", "edgar_companyfacts"):
        (raw,) = pages
        normalised = _canonical(_json(raw))
    elif feed.adapter == "azure":
        normalised = _canonical([_json(raw) for raw in pages])
    elif feed.adapter == "gcp":
        documents = []
        for raw in pages:
            document = _json(raw)
            if isinstance(document, dict):
                document = {name: value for name, value in document.items() if name != "nextPageToken"}
            documents.append(document)
        normalised = _canonical(documents)
    elif feed.adapter == "rss":
        (raw,) = pages
        normalised = _canonical({"items": _rss_items(raw)})
    elif feed.adapter in ("edgar_instance", "enforcement_csv"):
        (raw,) = pages
        normalised = raw
    else:
        raise FeedRefused("source_unrecognised", feed.key)
    return "sha256:" + hashlib.sha256(normalised).hexdigest()


_ADAPTERS = {
    "aws": _aws,
    "azure": _azure,
    "gcp": _gcp,
    "edgar_submissions": _edgar_submissions,
    "edgar_companyfacts": _edgar_companyfacts,
    "edgar_instance": _edgar_instance,
    "rss": _rss,
    "enforcement_csv": _enforcement_csv,
}
#: The adapters that read one answer; the others read every page of one.
SINGLE_PAGE = frozenset(set(_ADAPTERS) - {"azure", "gcp"})


def parse(
    feed: FeedSource,
    pages,
    *,
    as_of: date,
    retrieved_at: datetime,
    requests,
    filing: CompanyFiling | None = None,
) -> Snapshot:
    """``pages`` (``feed``'s answers to ``requests``, page by page) as a snapshot of
    records: the source version it is registered as (trust tier ``unverified``, the
    registry's licence class, retrieved at ``retrieved_at`` from the first request's
    recorded URL, which carries no key), and every record it holds. All or nothing:
    raises :class:`.feeds.FeedRefused` on any broken rule."""
    pages = list(pages)
    requests = list(requests)
    if not pages or len(pages) != len(requests):
        raise FeedRefused("feed_partial", "every page asked is answered")
    if feed.adapter in SINGLE_PAGE and len(pages) != 1:
        raise FeedRefused("feed_mismatch", f"{feed.key} is read from one answer")
    if len(pages) > int(feed.config.get("max_pages", 1)):
        raise FeedRefused("feed_over_limit", f"{len(pages)} pages; {feed.key} is read across at most "
                                             f"{feed.config.get('max_pages', 1)}")
    limit = int(feed.config.get("max_bytes", MAX_RESPONSE_BYTES))
    if sum(len(page) for page in pages) > limit:
        raise FeedRefused("response_too_large", f"{sum(len(page) for page in pages)} bytes")
    if feed.adapter == "edgar_instance" and filing is None:
        raise FeedRefused("filing_unknown", feed.key)
    digest = payload_hash(feed, pages)
    records = check_records(feed.kind, _ADAPTERS[feed.adapter](feed, pages, as_of, requests, filing))
    return Snapshot(
        snapshot_hash=digest,
        label=f"{feed.provider} feed {feed.key}, as known on {as_of.isoformat()}",
        synthetic=False,
        source=MappingProxyType(
            {
                "source_key": feed.key,
                "provider": feed.provider,
                "dataset": feed.dataset,
                "url": requests[0].recorded_url,
                "license_class": feed.license_class,
                # A fetched source is never trusted above unverified by its fetch.
                "trust_tier": TrustTier.UNVERIFIED.value,
                "retrieved_at": retrieved_at,
                "schema_version": feed.schema_version,
            }
        ),
        holidays=MappingProxyType({}),
        fx_rates=(),
        index_points=(),
        records=records,
        record_kind=feed.kind,
    )


def newest_periodic_filing(records, as_of: date) -> CompanyFiling | None:
    """The newest periodic report (10-K or 10-Q) in inline XBRL a filing watch lists,
    filed on or before ``as_of``: the filing whose XBRL instance segment revenue is
    read from."""
    candidates = [
        r for r in records
        if r.TYPE == CompanyFiling.TYPE and r.form in PERIODIC_FORMS and r.inline_xbrl and r.filing_date <= as_of
        and r.primary_document.endswith(".htm")
    ]
    if not candidates:
        return None
    return max(candidates, key=lambda r: (r.filing_date, r.accession))


def ages_from_retrieval(retrieved_at: datetime, as_of: date) -> int | None:
    """The age in days, on ``as_of``, of a version retrieved at ``retrieved_at`` (its
    UTC date); ``None`` where it was retrieved after ``as_of``."""
    if not isinstance(retrieved_at, datetime) or retrieved_at.tzinfo is None:
        raise TypeError("a retrieval time is an aware datetime")
    retrieved = retrieved_at.astimezone(timezone.utc).date()
    return None if retrieved > as_of else (as_of - retrieved).days


__all__ = [
    "CATALOG_MAX_BYTES",
    "CATALOG_REGISTRY",
    "CATALOG_SLA_DAYS",
    "CLOUD_PRICE",
    "COMPANY_FACT",
    "CONTEXT",
    "EDGAR_FAMILIES",
    "ENFORCEMENT",
    "FIGURE",
    "FILING_WATCH",
    "FORMAT_ASSUMED",
    "GATING",
    "INFORMATIONAL",
    "KINDS",
    "LICENCE_TERMS",
    "MAX_PAGES",
    "MAX_RECORDS",
    "NORMALISATION",
    "OBSERVATION",
    "OPERATING_INCOME_CONCEPTS",
    "PREFILL",
    "RECORDS_SCHEMA",
    "RETRIEVAL",
    "REVENUE_CONCEPTS",
    "SEGMENT_AXIS",
    "USES",
    "CompanyEntity",
    "CompanyFact",
    "CompanyFiling",
    "EnforcementRecord",
    "PriceObservation",
    "check_records",
    "edgar_cik",
    "edgar_key",
    "edgar_source",
    "known",
    "newest_periodic_filing",
    "next_request",
    "parse",
    "payload_hash",
    "read_record",
    "read_records",
    "records_digest",
    "records_json",
    "request_for",
    "source",
]
