"""Fetching a live feed into the snapshot store, the freshness of a feed source, and
a deployment's data health (MVP step 10; ``docs/economics/spec-v1.md``, section 29).

**Fetching** (:func:`fetch`, run by ``manage.py fetch_financial_source <source>
[--as-of DATE]``): one source of the feed registry
(:data:`assurance.economics.engine.feeds.REGISTRY`), as known on one date.

- Nothing is sent, and nothing written, unless the source is in the registry
  (``source_unrecognised``), its provider's key is set where it needs one
  (``source_key_missing``: the FRED key in ``ECONOMICS_FRED_API_KEY``, the BLS key in
  ``ECONOMICS_BLS_API_KEY``; ECB and H.10 need none), live fetching is switched on
  (``ECONOMICS_LIVE_FEEDS_ENABLED`` is ``True``; ``live_feeds_disabled``), and the date
  is one the provider can be asked for (``as_of_in_future``, ``as_of_unsupported``).
  The settings are read by their names, spelled out here; a key's value is never
  printed, logged, recorded or quoted, and a source version records the URL it was
  read from WITHOUT it.
- The request goes through the platform's outbound client (:mod:`safety.outbound`):
  no redirect is followed, nothing is read from the environment (no ``.netrc``, no
  proxy), and the key is withheld from any error; its own proxy, if the deployment
  needs one, is ``ECONOMICS_FEED_PROXY``, passed explicitly. A connect and read
  timeout of :data:`TIMEOUT`, and an answer of at most
  :data:`~assurance.economics.engine.feeds.MAX_RESPONSE_BYTES`.
- The answer is parsed by its adapter, all or nothing, and registered through the
  snapshot loader (:func:`assurance.economics.snapshots.register`) as a new
  platform-wide version at trust tier ``unverified`` -- a person raises it (spec,
  section 6.1) -- unless its normalised payload hash is one already recorded for the
  source: then nothing new is written but the fetch's own record, naming the version
  that holds it. Every fetch that sent a request is recorded once
  (:class:`~assurance.economics.models.FinancialSourceFetch`): recorded, unchanged, or
  refused with its code alone.

**The version a run uses** of a source (:func:`used_version`) is the latest one a
production run for its deployment may use (``FinancialSource.objects.usable_for_production``:
a reviewed licence, not synthetic, and in a production run above ``unverified``).
A newer version still waiting for a raise is not used; the gate's refusal of it is
shown (``gate``). Fetched versions never inherit a tier.

**Freshness** (:func:`source_state`): the used version's newest observation dated on
or before the as-of date (an FX rate's date; an index value's month's last day), its
age in days, and the source's state against its SLA:
``fresh``, ``stale`` (past the SLA), ``blocked`` (past twice it) or ``missing`` (no
version a run may use, no observation by the as-of date, or a key the registry does
not hold).

A parameter rests on a feed source when its ``evidence_ref`` names one,
``financial-source:<key>``. Nothing here is on a stop path, and no stop reads
anything it writes.

**MVP step 11** (spec, section 31) adds the cloud price catalogs, SEC EDGAR and the
regulators' enforcement listings (:mod:`assurance.economics.engine.catalogs`) to the
same fetch, store, freshness and data health:

- a catalog's answer is read whole -- every page of a paginated one (Azure, GCP),
  each through the same transport, BEFORE anything is parsed or written, so no
  transaction is open while a request is in flight -- and registered as a version
  with its records; the GCP key is ``ECONOMICS_GCP_BILLING_API_KEY`` (in the query),
  and SEC's declared User-Agent ``ECONOMICS_SEC_USER_AGENT`` (a header);
- a catalog's age runs from the day the version a run uses was retrieved, against
  its own SLA (cloud 7, EDGAR 1, enforcement 7). A cloud price's freshness GATES a
  figure resting on it as step 10's does; EDGAR's is INFORMATIONAL (the state is
  ``informational`` and ``age_state`` says what the age would be): it never lowers a
  grade or stops a receipt. A context source (enforcement, a filing watch, segment
  revenue) shows its age and never stops anything, and a figure never rests on one
  (``context_only_source``);
- data health lists them under ``catalog_sources``.
"""

from __future__ import annotations

import contextlib
import time
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from datetime import timezone as dt_timezone

import requests
from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import Max, Min, Q
from django.utils import timezone

from safety import outbound

from . import snapshots
from .engine import catalogs, cost_index, governance, money
from .engine import feeds as engine
from .models import (
    FETCH_RECORDED,
    FETCH_REFUSED,
    FETCH_UNCHANGED,
    CostIndexObservation,
    CustomerParameterSet,
    EconomicsRefused,
    FinancialParameter,
    FinancialScenario,
    FinancialSource,
    FinancialSourceFetch,
    FXObservation,
    fetch_codes,
    runs_in_production,
)

#: The connect and read timeouts of one fetch, in seconds: each socket operation's.
TIMEOUT = (5.0, 30.0)
#: The wall-clock budget of one fetch's whole answer, in seconds (review round 1,
#: NIT-1): a provider that drips its answer a byte at a time inside the read timeout
#: is cut off here (``fetch_deadline_exceeded``), never read for hours.
FETCH_DEADLINE_SECONDS = 120.0
#: The most parameters the data-health route lists as one source's Unknowns.
UNKNOWNS_LIMIT = 200
#: The step-11 catalogs answer XML too (an RSS listing, an XBRL instance).
_HEADERS = {
    "Accept": "text/csv, application/json, application/xml, application/rss+xml, text/xml",
    "User-Agent": "athena-backend economic-exposure feed",
}


# ------------------------------------------------------------------ settings


def live_feeds_enabled() -> bool:
    """``ECONOMICS_LIVE_FEEDS_ENABLED``: the one switch, off unless it is ``True``."""
    return getattr(settings, "ECONOMICS_LIVE_FEEDS_ENABLED", False) is True


def provider_key(feed: engine.FeedSource) -> str:
    """The key ``feed``'s provider needs, from its own setting, or ``""``. Each
    setting is named here as written; its value goes nowhere but the request."""
    if feed.key_setting == "ECONOMICS_FRED_API_KEY":
        value = getattr(settings, "ECONOMICS_FRED_API_KEY", "")
    elif feed.key_setting == "ECONOMICS_BLS_API_KEY":
        value = getattr(settings, "ECONOMICS_BLS_API_KEY", "")
    elif feed.key_setting == "ECONOMICS_GCP_BILLING_API_KEY":
        value = getattr(settings, "ECONOMICS_GCP_BILLING_API_KEY", "")
    elif feed.key_setting == "ECONOMICS_SEC_USER_AGENT":
        # Not a secret, but SEC's fair-access policy asks every request to say who
        # sends it: the owner's declared contact, sent as the User-Agent header.
        value = getattr(settings, "ECONOMICS_SEC_USER_AGENT", "")
    else:
        value = ""
    return value.strip() if isinstance(value, str) else ""


def known_source(key) -> engine.FeedSource | None:
    """The source ``key`` names: step 10's feed registry, or step 11's
    (:func:`assurance.economics.engine.catalogs.known`: the catalog registry and
    EDGAR's company sources). ``None`` for any other."""
    if not isinstance(key, str):
        return None
    return engine.REGISTRY.get(key) or catalogs.known(key)


def _feed_proxy() -> str:
    value = getattr(settings, "ECONOMICS_FEED_PROXY", "")
    return value.strip() if isinstance(value, str) else ""


def base_url(feed: engine.FeedSource) -> str:
    """Where ``feed`` is read from: the registry's base URL. (A test points this at a
    loopback service.)"""
    return feed.base_url


# ----------------------------------------------------------------- transport


class TransportFailed(Exception):
    """A fetch that was not answered, or whose answer was not read: its code only."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class OutboundTransport:
    """The feeds' lane of :mod:`safety.outbound`: no redirect, nothing from the
    environment, the key withheld from every error, its proxy only from
    ``ECONOMICS_FEED_PROXY``. Returns the answer's bytes, or raises
    :class:`TransportFailed` with a code."""

    def send(self, request: engine.FeedRequest, key: str) -> bytes:
        deadline = time.monotonic() + FETCH_DEADLINE_SECONDS
        proxy = _feed_proxy()
        withheld = tuple(v for v in (key, *outbound.logins_in(proxy)) if v)
        kwargs = {
            "headers": dict(_HEADERS),
            "timeout": TIMEOUT,
            "stream": True,
            "also_withhold": withheld,
        }
        if proxy:
            kwargs["proxies"] = {"http": proxy, "https": proxy}
        if key and request.key_in == "header":
            kwargs["headers"][request.key_name] = key
        try:
            if request.method == "GET":
                params = list(request.params)
                if key and request.key_in == "query":
                    params.append((request.key_name, key))
                response = outbound.get(request.url, params=params, **kwargs)
            else:
                body = {name: list(value) if isinstance(value, tuple) else value for name, value in request.body.items()}
                if key and request.key_in == "body":
                    body[request.key_name] = key
                response = outbound.post(request.url, json=body, **kwargs)
        except requests.RequestException:
            raise TransportFailed("fetch_failed") from None
        try:
            if response.status_code != 200:
                raise TransportFailed("fetch_http_error")
            content = b""
            if time.monotonic() > deadline:
                raise TransportFailed("fetch_deadline_exceeded")
            for chunk in response.iter_content(64 * 1024):
                content += chunk
                if len(content) > request.max_bytes:
                    raise TransportFailed("response_too_large")
                if time.monotonic() > deadline:
                    raise TransportFailed("fetch_deadline_exceeded")
            return content
        except requests.RequestException:
            raise TransportFailed("fetch_failed") from None
        finally:
            # Closing a finished answer decides nothing: a failure to close is not one.
            with contextlib.suppress(Exception):
                response.close()


# --------------------------------------------------------------------- fetch


@dataclass(frozen=True)
class FetchOutcome:
    """What :func:`fetch` did: ``recorded`` (a new version), ``unchanged`` (the payload
    was recorded already), or ``refused`` with its code. ``row`` is the fetch's
    record, ``None`` where nothing was sent and nothing written."""

    source_key: str
    outcome: str
    code: str | None = None
    version: FinancialSource | None = None
    row: FinancialSourceFetch | None = None
    payload_hash: str = ""
    observations: int = 0

    @property
    def meaning(self) -> str:
        if self.code is None:
            return ""
        return engine.FEED_REFUSALS.get(self.code) or money.REFUSALS.get(self.code) or self.code


def _refused_before_sending(source_key: str, code: str) -> FetchOutcome:
    return FetchOutcome(source_key, FETCH_REFUSED, code)


def _record_refusal(feed, as_of, code, payload_hash="") -> FetchOutcome:
    row = FinancialSourceFetch(
        source_key=feed.key, as_of=as_of, outcome=FETCH_REFUSED, code=code, payload_hash=payload_hash
    )
    row.save()
    return FetchOutcome(feed.key, FETCH_REFUSED, code, row=row, payload_hash=payload_hash)


def fetch(source_key: str, *, as_of: date | None = None, transport=None, now: datetime | None = None) -> FetchOutcome:
    """Fetch ``source_key`` as known on ``as_of`` (today, UTC, when ``None``) and
    record it. Never raises for a refusal: see the module's rules."""
    feed = known_source(source_key)
    if feed is None:
        return _refused_before_sending(str(source_key), "source_unrecognised")
    key = provider_key(feed)
    if feed.key_setting and not key:
        return _refused_before_sending(feed.key, "source_key_missing")
    if not live_feeds_enabled():
        return _refused_before_sending(feed.key, "live_feeds_disabled")
    now = now or timezone.now()
    today = now.astimezone(dt_timezone.utc).date()
    explicit = as_of is not None
    as_of = as_of if explicit else today
    if feed.key not in engine.REGISTRY:
        return _fetch_catalog(feed, key, as_of=as_of, explicit=explicit, today=today, now=now, transport=transport)
    try:
        request = engine.request_for(
            feed, as_of=as_of, explicit=explicit, today=today, base_url=base_url(feed),
            provider_today=engine.us_eastern_date(now),
        )
    except engine.FeedRefused as refused:
        return _refused_before_sending(feed.key, refused.code)
    try:
        raw = (transport or OutboundTransport()).send(request, key)
    except TransportFailed as failed:
        return _record_refusal(feed, as_of, failed.code)
    try:
        snapshot = engine.parse(feed, raw, as_of=as_of, retrieved_at=now, request=request)
    except engine.FeedRefused as refused:
        return _record_refusal(feed, as_of, refused.code, _hash_or_blank(feed, raw))
    except money.MoneyRefused as refused:
        return _record_refusal(feed, as_of, refused.code, _hash_or_blank(feed, raw))
    try:
        with transaction.atomic():
            version, created = snapshots.register(snapshot)
            row = FinancialSourceFetch(
                source_key=feed.key,
                as_of=as_of,
                outcome=FETCH_RECORDED if created else FETCH_UNCHANGED,
                payload_hash=snapshot.snapshot_hash,
                source=version,
            )
            row.save()
    except IntegrityError:
        return _record_refusal(feed, as_of, "fetch_conflict", snapshot.snapshot_hash)
    except EconomicsRefused as refused:
        return _record_refusal(feed, as_of, refused.code, snapshot.snapshot_hash)
    return FetchOutcome(
        feed.key, row.outcome, None, version, row, snapshot.snapshot_hash,
        len(snapshot.fx_rates) + len(snapshot.index_points),
    )


def _hash_or_blank(feed, raw: bytes) -> str:
    try:
        return engine.payload_hash(feed, raw)
    except (engine.FeedRefused, TypeError):
        return ""


def _catalog_hash_or_blank(feed, pages) -> str:
    try:
        return catalogs.payload_hash(feed, pages)
    except (engine.FeedRefused, TypeError):
        return ""


def _filing_to_read(feed: engine.FeedSource, as_of: date) -> catalogs.CompanyFiling | None:
    """The filing whose XBRL instance an EDGAR segment source reads: the newest
    periodic inline-XBRL filing (10-K or 10-Q) on or before ``as_of`` in the latest
    stored filing watch of the same company. A read, before anything is sent; no
    transaction is open."""
    watch = catalogs.edgar_key("submissions", catalogs.edgar_cik(feed.key))
    latest = _platform_versions(watch).order_by("-version").first()
    if latest is None:
        return None
    return catalogs.newest_periodic_filing(snapshots.records_of(latest), as_of)


def _fetch_catalog(feed, key, *, as_of, explicit, today, now, transport) -> FetchOutcome:
    """A step-11 fetch (spec, section 31.4): every page asked and read whole, one
    request at a time and with no transaction open, BEFORE anything is parsed; then
    parsed all or nothing and registered as step 10's fetch registers."""
    filing = None
    if feed.adapter == "edgar_instance":
        filing = _filing_to_read(feed, as_of)
        if filing is None:
            return _refused_before_sending(feed.key, "filing_unknown")
    try:
        request = catalogs.request_for(
            feed, as_of=as_of, explicit=explicit, today=today, base_url=base_url(feed),
            provider_today=engine.us_eastern_date(now), filing=filing,
        )
    except engine.FeedRefused as refused:
        return _refused_before_sending(feed.key, refused.code)
    sender = transport or OutboundTransport()
    pages: list[bytes] = []
    sent: list[engine.FeedRequest] = []
    most = int(feed.config.get("max_pages", 1))
    while request is not None:
        if len(pages) >= most:
            return _record_refusal(feed, as_of, "feed_over_limit")
        try:
            raw = sender.send(request, key)
        except TransportFailed as failed:
            return _record_refusal(feed, as_of, failed.code)
        pages.append(raw)
        sent.append(request)
        if sum(len(page) for page in pages) > int(feed.config.get("max_bytes", engine.MAX_RESPONSE_BYTES)):
            return _record_refusal(feed, as_of, "response_too_large")
        try:
            request = catalogs.next_request(feed, request, raw)
        except engine.FeedRefused as refused:
            return _record_refusal(feed, as_of, refused.code)
    try:
        snapshot = catalogs.parse(feed, pages, as_of=as_of, retrieved_at=now, requests=sent, filing=filing)
    except engine.FeedRefused as refused:
        return _record_refusal(feed, as_of, refused.code, _catalog_hash_or_blank(feed, pages))
    except money.MoneyRefused as refused:
        return _record_refusal(feed, as_of, refused.code, _catalog_hash_or_blank(feed, pages))
    try:
        with transaction.atomic():
            version, created = snapshots.register(snapshot)
            row = FinancialSourceFetch(
                source_key=feed.key,
                as_of=as_of,
                outcome=FETCH_RECORDED if created else FETCH_UNCHANGED,
                payload_hash=snapshot.snapshot_hash,
                source=version,
            )
            row.save()
    except IntegrityError:
        return _record_refusal(feed, as_of, "fetch_conflict", snapshot.snapshot_hash)
    except EconomicsRefused as refused:
        # A records row the store refuses is a value the answer held in a form the
        # store does not take: recorded by the fetch's own code.
        code = refused.code if refused.code in fetch_codes() else "feed_value_malformed"
        return _record_refusal(feed, as_of, code, snapshot.snapshot_hash)
    return FetchOutcome(feed.key, row.outcome, None, version, row, snapshot.snapshot_hash, len(snapshot.records))


# ------------------------------------------------------------------ freshness


def _platform_versions(key: str):
    return FinancialSource.objects.filter(deployment__isnull=True, source_key=key)


def _coverage_starts(key: str, tenant=None) -> tuple[dict[str, int], dict[str, int], dict[int, date]]:
    """For the platform-wide versions of ``key`` (or ``tenant``'s own, where one is
    given): ``{snapshot hash: the version
    holding its rows}`` (the earliest of that hash: a raised version holds none of its
    own), ``{snapshot hash: its newest version number}`` (a raise of the same payload
    supersedes the version it was raised from), and ``{holder: the date of its earliest
    observation}`` (an FX rate's date, or an index month's last day). Three reads."""
    holders: dict[str, int] = {}
    newest: dict[str, int] = {}
    for row in (
        FinancialSource._base_manager.filter(_scope(tenant), source_key=key)
        .order_by("version")
        .values("pk", "version", "snapshot_hash")
    ):
        holders.setdefault(row["snapshot_hash"], row["pk"])
        newest[row["snapshot_hash"]] = row["version"]
    ids = list(holders.values())
    starts: dict[int, date] = {
        row["source_id"]: row["first"]
        for row in FXObservation.objects.filter(source_id__in=ids).values("source_id").annotate(first=Min("effective_date"))
    }
    for row in (
        CostIndexObservation.objects.filter(source_id__in=ids).values("source_id").annotate(first=Min("period"))
    ):
        starts.setdefault(row["source_id"], cost_index.period_end(row["first"]))
    return holders, newest, starts


def _scope(tenant) -> Q:
    """Platform-wide versions, or ``tenant``'s own."""
    return Q(deployment__isnull=True) if tenant is None else Q(deployment=tenant)


def used_version(key: str, deployment, as_of: date, *, own: bool = False) -> FinancialSource | None:
    """The version of ``key`` a run of ``deployment`` dated ``as_of`` uses (the lead's
    decision on review round 1, MEDIUM-2): the NEWEST platform-wide version that is
    usable -- it passes the production gate for that deployment
    (``usable_for_production``) and no raise of the same payload supersedes it -- and
    whose coverage includes ``as_of``: it holds an observation dated on or before it.
    A version whose observations all fall after ``as_of`` does not cover it, and an
    older one that does is used instead; a date after a version's newest observation
    is covered, and only ages it (stale, blocked). None covers it: ``None``, and the
    source is ``missing``. With ``own``, the same rule over ``deployment``'s own
    versions of ``key`` (a normalization reads them, section 12.8)."""
    tenant = deployment if own else None
    if own and deployment is None:
        return None
    usable = list(
        FinancialSource.objects.usable_for_production(deployment)
        .filter(_scope(tenant), source_key=key)
        .order_by("-version")
    )
    if not usable:
        return None
    holders, newest, starts = _coverage_starts(key, tenant)
    feed = known_source(key)
    for version in usable:
        if newest.get(version.snapshot_hash) != version.version:
            continue
        if feed is not None and feed.age_basis == catalogs.RETRIEVAL:
            # A catalog covers a date once it was retrieved (spec, section 31.6).
            if catalogs.ages_from_retrieval(version.retrieved_at, as_of) is not None:
                return version
            continue
        start = starts.get(holders.get(version.snapshot_hash))
        if start is not None and start <= as_of:
            return version
    return None


def _holder(version: FinancialSource) -> int:
    """The version holding ``version``'s observations: the earliest of the same
    tenant, key and snapshot hash (a raised version holds none of its own)."""
    return (
        FinancialSource._base_manager.filter(
            deployment_id=version.deployment_id, source_key=version.source_key, snapshot_hash=version.snapshot_hash
        )
        .order_by("version")
        .values_list("pk", flat=True)
        .first()
    )


def data_through(version: FinancialSource, as_of: date) -> tuple[date | None, str | None]:
    """The newest observation of ``version`` dated on or before ``as_of``, and its
    kind (``fx`` or ``cost_index``): an FX rate's date, or the last day of an index
    value's month. ``(None, kind)`` with none.

    The age is measured on the data's own dates, whatever vintage the version was
    fetched in: a version fetched after ``as_of`` still says how far its publisher's
    series reached by then. (A month that ended before ``as_of`` but was published
    after it counts, which can understate the age by at most the publisher's lag; the
    vintages themselves are what a run READS, through the index book.)"""
    feed = known_source(version.source_key)
    if feed is not None and feed.age_basis == catalogs.RETRIEVAL:
        # A catalog's age runs from the day the version was retrieved (step 11).
        age = catalogs.ages_from_retrieval(version.retrieved_at, as_of)
        return (None if age is None else as_of - timedelta(days=age)), feed.kind
    holder = _holder(version)
    fx = FXObservation.objects.filter(source_id=holder)
    if fx.exists():
        newest = fx.filter(effective_date__lte=as_of).aggregate(newest=Max("effective_date"))["newest"]
        return newest, engine.FX
    periods = set(CostIndexObservation.objects.filter(source_id=holder).values_list("period", flat=True))
    if periods:
        ends = [cost_index.period_end(period) for period in periods]
        known = [end for end in ends if end <= as_of]
        return (max(known) if known else None), engine.COST_INDEX
    return None, None


def _version(row: FinancialSource | None) -> dict | None:
    if row is None:
        return None
    return {
        "version": row.version,
        "uuid": str(row.uuid),
        "retrieved_at": row.retrieved_at.isoformat(),
        "snapshot_hash": row.snapshot_hash,
        "trust_tier": row.trust_tier,
        "license_class": row.license_class,
    }


def source_state(key: str, *, deployment, as_of: date) -> dict:
    """The freshness of feed source ``key`` for a run of ``deployment`` on ``as_of``:
    the latest version, the version a run uses and why a newer one is not used, the
    newest observation known on that date, its age, the SLA and the state. A key the
    registry does not hold is ``missing``. Reads only; deterministic for the stored
    rows and the date."""
    feed = known_source(key)
    state = {
        "source_key": key,
        "in_registry": feed is not None,
        "provider": feed.provider if feed else None,
        "dataset": feed.dataset if feed else None,
        "kind": feed.kind if feed else None,
        "cadence": feed.cadence if feed else None,
        "sla_days": feed.sla_days if feed else None,
        "as_of": as_of.isoformat(),
        "latest_version": None,
        "used_version": None,
        "gate": None,
        "data_through": None,
        "age_days": None,
        "state": engine.MISSING,
    }
    if feed is None:
        state["reason"] = (
            "source_reference_malformed" if key == engine.MALFORMED_REFERENCE else "source_missing"
        )
        return state
    if key not in engine.REGISTRY:
        # Step 11's sources say what they may do and how their freshness acts.
        state.update(use=feed.use, freshness=feed.freshness, age_basis=feed.age_basis)
    latest = _platform_versions(key).order_by("-version").first()
    used = used_version(key, deployment, as_of)
    state["latest_version"] = _version(latest)
    state["used_version"] = _version(used)
    if latest is not None and (used is None or used.pk != latest.pk):
        # Why the newest version is not the one used: the gate's refusal of it, or
        # (None) that it does not cover the as-of date.
        state["gate"] = latest.production_use_refusal(deployment)
    if used is None:
        return state
    newest, _kind = data_through(used, as_of)
    if newest is None:
        return state
    age = (as_of - newest).days
    state.update(data_through=newest.isoformat(), age_days=age, state=engine.freshness_state(age, feed.sla_days))
    if feed.freshness == catalogs.INFORMATIONAL:
        # Shown, never acted on (spec, section 31.6): no downgrade, no stale claim, no
        # refused receipt for its age. A source with no version a run may use is
        # still missing.
        state.update(age_state=state["state"], state=INFORMATIONAL)
    return state


#: The state of a step-11 source whose freshness is informational and that has a
#: version a run may use: its age is shown (``age_state``), and nothing acts on it.
INFORMATIONAL = "informational"


def states_for(keys, *, deployment, as_of: date | None) -> dict[str, dict]:
    """:func:`source_state` of each of ``keys``; with no as-of date to read them at,
    each is ``missing`` and says it was not evaluated."""
    states = {}
    for key in sorted(set(keys)):
        feed = known_source(key)
        if feed is not None and feed.use == catalogs.CONTEXT:
            # A figure never rests on a context source (spec, section 31.5): one that
            # cites it anyway -- written past the model's check -- fails closed.
            states[key] = {"source_key": key, "state": engine.MISSING, "as_of": as_of.isoformat() if as_of else None,
                           "reason": "context_only_source"}
        elif as_of is None:
            states[key] = {"source_key": key, "state": engine.MISSING, "as_of": None,
                           "not_evaluated": "the run has no as-of date to read its sources at"}
        else:
            states[key] = source_state(key, deployment=deployment, as_of=as_of)
    return states


# --------------------------------------------------------- production receipts


def receipt_refusal(keys, deployment, as_of: date | None) -> tuple[str, str] | None:
    """Why a receipt for a run of ``deployment`` dated ``as_of`` resting on the feed
    sources ``keys`` may not be issued now, as ``(code, detail)``, or ``None``. A
    near-miss citation is ``source_reference_malformed`` and a key the registry does
    not hold ``source_missing``. For each source, the version the run uses now
    (:func:`used_version`: the newest usable version covering ``as_of``) must exist
    (the gate's refusal of the latest version, or ``source_missing``); and in a
    PRODUCTION run, one holding FX or cost-index observations must be trusted as
    ``authoritative`` (``source_not_authoritative``; the owner's decision of 13 Oct
    2026). A run that is not a production one needs no more than the gate."""
    production = runs_in_production(deployment)
    for key in sorted(set(keys)):
        if key == engine.MALFORMED_REFERENCE:
            return "source_reference_malformed", "a figure's evidence cites a feed source in a form that is not one"
        feed = known_source(key)
        if feed is None:
            return "source_missing", f"{key} is not in the feed registry"
        if feed.use == catalogs.CONTEXT:
            return "context_only_source", f"a figure rests on {key}, which is context only"
        if as_of is None:
            return "source_missing", f"{key}: the run has no as-of date to read it at"
        used = used_version(key, deployment, as_of)
        if used is None:
            latest = _platform_versions(key).order_by("-version").first()
            if latest is None:
                return "source_missing", f"{key} has no version"
            code = latest.production_use_refusal(deployment) or "source_missing"
            return code, (
                f"source {key} v{latest.version}, trust tier {latest.trust_tier}: no version a run may use covers "
                f"{as_of.isoformat()}"
            )
        if production:
            _newest, kind = data_through(used, date.max)
            if kind in (engine.FX, engine.COST_INDEX):
                refusal = governance.production_authority_refusal(used.trust_tier)
                if refusal is not None:
                    return refusal, f"source {key} v{used.version}, trust tier {used.trust_tier}"
    return None


# --------------------------------------------------------------- data health


def _last_failure(key: str) -> dict | None:
    row = (
        FinancialSourceFetch.objects.filter(source_key=key, outcome=FETCH_REFUSED)
        .order_by("-requested_at", "-id")
        .first()
    )
    return None if row is None else {"code": row.code, "at": row.requested_at.isoformat()}


def _current_parents(deployment) -> tuple[list[tuple[int, str]], list[tuple[int, str]]]:
    """The deployment's current parameter-set versions and its scenario versions no
    other supersedes, each with how a reader names it."""
    sets = []
    latest = (
        CustomerParameterSet.objects.filter(deployment=deployment)
        .values("set_key")
        .annotate(newest=Max("version"))
        .order_by("set_key")
    )
    for entry in latest:
        row = CustomerParameterSet.objects.filter(
            deployment=deployment, set_key=entry["set_key"], version=entry["newest"]
        ).values_list("pk", flat=True).first()
        sets.append((row, f"parameter-set:{entry['set_key']}:v{entry['newest']}"))
    superseded = set(
        FinancialScenario.objects.filter(deployment=deployment, supersedes__isnull=False).values_list(
            "supersedes_id", flat=True
        )
    )
    scenarios = [
        (pk, f"scenario:{scenario_uuid}")
        for pk, scenario_uuid in FinancialScenario.objects.filter(deployment=deployment)
        .exclude(pk__in=superseded)
        .order_by("id")
        .values_list("pk", "uuid")
    ]
    return sets, scenarios


def _unknowns(key: str, deployment, because: str, parents) -> tuple[list[dict], bool]:
    sets, scenarios = parents
    names = dict(sets)
    scenario_names = dict(scenarios)
    rows = (
        FinancialParameter.objects.filter(
            Q(parameter_set_id__in=list(names)) | Q(scenario_id__in=list(scenario_names)),
            evidence_ref__startswith=engine.EVIDENCE_PREFIX + key,
        )
        .order_by("id")
        .values_list("name", "evidence_ref", "parameter_set_id", "scenario_id")
    )
    found = []
    for name, evidence_ref, set_id, scenario_id in rows:
        if engine.feed_reference(evidence_ref) != key:
            continue
        where = names[set_id] if set_id is not None else scenario_names[scenario_id]
        found.append({"parameter": name, "in": where, "because": because})
    found.sort(key=lambda item: (item["in"], item["parameter"]))
    return found[:UNKNOWNS_LIMIT], len(found) > UNKNOWNS_LIMIT


def _stray_citations(deployment, parents) -> tuple[list[dict], bool]:
    """The deployment's current parameters whose evidence cites a feed source the
    registry does not hold (``source_missing``), or cites one in a form that is not a
    citation (``source_reference_malformed``; review round 1, NIT-3): each fails
    closed, and a receipt resting on it is refused with that code."""
    sets, scenarios = parents
    names, scenario_names = dict(sets), dict(scenarios)
    rows = (
        FinancialParameter.objects.filter(
            Q(parameter_set_id__in=list(names)) | Q(scenario_id__in=list(scenario_names)),
            evidence_ref__icontains="source",
        )
        .order_by("id")
        .values_list("name", "evidence_ref", "parameter_set_id", "scenario_id")
    )
    found = []
    for name, evidence_ref, set_id, scenario_id in rows:
        key = engine.feed_reference(evidence_ref)
        if key is None or known_source(key) is not None:
            continue
        malformed = key == engine.MALFORMED_REFERENCE
        found.append({
            "parameter": name,
            "in": names[set_id] if set_id is not None else scenario_names[scenario_id],
            "cites": None if malformed else key,
            "because": "source_reference_malformed" if malformed else "source_missing",
        })
    found.sort(key=lambda item: (item["in"], item["parameter"]))
    return found[:UNKNOWNS_LIMIT], len(found) > UNKNOWNS_LIMIT


#: What a source in each state does to the figures it feeds.
EFFECTS = {
    engine.FRESH: "none",
    engine.STALE: "each figure it feeds lowers its grade one step (stale_source)",
    engine.BLOCKED: (
        "each figure it feeds lowers its grade one step, the Validity Card says stale, and a receipt is refused "
        "(source_stale)"
    ),
    engine.MISSING: (
        "each figure it feeds lowers its grade one step, the Validity Card says stale, and a receipt is refused "
        "(source_missing)"
    ),
}


#: What a step-11 context source does, whatever its state (spec, section 31.6).
CONTEXT_EFFECT = (
    "context only: it shows its age, and never lowers a grade, makes a claim stale or stops a receipt; a figure "
    "never rests on it"
)
#: What a step-11 source whose freshness is informational does, while it has a version
#: a run may use.
INFORMATIONAL_EFFECT = (
    "informational: its age is shown (age_state, against its SLA), and never lowers a grade, makes a claim stale or "
    "stops a receipt"
)


def _catalog_effect(feed: engine.FeedSource, state: str) -> str:
    if feed.use == catalogs.CONTEXT:
        return CONTEXT_EFFECT
    if state == INFORMATIONAL:
        return INFORMATIONAL_EFFECT
    return EFFECTS[state]


def catalog_keys() -> list[str]:
    """Every step-11 source data health lists: the catalog registry's, and each EDGAR
    company source a version or a fetch has been recorded for."""
    keys = set(catalogs.CATALOG_REGISTRY)
    for model in (FinancialSource, FinancialSourceFetch):
        rows = model.objects.filter(source_key__startswith="sec-edgar-")
        if model is FinancialSource:
            rows = rows.filter(deployment__isnull=True)
        keys |= {key for key in rows.values_list("source_key", flat=True).distinct() if catalogs.known(key)}
    return sorted(keys)


def _catalog_health(deployment, as_of: date, parents) -> list[dict]:
    found = []
    for key in catalog_keys():
        feed = known_source(key)
        state = source_state(key, deployment=deployment, as_of=as_of)
        because = None
        if feed.use == catalogs.PREFILL:
            because = {engine.BLOCKED: "source_stale", engine.MISSING: "source_missing"}.get(state["state"])
        unknowns, truncated = ([], False) if because is None else _unknowns(key, deployment, because, parents)
        found.append(
            {
                **state,
                "effect": _catalog_effect(feed, state["state"]),
                "licence_terms": feed.licence_terms,
                "last_fetch_failure": _last_failure(key),
                "unknowns": unknowns,
                "unknowns_truncated": truncated,
            }
        )
    return found


def data_health(deployment, *, now: datetime | None = None) -> dict:
    """Every feed source a run of ``deployment`` can read, on today's date (UTC): its
    latest version, the version a run uses, its age, SLA and state, the last fetch
    that failed (its code only), and the Unknowns it causes -- the deployment's
    current parameters that name it, where it is blocked or missing. Reads only."""
    now = now or timezone.now()
    as_of = now.astimezone(dt_timezone.utc).date()
    parents = _current_parents(deployment)
    sources = []
    for key in sorted(engine.REGISTRY):
        state = source_state(key, deployment=deployment, as_of=as_of)
        because = {engine.BLOCKED: "source_stale", engine.MISSING: "source_missing"}.get(state["state"])
        unknowns, truncated = ([], False) if because is None else _unknowns(key, deployment, because, parents)
        sources.append(
            {
                **state,
                "effect": EFFECTS[state["state"]],
                "last_fetch_failure": _last_failure(key),
                "unknowns": unknowns,
                "unknowns_truncated": truncated,
            }
        )
    stray, stray_truncated = _stray_citations(deployment, parents)
    return {
        "deployment": str(deployment.uuid),
        "as_of": as_of.isoformat(),
        "production_run": runs_in_production(deployment),
        # Figures citing no registry source, or citing one in a form that is not a
        # citation: each fails closed (review round 1, NIT-3).
        "unregistered_citations": stray,
        "unregistered_citations_truncated": stray_truncated,
        "freshness_sla_days": {
            f"{provider} {cadence}": days for (provider, cadence), days in sorted(engine.FRESHNESS_SLA_DAYS.items())
        },
        "sources": sources,
        # MVP step 11 (spec, section 31.7): the cloud price catalogs, SEC EDGAR and
        # the enforcement listings, each with what it may do and how its age acts.
        "catalog_freshness_sla_days": {
            f"{provider} {cadence}": days for (provider, cadence), days in sorted(catalogs.CATALOG_SLA_DAYS.items())
        },
        "catalog_sources": _catalog_health(deployment, as_of, parents),
    }


__all__ = [
    "CONTEXT_EFFECT",
    "EFFECTS",
    "INFORMATIONAL",
    "INFORMATIONAL_EFFECT",
    "TIMEOUT",
    "FetchOutcome",
    "OutboundTransport",
    "TransportFailed",
    "base_url",
    "catalog_keys",
    "data_health",
    "data_through",
    "fetch",
    "known_source",
    "live_feeds_enabled",
    "provider_key",
    "receipt_refusal",
    "source_state",
    "states_for",
    "used_version",
]
