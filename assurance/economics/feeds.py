"""Fetching a live feed into the snapshot store, the freshness of a feed source, and
a deployment's data health (MVP step 10; ``docs/economics/spec-v1.md``, section 28).

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
"""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
from datetime import date, datetime
from datetime import timezone as dt_timezone

import requests
from django.conf import settings
from django.db import IntegrityError, transaction
from django.db.models import Max, Q
from django.utils import timezone

from safety import outbound

from . import snapshots
from .engine import cost_index, governance, money
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
    runs_in_production,
)

#: The connect and read timeouts of one fetch, in seconds.
TIMEOUT = (5.0, 30.0)
#: The most parameters the data-health route lists as one source's Unknowns.
UNKNOWNS_LIMIT = 200
_HEADERS = {"Accept": "text/csv, application/json", "User-Agent": "athena-backend economic-exposure feed"}


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
    else:
        value = ""
    return value.strip() if isinstance(value, str) else ""


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
            for chunk in response.iter_content(64 * 1024):
                content += chunk
                if len(content) > engine.MAX_RESPONSE_BYTES:
                    raise TransportFailed("response_too_large")
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
    try:
        feed = engine.source(source_key)
    except engine.FeedRefused as refused:
        return _refused_before_sending(str(source_key), refused.code)
    key = provider_key(feed)
    if feed.key_setting and not key:
        return _refused_before_sending(feed.key, "source_key_missing")
    if not live_feeds_enabled():
        return _refused_before_sending(feed.key, "live_feeds_disabled")
    now = now or timezone.now()
    today = now.astimezone(dt_timezone.utc).date()
    explicit = as_of is not None
    as_of = as_of if explicit else today
    try:
        request = engine.request_for(feed, as_of=as_of, explicit=explicit, today=today, base_url=base_url(feed))
    except engine.FeedRefused as refused:
        return _refused_before_sending(feed.key, refused.code)
    try:
        raw = (transport or OutboundTransport()).send(request, key)
    except TransportFailed as failed:
        return _record_refusal(feed, as_of, failed.code)
    try:
        snapshot = engine.parse(feed, raw, as_of=as_of, retrieved_at=now, url=request.recorded_url)
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


# ------------------------------------------------------------------ freshness


def _platform_versions(key: str):
    return FinancialSource.objects.filter(deployment__isnull=True, source_key=key)


def used_version(key: str, deployment) -> FinancialSource | None:
    """The latest platform-wide version of ``key`` a production run for
    ``deployment`` may use (the production gate's own query), or ``None``."""
    return FinancialSource.objects.usable_for_production(deployment).filter(
        deployment__isnull=True, source_key=key
    ).order_by("-version").first()


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
    feed = engine.REGISTRY.get(key)
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
        return state
    latest = _platform_versions(key).order_by("-version").first()
    used = used_version(key, deployment)
    state["latest_version"] = _version(latest)
    state["used_version"] = _version(used)
    if latest is not None and (used is None or used.pk != latest.pk):
        state["gate"] = latest.production_use_refusal(deployment)
    if used is None:
        return state
    newest, _kind = data_through(used, as_of)
    if newest is None:
        return state
    age = (as_of - newest).days
    state.update(data_through=newest.isoformat(), age_days=age, state=engine.freshness_state(age, feed.sla_days))
    return state


def states_for(keys, *, deployment, as_of: date | None) -> dict[str, dict]:
    """:func:`source_state` of each of ``keys``; with no as-of date to read them at,
    each is ``missing`` and says it was not evaluated."""
    states = {}
    for key in sorted(set(keys)):
        if as_of is None:
            states[key] = {"source_key": key, "state": engine.MISSING, "as_of": None,
                           "not_evaluated": "the run has no as-of date to read its sources at"}
        else:
            states[key] = source_state(key, deployment=deployment, as_of=as_of)
    return states


# --------------------------------------------------------- production receipts


def receipt_refusal(keys, deployment) -> tuple[str, str] | None:
    """Why a receipt for a run of ``deployment`` resting on the feed sources ``keys``
    may not be issued now, as ``(code, detail)``, or ``None``. For each source, the
    version a run uses now must exist (the gate's refusal of the latest version, or
    ``source_missing``); and in a PRODUCTION run, one holding FX or cost-index
    observations must be trusted as ``authoritative`` (``source_not_authoritative``;
    the owner's decision of 13 Oct 2026). A run that is not a production one needs no
    more than the gate."""
    production = runs_in_production(deployment)
    for key in sorted(set(keys)):
        if key not in engine.REGISTRY:
            return "source_missing", f"{key} is not in the feed registry"
        used = used_version(key, deployment)
        if used is None:
            latest = _platform_versions(key).order_by("-version").first()
            if latest is None:
                return "source_missing", f"{key} has no version"
            code = latest.production_use_refusal(deployment) or "source_missing"
            return code, f"source {key} v{latest.version}, trust tier {latest.trust_tier}: no version a run may use"
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
    return {
        "deployment": str(deployment.uuid),
        "as_of": as_of.isoformat(),
        "production_run": runs_in_production(deployment),
        "freshness_sla_days": {
            f"{provider} {cadence}": days for (provider, cadence), days in sorted(engine.FRESHNESS_SLA_DAYS.items())
        },
        "sources": sources,
    }


__all__ = [
    "EFFECTS",
    "TIMEOUT",
    "FetchOutcome",
    "OutboundTransport",
    "TransportFailed",
    "base_url",
    "data_health",
    "data_through",
    "fetch",
    "live_feeds_enabled",
    "provider_key",
    "receipt_refusal",
    "source_state",
    "states_for",
    "used_version",
]
