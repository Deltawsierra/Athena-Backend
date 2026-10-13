"""Step 11's two readers of catalog records, both CONTEXT ONLY (MVP step 11;
``docs/economics/spec-v1.md``, section 31.5):

- :func:`suggest`: a cloud cost, or a public company's revenue or operating margin,
  as a SUGGESTION for one parameter-set variable (``engine/context.py``,
  :class:`~assurance.economics.engine.context.Suggestion`). It writes nothing: a
  person accepts it by recording its entry in a parameter-set version, signed in,
  through the parameter-set route, where the model's citation rule holds it to what
  a prefill may be (``prefill_not_accepted``).
- :func:`precedents`: the enforcement records a scenario lists as precedent, each
  with its citation, the amounts its listing stated (as text) and
  :data:`~assurance.economics.engine.context.PRECEDENT_STATEMENT`. Never a figure,
  never summed into a loss.

Each reads the NEWEST platform-wide version of a source whose licence has been
reviewed (``governance.production_use_refusal`` on its licence class and synthetic
flag); a source with none is named, with the gate's code, and read no further.
Both read only: no write, no transaction, no lock, and no request to any provider.
Neither is on a stop path; the routes that serve them import this module inside the
view (``health_api.py``).
"""

from __future__ import annotations

from datetime import date, datetime
from datetime import timezone as dt_timezone

from django.utils import timezone

from . import snapshots
from .engine import catalogs, governance
from .engine import context as rules
from .engine.feeds import freshness_state
from .models import FinancialSource, LossComponent

#: The most precedents a scenario lists (``truncated`` says when there were more).
PRECEDENTS_LIMIT = 100
#: The query fields the suggestion route reads; any other is refused.
SUGGESTION_FIELDS = frozenset({"source", "target", "observation", "quantity"})


class Refused(ValueError):
    """A suggestion or a listing refused: its code (``engine/context.py``'s
    ``REFUSALS``, or a governance code) and a detail."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        super().__init__(f"{code}: {detail}")

    @property
    def meaning(self) -> str:
        return rules.REFUSALS.get(self.code) or governance.REFUSALS.get(self.code) or self.code


def reviewed_version(key: str) -> tuple[FinancialSource | None, str | None]:
    """The newest platform-wide version of ``key`` whose licence has been reviewed and
    that is not synthetic, or ``(None, why)``: the gate's code of the latest version,
    or ``source_missing``."""
    versions = list(FinancialSource.objects.filter(deployment__isnull=True, source_key=key).order_by("-version"))
    for version in versions:
        if governance.production_use_refusal(version.license_class, synthetic=version.synthetic) is None:
            return version, None
    if not versions:
        return None, "source_missing"
    return None, governance.production_use_refusal(versions[0].license_class, synthetic=versions[0].synthetic)


def _utc_date(instant: datetime) -> date:
    return instant.astimezone(dt_timezone.utc).date()


def _version(version: FinancialSource, today: date, sla: int) -> dict:
    age = catalogs.ages_from_retrieval(version.retrieved_at, today)
    return {
        "key": version.source_key,
        "version": version.version,
        "snapshot_hash": version.snapshot_hash,
        "license_class": version.license_class,
        "trust_tier": version.trust_tier,
        "retrieved_at": version.retrieved_at.isoformat(),
        "age_days": age,
        "sla_days": sla,
        "age_state": freshness_state(age, sla),
    }


def _one(query: dict, name: str, *, required: bool = True) -> str | None:
    values = query.get(name, [])
    if len(values) > 1 or (required and not values):
        raise Refused("suggestion_malformed", f"{name} is given once")
    return values[0] if values else None


def suggest(deployment, query: dict[str, list[str]], *, now: datetime | None = None) -> dict:
    """The suggestion ``query`` asks for (``source``, ``target``; for a cloud price,
    ``observation`` once to ten times and ``quantity``). Raises :class:`Refused`.
    Writes nothing."""
    unknown = sorted(set(query) - SUGGESTION_FIELDS)
    if unknown:
        raise Refused("suggestion_malformed", f"the route reads {sorted(SUGGESTION_FIELDS)}, not {unknown}")
    key = _one(query, "source")
    target = _one(query, "target")
    feed = catalogs.known(key)
    if feed is None or feed.use != catalogs.PREFILL:
        raise Refused("suggestion_source_unrecognised", f"{key!r} prefills nothing")
    version, why = reviewed_version(feed.key)
    if version is None:
        raise Refused(why, f"{feed.key}: no version whose licence has been reviewed")
    records = snapshots.records_of(version)
    today = _utc_date(now or timezone.now())
    try:
        if feed.kind == catalogs.CLOUD_PRICE:
            wanted = query.get("observation", [])
            by_id = {r.observation_id: r for r in records if r.TYPE == catalogs.PriceObservation.TYPE}
            missing = sorted(set(wanted) - set(by_id))
            if missing:
                raise Refused("suggestion_observation_missing", f"{missing[:5]} are not in v{version.version}")
            suggestion = rules.suggest_cloud_cost(
                target, [by_id[name] for name in wanted], _one(query, "quantity"),
                source_key=feed.key, version=version.version, snapshot_hash=version.snapshot_hash,
                retrieved=_utc_date(version.retrieved_at),
            )
            company = None
        else:
            if query.get("observation") or query.get("quantity"):
                raise Refused("suggestion_malformed", "an EDGAR suggestion reads the company's annual figures")
            cik = catalogs.edgar_cik(feed.key)
            watch, _why = reviewed_version(catalogs.edgar_key("submissions", cik))
            entity = None
            if watch is not None:
                entity = next((r for r in snapshots.records_of(watch) if r.TYPE == catalogs.CompanyEntity.TYPE), None)
            suggestion = rules.suggest_from_facts(
                target, records, entity, source_key=feed.key, version=version.version,
                snapshot_hash=version.snapshot_hash,
            )
            company = {"cik": cik, "name": entity.name, "tickers": list(entity.tickers),
                       "exchanges": list(entity.exchanges), "filing_watch_version": watch.version}
    except rules.SuggestionRefused as refused:
        raise Refused(refused.code, refused.detail) from None
    return {
        "deployment": str(deployment.uuid),
        **suggestion.as_dict(),
        "version": _version(version, today, feed.sla_days),
        "company": company,
    }


def scenario_families(scenario) -> list[str]:
    """The loss families of the scenario version's components."""
    return sorted(set(LossComponent.objects.filter(loss_event__scenario=scenario).values_list("family", flat=True)))


def precedents(deployment, scenario, *, now: datetime | None = None) -> dict:
    """The enforcement records the scenario version lists as precedent: every
    record of each enforcement source that gives precedent for one of the
    scenario's loss families, newest first, each with its citation. Reads only."""
    today = _utc_date(now or timezone.now())
    families = scenario_families(scenario)
    listed, sources, withheld = [], [], []
    for key, feed in sorted(catalogs.CATALOG_REGISTRY.items()):
        if feed.kind != catalogs.ENFORCEMENT or not set(rules.families_of(feed)) & set(families):
            continue
        version, why = reviewed_version(key)
        if version is None:
            withheld.append({"key": key, "because": why})
            continue
        sources.append(_version(version, today, feed.sla_days))
        listed.extend(
            rules.precedent_entry(record, source_key=key, version=version.version)
            for record in snapshots.records_of(version)
            if record.TYPE == catalogs.EnforcementRecord.TYPE
        )
    listed.sort(key=lambda entry: (entry["date"], entry["source"]["key"], entry["citation"]["url"]), reverse=True)
    return {
        "deployment": str(deployment.uuid),
        "scenario": str(scenario.uuid),
        "statement": rules.PRECEDENT_STATEMENT,
        "families": families,
        "precedents": listed[:PRECEDENTS_LIMIT],
        "truncated": len(listed) > PRECEDENTS_LIMIT,
        "sources": sources,
        "withheld": withheld,
    }


__all__ = ["PRECEDENTS_LIMIT", "Refused", "precedents", "reviewed_version", "scenario_families", "suggest"]
