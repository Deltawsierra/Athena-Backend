"""Normalizing the figures a run reads, when its scenario version is built (MVP steps 3
and 12 in runs; ``docs/economics/spec-v1.md``, section 36).

A build that states a normalization policy (:func:`parse_policy`: the base currency,
the FX providers and rules, the base currency's cost index and its lag) normalizes each
money figure of the parameter-set version that it READS -- a variable a template of its
events reads, or a term of the version's insurance policy -- and that is stated in
another currency than the build's or at another date than its as-of date (the run's
valuation date). :func:`normalize` does it through the very service the normalization
route uses (:func:`.normalization_service.normalize_for`: FX at the figure's own
``effective_date``, the cost index to the valuation date, in section 12.4's order,
over the source versions a run of the deployment may use on that date, section 12.8):
each of the figure's low, base and high, so a stale, blocked or missing source is
refused or downgraded exactly as the route does. A normalization the books cannot make
refuses the build with its reason (``rate_missing``, ``index_missing``,
``index_primary_unset``): never a number the policy did not allow.

The build reads the normalized figure, a scenario parameter named
:data:`~.engine.figure_normalization.PREFIX` and the variable's name, in its place; the
native figure is never overwritten. Its record (a
:class:`~assurance.economics.models.FigureNormalization` row) is written append-only
with the build, and every run of the version holds it in its canonical inputs
(:func:`normalization_records`), so its input digest covers it and a replay is exact. A build that
normalizes nothing -- every figure it reads in its currency at its as-of date, or no
policy stated -- writes no record, and its runs' inputs are what they were.

:func:`policy_of` is the insurance policy a run applies: the version's, each term the
build normalized read as its normalized figure. :func:`source_dependencies` is the hook
E6 (#168) reads: every source version a run's normalizations read, each a dependency of
the run (a newer usable version stales it).

Reads only here; the builder writes. Nothing here is on a stop path, holds a lock or a
transaction, or reads the network: the books are the stored snapshot versions.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date
from decimal import Decimal

from .engine import figure_normalization as fn
from .engine import loss as engine_loss
from .engine.money import Money, MoneyRefused
from .engine.parameters import MONEY_UNITS, POINTS, Parameter, ParameterRefused
from .models import FigureNormalization, FinancialParameter

_POLICY_REQUIRED = frozenset({"base_currency", "providers", "index"})
_POLICY_OPTIONAL = frozenset({
    "index_max_lag_months", "rate_types", "weekend_holiday_rule", "missing_rate", "max_interpolation_gap_days",
    "freshness_days",
})
_INDEX_FIELDS = frozenset({"series_id", "geography", "category", "base"})
#: The most FX providers a policy names, and the largest whole-number limit it states.
MAX_PROVIDERS = 10
MAX_LIMIT = 9999
_TEXT_MAX = 200


def _object(value, path: str, required: frozenset, optional: frozenset = frozenset()) -> dict:
    if not isinstance(value, dict):
        raise ParameterRefused("field_malformed", f"{path} is not an object")
    unknown = sorted(str(k) for k in value if k not in required | optional)
    if unknown:
        raise ParameterRefused("field_unrecognised", f"{path}: {unknown}")
    missing = sorted(required - set(value))
    if missing:
        raise ParameterRefused("field_missing", f"{path}: {missing}")
    return value


def _text(value, path: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip() or len(value) > _TEXT_MAX:
        raise ParameterRefused("field_malformed", f"{path} is text of 1 to {_TEXT_MAX} characters, not padded")
    return value


def _names(value, path: str, most: int) -> tuple[str, ...]:
    if not isinstance(value, list) or not 1 <= len(value) <= most:
        raise ParameterRefused("field_malformed", f"{path} is a list of 1 to {most} names")
    names = tuple(_text(item, f"{path}[]") for item in value)
    if len(set(names)) != len(names):
        raise ParameterRefused("field_malformed", f"{path} names each once")
    return names


def _whole(value, path: str) -> int:
    if type(value) is not int or not 0 <= value <= MAX_LIMIT:
        raise ParameterRefused("field_malformed", f"{path} is a whole number from 0 to {MAX_LIMIT}")
    return value


def parse_policy(raw, reporting_currency: str):
    """The normalization policy a build request states (``normalization``), read
    exactly, for a build in ``reporting_currency``: a
    :class:`~.engine.normalization.NormalizationPolicy`, or refused with the field's
    path (``field_malformed``, ``field_unrecognised``, ``field_missing``) or the
    engine's own code (``policy_invalid``, ``currency_unknown``, ...)."""
    from .engine.cost_index import IndexSelector
    from .engine.fx import FXPolicy
    from .engine.normalization import NormalizationPolicy

    body = _object(raw, "normalization", _POLICY_REQUIRED, _POLICY_OPTIONAL)
    index = _object(body["index"], "normalization.index", _INDEX_FIELDS)
    rules = {}
    if "rate_types" in body:
        rules["rate_types"] = _names(body["rate_types"], "normalization.rate_types", 4)
    for name in ("weekend_holiday_rule", "missing_rate"):
        if name in body:
            rules[name] = _text(body[name], f"normalization.{name}")
    for name in ("max_interpolation_gap_days", "freshness_days"):
        if name in body:
            rules[name] = _whole(body[name], f"normalization.{name}")
    lag = {}
    if "index_max_lag_months" in body:
        lag["index_max_lag_months"] = _whole(body["index_max_lag_months"], "normalization.index_max_lag_months")
    base = body["base_currency"]
    if not isinstance(base, str):
        raise ParameterRefused("field_malformed", "normalization.base_currency is a currency code")
    return NormalizationPolicy(
        base,
        reporting_currency,
        FXPolicy(_names(body["providers"], "normalization.providers", MAX_PROVIDERS), **rules),
        IndexSelector(*(_text(index[name], f"normalization.index.{name}")
                        for name in ("series_id", "geography", "category", "base")), base),
        **lag,
    )


@dataclass(frozen=True)
class Normalized:
    """One figure a build normalizes, before its rows are made: the native row, the
    normalized figure (its parameter id is the scenario row's to be), each point's
    normalization record, and the source versions those records read."""

    native: FinancialParameter
    parameter: Parameter
    points: Mapping[str, dict]
    sources: tuple[dict, ...]

    def record(self, parameter_set: Mapping, policy: Mapping) -> dict:
        return fn.record_of(
            native=self.native.as_engine(),
            parameter_set=parameter_set,
            normalized=self.parameter,
            points=self.points,
            policy=policy,
            sources=list(self.sources),
        )


def _named_sources(records: Iterable[dict], usable) -> tuple[dict, ...]:
    """The usable source versions ``records`` name: each observation's (by key and
    version) and each conflict's sources (by key), with their provenance."""
    versions, keys = set(), set()
    for record in records:
        for step in record.get("chain") or []:
            for observation in step.get("observations") or []:
                versions.add((observation.get("source_key"), observation.get("source_version")))
        for conflict in record.get("conflicts") or []:
            keys.update(conflict.get(side) for side in ("primary", "secondary"))
    named = []
    for source in usable:
        if (source.source_key, source.version) in versions or source.source_key in keys:
            named.append({
                "source_key": source.source_key,
                "version": source.version,
                "tenant": "platform" if source.deployment_id is None else "deployment",
                "provider": source.provider,
                "license_class": source.license_class,
                "trust_tier": source.trust_tier,
                "snapshot_hash": source.snapshot_hash,
            })
    return tuple(sorted(named, key=lambda s: (s["source_key"], s["tenant"], s["version"])))


def normalize(deployment, rows: Iterable[FinancialParameter], *, currency: str, valuation_date: date, policy,
              new_id) -> dict[str, Normalized]:
    """Each of ``rows`` (parameter-set rows the build reads) that is stated in another
    currency than ``currency`` or at another date than ``valuation_date``, normalized
    under ``policy`` for a run of ``deployment`` (see the module's rules), by its
    variable's name. ``new_id`` gives each normalized figure the id its scenario row
    will have. A figure that states a distribution is refused
    (``distribution_not_normalizable``); a normalization the books cannot make, with
    its reason."""
    from . import normalization_service
    from .engine import templates as tpl
    from .engine.normalization import UNAVAILABLE

    found: dict[str, Normalized] = {}
    usable = None
    for row in sorted(rows, key=lambda r: r.name):
        native = row.as_engine()
        if not fn.needs_normalizing(native, currency=currency, valuation_date=valuation_date):
            continue
        if row.distribution is not None:
            raise tpl.BuildRefused(
                "distribution_not_normalizable", f"{row.name} states a distribution in {native.currency}"
            )
        records: dict[Decimal, dict] = {}
        points = {}
        for point in POINTS:
            amount = native.at(point)
            if amount.amount not in records:
                result = normalization_service.normalize_for(
                    deployment, amount, event_date=native.effective_date, valuation_date=valuation_date, policy=policy
                )
                if result.status == UNAVAILABLE:
                    gone = result.unavailable
                    raise tpl.BuildRefused(
                        gone.reason, f"{row.name} {point.value}, {gone.step}: {gone.detail}"
                    )
                records[amount.amount] = result.as_dict()
            points[point.value] = records[amount.amount]
        if usable is None:
            usable = normalization_service.usable_versions(deployment, valuation_date)
        values = {
            point: Money(fn.parameter_value(Decimal(points[point.value]["value"]["amount"])), currency)
            for point in POINTS
        }
        parameter = Parameter(
            name=fn.figure_name(row.name),
            unit=native.unit,
            source_type=native.source_type,
            low=values[POINTS[0]],
            base=values[POINTS[1]],
            high=values[POINTS[2]],
            evidence_ref=native.evidence_ref,
            effective_date=native.effective_date,
            fresh_until=native.fresh_until,
            parameter_id=new_id(),
        )
        found[row.name] = Normalized(row, parameter, points, _named_sources(points.values(), usable))
    return found


def read_rows(rows: Iterable[FinancialParameter], names: Iterable[str]) -> list[FinancialParameter]:
    """The money rows of ``rows`` named in ``names``."""
    wanted = set(names)
    return [row for row in rows if row.name in wanted and row.unit in {u.value for u in MONEY_UNITS}]


def check_currency(rows: Iterable[FinancialParameter], currency: str) -> None:
    """Without a normalization policy, every money figure a build reads is in its
    currency already (``currency_mismatch``, as before section 36)."""
    for row in sorted(rows, key=lambda r: r.name):
        if row.currency and row.currency != currency:
            raise MoneyRefused(
                "currency_mismatch",
                f"{row.name} is in {row.currency}; the build reports in {currency} and states no normalization "
                "policy to convert it",
            )


# ------------------------------------------------------------------ reading them


def stored(scenario) -> list[FigureNormalization]:
    """The scenario version's normalizations, in figure order."""
    rows = list(FigureNormalization.objects.filter(scenario=scenario).select_related("native", "normalized"))
    return sorted(rows, key=lambda row: row.normalized.name)


def normalization_records(scenario) -> tuple[dict, ...]:
    """Each figure's normalization record, as stored, in figure order: what a run of
    the version holds in its inputs (none for a version that normalized nothing)."""
    return tuple(row.record for row in stored(scenario))


def substituted(policy, normalized: Mapping[str, Parameter]):
    """``policy`` with each term whose variable ``normalized`` names read as its
    normalized figure; ``policy`` itself where none is."""
    if policy is None:
        return None
    terms = [policy.deductible, policy.limit, *policy.sublimits.values()]
    if not any(term.name in normalized for term in terms):
        return policy

    def term(parameter: Parameter) -> Parameter:
        return normalized.get(parameter.name, parameter)

    return engine_loss.InsurancePolicy(
        deductible=term(policy.deductible),
        limit=term(policy.limit),
        sublimits={family: term(value) for family, value in policy.sublimits.items()},
        exclusions=policy.exclusions,
        waiting_period_hours=policy.waiting_period_hours,
    )


def policy_of(build):
    """The insurance policy a run of ``build``'s scenario version applies: its
    parameter-set version's, each term the build normalized read as its normalized
    figure; ``None`` where there is no build or the version states no policy."""
    from .models import CustomerParameterSet

    if build is None:
        return None
    policy = CustomerParameterSet.objects.get(pk=build.parameter_set_id).content().insurance_policy()
    if policy is None:
        return None
    rows = stored(build.scenario_id)
    return substituted(policy, {row.native.name: row.normalized.as_engine() for row in rows})


def source_dependencies(inputs) -> list[dict]:
    """The hook E6 (#168) reads: every source version a run's normalizations read,
    from its stored inputs, each once -- a newer usable version of any of them stales
    the run. Empty for a run that normalized nothing."""
    found = {}
    for record in (inputs or {}).get("normalizations") or []:
        for source in record.get("sources") or []:
            key = (source["source_key"], source["tenant"], source["version"])
            found[key] = {k: source[k] for k in ("source_key", "tenant", "version", "snapshot_hash")}
    return [found[key] for key in sorted(found)]


__all__ = [
    "MAX_LIMIT",
    "MAX_PROVIDERS",
    "Normalized",
    "check_currency",
    "normalize",
    "parse_policy",
    "policy_of",
    "read_rows",
    "normalization_records",
    "source_dependencies",
    "stored",
    "substituted",
]
