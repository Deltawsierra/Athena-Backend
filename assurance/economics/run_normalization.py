"""Normalizing the figures a run reads, when its scenario version is built (MVP steps 3
and 12 in runs; ``docs/economics/spec-v1.md``, section 36).

A build request may NAME a stored normalization policy (``"normalization": "<key>"``,
:func:`resolve_policy`: a :class:`~assurance.economics.models.FinancialNormalizationPolicy`,
the deployment's own version of the key before the platform's, the latest): the base
currency, the FX providers IN ORDER, the rules and the base currency's cost index. The
request never states a policy itself, so it never chooses which provider is the
primary. Under the policy :func:`normalize` normalizes each money figure the build READS:

- a parameter-set figure -- a variable a template of its events reads, or a term of the
  version's insurance policy -- stated in another currency than the build's, or at
  another date than its as-of date (the run's valuation date);
- an effect's money attribute a template reads, stated in the build's currency at
  another date than its as-of date: indexed exactly as a parameter-set figure is. An
  attribute in another currency is refused, as before (``currency_mismatch``).

Each of its low, base and high goes through the very service the normalization route
uses (:func:`.normalization_service.normalize_for`: FX at the figure's own
``effective_date``, the cost index to the valuation date, in section 12.4's order, over
the source versions a run of the deployment may use on that date, section 12.8), so a
stale, blocked or missing source is refused or downgraded exactly as the route does. A
normalization the books cannot make refuses the build with its reason (``rate_missing``,
``index_missing``, ``index_primary_unset``): never a number the policy did not allow.

The build reads the normalized figure, a scenario parameter named
:data:`~.engine.figure_normalization.PREFIX` and the figure's name, in its place; the
native figure is never overwritten. Its record (a
:class:`~assurance.economics.models.FigureNormalization` row) is written append-only
with the build, and checked again on EVERY read (:func:`stored`): a record or a figure
that no longer holds is refused (``normalization_record_malformed``), never used or
served. Every run of the version holds the records in its canonical inputs
(:func:`normalization_records`), so its input digest covers them and a replay is exact.

:func:`policy_of` is the insurance policy a run applies: the version's, each term the
build normalized read as its normalized figure. :func:`source_dependencies` lists the
source versions a run's normalizations read, and :func:`moved_sources` which of them a
run as of the same date would now read at another version: E6 (section 34) records
the first with the run and stales it on the second (``source_superseded``).

Reads only here; the builder writes. Nothing here is on a stop path, holds a lock or a
transaction, or reads the network: the books are the stored snapshot versions.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal

from .engine import figure_normalization as fn
from .engine import loss as engine_loss
from .engine.money import Money, MoneyRefused
from .engine.parameters import MONEY_UNITS, POINTS, Parameter, ParameterRefused
from .models import EconomicsRefused, FigureNormalization, FinancialNormalizationPolicy, FinancialParameter


def resolve_policy(deployment, named, reporting_currency: str):
    """The stored policy a build request names (``named``: its key, a string, and
    nothing else) for a build of ``deployment`` in ``reporting_currency``, and the
    engine's policy it gives: ``(row, policy)``. A request that states anything but a
    key is refused (``field_malformed``): the policy, the providers' order with it, is
    never the request's; a key no stored policy holds is
    ``normalization_policy_not_found``."""
    from .engine import templates as tpl

    if not isinstance(named, str) or not named:
        raise ParameterRefused(
            "field_malformed",
            "normalization names a stored normalization policy by its key: the policy and its providers' order are "
            "never a build request's to state",
        )
    row = FinancialNormalizationPolicy.named(deployment, named)
    if row is None:
        raise tpl.BuildRefused("normalization_policy_not_found", named[:100])
    return row, fn.policy_from_document(row.document, reporting_currency, f"normalization policy {named}")


@dataclass(frozen=True)
class Candidate:
    """One money figure a build reads, as stated: its parameter, where it is
    (``parent``), the distribution it states, and its row where it has one already (a
    parameter-set variable; an effect's attribute has its row made with the build)."""

    native: Parameter
    parent: Mapping
    distribution: Mapping | None = None
    row: FinancialParameter | None = None


@dataclass(frozen=True)
class Normalized:
    """One figure a build normalizes, before its rows are made: the figure as stated,
    the normalized figure (its parameter id is the scenario row's to be), each point's
    normalization record, and the source versions those records read."""

    candidate: Candidate
    parameter: Parameter
    points: Mapping[str, dict]
    sources: tuple[dict, ...] = field(default_factory=tuple)

    def record(self, native: Parameter, stored_policy: Mapping, policy: Mapping) -> dict:
        """The record, naming ``native`` (the figure's row as the engine reads it)."""
        return fn.record_of(
            native=native,
            parent=self.candidate.parent,
            normalized=self.parameter,
            points=self.points,
            policy=policy,
            stored_policy=stored_policy,
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


def set_candidates(rows: Iterable[FinancialParameter], parameter_set: Mapping) -> list[Candidate]:
    """The parameter-set ``rows`` a build reads, as candidates."""
    return [Candidate(row.as_engine(), {"parameter_set": dict(parameter_set)}, row.distribution, row) for row in rows]


def wants_normalizing(candidate: Candidate, *, currency: str, valuation_date: date) -> bool:
    """Whether ``candidate`` is normalized under a policy: a parameter-set figure in
    another currency or at another date; an effect's attribute in the build's currency
    at another date (one in another currency is refused later, as before)."""
    native = candidate.native
    if not fn.needs_normalizing(native, currency=currency, valuation_date=valuation_date):
        return False
    return "effect" not in candidate.parent or native.currency == currency


def normalize(deployment, candidates: Iterable[Candidate], *, currency: str, valuation_date: date, policy,
              new_id) -> dict[str, Normalized]:
    """Each of ``candidates`` that :func:`wants_normalizing`, normalized under ``policy``
    for a run of ``deployment`` (see the module's rules), by its name. ``new_id`` gives
    each normalized figure the id its scenario row will have. A figure that states a
    distribution is refused (``distribution_not_normalizable``); a normalization the
    books cannot make, with its reason."""
    from . import normalization_service
    from .engine import templates as tpl
    from .engine.normalization import UNAVAILABLE

    found: dict[str, Normalized] = {}
    usable = None
    for candidate in sorted(candidates, key=lambda c: c.native.name):
        native = candidate.native
        if not wants_normalizing(candidate, currency=currency, valuation_date=valuation_date):
            continue
        if candidate.distribution is not None:
            raise tpl.BuildRefused(
                "distribution_not_normalizable", f"{native.name} states a distribution in {native.currency}"
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
                    raise tpl.BuildRefused(gone.reason, f"{native.name} {point.value}, {gone.step}: {gone.detail}")
                records[amount.amount] = result.as_dict()
            points[point.value] = records[amount.amount]
        if usable is None:
            usable = normalization_service.usable_versions(deployment, valuation_date)
        values = {
            point: Money(fn.parameter_value(Decimal(points[point.value]["value"]["amount"])), currency)
            for point in POINTS
        }
        parameter = Parameter(
            name=fn.figure_name(native.name),
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
        found[native.name] = Normalized(candidate, parameter, points, _named_sources(points.values(), usable))
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
                f"{row.name} is in {row.currency}; the build reports in {currency} and names no normalization "
                "policy to convert it",
            )


# ------------------------------------------------------------------ reading them


def stored(scenario) -> list[FigureNormalization]:
    """The scenario version's normalizations, in figure order, EACH CHECKED AS IT IS
    READ (``FigureNormalization._check_form``: its digest, both figures as it names
    them, every chain replayed): a record or a figure changed since it was written --
    past the model's checks -- is refused (``normalization_record_malformed``), and
    nothing that reads through here uses or serves it. Every reader of a record, or
    of the policy a run applies, reads through here."""
    rows = list(FigureNormalization.objects.filter(scenario=scenario).select_related("native", "normalized"))
    for row in rows:
        row._check_form(row.native, row.normalized)
    return sorted(rows, key=lambda row: row.normalized.name)


def verified(scenario) -> str | None:
    """Why the scenario version's normalizations do not hold now (the refusal's
    detail), or ``None``: :func:`stored`'s check, as a value."""
    try:
        stored(scenario)
    except EconomicsRefused as refused:
        return f"{refused.code}: {refused.detail}"
    return None


def normalization_records(scenario) -> tuple[dict, ...]:
    """Each figure's normalization record, as stored and checked, in figure order: what
    a run of the version holds in its inputs (none for a version that normalized
    nothing)."""
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
    figure (each record checked as it is read); ``None`` where there is no build or the
    version states no policy."""
    from .models import CustomerParameterSet

    if build is None:
        return None
    policy = CustomerParameterSet.objects.get(pk=build.parameter_set_id).content().insurance_policy()
    if policy is None:
        return None
    rows = stored(build.scenario_id)
    return substituted(policy, {row.native.name: row.normalized.as_engine() for row in rows})


def source_dependencies(inputs) -> list[dict]:
    """Every source version a run's normalizations read, from its stored inputs, each
    once: E6 records them with the run (``normalization_sources`` in its dependency
    map, section 34.1). Empty for a run that normalized nothing."""
    found = {}
    for record in (inputs or {}).get("normalizations") or []:
        for source in record.get("sources") or []:
            key = (source["source_key"], source["tenant"], source["version"])
            found[key] = {k: source[k] for k in ("source_key", "tenant", "version", "snapshot_hash")}
    return [found[key] for key in sorted(found)]


def moved_sources(deployment, recorded: Iterable[Mapping], as_of: date) -> list[dict]:
    """Of the source versions a run's normalizations read (``recorded``,
    :func:`source_dependencies`'s), each that a run of ``deployment`` as of ``as_of``
    would now read at another version (``feeds.used_version``: a newer usable one, or
    none a run may use): ``{source_key, tenant, was, now}``. Reads only."""
    from . import feeds

    moved = []
    for entry in recorded:
        own = entry.get("tenant") == "deployment"
        now = feeds.used_version(entry["source_key"], deployment, as_of, own=own)
        if now is None or now.version != entry.get("version"):
            moved.append({"source_key": entry["source_key"], "tenant": entry.get("tenant"),
                          "was": entry.get("version"), "now": None if now is None else now.version})
    return moved


__all__ = [
    "Candidate",
    "Normalized",
    "check_currency",
    "moved_sources",
    "normalization_records",
    "normalize",
    "policy_of",
    "read_rows",
    "resolve_policy",
    "set_candidates",
    "source_dependencies",
    "stored",
    "substituted",
    "verified",
    "wants_normalizing",
]
