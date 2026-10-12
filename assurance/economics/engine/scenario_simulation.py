"""A scenario simulated (phase E2, MVP step 7b; ``docs/economics/spec-v1.md``,
section 25): step 7a's seeded sampler wired to step 4's formulas and loss model.

Per draw, every parameter a known component reads is sampled, every component is
evaluated by its formula's vectorised twin (:mod:`.twins`), the components are
summed to their event with cash and market value kept apart exactly as step 4
keeps them, the event's insurance policy is applied to the event (never to a sum
of events or of a year), and the events are summed to the scenario. The rules:

- **A distribution for every parameter, by a stated rule, never a guess**
  (:func:`resolve`, :data:`RULE_VERSION`). A parameter that states a distribution
  (an id, version and native parameters of step 7a's catalogue) draws from it,
  when the distribution fits the parameter's unit. One that states none draws
  from a point mass where its low, base and high are one figure, and from
  PERT(low, base, high) where they are a range and its source is an
  ``EXPERT_ESTIMATE``: the only source step 7a's rule lets an expert range stand
  for. Any other range with no distribution is refused
  (``no_admissible_distribution``), with the reason.
- **One seed, a stream per parameter.** Each parameter draws from step 7a's
  sub-stream of its own stream name (:func:`stream_name`, the SHA-256 of
  :data:`STREAM_DOMAIN` and its name), so a parameter's draws depend on the seed
  and its name only, and adding a parameter changes no other's draws. The
  frequency draws from 7a's ``@frequency`` stream.
- **Occurrences and years.** Without a frequency a draw is one occurrence of the
  scenario: every event once, each given it happens (section 24.7); there is no
  expected annual exposure, and the result says so. With a frequency parameter
  (a count distribution of events a year), a draw is a simulated year of N
  occurrences, summed by 7a's :func:`.simulation.compound_annual`.
- **What is shared and what varies** (:data:`VARIATION_VERSION`). A parameter in
  ``shared`` (the service names the customer parameter set's variables and the
  policy's terms) is drawn once per simulated year and is the same for every
  occurrence of that year: what the figure IS, uncertain. Every other parameter
  (an effect's attribute) is drawn afresh for each occurrence: what each
  occurrence costs or reaches. Without a frequency the two coincide.
- **Exact where nothing is uncertain.** A component whose every input is a point
  mass has no uncertainty: it is computed once, by its Decimal formula (the
  source of truth), and that value, as the nearest binary64, is the same in
  every draw. So a run whose parameters are all point masses reproduces step 4.
- **Floats inside, Decimal outside**, as step 7a: every summary is 7a's
  (:func:`.simulation.summarize`: percentiles, mean, standard error and bands,
  invariants checked) written as decimal strings, and the record holds no float.
- **Bounded.** 7a's draws, events and values limits; the values this run holds
  are counted before anything is sampled (in a compound run, once the years'
  counts are drawn and before any parameter is), and a caller-supplied
  ``check_time`` is called between the stages, so a service can bound the run's
  time without this module reading a clock.

Pure: no Django, no database, no I/O, no clock.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from types import MappingProxyType

import numpy as np

from . import distributions as dist
from . import simulation as sim
from . import twins as tw
from .formulas import ESTIMATED, MARKET_VALUE, LossComponent
from .loss import NEVER_COVERED, InsurancePolicy, LossEvent
from .money import Money, MoneyRefused, check_reporting_currency, decimal_text, parse_decimal
from .parameters import POINTS, Parameter, ParameterRefused, Unit
from .provenance import SourceType
from .taxonomy import LossFamily

#: The result's schema.
SCHEMA = "mythos.economics.scenario-simulation/v1"
#: The canonical inputs' schema: what the input digest is taken over.
INPUTS_SCHEMA = "mythos.economics.scenario-simulation-inputs/v1"
#: The version of this wiring: the aggregation order, the insurance step, the
#: constant components, the record. A change that alters a figure is a new one.
ENGINE_VERSION = 1
#: The parameter-to-distribution rule (:func:`resolve`).
RULE_VERSION = "mythos.economics.parameter-distribution/v1"
RULE = (
    "a stated distribution of step 7a's catalogue, where it fits the parameter's unit; otherwise a point mass "
    "where low = base = high; otherwise PERT(low, base, high), weight 4, where the source is EXPERT_ESTIMATE; "
    "otherwise refused (no_admissible_distribution)"
)
#: Which parameters are drawn once per simulated year and which per occurrence.
VARIATION_VERSION = "mythos.economics.variation/v1"
#: Hashed before a parameter's name to give its stream's name.
STREAM_DOMAIN = "mythos.economics.parameter-stream/v1"
#: The name of a scenario's frequency parameter: events a year.
FREQUENCY_PARAMETER = "frequency"

SHARED = "shared"
PER_OCCURRENCE = "per_occurrence"
VARIATIONS = (SHARED, PER_OCCURRENCE)

#: How a parameter's distribution was decided.
RULE_STATED = "stated"
RULE_POINT_MASS = "point_mass"
RULE_PERT_DEFAULT = "pert_default"

#: A point mass's record id. Not one of step 7a's catalogue: it draws nothing.
POINT_MASS = "point_mass"
POINT_MASS_VERSION = 1

#: How a component was evaluated.
BY_TWIN = "twin"
BY_DECIMAL = "decimal_constant"

#: What a result's percentiles are of.
PER_OCCURRENCE_BASIS = "per_occurrence"
ANNUAL_BASIS = sim.ANNUAL_LOSS

#: The scenario's figures, each a summary block.
GROSS_CASH = "gross_cash"
RETAINED_CASH = "retained_cash"
MARKET_VALUE_LINE = "market_value"

ONE_OCCURRENCE = (
    "no frequency: a draw is one occurrence of the scenario, every event once, each given it happens; "
    "there is no expected annual exposure"
)
COMPOUND = (
    "a draw is a simulated year of N occurrences, N from the frequency; each occurrence is every event once; "
    "the year's loss is the sum of its occurrences' (step 7a's compound_annual)"
)

#: What each refusal code of this module means. Codes step 7a, the money engine
#: and the scenario engine publish are raised as theirs, with their meaning.
REFUSALS: Mapping[str, str] = MappingProxyType(
    {
        "no_admissible_distribution": (
            "a parameter with a range (low below high), no distribution of its own, and a source other than "
            "EXPERT_ESTIMATE: an expert's PERT never stands in for data; state the parameter's distribution"
        ),
        "distribution_malformed": (
            "a stated distribution is an object of exactly id, version and params (and sparse, for an expert "
            "range), its parameters decimal strings (a splice's body and tail stated distributions)"
        ),
        "distribution_unknown": "a stated distribution's id is one of step 7a's catalogue",
        "distribution_version_unknown": "a stated distribution's version is the catalogue's version of it",
        "distribution_not_for_unit": (
            "a distribution draws only what its parameter's unit holds: a ratio from 0 to 1 (a rate, or an "
            "expert range inside [0, 1]); a count from a count, severity or expert distribution; anything else "
            "from a severity or expert distribution at or above zero"
        ),
        "frequency_distribution_missing": "a scenario's frequency parameter states a count distribution",
        "frequency_not_a_count": "a frequency is a count distribution (Poisson, negative binomial, zero-inflated Poisson)",
        "twin_missing": "a formula a simulation evaluates has a vectorised twin: none is approximated",
        "events_missing": "a scenario holds at least one loss event",
        "variation_unrecognised": "a shared parameter is one the scenario reads",
        "out_of_range": "a component's, event's or year's loss too large to hold as a binary64 float",
        "time_over_budget": "the run took longer than its time budget, and was stopped between two stages",
    }
)


class ScenarioSimulationRefused(ValueError):
    """A scenario simulation refused. ``code`` is one of :data:`REFUSALS`."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        super().__init__(f"{code}: {REFUSALS[code]}{suffix}")


# ------------------------------------------------------ stated distributions


#: Each catalogue distribution's native parameters, as a stored distribution
#: states them. PERT's weight is optional (4 unless stated, section 23.12).
NATIVE_PARAMETERS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "poisson": ("rate",),
        "negative_binomial": ("size", "probability"),
        "zero_inflated_poisson": ("zero_inflation", "rate"),
        "beta_binomial_rate": ("alpha", "beta"),
        "lognormal": ("mu", "sigma"),
        "gamma": ("shape", "scale"),
        "generalized_pareto": ("shape", "scale", "threshold"),
        "spliced": ("body", "tail", "tail_probability"),
        "pert": ("minimum", "mode", "maximum", "shape"),
        "triangular": ("minimum", "mode", "maximum"),
    }
)
_OPTIONAL_PARAMETERS = MappingProxyType({"pert": frozenset({"shape"})})
_NESTED = frozenset({"body", "tail"})
_STATED_REQUIRED = frozenset({"id", "version", "params"})
_STATED_OPTIONAL = frozenset({"sparse"})


@dataclass(frozen=True)
class StatedDistribution:
    """A distribution a parameter states: a catalogue id and version, its native
    parameters (Decimals; a splice's body and tail are stated distributions), and,
    for an expert range, whether the data are sparse."""

    distribution_id: str
    version: int
    params: Mapping[str, Decimal | StatedDistribution]
    sparse: bool | None = None

    def as_json(self) -> dict:
        """The stored form: every number a decimal string in the one spelling."""
        body = {
            "id": self.distribution_id,
            "version": self.version,
            "params": {
                name: value.as_json() if isinstance(value, StatedDistribution) else decimal_text(value)
                for name, value in sorted(self.params.items())
            },
        }
        if self.sparse is not None:
            body["sparse"] = self.sparse
        return body


def parse_stated(obj, path: str = "distribution") -> StatedDistribution:
    """A stated distribution read exactly from its stored form, or refused."""

    def malformed(detail: str) -> ScenarioSimulationRefused:
        return ScenarioSimulationRefused("distribution_malformed", f"{path}: {detail}")

    if not isinstance(obj, dict):
        raise malformed(f"a {type(obj).__name__}, not an object")
    keys = set(obj)
    if not _STATED_REQUIRED <= keys or not keys <= _STATED_REQUIRED | _STATED_OPTIONAL:
        raise malformed(f"keys {sorted(keys)}")
    distribution_id = obj["id"]
    if not isinstance(distribution_id, str) or distribution_id not in dist.CATALOGUE:
        raise ScenarioSimulationRefused("distribution_unknown", f"{path}: {distribution_id!r}")
    if distribution_id not in NATIVE_PARAMETERS:
        raise ScenarioSimulationRefused("distribution_unknown", f"{path}: {distribution_id!r} has no stored form")
    version = obj["version"]
    if type(version) is not int or version != dist.CATALOGUE[distribution_id].VERSION:
        raise ScenarioSimulationRefused(
            "distribution_version_unknown",
            f"{path}: {distribution_id} version {version!r}; the catalogue's is {dist.CATALOGUE[distribution_id].VERSION}",
        )
    raw = obj["params"]
    if not isinstance(raw, dict):
        raise malformed("params is not an object")
    names = set(NATIVE_PARAMETERS[distribution_id])
    optional = _OPTIONAL_PARAMETERS.get(distribution_id, frozenset())
    if not names - optional <= set(raw) or not set(raw) <= names:
        raise malformed(f"params {sorted(raw)}; {distribution_id} takes {sorted(names)}")
    params: dict[str, Decimal | StatedDistribution] = {}
    for name, value in raw.items():
        if name in _NESTED:
            params[name] = parse_stated(value, f"{path}.params.{name}")
            continue
        try:
            params[name] = parse_decimal(value, f"{path}.params.{name}")
        except MoneyRefused as refused:
            raise malformed(f"params.{name}: {refused.code}") from None
    expert = type_is_expert(distribution_id)
    sparse = obj.get("sparse")
    if "sparse" in obj:
        if not expert or not isinstance(sparse, bool):
            raise malformed("sparse is true or false, and only for an expert range")
    elif expert:
        sparse = False
    return StatedDistribution(distribution_id, version, MappingProxyType(params), sparse)


def type_is_expert(distribution_id: str) -> bool:
    return bool(dist.CATALOGUE[distribution_id].EXPERT)


def build(stated: StatedDistribution, source_type: SourceType) -> dist.Distribution:
    """The catalogue distribution ``stated`` names, from its native parameters; an
    expert range takes the parameter's own ``source_type``, never one it states."""
    cls = dist.CATALOGUE[stated.distribution_id]
    kwargs: dict[str, object] = {}
    for name, value in stated.params.items():
        kwargs[name] = build(value, source_type) if isinstance(value, StatedDistribution) else value
    if cls.EXPERT:
        kwargs["source_type"] = source_type
        kwargs["sparse"] = bool(stated.sparse)
    return cls(**kwargs)


def _support_fits(distribution: dist.Distribution, unit: Unit) -> bool:
    kind = type(distribution).KIND
    expert_at_or_above_zero = kind == dist.EXPERT and distribution.minimum >= 0.0
    if unit is Unit.RATIO:
        return kind == dist.RATE or (expert_at_or_above_zero and distribution.maximum <= 1.0)
    if unit in (Unit.COUNT, Unit.COUNT_PER_DAY):
        return kind in (dist.FREQUENCY, dist.SEVERITY) or expert_at_or_above_zero
    return kind == dist.SEVERITY or expert_at_or_above_zero


def check_stated(stated: StatedDistribution, parameter: Parameter) -> dist.Distribution:
    """The distribution ``stated`` builds for ``parameter``, refused unless it fits
    the parameter's unit. A frequency parameter's is checked by :func:`resolve_frequency`."""
    distribution = build(stated, parameter.source_type)
    if parameter.name != FREQUENCY_PARAMETER and not _support_fits(distribution, parameter.unit):
        raise ScenarioSimulationRefused(
            "distribution_not_for_unit", f"{parameter.name} is {parameter.unit.value}; {stated.distribution_id} does not fit it"
        )
    return distribution


# --------------------------------------------------------------- the rule


def stream_name(name: str) -> str:
    """The step-7a stream a parameter named ``name`` draws from: ``p`` and the first
    40 hex digits of the SHA-256 of :data:`STREAM_DOMAIN`, a zero byte and the
    name's UTF-8 (a stream name is lowercase letters, digits and ``_``; a
    parameter's name need not be)."""
    digest = hashlib.sha256(STREAM_DOMAIN.encode("ascii") + b"\x00" + name.encode("utf-8")).hexdigest()
    return "p" + digest[:40]


def _amount(value: Money | Decimal) -> Decimal:
    return value.amount if isinstance(value, Money) else value


@dataclass(frozen=True)
class Resolved:
    """A parameter and the distribution the rule gave it: ``distribution`` is
    ``None`` for a point mass, whose exact value is ``point``."""

    parameter: Parameter
    rule: str
    variation: str
    distribution: dist.Distribution | None = None
    point: Decimal | None = None

    @property
    def name(self) -> str:
        return self.parameter.name

    @property
    def stream(self) -> str:
        return stream_name(self.parameter.name)

    @property
    def expert(self) -> bool:
        return self.distribution is not None and bool(type(self.distribution).EXPERT)

    @property
    def mean_finite(self) -> bool:
        return self.distribution is None or self.distribution.mean is not None

    @property
    def variance_finite(self) -> bool:
        return self.distribution is None or self.distribution.variance is not None

    def distribution_record(self) -> dict:
        if self.distribution is None:
            return {"id": POINT_MASS, "version": POINT_MASS_VERSION, "value": decimal_text(self.point)}
        return self.distribution.record()

    def record(self) -> dict:
        return {
            "rule": self.rule,
            "variation": self.variation,
            "stream": None if self.distribution is None else self.stream,
            "distribution": self.distribution_record(),
        }


def resolve(parameter: Parameter, stated: StatedDistribution | None, *, variation: str = PER_OCCURRENCE) -> Resolved:
    """The distribution ``parameter`` draws from, by :data:`RULE_VERSION`. See the
    module's rules."""
    if not isinstance(parameter, Parameter):
        raise TypeError(f"a Parameter, not a {type(parameter).__name__}")
    if variation not in VARIATIONS:
        raise ScenarioSimulationRefused("variation_unrecognised", repr(variation))
    if stated is not None:
        return Resolved(parameter, RULE_STATED, variation, distribution=check_stated(stated, parameter))
    low, base, high = (_amount(parameter.at(point)) for point in POINTS)
    if low == high:
        return Resolved(parameter, RULE_POINT_MASS, variation, point=base)
    if parameter.source_type is not SourceType.EXPERT_ESTIMATE:
        raise ScenarioSimulationRefused(
            "no_admissible_distribution",
            f"{parameter.name} ranges from {low} to {high}, rests on {parameter.source_type.value} and states no "
            "distribution",
        )
    pert = dist.Pert(low, base, high, source_type=SourceType.EXPERT_ESTIMATE, sparse=False)
    if not _support_fits(pert, parameter.unit):
        raise ScenarioSimulationRefused("distribution_not_for_unit", parameter.name)
    return Resolved(parameter, RULE_PERT_DEFAULT, variation, distribution=pert)


def resolve_frequency(parameter: Parameter, stated: StatedDistribution | None) -> Resolved:
    """A scenario's frequency: a ``count`` parameter that states a count
    distribution of events a year. Nothing defaults: a PERT is not a count."""
    if parameter.unit is not Unit.COUNT:
        raise ParameterRefused("unit_mismatch", f"the frequency is {parameter.unit.value}, not a count of events a year")
    if stated is None:
        raise ScenarioSimulationRefused("frequency_distribution_missing", parameter.name)
    distribution = build(stated, parameter.source_type)
    if not (type(distribution).DISCRETE and type(distribution).KIND == dist.FREQUENCY):
        raise ScenarioSimulationRefused("frequency_not_a_count", stated.distribution_id)
    return Resolved(parameter, RULE_STATED, SHARED, distribution=distribution)


# --------------------------------------------------------------- the input


@dataclass(frozen=True)
class ScenarioInput:
    """What one run reads: the scenario's events (step 4's, each component
    computed from the parameters it cites), the policy their insurance applies,
    each parameter's stated distribution by name, the names drawn once per
    simulated year, and the frequency parameter, if any."""

    scenario_id: str | None
    currency: str
    events: tuple[LossEvent, ...]
    policy: InsurancePolicy | None = None
    stated: Mapping[str, StatedDistribution] = field(default_factory=dict)
    shared: frozenset[str] = frozenset()
    frequency: Parameter | None = None


def _policy_terms(policy: InsurancePolicy | None) -> list[tuple[str, Parameter]]:
    if policy is None:
        return []
    terms = [("deductible", policy.deductible), ("limit", policy.limit)]
    terms += [(f"sublimit:{family}", term) for family, term in sorted(policy.sublimits.items())]
    if policy.waiting_period_hours is not None:
        terms.append(("waiting_period_hours", policy.waiting_period_hours))
    return terms


def _named(si: ScenarioInput) -> dict[str, Parameter]:
    """Every parameter the scenario cites, its policy's terms and its frequency, by
    name: one name is one parameter (``duplicate_id``)."""
    named: dict[str, Parameter] = {}

    def add(parameter: Parameter) -> None:
        held = named.get(parameter.name)
        if held is not None and held != parameter:
            raise ParameterRefused("duplicate_id", f"two different parameters are both {parameter.name!r} in one scenario")
        named[parameter.name] = parameter

    keys = [event.loss_event_id for event in si.events]
    if len(set(keys)) != len(keys):
        raise ParameterRefused("duplicate_id", "an event twice in one scenario: it would be counted twice")
    for event in si.events:
        for component in event.components:
            for cited in component.inputs:
                add(cited.parameter)
    for _, term in _policy_terms(si.policy):
        add(term)
    if si.frequency is not None:
        if si.frequency.name in named:
            raise ParameterRefused("duplicate_id", f"the frequency {si.frequency.name!r} is also a component's input")
        add(si.frequency)
    return named


def versions(si: ScenarioInput) -> dict:
    """Every version a run's figures depend on: this wiring's, the rule's, the
    twins', each formula's and each catalogue distribution's, the sampler's and
    numpy's. They are part of the canonical inputs, so a change to any is a new
    input digest and a new stored result, never an old one returned."""
    formulas = sorted(
        {f"{c.formula.formula_id}/{c.formula.version}" for event in si.events for c in event.components}
    )
    return {
        "scenario_simulation": ENGINE_VERSION,
        "schema": SCHEMA,
        "parameter_distribution_rule": RULE_VERSION,
        "variation": VARIATION_VERSION,
        "twins": tw.TWINS_VERSION,
        "twin_tolerance": decimal_text(tw.RELATIVE_TOLERANCE),
        "formulas": formulas,
        "distributions": {name: cls.VERSION for name, cls in sorted(dist.CATALOGUE.items())},
        "sampler": sim.SAMPLER_VERSION,
        "bit_generator": sim.BIT_GENERATOR,
        "substream_domain": sim.SUBSTREAM_DOMAIN,
        "stream_domain": STREAM_DOMAIN,
        "numpy": np.__version__,
    }


def canonical_inputs(si: ScenarioInput, *, severe_percentile=sim.DEFAULT_SEVERE_PERCENTILE) -> dict:
    """The inputs a run reads, in canonical form, without the seed and the draws
    (they are stored beside the digest): every event and component with its
    formula and the parameter each input reads, every parameter with its values,
    source, evidence and STATED distribution, which are shared, the policy, the
    frequency, the severe-but-plausible percentile, the rules and every version.
    It is computed before anything is resolved, so a refused run has a digest."""
    if not isinstance(si, ScenarioInput):
        raise TypeError(f"a ScenarioInput, not a {type(si).__name__}")
    percentile = sim.check_severe_percentile(severe_percentile)
    named = _named(si)
    unknown_shared = sorted(si.shared - set(named))
    if unknown_shared:
        raise ScenarioSimulationRefused("variation_unrecognised", f"{unknown_shared}")
    stated = dict(si.stated)
    for name, value in stated.items():
        if not isinstance(value, StatedDistribution):
            raise ScenarioSimulationRefused("distribution_malformed", f"{name}: a {type(value).__name__}")
    policy = si.policy
    return {
        "schema": INPUTS_SCHEMA,
        "scenario_id": si.scenario_id,
        "reporting_currency": si.currency,
        "severe_percentile": decimal_text(percentile),
        "events": [
            {
                "event_key": event.loss_event_id,
                "currency": event.currency,
                "components": [
                    {
                        "component_id": c.component_id,
                        "family": c.family,
                        "formula": [c.formula.formula_id, c.formula.version],
                        "status": c.status,
                        "unknown_reason": c.unknown_reason,
                        "missing": list(c.missing),
                        "as_of": c.as_of.isoformat(),
                        "reads": {cited.input.name: cited.parameter.name for cited in c.inputs},
                    }
                    for c in event.components
                ],
            }
            for event in si.events
        ],
        "parameters": {
            name: {
                **parameter.as_dict(),
                "distribution": stated[name].as_json() if name in stated else None,
                "variation": SHARED if name in si.shared else PER_OCCURRENCE,
            }
            for name, parameter in sorted(named.items())
        },
        "policy": None
        if policy is None
        else {
            "terms": {role: term.name for role, term in _policy_terms(policy)},
            "exclusions": sorted(policy.exclusions),
            "never_covered": sorted(NEVER_COVERED),
            "applied": "once per event occurrence, after its gross components",
        },
        "frequency": None if si.frequency is None else si.frequency.name,
        "rules": {"parameter_distribution": RULE_VERSION, "rule": RULE, "variation": VARIATION_VERSION},
        "versions": versions(si),
    }


def digest_of(document: Mapping) -> str:
    """``sha256:`` and the SHA-256 of a document's canonical JSON (7a's form)."""
    return "sha256:" + hashlib.sha256(sim.canonical_json(document)).hexdigest()


# ---------------------------------------------------------------- the plan


@dataclass(frozen=True)
class _Component:
    event: int
    component: LossComponent
    reads: Mapping[str, str]
    twin: tw.Twin | None
    constant: float | None

    @property
    def estimated(self) -> bool:
        return self.component.status == ESTIMATED

    @property
    def cash(self) -> bool:
        return self.component.family != MARKET_VALUE

    @property
    def evaluated_by(self) -> str | None:
        if not self.estimated:
            return None
        return BY_DECIMAL if self.constant is not None else BY_TWIN


@dataclass(frozen=True)
class _Plan:
    si: ScenarioInput
    components: tuple[_Component, ...]
    resolved: Mapping[str, Resolved]
    terms: Mapping[str, str]
    frequency: Resolved | None


def _constant(component: LossComponent, resolved: Mapping[str, Resolved]) -> float | None:
    """A component whose every input is a point mass, computed once by its Decimal
    formula, as the nearest binary64; ``None`` if any input is uncertain."""
    points = {}
    for cited in component.inputs:
        held = resolved[cited.parameter.name]
        if held.distribution is not None:
            return None
        points[cited.input.name] = cited.parameter.base
    result = component.formula.calculate(points)
    return float(result.amount)


def plan(si: ScenarioInput) -> _Plan:
    """Check ``si`` and decide every distribution, twin and constant; refused
    before anything is sampled."""
    check_reporting_currency(si.currency)
    if not si.events:
        raise ScenarioSimulationRefused("events_missing", "the scenario holds no loss event")
    for event in si.events:
        if not isinstance(event, LossEvent):
            raise TypeError(f"a LossEvent, not a {type(event).__name__}")
        if event.currency != si.currency:
            raise MoneyRefused(
                "currency_mismatch", f"event {event.loss_event_id} is in {event.currency}; the run is in {si.currency}"
            )
    if si.policy is not None and si.policy.currency != si.currency:
        raise MoneyRefused("currency_mismatch", f"the policy is in {si.policy.currency}; the run is in {si.currency}")
    named = _named(si)
    needed: set[str] = set()
    for event in si.events:
        for component in event.components:
            if component.status == ESTIMATED:
                needed.update(cited.parameter.name for cited in component.inputs)
    terms = {role: term.name for role, term in _policy_terms(si.policy)}
    needed.update(terms.values())
    resolved = {
        name: resolve(named[name], si.stated.get(name), variation=SHARED if name in si.shared else PER_OCCURRENCE)
        for name in sorted(needed)
    }
    frequency = None
    if si.frequency is not None:
        frequency = resolve_frequency(si.frequency, si.stated.get(si.frequency.name))
    components = []
    for index, event in enumerate(si.events):
        for component in event.components:
            reads = MappingProxyType({cited.input.name: cited.parameter.name for cited in component.inputs})
            if component.status != ESTIMATED:
                components.append(_Component(index, component, reads, None, None))
                continue
            try:
                twin = tw.twin(component.formula.formula_id, component.formula.version)
            except tw.TwinMissing as missing:
                raise ScenarioSimulationRefused(
                    "twin_missing", f"{missing.formula_id} version {missing.version} ({component.component_id})"
                ) from None
            components.append(_Component(index, component, reads, twin, _constant(component, resolved)))
    return _Plan(si, tuple(components), MappingProxyType(resolved), MappingProxyType(terms), frequency)


# ---------------------------------------------------------------- the draws

#: Vectors the insurance step holds beside the lines at its peak: one family's
#: sum (and its waiting-period mask), the covered total and the excess.
INSURANCE_TEMPORARIES = 4
#: Vectors a summary holds beside the lines: a line's annual sum and its sorted copy.
SUMMARY_TEMPORARIES = 2
#: Annual lines a compound run holds a value of per simulated year: the
#: scenario's gross cash, market value, recovery and retained cash.
ANNUAL_LINES = 4


def _last_reads(p: _Plan) -> dict[str, int]:
    """Each parameter's last reader, by component index: its draws are let go once
    that component is evaluated. A policy term's are kept to the insurance step."""
    last: dict[str, int] = {}
    for index, c in enumerate(p.components):
        if c.estimated and c.constant is None:
            for name in c.reads.values():
                last[name] = index
    for name in p.terms.values():
        last[name] = len(p.components)
    return last


def _line_vectors(p: _Plan) -> int:
    """The vectors of the occurrence length the lines hold: each event's gross cash,
    its market value where it has a known market-value component, and its recovery
    and retained cash under a policy; the scenario's the same, unless it has one
    event, whose lines it is."""
    policy = 2 if p.si.policy is not None else 0
    markets = [
        any(c.event == index and c.estimated and not c.cash for c in p.components) for index in range(len(p.si.events))
    ]
    held = sum(1 + int(market) + policy for market in markets)
    if len(p.si.events) > 1:
        held += 1 + int(any(markets)) + policy
    return held


def values_held(p: _Plan, length: int, years: int | None = None) -> int:
    """The values a run holds at its peak, by its own count, stage by stage.
    Drawing and evaluating: every drawn parameter's vector until its last reader
    is evaluated, the components evaluated so far, and 7a's RUN_VECTORS of
    temporaries. Insurance: the components, the lines (:func:`_line_vectors`), the
    drawn policy terms and :data:`INSURANCE_TEMPORARIES`. Summaries: the
    components, the lines and :data:`SUMMARY_TEMPORARIES`. Each of the sampled
    length (the draws, or a compound run's occurrences); and, in a compound run,
    beside them, one value per simulated year of each shared drawn parameter, of
    the :data:`ANNUAL_LINES` and of 7a's YEAR_VECTORS."""
    drawn = {name for name, r in p.resolved.items() if r.distribution is not None}
    last = _last_reads(p)
    live, done, drawing = len(drawn), 0, 0
    for index, c in enumerate(p.components):
        if not c.estimated:
            continue
        drawing = max(drawing, live + done + 1 + sim.RUN_VECTORS)
        done += 1
        live -= sum(1 for name in drawn if last.get(name) == index)
    drawing = max(drawing, len(drawn) + sim.RUN_VECTORS)
    lines = _line_vectors(p)
    terms = sum(1 for name in set(p.terms.values()) if name in drawn)
    insuring = done + lines + terms + INSURANCE_TEMPORARIES
    summarising = done + lines + SUMMARY_TEMPORARIES
    held = max(drawing, insuring, summarising) * length
    if years is not None:
        shared = sum(1 for name in drawn if p.resolved[name].variation == SHARED)
        held += (shared + ANNUAL_LINES + sim.YEAR_VECTORS) * years
    return held


def _check_budget(p: _Plan, length: int, years: int | None) -> None:
    held = values_held(p, length, years)
    if held > sim.MAX_VALUES:
        what = f"{length} draws" if years is None else f"{length} occurrences in {years} years"
        raise sim.SimulationRefused("values_over_budget", f"{what} hold {held} values; at most {sim.MAX_VALUES}")


def _checked_draws(r: Resolved, drawn: np.ndarray) -> np.ndarray:
    drawn = np.asarray(drawn, dtype=np.float64)
    if not np.isfinite(drawn).all() or (drawn < 0.0).any() or (r.parameter.unit is Unit.RATIO and (drawn > 1.0).any()):
        raise sim.InvariantBroken(f"{r.name} drew a value its unit does not hold: the admissibility check failed")
    drawn.flags.writeable = False
    return drawn


def _finite(vector: np.ndarray, what: str) -> np.ndarray:
    if not np.isfinite(vector).all():
        raise ScenarioSimulationRefused("out_of_range", what)
    if (vector < 0.0).any():
        raise sim.InvariantBroken(f"{what} is negative: no benefit model is enabled")
    return vector


@dataclass
class _Sample:
    counts: np.ndarray | None
    occurrences: int
    limit: np.ndarray | float | None
    components: dict[int, np.ndarray]
    events: list[dict[str, np.ndarray | None]]
    scenario: dict[str, np.ndarray | None]
    annual: dict[str, np.ndarray | None]


def _zeros(n: int) -> np.ndarray:
    return np.zeros(n, dtype=np.float64)


def _insure(terms: Mapping[str, np.ndarray | float], policy: InsurancePolicy, cash, gross: np.ndarray):
    """Step 4's insurance (spec, section 17), per occurrence of ONE event: each cash
    family's covered amount (not an excluded family, not the insurance family, and
    business interruption only where the waiting period is zero; a waiting period
    left unstated is unknown, so never), summed in component order and capped at
    its sublimit, the families taken in the order they first appear; the
    deductible off their total; the recovery capped at the limit, and never more
    than the gross loss. Returns the recovery and the retained cash."""
    uncovered = set(policy.exclusions) | NEVER_COVERED
    waiting = terms.get("waiting_period_hours")
    families: dict[str, list[np.ndarray]] = {}
    for c, vector in cash:
        family = c.component.family
        if family in uncovered:
            continue
        if family == LossFamily.BUSINESS_INTERRUPTION.value and waiting is None:
            continue
        families.setdefault(family, []).append(vector)
    covered = _zeros(gross.size)
    for family, vectors in families.items():
        amount = np.array(vectors[0], dtype=np.float64, copy=True)
        for vector in vectors[1:]:
            amount += vector
        if family == LossFamily.BUSINESS_INTERRUPTION.value:
            amount = np.where(np.asarray(waiting) == 0.0, amount, 0.0)
        cap = terms.get(f"sublimit:{family}")
        if cap is not None:
            np.minimum(amount, cap, out=amount)
        covered += amount
        del amount
    excess = covered - terms["deductible"]
    del covered
    np.maximum(excess, 0.0, out=excess)
    recovery = np.minimum(excess, terms["limit"])
    del excess
    np.minimum(recovery, gross, out=recovery)
    return recovery, gross - recovery


def _sample(p: _Plan, seed: int, draws: int, check_time: Callable[[str], None]) -> _Sample:
    random = sim.RunRandom(seed)
    counts = None
    years = None
    occurrences = draws
    if p.frequency is not None:
        counts = np.asarray(p.frequency.distribution.sample(random.stream(sim.FREQUENCY_STREAM), draws), dtype=np.int64)
        counts.flags.writeable = False
        occurrences = int(counts.sum())
        if occurrences > sim.MAX_EVENTS:
            raise sim.SimulationRefused("events_over_limit", f"{occurrences} occurrences in {draws} years")
        years = draws
    _check_budget(p, occurrences, years)
    check_time("frequency")

    term_names = set(p.terms.values())
    values: dict[str, np.ndarray | float] = {}
    yearly_terms: dict[str, np.ndarray | float] = {}
    for name in sorted(p.resolved):
        r = p.resolved[name]
        if r.distribution is None:
            values[name] = yearly_terms[name] = float(r.point)
            continue
        stream = random.stream(r.stream)
        if counts is not None and r.variation == SHARED:
            yearly = _checked_draws(r, r.distribution.sample(stream, draws))
            if name in term_names:
                yearly_terms[name] = yearly
            values[name] = _checked_draws(r, np.repeat(yearly, counts))
            del yearly
        else:
            values[name] = _checked_draws(r, r.distribution.sample(stream, occurrences))
        check_time(f"parameter {name}")

    n = occurrences
    last = _last_reads(p)
    components: dict[int, np.ndarray] = {}
    for index, c in enumerate(p.components):
        if not c.estimated:
            continue
        if c.constant is not None:
            vector = np.full(n, c.constant, dtype=np.float64)
        else:
            vector = c.twin({name: values[source] for name, source in c.reads.items()})
            if vector.shape != (n,):
                vector = np.array(np.broadcast_to(vector, (n,)), dtype=np.float64)
        components[index] = _finite(vector, f"component {c.component.component_id}")
        for name in [name for name, at in last.items() if at == index]:
            values.pop(name, None)  # its last reader is evaluated: its draws are let go
        check_time(f"component {c.component.component_id}")

    policy = p.si.policy
    terms = {role: values[name] for role, name in p.terms.items()}
    del values
    events: list[dict[str, np.ndarray | None]] = []
    for event_index in range(len(p.si.events)):
        known = [(c, components[i]) for i, c in enumerate(p.components) if c.event == event_index and c.estimated]
        # Cash and market value are summed apart, each in component order, and never
        # one into the other (spec, section 16).
        gross = _zeros(n)
        for c, vector in known:
            if c.cash:
                gross += vector
        market = None
        if any(not c.cash for c, _ in known):
            market = _zeros(n)
            for c, vector in known:
                if not c.cash:
                    market += vector
        line: dict[str, np.ndarray | None] = {
            GROSS_CASH: _finite(gross, f"event {p.si.events[event_index].loss_event_id}"),
            MARKET_VALUE_LINE: market,
            "recovery": None,
            RETAINED_CASH: None,
        }
        if policy is not None:
            line["recovery"], line[RETAINED_CASH] = _insure(terms, policy, [(c, v) for c, v in known if c.cash], gross)
        events.append(line)
    if len(events) == 1:
        scenario = dict(events[0])  # one event: its lines are the scenario's
    else:
        scenario = {}
        for key in (GROSS_CASH, MARKET_VALUE_LINE, "recovery", RETAINED_CASH):
            held = [line[key] for line in events if line[key] is not None]
            if not held:
                scenario[key] = None
                continue
            total = _zeros(n)
            for vector in held:
                total += vector
            scenario[key] = _finite(total, f"the scenario's {key}")
    limit = None
    if policy is not None:
        limit = yearly_terms.get(p.terms["limit"]) if counts is not None else terms["limit"]
    check_time("aggregation")

    annual: dict[str, np.ndarray | None] = {}
    if counts is not None:
        for key, vector in scenario.items():
            annual[key] = None if vector is None else _finite(sim.compound_annual(counts, vector), f"a year's {key}")
        check_time("years")
    return _Sample(counts, occurrences, limit, components, events, scenario, annual)


def _ordered_vectors(p: _Plan, s: _Sample) -> list[tuple[str, np.ndarray]]:
    """Every vector a run's figures come from, in a fixed order, by label."""
    ordered: list[tuple[str, np.ndarray]] = []
    if s.counts is not None:
        ordered.append(("counts", s.counts))
    for index, c in enumerate(p.components):
        if c.estimated:
            ordered.append((f"component/{p.si.events[c.event].loss_event_id}/{c.component.component_id}",
                            s.components[index]))
    for event, line in zip(p.si.events, s.events, strict=True):
        for key in (GROSS_CASH, MARKET_VALUE_LINE, "recovery", RETAINED_CASH):
            if line[key] is not None:
                ordered.append((f"event/{event.loss_event_id}/{key}", line[key]))
    for key in (GROSS_CASH, MARKET_VALUE_LINE, "recovery", RETAINED_CASH):
        if s.scenario[key] is not None:
            ordered.append((f"scenario/{key}", s.scenario[key]))
        if s.annual.get(key) is not None:
            ordered.append((f"annual/{key}", s.annual[key]))
    return ordered


def outcomes_digest(ordered: Iterable[tuple[str, np.ndarray]]) -> str:
    """``sha256:`` over every vector, each as its label, a zero byte, its length
    and its values little-endian (binary64, or int64 for the counts)."""
    hasher = hashlib.sha256()
    for label, vector in ordered:
        kind = "<i8" if vector.dtype.kind in "iu" else "<f8"
        hasher.update(label.encode("utf-8") + b"\x00" + str(vector.size).encode("ascii") + b"\x00")
        hasher.update(np.ascontiguousarray(vector, dtype=kind).data)
    return "sha256:" + hasher.hexdigest()


# ------------------------------------------------------------ the summaries


def _defined(resolved: Iterable[Resolved]) -> tuple[list[str], list[str]]:
    resolved = list(resolved)
    return (
        sorted(r.name for r in resolved if not r.mean_finite),
        sorted(r.name for r in resolved if not r.variance_finite),
    )


def _block(vector: np.ndarray, *, currency: str, severe, annual: bool, inputs: Iterable[Resolved]) -> dict:
    """7a's summary of one line, as decimal strings, and its expected annual
    exposure where the line is annual."""
    infinite_mean, infinite_variance = _defined(inputs)
    summary = sim.summarize(
        vector, severe_percentile=severe, mean_defined=not infinite_mean, error_defined=not infinite_variance
    )
    block = sim.summary_block(summary, currency)
    block["expected_annual_exposure"] = block["mean"] if annual else None
    block["mean_undefined"] = infinite_mean or None
    block["standard_error_undefined"] = infinite_variance or None
    return block


@dataclass(frozen=True)
class ScenarioSimulation:
    """One run: :attr:`record` is everything :attr:`digest` covers; ``vectors``
    holds every component and line, per occurrence, and the scenario's lines per
    year in a compound run, read-only, for the caller and the tests."""

    record: Mapping
    digest: str
    input_digest: str
    inputs: Mapping
    vectors: Mapping[str, np.ndarray]


def _noop(stage: str) -> None:
    return None


def run(
    si: ScenarioInput,
    *,
    seed: int,
    draws: int = sim.DEFAULT_DRAWS,
    severe_percentile=sim.DEFAULT_SEVERE_PERCENTILE,
    check_time: Callable[[str], None] | None = None,
) -> ScenarioSimulation:
    """Simulate ``si``: ``draws`` occurrences, or simulated years where it has a
    frequency, seeded by ``seed``. See the module's rules."""
    sim.check_seed(seed)
    sim.check_draws(draws)
    severe = sim.check_severe_percentile(severe_percentile)
    check_time = check_time or _noop
    inputs = canonical_inputs(si, severe_percentile=severe)
    input_digest = digest_of(inputs)
    p = plan(si)
    if p.frequency is None:
        _check_budget(p, draws, None)

    # Reproducibility, enforced as 7a enforces it: the run is sampled twice from
    # fresh streams and must agree bit for bit. The first sample is hashed and let
    # go before the second is drawn, so the peak is one sample's.
    first = _sample(p, seed, draws, check_time)
    first_digest = outcomes_digest(_ordered_vectors(p, first))
    del first
    s = _sample(p, seed, draws, check_time)
    ordered = _ordered_vectors(p, s)
    digest_of_outcomes = outcomes_digest(ordered)
    if digest_of_outcomes != first_digest:
        raise sim.InvariantBroken("the same seed and inputs gave different draws: the run is not reproducible")

    currency = si.currency
    annual = p.frequency is not None
    lines = s.annual if annual else s.scenario
    resolved = p.resolved
    term_inputs = [resolved[name] for name in p.terms.values()]

    def reads(cs: Iterable[_Component]) -> list[Resolved]:
        return [resolved[name] for c in cs if c.estimated for name in c.reads.values()]

    def summarise(vector, inputs, *, per_year: bool = annual) -> dict:
        return _block(vector, currency=currency, severe=severe, annual=per_year, inputs=inputs)

    def yearly(vector: np.ndarray) -> np.ndarray:
        return sim.compound_annual(s.counts, vector) if annual else vector

    freq_inputs = [p.frequency] if p.frequency is not None else []
    events_record = []
    for event_index, (event, line) in enumerate(zip(si.events, s.events, strict=True)):
        mine = [c for c in p.components if c.event == event_index]
        cash = [c for c in mine if c.cash]
        market = [c for c in mine if not c.cash and c.estimated]
        cash_inputs = reads(cash) + freq_inputs
        unknown = [c.component.component_id for c in mine if not c.estimated]
        component_records = []
        for c in mine:
            index = p.components.index(c)
            component_records.append(
                {
                    "component_id": c.component.component_id,
                    "family": c.component.family,
                    "cash": c.cash,
                    "formula": [c.component.formula.formula_id, c.component.formula.version],
                    "status": c.component.status,
                    "evaluated_by": c.evaluated_by,
                    "reads": dict(sorted(c.reads.items())),
                    "summary": summarise(yearly(s.components[index]), reads([c]) + freq_inputs)
                    if c.estimated
                    else None,
                    "unknown": None
                    if c.estimated
                    else {"reason": c.component.unknown_reason, "inputs": list(c.component.missing)},
                }
            )
        events_record.append(
            {
                "event_key": event.loss_event_id,
                GROSS_CASH: summarise(yearly(line[GROSS_CASH]), cash_inputs),
                RETAINED_CASH: None
                if line[RETAINED_CASH] is None
                else summarise(yearly(line[RETAINED_CASH]), cash_inputs + term_inputs),
                MARKET_VALUE_LINE: None
                if not market
                else {
                    **summarise(yearly(line[MARKET_VALUE_LINE]), reads(market) + freq_inputs),
                    "never_added_to_cash": True,
                },
                "complete": not [c for c in cash if not c.estimated],
                "unknown_components": unknown,
                "insurance": None if si.policy is None else "applied to this event, once per occurrence",
                "components": component_records,
            }
        )
        check_time(f"summary {event.loss_event_id}")

    all_cash = reads([c for c in p.components if c.cash]) + freq_inputs
    all_market = [c for c in p.components if not c.cash and c.estimated]
    scenario_record = {
        "headline": RETAINED_CASH if si.policy is not None else GROSS_CASH,
        GROSS_CASH: summarise(lines[GROSS_CASH], all_cash),
        RETAINED_CASH: None if si.policy is None else summarise(lines[RETAINED_CASH], all_cash + term_inputs),
        MARKET_VALUE_LINE: None
        if not all_market
        else {**summarise(lines[MARKET_VALUE_LINE], reads(all_market) + freq_inputs), "never_added_to_cash": True},
        "complete": all(not (c.cash and not c.estimated) for c in p.components),
        "unknown_components": [
            f"{si.events[c.event].loss_event_id}/{c.component.component_id}" for c in p.components if not c.estimated
        ],
        "aggregate_limit_exceeded_share": _limit_share(p, s),
        "per_occurrence": None,
    }
    if annual and s.occurrences >= sim.MIN_DRAWS:
        scenario_record["per_occurrence"] = {
            GROSS_CASH: summarise(s.scenario[GROSS_CASH], reads([c for c in p.components if c.cash]), per_year=False),
            RETAINED_CASH: None
            if si.policy is None
            else summarise(
                s.scenario[RETAINED_CASH], reads([c for c in p.components if c.cash]) + term_inputs, per_year=False
            ),
        }
    check_time("summary")

    record = {
        "schema": SCHEMA,
        "engine_version": ENGINE_VERSION,
        "scenario_id": si.scenario_id,
        "seed": str(seed),
        "simulations": draws,
        "reporting_currency": currency,
        "basis": ANNUAL_BASIS if annual else PER_OCCURRENCE_BASIS,
        "occurrences": {
            "total": s.occurrences,
            "statement": COMPOUND if annual else ONE_OCCURRENCE,
        },
        "frequency": None
        if p.frequency is None
        else {"parameter": p.frequency.name, "distribution": p.frequency.distribution.record()},
        "severe_percentile": decimal_text(severe),
        "confidence_level": decimal_text(sim.CONFIDENCE_LEVEL),
        "scenario": scenario_record,
        "events": events_record,
        "parameters": {name: resolved[name].record() for name in sorted(resolved)},
        "expert_parameters": sorted(name for name, r in resolved.items() if r.expert),
        "versions": inputs["versions"],
        "input_digest": input_digest,
        "outcomes_sha256": digest_of_outcomes,
    }
    vectors = {label: _readonly(vector) for label, vector in ordered}
    return ScenarioSimulation(
        record=MappingProxyType(record),
        digest=digest_of(record),
        input_digest=input_digest,
        inputs=MappingProxyType(inputs),
        vectors=MappingProxyType(vectors),
    )


def _readonly(vector: np.ndarray) -> np.ndarray:
    vector.flags.writeable = False
    return vector


def _limit_share(p: _Plan, s: _Sample) -> str | None:
    """The share of draws (of years, in a compound run) whose recoveries, summed
    across the scenario's events, exceed the policy's limit: step 4 reads the
    limit per event, so where this is above zero the retained loss may be
    understated (spec, section 25.4)."""
    if p.si.policy is None or s.limit is None:
        return None  # in a compound run, a limit drawn per occurrence has no one value a year
    recoveries = s.annual["recovery"] if s.counts is not None else s.scenario["recovery"]
    exceeded = int(np.count_nonzero(recoveries > s.limit))
    return decimal_text(Decimal(exceeded) / Decimal(recoveries.size))


def no_float(value, path: str = "record") -> None:
    """Refuse a float anywhere in a record: every number is text or an int."""
    if isinstance(value, float):
        raise sim.InvariantBroken(f"{path} is a float")
    if isinstance(value, Mapping):
        for key, item in value.items():
            no_float(item, f"{path}.{key}")
    elif isinstance(value, (list, tuple)):
        for index, item in enumerate(value):
            no_float(item, f"{path}[{index}]")


def canonical_json(document: Mapping) -> str:
    """7a's canonical JSON of ``document``, as text."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


__all__ = [
    "ENGINE_VERSION",
    "FREQUENCY_PARAMETER",
    "NATIVE_PARAMETERS",
    "PER_OCCURRENCE",
    "REFUSALS",
    "RULE_VERSION",
    "SCHEMA",
    "SHARED",
    "STREAM_DOMAIN",
    "VARIATION_VERSION",
    "Resolved",
    "ScenarioInput",
    "ScenarioSimulation",
    "ScenarioSimulationRefused",
    "StatedDistribution",
    "build",
    "canonical_inputs",
    "check_stated",
    "digest_of",
    "no_float",
    "parse_stated",
    "plan",
    "resolve",
    "resolve_frequency",
    "run",
    "stream_name",
    "versions",
]
