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
  when the distribution fits the parameter's unit and holds its own figures
  (:func:`check_fits_range`, ``distribution_contradicts_range`` otherwise): a
  continuous one from both sides (its base between its P5 and P95, its low and
  high inside its support, its median between them, and at least
  :data:`RANGE_MASS_FLOOR` of its mass between them), and only on a range
  (``distribution_on_fixed_row``), a count on any row but the frequency included;
  the frequency, whose row's figures are values of its RATE, by the rate its count
  implies (its mean between the low and the high, exactly; the implied rate's median
  between them and at least :data:`RANGE_MASS_FLOOR` of it between them), a fixed
  rate only as a Poisson of that rate. One that states none
  draws from a point mass where its low, base and high are one figure, and from
  PERT(low, base, high) where they are a range and its source is an
  ``EXPERT_ESTIMATE``: the only source step 7a's rule lets an expert range stand
  for. Any other range with no distribution is refused
  (``no_admissible_distribution``), with the reason. A parameter derived across
  several effects' attributes (the scenario builder's larger loss) draws each of
  them by this rule and takes, per draw, the one giving the larger loss.
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
- **What is shared and what varies** (:data:`VARIATION_VERSION`). Every
  parameter is drawn once per simulated year and is the same for every
  occurrence of that year: a range is uncertainty about what the figure IS. A
  parameter named in ``per_occurrence`` is drawn afresh for each occurrence
  instead, an explicit option that enters the input digest. Without a frequency
  the two coincide.
- **Exact where nothing is uncertain.** A component whose every input is a point
  mass is computed once, by its Decimal formula (the source of truth); an event
  whose every component is so (and its policy's terms point masses) has its lines
  from step 4's Decimal ``assess``, and a scenario of such events their Decimal
  sums. Each value, as the nearest binary64, is the same in every draw, and its
  summary is the Decimal value itself, so such a run reproduces step 4 to the last
  digit.
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
import math
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field, replace
from decimal import Decimal
from fractions import Fraction
from types import MappingProxyType

import numpy as np

from . import distributions as dist
from . import simulation as sim
from . import twins as tw
from .formulas import COMPONENT_FAMILIES, ESTIMATED, MARKET_VALUE, Direction, LossComponent
from .loss import NEVER_COVERED, InsurancePolicy, LossEvent, assess
from .money import Money, MoneyRefused, check_reporting_currency, decimal_text, parse_decimal
from .parameters import POINTS, Parameter, ParameterRefused, Point, Unit
from .provenance import SourceType
from .taxonomy import LossFamily

#: The result's schema.
SCHEMA = "mythos.economics.scenario-simulation/v1"
#: The canonical inputs' schema: what the input digest is taken over.
INPUTS_SCHEMA = "mythos.economics.scenario-simulation-inputs/v1"
#: The version of this wiring: the aggregation order, the insurance step, the
#: constant components, the record. A change that alters a figure is a new one.
ENGINE_VERSION = 2
#: A stated distribution holds its parameter's own figures: the base between
#: these percentiles of it, and the low and the high inside the closure of its
#: support (spec, section 25.1). An owner decision (section 25.10).
RANGE_FIT_PERCENTILES = (Decimal(5), Decimal(95))
#: ...and a continuous one from both sides: its median between the low and the
#: high, and at least this share of its mass between them, both included (spec,
#: section 25.1; the lead's call on decision 9 of section 25.10, which the owner
#: may change). One constant: the owner's change is one line, and a new input
#: digest (:func:`limits`). The frequency's count is not held to it, but the rate
#: its count implies is: its row's figures are values of its rate (decision 12).
RANGE_MASS_FLOOR = Decimal("0.5")
#: The parameter-to-distribution rule (:func:`resolve`). v3 (step 6): a stated
#: distribution is held to its row from both sides and only on a range, a count on
#: any row but the frequency included; the frequency by the rate its count implies.
RULE_VERSION = "mythos.economics.parameter-distribution/v3"
RULE = (
    "a stated distribution of step 7a's catalogue, where it fits the parameter's unit and holds its figures: from "
    "both sides (the base between its P5 and P95, the low and the high inside its support, its median between the "
    f"low and the high, and at least {RANGE_MASS_FLOOR} of its mass between them), stated on a range (low below "
    "high), a count on any row but the frequency included; the frequency, whose low, base and high are values of its "
    "rate, by the rate its count implies (a Poisson's rate; a negative binomial's Gamma(size, (1 - p) / p); a "
    "zero-inflated Poisson's 0 with probability pi, else its rate): its exact mean between the low and the high, its "
    "low and high inside its support, its base below the count after its P95 and at or above its P5, the implied "
    f"rate's median between the low and the high and at least {RANGE_MASS_FLOOR} of it between them, and on a fixed "
    "rate (low = base = high) only a count whose implied rate is that point; otherwise a point mass where low = base "
    "= high; otherwise PERT(low, base, high), weight 4, where the source is EXPERT_ESTIMATE; otherwise refused "
    "(no_admissible_distribution). A parameter derived across several parameters draws each by this rule and takes, "
    "per draw, the one giving the larger loss in the direction of the inputs that read it"
)
#: Which parameters are drawn once per simulated year and which per occurrence.
VARIATION_VERSION = "mythos.economics.variation/v2"
#: Hashed before a parameter's name to give its stream's name.
STREAM_DOMAIN = "mythos.economics.parameter-stream/v1"
#: The name of a scenario's frequency parameter: events a year.
FREQUENCY_PARAMETER = "frequency"

#: A residual run (MVP step 13; spec, section 28): the scenario run again with ONE
#: remediation option's control effect, on the SAME seed and the SAME parameter
#: streams, so the current and the residual run differ only by the control effect.
REMEDIATION_SCHEMA = "mythos.economics.remediation-run/v1"
REMEDIATION_VERSION = 1
#: Hashed before a reduction's role to give its own stream's name: never a
#: parameter's stream, so drawing the control effect moves no parameter's draws.
REMEDIATION_STREAM_DOMAIN = "mythos.economics.remediation-stream/v1"
#: The two reductions' names (``assurance.economics.engine.remediation`` names them
#: alike), and the role of the stream deciding which occurrences the control stops.
FREQUENCY_REDUCTION = "remediation.frequency_reduction"
MAGNITUDE_REDUCTION = "remediation.magnitude_reduction"
REMEDIATION_KEPT = "remediation.kept"
#: Vectors a residual run holds beside a run's own: the factor each reduced
#: component is multiplied by, the uniform draws deciding what is kept, and one
#: reduction's draws, one per occurrence.
REMEDIATION_TEMPORARIES = 3
REMEDIATION_RULE = (
    "the current run's seed and parameter streams, unchanged; r_f and r_m each drawn by the parameter-to-distribution "
    "rule (a point mass for a fixed figure, PERT for an expert range, a stated distribution), once per simulated year "
    "(per draw without a frequency), each from its own stream; each occurrence of a component the option acts on is "
    "kept where a uniform draw from its own stream is below 1 - r_f (its year's r_f), so the expected count of "
    "occurrences it suffers is the frequency times 1 - r_f, and is multiplied by 1 - r_m; insurance applies after, to "
    "what remains; a component the option does not act on is the current run's, draw for draw"
)

SHARED = "shared"
PER_OCCURRENCE = "per_occurrence"
VARIATIONS = (SHARED, PER_OCCURRENCE)

#: How a parameter's distribution was decided.
RULE_STATED = "stated"
RULE_POINT_MASS = "point_mass"
RULE_PERT_DEFAULT = "pert_default"
RULE_DERIVED = "derived_larger_loss"

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
        "distribution_contradicts_range": (
            "a stated distribution holds its parameter's own figures from both sides: the base between its P5 and "
            "P95, the low and the high inside its support, its median between the low and the high, and at least "
            f"{RANGE_MASS_FLOOR} of its mass between them; the frequency, whose figures are values of its rate, by the "
            "rate its count implies: its exact mean between the low and the high, the low and the high inside its "
            "support, the base at or above the count's P5 and below the count after its P95, and the implied rate's "
            f"median between the low and the high and at least {RANGE_MASS_FLOOR} of it between them. A distribution "
            "that does not is a conflict, surfaced, and the refusal names the test it failed"
        ),
        "distribution_on_fixed_row": (
            "a parameter whose low, base and high are one figure is a point mass and states no distribution: one "
            "stated on it contradicts it (a fixed frequency is a known rate, and may state only a Poisson of that "
            "rate, a count whose implied rate is that point)"
        ),
        "derived_malformed": (
            "a derived parameter is one a component reads, in one direction, taken across at least two parameters "
            "of its unit (none derived, none read by anything else), its low, base and high each the larger loss of "
            "theirs; it states no distribution of its own"
        ),
        "distribution_not_for_unit": (
            "a distribution draws only what its parameter's unit holds: a ratio from 0 to 1 (a rate, or an "
            "expert range inside [0, 1]); a count from a count, severity or expert distribution; anything else "
            "from a severity or expert distribution at or above zero"
        ),
        "frequency_distribution_missing": "a scenario's frequency parameter states a count distribution",
        "frequency_not_a_count": "a frequency is a count distribution (Poisson, negative binomial, zero-inflated Poisson)",
        "twin_missing": "a formula a simulation evaluates has a vectorised twin: none is approximated",
        "events_missing": "a scenario holds at least one loss event",
        "variation_unrecognised": "a parameter drawn per occurrence is one a component or the policy reads",
        "out_of_range": "a component's, event's or year's loss too large to hold as a binary64 float",
        "time_over_budget": "the run took longer than its time budget, and was stopped between two stages",
        "remediation_malformed": (
            "a residual run's remediation names its option and the option's digest, states a frequency reduction, a "
            "magnitude reduction or both, each a ratio named remediation.frequency_reduction or "
            "remediation.magnitude_reduction, and acts on every component or on the loss families or components it "
            "names, one or the other"
        ),
        "remediation_needs_frequency": (
            "a frequency reduction reduces the scenario's frequency: a scenario that states none is run per "
            "occurrence, each given it happens, and has no frequency to reduce"
        ),
        "remediation_target_unknown": "a component the control effect names is not one of the scenario's",
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


def support(distribution: dist.Distribution) -> tuple[float, float]:
    """The closure of ``distribution``'s support: the least and the greatest value
    its draws can come near (an upper end of infinity where it has none)."""
    if isinstance(distribution, dist.Spliced):
        return 0.0, support(distribution.tail)[1]
    if isinstance(distribution, dist.GeneralizedPareto):
        upper = distribution.threshold + distribution.scale / -distribution.shape if distribution.shape < 0.0 else math.inf
        return distribution.threshold, upper
    kind = type(distribution).KIND
    if kind == dist.EXPERT:
        return distribution.minimum, distribution.maximum
    if kind == dist.RATE:
        return 0.0, 1.0
    return 0.0, math.inf  # a count, a lognormal or a gamma


#: The tests :func:`check_fits_range` holds a stated distribution to, in the order it
#: applies them, a count on any row but the frequency included; a refusal names the
#: first one failed.
RANGE_TESTS = ("support", "base", "median", "mass")
#: The tests it holds the frequency to, in order. The frequency's low, base and high
#: are values of its RATE (the annual rate its formulas multiply), not of the count a
#: year draws, so the count's spread is not compared with them: the RATE its count
#: implies is (:func:`implied_rate`), with the count's exact mean and round 2's base
#: rule beside.
FREQUENCY_RANGE_TESTS = ("support", "rate", "base", "rate_median", "rate_mass")


def mass_between(distribution: dist.Distribution, low: float, high: float) -> float:
    """P(low <= X <= high), both ends included. A count's mass is that of the whole
    numbers from the first at or above ``low`` to the last at or below ``high``."""
    if type(distribution).DISCRETE:
        below = distribution.cdf(math.ceil(low) - 1.0) if low > 0.0 else 0.0
    else:
        below = distribution.cdf(low)
    return max(0.0, distribution.cdf(high) - below)


def _text(value) -> str:
    """A figure a refusal compares, in full: its shortest round-trip spelling
    (``dist.float_text``), so 0.49995 is never printed as 0.5."""
    if value is None:
        return "undefined"
    if isinstance(value, Fraction):
        value = float(value)
    if math.isnan(value):
        return "undefined"
    if math.isinf(value):
        return "infinite" if value > 0 else "-infinite"
    return dist.float_text(value)


def _count_params(distribution: dist.Distribution, stated: StatedDistribution | None) -> dict[str, Fraction]:
    """A count's native parameters, exactly: as stated (decimal strings, read exactly),
    or, where none is given, each binary64 one's shortest decimal spelling."""
    if stated is not None:
        return {name: Fraction(value) for name, value in stated.params.items()}
    return {name: Fraction(dist.float_decimal(value)) for name, value in distribution.params().items()}


def exact_count_mean(distribution: dist.Distribution, stated: StatedDistribution | None = None) -> Fraction | None:
    """A count's mean, exactly, from its stated parameters where the catalogue has a
    closed form: a Poisson's rate; a negative binomial's size (1 - p) / p; a
    zero-inflated Poisson's (1 - pi) rate. ``None`` for any other distribution."""
    params = _count_params(distribution, stated)
    kind = type(distribution)
    if kind is dist.Poisson:
        return params["rate"]
    if kind is dist.NegativeBinomial:
        return params["size"] * (1 - params["probability"]) / params["probability"]
    if kind is dist.ZeroInflatedPoisson:
        return (1 - params["zero_inflation"]) * params["rate"]
    return None


@dataclass(frozen=True)
class ImpliedRate:
    """The annual RATE a frequency's count distribution implies, which its row's low,
    base and high are values of: a count is a Poisson GIVEN its rate, and what the
    catalogue's counts add to a Poisson is uncertainty about that rate.

    - a Poisson(lambda): the rate is lambda, a point (``point``);
    - a negative binomial(size r, probability p), numpy's failures before the r-th
      success: a Poisson whose rate is Gamma(shape r, scale (1 - p) / p) (``gamma``),
      the Gamma-Poisson mixture: its mean r (1 - p) / p and variance r (1 - p) / p^2
      are the negative binomial's;
    - a zero-inflated Poisson(pi, lambda): the rate is 0 with probability pi and
      lambda otherwise (``zero`` and ``point``), a point where pi is 0.

    The point and the zero's weight are exact (from the stated parameters); a Gamma is
    the run's binary64."""

    point: Fraction | None = None
    zero: Fraction = Fraction(0)
    gamma: dist.Distribution | None = None

    @property
    def is_point(self) -> bool:
        """True where the rate is known exactly: a Poisson, or no zero inflation."""
        return self.gamma is None and self.zero == 0

    def describe(self) -> str:
        if self.gamma is not None:
            return f"Gamma(shape {_text(self.gamma.shape)}, scale {_text(self.gamma.scale)})"
        if self.zero == 0:
            return f"the point {_text(self.point)}"
        return f"0 with probability {_text(self.zero)}, else {_text(self.point)}"

    def median(self) -> Fraction | float:
        """The smallest rate r with P(R <= r) >= 1/2."""
        if self.gamma is not None:
            return self.gamma.ppf(0.5)
        return Fraction(0) if self.zero >= Fraction(1, 2) else self.point

    def median_between(self, low: Decimal, high: Decimal) -> bool:
        median = self.median()
        if isinstance(median, Fraction):
            return Fraction(low) <= median <= Fraction(high)
        return float(low) <= median <= float(high)

    def mass_between(self, low: Decimal, high: Decimal) -> Fraction | float:
        """P(low <= R <= high), both ends included: exact for a point or a zero and a
        point, the Gamma's binary64 otherwise."""
        if self.gamma is not None:
            return mass_between(self.gamma, float(low), float(high))
        lowest, highest = Fraction(low), Fraction(high)
        inside = Fraction(0)
        if self.zero and lowest <= 0 <= highest:
            inside += self.zero
        if lowest <= self.point <= highest:
            inside += 1 - self.zero
        return inside

    def holds_floor(self, mass: Fraction | float) -> bool:
        if isinstance(mass, Fraction):
            return mass >= Fraction(RANGE_MASS_FLOOR)
        return mass >= float(RANGE_MASS_FLOOR)


def implied_rate(distribution: dist.Distribution, stated: StatedDistribution | None = None) -> ImpliedRate:
    """The rate ``distribution``, a count of the catalogue, implies: see
    :class:`ImpliedRate`. Refused (``frequency_not_a_count``) for any other."""
    params = _count_params(distribution, stated)
    kind = type(distribution)
    if kind is dist.Poisson:
        return ImpliedRate(point=params["rate"])
    if kind is dist.ZeroInflatedPoisson:
        return ImpliedRate(point=params["rate"], zero=params["zero_inflation"])
    if kind is dist.NegativeBinomial:
        p = params["probability"]
        return ImpliedRate(gamma=dist.Gamma(float(params["size"]), float((1 - p) / p)))
    raise ScenarioSimulationRefused("frequency_not_a_count", type(distribution).ID)


def check_fits_range(
    distribution: dist.Distribution,
    parameter: Parameter,
    *,
    frequency: bool = False,
    stated: StatedDistribution | None = None,
) -> None:
    """Refuse a stated distribution that does not hold ``parameter``'s own figures
    (``distribution_contradicts_range``, naming the test it failed, and printing each
    figure it compared in full).

    Any stated distribution -- a severity, a rate, an expert range, or a count on any
    row but the frequency (an observed repeat count, a number of affected customers:
    the count itself) -- is held to them from both sides, :data:`RANGE_TESTS`, each
    figure compared as the binary64 the run would draw:

    - ``support``: its low and high inside the closure of its support;
    - ``base``: its base between the distribution's :data:`RANGE_FIT_PERCENTILES`;
    - ``median``: its P50 between its low and its high, both included;
    - ``mass``: at least :data:`RANGE_MASS_FLOOR` of its mass between its low and
      its high, both included (:func:`mass_between`).

    The first two alone were one-sided: a gamma whose median lay far below the low
    held a base below its P95 and a low inside its support. A parameter whose low,
    base and high are one figure is a point mass and states no distribution
    (``distribution_on_fixed_row``).

    The ``frequency`` (:func:`resolve_frequency`'s, the parameter named
    :data:`FREQUENCY_PARAMETER`) is another matter: its row's low, base and high are
    values of its RATE, which the formulas multiply, and its count distribution says
    how the count varies from year to year GIVEN the rate, and how uncertain the rate
    is (:class:`ImpliedRate`). The count's yearly spread is not compared with the row;
    the rate is. It is held to :data:`FREQUENCY_RANGE_TESTS`:

    - ``support``: as above;
    - ``rate``: the count's mean between the low and the high, compared exactly, the
      mean from the stated parameters (:func:`exact_count_mean`);
    - ``base``: its base at or above the count's P5 and below the count after its P95
      (round 2's rule: it refuses a base far from the mean while the mean is in
      range, as 0 / 1 / 2 stating Poisson(0.02));
    - ``rate_median``: the implied rate's median between the low and the high;
    - ``rate_mass``: at least :data:`RANGE_MASS_FLOOR` of the implied rate between
      them.

    A fixed frequency (low = base = high) is a known rate: it may state only a count
    whose implied rate is that point, a Poisson of that rate, and the rate test asks
    that its mean be exactly that figure; a count whose rate is uncertain contradicts
    it (``distribution_on_fixed_row``). A conflict is surfaced, never resolved by
    silently taking one side."""
    low, base, high = (_amount(parameter.at(point)) for point in POINTS)
    name = type(distribution).ID
    as_rate = frequency and bool(type(distribution).DISCRETE)
    implied = implied_rate(distribution, stated) if as_rate else None
    if low == high and (implied is None or not implied.is_point):
        if implied is None:
            detail = f"{parameter.name} is {low} / {base} / {high}, one figure: a point mass, and it states a {name}"
        else:
            detail = (
                f"{parameter.name} is {low} / {base} / {high}, one rate: a known rate, and its {name} states the rate "
                f"uncertain ({implied.describe()}); a fixed rate states a poisson of that rate"
            )
        raise ScenarioSimulationRefused("distribution_on_fixed_row", detail)
    lowest, b, highest = float(low), float(base), float(high)
    lower, upper = support(distribution)
    p_low, p_high = (distribution.ppf(float(q / 100)) for q in RANGE_FIT_PERCENTILES)
    inside_support = lower <= lowest and highest <= upper
    if implied is not None:
        mean = exact_count_mean(distribution, stated)
        if mean is None:  # no closed form: the catalogue's binary64 mean, finite or refused
            mean = distribution.mean
            rate_held = mean is not None and math.isfinite(mean) and lowest <= mean <= highest
        else:
            rate_held = Fraction(low) <= mean <= Fraction(high)
        rate_median = implied.median()
        rate_mass = implied.mass_between(low, high)
        held = {
            "support": inside_support,
            "rate": rate_held,
            "base": p_low <= b < p_high + 1.0,
            "rate_median": implied.median_between(low, high),
            "rate_mass": implied.holds_floor(rate_mass),
        }
        failed = next((test for test in FREQUENCY_RANGE_TESTS if not held[test]), None)
        if failed is None:
            return
        raise ScenarioSimulationRefused(
            "distribution_contradicts_range",
            f"{parameter.name} is {low} / {base} / {high}, values of its rate; its {name} fails the {failed} test: "
            f"support [{_text(lower)}, {_text(upper)}], mean {_text(mean)}, P5 to P95 [{_text(p_low)}, "
            f"{_text(p_high)}], its rate {implied.describe()}: P50 {_text(rate_median)}, P(low <= rate <= high) "
            f"{_text(rate_mass)} (at least {RANGE_MASS_FLOOR})",
        )
    median = distribution.ppf(0.5)
    mass = mass_between(distribution, lowest, highest)
    held = {
        "support": inside_support,
        "base": p_low <= b <= p_high,
        "median": lowest <= median <= highest,
        "mass": mass >= float(RANGE_MASS_FLOOR),
    }
    failed = next((test for test in RANGE_TESTS if not held[test]), None)
    if failed is None:
        return
    raise ScenarioSimulationRefused(
        "distribution_contradicts_range",
        f"{parameter.name} is {low} / {base} / {high}; its {name} fails the {failed} test: support "
        f"[{_text(lower)}, {_text(upper)}], P5 to P95 [{_text(p_low)}, {_text(p_high)}], P50 {_text(median)}, "
        f"P(low <= X <= high) {_text(mass)} (at least {RANGE_MASS_FLOOR})",
    )


def check_stated(stated: StatedDistribution, parameter: Parameter) -> dist.Distribution:
    """The distribution ``stated`` builds for ``parameter``, refused unless it fits
    the parameter's unit and holds its figures from both sides
    (:func:`check_fits_range`). The frequency's is checked by
    :func:`resolve_frequency`, by the rate its count implies."""
    distribution = build(stated, parameter.source_type)
    if parameter.name != FREQUENCY_PARAMETER and not _support_fits(distribution, parameter.unit):
        raise ScenarioSimulationRefused(
            "distribution_not_for_unit", f"{parameter.name} is {parameter.unit.value}; {stated.distribution_id} does not fit it"
        )
    check_fits_range(distribution, parameter)
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
    """A parameter and the distribution the rule gave it. A point mass draws
    nothing: its exact value is ``point``. A derived parameter (``contributors``)
    draws each contributor by its own rule and takes, per draw, the larger loss in
    its ``direction``; it is a point mass where every contributor is."""

    parameter: Parameter
    rule: str
    variation: str
    distribution: dist.Distribution | None = None
    point: Decimal | None = None
    contributors: tuple[Resolved, ...] = ()
    direction: str | None = None

    @property
    def name(self) -> str:
        return self.parameter.name

    @property
    def stream(self) -> str:
        return stream_name(self.parameter.name)

    @property
    def drawn(self) -> bool:
        """True unless a point mass: the run draws it."""
        return self.point is None

    @property
    def expert(self) -> bool:
        return self.distribution is not None and bool(type(self.distribution).EXPERT)

    @property
    def mean_finite(self) -> bool:
        if self.contributors:
            return all(c.mean_finite for c in self.contributors)
        return self.distribution is None or self.distribution.mean is not None

    @property
    def variance_finite(self) -> bool:
        if self.contributors:
            return all(c.variance_finite for c in self.contributors)
        return self.distribution is None or self.distribution.variance is not None

    def distribution_record(self) -> dict | None:
        if self.point is not None:
            return {"id": POINT_MASS, "version": POINT_MASS_VERSION, "value": decimal_text(self.point)}
        if self.distribution is None:
            return None  # derived: its contributors' draws, each recorded
        return self.distribution.record()

    def record(self) -> dict:
        record = {
            "rule": self.rule,
            "variation": self.variation,
            "stream": self.stream if self.distribution is not None else None,
            "distribution": self.distribution_record(),
        }
        if self.contributors:
            record["direction"] = self.direction
            record["contributors"] = {c.name: c.record() for c in self.contributors}
        return record


def resolve(parameter: Parameter, stated: StatedDistribution | None, *, variation: str = SHARED) -> Resolved:
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


def _larger(direction: Direction) -> Callable:
    return max if direction is Direction.INCREASES else min


def resolve_derived(
    parameter: Parameter,
    contributors: Iterable[Parameter],
    stated: Mapping[str, StatedDistribution],
    *,
    direction: Direction,
    variation: str = SHARED,
) -> Resolved:
    """A parameter derived across ``contributors`` (the scenario builder's larger
    loss of an event's attribute across its effects, spec section 24.5): each
    contributor resolved by its own rule (stated, point mass, PERT for an expert,
    or refused), and per draw the value giving the larger loss in ``direction``,
    as the builder takes it per point. A refused contributor refuses the merge,
    naming it. Where every contributor is a point mass, so is the merge."""
    contributors = tuple(contributors)
    name = parameter.name
    if name in stated:
        raise ScenarioSimulationRefused("derived_malformed", f"{name} states a distribution of its own")
    if len(contributors) < 2 or len({c.name for c in contributors}) != len(contributors):
        raise ScenarioSimulationRefused("derived_malformed", f"{name} is taken across {len(contributors)} parameters")
    larger = _larger(direction)
    for point in POINTS:
        figures = [_amount(c.at(point)) for c in contributors]
        if any(c.unit is not parameter.unit for c in contributors) or _amount(parameter.at(point)) != larger(figures):
            raise ScenarioSimulationRefused(
                "derived_malformed", f"{name} at {point.value} is not the larger loss of {[c.name for c in contributors]}"
            )
    resolved = []
    for contributor in contributors:
        try:
            resolved.append(resolve(contributor, stated.get(contributor.name), variation=variation))
        except (ScenarioSimulationRefused, dist.DistributionRefused) as refused:
            raise type(refused)(refused.code, f"{name} is derived from {contributor.name}: {refused.detail}") from None
    point = None
    if not any(r.drawn for r in resolved):
        point = larger(r.point for r in resolved)
    return Resolved(
        parameter, RULE_DERIVED, variation, point=point, contributors=tuple(resolved), direction=direction.value
    )


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
    check_fits_range(distribution, parameter, frequency=True, stated=stated)
    return Resolved(parameter, RULE_STATED, SHARED, distribution=distribution)


# --------------------------------------------------------------- the input


@dataclass(frozen=True)
class Remediation:
    """One remediation option's control effect, for a residual run (spec, section
    28): the option's id and digest, its frequency reduction ``r_f`` and magnitude
    reduction ``r_m`` (each a ratio parameter, or ``None``), the distribution each
    states (by its name), and what it acts on: every component (both ``None``), the
    loss families named, or the components named (``<event key>/<component key>``)."""

    option_id: str
    option_digest: str
    frequency_reduction: Parameter | None = None
    magnitude_reduction: Parameter | None = None
    stated: Mapping[str, StatedDistribution] = field(default_factory=dict)
    families: tuple[str, ...] | None = None
    components: tuple[str, ...] | None = None

    def reductions(self) -> list[tuple[str, Parameter]]:
        return [
            (name, parameter)
            for name, parameter in ((FREQUENCY_REDUCTION, self.frequency_reduction),
                                    (MAGNITUDE_REDUCTION, self.magnitude_reduction))
            if parameter is not None
        ]


def remediation_stream(role: str) -> str:
    """The step-7a stream a residual run draws ``role`` from: ``r`` and the first 40
    hex digits of the SHA-256 of :data:`REMEDIATION_STREAM_DOMAIN`, a zero byte and
    the role's UTF-8. Never a parameter's stream (``p...``) or the frequency's."""
    digest = hashlib.sha256(REMEDIATION_STREAM_DOMAIN.encode("ascii") + b"\x00" + role.encode("utf-8")).hexdigest()
    return "r" + digest[:40]


@dataclass(frozen=True)
class ScenarioInput:
    """What one run reads: the scenario's events (step 4's, each component
    computed from the parameters it cites), the policy their insurance applies,
    each parameter's stated distribution by name, the names drawn afresh for each
    occurrence (every other parameter is drawn once per simulated year), the
    frequency parameter, if any, and each derived parameter's contributors, by
    the derived parameter's name. A residual run also reads one remediation
    option's control effect (``remediation``; ``None`` for the scenario as it is)."""

    scenario_id: str | None
    currency: str
    events: tuple[LossEvent, ...]
    policy: InsurancePolicy | None = None
    stated: Mapping[str, StatedDistribution] = field(default_factory=dict)
    per_occurrence: frozenset[str] = frozenset()
    frequency: Parameter | None = None
    derived: Mapping[str, tuple[Parameter, ...]] = field(default_factory=dict)
    remediation: Remediation | None = None


def _policy_terms(policy: InsurancePolicy | None) -> list[tuple[str, Parameter]]:
    if policy is None:
        return []
    terms = [("deductible", policy.deductible), ("limit", policy.limit)]
    terms += [(f"sublimit:{family}", term) for family, term in sorted(policy.sublimits.items())]
    if policy.waiting_period_hours is not None:
        terms.append(("waiting_period_hours", policy.waiting_period_hours))
    return terms


def _named(si: ScenarioInput) -> dict[str, Parameter]:
    """Every parameter the scenario cites, its policy's terms, its frequency and
    each derived parameter's contributors, by name: one name is one parameter
    (``duplicate_id``)."""
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
    read = set(named)
    for name, contributors in sorted(dict(si.derived).items()):
        if name not in read or not isinstance(contributors, tuple):
            raise ScenarioSimulationRefused("derived_malformed", f"{name!r} is not a parameter the scenario reads")
        for contributor in contributors:
            if not isinstance(contributor, Parameter):
                raise ScenarioSimulationRefused("derived_malformed", f"{name} is taken across a {type(contributor).__name__}")
            if contributor.name in read:
                raise ScenarioSimulationRefused("derived_malformed", f"{contributor.name} is read beside {name}")
            add(contributor)
    return named


def _variation(si: ScenarioInput, name: str) -> str:
    """How ``name`` is drawn: per occurrence where the input names it (a derived
    parameter's contributors as it is), otherwise once per simulated year."""
    if name in si.per_occurrence:
        return PER_OCCURRENCE
    for derived, contributors in dict(si.derived).items():
        if derived in si.per_occurrence and any(c.name == name for c in contributors):
            return PER_OCCURRENCE
    return SHARED


def _reads(si: ScenarioInput) -> set[str]:
    """The names a component or the policy reads."""
    names = {cited.parameter.name for event in si.events for c in event.components for cited in c.inputs}
    return names | {term.name for _, term in _policy_terms(si.policy)}


def limits() -> dict:
    """Every limit that decides a refusal a run records: the values and events
    budgets, the largest sample and count mean, the generalized Pareto's shapes,
    a splice's body share, the largest standard exponential, and the range a
    stated distribution must hold (its percentiles and its mass floor). Part of
    the versions, so a changed limit is a new input digest: a refusal recorded
    under the old limit is never returned under the new."""
    return {
        "max_values": sim.MAX_VALUES,
        "max_events": sim.MAX_EVENTS,
        "max_sample": dist.MAX_SAMPLE,
        "max_count_mean": dist.float_text(dist.MAX_COUNT_MEAN),
        "gpd_shape": [dist.float_text(dist.GPD_SHAPE_MIN), dist.float_text(dist.GPD_SHAPE_MAX)],
        "splice_min_body_share": dist.float_text(dist.SPLICE_MIN_BODY_SHARE),
        "largest_exponential": dist.float_text(dist.LARGEST_EXPONENTIAL),
        "range_fit_percentiles": [decimal_text(q) for q in RANGE_FIT_PERCENTILES],
        "range_mass_floor": decimal_text(RANGE_MASS_FLOOR),
        # The values budget counts these with MAX_VALUES (``values_over_budget``),
        # and a splice's rounds decide its ``out_of_range``.
        "run_vectors": sim.RUN_VECTORS,
        "year_vectors": sim.YEAR_VECTORS,
        "insurance_temporaries": INSURANCE_TEMPORARIES,
        "summary_temporaries": SUMMARY_TEMPORARIES,
        "annual_lines": ANNUAL_LINES,
        "splice_max_rounds": dist.SPLICE_MAX_ROUNDS,
    }


def versions(si: ScenarioInput) -> dict:
    """Every version a run's figures depend on: this wiring's, the rule's, the
    twins', each formula's and each catalogue distribution's, the sampler's and
    numpy's, and every limit that decides a recorded refusal (:func:`limits`).
    They are part of the canonical inputs, so a change to any is a new input
    digest and a new stored result, never an old one returned."""
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
        "limits": limits(),
    }


def canonical_inputs(si: ScenarioInput, *, severe_percentile=sim.DEFAULT_SEVERE_PERCENTILE) -> dict:
    """The inputs a run reads, in canonical form, without the seed and the draws
    (they are stored beside the digest): every event and component with its
    formula and the parameter each input reads, every parameter with its values,
    source, evidence, STATED distribution and variation, each derived parameter's
    contributors, the policy, the frequency, the severe-but-plausible percentile,
    the rules and every version. It is computed before anything is resolved, so
    a refused run has a digest."""
    if not isinstance(si, ScenarioInput):
        raise TypeError(f"a ScenarioInput, not a {type(si).__name__}")
    percentile = sim.check_severe_percentile(severe_percentile)
    named = _named(si)
    unknown = sorted(set(si.per_occurrence) - _reads(si))
    if unknown:
        raise ScenarioSimulationRefused("variation_unrecognised", f"{unknown}")
    stated = dict(si.stated)
    for name, value in stated.items():
        if not isinstance(value, StatedDistribution):
            raise ScenarioSimulationRefused("distribution_malformed", f"{name}: a {type(value).__name__}")
    policy = si.policy
    document = {
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
                "variation": _variation(si, name),
            }
            for name, parameter in sorted(named.items())
        },
        "derived": {name: [c.name for c in contributors] for name, contributors in sorted(dict(si.derived).items())},
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
    if si.remediation is not None:
        # Only a residual run has this key: the scenario as it is keeps the inputs,
        # and so the input digest, it had before remediation existed, and a residual
        # run's inputs are exactly its current run's with this one key added.
        document["remediation"] = _remediation_inputs(si, named)
    return document


def _is_digest(value) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 71
        and value.startswith("sha256:")
        and all(ch in "0123456789abcdef" for ch in value[7:])
    )


def _remediation_inputs(si: ScenarioInput, named: Mapping[str, Parameter]) -> dict:
    """A residual run's remediation in canonical form: the option and its digest,
    each reduction with its figures, source, evidence and stated distribution, what
    it acts on, its streams and the rule. Refused (``remediation_malformed``) unless
    well formed, and ``duplicate_id`` where a reduction's name is a parameter's."""
    rem = si.remediation
    if not isinstance(rem, Remediation):
        raise ScenarioSimulationRefused("remediation_malformed", f"a {type(rem).__name__}")
    if not isinstance(rem.option_id, str) or not rem.option_id or not _is_digest(rem.option_digest):
        raise ScenarioSimulationRefused("remediation_malformed", "the option's id, and its digest (sha256: and 64 hex)")
    reductions = rem.reductions()
    if not reductions:
        raise ScenarioSimulationRefused("remediation_malformed", "it states no reduction")
    for name, parameter in reductions:
        if not isinstance(parameter, Parameter) or parameter.name != name or parameter.unit is not Unit.RATIO:
            raise ScenarioSimulationRefused("remediation_malformed", f"{name} is a ratio parameter named {name}")
        if name in named:
            raise ParameterRefused("duplicate_id", f"{name} is also a parameter of the scenario")
    stated = dict(rem.stated)
    if not set(stated) <= {name for name, _ in reductions} or not all(
        isinstance(value, StatedDistribution) for value in stated.values()
    ):
        raise ScenarioSimulationRefused("remediation_malformed", "a stated distribution names no reduction")
    if rem.families is not None and rem.components is not None:
        raise ScenarioSimulationRefused("remediation_malformed", "it acts on families or on components, not both")
    targets = rem.families if rem.families is not None else rem.components
    if targets is not None and (
        not targets
        or not all(isinstance(t, str) for t in targets)
        or len(set(targets)) != len(targets)
        or (rem.families is not None and not set(targets) <= COMPONENT_FAMILIES)
    ):
        raise ScenarioSimulationRefused("remediation_malformed", f"acts on {targets!r}")
    acts_on = None
    if rem.families is not None:
        acts_on = {"families": sorted(rem.families)}
    elif rem.components is not None:
        acts_on = {"components": sorted(rem.components)}
    return {
        "schema": REMEDIATION_SCHEMA,
        "version": REMEDIATION_VERSION,
        "option": rem.option_id,
        "option_digest": rem.option_digest,
        "reductions": {
            name: {**parameter.as_dict(), "distribution": stated[name].as_json() if name in stated else None}
            for name, parameter in reductions
        },
        "acts_on": acts_on,
        "stream_domain": REMEDIATION_STREAM_DOMAIN,
        "kept_stream": remediation_stream(REMEDIATION_KEPT),
        "temporaries": REMEDIATION_TEMPORARIES,
        "rule": REMEDIATION_RULE,
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
    exact: Decimal | None
    #: A residual run's control effect changes this component: each occurrence is
    #: multiplied by the reduction factor, so its summary is no longer the exact
    #: Decimal value even where its inputs are all point masses.
    reduced: bool = False

    @property
    def constant(self) -> float | None:
        """The exact value as the nearest binary64, the same in every draw."""
        return None if self.exact is None else float(self.exact)

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
        return BY_DECIMAL if self.exact is not None else BY_TWIN


#: The lines of an event or a scenario, each a vector of the sampled length.
LINES = (GROSS_CASH, MARKET_VALUE_LINE, "recovery", RETAINED_CASH)


@dataclass(frozen=True)
class _Plan:
    si: ScenarioInput
    components: tuple[_Component, ...]
    resolved: Mapping[str, Resolved]
    terms: Mapping[str, str]
    frequency: Resolved | None
    #: Each event's lines as step 4's Decimal ``assess`` gives them, where nothing
    #: the event reads is uncertain; ``None`` otherwise. The scenario's likewise.
    exact_events: tuple[Mapping[str, Decimal | None] | None, ...] = ()
    exact_scenario: Mapping[str, Decimal | None] | None = None
    #: A residual run's control effect, resolved; ``None`` for the scenario as it is.
    remediation: _RemedyPlan | None = None


@dataclass(frozen=True)
class _RemedyPlan:
    """A residual run's control effect as the run applies it: each reduction
    resolved by the parameter-to-distribution rule (``None`` where the option states
    none), whether it changes anything (a point mass at zero changes nothing), and
    the components it changes, by index."""

    remediation: Remediation
    frequency: Resolved | None
    magnitude: Resolved | None
    keeps: bool
    scales: bool
    reduced: frozenset[int]

    def resolved(self) -> list[Resolved]:
        return [r for r in (self.frequency, self.magnitude) if r is not None]


def _changes(r: Resolved | None) -> bool:
    """Whether a reduction changes a run: one that is drawn, or a point mass above zero."""
    return r is not None and (r.drawn or r.point != 0)


def _plan_remediation(si: ScenarioInput, components: list[_Component]) -> _RemedyPlan:
    """Resolve a residual run's reductions by the parameter-to-distribution rule and
    find the components its control effect acts on (every known component, or those
    of the families or keys it names). Refused where a frequency reduction meets a
    scenario with no frequency (``remediation_needs_frequency``), or a component it
    names is not the scenario's (``remediation_target_unknown``): recorded, as every
    refusal the inputs decide."""
    rem = si.remediation
    stated = dict(rem.stated)

    def resolved(name: str, parameter: Parameter | None) -> Resolved | None:
        return None if parameter is None else resolve(parameter, stated.get(name))

    frequency = resolved(FREQUENCY_REDUCTION, rem.frequency_reduction)
    magnitude = resolved(MAGNITUDE_REDUCTION, rem.magnitude_reduction)
    if frequency is not None and si.frequency is None:
        raise ScenarioSimulationRefused("remediation_needs_frequency", "the scenario states no frequency")
    keys = {f"{si.events[c.event].loss_event_id}/{c.component.component_id}": index
            for index, c in enumerate(components)}
    if rem.components is not None:
        unknown = sorted(set(rem.components) - set(keys))
        if unknown:
            raise ScenarioSimulationRefused("remediation_target_unknown", ", ".join(unknown))
        targets = {keys[name] for name in rem.components}
    elif rem.families is not None:
        targets = {index for index, c in enumerate(components) if c.component.family in rem.families}
    else:
        targets = set(range(len(components)))
    keeps, scales = _changes(frequency), _changes(magnitude)
    reduced = frozenset(i for i in targets if components[i].estimated) if keeps or scales else frozenset()
    return _RemedyPlan(rem, frequency, magnitude, keeps, scales, reduced)


def _exact(component: LossComponent, resolved: Mapping[str, Resolved]) -> Decimal | None:
    """A component whose every input is a point mass, computed once by its Decimal
    formula; ``None`` if any input is uncertain."""
    points = {}
    for cited in component.inputs:
        if resolved[cited.parameter.name].drawn:
            return None
        points[cited.input.name] = cited.parameter.base
    return component.formula.calculate(points).amount


def _exact_lines(event: LossEvent, policy, components: list[_Component], p_resolved, terms) -> dict | None:
    """The event's lines by step 4's Decimal ``assess``, where every input of its
    known components and every term of its policy is a point mass: what the
    deterministic engine gives, to the last digit."""
    known = [c for c in components if c.estimated]
    if any(c.exact is None for c in known) or any(p_resolved[name].drawn for name in terms.values()):
        return None
    assessment = assess(event, policy)
    lines: dict[str, Decimal | None] = {
        GROSS_CASH: assessment.gross.total.at(Point.BASE).amount,
        MARKET_VALUE_LINE: assessment.market_value.at(Point.BASE).amount if any(not c.cash for c in known) else None,
        "recovery": None,
        RETAINED_CASH: None,
    }
    if policy is not None:
        insured = assessment.insured.points[Point.BASE]
        lines["recovery"], lines[RETAINED_CASH] = insured.recovery.amount, insured.retained.amount
    return lines


def _exact_sum(events: list[Mapping[str, Decimal | None]]) -> dict:
    """The scenario's lines as the Decimal sums of its exact events' lines."""
    lines: dict[str, Decimal | None] = {}
    for key in LINES:
        held = [line[key] for line in events if line[key] is not None]
        lines[key] = sum(held, Decimal(0)) if held else None
    return lines


def _direction(si: ScenarioInput, name: str) -> Direction:
    """The one direction in which the components' inputs that read ``name`` move
    the loss: a derived parameter is the larger loss in it."""
    directions = {
        cited.input.direction
        for event in si.events
        for component in event.components
        for cited in component.inputs
        if cited.parameter.name == name
    }
    if len(directions) != 1:
        raise ScenarioSimulationRefused("derived_malformed", f"{name} is read in {len(directions)} directions")
    return directions.pop()


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
    derived = dict(si.derived)
    resolved = {}
    for name in sorted(needed):
        variation = _variation(si, name)
        if name in derived:
            resolved[name] = resolve_derived(
                named[name], derived[name], si.stated, direction=_direction(si, name), variation=variation
            )
        else:
            resolved[name] = resolve(named[name], si.stated.get(name), variation=variation)
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
            components.append(_Component(index, component, reads, twin, _exact(component, resolved)))
    remedy = None
    if si.remediation is not None:
        remedy = _plan_remediation(si, components)
        components = [replace(c, reduced=True) if i in remedy.reduced else c for i, c in enumerate(components)]
    exact_events = tuple(
        None
        if any(c.reduced for c in components if c.event == index)
        else _exact_lines(event, si.policy, [c for c in components if c.event == index], resolved, terms)
        for index, event in enumerate(si.events)
    )
    exact_scenario = None
    if all(lines is not None for lines in exact_events):
        exact_scenario = exact_events[0] if len(exact_events) == 1 else _exact_sum(list(exact_events))
    return _Plan(
        si,
        tuple(components),
        MappingProxyType(resolved),
        MappingProxyType(terms),
        frequency,
        exact_events,
        exact_scenario,
        remedy,
    )


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
    is evaluated (and a derived one's drawn contributors), the components
    evaluated so far, and 7a's RUN_VECTORS of
    temporaries. Insurance: the components, the lines (:func:`_line_vectors`), the
    drawn policy terms and :data:`INSURANCE_TEMPORARIES`. Summaries: the
    components, the lines and :data:`SUMMARY_TEMPORARIES`. Each of the sampled
    length (the draws, or a compound run's occurrences); and, in a compound run,
    beside them, one value per simulated year of each shared drawn parameter, of
    the :data:`ANNUAL_LINES` and of 7a's YEAR_VECTORS."""
    drawn = {name for name, r in p.resolved.items() if r.drawn}
    # A derived parameter's drawn contributors, each held while it is drawn and
    # taken into the merge: counted as if all were held at once.
    merging = {name: sum(1 for c in p.resolved[name].contributors if c.drawn) for name in drawn}
    last = _last_reads(p)
    live, done, drawing = len(drawn), 0, 0
    for index, c in enumerate(p.components):
        if not c.estimated:
            continue
        drawing = max(drawing, live + done + 1 + sim.RUN_VECTORS)
        done += 1
        live -= sum(1 for name in drawn if last.get(name) == index)
    drawing = max(drawing, len(drawn) + sum(merging.values()) + sim.RUN_VECTORS)
    lines = _line_vectors(p)
    terms = sum(1 for name in set(p.terms.values()) if name in drawn)
    insuring = done + lines + terms + INSURANCE_TEMPORARIES
    summarising = done + lines + SUMMARY_TEMPORARIES
    held = max(drawing, insuring, summarising) * length
    if years is not None:
        shared = sum(1 + merging[name] for name in drawn if p.resolved[name].variation == SHARED)
        held += (shared + ANNUAL_LINES + sim.YEAR_VECTORS) * years
    if p.remediation is not None and p.remediation.reduced:
        # A residual run's reduction factor, its uniform draws and one reduction's
        # draws per occurrence, held beside everything above; and each drawn
        # reduction's yearly draws.
        held += REMEDIATION_TEMPORARIES * length
        if years is not None:
            held += sum(1 for r in p.remediation.resolved() if r.drawn) * years
    return held


def _check_budget(p: _Plan, length: int, years: int | None) -> None:
    held = values_held(p, length, years)
    if held > sim.MAX_VALUES:
        what = f"{length} draws" if years is None else f"{length} occurrences in {years} years"
        raise sim.SimulationRefused("values_over_budget", f"{what} hold {held} values; at most {sim.MAX_VALUES}")


def check_fits(si: ScenarioInput, *, seed: int, draws: int) -> int:
    """The values a run of ``si`` would hold at its peak, or refused exactly as the run
    would refuse it (``values_over_budget``, ``events_over_limit``) -- before anything
    is sampled but the years' counts, which are drawn from the frequency's own stream
    as the run draws them. So a caller can refuse a run that cannot fit before making
    another (a residual run, which holds more than its current run, spec section 28.2).
    Any other refusal of the inputs is raised as the run would raise it."""
    sim.check_seed(seed)
    sim.check_draws(draws)
    p = plan(si)
    if p.frequency is None:
        _check_budget(p, draws, None)
        return values_held(p, draws)
    counts = np.asarray(p.frequency.distribution.sample(sim.RunRandom(seed).stream(sim.FREQUENCY_STREAM), draws),
                        dtype=np.int64)
    occurrences = int(counts.sum())
    if occurrences > sim.MAX_EVENTS:
        raise sim.SimulationRefused("events_over_limit", f"{occurrences} occurrences in {draws} years")
    _check_budget(p, occurrences, draws)
    return values_held(p, occurrences, draws)


def _checked_draws(r: Resolved, drawn: np.ndarray) -> np.ndarray:
    drawn = np.asarray(drawn, dtype=np.float64)
    if not np.isfinite(drawn).all() or (drawn < 0.0).any() or (r.parameter.unit is Unit.RATIO and (drawn > 1.0).any()):
        raise sim.InvariantBroken(f"{r.name} drew a value its unit does not hold: the admissibility check failed")
    drawn.flags.writeable = False
    return drawn


def _draw(r: Resolved, random: sim.RunRandom, length: int) -> np.ndarray | float:
    """``length`` draws of ``r``: from its own stream, or, for a derived parameter,
    each contributor's from its own stream and, per draw, the larger loss in its
    direction (the highest where its inputs increase the loss, the lowest where
    they decrease it). A point mass is its value."""
    if not r.drawn:
        return float(r.point)
    if not r.contributors:
        return _checked_draws(r, r.distribution.sample(random.stream(r.stream), length))
    larger = np.maximum if r.direction == Direction.INCREASES.value else np.minimum
    merged = None
    for contributor in r.contributors:
        drawn = _draw(contributor, random, length)
        if merged is None:
            merged = np.array(np.broadcast_to(drawn, (length,)), dtype=np.float64)
        else:
            larger(merged, drawn, out=merged)
        del drawn
    return _checked_draws(r, merged)


def draw_reduction(r: Resolved, random: sim.RunRandom, length: int) -> np.ndarray | float:
    """``length`` draws of a residual run's reduction ``r``, from its OWN stream
    (:func:`remediation_stream`), never a parameter's; a point mass is its value."""
    if not r.drawn:
        return float(r.point)
    return _checked_draws(r, r.distribution.sample(random.stream(remediation_stream(r.name)), length))


def _reduction_factor(p: _Plan, random: sim.RunRandom, counts: np.ndarray | None, draws: int, n: int) -> np.ndarray:
    """What each of the ``n`` occurrences of a reduced component is multiplied by in
    a residual run: 0 or 1 by whether the control stops the occurrence -- kept where
    a uniform draw of its own stream is below ``1 - r_f``, its year's ``r_f`` -- times
    ``1 - r_m``, its year's ``r_m``. Each reduction is drawn once per simulated year
    (once per draw without a frequency), as every shared parameter is."""
    rem = p.remediation
    factor = np.ones(n, dtype=np.float64)

    def per_occurrence(r: Resolved) -> np.ndarray | float:
        drawn = draw_reduction(r, random, draws)
        if isinstance(drawn, float) or counts is None:
            return drawn
        return np.repeat(drawn, counts)

    if rem.keeps:
        kept = 1.0 - per_occurrence(rem.frequency)
        uniform = random.stream(remediation_stream(REMEDIATION_KEPT)).random(n)
        factor *= uniform < kept
        del uniform, kept
    if rem.scales:
        factor *= 1.0 - per_occurrence(rem.magnitude)
    factor.flags.writeable = False
    return factor


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


def _full(n: int, value: Decimal) -> np.ndarray:
    return _finite(np.full(n, float(value), dtype=np.float64), f"the exact figure {value}")


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


def _sample(
    p: _Plan,
    seed: int,
    draws: int,
    check_time: Callable[[str], None],
    *,
    random: sim.RunRandom | None = None,
    counts: np.ndarray | None = None,
) -> _Sample:
    """One sample of the run. By default the years' counts are drawn from the
    frequency's own stream and every stream is the seed's (a run, the analysis and
    the series all sample so). The portfolio (``engine/portfolio.py``, spec section
    29) hands in its own ``random`` (one seed, a sub-stream per scenario) and the
    years' ``counts`` it drew from the scenario's frequency with its group's common
    driver; the rest of the sample is the same code."""
    random = sim.RunRandom(seed) if random is None else random
    years = None
    occurrences = draws
    if counts is None and p.frequency is not None:
        counts = np.asarray(p.frequency.distribution.sample(random.stream(sim.FREQUENCY_STREAM), draws), dtype=np.int64)
    if counts is not None:
        if p.frequency is None or counts.shape != (draws,) or counts.dtype != np.int64 or (counts < 0).any():
            raise sim.InvariantBroken("a year's counts are one whole number at least zero per year of a run with a frequency")
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
        if not r.drawn:
            values[name] = yearly_terms[name] = float(r.point)
            continue
        if counts is not None and r.variation == SHARED:
            yearly = _draw(r, random, draws)
            if name in term_names:
                yearly_terms[name] = yearly
            values[name] = _checked_draws(r, np.repeat(yearly, counts))
            del yearly
        else:
            values[name] = _draw(r, random, occurrences)
        check_time(f"parameter {name}")

    n = occurrences
    factor = None
    if p.remediation is not None and p.remediation.reduced:
        # A residual run: the control effect's draws come from streams of their own,
        # so every parameter above drew exactly what the current run drew.
        factor = _reduction_factor(p, random, counts, draws, n)
        check_time("remediation")
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
        if c.reduced:
            vector = vector * factor
        components[index] = _finite(vector, f"component {c.component.component_id}")
        for name in [name for name, at in last.items() if at == index]:
            values.pop(name, None)  # its last reader is evaluated: its draws are let go
        check_time(f"component {c.component.component_id}")

    policy = p.si.policy
    terms = {role: values[name] for role, name in p.terms.items()}
    del values
    events: list[dict[str, np.ndarray | None]] = []
    for event_index in range(len(p.si.events)):
        exact = p.exact_events[event_index]
        if exact is not None:
            # Nothing the event reads is uncertain: step 4's Decimal lines, the same in every draw.
            events.append({key: None if exact[key] is None else _full(n, exact[key]) for key in LINES})
            continue
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
    elif p.exact_scenario is not None:
        scenario = {key: None if value is None else _full(n, value) for key, value in p.exact_scenario.items()}
    else:
        scenario = {}
        for key in LINES:
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
    for key in LINES:
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


def _block(
    vector: np.ndarray, *, currency: str, severe, annual: bool, inputs: Iterable[Resolved], exact: Decimal | None = None
) -> dict:
    """7a's summary of one line, as decimal strings, and its expected annual
    exposure where the line is annual. A line with an ``exact`` value (nothing it
    reads is uncertain, and it is not a year's sum) is that Decimal value in every
    figure, with a standard error of zero: the vector holds its nearest binary64."""
    infinite_mean, infinite_variance = _defined(inputs)
    summary = sim.summarize(
        vector, severe_percentile=severe, mean_defined=not infinite_mean, error_defined=not infinite_variance
    )
    block = sim.summary_block(summary, currency)
    if exact is not None and not annual:
        # Every draw is the value: that is the invariant. 7a's mean of the vector
        # (fsum / n) may round one ulp off it, and its standard error then is not
        # zero; neither is a draw of another value, and the line reports the value.
        if not (vector == float(exact)).all():
            raise sim.InvariantBroken(f"an exact line {exact} drew another value")
        text = decimal_text(exact)
        block.update({key: text for key in ("p10", "p50", "p90", "severe_plausible")})
        block["mean"] = None if summary.mean is None else text
        block["standard_error_of_mean"] = None if summary.standard_error is None else "0"
        block["bands"] = {key: None if band is None else [text, text] for key, band in summary.bands.items()}
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

    def summarise(vector, inputs, *, per_year: bool = annual, exact: Decimal | None = None) -> dict:
        return _block(vector, currency=currency, severe=severe, annual=per_year, inputs=inputs, exact=exact)

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
            component_record = {
                "component_id": c.component.component_id,
                "family": c.component.family,
                "cash": c.cash,
                "formula": [c.component.formula.formula_id, c.component.formula.version],
                "status": c.component.status,
                "evaluated_by": c.evaluated_by,
                "reads": dict(sorted(c.reads.items())),
                "summary": summarise(
                    yearly(s.components[index]), reads([c]) + freq_inputs, exact=None if c.reduced else c.exact
                )
                if c.estimated
                else None,
                "unknown": None
                if c.estimated
                else {"reason": c.component.unknown_reason, "inputs": list(c.component.missing)},
            }
            if c.reduced:
                # Only where a residual run's control effect changes the component: a
                # component it leaves as it is records exactly what the current run does.
                component_record["remediated"] = True
            component_records.append(component_record)
        exact = p.exact_events[event_index] or dict.fromkeys(LINES)
        events_record.append(
            {
                "event_key": event.loss_event_id,
                "evaluated_by": BY_DECIMAL if p.exact_events[event_index] is not None else BY_TWIN,
                GROSS_CASH: summarise(yearly(line[GROSS_CASH]), cash_inputs, exact=exact[GROSS_CASH]),
                RETAINED_CASH: None
                if line[RETAINED_CASH] is None
                else summarise(yearly(line[RETAINED_CASH]), cash_inputs + term_inputs, exact=exact[RETAINED_CASH]),
                MARKET_VALUE_LINE: None
                if not market
                else {
                    **summarise(
                        yearly(line[MARKET_VALUE_LINE]), reads(market) + freq_inputs, exact=exact[MARKET_VALUE_LINE]
                    ),
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
    exact = p.exact_scenario or dict.fromkeys(LINES)
    scenario_record = {
        "headline": RETAINED_CASH if si.policy is not None else GROSS_CASH,
        "evaluated_by": BY_DECIMAL if p.exact_scenario is not None else BY_TWIN,
        GROSS_CASH: summarise(lines[GROSS_CASH], all_cash, exact=exact[GROSS_CASH]),
        RETAINED_CASH: None
        if si.policy is None
        else summarise(lines[RETAINED_CASH], all_cash + term_inputs, exact=exact[RETAINED_CASH]),
        MARKET_VALUE_LINE: None
        if not all_market
        else {
            **summarise(lines[MARKET_VALUE_LINE], reads(all_market) + freq_inputs, exact=exact[MARKET_VALUE_LINE]),
            "never_added_to_cash": True,
        },
        "complete": all(not (c.cash and not c.estimated) for c in p.components),
        "unknown_components": [
            f"{si.events[c.event].loss_event_id}/{c.component.component_id}" for c in p.components if not c.estimated
        ],
        "aggregate_limit_exceeded_share": _limit_share(p, s),
        "per_occurrence": None,
    }
    if annual and s.occurrences >= sim.MIN_DRAWS:
        scenario_record["per_occurrence"] = {
            GROSS_CASH: summarise(
                s.scenario[GROSS_CASH], reads([c for c in p.components if c.cash]), per_year=False,
                exact=exact[GROSS_CASH],
            ),
            RETAINED_CASH: None
            if si.policy is None
            else summarise(
                s.scenario[RETAINED_CASH], reads([c for c in p.components if c.cash]) + term_inputs, per_year=False,
                exact=exact[RETAINED_CASH],
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
        "expert_parameters": sorted(
            {r.name for r in resolved.values() if r.expert}
            | {c.name for r in resolved.values() for c in r.contributors if c.expert}
        ),
        "versions": inputs["versions"],
        "input_digest": input_digest,
        "outcomes_sha256": digest_of_outcomes,
    }
    if p.remediation is not None:
        record["remediation"] = _remediation_record(p)
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


def _remediation_record(p: _Plan) -> dict:
    """What a residual run records of its control effect: the option and its digest,
    each reduction's rule, distribution and stream, the components it changed, and
    whether it changed any (a point mass at zero changes nothing)."""
    rem = p.remediation

    def reduction(r: Resolved | None) -> dict | None:
        if r is None:
            return None
        return {
            "rule": r.rule,
            "distribution": r.distribution_record(),
            "stream": remediation_stream(r.name) if r.drawn else None,
            "expert": r.expert,
        }

    return {
        "schema": REMEDIATION_SCHEMA,
        "option": rem.remediation.option_id,
        "option_digest": rem.remediation.option_digest,
        "frequency_reduction": reduction(rem.frequency),
        "magnitude_reduction": reduction(rem.magnitude),
        "kept_stream": remediation_stream(REMEDIATION_KEPT) if rem.keeps and rem.reduced else None,
        "reduced_components": sorted(
            f"{p.si.events[c.event].loss_event_id}/{c.component.component_id}" for c in p.components if c.reduced
        ),
        "changes_the_run": bool(rem.reduced),
    }


def reductions(p: _Plan) -> list[Resolved]:
    """A residual run's reductions, resolved, in name order; none for the scenario as it is."""
    if p.remediation is None:
        return []
    return sorted(p.remediation.resolved(), key=lambda r: r.name)


def reduction_at(p: _Plan, values: Mapping[str, float]) -> float:
    """The factor a reduced component's ONE occurrence is multiplied by in
    expectation, at the reductions' ``values`` (a point mass at its own):
    ``(1 - r_f) (1 - r_m)``, each where it changes the run. For the sensitivity
    analysis's swings (spec, section 28)."""
    rem = p.remediation
    factor = 1.0
    if rem.keeps:
        factor *= 1.0 - values[rem.frequency.name]
    if rem.scales:
        factor *= 1.0 - values[rem.magnitude.name]
    return factor


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
    "FREQUENCY_RANGE_TESTS",
    "FREQUENCY_REDUCTION",
    "MAGNITUDE_REDUCTION",
    "REMEDIATION_RULE",
    "REMEDIATION_SCHEMA",
    "REMEDIATION_STREAM_DOMAIN",
    "REMEDIATION_VERSION",
    "Remediation",
    "check_fits",
    "draw_reduction",
    "reduction_at",
    "reductions",
    "remediation_stream",
    "NATIVE_PARAMETERS",
    "PER_OCCURRENCE",
    "REFUSALS",
    "RANGE_FIT_PERCENTILES",
    "RANGE_MASS_FLOOR",
    "RANGE_TESTS",
    "RULE_VERSION",
    "SCHEMA",
    "SHARED",
    "STREAM_DOMAIN",
    "VARIATION_VERSION",
    "ImpliedRate",
    "Resolved",
    "ScenarioInput",
    "ScenarioSimulation",
    "ScenarioSimulationRefused",
    "StatedDistribution",
    "build",
    "canonical_inputs",
    "check_fits_range",
    "check_stated",
    "digest_of",
    "exact_count_mean",
    "implied_rate",
    "no_float",
    "parse_stated",
    "plan",
    "limits",
    "mass_between",
    "resolve",
    "resolve_derived",
    "resolve_frequency",
    "run",
    "stream_name",
    "support",
    "versions",
]
