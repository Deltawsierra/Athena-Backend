"""Sensitivity analysis of a simulated scenario (MVP step 8;
``docs/economics/spec-v1.md``, section 26.1): which parameters drive the
uncertainty of the scenario's gross cash loss, and in which direction.

Two methods, both on the run's OWN draws -- the same seed, the same sub-streams,
the same plan as step 7b's :func:`.scenario_simulation.run` -- and both stated
(:data:`METHOD_ID`, :data:`VERSION`):

- **Ranking: contribution to variance by rank correlation.** For every uncertain
  parameter the gross cash reads, the Spearman rank correlation of its draws with
  the scenario's gross cash loss (per simulated year where the run has a
  frequency, per occurrence otherwise); its importance is its squared rank
  correlation over the sum of every ranked parameter's, so the importances sum to
  one, and its direction is the correlation's sign. Ties take their mean rank. The
  sums are taken over whole numbers (twice each centred rank), so the correlation
  is exact for the draws and the same on every platform; it is written to
  :data:`DIGITS` decimal places. For a sum of independent parameters the
  importances are close to their shares of the variance; for a skewed or
  non-additive formula they rank by monotone association, which is what a
  tornado is read for.
- **The tornado: one at a time.** Every other uncertain parameter is held at its
  P50 and one is moved to its P10 and then its P90 (each of its own draws, type 7,
  as the run's summaries), and the scenario's gross cash is evaluated at each by
  the formula twins: per occurrence, and in a run with a frequency, times the
  frequency's mean count over the run's years (every parameter is shared by a
  year's occurrences, section 25.2, so a year at fixed parameters is N times one
  occurrence). The frequency's own swing is its P10 and P90 counts. At most
  :data:`MAX_SWINGS` parameters are swung, the most important first.

- **The level** (:func:`level_shares`): each figure's share of the result's
  LEVEL, which the grade weighs by -- the absolute elasticity of the base-case gross
  cash (every parameter at its base, by the twins) to each parameter it reads, fixed
  or ranged, normalised; with a frequency, a year is N occurrences, so the
  frequency's elasticity is one.

What is not ranked is listed with the reason: a point mass is **fixed** (it draws
nothing), a parameter only the policy or a market-value line reads does not enter
the gross cash, and a parameter drawn per occurrence has no one value a year.

The analysis is bound to the stored run: the canonical inputs it reads must give
the run's input digest (``inputs_changed`` otherwise), and its draws the run's
outcomes digest (``result_not_reproduced`` otherwise), so it is never made from
other draws than the run's.

Pure: no Django, no database, no I/O, no clock (``check_time`` is the caller's).
"""

from __future__ import annotations

import hashlib
import json
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Context, Decimal
from fractions import Fraction

import numpy as np

from . import distributions as dist
from . import scenario_simulation as ss
from . import simulation as sim
from .money import decimal_text

SCHEMA = "mythos.economics.sensitivity/v1"
METHOD_ID = "mythos.economics.sensitivity"
VERSION = 1
RANKING = (
    "Spearman rank correlation of each uncertain parameter's draws with the scenario's gross cash loss (per year "
    "with a frequency, per occurrence otherwise), ties at their mean rank; importance is the squared correlation "
    "over the sum of every ranked parameter's (contribution to variance); direction is the correlation's sign"
)
SWING = (
    "one at a time: every other uncertain parameter at its P50, the one swung to its P10 and its P90 "
    "(type 7 quantiles of its own draws); the gross cash evaluated by the formula twins per occurrence, times the "
    "frequency's mean count in a run with a frequency; the frequency's own swing is its P10 and P90 count"
)
LEVEL = (
    "each parameter's share of the result's LEVEL: the absolute elasticity of the base-case gross cash (every "
    "parameter at its base, by the formula twins) to it, by a central difference of LEVEL_STEP either side of its "
    "base (zero for a base of zero); with a frequency, a year at base is N occurrences, so the frequency's elasticity "
    "is one; normalised to sum to one. A fixed figure counts exactly as a range does"
)
#: The relative step of the level's central difference. Every formula is affine in
#: each input (a sum and product of inputs and 1 - ratio) or a min of such, so the
#: difference is the derivative itself away from a cap's kink, and the slopes'
#: mean at one.
LEVEL_STEP = 0.001
#: The output every parameter is ranked against.
OUTPUT = ss.GROSS_CASH
#: At most this many parameters are swung for the tornado, the most important
#: first. Every ranked parameter's importance is recorded: the run already holds
#: one vector per parameter within 7a's values budget, so their number is bounded.
MAX_SWINGS = 20
#: Decimal places an importance and a correlation are written to.
DIGITS = 10
_QUANTUM = Decimal(1).scaleb(-DIGITS)
_CONTEXT = Context(prec=60, rounding=ROUND_HALF_EVEN)
#: The swing's percentiles.
P10, P50, P90 = Fraction(1, 10), Fraction(1, 2), Fraction(9, 10)

INCREASES = "increases"
DECREASES = "decreases"
NONE = "none"

FIXED = "fixed: a point mass draws nothing"
NOT_IN_GROSS = "not read by the gross cash: only the policy or a market-value line reads it"
PER_OCCURRENCE = "drawn per occurrence: it has no one value a year"

REFUSALS: Mapping[str, str] = {
    "inputs_changed": (
        "the scenario's stored rows no longer give the run's canonical inputs: the analysis is made only from "
        "the inputs the run read"
    ),
    "result_not_reproduced": (
        "the draws made again from the run's seed and sub-streams are not the run's (another numpy or platform, "
        "section 23.8): the analysis is made only on the run's own draws"
    ),
}


class SensitivityRefused(ValueError):
    """A sensitivity analysis refused. ``code`` is one of :data:`REFUSALS`."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        super().__init__(f"{code}: {REFUSALS[code]}{suffix}")


def version_record() -> dict:
    """The method, as every record names it."""
    return {
        "id": METHOD_ID,
        "version": VERSION,
        "ranking": RANKING,
        "swing": SWING,
        "output": OUTPUT,
        "level": LEVEL,
        "level_step": dist.float_text(LEVEL_STEP),
        "max_swings": MAX_SWINGS,
        "digits": DIGITS,
    }


# ------------------------------------------------------------------ ranks


def centred_ranks(values: np.ndarray) -> tuple[np.ndarray, np.ndarray]:
    """Twice each value's rank, minus ``n + 1`` (so they sum to zero), ties at
    their mean rank, as int64; and the values sorted. Whole numbers, so the sums
    taken over them are exact."""
    values = np.asarray(values)
    n = values.size
    order = np.argsort(values, kind="stable")
    ordered = values[order]
    if n == 0:
        return np.zeros(0, dtype=np.int64), ordered
    starts = np.flatnonzero(np.concatenate(([True], ordered[1:] != ordered[:-1])))
    ends = np.append(starts[1:], n)
    doubled = np.repeat((starts + 1 + ends).astype(np.int64), ends - starts)
    ranks = np.empty(n, dtype=np.int64)
    ranks[order] = doubled
    ranks -= n + 1
    return ranks, ordered


def _dot(a: np.ndarray, b: np.ndarray) -> int:
    """An exact integer sum of products: each centred rank is below 2 x 10^6 in
    magnitude and there are at most 10^6, so no partial sum leaves int64."""
    return int(np.dot(a, b))


def _text(value: Fraction | Decimal) -> str:
    if isinstance(value, Fraction):
        value = _CONTEXT.divide(Decimal(value.numerator), Decimal(value.denominator))
    return decimal_text(value.quantize(_QUANTUM, rounding=ROUND_HALF_EVEN, context=_CONTEXT))


def _correlation(sxy: int, sxx: int, syy: int) -> Decimal:
    root = _CONTEXT.sqrt(Decimal(sxx) * Decimal(syy))
    return _CONTEXT.divide(Decimal(sxy), root)


# ------------------------------------------------------------------ the run


@dataclass(frozen=True)
class Ranked:
    """One ranked parameter: its squared rank correlation (exact), the
    correlation's sign and its P10, P50 and P90."""

    name: str
    squared: Fraction
    sign: int
    correlation: Decimal | None
    quantiles: tuple[float, float, float]
    resolved: ss.Resolved | None  # None for the frequency


def _sources(r: ss.Resolved | None, frequency: ss.Resolved | None) -> list[str]:
    """The source type(s) a ranked parameter's draws rest on: its own, or, for a
    derived one, each contributor's."""
    if r is None:
        return [frequency.parameter.source_type.value]
    if r.contributors:
        return [c.parameter.source_type.value for c in r.contributors]
    return [r.parameter.source_type.value]


def _expert(r: ss.Resolved | None) -> bool:
    if r is None:
        return False
    return r.expert or any(c.expert for c in r.contributors)


def _gross_at(p: ss._Plan, values: Mapping[str, float]) -> float:
    """The scenario's gross cash for ONE occurrence with every parameter at the
    value given (a point mass at its own), by the formula twins, summed as the run
    sums it: each event's cash components in order, the events in order; an exact
    event (nothing it reads uncertain) at step 4's Decimal value."""
    totals = []
    for index in range(len(p.si.events)):
        exact = p.exact_events[index]
        if exact is not None:
            totals.append(float(exact[ss.GROSS_CASH]))
            continue
        gross = 0.0
        for c in p.components:
            if c.event != index or not c.estimated or not c.cash:
                continue
            if c.constant is not None:
                gross += c.constant
            else:
                gross += float(np.asarray(c.twin({name: values[source] for name, source in c.reads.items()})).reshape(-1)[0])
        totals.append(gross)
    if p.exact_scenario is not None and len(totals) > 1:
        return float(p.exact_scenario[ss.GROSS_CASH])
    total = 0.0
    for value in totals:
        total += value
    return total


def _gross_by_twins(p: ss._Plan, values: Mapping[str, float]) -> float:
    """One occurrence's gross cash with every parameter at the value given, every
    known cash component by its twin (never a stored constant, so a fixed figure
    moves the level as a range does), summed in component and event order."""
    total = 0.0
    for c in p.components:
        if c.estimated and c.cash:
            total += float(np.asarray(c.twin({name: values[source] for name, source in c.reads.items()})).reshape(-1)[0])
    return total


def _amount_of(value) -> float:
    return float(value.amount if hasattr(value, "amount") else value)


def level_shares(p: ss._Plan) -> dict:
    """Each parameter's share of the result's level (:data:`LEVEL`): every
    parameter a known cash component reads, fixed or not, and the frequency. A
    derived parameter names its contributors and those whose base supplies its
    own (the larger loss at base). Refused where the base-case gross is zero."""
    cash_reads = sorted({name for c in p.components if c.estimated and c.cash for name in c.reads.values()})
    base = {name: _amount_of(p.resolved[name].parameter.base) for name in cash_reads}
    gross = _gross_by_twins(p, base)
    elasticities: dict[str, float] = {}
    for name in cash_reads:
        at = base[name]
        if at == 0.0 or gross == 0.0:
            elasticities[name] = 0.0
            continue
        up = _gross_by_twins(p, {**base, name: at * (1.0 + LEVEL_STEP)})
        down = _gross_by_twins(p, {**base, name: at * (1.0 - LEVEL_STEP)})
        elasticities[name] = abs(up - down) / (2.0 * LEVEL_STEP * gross)
    frequency = p.frequency.name if p.frequency is not None else None
    if frequency is not None:
        elasticities[frequency] = 1.0 if gross != 0.0 else 0.0
    total = math.fsum(elasticities.values())
    entries = []
    for name in sorted(elasticities):
        r = p.frequency if name == frequency else p.resolved[name]
        share = Fraction(0) if total == 0.0 else Fraction(elasticities[name]) / Fraction(total)
        entry = {
            "name": name,
            "base": decimal_text(r.parameter.base.amount if hasattr(r.parameter.base, "amount") else r.parameter.base),
            "source_type": r.parameter.source_type.value,
            "elasticity": dist.float_text(elasticities[name]),
            "share": _text(share),
            "fixed": not r.drawn,
            "frequency": name == frequency,
            "derived_from": [],
            "supplied_by": [],
        }
        if r.contributors:
            entry["derived_from"] = [c.name for c in r.contributors]
            entry["supplied_by"] = [c.name for c in r.contributors if c.parameter.base == r.parameter.base]
        entries.append(entry)
    return {
        "basis": "base-case gross cash" + (", a year of N occurrences" if frequency is not None else ""),
        "base_gross": dist.float_text(gross),
        "defined": total != 0.0,
        "parameters": entries,
    }


def _noop(stage: str) -> None:
    return None


def analyse(
    si: ss.ScenarioInput,
    *,
    seed: int,
    draws: int,
    severe_percentile,
    input_digest: str,
    outcomes_sha256: str,
    check_time: Callable[[str], None] | None = None,
) -> dict:
    """The sensitivity of ``si``'s run with ``seed`` and ``draws``, whose stored
    input digest and outcomes digest are given: a record of decimal strings (see
    the module's methods). Refused unless the inputs and the draws are the run's."""
    check_time = check_time or _noop
    sim.check_seed(seed)
    sim.check_draws(draws)
    inputs = ss.canonical_inputs(si, severe_percentile=severe_percentile)
    if ss.digest_of(inputs) != input_digest:
        raise SensitivityRefused("inputs_changed", f"{ss.digest_of(inputs)}, not {input_digest}")
    p = ss.plan(si)
    if p.frequency is None:
        ss._check_budget(p, draws, None)
    sample = ss._sample(p, seed, draws, check_time)
    reproduced = ss.outcomes_digest(ss._ordered_vectors(p, sample))
    if reproduced != outcomes_sha256:
        raise SensitivityRefused("result_not_reproduced", f"{reproduced}, not {outcomes_sha256}")
    annual = p.frequency is not None
    output = sample.annual[OUTPUT] if annual else sample.scenario[OUTPUT]
    counts = sample.counts
    occurrences = sample.occurrences
    output_ranks, _ = centred_ranks(output)
    syy = _dot(output_ranks, output_ranks)
    del sample, output
    check_time("sensitivity output")

    cash_reads = {name for c in p.components if c.estimated and c.cash for name in c.reads.values()}
    fixed, not_in_gross, per_occurrence = [], [], []
    ranked: list[Ranked] = []
    p50s: dict[str, float] = {}
    values: dict[str, float] = {}

    def rank(name: str, draws_of: np.ndarray, r: ss.Resolved | None) -> None:
        ranks, ordered = centred_ranks(draws_of)
        quantiles = tuple(sim.quantile(ordered, q) for q in (P10, P50, P90))
        sxx = _dot(ranks, ranks)
        sxy = _dot(ranks, output_ranks)
        if sxx == 0 or syy == 0:
            squared, sign, correlation = Fraction(0), 0, None
        else:
            squared = Fraction(sxy * sxy, sxx * syy)
            sign = (sxy > 0) - (sxy < 0)
            correlation = _correlation(sxy, sxx, syy)
        ranked.append(Ranked(name, squared, sign, correlation, quantiles, r))
        p50s[name] = quantiles[1]

    for name in sorted(p.resolved):
        r = p.resolved[name]
        if not r.drawn:
            fixed.append({"name": name, "value": decimal_text(r.point)})
            values[name] = float(r.point)
            continue
        if name not in cash_reads:
            not_in_gross.append(name)
            continue
        if annual and r.variation == ss.PER_OCCURRENCE:
            per_occurrence.append(name)
            drawn = np.asarray(ss._draw(r, sim.RunRandom(seed), occurrences), dtype=np.float64)
            values[name] = sim.quantile(np.sort(drawn), P50)
            del drawn
            continue
        drawn = np.asarray(ss._draw(r, sim.RunRandom(seed), draws), dtype=np.float64)
        rank(name, drawn, r)
        del drawn
        check_time(f"sensitivity {name}")
    frequency_name = None
    if annual:
        frequency_name = p.frequency.name
        rank(frequency_name, counts, None)

    total = sum((item.squared for item in ranked), Fraction(0))
    ordered = sorted(ranked, key=lambda item: (-item.squared, item.name))
    for item in ranked:
        if item.name != frequency_name:
            values[item.name] = item.quantiles[1]
    mean_count = None
    if annual:
        mean_count = math.fsum(counts.tolist()) / counts.size

    def outcome(at: Mapping[str, float], count: float | None = None) -> str:
        gross = _gross_at(p, at)
        if annual:
            gross *= mean_count if count is None else count
        return dist.float_text(gross)

    baseline = outcome(values)
    entries = []
    for position, item in enumerate(ordered, start=1):
        importance = Fraction(0) if total == 0 else item.squared / total
        entry = {
            "name": item.name,
            "rank": position,
            "importance": _text(importance),
            "rank_correlation": None if item.correlation is None else _text(item.correlation),
            "direction": INCREASES if item.sign > 0 else DECREASES if item.sign < 0 else NONE,
            "source_types": _sources(item.resolved, p.frequency),
            "rule": ss.RULE_STATED if item.resolved is None else item.resolved.rule,
            "expert": _expert(item.resolved),
            "derived_from": [] if item.resolved is None else [c.name for c in item.resolved.contributors],
            "frequency": item.resolved is None,
            "swing": None,
        }
        if position <= MAX_SWINGS:
            low, middle, high = item.quantiles
            if item.resolved is None:
                at_low, at_high = outcome(values, low), outcome(values, high)
            else:
                at_low = outcome({**values, item.name: low})
                at_high = outcome({**values, item.name: high})
            entry["swing"] = {
                "p10": dist.float_text(low),
                "p50": dist.float_text(middle),
                "p90": dist.float_text(high),
                "low_outcome": at_low,
                "high_outcome": at_high,
            }
        entries.append(entry)
        check_time(f"swing {item.name}")
    return {
        "schema": SCHEMA,
        "method": version_record(),
        "scenario_id": si.scenario_id,
        "seed": str(seed),
        "draws": draws,
        "input_digest": input_digest,
        "outcomes_sha256": outcomes_sha256,
        "basis": ss.ANNUAL_BASIS if annual else ss.PER_OCCURRENCE_BASIS,
        "reporting_currency": si.currency,
        "output_varies": syy != 0,
        "ranked": entries,
        "swung": min(len(entries), MAX_SWINGS),
        "swing_baseline": {
            "outcome": baseline,
            "frequency_at": None if not annual else {"mean_count": dist.float_text(mean_count)},
        },
        "fixed": fixed,
        "not_in_gross_cash": not_in_gross,
        "per_occurrence": per_occurrence,
        "statements": {"fixed": FIXED, "not_in_gross_cash": NOT_IN_GROSS, "per_occurrence": PER_OCCURRENCE},
        "level": level_shares(p),
    }


def digest_of(record: Mapping) -> str:
    """``sha256:`` over the record's canonical JSON (sorted keys, no whitespace, ASCII)."""
    text = json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


__all__ = [
    "DECREASES",
    "INCREASES",
    "MAX_SWINGS",
    "METHOD_ID",
    "NONE",
    "REFUSALS",
    "SCHEMA",
    "VERSION",
    "SensitivityRefused",
    "analyse",
    "centred_ranks",
    "digest_of",
    "level_shares",
    "version_record",
]
