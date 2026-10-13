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
  LEVEL, which the grade weighs by, for the gross cash and, under a policy, the
  retained cash -- an ADDITIVE decomposition at base (:data:`LEVEL`): each known cash
  component carries its base over the total; one whose formula is a sum is split
  first by its additive terms, each its base over the component's, and each term
  among its own factors equally; one of a single term is split among its inputs by
  their elasticity of it at base (a product's factors equally, a recovery through its
  complement ``1 - rate`` as one factor); a frequency carries one half; the retained
  cash's pieces (uncovered, over a sublimit, kept by the deductible, past the limit)
  read the policy's terms. Fixed or ranged alike, from bases only.

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
from .formulas import Direction
from .loss import NEVER_COVERED
from .money import decimal_text
from .parameters import Unit
from .taxonomy import LossFamily

SCHEMA = "mythos.economics.sensitivity/v1"
METHOD_ID = "mythos.economics.sensitivity"
#: 2: the level splits a component whose formula is a sum by its additive terms
#: first (spec 26.1; 26.10, decision 8). 1 (#153) split it by elasticity across
#: the whole sum, which gave a fixed amount F beside a two-factor product P the share
#: F / (F + 2P), not F / (F + P). Every formula of one term is split as in 1.
VERSION = 2
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
    "an ADDITIVE decomposition of the base case (every parameter at its base). The base-case gross cash is the sum "
    "of its known cash components; each carries its base over the total. A component whose formula is a sum of "
    "terms (fixed_cost + hourly_rate x hours) is split first by its terms, each carrying its base over the "
    "component's (the product of its factors' bases, a recovery through its complement 1 - rate), and each term "
    "among its own factors equally (each factor of a product has elasticity one); an input of two terms adds both "
    "parts. A component whose formula is one term (a product, a cap, a lump sum) is split among its own inputs in "
    "proportion to their elasticity of the component at base (a central difference of LEVEL_STEP either side: each "
    "factor of a product one, the complement 1 - rate of a recovery one factor like any other). With a frequency, a "
    "year is frequency x severity: the frequency carries one half and the severity's decomposition the other. Under a "
    "policy the base-case retained cash is decomposed the same way, per event, into the cash the policy leaves "
    "uncovered, each family's excess over its sublimit, what the deductible keeps and what passes the limit, each "
    "split among what it reads in proportion to its elasticity at base, the policy's terms among them; the "
    "business-interruption cash a waiting period above zero leaves uncovered is one half the waiting period's. A "
    "fixed figure counts exactly as a range does; a line's shares sum to exactly one and are computed from bases "
    "only. A line that is zero at base, or a frequency whose base is zero, has no level"
)
#: The relative step of the level's central difference inside a component. Every
#: formula is affine in each input (a sum and product of inputs and 1 - ratio) or a
#: min of such, so the difference is the derivative itself away from a cap's kink,
#: and the slopes' mean at one.
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
                value = c.constant
            else:
                value = float(np.asarray(c.twin({name: values[source] for name, source in c.reads.items()})).reshape(-1)[0])
            if c.reduced:
                # A residual run (spec, section 28): the occurrence as its control
                # effect leaves it, in expectation at the reductions' values.
                value *= ss.reduction_at(p, values)
            gross += value
        totals.append(gross)
    if p.exact_scenario is not None and len(totals) > 1:
        return float(p.exact_scenario[ss.GROSS_CASH])
    total = 0.0
    for value in totals:
        total += value
    return total


def _base(value) -> Decimal:
    return value.amount if hasattr(value, "amount") else Decimal(value)


def _exact_text(value: Fraction) -> str:
    """A base value (a sum or difference of decimal figures) in its one spelling."""
    return decimal_text(_CONTEXT.divide(Decimal(value.numerator), Decimal(value.denominator)))


class _NoLevel(Exception):
    """A line with no level to weigh; the message says why."""


def _alone(name: str) -> dict[str, Fraction]:
    return {name: Fraction(1)}


def _mix(*parts: tuple[Fraction, Mapping[str, Fraction]]) -> dict[str, Fraction]:
    """The splits ``parts`` (each a weight and a split summing to one), weighted:
    a split summing to the weights' sum."""
    mixed: dict[str, Fraction] = {}
    for weight, split in parts:
        if weight == 0:
            continue
        for name, share in split.items():
            mixed[name] = mixed.get(name, Fraction(0)) + weight * share
    return mixed


def _by_terms(p: ss._Plan, c, complements: Mapping[str, bool]) -> tuple[dict[str, Fraction], list[dict]]:
    """A formula that is a SUM of terms (:attr:`.formulas.Formula.terms`), split
    among its inputs: each additive term carries its base over the component's (the
    sum of the terms' bases), exactly, from the bases only -- a term's base is the
    product of its factors' bases, a recovery rate's through its complement
    ``1 - rate`` -- and each of a term's k factors carries 1/k of the term, its
    elasticity of a product being one like every other factor's. An input that is a
    factor of two terms adds both parts. Each input's part of the component, and a row
    per term."""
    terms = c.component.formula.terms

    def factor(name: str) -> Fraction:
        base = Fraction(_base(p.resolved[c.reads[name]].parameter.base))
        return 1 - base if complements[name] else base

    bases = []
    for term in terms:
        product = Fraction(1)
        for name in term:
            product *= factor(name)
        bases.append(product)
    whole = sum(bases, Fraction(0))
    parts = dict.fromkeys(c.reads, Fraction(0))
    rows = []
    for term, base in zip(terms, bases, strict=True):
        weight = Fraction(0) if whole == 0 else base / whole
        for name in term:
            parts[name] += weight / len(term)
        rows.append({"inputs": list(term), "base": _exact_text(base), "weight": _text(weight)})
    return parts, rows


def _component(p: ss._Plan, c) -> dict:
    """One known cash component at base: its exact base value (step 4's Decimal
    figure) and how it splits among its own inputs.

    A formula that is a SUM (``fixed_cost + hourly_rate x hours``) is split first by
    its additive terms, each carrying its base over the component's, and then each
    term among its own factors (:func:`_by_terms`): a fixed amount beside a product
    carries exactly its base share. A formula of one term (a product, a cap, a lump
    sum) is split in proportion to each input's elasticity of the component at base,
    by its twin, a central difference of :data:`LEVEL_STEP` either side. An input that
    lowers the loss (a recovery rate, read as ``1 - rate``) is moved through that
    complement: one factor like any other, never ``r / (1 - r)`` of the product. An
    input read twice adds both."""
    where = f"{p.si.events[c.event].loss_event_id}/{c.component.component_id}"
    value = Fraction(c.component.base.amount)
    if value < 0:
        raise _NoLevel(f"the component {where} is below zero at base")
    values = {name: float(_base(p.resolved[source].parameter.base)) for name, source in c.reads.items()}

    def at(moved: Mapping[str, float]) -> float:
        return float(np.asarray(c.twin(moved)).reshape(-1)[0])

    level = at(values)
    swings: dict[str, float] = {}
    complements: dict[str, bool] = {}
    for name in sorted(c.reads):
        spec = c.component.formula.input(name)
        complement = spec.direction is Direction.DECREASES and spec.unit is Unit.RATIO
        moved = 1.0 - values[name] if complement else values[name]
        if moved == 0.0:
            swings[name] = 0.0
        elif complement:
            up, down = 1.0 - moved * (1.0 + LEVEL_STEP), 1.0 - moved * (1.0 - LEVEL_STEP)
            swings[name] = abs(at({**values, name: up}) - at({**values, name: down}))
        else:
            up, down = moved * (1.0 + LEVEL_STEP), moved * (1.0 - LEVEL_STEP)
            swings[name] = abs(at({**values, name: up}) - at({**values, name: down}))
        complements[name] = complement
    total = sum((Fraction(swing) for swing in swings.values()), Fraction(0))
    terms = None
    if len(c.component.formula.terms) > 1:
        parts, terms = _by_terms(p, c, complements)
    else:
        parts = {name: Fraction(0) if total == 0 else Fraction(swing) / total for name, swing in swings.items()}
    split: dict[str, Fraction] = {}
    if value != 0:
        if terms is None and total == 0:
            raise _NoLevel(f"no input of the component {where} moves it at base")
        for name, part in parts.items():
            source = c.reads[name]
            split[source] = split.get(source, Fraction(0)) + part
    inputs = [
        {
            "input": name,
            "parameter": c.reads[name],
            "complement": complements[name],
            "elasticity": dist.float_text(swings[name] / (2.0 * LEVEL_STEP * level)) if level else "0",
            "weight": _text(parts[name]),
        }
        for name in sorted(c.reads)
    ]
    piece = {
        "piece": where,
        "kind": "component",
        "event": c.event,
        "family": c.component.family,
        "value": value,
        "split": split,
        "inputs": inputs,
    }
    if terms is not None:
        piece["terms"] = terms
    return piece


def _retained_pieces(p: ss._Plan, components: list[dict]) -> tuple[list[dict], Fraction]:
    """The base-case retained cash of every event under the policy, as additive
    pieces (spec 26.1): the cash the policy leaves uncovered (an excluded or
    never-covered family, business interruption without a stated waiting period, or
    under one above zero, which is then one half the waiting period's), each covered
    family's excess over its sublimit, what the deductible keeps and what passes the
    limit. Each piece splits among what it reads in proportion to its elasticity at
    base: a difference ``a - b`` as ``a : b``, a capped amount to the cap where the cap
    binds, to the amount where it does not, half each at the kink. The pieces of an
    event sum exactly to its retained cash, as step 7b's insurance gives it."""
    policy = p.si.policy
    terms = p.terms

    def term(role: str) -> Fraction:
        value = Fraction(_base(p.resolved[terms[role]].parameter.base))
        if value < 0:
            raise _NoLevel(f"the policy's {role} is below zero at base")
        return value

    uncovered = set(policy.exclusions) | NEVER_COVERED
    interruption = LossFamily.BUSINESS_INTERRUPTION.value
    waiting_name = terms.get("waiting_period_hours")
    waiting = None if waiting_name is None else term("waiting_period_hours")
    deductible, limit = term("deductible"), term("limit")
    half = Fraction(1, 2)
    pieces: list[dict] = []
    retained_total = Fraction(0)
    for index, event in enumerate(p.si.events):
        mine = [c for c in components if c["event"] == index]
        gross = sum((c["value"] for c in mine), Fraction(0))
        held: list[dict] = []
        families: dict[str, list[dict]] = {}
        for c in mine:
            if c["family"] in uncovered or (c["family"] == interruption and waiting is None):
                held.append({"piece": c["piece"], "kind": "uncovered", "value": c["value"], "split": c["split"]})
            elif c["family"] == interruption and waiting > 0:
                held.append({"piece": c["piece"], "kind": "uncovered_by_waiting_period", "value": c["value"],
                             "split": _mix((half, c["split"]), (half, _alone(waiting_name)))})
            else:
                families.setdefault(c["family"], []).append(c)
        capped: list[tuple[Fraction, dict[str, Fraction]]] = []
        for family, members in families.items():
            amount = sum((c["value"] for c in members), Fraction(0))
            split = _mix(*((c["value"] / amount, c["split"]) for c in members)) if amount else {}
            role = f"sublimit:{family}"
            if role not in terms:
                capped.append((amount, split))
                continue
            cap, cap_split = term(role), _alone(terms[role])
            if amount > cap:
                whole = amount + cap
                held.append({"piece": f"{event.loss_event_id}/{family}", "kind": "sublimit_excess",
                             "value": amount - cap, "split": _mix((amount / whole, split), (cap / whole, cap_split))})
                capped.append((cap, cap_split))
            elif amount == cap:
                capped.append((amount, _mix((half, split), (half, cap_split))))
            else:
                capped.append((amount, split))
        covered = sum((value for value, _ in capped), Fraction(0))
        covered_split = _mix(*((value / covered, split) for value, split in capped)) if covered else {}
        kept_split = _alone(terms["deductible"])
        if covered > deductible:
            kept = deductible
        elif covered < deductible:
            kept, kept_split = covered, covered_split
        else:
            kept, kept_split = covered, _mix((half, covered_split), (half, kept_split))
        if kept:
            held.append({"piece": event.loss_event_id, "kind": "deductible", "value": kept, "split": kept_split})
        beyond = covered - deductible - limit
        if beyond > 0:
            whole = covered + deductible + limit
            held.append({"piece": event.loss_event_id, "kind": "beyond_limit", "value": beyond,
                         "split": _mix((covered / whole, covered_split), (deductible / whole, _alone(terms["deductible"])),
                                       (limit / whole, _alone(terms["limit"])))})
        recovery = min(max(covered - deductible, Fraction(0)), limit, gross)
        retained = gross - recovery
        if sum((piece["value"] for piece in held), Fraction(0)) != retained:
            raise sim.InvariantBroken(f"the retained cash of {event.loss_event_id} at base is not the sum of its pieces")
        pieces.extend(held)
        retained_total += retained
    return pieces, retained_total


def _line(p: ss._Plan, line: str, pieces: list[dict], total: Fraction, reads: list[str],
          why_not: str | None) -> dict:
    """One line's level record: each piece's share (its base over the line's,
    times one half beside a frequency), each parameter's (the sum of its parts of
    every piece, and the frequency's one half); the shares sum to exactly one."""
    frequency = p.frequency
    severity = Fraction(1, 2) if frequency is not None else Fraction(1)
    shares: dict[str, Fraction] = dict.fromkeys(reads, Fraction(0))
    rows = []
    if why_not is None:
        for piece in pieces:
            share = severity * piece["value"] / total
            for name, weight in piece["split"].items():
                shares[name] = shares.get(name, Fraction(0)) + share * weight
            row = {
                "piece": piece["piece"],
                "kind": piece["kind"],
                "base": _exact_text(piece["value"]),
                "share": _text(share),
                "split": [{"parameter": name, "share": _text(share * weight)}
                          for name, weight in sorted(piece["split"].items())],
            }
            if "inputs" in piece:
                row["inputs"] = piece["inputs"]
            if "terms" in piece:
                row["terms"] = piece["terms"]
            rows.append(row)
        if frequency is not None:
            shares[frequency.name] = Fraction(1, 2)
        if sum(shares.values(), Fraction(0)) != 1:
            raise sim.InvariantBroken(f"the {line} level shares sum to {sum(shares.values(), Fraction(0))}, not one")
    elif frequency is not None:
        shares[frequency.name] = Fraction(0)
    terms = {name: role for role, name in p.terms.items()}
    entries = []
    for name in sorted(shares):
        r = frequency if frequency is not None and name == frequency.name else p.resolved[name]
        entry = {
            "name": name,
            "base": decimal_text(_base(r.parameter.base)),
            "source_type": r.parameter.source_type.value,
            "share": _text(shares[name]),
            "fixed": not r.drawn,
            "frequency": r is frequency,
            "policy_term": terms.get(name),
            "derived_from": [],
            "supplied_by": [],
        }
        if r.contributors:
            entry["derived_from"] = [c.name for c in r.contributors]
            entry["supplied_by"] = [c.name for c in r.contributors if c.parameter.base == r.parameter.base]
        entries.append(entry)
    return {
        "line": line,
        "basis": f"base-case {line.replace('_', ' ')}" + (", a year: frequency x severity" if frequency else ""),
        "base": _exact_text(total),
        "frequency_base": None if frequency is None else decimal_text(_base(frequency.parameter.base)),
        "defined": why_not is None,
        "undefined_because": why_not,
        "pieces": rows,
        "parameters": entries,
    }


def level_shares(p: ss._Plan) -> dict:
    """Each figure's share of the level of the gross cash and, under a policy, of
    the retained cash (:data:`LEVEL`): an additive decomposition at base. A line
    whose base case is zero, or a run whose frequency's base is zero, has no level
    (``defined`` false, and why)."""
    frequency_zero = p.frequency is not None and _base(p.frequency.parameter.base) == 0
    cash = [c for c in p.components if c.estimated and c.cash]
    gross_reads = sorted({name for c in cash for name in c.reads.values()})
    no_level = None
    components: list[dict] = []
    try:
        components = [_component(p, c) for c in cash]
    except _NoLevel as why:
        no_level = str(why)
    gross = sum((c["value"] for c in components), Fraction(0))
    if no_level is None and frequency_zero:
        no_level = "the frequency's base is zero: a base-case year holds no occurrence, so there is no level to weigh"
    why_gross = no_level
    if why_gross is None and gross == 0:
        why_gross = "the base-case gross cash is zero, or reads no figure: there is no level to weigh"
    lines = {ss.GROSS_CASH: _line(p, ss.GROSS_CASH, components, gross, gross_reads, why_gross),
             ss.RETAINED_CASH: None}
    if p.si.policy is not None:
        pieces, retained, why_retained = [], Fraction(0), no_level
        if why_retained is None:
            try:
                pieces, retained = _retained_pieces(p, components)
            except _NoLevel as why:
                why_retained = str(why)
        if why_retained is None and retained == 0:
            why_retained = (
                "the base-case retained cash is zero (at base the policy recovers all of it, or the gross is zero): "
                "there is no level to weigh"
            )
        reads = sorted(set(gross_reads) | set(p.terms.values()))
        lines[ss.RETAINED_CASH] = _line(p, ss.RETAINED_CASH, pieces, retained, reads, why_retained)
    return lines


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
    # A residual run's reductions (spec, section 28): ranked like any parameter, on
    # their own yearly draws from their own streams, and swung through the factor
    # they put on each reduced component. A point mass is fixed; a reduction that
    # changes no cash component is not in the gross cash. None for any other run.
    reduces_cash = any(c.reduced and c.cash for c in p.components)
    for r in ss.reductions(p):
        if not r.drawn:
            fixed.append({"name": r.name, "value": decimal_text(r.point)})
            values[r.name] = float(r.point)
            continue
        if not reduces_cash:
            not_in_gross.append(r.name)
            continue
        drawn = np.asarray(ss.draw_reduction(r, sim.RunRandom(seed), draws), dtype=np.float64)
        rank(r.name, drawn, r)
        del drawn
        check_time(f"sensitivity {r.name}")
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
