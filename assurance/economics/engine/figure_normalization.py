"""A figure a run reads, normalized into the run's reporting currency at its valuation
date when its build is made, and the record that says how (``docs/economics/spec-v1.md``,
section 36).

A money figure of a customer's parameter-set version that a build reads is stated in
its own currency as of its own ``effective_date``. Where the build states a
normalization policy, a figure in another currency than the build's, or stated at
another date than the build's as-of date (the run's valuation date), is normalized in
section 12.4's order -- event-date FX into the base currency, the base's cost index to
the valuation month, valuation-date FX into the reporting currency -- each of its low,
base and high, and the build reads the NORMALIZED figure (:data:`PREFIX` and the
variable's name, a parameter of the scenario version) in its place. The native figure
is never overwritten.

:func:`record_of` makes the per-figure record: the native figure, the normalized one,
the policy, each point's normalization record (section 12.6) with its chain, and the
downgrades, conflicts and fallbacks they carry, and the source versions they read.
:func:`record_refusal` holds a record to its two figures and REPLAYS each chain: every
step's output is its input times the factor (or ratio) it records, at the engine's
precision, each step's output the next one's input, and the last the point's value; the
normalized figure is that value at a parameter's precision (:data:`PARAMETER_PLACES`).
So the record reproduces the figure from what it lists, digit for digit.

Pure: no Django, no I/O.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from decimal import ROUND_HALF_EVEN, Decimal

from .money import MoneyRefused, compute, decimal_text, parse_decimal
from .parameters import MONEY_UNITS, POINTS, Parameter

#: The rule a build normalizes a figure by; a change to what it records or how it
#: rounds is a new version.
VERSION = "mythos.economics.run-normalization/v1"
#: The name of a figure's normalized copy, a parameter of the scenario version: this
#: and the parameter-set variable's name (an effect attribute is ``<effect>.<name>`` and
#: a derived value ``ev-...:<name>``, so neither is ever spelled so).
PREFIX = "normalized:"
#: A parameter holds at most 20 places after its point (spec, section 14,
#: ``value_too_long``): the normalized figure is each point's value rounded half-even
#: to them; the record keeps the value at full precision.
PARAMETER_PLACES = 20
_QUANTUM = Decimal(1).scaleb(-PARAMETER_PLACES)
ROUNDING = (
    f"each point's normalized value, ROUND_HALF_EVEN to {PARAMETER_PLACES} places: a parameter's precision (spec, "
    "section 14); the point's record keeps the value at full precision"
)
_KEYS = frozenset({
    "rule", "figure", "native", "normalized", "event_date", "valuation_date", "policy", "points",
    "confidence_downgrades", "conflicts", "primary_unavailable", "sources", "rounding",
})


def figure_name(native_name: str) -> str:
    return PREFIX + native_name


def needs_normalizing(parameter: Parameter, *, currency: str, valuation_date) -> bool:
    """Whether ``parameter``, a money figure, is stated in another currency than
    ``currency`` or at another date than ``valuation_date``."""
    return parameter.unit in MONEY_UNITS and (
        parameter.currency != currency or parameter.effective_date != valuation_date
    )


def parameter_value(value: Decimal) -> Decimal:
    """A point's normalized value at a parameter's precision (:data:`ROUNDING`)."""
    return compute(lambda: value.quantize(_QUANTUM, rounding=ROUND_HALF_EVEN))


def _union(lists) -> list:
    """The items of ``lists``, each once, in the order first met (compared as JSON)."""
    found, seen = [], set()
    for items in lists:
        for item in items:
            key = json.dumps(item, sort_keys=True)
            if key not in seen:
                seen.add(key)
                found.append(item)
    return found


def record_of(
    *,
    native: Parameter,
    parameter_set: Mapping,
    normalized: Parameter,
    points: Mapping[str, dict],
    policy: Mapping,
    sources: list[dict],
) -> dict:
    """The record of one normalized figure. ``points`` is each point's normalization
    record (``Normalization.as_dict()``), by point; ``sources`` the source versions
    those records read, each with its key, version, tenant, provider, licence, tier and
    snapshot hash."""
    ordered = [points[point.value] for point in POINTS]
    base = points["base"]
    return {
        "rule": VERSION,
        "figure": normalized.name,
        "native": {
            "parameter": native.parameter_id,
            "name": native.name,
            "parameter_set": dict(parameter_set),
            "unit": native.unit.value,
            "currency": native.currency,
            **{point.value: Parameter.text(native.at(point)) for point in POINTS},
            "effective_date": native.effective_date.isoformat(),
        },
        "normalized": {
            "parameter": normalized.parameter_id,
            "currency": normalized.currency,
            **{point.value: Parameter.text(normalized.at(point)) for point in POINTS},
        },
        "rounding": ROUNDING,
        "event_date": base["event_date"],
        "valuation_date": base["valuation_date"],
        "policy": dict(policy),
        "points": {point.value: points[point.value] for point in POINTS},
        "confidence_downgrades": _union(record["confidence_downgrades"] for record in ordered),
        "conflicts": _union(record["conflicts"] for record in ordered),
        "primary_unavailable": _union(record["primary_unavailable"] for record in ordered),
        "sources": sorted(sources, key=lambda s: (s["source_key"], s["tenant"], s["version"])),
    }


def _amount(money_record, what: str) -> tuple[Decimal, str]:
    if not isinstance(money_record, Mapping):
        raise MoneyRefused("snapshot_malformed", f"{what} is not an amount")
    return parse_decimal(money_record.get("amount"), what), money_record.get("currency")


def _replay(record: Mapping, what: str) -> Decimal:
    """The point record's value, replayed from its chain (see the module's rules), or
    a refusal naming the step that does not reproduce."""
    if record.get("status") != "normalized" or not isinstance(record.get("chain"), list):
        raise MoneyRefused("snapshot_malformed", f"{what} is not a normalized record with its chain")
    chain = record["chain"]
    if [step.get("step") if isinstance(step, Mapping) else None for step in chain] != list(record.get("order") or []):
        raise MoneyRefused("snapshot_malformed", f"{what}: the chain is not the normalization order")
    carried = record.get("native")
    for step in chain:
        if step.get("input") != carried:
            raise MoneyRefused("snapshot_malformed", f"{what}: {step.get('step')} does not take the step before's output")
        amount, _ = _amount(step["input"], f"{what} {step['step']} input")
        multiplier = step.get("ratio") if step.get("step") == "cost_index" else step.get("factor")
        product = compute(lambda a=amount, m=parse_decimal(multiplier, f"{what} {step['step']} factor"): a * m)
        output, _ = _amount(step.get("output"), f"{what} {step['step']} output")
        if decimal_text(product) != decimal_text(output):
            raise MoneyRefused("snapshot_malformed", f"{what}: {step['step']} is not its input times its factor")
        carried = step["output"]
    if carried != record.get("value"):
        raise MoneyRefused("snapshot_malformed", f"{what}: the last step's output is not the value")
    value, _ = _amount(record["value"], f"{what} value")
    return value


def record_refusal(record, *, native: Parameter, normalized: Parameter) -> str | None:
    """Why ``record`` is not the record of normalizing ``native`` into ``normalized``,
    or ``None``: its form, both figures as it names them, and every point's chain
    replayed (see the module's rules). Pure."""
    if not isinstance(record, Mapping) or set(record) != _KEYS:
        return "the record is an object of exactly its fields"
    if record["rule"] != VERSION or record["figure"] != normalized.name or normalized.name != figure_name(native.name):
        return "the record names its rule and the normalized figure of its native figure"
    if normalized.unit is not native.unit or normalized.source_type is not native.source_type:
        return "the normalized figure keeps its native figure's unit and source"
    held_native = record["native"]
    if not isinstance(held_native, Mapping) or held_native.get("parameter") != native.parameter_id or any(
        held_native.get(point.value) != Parameter.text(native.at(point)) for point in POINTS
    ) or held_native.get("currency") != native.currency:
        return "the record's native figure is not the parameter-set variable it names"
    held = record["normalized"]
    if not isinstance(held, Mapping) or held.get("parameter") != normalized.parameter_id or held.get(
        "currency"
    ) != normalized.currency or any(held.get(point.value) != Parameter.text(normalized.at(point)) for point in POINTS):
        return "the record's normalized figure is not the scenario parameter it names"
    points = record["points"]
    if not isinstance(points, Mapping) or set(points) != {point.value for point in POINTS}:
        return "the record holds the normalization of the low, the base and the high"
    try:
        for point in POINTS:
            one = points[point.value]
            if not isinstance(one, Mapping):
                return f"the {point.value} is not a normalization record"
            if one.get("native") != {"amount": Parameter.text(native.at(point)), "currency": native.currency}:
                return f"the {point.value}'s native amount is not the figure's"
            if (one.get("event_date"), one.get("valuation_date")) != (record["event_date"], record["valuation_date"]):
                return f"the {point.value} is normalized on other dates than the record's"
            if one.get("reporting_currency") != normalized.currency or one.get("policy") != record["policy"]:
                return f"the {point.value} is normalized under another policy or into another currency"
            value = _replay(one, point.value)
            if Parameter.text(normalized.at(point)) != decimal_text(parameter_value(value)):
                return f"the normalized {point.value} is not its record's value at a parameter's precision"
    except MoneyRefused as refused:
        return refused.detail or refused.code
    ordered = [points[point.value] for point in POINTS]
    for field in ("confidence_downgrades", "conflicts", "primary_unavailable"):
        if record[field] != _union(one[field] for one in ordered):
            return f"the record's {field} are not its points'"
    return None


__all__ = [
    "PARAMETER_PLACES",
    "PREFIX",
    "ROUNDING",
    "VERSION",
    "figure_name",
    "needs_normalizing",
    "parameter_value",
    "record_of",
    "record_refusal",
]
