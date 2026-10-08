"""Economic Exposure's scenario engine, with no database and no Django.

:mod:`assurance.economics.engine.parameters`, :mod:`.formulas`, :mod:`.loss` and
:mod:`.parameter_set` (``docs/economics/spec-v1.md``, sections 14 to 19). Pinned
here, for every formula in the catalogue:

- a known answer, computed by hand in the comment beside it;
- ``0 <= low <= base <= high``;
- monotonicity in every input, by a deterministic sweep (the repo does not use
  hypothesis): with every other input held at several settings, raising one input
  never lowers the loss where it ``increases`` it and never raises it where it
  ``decreases`` it; and widening one parameter's range moves only the end of the
  result its direction says;
- a parameter of another unit is refused, money in two currencies is refused,
  and a missing input gives an ``unknown`` component, never a zero;

and for the engine as a whole: insurance applied once and never leaving a
negative retained loss, market value never summed into cash, the adversarial
inputs of the owner's specification (section 27: NaN, negative counts, rates
above 1, unit mismatch, date inversion, duplicate ids), seed-free determinism,
and the customer parameter set's schema. The two worked examples are
``tests/test_economics_known_answers.py``.
"""

from __future__ import annotations

import ast
import dataclasses
import hashlib
import json
import os
import subprocess
import sys
import textwrap
from datetime import date, datetime
from decimal import Decimal
from pathlib import Path

import pytest

from assurance.economics.engine import formulas, loss, parameter_set, parameters
from assurance.economics.engine import money as money_engine
from assurance.economics.engine.formulas import (
    CATALOGUE,
    COMPONENT_FAMILIES,
    ESTIMATED,
    MARKET_VALUE,
    UNKNOWN,
    Direction,
    evaluate,
)
from assurance.economics.engine.loss import (
    GrossLoss,
    InsurancePolicy,
    LossEvent,
    apply_insurance,
    assess,
    cash_total,
)
from assurance.economics.engine.money import Money, MoneyRefused
from assurance.economics.engine.parameters import MONEY_UNITS, POINTS, Parameter, Point, Unit
from assurance.economics.engine.taxonomy import LossFamily

REPO = Path(__file__).resolve().parent.parent
ENGINE = REPO / "assurance" / "economics" / "engine"
AS_OF = date(2026, 10, 6)


def money(value, currency="USD") -> Money:
    return Money(Decimal(str(value)), currency)


def param(name, unit, low, base=None, high=None, *, source="CUSTOMER_PROVIDED", currency="USD", **over) -> Parameter:
    """A parameter of ``unit`` from plain figures: ``low`` alone is a point value."""
    base = low if base is None else base
    high = base if high is None else high
    unit = Unit(unit)

    def value(figure):
        return money(figure, currency) if unit in MONEY_UNITS else Decimal(str(figure))

    fields = {"evidence_ref": f"test: {name}", "effective_date": date(2026, 9, 1)}
    fields.update(over)
    return Parameter(name, unit, source, value(low), value(base), value(high), **fields)


def amounts(component) -> tuple[Decimal, Decimal, Decimal]:
    return tuple(component.at(point).amount for point in POINTS)


def run(formula_id, family, figures, *, version=1, component_id="c", **kwargs):
    """Evaluate ``formula_id`` from ``figures``: {input: (low, base, high)}."""
    chosen = CATALOGUE[(formula_id, version)]
    bindings = {}
    for spec in chosen.inputs:
        if spec.name in figures:
            low, base, high = figures[spec.name]
            source = "CUSTOMER_PROVIDED"
            bindings[spec.name] = param(spec.name, spec.unit, low, base, high, source=source)
    return evaluate(component_id, family, formula_id, version, bindings, as_of=AS_OF, **kwargs)


# ------------------------------------------------------------ the catalogue

#: One known answer per formula: (family, {input: (low, base, high)}, (low, base, high)).
#: Every expected figure is worked by hand beside it, in the input's direction.
KNOWN_ANSWERS = {
    # low:  10 x 1,000 x (1 - 0.9)  =  1,000   (recovery decreases loss: low reads its HIGH)
    # base: 20 x 1,500 x (1 - 0.6)  = 12,000
    # high: 40 x 2,000 x (1 - 0.5)  = 40,000   (high reads recovery's LOW)
    "repeat_loss": (
        "direct_financial",
        {"repeat_count": (10, 20, 40), "loss_per_event": (1000, 1500, 2000), "recovery_rate": ("0.5", "0.6", "0.9")},
        ("1000", "12000", "40000"),
    ),
    # 2,400 a day is 100 an hour.
    # low:  100 x 1 h x 0.1 x 50 x (1 - 0.6) =   200
    # base: 100 x 2 h x 0.2 x 50 x (1 - 0.4) = 1,200
    # high: 100 x 4 h x 0.3 x 50 x (1 - 0.2) = 4,800
    "repeat_in_window": (
        "direct_financial",
        {
            "transactions_per_day": (2400, 2400, 2400),
            "window_hours": (1, 2, 4),
            "success_rate": ("0.1", "0.2", "0.3"),
            "value_per_transaction": (50, 50, 50),
            "recovery_rate": ("0.2", "0.4", "0.6"),
        },
        ("200", "1200", "4800"),
    ),
    # 2 x 1,000 = 2,000; 6 x 1,500 = 9,000; 18 x 2,500 = 45,000
    "interruption": (
        "business_interruption",
        {"interruption_hours": (2, 6, 18), "value_per_hour": (1000, 1500, 2500)},
        ("2000", "9000", "45000"),
    ),
    # 1,000 + 100 x 10 = 2,000; 2,000 + 150 x 20 = 5,000; 3,000 + 200 x 40 = 11,000
    "fixed_plus_hours": (
        "incident_response",
        {"fixed_cost": (1000, 2000, 3000), "hourly_rate": (100, 150, 200), "hours": (10, 20, 40)},
        ("2000", "5000", "11000"),
    ),
    # 100 x 2 + 500 = 700; 200 x 3 + 1,000 = 1,600; 400 x 4 + 2,000 = 3,600
    "per_affected_plus_fixed": (
        "notification",
        {"affected": (100, 200, 400), "unit_cost": (2, 3, 4), "fixed_cost": (500, 1000, 2000)},
        ("700", "1600", "3600"),
    ),
    # 100 x 10 = 1,000; 200 x 20 = 4,000; 400 x 25 = 10,000
    "per_affected": (
        "customer_restitution",
        {"affected": (100, 200, 400), "amount_per_affected": (10, 20, 25)},
        ("1000", "4000", "10000"),
    ),
    # 1,000 x 0.1 x 0.5 h x 40 = 2,000; 2,000 x 0.2 x 0.5 h x 50 = 10,000; 4,000 x 0.25 x 1 h x 60 = 60,000
    "support_contacts": (
        "notification",
        {
            "affected": (1000, 2000, 4000),
            "contact_rate": ("0.1", "0.2", "0.25"),
            "handling_hours": ("0.5", "0.5", "1"),
            "loaded_rate": (40, 50, 60),
        },
        ("2000", "10000", "60000"),
    ),
    # min(100 x 5, 1,000) = 500; min(200 x 10, 1,500) = 1,500 (capped); min(300 x 20, 10,000) = 6,000
    "capped_credit": (
        "contractual",
        {"credit_per_hour": (100, 200, 300), "breach_hours": (5, 10, 20), "contract_cap": (1000, 1500, 10000)},
        ("500", "1500", "6000"),
    ),
    # 10,000 x 0.1 = 1,000; 20,000 x 0.25 = 5,000; 40,000 x 0.5 = 20,000
    "replacement_share": (
        "data_and_ip",
        {"replacement_cost": (10000, 20000, 40000), "share_compromised": ("0.1", "0.25", "0.5")},
        ("1000", "5000", "20000"),
    ),
    # 1,000 x 0.01 x 100 x 1 y = 1,000; 2,000 x 0.02 x 150 x 2 y = 12,000; 4,000 x 0.05 x 200 x 3 y = 120,000
    "churned_margin": (
        "customer_loss",
        {
            "customers": (1000, 2000, 4000),
            "churn_rate": ("0.01", "0.02", "0.05"),
            "margin_per_customer_per_year": (100, 150, 200),
            "recovery_years": (1, 2, 3),
        },
        ("1000", "12000", "120000"),
    ),
    # 10,000 x 1 = 10,000; 20,000 x 2 = 40,000; 30,000 x 3 = 90,000
    "premium_increase": (
        "insurance",
        {"premium_increase_per_year": (10000, 20000, 30000), "years": (1, 2, 3)},
        ("10000", "40000", "90000"),
    ),
    # the amount as given
    "lump_sum": ("legal", {"amount": (80000, 165000, 250000)}, ("80000", "165000", "250000")),
    # 1,000,000 x 0.01 = 10,000; x 0.02 = 20,000; x 0.05 = 50,000
    "share_price_reaction": (
        MARKET_VALUE,
        {"market_capitalisation": (1000000, 1000000, 1000000), "price_decline": ("0.01", "0.02", "0.05")},
        ("10000", "20000", "50000"),
    ),
}


def test_every_formula_has_a_known_answer_and_every_family_a_formula():
    assert {formula_id for formula_id, _ in CATALOGUE} == set(KNOWN_ANSWERS)
    served = set().union(*(f.families for f in CATALOGUE.values()))
    assert served == COMPONENT_FAMILIES == {f.value for f in LossFamily} | {MARKET_VALUE}
    for chosen in CATALOGUE.values():
        names = [i.name for i in chosen.inputs]
        assert len(names) == len(set(names)), chosen.formula_id
        assert chosen.families <= COMPONENT_FAMILIES
        assert all(isinstance(family, str) and type(family) is str for family in chosen.families)
    # Market value is computed by one formula, which computes nothing else.
    assert {f.formula_id for f in CATALOGUE.values() if MARKET_VALUE in f.families} == {"share_price_reaction"}
    assert CATALOGUE[("share_price_reaction", 1)].families == {MARKET_VALUE}
    # Customer loss only from the customer's own churn figure: never a lump sum.
    assert "customer_loss" not in CATALOGUE[("lump_sum", 1)].families


@pytest.mark.parametrize("formula_id", sorted(KNOWN_ANSWERS))
def test_known_answer(formula_id):
    family, figures, expected = KNOWN_ANSWERS[formula_id]
    component = run(formula_id, family, figures)
    assert component.status == ESTIMATED
    assert amounts(component) == tuple(Decimal(e) for e in expected)
    assert component.currency == "USD"
    assert component.formula.key == (formula_id, 1)
    record = component.as_dict()
    assert record["formula"] == {
        "formula_id": formula_id,
        "version": 1,
        "expression": CATALOGUE[(formula_id, 1)].expression,
    }
    assert record["insurance_treatment"] == "gross"
    # The provenance of every input stays attached to the output.
    assert {row["input"] for row in record["inputs"]} == set(figures)
    for row in record["inputs"]:
        assert row["parameter"]["source_type"] == "CUSTOMER_PROVIDED"
        assert row["parameter"]["evidence_ref"] == f"test: {row['input']}"


@pytest.mark.parametrize("formula_id", sorted(KNOWN_ANSWERS))
def test_low_base_high_are_ordered_and_never_negative(formula_id):
    family, figures, _ = KNOWN_ANSWERS[formula_id]
    low, base, high = amounts(run(formula_id, family, figures))
    assert Decimal(0) <= low <= base <= high


# ----------------------------------------------------------- monotonicity

#: A ladder of values each input is swept through, by unit.
LADDER = {
    Unit.RATIO: ["0", "0.05", "0.3", "0.5", "0.95", "1"],
    Unit.COUNT: ["0", "1", "7", "250", "18000"],
    Unit.COUNT_PER_DAY: ["0", "24", "2400", "18000"],
    Unit.HOURS: ["0", "0.5", "2", "18", "720"],
    Unit.YEARS: ["0", "1", "2.5", "5"],
    Unit.DAYS: ["0", "1", "30"],
}
MONEY_LADDER = ["0", "1.50", "75", "25000", "1500000"]


def _ladder(unit):
    return MONEY_LADDER if unit in MONEY_UNITS else LADDER[unit]


def _settings(chosen):
    """Several settings of every input: all at the ladder's second rung, all at its
    second-highest, and alternating, so a sweep is not read at one corner only."""
    names = [i.name for i in chosen.inputs]
    rungs = []
    for pick in (1, -2, None):
        setting = {}
        for position, spec in enumerate(chosen.inputs):
            ladder = _ladder(spec.unit)
            index = pick if pick is not None else (1 if position % 2 else -2)
            setting[spec.name] = ladder[index]
        rungs.append(setting)
    return names, rungs


@pytest.mark.parametrize("formula_id", sorted(KNOWN_ANSWERS))
def test_every_formula_is_monotone_in_every_input(formula_id):
    """Deterministic sweep: each input through its ladder, every other input held at
    each setting; the loss never moves against the input's declared direction."""
    chosen = CATALOGUE[(formula_id, 1)]
    _, settings = _settings(chosen)
    for spec in chosen.inputs:
        for setting in settings:
            results = []
            for value in _ladder(spec.unit):
                figures = {name: (v, v, v) for name, v in setting.items()}
                figures[spec.name] = (value, value, value)
                family = sorted(chosen.families)[0]
                results.append(run(formula_id, family, figures).base.amount)
            ordered = results if spec.direction is Direction.INCREASES else list(reversed(results))
            assert ordered == sorted(ordered), (formula_id, spec.name, setting, results)


@pytest.mark.parametrize("formula_id", sorted(KNOWN_ANSWERS))
def test_widening_one_input_moves_only_the_end_its_direction_says(formula_id):
    """The low result reads each input's low where it increases the loss and its
    high where it decreases it, the high result the other way round. Widening one
    parameter upward from a point therefore raises only the HIGH result of an
    input that increases the loss, and lowers only the LOW result of one that
    decreases it (a higher recovery rate lowers loss)."""
    chosen = CATALOGUE[(formula_id, 1)]
    family = sorted(chosen.families)[0]
    _, settings = _settings(chosen)
    setting = settings[2]
    point = {name: (v, v, v) for name, v in setting.items()}
    before = amounts(run(formula_id, family, point))
    for spec in chosen.inputs:
        ladder = _ladder(spec.unit)
        here = ladder.index(setting[spec.name])
        wider = ladder[min(here + 1, len(ladder) - 1)]
        if wider == setting[spec.name]:
            continue
        figures = dict(point)
        figures[spec.name] = (setting[spec.name], setting[spec.name], wider)
        low, base, high = amounts(run(formula_id, family, figures))
        assert base == before[1], (formula_id, spec.name)
        if spec.direction is Direction.INCREASES:
            assert low == before[0] and high >= before[2], (formula_id, spec.name)
        else:
            assert high == before[2] and low <= before[0], (formula_id, spec.name)


def test_a_higher_recovery_rate_lowers_the_loss():
    """The direction stated in words, on the formula the brief names: direct loss =
    repeat count x loss per event x (1 - recovery rate)."""
    spec = CATALOGUE[("repeat_loss", 1)].input("recovery_rate")
    assert spec.direction is Direction.DECREASES
    assert spec.end(Point.LOW) is Point.HIGH and spec.end(Point.HIGH) is Point.LOW
    lower = run("repeat_loss", "direct_financial", {"repeat_count": (1, 1, 1), "loss_per_event": (100, 100, 100),
                                                     "recovery_rate": ("0.2", "0.2", "0.2")})
    higher = run("repeat_loss", "direct_financial", {"repeat_count": (1, 1, 1), "loss_per_event": (100, 100, 100),
                                                      "recovery_rate": ("0.8", "0.8", "0.8")})
    assert higher.base < lower.base
    for chosen in CATALOGUE.values():
        for spec in chosen.inputs:
            expected = Direction.DECREASES if spec.name == "recovery_rate" else Direction.INCREASES
            assert spec.direction is expected, (chosen.formula_id, spec.name)


# --------------------------------------------- units, currencies, unknowns

_OTHER_UNIT = {unit: (Unit.HOURS if unit in MONEY_UNITS else Unit.MONEY) for unit in Unit}
_OTHER_UNIT[Unit.HOURS] = Unit.DAYS
_OTHER_UNIT[Unit.DAYS] = Unit.HOURS
_OTHER_UNIT[Unit.MONEY] = Unit.MONEY_PER_UNIT
_OTHER_UNIT[Unit.MONEY_PER_UNIT] = Unit.MONEY
_OTHER_UNIT[Unit.MONEY_PER_HOUR] = Unit.MONEY_PER_YEAR
_OTHER_UNIT[Unit.MONEY_PER_YEAR] = Unit.MONEY_PER_HOUR


def _bindings(formula_id, currency="USD"):
    family, figures, _ = KNOWN_ANSWERS[formula_id]
    chosen = CATALOGUE[(formula_id, 1)]
    return family, {
        spec.name: param(spec.name, spec.unit, *figures[spec.name], currency=currency) for spec in chosen.inputs
    }


@pytest.mark.parametrize("formula_id", sorted(KNOWN_ANSWERS))
def test_a_parameter_of_another_unit_is_refused(formula_id):
    chosen = CATALOGUE[(formula_id, 1)]
    family, bindings = _bindings(formula_id)
    for spec in chosen.inputs:
        other = _OTHER_UNIT[spec.unit]
        wrong = dict(bindings)
        wrong[spec.name] = param(spec.name, other, "0.5")
        with pytest.raises(MoneyRefused) as refused:
            evaluate("c", family, formula_id, 1, wrong, as_of=AS_OF)
        assert refused.value.code == "unit_mismatch", (formula_id, spec.name)


@pytest.mark.parametrize("formula_id", sorted(KNOWN_ANSWERS))
def test_money_in_two_currencies_is_refused(formula_id):
    chosen = CATALOGUE[(formula_id, 1)]
    money_inputs = [spec for spec in chosen.inputs if spec.unit in MONEY_UNITS]
    assert money_inputs, formula_id
    family, bindings = _bindings(formula_id)
    if len(money_inputs) == 1:
        # One money input: the component is in its currency, and the EVENT refuses
        # a component in another currency than its own.
        euro = dict(bindings)
        spec = money_inputs[0]
        euro[spec.name] = param(spec.name, spec.unit, *KNOWN_ANSWERS[formula_id][1][spec.name], currency="EUR")
        component = evaluate("c", family, formula_id, 1, euro, as_of=AS_OF)
        assert component.currency == "EUR"
        with pytest.raises(MoneyRefused) as refused:
            LossEvent("e", "USD", (component,))
        assert refused.value.code == "currency_mismatch"
        return
    quantity = next(spec.name for spec in chosen.inputs if spec.unit not in MONEY_UNITS)
    for spec in money_inputs:
        mixed = dict(bindings)
        mixed[spec.name] = param(spec.name, spec.unit, *KNOWN_ANSWERS[formula_id][1][spec.name], currency="EUR")
        with pytest.raises(MoneyRefused) as refused:
            evaluate("c", family, formula_id, 1, mixed, as_of=AS_OF)
        assert refused.value.code == "currency_mismatch", (formula_id, spec.name)
        # Refused too when an input is missing and nothing is computed: an unknown
        # component is never filed under one of two currencies.
        partial = {name: p for name, p in mixed.items() if name != quantity}
        with pytest.raises(MoneyRefused) as refused:
            evaluate("c", family, formula_id, 1, partial, as_of=AS_OF)
        assert refused.value.code == "currency_mismatch", (formula_id, spec.name, "unknown")


@pytest.mark.parametrize("formula_id", sorted(KNOWN_ANSWERS))
def test_a_missing_input_gives_unknown_never_zero(formula_id):
    chosen = CATALOGUE[(formula_id, 1)]
    family, bindings = _bindings(formula_id)
    for spec in chosen.inputs:
        partial = {name: p for name, p in bindings.items() if name != spec.name}
        component = evaluate("c", family, formula_id, 1, partial, as_of=AS_OF)
        assert component.status == UNKNOWN, (formula_id, spec.name)
        assert component.unknown_reason == "input_missing"
        assert component.missing == (spec.name,)
        assert component.low is component.base is component.high is None
        with pytest.raises(ValueError):
            component.at(Point.BASE)
        record = component.as_dict()
        assert (record["low"], record["base"], record["high"]) == (None, None, None)
        assert record["unknown"] == {"reason": "input_missing", "inputs": [spec.name]}
        # And a total that holds it is incomplete: the known part is a floor, and
        # the unknown one is named, never read as zero.
        known = run("lump_sum", "legal", {"amount": (100, 200, 300)}, component_id="known")
        if component.cash:
            total = cash_total((known, component), "USD")
            assert not total.complete and total.unknown == ("c",)
            assert total.as_dict()["reads_as"] == "at least: the known components only"


def test_customer_loss_needs_the_customers_own_churn_figure():
    """Spec section 31: customer loss only when customer data support it; otherwise
    Unknown. A benchmark churn rate gives an unknown component, never a figure."""
    family, bindings = _bindings("churned_margin")
    bindings["churn_rate"] = dataclasses.replace(bindings["churn_rate"], source_type="INDUSTRY_BENCHMARK")
    component = evaluate("churn", family, "churned_margin", 1, bindings, as_of=AS_OF)
    assert (component.status, component.unknown_reason, component.missing) == (
        UNKNOWN, "input_source_not_accepted", ("churn_rate",)
    )


# ---------------------------------------------------- refusals of the engine


def test_formula_family_and_input_refusals():
    family, bindings = _bindings("fixed_plus_hours")
    cases = [
        (("c", family, "no_such_formula", 1, bindings), "formula_unknown"),
        (("c", family, "fixed_plus_hours", 2, bindings), "formula_unknown"),
        (("c", "direct_financial", "fixed_plus_hours", 1, bindings), "formula_not_for_family"),
        (("c", "share_price", "fixed_plus_hours", 1, bindings), "loss_family_unrecognised"),
        (("c", MARKET_VALUE, "lump_sum", 1, {"amount": param("a", "money", 1)}), "formula_not_for_family"),
        (("c", "legal", "share_price_reaction", 1, {}), "formula_not_for_family"),
        (("c", family, "fixed_plus_hours", 1, {**bindings, "minutes": param("m", "hours", 1)}), "input_unrecognised"),
        (("", family, "fixed_plus_hours", 1, bindings), "required_field_blank"),
    ]
    for args, code in cases:
        with pytest.raises(MoneyRefused) as refused:
            evaluate(*args, as_of=AS_OF)
        assert refused.value.code == code, (args[:4], code)


ADVERSARIAL_PARAMETERS = [
    # (what, constructor, code)
    ("NaN", lambda: Parameter("n", Unit.COUNT, "CUSTOMER_PROVIDED", Decimal("NaN"), Decimal(1), Decimal(1), "e"), "not_finite"),
    ("signalling NaN", lambda: Parameter("n", Unit.COUNT, "CUSTOMER_PROVIDED", Decimal("sNaN"), Decimal(1), Decimal(1), "e"), "not_finite"),
    ("Infinity", lambda: Parameter("n", Unit.HOURS, "CUSTOMER_PROVIDED", Decimal(1), Decimal(1), Decimal("Infinity"), "e"), "not_finite"),
    ("a float", lambda: Parameter("n", Unit.COUNT, "CUSTOMER_PROVIDED", 1.5, Decimal(2), Decimal(3), "e"), "not_decimal"),
    ("an int", lambda: Parameter("n", Unit.COUNT, "CUSTOMER_PROVIDED", 1, Decimal(2), Decimal(3), "e"), "not_decimal"),
    ("a negative count", lambda: param("n", "count", -1, 2, 3), "negative_value"),
    ("a negative amount", lambda: param("n", "money", "-0.01", 2, 3), "negative_value"),
    ("a negative duration", lambda: param("n", "hours", 0, 0, "-1"), "negative_value"),
    ("a rate above 1", lambda: param("n", "ratio", "0.5", "0.9", "1.01"), "ratio_out_of_range"),
    ("a low above its base", lambda: param("n", "count", 3, 2, 4), "range_inverted"),
    ("a base above its high", lambda: param("n", "money", 1, 5, 4), "range_inverted"),
    ("money for a count", lambda: Parameter("n", Unit.COUNT, "CUSTOMER_PROVIDED", money(1), money(1), money(1), "e"), "unit_mismatch"),
    ("a count for money", lambda: Parameter("n", Unit.MONEY, "CUSTOMER_PROVIDED", Decimal(1), Decimal(1), Decimal(1), "e"), "unit_mismatch"),
    ("one parameter in two currencies", lambda: Parameter("n", Unit.MONEY, "CUSTOMER_PROVIDED", money(1), money(1), money(1, "EUR"), "e"), "currency_mismatch"),
    ("an unknown unit", lambda: Parameter("n", "furlongs", "CUSTOMER_PROVIDED", Decimal(1), Decimal(1), Decimal(1), "e"), "unit_unrecognised"),
    ("an unknown source type", lambda: param("n", "count", 1, source="A_BLOG_POST"), "source_type_unrecognised"),
    ("no evidence", lambda: param("n", "count", 1, evidence_ref="  "), "evidence_ref_missing"),
    ("no name", lambda: param("", "count", 1), "required_field_blank"),
    ("fresh until before it holds", lambda: param("n", "count", 1, effective_date=date(2026, 9, 1), fresh_until=date(2026, 8, 31)), "date_inversion"),
    ("a datetime for a date", lambda: param("n", "count", 1, effective_date=datetime(2026, 9, 1)), "date_malformed"),
]


@pytest.mark.parametrize("what, build, code", ADVERSARIAL_PARAMETERS, ids=[c[0] for c in ADVERSARIAL_PARAMETERS])
def test_an_adversarial_parameter_is_refused(what, build, code):
    with pytest.raises(MoneyRefused) as refused:
        build()
    assert refused.value.code == code


def test_a_parameter_from_after_the_runs_date_is_refused_and_a_stale_one_flagged():
    future = param("rate", "money_per_hour", 100, effective_date=date(2026, 10, 7))
    bindings = {"fixed_cost": param("fixed", "money", 1), "hourly_rate": future, "hours": param("hours", "hours", 1)}
    with pytest.raises(MoneyRefused) as refused:
        evaluate("c", "legal", "fixed_plus_hours", 1, bindings, as_of=AS_OF)
    assert refused.value.code == "date_inversion"
    bindings["hourly_rate"] = param("rate", "money_per_hour", 100, fresh_until=date(2026, 9, 30))
    component = evaluate("c", "legal", "fixed_plus_hours", 1, bindings, as_of=AS_OF)
    assert component.stale_inputs == ("hourly_rate",)
    assert component.as_dict()["stale_inputs"] == ["hourly_rate"]
    with pytest.raises(MoneyRefused) as refused:
        evaluate("c", "legal", "fixed_plus_hours", 1, bindings, as_of=datetime(2026, 10, 6))
    assert refused.value.code == "date_malformed"


def test_duplicate_ids_are_refused():
    a = run("lump_sum", "legal", {"amount": (1, 2, 3)}, component_id="same")
    b = run("lump_sum", "incident_response", {"amount": (1, 2, 3)}, component_id="same")
    with pytest.raises(MoneyRefused) as refused:
        LossEvent("e", "USD", (a, b))
    assert refused.value.code == "duplicate_id"
    # Two different parameters under one name, in one component and across an event.
    with pytest.raises(MoneyRefused) as refused:
        evaluate(
            "c", "legal", "fixed_plus_hours", 1,
            {"fixed_cost": param("x", "money", 1), "hourly_rate": param("x", "money_per_hour", 2),
             "hours": param("h", "hours", 1)},
            as_of=AS_OF,
        )
    assert refused.value.code == "duplicate_id"
    one = evaluate("one", "legal", "lump_sum", 1, {"amount": param("fee", "money", 1)}, as_of=AS_OF)
    two = evaluate("two", "recovery", "lump_sum", 1, {"amount": param("fee", "money", 2)}, as_of=AS_OF)
    with pytest.raises(MoneyRefused) as refused:
        LossEvent("e", "USD", (one, two))
    assert refused.value.code == "duplicate_id"
    # One parameter id naming two different parameters.
    first = param("fee", "money", 1, parameter_id="p-1")
    second = param("other", "money", 2, parameter_id="p-1")
    with pytest.raises(MoneyRefused) as refused:
        LossEvent("e", "USD", (
            evaluate("one", "legal", "lump_sum", 1, {"amount": first}, as_of=AS_OF),
            evaluate("two", "recovery", "lump_sum", 1, {"amount": second}, as_of=AS_OF),
        ))
    assert refused.value.code == "duplicate_id"
    # The same parameter read by two components is one parameter, and allowed.
    shared = param("fee", "money", 1, parameter_id="p-1")
    LossEvent("e", "USD", (
        evaluate("one", "legal", "lump_sum", 1, {"amount": shared}, as_of=AS_OF),
        evaluate("two", "recovery", "lump_sum", 1, {"amount": shared}, as_of=AS_OF),
    ))


def test_every_refusal_code_and_unknown_reason_is_published():
    """The codes themselves are pinned in tests/test_economics_engine.py, beside
    every other table's; here, that the scenario engine's refusal is a money
    refusal, so one ``except`` catches the engine's every refusal."""
    assert set(formulas.UNKNOWN_REASONS) == {"input_missing", "input_source_not_accepted"}
    refused = parameters.ParameterRefused("unit_mismatch", "detail")
    assert isinstance(refused, MoneyRefused) and refused.code == "unit_mismatch" and refused.detail == "detail"
    assert not set(parameters.REFUSALS) & set(money_engine.REFUSALS)
    with pytest.raises(KeyError):
        parameters.ParameterRefused("not_a_published_code")


# ------------------------------------------------------------------ insurance


def _legal(amounts_, component_id="legal", family="legal"):
    return evaluate(component_id, family, "lump_sum", 1, {"amount": param(component_id, "money", *amounts_)}, as_of=AS_OF)


def _policy(deductible, limit, **over):
    return InsurancePolicy(
        deductible=param("insurance_deductible", "money", *deductible),
        limit=param("insurance_limit", "money", *limit),
        **over,
    )


def _retained(event, policy):
    return tuple(assess(event, policy).insured.retained.at(p).amount for p in POINTS)


def test_insurance_known_answers():
    event = LossEvent("e", "USD", (_legal((1000, 1000, 1000)),))
    # 1,000 covered; less a 100 deductible is 900; capped at the 500 limit: 500 back, 500 kept.
    assert _retained(event, _policy((100,), (500,))) == (Decimal(500),) * 3
    # A deductible above the loss: nothing back, all kept.
    assert _retained(event, _policy((2000,), (500,))) == (Decimal(1000),) * 3
    # Excluded: all kept, whatever the policy says.
    assert _retained(event, _policy((0,), (10**9,), exclusions=frozenset({"legal"}))) == (Decimal(1000),) * 3
    # A 300 sublimit: 300 covered, less 100 is 200 back, 800 kept.
    sub = {"legal": param("insurance_sublimit:legal", "money", 300)}
    assert _retained(event, _policy((100,), (10**9,), sublimits=sub)) == (Decimal(800),) * 3


def test_insurance_reads_each_term_at_the_end_its_direction_says():
    """Retained loss rises with the deductible and falls with the limit: the LOW
    retained loss reads the low deductible and the HIGH limit."""
    event = LossEvent("e", "USD", (_legal((1000, 2000, 4000)),))
    insured = assess(event, _policy((100, 200, 400), (500, 1000, 3000))).insured
    # low:  1,000 - min(1,000 - 100, 3,000) =   100
    # base: 2,000 - min(2,000 - 200, 1,000) = 1,000
    # high: 4,000 - min(4,000 - 400,   500) = 3,500
    assert tuple(insured.retained.at(p).amount for p in POINTS) == (Decimal(100), Decimal(1000), Decimal(3500))
    assert loss.TERM_DIRECTIONS == {
        "deductible": Direction.INCREASES,
        "limit": Direction.DECREASES,
        "sublimit": Direction.DECREASES,
        "waiting_period_hours": Direction.INCREASES,
    }


def test_insurance_is_applied_once():
    event = LossEvent("e", "USD", (_legal((1000, 1000, 1000)),))
    policy = _policy((100,), (500,))
    insured = apply_insurance(GrossLoss.of(event), policy)
    with pytest.raises(MoneyRefused) as refused:
        apply_insurance(insured, policy)
    assert refused.value.code == "insurance_applied_twice"
    net = dataclasses.replace(event.components[0], insurance_treatment="net")
    with pytest.raises(MoneyRefused) as refused:
        apply_insurance(GrossLoss.of(LossEvent("e", "USD", (net,))), policy)
    assert refused.value.code == "insurance_applied_twice"
    # The retained loss is the gross less ONE recovery.
    point = insured.points[Point.BASE]
    assert point.retained == point.gross - point.recovery
    assert (point.gross.amount, point.recovery.amount, point.retained.amount) == (1000, 500, 500)


def test_retained_loss_is_never_negative():
    gross_cases = [(0, 0, 0), (1, 1, 1), (1000, 5000, 9000)]
    for gross in gross_cases:
        event = LossEvent("e", "USD", (_legal(gross), _legal(gross, "bi", "business_interruption")))
        for deductible in ((0,), (1,), (10**12,)):
            for limit in ((0,), (1,), (10**12,)):
                sub = {"legal": param("insurance_sublimit:legal", "money", 10**15)}
                retained = _retained(event, _policy(deductible, limit, sublimits=sub))
                assert all(r >= 0 for r in retained), (gross, deductible, limit, retained)
                assert retained[0] <= retained[1] <= retained[2]


def test_retained_loss_is_monotone_in_every_term_and_every_component():
    ladder = ["0", "50", "500", "5000", "50000"]

    def event(legal="1000", bi="2000"):
        return LossEvent("e", "USD", (
            _legal((legal,) * 3),
            evaluate("bi", "business_interruption", "lump_sum", 1, {"amount": param("bi", "money", bi)}, as_of=AS_OF),
        ))

    def kept(e, deductible="100", limit="1500", sublimit="800", waiting="0"):
        policy = _policy((deductible,), (limit,), sublimits={"legal": param("insurance_sublimit:legal", "money", sublimit)},
                         waiting_period_hours=param("insurance_waiting_period_hours", "hours", waiting))
        return assess(e, policy).insured.retained.base.amount

    rising = {
        "deductible": [kept(event(), deductible=v) for v in ladder],
        "waiting": [kept(event(), waiting=v) for v in ["0", "1", "24"]],
        "legal": [kept(event(legal=v)) for v in ladder],
        "bi": [kept(event(bi=v)) for v in ladder],
    }
    falling = {
        "limit": [kept(event(), limit=v) for v in ladder],
        "sublimit": [kept(event(), sublimit=v) for v in ladder],
    }
    for name, values in rising.items():
        assert values == sorted(values), (name, values)
    for name, values in falling.items():
        assert values == sorted(values, reverse=True), (name, values)


def test_what_a_policy_never_covers():
    premium = evaluate("premium", "insurance", "premium_increase", 1, {
        "premium_increase_per_year": param("p", "money_per_year", 1000), "years": param("y", "years", 2)}, as_of=AS_OF)
    bi = evaluate("bi", "business_interruption", "lump_sum", 1, {"amount": param("bi", "money", 5000)}, as_of=AS_OF)
    event = LossEvent("e", "USD", (premium, bi))
    # The premium rise is the policy's own cost: never covered. 5,000 BI covered in full.
    assert _retained(event, _policy((0,), (10**9,))) == (Decimal(2000),) * 3
    # A waiting period the engine does not apportion: BI not covered at all (the
    # side that never understates what is kept).
    waiting = param("insurance_waiting_period_hours", "hours", 0, 0, 12)
    low, base, high = _retained(event, _policy((0,), (10**9,), waiting_period_hours=waiting))
    assert (low, base, high) == (Decimal(2000), Decimal(2000), Decimal(7000))


def test_a_policy_is_refused_when_its_terms_are_wrong():
    cases = [
        (lambda: InsurancePolicy(param("d", "hours", 1), param("l", "money", 1)), "unit_mismatch"),
        (lambda: InsurancePolicy(param("d", "money", 1), param("l", "money", 1, currency="EUR")), "currency_mismatch"),
        (lambda: _policy((1,), (1,), sublimits={MARKET_VALUE: param("s", "money", 1)}), "loss_family_unrecognised"),
        (lambda: _policy((1,), (1,), exclusions=frozenset({"fines"})), "loss_family_unrecognised"),
        (lambda: _policy((1,), (1,), waiting_period_hours=param("w", "days", 1)), "unit_mismatch"),
    ]
    for build, code in cases:
        with pytest.raises(MoneyRefused) as refused:
            build()
        assert refused.value.code == code
    event = LossEvent("e", "USD", (_legal((1, 1, 1)),))
    euro = InsurancePolicy(param("d", "money", 1, currency="EUR"), param("l", "money", 1, currency="EUR"))
    with pytest.raises(MoneyRefused) as refused:
        assess(event, euro)
    assert refused.value.code == "currency_mismatch"


def test_insurance_on_an_incomplete_loss_is_a_floor():
    unknown = evaluate("forensics", "incident_response", "fixed_plus_hours", 1,
                       {"fixed_cost": param("f", "money", 1000)}, as_of=AS_OF)
    event = LossEvent("e", "USD", (_legal((1000, 1000, 1000)), unknown))
    result = assess(event, _policy((100,), (500,)))
    assert not result.gross.total.complete and not result.insured.retained.complete
    assert result.insured.retained.unknown == ("forensics",)
    assert result.as_dict()["retained_cash"]["reads_as"] == "at least: the known components only"


# -------------------------------------------------------------- market value


def test_market_value_is_never_summed_into_cash():
    reaction = run("share_price_reaction", MARKET_VALUE, KNOWN_ANSWERS["share_price_reaction"][1], component_id="mv")
    cash = _legal((1000, 2000, 3000))
    with pytest.raises(MoneyRefused) as refused:
        cash_total((cash, reaction), "USD")
    assert refused.value.code == "market_value_in_cash"
    event = LossEvent("e", "USD", (cash, reaction))
    result = assess(event, _policy((0,), (10**9,)))
    # Cash is the legal component alone; market value is on its own line.
    assert tuple(result.gross.total.at(p).amount for p in POINTS) == (Decimal(1000), Decimal(2000), Decimal(3000))
    assert tuple(result.market_value.at(p).amount for p in POINTS) == (Decimal(10000), Decimal(20000), Decimal(50000))
    record = result.as_dict()
    assert record["market_value"]["never_added_to_cash"] is True
    assert record["market_value"]["components"] == ["mv"]
    assert record["gross_cash"]["base"] == "2000"
    # The policy never sees it: everything insured is the 2,000 of cash.
    assert result.insured.points[Point.BASE].covered.amount == 2000
    with pytest.raises(MoneyRefused) as refused:
        loss.market_value_total((cash,), "USD")
    assert refused.value.code == "loss_family_unrecognised"


# ------------------------------------------------------------ determinism


def _worked_digest_script():
    return textwrap.dedent(
        """
        import hashlib, json
        from datetime import date
        from decimal import Decimal
        from assurance.economics.engine.money import Money
        from assurance.economics.engine.parameters import Parameter
        from assurance.economics.engine.formulas import evaluate
        from assurance.economics.engine.loss import InsurancePolicy, LossEvent, assess

        def p(name, unit, *values, cur="USD"):
            make = (lambda v: Money(Decimal(v), cur)) if unit.startswith("money") else Decimal
            return Parameter(name, unit, "EXPERT_ESTIMATE", *(make(v) for v in values), "determinism probe")

        as_of = date(2026, 10, 6)
        parts = (
            evaluate("notify", "notification", "per_affected_plus_fixed", 1, {
                "affected": p("affected", "count", "20000", "50000", "120000"),
                "unit_cost": p("unit", "money_per_unit", "1.5", "2", "3"),
                "fixed_cost": p("fixed", "money", "25000", "40000", "60000")}, as_of=as_of),
            evaluate("window", "direct_financial", "repeat_in_window", 1, {
                "transactions_per_day": p("tpd", "count_per_day", "18000", "18000", "18000"),
                "window_hours": p("window", "hours", "0.5", "1.25", "2"),
                "success_rate": p("success", "ratio", "0.35", "0.35", "0.35"),
                "value_per_transaction": p("value", "money_per_unit", "25000", "25000", "25000"),
                "recovery_rate": p("recovery", "ratio", "0.7", "0.825", "0.95")}, as_of=as_of),
        )
        policy = InsurancePolicy(p("ded", "money", "100000", "100000", "100000"),
                                 p("lim", "money", "1000000", "1000000", "1000000"),
                                 exclusions=frozenset({"direct_financial", "regulatory_compliance"}))
        record = assess(LossEvent("e", "USD", parts), policy).as_dict()
        print(hashlib.sha256(json.dumps(record, sort_keys=True).encode()).hexdigest())
        """
    )


def test_the_same_inputs_give_the_same_result_with_no_seed():
    """Run twice in two fresh interpreters with different hash seeds: the full
    provenance record digests the same. Nothing samples, and nothing depends on a
    set's iteration order."""
    digests = set()
    for seed in ("0", "4242"):
        env = {k: v for k, v in os.environ.items() if k != "DJANGO_SETTINGS_MODULE"}
        env["PYTHONHASHSEED"] = seed
        result = subprocess.run(
            [sys.executable, "-c", _worked_digest_script()],
            cwd=REPO, env=env, capture_output=True, text=True, timeout=60, check=False,
        )
        assert result.returncode == 0, result.stderr
        digests.add(result.stdout.strip())
    assert len(digests) == 1, digests


def test_no_scenario_module_reads_a_clock_or_a_random_source():
    """Read, not run: the formulas, the loss rules, the parameters and the parameter
    set import nothing random and read no clock, so a result depends on its
    inputs alone."""
    for name in ("formulas.py", "loss.py", "parameters.py", "parameter_set.py"):
        tree = ast.parse((ENGINE / name).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import | ast.ImportFrom):
                modules = [a.name for a in node.names] + ([node.module] if getattr(node, "module", None) else [])
                for module in modules:
                    assert module.split(".")[0] not in {"random", "secrets", "time", "uuid"}, (name, module)
            if isinstance(node, ast.Attribute):
                assert node.attr not in {"now", "today", "utcnow", "random"}, (name, node.attr)


# ---------------------------------------------------- the customer parameter set


def _entry(unit, low, base=None, high=None, *, currency="USD", **over):
    base = low if base is None else base
    high = base if high is None else high
    entry = {
        "unit": unit,
        "low": low,
        "base": base,
        "high": high,
        "source_type": "CUSTOMER_PROVIDED",
        "evidence_ref": "CFO questionnaire, 2026-09 (SYNTHETIC)",
        "effective_date": "2026-09-30",
    }
    if Unit(unit) in MONEY_UNITS:
        entry["currency"] = currency
    entry.update(over)
    return entry


def full_document():
    """Every variable once, with a value of its unit: SYNTHETIC test figures."""
    figures = {
        Unit.MONEY: "250000.00",
        Unit.MONEY_PER_UNIT: "25000",
        Unit.MONEY_PER_HOUR: "180",
        Unit.MONEY_PER_YEAR: "4200000000",
        Unit.COUNT: "1200000",
        Unit.COUNT_PER_DAY: "18000",
        Unit.RATIO: "0.85",
        Unit.HOURS: "4",
        Unit.DAYS: "2555",
        Unit.YEARS: "1",
    }
    return {
        "variables": {name: _entry(v.unit.value, figures[v.unit]) for name, v in parameter_set.VARIABLES.items()},
        "insurance_sublimits": {"notification": _entry("money", "150000")},
        "insurance_exclusions": ["regulatory_compliance"],
    }


def test_the_schema_holds_thirty_variables_in_nine_domains():
    variables = parameter_set.VARIABLES
    assert len(variables) == 30
    domains = {v.domain for v in variables.values()}
    assert domains == set(parameter_set.Domain)
    assert {d.value for d in parameter_set.Domain} == {
        "scale", "transactions", "data", "operations", "labor", "legal", "vendors", "insurance", "remediation"
    }
    for variable in variables.values():
        assert variable.unit in Unit and variable.meaning.strip()
    # The insurance variables the policy reads.
    assert variables["insurance_deductible"].unit is Unit.MONEY
    assert variables["insurance_limit"].unit is Unit.MONEY
    assert variables["insurance_waiting_period_hours"].unit is Unit.HOURS


def test_a_full_document_is_read_into_parameters():
    content = parameter_set.parse_document(full_document())
    assert set(content.variables) == set(parameter_set.VARIABLES)
    assert content.variables["annual_revenue"].low == money("4200000000")
    assert content.variables["recovery_rate"].base == Decimal("0.85")
    assert content.sublimits["notification"].name == "insurance_sublimit:notification"
    assert content.exclusions == ("regulatory_compliance",)
    policy = content.insurance_policy()
    assert policy is not None and policy.exclusions == {"regulatory_compliance"}
    assert set(policy.sublimits) == {"notification"}
    assert len(content.parameters()) == 31
    assert content.digest().startswith("sha256:") and len(content.digest()) == 71


def test_the_digest_is_the_contents_not_its_spelling_or_order():
    document = full_document()
    respelled = json.loads(json.dumps(document))
    respelled["variables"]["insurance_deductible"]["low"] = "250000.0"
    reordered = {"insurance_exclusions": document["insurance_exclusions"], **{
        k: v for k, v in reversed(list(document.items())) if k != "insurance_exclusions"}}
    digests = {parameter_set.parse_document(d).digest() for d in (document, respelled, reordered)}
    assert len(digests) == 1
    changed = json.loads(json.dumps(document))
    changed["variables"]["insurance_deductible"]["high"] = "250000.01"
    assert parameter_set.parse_document(changed).digest() not in digests


def test_no_policy_without_a_deductible_and_a_limit():
    document = full_document()
    del document["variables"]["insurance_limit"]
    assert parameter_set.parse_document(document).insurance_policy() is None


def _variant(edit):
    document = full_document()
    edit(document)
    return document


SCHEMA_REFUSALS = [
    ("an unknown top-level field", lambda d: d.update(author="mallory"), "field_unrecognised"),
    ("an unknown variable", lambda d: d["variables"].update(ebitda=_entry("money", "1")), "field_unrecognised"),
    ("an unknown entry field", lambda d: d["variables"]["recovery_rate"].update(note="x"), "field_unrecognised"),
    ("a currency on a quantity", lambda d: d["variables"]["recovery_rate"].update(currency="USD"), "field_unrecognised"),
    ("no variables", lambda d: d.update(variables={}), "field_missing"),
    ("no variables field", lambda d: d.pop("variables"), "field_missing"),
    ("an entry without its evidence", lambda d: d["variables"]["recovery_rate"].pop("evidence_ref"), "field_missing"),
    ("money without its currency", lambda d: d["variables"]["legal_retainer"].pop("currency"), "field_missing"),
    ("a JSON number", lambda d: d["variables"]["recovery_rate"].update(low=0.7), "not_decimal"),
    ("an integer", lambda d: d["variables"]["customer_count"].update(high=5), "not_decimal"),
    ("an exponent", lambda d: d["variables"]["customer_count"].update(base="1e6"), "not_decimal"),
    ("surrounding whitespace", lambda d: d["variables"]["customer_count"].update(base=" 1200000"), "not_decimal"),
    ("a plus sign", lambda d: d["variables"]["customer_count"].update(base="+1200000"), "not_decimal"),
    ("a NaN string", lambda d: d["variables"]["customer_count"].update(base="NaN"), "not_decimal"),
    ("an underscore", lambda d: d["variables"]["customer_count"].update(base="1_200_000"), "not_decimal"),
    ("a negative count", lambda d: d["variables"]["customer_count"].update(low="-1"), "negative_value"),
    ("a rate above 1", lambda d: d["variables"]["recovery_rate"].update(high="1.2"), "ratio_out_of_range"),
    ("an inverted range", lambda d: d["variables"]["recovery_rate"].update(low="0.9", base="0.85"), "range_inverted"),
    ("the wrong unit", lambda d: d["variables"]["transactions_per_day"].update(unit="count"), "unit_mismatch"),
    ("no such unit", lambda d: d["variables"]["transactions_per_day"].update(unit="per_fortnight"), "unit_unrecognised"),
    ("an unknown currency", lambda d: d["variables"]["legal_retainer"].update(currency="usd"), "currency_unknown"),
    ("a code with no minor unit", lambda d: d["variables"]["legal_retainer"].update(currency="XAU"), "currency_retired"),
    ("a bad source type", lambda d: d["variables"]["recovery_rate"].update(source_type="GUESS"), "source_type_unrecognised"),
    ("blank evidence", lambda d: d["variables"]["recovery_rate"].update(evidence_ref=" "), "evidence_ref_missing"),
    ("overlong evidence", lambda d: d["variables"]["recovery_rate"].update(evidence_ref="x" * 501), "field_malformed"),
    ("a malformed date", lambda d: d["variables"]["recovery_rate"].update(effective_date="2026-9-30"), "date_malformed"),
    ("no such day", lambda d: d["variables"]["recovery_rate"].update(effective_date="2026-02-30"), "date_malformed"),
    ("a week date", lambda d: d["variables"]["recovery_rate"].update(effective_date="2026-W40-1"), "date_malformed"),
    ("fresh before effective", lambda d: d["variables"]["recovery_rate"].update(fresh_until="2026-09-01"), "date_inversion"),
    ("variables not an object", lambda d: d.update(variables=[]), "field_malformed"),
    ("an entry not an object", lambda d: d["variables"].update(recovery_rate="0.85"), "field_malformed"),
    ("exclusions not a list", lambda d: d.update(insurance_exclusions="legal"), "field_malformed"),
    ("an unknown excluded family", lambda d: d.update(insurance_exclusions=["fines"]), "loss_family_unrecognised"),
    ("market value excluded", lambda d: d.update(insurance_exclusions=[MARKET_VALUE]), "loss_family_unrecognised"),
    ("a family excluded twice", lambda d: d.update(insurance_exclusions=["legal", "legal"]), "duplicate_id"),
    ("a sublimit for no family", lambda d: d["insurance_sublimits"].update(fines=_entry("money", "1")), "loss_family_unrecognised"),
    ("a sublimit in hours", lambda d: d["insurance_sublimits"].update(legal=_entry("hours", "1")), "unit_mismatch"),
    ("a policy in two currencies", lambda d: d["variables"]["insurance_limit"].update(currency="EUR"), "currency_mismatch"),
]


@pytest.mark.parametrize("what, edit, code", SCHEMA_REFUSALS, ids=[c[0] for c in SCHEMA_REFUSALS])
def test_the_schema_refuses(what, edit, code):
    with pytest.raises(MoneyRefused) as refused:
        parameter_set.parse_document(_variant(edit))
    assert refused.value.code == code, refused.value


def test_a_document_that_is_not_an_object_is_refused():
    for document in ([], "variables", None, 7):
        with pytest.raises(MoneyRefused) as refused:
            parameter_set.parse_document(document)
        assert refused.value.code == "field_malformed"


def test_a_set_key():
    for good in ("bank_prod_2026q4", "a", "x-1", "0" * 100):
        assert parameter_set.check_set_key(good) == good
    for bad in ("", "Bank", "-lead", "a b", "a/b", "0" * 101, "ключ", None, 7):
        with pytest.raises(MoneyRefused) as refused:
            parameter_set.check_set_key(bad)
        assert refused.value.code == "set_key_malformed"


def test_a_sublimit_name_maps_back_to_its_family():
    assert parameter_set.variable_unit("insurance_sublimit:legal") is Unit.MONEY
    assert parameter_set.variable_unit("recovery_rate") is Unit.RATIO
    for bad, code in (("insurance_sublimit:fines", "loss_family_unrecognised"), ("ebitda", "field_unrecognised")):
        with pytest.raises(MoneyRefused) as refused:
            parameter_set.variable_unit(bad)
        assert refused.value.code == code


def test_a_digest_names_the_canonical_document():
    content = parameter_set.parse_document(full_document())
    canonical = json.dumps(content.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert content.digest() == "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    assert content.as_dict()["schema"] == parameter_set.SCHEMA_VERSION
    assert "currency" not in content.as_dict()["variables"]["recovery_rate"]
    assert content.as_dict()["variables"]["legal_retainer"]["currency"] == "USD"
    assert content.as_dict()["variables"]["legal_retainer"]["low"] == "250000"
