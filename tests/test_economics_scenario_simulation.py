"""Wiring the simulation (MVP step 7b; ``docs/economics/spec-v1.md``, section 25):
step 7a's seeded sampler over step 4's formulas and loss model. No database.

- the twins: every formula has one, equal to the Decimal formula at the step-4
  and step-5 known-answer points and at random points drawn at fixed seeds,
  within the stated tolerance, monotone in each input's direction, with the
  complement and the cap exact; a formula without one is refused by name;
- the parameter-to-distribution rule: a stated distribution where it fits the
  unit, a point mass, PERT for an expert's range only, otherwise refused;
- known answers: degenerate parameters reproduce step 4 exactly for every
  known-answer fixture and the six templates; the expected annual exposure is
  E[N] E[X]; insurance is applied per event, never to a year's sum;
- invariants: P10 <= P50 <= P90 everywhere; components sum to their event and
  events to the scenario per draw; cash and market value are never added; the
  simulation adds no event and counts no effect twice;
- determinism: one seed one digest, another seed another, the same digest under
  two hash seeds, and a parameter's draws unchanged by another's;
- refusals and bounds: no admissible distribution, no twin, too many draws, two
  currencies, the values budget; no float in a record.
"""

from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys
import textwrap
import time
from decimal import Decimal
from pathlib import Path

import numpy as np
import pytest

from assurance.economics.engine import distributions as d
from assurance.economics.engine import scenario_simulation as ss
from assurance.economics.engine import simulation as sim
from assurance.economics.engine import twins as tw
from assurance.economics.engine.formulas import CATALOGUE, DEC, ESTIMATED, INC, evaluate
from assurance.economics.engine.loss import TERM_DIRECTIONS, InsurancePolicy, LossEvent, _end, assess
from assurance.economics.engine.money import Money, MoneyRefused
from assurance.economics.engine.parameters import MONEY_UNITS, POINTS, Parameter, Point, Unit
from assurance.economics.engine.provenance import SourceType
from tests.test_economics_known_answers import example_a, example_b, example_b_policy
from tests.test_economics_templates import (
    bank_variables,
    p,
    run as template_event,
    section_30_attributes,
    section_30_variables,
    section_31_attributes,
    section_31_variables,
)

REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "docs" / "economics" / "spec-v1.md"
TOLERANCE = tw.RELATIVE_TOLERANCE
#: Random points per formula, and the seeds they are drawn at.
RANDOM_POINTS = 2_000
TWIN_SEEDS = (2026, 7, 31)


# ======================================================================
# Fixtures: step 4's known answers and the six step-5 templates
# ======================================================================


def customer_service_event() -> LossEvent:
    variables = {
        "support_agent_hourly_rate": p("support_agent_hourly_rate", "money_per_hour", "40", "50", "60"),
        "legal_retainer": p("legal_retainer", "money", "20000", "25000", "30000"),
        "external_counsel_hourly_rate": p("external_counsel_hourly_rate", "money_per_hour", "400", "500", "600"),
    }
    attributes = {
        "affected_customers": p("fee.affected_customers", "count", "1000", "2000", "5000"),
        "restitution_per_customer": p("fee.restitution_per_customer", "money_per_unit", "40", "50", "80"),
        "contact_rate": p("fee.contact_rate", "ratio", "0.10", "0.20", "0.30"),
        "handling_hours": p("fee.handling_hours", "hours", "0.20", "0.25", "0.50"),
        "counsel_hours": p("fee.counsel_hours", "hours", "20", "40", "100", source="EXPERT_ESTIMATE"),
        "regulatory_response_cost": p("fee.regulatory_response_cost", "money", "10000", "25000", "60000",
                                      source="EXPERT_ESTIMATE"),
    }
    return template_event("customer_service_ai_misstatement", variables, attributes)


def fraud_event() -> LossEvent:
    attributes = {
        "missed_cases": p("aml.missed_cases", "count", "10", "20", "40", source="EXPERT_ESTIMATE"),
        "loss_per_missed_case": p("aml.loss_per_missed_case", "money_per_unit", "5000", "8000", "12000"),
        "rework_cost": p("aml.rework_cost", "money", "15000", "30000", "60000", source="EXPERT_ESTIMATE"),
        "forensics_fixed_cost": p("aml.forensics_fixed_cost", "money", "10000", "20000", "30000"),
        "investigation_hours": p("aml.investigation_hours", "hours", "40", "80", "160", source="EXPERT_ESTIMATE"),
        "regulatory_response_cost": p("aml.regulatory_response_cost", "money", "0", "50000", "250000",
                                      source="EXPERT_ESTIMATE"),
    }
    return template_event("fraud_aml_workflow_failure", bank_variables(), attributes)


def bypass_event() -> LossEvent:
    attributes = {
        "repeat_count": p("bypass.repeat_count", "count", "1", "3", "6", source="EXPERT_ESTIMATE"),
        "loss_per_event": p("bypass.loss_per_event", "money_per_unit", "10000", "12000", "15000"),
        "recovery_fixed_cost": p("bypass.recovery_fixed_cost", "money", "5000", "8000", "12000"),
        "recovery_hours": p("bypass.recovery_hours", "hours", "16", "40", "80", source="EXPERT_ESTIMATE"),
        "incident_response_cost": p("bypass.incident_response_cost", "money", "20000", "40000", "80000",
                                    source="EXPERT_ESTIMATE"),
    }
    return template_event("agent_approval_bypass", bank_variables(), attributes)


def outage_event() -> LossEvent:
    attributes = {
        "outage_hours": p("outage.outage_hours", "hours", "2", "6", "12", source="EXPERT_ESTIMATE"),
        "recovery_fixed_cost": p("outage.recovery_fixed_cost", "money", "5000", "8000", "12000"),
        "recovery_hours": p("outage.recovery_hours", "hours", "8", "16", "40", source="EXPERT_ESTIMATE"),
        "sla_credit_per_hour": p("outage.sla_credit_per_hour", "money_per_hour", "1000", "2000", "3000"),
        "sla_credit_cap": p("outage.sla_credit_cap", "money", "10000", "10000", "25000"),
    }
    return template_event("third_party_provider_outage", bank_variables(), attributes)


def exposure_event(**extra) -> LossEvent:
    return template_event("cross_customer_data_exposure", section_31_variables(), section_31_attributes(**extra))


def payment_event() -> LossEvent:
    return template_event("payment_agent_misuse", section_30_variables(), section_30_attributes())


#: Every known-answer fixture: step 4's two worked examples and the six templates'.
FIXTURES = {
    "section_30": lambda: (example_a(), None),
    "section_31_with_policy": lambda: (example_b(), example_b_policy()),
    "payment_agent_misuse": lambda: (payment_event(), None),
    "cross_customer_data_exposure": lambda: (exposure_event(), example_b_policy()),
    "customer_service_ai_misstatement": lambda: (customer_service_event(), None),
    "fraud_aml_workflow_failure": lambda: (fraud_event(), None),
    "agent_approval_bypass": lambda: (bypass_event(), None),
    "third_party_provider_outage": lambda: (outage_event(), None),
}


def collapse(event: LossEvent, policy: InsurancePolicy | None, point: Point):
    """The event and policy with every parameter collapsed to the one value step 4
    reads at ``point`` (an input's low end is its high where it decreases the
    loss): degenerate distributions, low = base = high."""
    chosen: dict[str, tuple[Point, Parameter]] = {}

    def at(parameter: Parameter, end: Point) -> Parameter:
        held = chosen.get(parameter.name)
        if held is not None:
            assert held[0] == end, f"{parameter.name} is read at two ends"
            return held[1]
        value = parameter.at(end)
        collapsed = dataclasses.replace(parameter, low=value, base=value, high=value)
        chosen[parameter.name] = (end, collapsed)
        return collapsed

    components = tuple(
        evaluate(
            c.component_id,
            c.family,
            c.formula.formula_id,
            c.formula.version,
            {cited.input.name: at(cited.parameter, cited.input.end(point)) for cited in c.inputs},
            as_of=c.as_of,
        )
        for c in event.components
    )
    collapsed_policy = None
    if policy is not None:

        def term(name, parameter):
            return at(parameter, _end(TERM_DIRECTIONS[name], point))

        collapsed_policy = InsurancePolicy(
            deductible=term("deductible", policy.deductible),
            limit=term("limit", policy.limit),
            sublimits={f: term("sublimit", t) for f, t in policy.sublimits.items()},
            exclusions=policy.exclusions,
            waiting_period_hours=None
            if policy.waiting_period_hours is None
            else term("waiting_period_hours", policy.waiting_period_hours),
        )
    return LossEvent(event.loss_event_id, event.currency, components), collapsed_policy


def scenario(*events, policy=None, stated=None, per_occurrence=frozenset(), frequency=None, currency="USD",
             derived=None):
    extra = {"derived": derived} if derived else {}
    return ss.ScenarioInput("scenario-test", currency, tuple(events), policy, dict(stated or {}),
                            frozenset(per_occurrence), frequency, **extra)


def stated(distribution_id, sparse=None, **params):
    obj = {"id": distribution_id, "version": d.CATALOGUE[distribution_id].VERSION,
           "params": {k: v if isinstance(v, dict) else str(v) for k, v in params.items()}}
    if sparse is not None:
        obj["sparse"] = sparse
    return ss.parse_stated(obj)


def figure(block, key="p50") -> Decimal:
    return Decimal(block[key])


def blocks(record):
    """Every summary block of a record, with where it is."""
    found = []

    def walk(value, path):
        if isinstance(value, dict):
            if {"p10", "p50", "p90", "bands"} <= set(value):
                found.append((path, value))
            for key, item in value.items():
                walk(item, f"{path}.{key}")
        elif isinstance(value, list):
            for index, item in enumerate(value):
                walk(item, f"{path}[{index}]")

    walk(dict(record), "record")
    return found


# ======================================================================
# The twins
# ======================================================================


def test_every_formula_has_a_twin_and_every_twin_a_formula():
    assert set(tw.TWINS) == set(CATALOGUE)
    for key, twin in tw.TWINS.items():
        assert twin.key == key


def test_a_formula_without_a_twin_is_refused_by_name(monkeypatch):
    with pytest.raises(tw.TwinMissing, match="'repeat_in_window' version 2"):
        tw.twin("repeat_in_window", 2)
    without = {k: v for k, v in tw.TWINS.items() if k != ("lump_sum", 1)}
    monkeypatch.setattr(tw, "TWINS", without)
    event, _ = collapse(example_a(), None, Point.BASE)
    with pytest.raises(ss.ScenarioSimulationRefused) as refused:
        ss.run(scenario(event), seed=1, draws=1_000)
    assert refused.value.code == "twin_missing"
    assert "lump_sum version 1" in refused.value.detail


def _close(twin_value: float, exact: Decimal) -> bool:
    if exact == 0:
        return twin_value == 0.0
    return abs(Decimal(twin_value) - exact) <= TOLERANCE * abs(exact)


def _fixture_points():
    """Every (formula, inputs as Decimals, the step-4 result) of every fixture,
    at its low, base and high."""
    for name, make in FIXTURES.items():
        event, _ = make()
        for component in event.components:
            if component.status != ESTIMATED:
                continue
            for point in POINTS:
                values = {c.input.name: c.value(point) for c in component.inputs}
                yield name, component.formula, values, component.at(point).amount


def _amount(value):
    return value.amount if isinstance(value, Money) else value


def test_each_twin_equals_its_formula_at_the_known_answer_points():
    tested: dict[tuple, int] = {}
    for name, formula, values, exact in _fixture_points():
        twin = tw.twin(formula.formula_id, formula.version)
        result = twin({k: np.array([float(_amount(v))]) for k, v in values.items()})
        assert result.shape == (1,)
        assert _close(float(result[0]), exact), (name, formula.formula_id, values, result[0], exact)
        tested[formula.key] = tested.get(formula.key, 0) + 1
    # Every known component of every fixture, at its low, base and high: 90 points of
    # nine formulas (the other four are proven at the random points only).
    assert sum(tested.values()) == 90
    assert len(tested) == 9


def _random_values(formula, rng, n):
    values = {}
    for spec in formula.inputs:
        if spec.unit is Unit.RATIO:
            column = rng.random(n)
            column[:4] = (0.0, 1.0, 0.5, 0.95)  # the complement's ends, and Sterbenz's
        else:
            column = np.exp(rng.uniform(np.log(1e-3), np.log(1e9), n))
            column[0] = 0.0
        values[spec.name] = column
    if formula.formula_id == "capped_credit":
        # The cap below, at and above the uncapped credit: both sides of the clip.
        uncapped = values["credit_per_hour"] * values["breach_hours"]
        values["contract_cap"] = uncapped * rng.choice(np.array([0.25, 1.0, 4.0]), n)
    return values


def _decimal_at(formula, values, i):
    """The Decimal formula at the binary64 inputs of point ``i``, exactly."""
    args = {}
    for spec in formula.inputs:
        exact = Decimal(float(values[spec.name][i]))
        args[spec.name] = Money(exact, "USD") if spec.unit in MONEY_UNITS else exact
    return formula.calculate(args).amount


@pytest.mark.parametrize("key", sorted(CATALOGUE), ids=[f"{k[0]}-v{k[1]}" for k in sorted(CATALOGUE)])
def test_each_twin_equals_its_formula_at_random_points(key):
    formula = CATALOGUE[key]
    twin = tw.twin(*key)
    clipped = unclipped = 0
    for seed in TWIN_SEEDS:
        rng = np.random.default_rng(seed)
        values = _random_values(formula, rng, RANDOM_POINTS)
        frozen = {}
        for name, column in values.items():
            column.flags.writeable = False
            frozen[name] = column
        result = twin(frozen)
        assert result.shape == (RANDOM_POINTS,) and result.dtype == np.float64
        for i in range(RANDOM_POINTS):
            exact = _decimal_at(formula, values, i)
            assert _close(float(result[i]), exact), (key, {k: v[i] for k, v in values.items()}, result[i], exact)
        if key == ("capped_credit", 1):
            uncapped = values["credit_per_hour"] * values["breach_hours"]
            clipped += int(np.count_nonzero(values["contract_cap"] < uncapped))
            unclipped += int(np.count_nonzero(values["contract_cap"] > uncapped))
    if key == ("capped_credit", 1):
        assert clipped > 1_000 and unclipped > 1_000


@pytest.mark.parametrize("key", sorted(CATALOGUE), ids=[f"{k[0]}-v{k[1]}" for k in sorted(CATALOGUE)])
def test_each_twin_moves_the_loss_the_way_each_input_says(key):
    """Direction: raising an input that increases the loss never lowers the twin's
    result, and raising one that decreases it never raises it."""
    formula = CATALOGUE[key]
    twin = tw.twin(*key)
    rng = np.random.default_rng(91)
    base = _random_values(formula, rng, 1_000)
    for spec in formula.inputs:
        raised = dict(base)
        bump = rng.random(1_000)
        raised[spec.name] = np.minimum(base[spec.name] + bump, 1.0) if spec.unit is Unit.RATIO else base[spec.name] * (1 + bump)
        before, after = twin(base), twin(raised)
        if spec.direction is INC:
            assert (after >= before).all(), (key, spec.name)
        else:
            assert spec.direction is DEC
            assert (after <= before).all(), (key, spec.name)


def test_the_complement_and_the_cap_are_exact():
    repeat = tw.twin("repeat_loss", 1)
    full = repeat({"repeat_count": np.array([3.0, 3.0, 3.0]), "loss_per_event": np.array([1000.0] * 3),
                   "recovery_rate": np.array([0.0, 1.0, 0.75])})
    assert full.tolist() == [3000.0, 0.0, 750.0]
    capped = tw.twin("capped_credit", 1)
    out = capped({"credit_per_hour": np.array([1000.0] * 3), "breach_hours": np.array([6.0] * 3),
                  "contract_cap": np.array([5000.0, 6000.0, 7000.0])})
    assert out.tolist() == [5000.0, 6000.0, 6000.0]


# ======================================================================
# The parameter-to-distribution rule
# ======================================================================


NON_EXPERT = [s for s in SourceType if s is not SourceType.EXPERT_ESTIMATE]


def test_a_point_is_a_point_mass():
    resolved = ss.resolve(p("x", "money", "125.50"), None)
    assert resolved.rule == ss.RULE_POINT_MASS and resolved.distribution is None and resolved.point == Decimal("125.50")
    assert resolved.record()["distribution"] == {"id": "point_mass", "version": 1, "value": "125.5"}


def test_an_experts_range_defaults_to_pert():
    resolved = ss.resolve(p("x", "hours", "0.5", "1.25", "2.0", source="EXPERT_ESTIMATE"), None)
    assert resolved.rule == ss.RULE_PERT_DEFAULT
    assert isinstance(resolved.distribution, d.Pert)
    assert (resolved.distribution.minimum, resolved.distribution.mode, resolved.distribution.maximum) == (0.5, 1.25, 2.0)
    assert resolved.distribution.shape == 4.0 and resolved.expert


@pytest.mark.parametrize("source", NON_EXPERT, ids=[s.value for s in NON_EXPERT])
def test_any_other_range_without_a_distribution_is_refused(source):
    with pytest.raises(ss.ScenarioSimulationRefused) as refused:
        ss.resolve(p("recovery_rate", "ratio", "0.70", "0.825", "0.95", source=source.value), None)
    assert refused.value.code == "no_admissible_distribution"
    assert source.value in refused.value.detail and "recovery_rate" in refused.value.detail


def test_a_stated_distribution_is_drawn_from_where_it_fits_the_unit():
    lognormal = stated("lognormal", mu="9.2", sigma="0.8")
    resolved = ss.resolve(p("x", "money", "3000", "10000", "36000"), lognormal)
    assert resolved.rule == ss.RULE_STATED and isinstance(resolved.distribution, d.Lognormal)
    beta = stated("beta_binomial_rate", alpha="8", beta="13")
    assert isinstance(ss.resolve(p("r", "ratio", "0.2", "0.35", "0.5"), beta).distribution, d.BetaBinomialRate)
    poisson = stated("poisson", rate="40")
    assert isinstance(ss.resolve(p("n", "count", "20", "40", "60"), poisson).distribution, d.Poisson)


@pytest.mark.parametrize(
    "unit, distribution",
    [
        ("ratio", stated("lognormal", mu="0", sigma="1")),
        ("ratio", stated("poisson", rate="1")),
        ("money", stated("beta_binomial_rate", alpha="1", beta="1")),
        ("hours", stated("poisson", rate="3")),
        ("ratio", stated("pert", minimum="0", mode="0.5", maximum="2")),
        ("money", stated("triangular", minimum="-5", mode="1", maximum="2")),
    ],
)
def test_a_distribution_outside_its_units_values_is_refused(unit, distribution):
    expert = SourceType.EXPERT_ESTIMATE.value
    with pytest.raises(ss.ScenarioSimulationRefused) as refused:
        ss.resolve(p("x", unit, "0", "0.5", "1", source=expert), distribution)
    assert refused.value.code == "distribution_not_for_unit"


def test_a_stated_expert_range_keeps_7as_rule():
    pert = stated("pert", minimum="1", mode="2", maximum="4")
    with pytest.raises(d.DistributionRefused) as refused:
        ss.resolve(p("x", "money", "1", "2", "4", source="CUSTOMER_PROVIDED"), pert)
    assert refused.value.code == "expert_not_allowed"
    sparse = stated("pert", sparse=True, minimum="1", mode="2", maximum="4")
    resolved = ss.resolve(p("x", "money", "1", "2", "4", source="CUSTOMER_PROVIDED"), sparse)
    assert resolved.expert and resolved.record()["distribution"]["sparse"] is True


@pytest.mark.parametrize(
    "obj, code",
    [
        ({"id": "lognormal", "version": 1, "params": {"mu": "1"}}, "distribution_malformed"),
        ({"id": "lognormal", "version": 1, "params": {"mu": 1, "sigma": "1"}}, "distribution_malformed"),
        ({"id": "lognormal", "version": 1, "params": {"mu": "1", "sigma": "1e3"}}, "distribution_malformed"),
        ({"id": "lognormal", "version": 1, "params": {"mu": "1", "sigma": "1"}, "extra": 1}, "distribution_malformed"),
        ({"id": "lognormal", "version": 1, "params": {"mu": "1", "sigma": "1"}, "sparse": True}, "distribution_malformed"),
        ({"id": "cauchy", "version": 1, "params": {}}, "distribution_unknown"),
        ({"id": "lognormal", "version": 2, "params": {"mu": "1", "sigma": "1"}}, "distribution_version_unknown"),
        ({"id": "lognormal", "version": True, "params": {"mu": "1", "sigma": "1"}}, "distribution_version_unknown"),
        ("lognormal", "distribution_malformed"),
    ],
)
def test_a_stated_distribution_is_read_exactly(obj, code):
    with pytest.raises(ss.ScenarioSimulationRefused) as refused:
        ss.parse_stated(obj)
    assert refused.value.code == code


def test_a_stated_splice_and_its_stored_form():
    splice = {
        "id": "spliced",
        "version": 1,
        "params": {
            "body": {"id": "lognormal", "version": 1, "params": {"mu": "9", "sigma": "1.0"}},
            "tail": {"id": "generalized_pareto", "version": 1,
                     "params": {"shape": "0.3", "scale": "20000", "threshold": "50000"}},
            "tail_probability": "0.05",
        },
    }
    parsed = ss.parse_stated(splice)
    assert parsed.as_json()["params"]["body"]["params"]["sigma"] == "1"
    resolved = ss.resolve(p("x", "money", "1000", "8000", "90000"), parsed)
    assert isinstance(resolved.distribution, d.Spliced)


def test_a_frequency_states_a_count_distribution():
    rate = p(ss.FREQUENCY_PARAMETER, "count", "1", "2", "4", source="INDUSTRY_BENCHMARK")
    with pytest.raises(ss.ScenarioSimulationRefused) as refused:
        ss.resolve_frequency(rate, None)
    assert refused.value.code == "frequency_distribution_missing"
    with pytest.raises(ss.ScenarioSimulationRefused) as refused:
        ss.resolve_frequency(rate, stated("gamma", shape="2", scale="1"))
    assert refused.value.code == "frequency_not_a_count"
    assert ss.resolve_frequency(rate, stated("negative_binomial", size="4", probability="0.6")).variation == ss.SHARED


# ======================================================================
# Known answers
# ======================================================================


def _exact(block, expected: Decimal) -> None:
    for key in ("p10", "p50", "p90", "mean", "severe_plausible"):
        assert Decimal(block[key]) == expected, (key, block[key], expected)
    assert Decimal(block["standard_error_of_mean"]) == 0


@pytest.mark.parametrize("name", sorted(FIXTURES))
@pytest.mark.parametrize("point", POINTS, ids=[point.value for point in POINTS])
def test_degenerate_distributions_reproduce_step_4_exactly(name, point):
    event, policy = FIXTURES[name]()
    deterministic = assess(event, policy)
    collapsed, collapsed_policy = collapse(event, policy, point)
    result = ss.run(scenario(collapsed, policy=collapsed_policy), seed=20261012, draws=1_000)
    record = result.record
    assert record["parameters"] and all(r["rule"] == ss.RULE_POINT_MASS for r in record["parameters"].values())
    event_record = record["events"][0]
    _exact(record["scenario"]["gross_cash"], deterministic.gross.total.at(point).amount)
    _exact(event_record["gross_cash"], deterministic.gross.total.at(point).amount)
    assert record["scenario"]["complete"] is deterministic.gross.total.complete
    if policy is not None:
        _exact(record["scenario"]["retained_cash"], deterministic.insured.retained.at(point).amount)
        _exact(event_record["retained_cash"], deterministic.insured.retained.at(point).amount)
    if any(c.status == ESTIMATED for c in deterministic.event.market_value_components):
        _exact(event_record["market_value"], deterministic.market_value.at(point).amount)
    else:
        assert event_record["market_value"] is None  # no known market-value component: no line
    for component, built in zip(event.components, event_record["components"], strict=True):
        assert built["component_id"] == component.component_id
        if component.status == ESTIMATED:
            assert built["evaluated_by"] == ss.BY_DECIMAL
            _exact(built["summary"], component.at(point).amount)
        else:
            assert built["summary"] is None and built["unknown"]["reason"] == component.unknown_reason


def _gamma_event(scale="1000"):
    amount = p("loss.amount", "money", "1000", "2000", "4000", source="INDUSTRY_BENCHMARK")
    component = evaluate("loss", "direct_financial", "lump_sum", 1, {"amount": amount},
                         as_of=example_a().components[0].as_of)
    return LossEvent("ev-gamma", "USD", (component,)), {"loss.amount": stated("gamma", shape="2", scale=scale)}


def test_the_expected_annual_exposure_is_the_frequency_times_the_severity():
    event, distributions = _gamma_event()
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "2", "3", "4", source="INDUSTRY_BENCHMARK")
    distributions[ss.FREQUENCY_PARAMETER] = stated("poisson", rate="3")
    result = ss.run(scenario(event, stated=distributions, frequency=frequency), seed=11, draws=100_000)
    gross = result.record["scenario"]["gross_cash"]
    assert result.record["basis"] == "annual_loss"
    assert gross["expected_annual_exposure"] == gross["mean"]
    expected = Decimal(3) * Decimal(2) * Decimal(1000)  # E[N] E[X]
    error = Decimal(gross["standard_error_of_mean"])
    assert abs(Decimal(gross["mean"]) - expected) <= 4 * error, (gross["mean"], expected, error)
    assert result.record["scenario"]["per_occurrence"]["gross_cash"]["expected_annual_exposure"] is None
    # Without a frequency there is no expected annual exposure, and the record says why.
    once = ss.run(scenario(event, stated=_gamma_event()[1]), seed=11, draws=10_000)
    assert once.record["basis"] == "per_occurrence"
    assert once.record["scenario"]["gross_cash"]["expected_annual_exposure"] is None
    assert "no expected annual exposure" in once.record["occurrences"]["statement"]


def _flat_event(amount="150", family="notification", formula="lump_sum"):
    value = p("flat.amount", "money", amount)
    component = evaluate("flat", family, formula, 1, {"amount": value}, as_of=example_a().components[0].as_of)
    return LossEvent("ev-flat", "USD", (component,))


def _policy(deductible="100", limit="1000000", sublimits=None):
    def term(name, figure):
        return p(name, "money", figure)

    return InsurancePolicy(
        deductible=term("insurance_deductible", deductible),
        limit=term("insurance_limit", limit),
        sublimits={f: term(f"insurance_sublimit:{f}", v) for f, v in (sublimits or {}).items()},
    )


def _yearly(policy):
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "1", "3", "5", source="INDUSTRY_BENCHMARK")
    si = scenario(_flat_event(), policy=policy, frequency=frequency,
                  stated={ss.FREQUENCY_PARAMETER: stated("poisson", rate="3")})
    return ss.run(si, seed=5, draws=20_000)


def test_the_retention_is_applied_per_event_never_to_the_years_sum():
    # Each event: 150 gross, a deductible of 100 retained, 50 recovered. A year of N
    # events retains 100 N; a deductible taken off the year's sum would retain 100.
    result = _yearly(_policy(deductible="100"))
    counts = result.vectors["counts"]
    assert (counts >= 2).sum() > 1_000
    assert np.array_equal(result.vectors["annual/retained_cash"], 100.0 * counts)
    assert np.array_equal(result.vectors["annual/recovery"], 50.0 * counts)


def test_the_sublimit_is_applied_per_event_never_to_the_years_sum():
    # Each event: 150 of notification, its sublimit 120, no deductible: 120
    # recovered and 30 retained per event, so 30 N a year (never 150 N - 120).
    result = _yearly(_policy(deductible="0", sublimits={"notification": "120"}))
    counts = result.vectors["counts"]
    assert np.array_equal(result.vectors["annual/retained_cash"], 30.0 * counts)
    assert np.array_equal(result.vectors["annual/recovery"], 120.0 * counts)


# ======================================================================
# Invariants
# ======================================================================


def _uncertain_exposure():
    """Section 31 through the template, with a distribution for every range."""
    event = exposure_event(
        churn_rate=p("exposure.churn_rate", "ratio", "0.01", "0.02", "0.04", source="CUSTOMER_PROVIDED"),
        market_capitalisation=p("exposure.market_capitalisation", "money", "5000000000"),
        share_price_decline=p("exposure.share_price_decline", "ratio", "0.001", "0.01", "0.03",
                              source="EXPERT_ESTIMATE"),
    )
    distributions = {
        "notification_unit_cost": stated("gamma", shape="16", scale="0.125"),
        "notification_fixed_cost": stated("lognormal", mu="10.6", sigma="0.3"),
        "support_agent_hourly_rate": stated("gamma", shape="30", scale="1.8"),
        "security_responder_hourly_rate": stated("gamma", shape="25", scale="16"),
        "legal_retainer": stated("lognormal", mu="10.8", sigma="0.4"),
        "external_counsel_hourly_rate": stated("gamma", shape="20", scale="30"),
        "exposure.contact_rate": stated("beta_binomial_rate", alpha="10", beta="90"),
        "exposure.handling_hours": stated("gamma", shape="9", scale="0.0166"),
        "exposure.forensics_fixed_cost": stated("lognormal", mu="11.2", sigma="0.2"),
        "exposure.churn_rate": stated("beta_binomial_rate", alpha="4", beta="196"),
        "exposure.margin_per_customer_per_year": stated("gamma", shape="36", scale="4.2"),
    }
    return event, distributions


def test_percentiles_are_ordered_everywhere():
    event, distributions = _uncertain_exposure()
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "0", "1", "2", source="INDUSTRY_BENCHMARK")
    distributions = {**distributions, ss.FREQUENCY_PARAMETER: stated("poisson", rate="1.5")}
    for freq in (None, frequency):
        result = ss.run(scenario(event, policy=example_b_policy(), stated=distributions, frequency=freq), seed=3,
                        draws=20_000)
        found = blocks(result.record)
        assert len(found) >= 10
        for path, block in found:
            p10, p50, p90, severe = (Decimal(block[k]) for k in ("p10", "p50", "p90", "severe_plausible"))
            assert 0 <= p10 <= p50 <= p90 <= severe, path


def _two_event_run(frequency=None):
    exposure, distributions = _uncertain_exposure()
    payment = payment_event()
    distributions.update({
        "recovery_rate": stated("pert", sparse=True, minimum="0.70", mode="0.825", maximum="0.95"),
    })
    stated_all = dict(distributions)
    if frequency is not None:
        stated_all[ss.FREQUENCY_PARAMETER] = stated("poisson", rate="2")
    return ss.run(scenario(exposure, payment, policy=example_b_policy(), stated=stated_all, frequency=frequency),
                  seed=8, draws=20_000)


@pytest.mark.parametrize("yearly", [False, True], ids=["occurrences", "years"])
def test_components_sum_to_their_event_and_events_to_the_scenario_per_draw(yearly):
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "1", "2", "3", source="INDUSTRY_BENCHMARK") if yearly else None
    result = _two_event_run(frequency)
    v = result.vectors
    events = [e["event_key"] for e in result.record["events"]]
    gross_sum = np.zeros_like(v["scenario/gross_cash"])
    retained_sum = np.zeros_like(gross_sum)
    for event in result.record["events"]:
        key = event["event_key"]
        cash = np.zeros_like(gross_sum)
        market = np.zeros_like(gross_sum)
        for c in event["components"]:
            if c["status"] != ESTIMATED:
                continue
            vector = v[f"component/{key}/{c['component_id']}"]
            if c["cash"]:
                cash = cash + vector
            else:
                market = market + vector
        assert np.array_equal(cash, v[f"event/{key}/gross_cash"])
        if f"event/{key}/market_value" in v:
            assert np.array_equal(market, v[f"event/{key}/market_value"])
        else:
            assert not market.any()  # no market-value component: no line
        assert np.array_equal(v[f"event/{key}/retained_cash"], v[f"event/{key}/gross_cash"] - v[f"event/{key}/recovery"])
        gross_sum = gross_sum + v[f"event/{key}/gross_cash"]
        retained_sum = retained_sum + v[f"event/{key}/retained_cash"]
    assert np.array_equal(gross_sum, v["scenario/gross_cash"])
    assert np.array_equal(retained_sum, v["scenario/retained_cash"])
    assert len(events) == 2 and events == ["cross_customer_data_exposure-example", "payment_agent_misuse-example"]
    if yearly:
        counts = v["counts"]
        assert np.array_equal(v["annual/gross_cash"], sim.compound_annual(counts, v["scenario/gross_cash"]))


def test_cash_and_market_value_are_never_added_together():
    result = _two_event_run()
    v = result.vectors
    key = "cross_customer_data_exposure-example"
    market = v[f"component/{key}/share-price-reaction"]
    assert market.min() > 0
    cash = sum(v[f"component/{key}/{c}"] for c in ("notification", "support", "forensics", "legal", "regulatory",
                                                     "customer-loss"))
    assert np.array_equal(cash, v[f"event/{key}/gross_cash"])
    assert np.array_equal(market, v[f"event/{key}/market_value"])
    event = result.record["events"][0]
    assert event["market_value"]["never_added_to_cash"] is True
    assert Decimal(event["gross_cash"]["p50"]) < Decimal(event["market_value"]["p50"])
    assert result.record["scenario"]["market_value"]["never_added_to_cash"] is True


def test_the_simulation_adds_no_event_and_counts_each_effect_once():
    """The double-count invariant: the run's events are exactly the scenario's, each
    component in one event once, and an occurrence realises each event once."""
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "1", "2", "3", source="INDUSTRY_BENCHMARK")
    result = _two_event_run(frequency)
    record = result.record
    assert [e["event_key"] for e in record["events"]] == [
        "cross_customer_data_exposure-example", "payment_agent_misuse-example"]
    seen = [(e["event_key"], c["component_id"]) for e in record["events"] for c in e["components"]]
    assert len(seen) == len(set(seen)) == 10
    v = result.vectors
    per_occurrence = v["event/cross_customer_data_exposure-example/gross_cash"] + v[
        "event/payment_agent_misuse-example/gross_cash"]
    assert per_occurrence.size == record["occurrences"]["total"] == int(v["counts"].sum())
    assert np.array_equal(v["annual/gross_cash"], sim.compound_annual(v["counts"], per_occurrence))
    # The same event twice in one scenario is refused, not counted twice.
    with pytest.raises(MoneyRefused):
        ss.run(scenario(payment_event(), payment_event(), stated={"recovery_rate": stated(
            "pert", sparse=True, minimum="0.70", mode="0.825", maximum="0.95")}), seed=1, draws=1_000)


# ======================================================================
# Determinism
# ======================================================================


def _payment_run(seed=2026, draws=20_000, extra_event=None):
    distributions = {"recovery_rate": stated("pert", sparse=True, minimum="0.70", mode="0.825", maximum="0.95")}
    events = (payment_event(),) + ((extra_event,) if extra_event is not None else ())
    return ss.run(scenario(*events, stated=distributions), seed=seed, draws=draws)


def test_the_same_seed_gives_the_same_digests_and_another_seed_another():
    first, again, other = _payment_run(), _payment_run(), _payment_run(seed=2027)
    assert first.digest == again.digest and first.input_digest == again.input_digest
    assert first.record["outcomes_sha256"] == again.record["outcomes_sha256"]
    assert other.input_digest == first.input_digest
    assert other.digest != first.digest
    assert other.record["outcomes_sha256"] != first.record["outcomes_sha256"]
    assert first.record["seed"] == "2026"


def test_two_interpreters_with_different_hash_seeds_give_one_digest():
    script = textwrap.dedent(
        """
        from tests.test_economics_scenario_simulation import _payment_run
        result = _payment_run(draws=5_000)
        print(result.digest, result.input_digest)
        """
    )
    digests = set()
    for hash_seed in ("0", "4242"):
        env = {**os.environ, "PYTHONHASHSEED": hash_seed}
        out = subprocess.run([sys.executable, "-c", script], cwd=REPO, env=env, capture_output=True, text=True,
                             timeout=300, check=False)
        assert out.returncode == 0, out.stderr[-3000:]
        digests.add(out.stdout.strip().splitlines()[-1])
    assert len(digests) == 1
    assert digests == {" ".join((_payment_run(draws=5_000).digest, _payment_run(draws=5_000).input_digest))}


def test_an_unrelated_parameter_leaves_every_other_parameters_draws_unchanged():
    event, distributions = _gamma_event()
    alone = _payment_run()
    distributions["recovery_rate"] = stated("pert", sparse=True, minimum="0.70", mode="0.825", maximum="0.95")
    together = ss.run(scenario(payment_event(), event, stated=distributions), seed=2026, draws=20_000)
    for component in ("direct-loss", "incident-response", "legal-regulatory-response"):
        name = f"component/payment_agent_misuse-example/{component}"
        assert np.array_equal(alone.vectors[name], together.vectors[name]), name
    # The lump sum's vector is its parameter's draws.
    assert "component/ev-gamma/loss" in together.vectors and "component/ev-gamma/loss" not in alone.vectors


def test_a_parameter_is_one_value_a_year_unless_named_per_occurrence():
    event, distributions = _gamma_event()
    # 2 / 4 / 6, not 1 / 2 / 3: Poisson(4)'s median is 4, above a high of 3, which
    # the two-sided range test (step 6) refuses.
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "2", "4", "6", source="INDUSTRY_BENCHMARK")
    distributions[ss.FREQUENCY_PARAMETER] = stated("poisson", rate="4")
    shared = ss.run(scenario(event, stated=distributions, frequency=frequency), seed=9, draws=5_000)
    varying = ss.run(scenario(event, stated=distributions, frequency=frequency, per_occurrence={"loss.amount"}),
                     seed=9, draws=5_000)
    counts = shared.vectors["counts"]
    draws = shared.vectors["component/ev-gamma/loss"]  # a lump sum: its parameter's draws
    starts = np.cumsum(counts) - counts
    for year in np.flatnonzero(counts > 1)[:200]:
        block = draws[starts[year]: starts[year] + counts[year]]
        assert (block == block[0]).all()
    assert shared.record["parameters"]["loss.amount"]["variation"] == ss.SHARED
    assert varying.record["parameters"]["loss.amount"]["variation"] == ss.PER_OCCURRENCE
    assert shared.input_digest != varying.input_digest
    # Parameter uncertainty spreads the years wider than per-event variation does.
    assert Decimal(shared.record["scenario"]["gross_cash"]["p90"]) > Decimal(
        varying.record["scenario"]["gross_cash"]["p90"])


# ======================================================================
# Digests, refusals and bounds
# ======================================================================


def test_the_input_digest_covers_each_parameters_distribution():
    base = _payment_run()
    for other in (
        stated("pert", sparse=True, minimum="0.70", mode="0.80", maximum="0.95"),
        stated("beta_binomial_rate", alpha="33", beta="7"),
    ):
        changed = ss.run(scenario(payment_event(), stated={"recovery_rate": other}), seed=2026, draws=20_000)
        assert changed.input_digest != base.input_digest
        assert changed.inputs["parameters"]["recovery_rate"]["distribution"] == other.as_json()
    assert base.inputs["parameters"]["recovery_rate"]["distribution"]["id"] == "pert"


def test_every_version_is_in_the_inputs():
    versions = _payment_run(draws=1_000).inputs["versions"]
    assert versions["numpy"] == np.__version__ and versions["sampler"] == sim.SAMPLER_VERSION
    assert versions["twins"] == tw.TWINS_VERSION and versions["parameter_distribution_rule"] == ss.RULE_VERSION
    assert versions["formulas"] == ["lump_sum/1", "repeat_in_window/1"]
    assert versions["distributions"]["pert"] == 1


def test_a_range_with_no_admissible_distribution_is_refused():
    with pytest.raises(ss.ScenarioSimulationRefused) as refused:
        ss.run(scenario(payment_event()), seed=1, draws=1_000)
    assert refused.value.code == "no_admissible_distribution" and "recovery_rate" in refused.value.detail


@pytest.mark.parametrize("draws", [999, 1_000_001, True, 5_000.0])
def test_too_many_or_too_few_draws_are_refused(draws):
    with pytest.raises(sim.SimulationRefused) as refused:
        _payment_run(draws=draws)
    assert refused.value.code == "draws_out_of_range"


def test_two_currencies_in_one_run_are_refused():
    eur = dataclasses.replace(p("eur.amount", "money", "1"), low=Money(Decimal(1), "EUR"),
                              base=Money(Decimal(1), "EUR"), high=Money(Decimal(1), "EUR"))
    euro_event = LossEvent("ev-eur", "EUR", (evaluate("flat", "legal", "lump_sum", 1, {"amount": eur},
                                                      as_of=example_a().components[0].as_of),))
    with pytest.raises(MoneyRefused) as refused:
        ss.run(scenario(_flat_event(), euro_event), seed=1, draws=1_000)
    assert refused.value.code == "currency_mismatch"
    with pytest.raises(MoneyRefused) as refused:
        ss.run(scenario(euro_event, currency="USD"), seed=1, draws=1_000)
    assert refused.value.code == "currency_mismatch"


def test_a_run_past_the_values_budget_is_refused_before_a_parameter_is_drawn(monkeypatch):
    event, distributions = _uncertain_exposure()
    # 3 / 5 / 7, not 4 / 5 / 6: Poisson(5) holds only 49.7% of its mass in 4 to 6,
    # which the two-sided range test (step 6) refuses before the budget is reached.
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "3", "5", "7", source="INDUSTRY_BENCHMARK")
    distributions[ss.FREQUENCY_PARAMETER] = stated("poisson", rate="5")
    sampled = []
    original = d.Gamma._draw
    monkeypatch.setattr(d.Gamma, "_draw", lambda self, rng, n: sampled.append(n) or original(self, rng, n))
    with pytest.raises(sim.SimulationRefused) as refused:
        ss.run(scenario(event, policy=example_b_policy(), stated=distributions, frequency=frequency), seed=1,
               draws=1_000_000)
    assert refused.value.code == "values_over_budget"
    assert sampled == []


def test_the_time_budget_is_checked_between_stages():
    stages = []

    def check_time(stage):
        stages.append(stage)
        if stage.startswith("component"):
            raise ss.ScenarioSimulationRefused("time_over_budget", stage)

    with pytest.raises(ss.ScenarioSimulationRefused) as refused:
        ss.run(scenario(payment_event(), stated={"recovery_rate": stated(
            "pert", sparse=True, minimum="0.70", mode="0.825", maximum="0.95")}), seed=1, draws=1_000,
            check_time=check_time)
    assert refused.value.code == "time_over_budget"
    assert stages[0] == "frequency" and any(s.startswith("parameter") for s in stages)


def test_no_number_in_a_record_is_a_float():
    result = _two_event_run()
    ss.no_float(dict(result.record))
    ss.no_float(dict(result.inputs))
    text = ss.canonical_json(dict(result.record))

    def refuse_float(value):
        raise AssertionError(f"a float in the record: {value}")

    json.loads(text, parse_float=refuse_float)
    assert result.digest == ss.digest_of(dict(result.record))
    with pytest.raises(sim.InvariantBroken):
        ss.no_float({"a": [{"b": 1.5}]})


def test_a_default_run_of_the_largest_template_is_quick():
    """100,000 draws of section 31 through the template (seven components, eleven
    stated distributions, a policy), sampled twice as 7a does: a per-draw Python
    loop would take minutes; CI's load never makes this 60 s."""
    event, distributions = _uncertain_exposure()
    start = time.perf_counter()
    result = ss.run(scenario(event, policy=example_b_policy(), stated=distributions), seed=1, draws=100_000)
    elapsed = time.perf_counter() - start
    assert result.record["simulations"] == 100_000
    assert elapsed < 60, elapsed


# ======================================================================
# Review round 1
# ======================================================================

AS_OF = example_a().components[0].as_of


def _lump(component_id, parameter, family="notification"):
    return evaluate(component_id, family, "lump_sum", 1, {"amount": parameter}, as_of=AS_OF)


def test_a_stated_distribution_that_contradicts_its_figures_is_refused():
    """M1. The reviewer's case: a lump sum of 100,000 / 200,000 / 400,000 stating
    lognormal(0, 1) would run with a mean of 1.63. Refused, at run time as at write
    time, naming the parameter; one that holds the figures is drawn from."""
    row = p("c.amt", "money", "100000", "200000", "400000")
    contradicting = stated("lognormal", mu="0", sigma="1")
    with pytest.raises(ss.ScenarioSimulationRefused) as refused:
        ss.resolve(row, contradicting)
    assert refused.value.code == "distribution_contradicts_range" and "c.amt" in refused.value.detail
    with pytest.raises(ss.ScenarioSimulationRefused) as refused:
        ss.run(scenario(LossEvent("ev", "USD", (_lump("c", row),)), stated={"c.amt": contradicting}), seed=1,
               draws=1_000)
    assert refused.value.code == "distribution_contradicts_range"
    # Median 198,789, P5 102,900, P95 384,000: it holds the base, and its support the ends.
    assert ss.resolve(row, stated("lognormal", mu="12.2", sigma="0.4")).rule == ss.RULE_STATED
    for outside in (
        stated("gamma", shape="2", scale="10000"),  # P95 47,400: the base is above it
        stated("pert", sparse=True, minimum="150000", mode="200000", maximum="400000"),  # the low is below it
        stated("generalized_pareto", shape="-0.5", scale="100000", threshold="0"),  # it ends at 200,000
    ):
        with pytest.raises(ss.ScenarioSimulationRefused) as refused:
            ss.resolve(row, outside)
        assert refused.value.code == "distribution_contradicts_range", outside
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "1", "2", "4", source="INDUSTRY_BENCHMARK")
    with pytest.raises(ss.ScenarioSimulationRefused) as refused:
        ss.resolve_frequency(frequency, stated("poisson", rate="40"))
    assert refused.value.code == "distribution_contradicts_range"
    assert ss.RANGE_FIT_PERCENTILES == (Decimal(5), Decimal(95))


def test_a_run_with_nothing_uncertain_is_step_4_to_the_last_digit():
    """L1. 100.10 + 200.20 is 300.29999999999995 in binary64 and 300.30 in step 4;
    repeat_in_window at 100 a day is a 60-digit Decimal binary64 cannot hold. A run
    with nothing uncertain reports step 4's figures, every digit."""
    event = LossEvent("ev", "USD", (_lump("a", p("a.amt", "money", "100.10")),
                                    _lump("b", p("b.amt", "money", "200.20"))))
    assert 100.10 + 200.20 != 300.30
    policy = _policy(deductible="100.05")
    deterministic = assess(event, policy)
    result = ss.run(scenario(event, policy=policy), seed=1, draws=1_000)
    record = result.record
    assert deterministic.gross.total.at(Point.BASE).amount == Decimal("300.30")
    for block in (record["scenario"]["gross_cash"], record["events"][0]["gross_cash"]):
        _exact(block, Decimal("300.30"))
    _exact(record["scenario"]["retained_cash"], deterministic.insured.retained.at(Point.BASE).amount)
    assert record["events"][0]["evaluated_by"] == record["scenario"]["evaluated_by"] == ss.BY_DECIMAL
    # Two events, each exact: the scenario's line is their Decimal sum.
    pair = ss.run(scenario(LossEvent("ev-1", "USD", (_lump("a", p("a.amt", "money", "0.1")),)),
                           LossEvent("ev-2", "USD", (_lump("b", p("b.amt", "money", "0.2")),))), seed=1, draws=1_000)
    _exact(pair.record["scenario"]["gross_cash"], Decimal("0.3"))
    component = evaluate("w", "direct_financial", "repeat_in_window", 1, {
        "transactions_per_day": p("tpd", "count_per_day", "100"), "window_hours": p("wh", "hours", "7"),
        "success_rate": p("sr", "ratio", "0.3"), "value_per_transaction": p("vpt", "money_per_unit", "123.45"),
        "recovery_rate": p("rr", "ratio", "0.1")}, as_of=AS_OF)
    expected = component.at(Point.BASE).amount
    assert Decimal(float(expected)) != expected and len(expected.as_tuple().digits) > 50
    window = ss.run(scenario(LossEvent("ev-w", "USD", (component,))), seed=1, draws=1_000).record
    for block in (window["events"][0]["components"][0]["summary"], window["events"][0]["gross_cash"],
                  window["scenario"]["gross_cash"]):
        _exact(block, expected)


def test_every_limit_that_decides_a_recorded_refusal_is_in_the_input_digest(monkeypatch):
    """L3. A refusal recorded under one values or events budget is never returned
    under another: each limit is a version of the inputs."""
    event, distributions = _gamma_event()
    si = scenario(event, stated=distributions)
    before = ss.digest_of(ss.canonical_inputs(si))
    limits = ss.versions(si)["limits"]
    assert (limits["max_values"], limits["max_events"]) == (sim.MAX_VALUES, sim.MAX_EVENTS)
    assert limits["range_fit_percentiles"] == ["5", "95"]
    for name in ("MAX_VALUES", "MAX_EVENTS"):
        monkeypatch.setattr(sim, name, getattr(sim, name) - 1)
        after = ss.digest_of(ss.canonical_inputs(si))
        assert after != before, name
        before = after


def test_an_effects_range_is_drawn_once_a_year_unless_named_per_occurrence():
    """L4. The reviewer's case: an expert lump sum of 10,000 / 100,000 / 1,000,000
    and Poisson(5) events a year. Drawn once a year (the default: the range is
    uncertainty about the figure), the annual P95 is at or above the per-occurrence
    option's, with the same mean."""
    amount = p("x.amt", "money", "10000", "100000", "1000000", source="EXPERT_ESTIMATE")
    event = LossEvent("ev", "USD", (_lump("x", amount),))
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "1", "5", "9", source="INDUSTRY_BENCHMARK")
    distributions = {ss.FREQUENCY_PARAMETER: stated("poisson", rate="5")}
    yearly = ss.run(scenario(event, stated=distributions, frequency=frequency), seed=3, draws=50_000)
    each = ss.run(scenario(event, stated=distributions, frequency=frequency, per_occurrence={"x.amt"}), seed=3,
                  draws=50_000)
    assert yearly.record["parameters"]["x.amt"]["variation"] == ss.SHARED
    assert each.record["parameters"]["x.amt"]["variation"] == ss.PER_OCCURRENCE
    assert yearly.inputs["parameters"]["x.amt"]["variation"] == ss.SHARED
    assert yearly.input_digest != each.input_digest
    once, per = yearly.record["scenario"]["gross_cash"], each.record["scenario"]["gross_cash"]
    assert Decimal(once["severe_plausible"]) >= Decimal(per["severe_plausible"])
    assert Decimal(once["p90"]) >= Decimal(per["p90"])
    # The reviewer measured P95 3.18M against 2.32M: well apart, not merely ordered.
    assert Decimal(once["severe_plausible"]) > Decimal("1.2") * Decimal(per["severe_plausible"])
    error = (Decimal(once["standard_error_of_mean"]) ** 2 + Decimal(per["standard_error_of_mean"]) ** 2).sqrt()
    assert abs(Decimal(once["mean"]) - Decimal(per["mean"])) <= 4 * error
    with pytest.raises(ss.ScenarioSimulationRefused) as refused:
        ss.run(scenario(event, stated=distributions, frequency=frequency, per_occurrence={"nothing.read"}), seed=3,
               draws=1_000)
    assert refused.value.code == "variation_unrecognised"


@pytest.mark.parametrize("figures", [("10000", "10000", "25000"), ("10000", "25000", "25000")],
                         ids=["low=base", "base=high"])
def test_a_range_with_one_end_at_its_base_is_not_a_point_mass(figures):
    """L5. Only low = base = high is a point mass: low = base < high is a range,
    PERT for an expert and refused for any other source."""
    resolved = ss.resolve(p("x", "money", *figures, source="EXPERT_ESTIMATE"), None)
    assert resolved.rule == ss.RULE_PERT_DEFAULT and resolved.drawn
    assert (resolved.distribution.minimum, resolved.distribution.maximum) == (10000.0, 25000.0)
    for source in NON_EXPERT:
        with pytest.raises(ss.ScenarioSimulationRefused) as refused:
            ss.resolve(p("x", "money", *figures, source=source.value), None)
        assert refused.value.code == "no_admissible_distribution"


def _derived(name, unit, contributors, direction=INC, source="CALCULATED"):
    """The builder's larger loss of ``contributors``, point by point."""
    larger = max if direction is INC else min
    figures = [str(larger(c.at(point).amount if isinstance(c.at(point), Money) else c.at(point)
                          for c in contributors)) for point in POINTS]
    return p(name, unit, *figures, source=source)


def test_a_derived_parameter_of_two_point_masses_is_the_larger_exactly():
    """L6. A CALCULATED merge of two effects' point figures is the larger loss,
    exactly: the highest where the input increases the loss, the lowest where it
    decreases it."""
    contributors = (p("e1.amount", "money", "150000"), p("e2.amount", "money", "165000.10"))
    merged = _derived("ev:amount", "money", contributors)
    result = ss.run(scenario(LossEvent("ev", "USD", (_lump("x", merged),)), derived={"ev:amount": contributors}),
                    seed=1, draws=1_000)
    record = result.record["parameters"]["ev:amount"]
    assert record["rule"] == ss.RULE_DERIVED and record["direction"] == "increases"
    assert record["distribution"] == {"id": "point_mass", "version": 1, "value": "165000.1"}
    assert sorted(record["contributors"]) == ["e1.amount", "e2.amount"]
    _exact(result.record["scenario"]["gross_cash"], Decimal("165000.10"))
    assert result.inputs["derived"] == {"ev:amount": ["e1.amount", "e2.amount"]}
    rates = (p("e1.recovery", "ratio", "0.8"), p("e2.recovery", "ratio", "0.7"))
    lower = ss.resolve_derived(_derived("ev:recovery", "ratio", rates, DEC), rates, {}, direction=DEC)
    assert lower.point == Decimal("0.7") and not lower.drawn


def test_a_derived_parameter_of_two_expert_ranges_is_the_drawwise_larger():
    """L6. Each contributor is drawn by its own rule from its own stream, and the
    merge takes the larger per draw: its mean is at least each contributor's."""
    e1 = p("e1.amount", "money", "10000", "40000", "90000", source="EXPERT_ESTIMATE")
    e2 = p("e2.amount", "money", "20000", "30000", "120000", source="EXPERT_ESTIMATE")
    merged = _derived("ev:amount", "money", (e1, e2))
    run = ss.run(scenario(LossEvent("ev", "USD", (_lump("x", merged),)), derived={"ev:amount": (e1, e2)}),
                 seed=4, draws=20_000)
    alone = [ss.run(scenario(LossEvent("ev", "USD", (_lump("x", c),))), seed=4, draws=20_000) for c in (e1, e2)]
    drawn = [r.vectors["component/ev/x"] for r in alone]
    assert np.array_equal(run.vectors["component/ev/x"], np.maximum(*drawn))
    mean = Decimal(run.record["scenario"]["gross_cash"]["mean"])
    for r in alone:
        assert mean >= Decimal(r.record["scenario"]["gross_cash"]["mean"])
    record = run.record["parameters"]["ev:amount"]
    assert record["rule"] == ss.RULE_DERIVED and record["distribution"] is None
    assert {k: v["rule"] for k, v in record["contributors"].items()} == {
        "e1.amount": ss.RULE_PERT_DEFAULT, "e2.amount": ss.RULE_PERT_DEFAULT}
    assert run.record["expert_parameters"] == ["e1.amount", "e2.amount"]


def test_a_derived_parameter_with_a_refused_contributor_is_refused_naming_it():
    """L6. A contributor no rule admits (a customer's range with no distribution)
    refuses the merge, and the refusal names it; a merge is never a PERT of its
    own range, and states no distribution of its own."""
    e1 = p("e1.amount", "money", "10000", "40000", "90000", source="EXPERT_ESTIMATE")
    e2 = p("e2.amount", "money", "20000", "30000", "120000", source="CUSTOMER_PROVIDED")
    merged = _derived("ev:amount", "money", (e1, e2))
    event = LossEvent("ev", "USD", (_lump("x", merged),))
    with pytest.raises(ss.ScenarioSimulationRefused) as refused:
        ss.run(scenario(event, derived={"ev:amount": (e1, e2)}), seed=1, draws=1_000)
    assert refused.value.code == "no_admissible_distribution"
    assert "e2.amount" in refused.value.detail and "ev:amount" in refused.value.detail
    fits = stated("lognormal", mu="10.3", sigma="0.5")  # P5 13,000, P95 67,500
    assert ss.run(scenario(event, derived={"ev:amount": (e1, e2)}, stated={"e2.amount": fits}), seed=1,
                  draws=1_000).record["parameters"]["ev:amount"]["contributors"]["e2.amount"]["rule"] == ss.RULE_STATED
    for bad in (
        {"stated": {"e2.amount": fits, "ev:amount": fits}},  # the merge states its own
        {"derived_parameter": p("ev:amount", "money", "10000", "40000", "120000", source="CALCULATED")},  # not the larger
    ):
        parameter = bad.get("derived_parameter", merged)
        with pytest.raises(ss.ScenarioSimulationRefused) as refused:
            ss.run(scenario(LossEvent("ev", "USD", (_lump("x", parameter),)), derived={"ev:amount": (e1, e2)},
                            stated=bad.get("stated", {"e2.amount": fits})), seed=1, draws=1_000)
        assert refused.value.code == "derived_malformed"


# ======================================================================
# The spec
# ======================================================================


SPEC_PHRASES = (
    "## 25. Wiring the simulation (MVP step 7b)",
    "### 25.1 The parameter-to-distribution rule",
    "PERT(low, base, high)",
    "`no_admissible_distribution`",
    "### 25.3 The formula twins",
    "1E-13",
    "### 25.4 The aggregation order",
    "never to a year's sum",
    "### 25.5 Frequency",
    "one occurrence",
    "### 25.6 The stored result",
    "`uq_econ_simulation_inputs`",
    "### 25.8 Limits and timing",
    "### 25.9 What is still not done",
    "the confidence grade",
    "the Validity Card",
    "the signed receipt",
    "Decisions this step takes",
    "`distribution_contradicts_range`",
    "`derived_larger_loss`",
    "normal\nbinary64 results only",
    "**Every parameter is drawn once per simulated year**",
    "**The transaction only inserts**",
)


def test_the_spec_states_the_wiring():
    text = SPEC.read_text(encoding="utf-8")
    for phrase in SPEC_PHRASES:
        assert phrase in text, phrase
    section = text.split("### 23.11", 1)[1].split("### 23.12", 1)[0]
    assert "No formula is evaluated" not in section
    assert "Nothing is stored" not in section


# ======================================================================
# Review round 2
# ======================================================================


def test_an_exact_line_completes_whatever_the_draws_or_the_seed():
    """N1. An exact line was refused as ``invariant_broken`` when 7a's mean of a
    constant vector (fsum / n) came out one ulp off and its standard error not zero:
    100.05 at 1,312 draws, 0.1 likewise. The line is exact when every draw is the
    value; a binary64 mean that rounds is not a draw of another value."""
    for amount in ("100.05", "0.1", "1234.56"):
        event = LossEvent("ev", "USD", (_lump("a", p("a.amt", "money", amount)),))
        for draws in (1_000, 1_312, 5_861):
            record = ss.run(ss.ScenarioInput("s", "USD", (event,)), seed=1, draws=draws).record
            _exact(record["events"][0]["gross_cash"], Decimal(amount))
    # A fixed severity with an uncertain frequency: n is each year's count, so the
    # seed decides it. Seeds 3, 8, 19 and 20 were refused.
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "1", "3", "5", source="INDUSTRY_BENCHMARK")
    event = LossEvent("ev", "USD", (_lump("a", p("a.amt", "money", "1234.56")),))
    for seed in (3, 8, 19, 20):
        ss.run(ss.ScenarioInput("s", "USD", (event,), stated={ss.FREQUENCY_PARAMETER: stated("poisson", rate="3")},
                                frequency=frequency), seed=seed, draws=10_000)


def test_a_rare_count_holds_its_own_rate():
    """Low 2. A Poisson rarer than once in twenty years has a P95 of 0, so a base of
    its own rate fell outside P5 to P95 and the frequency was refused. A count's
    upper bound is P95 + 1, exclusive: the base may lie anywhere below the next count."""
    rare = p(ss.FREQUENCY_PARAMETER, "count", "0", "0.05", "0.2", source="INDUSTRY_BENCHMARK")
    assert ss.resolve_frequency(rare, stated("poisson", rate="0.05")) is not None
    assert ss.resolve_frequency(
        p(ss.FREQUENCY_PARAMETER, "count", "0", "0.02", "0.1", source="INDUSTRY_BENCHMARK"),
        stated("poisson", rate="0.02"),
    ) is not None
    # Still refused: a base at or past the count after P95.
    with pytest.raises(ss.ScenarioSimulationRefused) as refused:
        ss.resolve_frequency(p(ss.FREQUENCY_PARAMETER, "count", "0", "1", "2", source="INDUSTRY_BENCHMARK"),
                             stated("poisson", rate="0.02"))
    assert refused.value.code == "distribution_contradicts_range"


def test_every_constant_the_values_budget_counts_is_in_the_digest():
    """Low 3. MAX_VALUES was in the versions, but the counts the budget adds to it
    were not: raising one refused, under the same input digest, a run that had run."""
    held = ss.limits()
    assert held["run_vectors"] == sim.RUN_VECTORS and held["year_vectors"] == sim.YEAR_VECTORS
    assert held["insurance_temporaries"] == ss.INSURANCE_TEMPORARIES
    assert held["summary_temporaries"] == ss.SUMMARY_TEMPORARIES
    assert held["annual_lines"] == ss.ANNUAL_LINES
    assert held["splice_max_rounds"] == d.SPLICE_MAX_ROUNDS
