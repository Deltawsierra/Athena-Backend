"""Sensitivity analysis and the confidence grade (MVP step 8;
``docs/economics/spec-v1.md``, sections 26.1 and 26.2). No database.

- the sensitivity known answers: one parameter that drives everything ranks first
  with its direction; two independent parameters in a sum share the importance as
  they share the variance; a decreasing input (a recovery rate) reads "decreases";
  the same seed gives the same analysis; the analysis is made only from the run's
  own inputs and draws; point masses are fixed; the tornado swings at most
  ``MAX_SWINGS``; a run with a frequency ranks it and swings it;
- the grade: all customer and observed and fresh is A; benchmark-heavy is C;
  mostly expert is D; a refused run, conflicting inputs and an unknown cash
  component are Unknown; each downgrade fires once; the grade weighs by
  level, never by count; the thresholds are in its version digest;
- the level (review round 2): an additive decomposition at base -- a component's
  base share split among its own inputs (a product's factors equally, a recovery
  through its complement), a frequency one half -- for the gross cash and, under a
  policy, the retained cash; the headline grade is the lower of the two lines'; a
  frequency whose base is zero has no level; the reviewer's cases (a)-(e).
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal

import pytest

from assurance.economics.engine import grade as g
from assurance.economics.engine import scenario_simulation as ss
from assurance.economics.engine import sensitivity as sens
from assurance.economics.engine.confidence import ConfidenceGrade
from assurance.economics.engine.formulas import evaluate
from assurance.economics.engine.loss import InsurancePolicy, LossEvent
from assurance.economics.engine.money import Money
from assurance.economics.engine.parameters import MONEY_UNITS, Parameter, Unit
from assurance.economics.engine.provenance import SourceType
from tests.test_economics_scenario_simulation import stated

AS_OF = date(2026, 10, 6)
LABEL = "SYNTHETIC / ILLUSTRATIVE"
DRAWS = 20_000


def p(name, unit, low, base=None, high=None, source="CUSTOMER_PROVIDED", fresh_until=None) -> Parameter:
    unit = Unit(unit)
    base = low if base is None else base
    high = base if high is None else high

    def value(figure):
        return Money(Decimal(figure), "USD") if unit in MONEY_UNITS else Decimal(figure)

    return Parameter(name, unit, source, value(low), value(base), value(high), f"{LABEL}: made up",
                     effective_date=date(2026, 9, 1), fresh_until=fresh_until)


def lump(component_id, parameter, family="notification"):
    return evaluate(component_id, family, "lump_sum", 1, {"amount": parameter}, as_of=AS_OF)


def analysed(si: ss.ScenarioInput, seed=7, draws=DRAWS):
    run = ss.run(si, seed=seed, draws=draws)
    record = sens.analyse(si, seed=seed, draws=draws, severe_percentile=Decimal(95), input_digest=run.input_digest,
                          outcomes_sha256=run.record["outcomes_sha256"])
    return run, record


def ranked(record) -> dict:
    return {entry["name"]: entry for entry in record["ranked"]}


# ======================================================================
# Sensitivity: the known answers
# ======================================================================


def test_one_parameter_that_drives_everything_ranks_first_with_its_direction():
    """A wide expert range beside a narrow one: the wide one carries almost all the
    variance, ranks first, and increases the loss; its swing moves the outcome far
    more than the other's."""
    wide = p("wide.amt", "money", "0", "500000", "1000000", source="EXPERT_ESTIMATE")
    narrow = p("narrow.amt", "money", "1000", "1010", "1020", source="EXPERT_ESTIMATE")
    event = LossEvent("ev", "USD", (lump("a", wide), lump("b", narrow, "legal")))
    _, record = analysed(ss.ScenarioInput("s", "USD", (event,)))
    first, second = record["ranked"]
    assert (first["name"], first["rank"], first["direction"]) == ("wide.amt", 1, sens.INCREASES)
    assert Decimal(first["importance"]) > Decimal("0.999") and Decimal(second["importance"]) < Decimal("0.001")
    assert Decimal(first["rank_correlation"]) > Decimal("0.999")
    low, high = (Decimal(first["swing"][k]) for k in ("low_outcome", "high_outcome"))
    narrow_low, narrow_high = (Decimal(second["swing"][k]) for k in ("low_outcome", "high_outcome"))
    assert high - low > 1000 * (narrow_high - narrow_low) > 0
    assert record["method"]["id"] == sens.METHOD_ID and record["method"]["version"] == sens.VERSION


def test_two_independent_parameters_in_a_sum_share_importance_by_their_variances():
    """X1 + X2, independent, symmetric PERTs whose widths are 2:1, so their
    variances are 4:1: importances 0.8 and 0.2 within 0.03 (Spearman's correlation
    is the rank form of Pearson's, whose square is exactly the variance share)."""
    x1 = p("x1.amt", "money", "0", "100000", "200000", source="EXPERT_ESTIMATE")
    x2 = p("x2.amt", "money", "0", "50000", "100000", source="EXPERT_ESTIMATE")
    event = LossEvent("ev", "USD", (lump("a", x1), lump("b", x2, "legal")))
    _, record = analysed(ss.ScenarioInput("s", "USD", (event,)), draws=100_000)
    found = ranked(record)
    assert abs(Decimal(found["x1.amt"]["importance"]) - Decimal("0.8")) < Decimal("0.03")
    assert abs(Decimal(found["x2.amt"]["importance"]) - Decimal("0.2")) < Decimal("0.03")
    assert sum(Decimal(e["importance"]) for e in record["ranked"]) == pytest.approx(Decimal(1), abs=Decimal("1E-9"))
    # Equal variances share it equally.
    y1 = p("y1.amt", "money", "0", "50000", "100000", source="EXPERT_ESTIMATE")
    event = LossEvent("ev", "USD", (lump("a", x2), lump("b", y1, "legal")))
    _, record = analysed(ss.ScenarioInput("s", "USD", (event,)), draws=100_000)
    assert abs(Decimal(ranked(record)["x2.amt"]["importance"]) - Decimal("0.5")) < Decimal("0.03")


def test_a_recovery_rate_reads_decreases():
    """repeat_loss: count x amount x (1 - recovery). The recovery rate decreases
    the loss: its correlation is negative and its P90 swing gives the lower outcome."""
    count = p("r.repeat_count", "count", "5", "10", "20", source="EXPERT_ESTIMATE")
    amount = p("r.loss_per_event", "money_per_unit", "10000", "12000", "15000", source="EXPERT_ESTIMATE")
    recovery = p("r.recovery_rate", "ratio", "0.10", "0.50", "0.90", source="EXPERT_ESTIMATE")
    component = evaluate("direct", "direct_financial", "repeat_loss", 1,
                         {"repeat_count": count, "loss_per_event": amount, "recovery_rate": recovery}, as_of=AS_OF)
    _, record = analysed(ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (component,)),)))
    found = ranked(record)
    entry = found["r.recovery_rate"]
    assert entry["direction"] == sens.DECREASES and Decimal(entry["rank_correlation"]) < 0
    assert Decimal(entry["swing"]["high_outcome"]) < Decimal(entry["swing"]["low_outcome"])
    assert found["r.repeat_count"]["direction"] == found["r.loss_per_event"]["direction"] == sens.INCREASES


def test_the_analysis_is_deterministic_per_seed():
    x1 = p("x1.amt", "money", "0", "100000", "200000", source="EXPERT_ESTIMATE")
    x2 = p("x2.amt", "money", "0", "50000", "100000", source="EXPERT_ESTIMATE")
    si = ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (lump("a", x1), lump("b", x2, "legal"))),))
    _, first = analysed(si, seed=11)
    _, again = analysed(si, seed=11)
    _, other = analysed(si, seed=12)
    assert first == again and sens.digest_of(first) == sens.digest_of(again)
    assert sens.digest_of(other) != sens.digest_of(first)
    assert [e["name"] for e in other["ranked"]] == [e["name"] for e in first["ranked"]]


def test_the_analysis_is_made_only_from_the_runs_own_inputs_and_draws():
    x1 = p("x1.amt", "money", "0", "100000", "200000", source="EXPERT_ESTIMATE")
    si = ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (lump("a", x1),)),))
    run = ss.run(si, seed=3, draws=2_000)
    with pytest.raises(sens.SensitivityRefused) as refused:
        sens.analyse(si, seed=3, draws=2_000, severe_percentile=Decimal(95), input_digest=run.input_digest,
                     outcomes_sha256="sha256:" + "0" * 64)
    assert refused.value.code == "result_not_reproduced"
    changed = ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (lump("a", p("x1.amt", "money", "0", "100000",
                                                                                 "300000", source="EXPERT_ESTIMATE")),)),))
    with pytest.raises(sens.SensitivityRefused) as refused:
        sens.analyse(changed, seed=3, draws=2_000, severe_percentile=Decimal(95), input_digest=run.input_digest,
                     outcomes_sha256=run.record["outcomes_sha256"])
    assert refused.value.code == "inputs_changed"


def test_point_masses_are_fixed_and_what_the_gross_does_not_read_is_listed_apart():
    x1 = p("x1.amt", "money", "0", "100000", "200000", source="EXPERT_ESTIMATE")
    fixed = p("fixed.amt", "money", "25000")
    deductible = p("policy.deductible", "money", "10000", "20000", "40000", source="EXPERT_ESTIMATE")
    limit = p("policy.limit", "money", "1000000")
    policy = InsurancePolicy(deductible, limit)
    event = LossEvent("ev", "USD", (lump("a", x1), lump("b", fixed, "legal")))
    _, record = analysed(ss.ScenarioInput("s", "USD", (event,), policy=policy))
    assert [e["name"] for e in record["ranked"]] == ["x1.amt"]
    assert {f["name"] for f in record["fixed"]} == {"fixed.amt", "policy.limit"}
    assert record["not_in_gross_cash"] == ["policy.deductible"]
    assert Decimal(record["ranked"][0]["importance"]) == 1


def test_the_tornado_swings_at_most_its_limit_and_ranks_every_parameter():
    components = tuple(
        lump(f"c{i}", p(f"x{i:02d}.amt", "money", "0", str(1000 * (i + 1)), str(2000 * (i + 1)),
                        source="EXPERT_ESTIMATE"))
        for i in range(sens.MAX_SWINGS + 4)
    )
    _, record = analysed(ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", components),)), draws=2_000)
    assert len(record["ranked"]) == sens.MAX_SWINGS + 4
    assert record["swung"] == sens.MAX_SWINGS
    assert [e["swing"] is not None for e in record["ranked"]] == [True] * sens.MAX_SWINGS + [False] * 4
    # The widest ranges are the most important.
    assert record["ranked"][0]["name"] == f"x{sens.MAX_SWINGS + 3:02d}.amt"


def test_a_run_with_a_frequency_ranks_the_frequency_and_swings_it_by_its_counts():
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "1", "3", "6", source="INDUSTRY_BENCHMARK")
    severity = p("x1.amt", "money", "90000", "100000", "110000", source="EXPERT_ESTIMATE")
    si = ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (lump("a", severity),)),),
                          stated={ss.FREQUENCY_PARAMETER: stated("poisson", rate="3")}, frequency=frequency)
    _, record = analysed(si)
    assert record["basis"] == ss.ANNUAL_BASIS
    first = record["ranked"][0]
    assert first["name"] == ss.FREQUENCY_PARAMETER and first["frequency"] is True
    assert first["direction"] == sens.INCREASES and first["source_types"] == ["INDUSTRY_BENCHMARK"]
    assert Decimal(first["importance"]) > Decimal("0.9")
    assert record["swing_baseline"]["frequency_at"]["mean_count"]
    assert Decimal(first["swing"]["low_outcome"]) < Decimal(first["swing"]["high_outcome"])


def test_ties_take_their_mean_rank():
    import numpy as np

    ranks, ordered = sens.centred_ranks(np.array([3.0, 1.0, 3.0, 2.0]))
    # Ranks 3.5, 1, 3.5, 2 (doubled 7, 2, 7, 4), minus n + 1 = 5.
    assert ranks.tolist() == [2, -3, 2, -1] and ordered.tolist() == [1.0, 2.0, 3.0, 3.0]
    assert int(ranks.sum()) == 0


# ======================================================================
# The grade
# ======================================================================


def w(name, source, level, *, derived=False, sources=None):
    return g.Weighted(name, tuple(sources or (source,)), Decimal(level), derived=derived)


def graded(weighted, *, stale=(), refusal=None, unknown=(), per_occurrence=()):
    return g.grade(refusal=refusal, unknown_cash_components=unknown, weighted=weighted, stale=stale,
                   per_occurrence=per_occurrence)


def test_customer_and_observed_figures_that_are_fresh_grade_a():
    result = graded([w("txn", "CUSTOMER_PROVIDED", "0.6"), w("window", "MYTHOS_OBSERVED", "0.4")])
    assert result.grade is ConfidenceGrade.A and result.base is ConfidenceGrade.A and result.downgrades == ()
    assert result.shares["customer"] == "0.6" and result.shares["observed"] == "0.4"
    assert result.reason.startswith("A: weighed by each figure's share of the base-case level")


def test_benchmark_heavy_grades_c():
    result = graded([w("churn", "INDUSTRY_BENCHMARK", "0.7"), w("txn", "CUSTOMER_PROVIDED", "0.3")])
    assert result.grade is ConfidenceGrade.C


def test_mostly_expert_grades_d():
    result = graded([w("window", "EXPERT_ESTIMATE", "0.8"), w("txn", "CUSTOMER_PROVIDED", "0.2")])
    assert result.grade is ConfidenceGrade.D


def test_a_refused_run_conflicting_inputs_and_an_unknown_cash_component_are_unknown():
    weighted = [w("txn", "CUSTOMER_PROVIDED", "1")]
    refused = graded(weighted, refusal="no_admissible_distribution")
    assert refused.grade is ConfidenceGrade.UNKNOWN and "refused" in refused.reason
    conflict = graded(weighted, refusal="distribution_contradicts_range")
    assert conflict.grade is ConfidenceGrade.UNKNOWN and "the inputs conflict" in conflict.reason
    unknown = graded(weighted, unknown=["ev/customer-loss"])
    assert unknown.grade is ConfidenceGrade.UNKNOWN and "ev/customer-loss" in unknown.reason
    assert unknown.shares["customer"] == "1"  # the evidence mix is still shown
    assert graded([]).grade is ConfidenceGrade.UNKNOWN


def test_each_downgrade_fires_once():
    base = [w("txn", "CUSTOMER_PROVIDED", "0.97"), w("guess", "EXPERT_ESTIMATE", "0.03")]
    assert graded(base).grade is ConfidenceGrade.A  # a 3% guess is not material
    # Two stale figures are one step, not two.
    stale = graded(base, stale=["txn", "guess"])
    assert stale.grade is ConfidenceGrade.B and stale.downgrades == (g.STALE,)
    # A material expert figure: one step, however many.
    experts = [w("txn", "CUSTOMER_PROVIDED", "0.95"), w("e1", "EXPERT_ESTIMATE", "0.05")]
    assert graded(experts).base is ConfidenceGrade.A
    assert graded(experts).downgrades == (g.EXPERT,) and graded(experts).grade is ConfidenceGrade.B
    two = [w("txn", "CUSTOMER_PROVIDED", "0.85"), w("e1", "EXPERT_ESTIMATE", "0.10"), w("e2", "UNKNOWN", "0.05")]
    assert graded(two).downgrades == (g.EXPERT,) and graded(two).expert == ("e1", "e2")
    # A material derived value: one step.
    derived = [w("txn", "CUSTOMER_PROVIDED", "0.9"),
               w("ev:window", "CALCULATED", "0.1", derived=True, sources=("MYTHOS_OBSERVED", "CUSTOMER_PROVIDED"))]
    assert graded(derived).downgrades == (g.DERIVED,) and graded(derived).grade is ConfidenceGrade.B
    # All three: three steps, A to D; never below D.
    everything = [w("txn", "CUSTOMER_PROVIDED", "0.90"), w("e1", "EXPERT_ESTIMATE", "0.05"),
                  w("ev:w", "CALCULATED", "0.05", derived=True, sources=("CUSTOMER_PROVIDED",))]
    result = graded(everything, stale=["txn"])
    assert result.base is ConfidenceGrade.A
    assert result.downgrades == (g.STALE, g.EXPERT, g.DERIVED) and result.grade is ConfidenceGrade.D
    assert graded([w("x", "EXPERT_ESTIMATE", "1")], stale=["x"]).grade is ConfidenceGrade.D


def test_the_grade_weighs_by_level_not_by_count():
    """One customer figure and one expert figure, either way round: the grade
    follows the one that carries the level. By count both would be one half."""
    customer_drives = graded([w("txn", "CUSTOMER_PROVIDED", "0.97"), w("guess", "EXPERT_ESTIMATE", "0.03")])
    expert_drives = graded([w("txn", "CUSTOMER_PROVIDED", "0.03"), w("guess", "EXPERT_ESTIMATE", "0.97")])
    assert customer_drives.grade is ConfidenceGrade.A
    assert expert_drives.grade is ConfidenceGrade.D
    assert customer_drives.expert == () and expert_drives.expert == ("guess",)


def test_no_level_to_weigh_is_unknown_never_a_count():
    """Review round 1, H1: the equal-weight fallback is gone. A base-case gross of
    zero has no level to weigh, and is Unknown."""
    flat = graded([w("txn", "CUSTOMER_PROVIDED", "0"), w("guess", "EXPERT_ESTIMATE", "0")])
    assert flat.grade is ConfidenceGrade.UNKNOWN and "no level to weigh" in flat.reason


def test_fixed_figures_are_weighed_by_their_level():
    """Review round 1, L8: figures that are all fixed are graded by their level,
    exactly as ranges at the same base would be."""
    p20 = [w(f"c{i}", "CUSTOMER_PROVIDED", "0.0000002") for i in range(20)] + [w("fine", "EXPERT_ESTIMATE", "0.999996")]
    result = graded(p20)
    assert result.grade is ConfidenceGrade.D and result.expert == ("fine",)
    assert graded([w("a", "CUSTOMER_PROVIDED", "0.9"), w("b", "OFFICIAL_PUBLIC", "0.1")]).grade is ConfidenceGrade.A


def test_a_derived_value_rests_on_the_contributors_that_supply_it():
    result = graded([w("ev:window", "CALCULATED", "1", derived=True, sources=("MYTHOS_OBSERVED", "EXPERT_ESTIMATE"))])
    assert result.shares["observed"] == "0.5" and result.shares["expert"] == "0.5" and result.shares["calculated"] == "0"


def test_a_per_occurrence_parameter_of_an_annual_run_is_unknown():
    """Review round 1, L6: such a parameter is neither ranked nor weighed yet."""
    result = graded([w("txn", "CUSTOMER_PROVIDED", "1")], per_occurrence=["sev.amt"])
    assert result.grade is ConfidenceGrade.UNKNOWN and "sev.amt drawn per occurrence" in result.reason
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "1", "3", "6")
    severity = p("sev.amt", "money", "0", "100000", "5000000", source="EXPERT_ESTIMATE")
    si = ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (lump("a", severity),)),),
                          stated={ss.FREQUENCY_PARAMETER: stated("poisson", rate="3")}, frequency=frequency,
                          per_occurrence=frozenset({"sev.amt"}))
    _, record = analysed(si)
    assert record["per_occurrence"] == ["sev.amt"]


def test_the_thresholds_are_constants_in_the_grades_version_digest(monkeypatch):
    record = g.version_record()
    assert record["thresholds"]["A"] == {"evidence_at_least": "0.8", "assumption_at_most": "0.05"}
    assert record["material_share"] == "0.05"
    digest = g.version_digest()
    assert graded([w("txn", "CUSTOMER_PROVIDED", "1")]).as_dict()["version_digest"] == digest
    monkeypatch.setattr(g, "MATERIAL_SHARE", Decimal("0.10"))
    assert g.version_digest() != digest


def test_every_source_type_has_a_class():
    assert set(g.CLASSES) == set(SourceType)
    assert set(g.CLASSES.values()) == set(g.CLASS_ORDER)


# ======================================================================
# The level: each figure's share of the base case (review round 1, H1), an
# ADDITIVE decomposition at base (review round 2, HIGH 1 and MEDIUM 2)
# ======================================================================


def level_of(record, line=ss.GROSS_CASH) -> dict:
    return {entry["name"]: entry for entry in record["level"][line]["parameters"]}


def share_of(record, name, line=ss.GROSS_CASH) -> Decimal:
    return Decimal(level_of(record, line)[name]["share"])


def near(value, target, tolerance="1E-9") -> bool:
    return abs(Decimal(value) - Decimal(target)) < Decimal(tolerance)


def test_a_sum_shares_its_level_by_each_figures_base_fixed_or_ranged():
    """A lump of 4M-6M (an expert range, base 5M), a fixed $1M and a customer gamma
    (base 100,000): shares 5/6.1, 1/6.1 and 0.1/6.1, the fixed figure counting as a
    range would."""
    ranged = p("fine.amt", "money", "4000000", "5000000", "6000000", source="EXPERT_ESTIMATE")
    fixed = p("fixed.amt", "money", "1000000")
    measured = p("cost.amt", "money", "0", "100000", "500000")
    event = LossEvent("ev", "USD", (lump("a", ranged), lump("b", fixed, "legal"), lump("c", measured, "recovery")))
    _, record = analysed(ss.ScenarioInput("s", "USD", (event,), stated={
        "cost.amt": stated("gamma", shape="4", scale="25000")}))
    level = level_of(record)
    for name, base in (("fine.amt", "5000000"), ("fixed.amt", "1000000"), ("cost.amt", "100000")):
        assert near(level[name]["share"], Decimal(base) / Decimal("6100000")), name
    assert level["fixed.amt"]["fixed"] is True and level["fine.amt"]["fixed"] is False
    assert record["level"][ss.GROSS_CASH]["base"] == "6100000"
    assert record["level"][ss.RETAINED_CASH] is None  # no policy: no retained line


def _repeat(key, count, loss, rate):
    return evaluate(key, "direct_financial", "repeat_loss", 1,
                    {"repeat_count": count, "loss_per_event": loss, "recovery_rate": rate}, as_of=AS_OF)


@pytest.mark.parametrize("rate", ["0.5", "0.9", "0.99"])
def test_a_product_splits_its_component_equally_and_a_recovery_is_one_factor(rate):
    """HIGH 1: repeat_loss = count x amount x (1 - recovery) is three factors, a
    third each at ANY recovery: the recovery is weighed through its complement
    1 - r, elasticity one like the others, never r / (1 - r) of the product (9 at
    0.9, 99 at 0.99)."""
    count = p("r.repeat_count", "count", "10")
    amount = p("r.loss_per_event", "money_per_unit", "10000", "12000", "15000", source="EXPERT_ESTIMATE")
    recovery = p("r.recovery_rate", "ratio", rate)
    _, record = analysed(ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (
        _repeat("direct", count, amount, recovery),)),)))
    for name in ("r.repeat_count", "r.loss_per_event", "r.recovery_rate"):
        assert near(share_of(record, name), Decimal(1) / 3), (rate, name)
    (piece,) = record["level"][ss.GROSS_CASH]["pieces"]
    inputs = {row["input"]: row for row in piece["inputs"]}
    assert inputs["recovery_rate"]["complement"] is True and inputs["repeat_count"]["complement"] is False
    assert near(inputs["recovery_rate"]["elasticity"], 1, "1E-6")


def test_a_complement_at_0_9_gets_no_more_than_the_other_factors_of_its_product():
    """HIGH 1: at r = 0.9 the old r / (1 - r) gave the recovery 9 / 11 of its product."""
    _, record = analysed(ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (_repeat(
        "direct", p("r.repeat_count", "count", "10"), p("r.loss_per_event", "money_per_unit", "100000"),
        p("r.recovery_rate", "ratio", "0.9")),)),)))
    recovery = share_of(record, "r.recovery_rate")
    for other in ("r.repeat_count", "r.loss_per_event"):
        assert recovery <= share_of(record, other) + Decimal("1E-9")


#: One product of each length k, with an input of each.
PRODUCTS = {
    2: ("interruption", "business_interruption", {"interruption_hours": ("hours", "10"),
                                                  "value_per_hour": ("money_per_hour", "5000")}),
    3: ("repeat_loss", "direct_financial", {"repeat_count": ("count", "10"), "loss_per_event": ("money_per_unit", "10000"),
                                            "recovery_rate": ("ratio", "0.5")}),
    4: ("support_contacts", "notification", {"affected": ("count", "10000"), "contact_rate": ("ratio", "0.5"),
                                             "handling_hours": ("hours", "1"), "loaded_rate": ("money_per_hour", "200")}),
    5: ("repeat_in_window", "direct_financial", {"transactions_per_day": ("count_per_day", "2400"),
                                                 "window_hours": ("hours", "10"), "success_rate": ("ratio", "0.1"),
                                                 "value_per_transaction": ("money_per_unit", "50"),
                                                 "recovery_rate": ("ratio", "0.9")}),
}


@pytest.mark.parametrize("k", sorted(PRODUCTS))
def test_one_expert_factor_of_a_product_of_k_carries_one_kth_of_it(k):
    """HIGH 1: a product of k factors, one an expert's (each in turn), the rest the
    customer's, beside a customer lump of the product's own base: the product is half
    the level, and the expert factor carries 1/k of it, whatever the others are."""
    formula, family, inputs = PRODUCTS[k]
    for expert in inputs:
        figures = {
            name: p(f"x.{name}", unit, figure, source="EXPERT_ESTIMATE" if name == expert else "CUSTOMER_PROVIDED")
            for name, (unit, figure) in inputs.items()
        }
        product = evaluate("product", family, formula, 1, figures, as_of=AS_OF)
        twin = lump("twin", p("c.lump", "money", str(product.base.amount)), "legal")
        grade_, record = _grade_of(ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (product, twin)),)))
        assert near(share_of(record, f"x.{expert}"), Decimal(1) / (2 * k)), (k, expert)
        assert near(share_of(record, "c.lump"), Decimal("0.5")), (k, expert)
        assert near(grade_.shares["expert"], Decimal(1) / (2 * k), "1E-6"), (k, expert)


def test_a_frequency_carries_one_half():
    """HIGH 1: the headline is frequency x severity, so the frequency carries one
    half, whatever the severity's formulas, and the severity's decomposition the other."""
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "1", "3", "6", source="INDUSTRY_BENCHMARK")
    a = p("a.amt", "money", "75000", "100000", "125000", source="EXPERT_ESTIMATE")
    b = p("b.amt", "money", "300000")
    si = ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (lump("a", a), lump("b", b, "legal"))),),
                          stated={ss.FREQUENCY_PARAMETER: stated("poisson", rate="3")}, frequency=frequency)
    _, record = analysed(si)
    level = level_of(record)
    assert Decimal(level[ss.FREQUENCY_PARAMETER]["share"]) == Decimal("0.5")
    assert Decimal(level["a.amt"]["share"]) == Decimal("0.125") and Decimal(level["b.amt"]["share"]) == Decimal("0.375")
    # A product of four factors beside it moves nothing of the frequency's half.
    formula, family, inputs = PRODUCTS[4]
    product = evaluate("product", family, formula, 1, {n: p(f"x.{n}", u, f) for n, (u, f) in inputs.items()},
                       as_of=AS_OF)
    si = ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (lump("a", a), product)),),
                          stated={ss.FREQUENCY_PARAMETER: stated("poisson", rate="3")}, frequency=frequency)
    _, record = analysed(si)
    assert share_of(record, ss.FREQUENCY_PARAMETER) == Decimal("0.5")


def test_a_frequency_whose_base_is_zero_has_no_level_and_grades_unknown():
    """LOW 3 (the reviewer's h1-zero probe): a frequency of 0 / 0 / 1 (Poisson 0.01)
    beside a customer lump: a base-case year holds no occurrence, so there is no level
    to weigh; the grade is Unknown, never A, and the frequency's zero is not hidden as
    a zero elasticity."""
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "0", "0", "1")
    cost = p("c.cost", "money", "100000")
    si = ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (lump("c", cost, "legal"),)),),
                          stated={ss.FREQUENCY_PARAMETER: stated("poisson", rate="0.01")}, frequency=frequency)
    grade_, record = _grade_of(si)
    gross = record["level"][ss.GROSS_CASH]
    assert gross["defined"] is False and "the frequency's base is zero" in gross["undefined_because"]
    assert gross["frequency_base"] == "0"
    assert grade_.grade is ConfidenceGrade.UNKNOWN and "the frequency's base is zero" in grade_.reason


@pytest.mark.parametrize("fine, count, expert", [("3000000", "100", "0.75"), ("8500000", "150", "0.85"),
                                                 ("19000000", "1000", "0.95")])
def test_an_expert_lump_of_three_quarters_or_more_of_the_level_never_grades_a(fine, count, expert):
    """HIGH 1, the reviewer's (a) and (b): an expert lump beside a customer
    repeat_loss at a high recovery (count x 1,000,000 x (1 - r), r = 0.99, 0.99,
    0.999 so the product is 1M, 1.5M and 1M): the lump carries exactly its base
    share (75%, 85%, 95%), and the grade is D. Before, the recovery's r / (1 - r)
    swamped the level and the lump read 1.9% to 2.9%: A."""
    rate = "0.999" if count == "1000" else "0.99"
    product = _repeat("repeat", p("c.count", "count", count), p("c.loss", "money_per_unit", "1000000"),
                      p("c.rate", "ratio", rate))
    fine_ = lump("fine", p("e.fine", "money", fine, source="EXPERT_ESTIMATE"), "regulatory_compliance")
    grade_, record = _grade_of(ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (fine_, product)),)))
    assert share_of(record, "e.fine") == Decimal(expert)
    for name in ("c.count", "c.loss", "c.rate"):
        assert near(share_of(record, name), (1 - Decimal(expert)) / 3), name
    assert grade_.grade is ConfidenceGrade.D and grade_.expert == ("e.fine",), grade_.reason


def test_a_four_factor_product_no_longer_dilutes_an_expert_lump():
    """HIGH 1, the reviewer's (c): an expert lump of 200,000 beside a customer
    support_contacts of 10000 x 0.5 x 1 x 200 = 1,000,000. The lump is 1/6 of the
    base case and carries 1/6 (4.8% before, as each factor counted the product's
    whole share); each factor 5/24. Not A: C (B less one step for the expert figure)."""
    formula, family, inputs = PRODUCTS[4]
    product = evaluate("support", family, formula, 1, {n: p(f"c.{n}", u, f) for n, (u, f) in inputs.items()},
                       as_of=AS_OF)
    fine = lump("fine", p("e.fine", "money", "200000", source="EXPERT_ESTIMATE"), "regulatory_compliance")
    grade_, record = _grade_of(ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (fine, product)),)))
    assert near(share_of(record, "e.fine"), Decimal(1) / 6)
    for name in inputs:
        assert near(share_of(record, f"c.{name}"), Decimal(5) / 24), name
    assert grade_.base is ConfidenceGrade.B and grade_.grade is ConfidenceGrade.C, grade_.reason


def test_an_expert_frequency_carries_half_the_level_beside_any_severity():
    """HIGH 1, the reviewer's (d): an expert's Poisson frequency beside a customer
    repeat_loss at r = 0.95. The whole annual figure scales with the expert's rate:
    it carries one half (4.5% before), and the grade is D (C less one step), not A."""
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "1", "2", "4", source="EXPERT_ESTIMATE")
    product = _repeat("repeat", p("c.count", "count", "10"), p("c.loss", "money_per_unit", "100000"),
                      p("c.rate", "ratio", "0.95"))
    si = ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (product,)),),
                          stated={ss.FREQUENCY_PARAMETER: stated("poisson", rate="2")}, frequency=frequency)
    grade_, record = _grade_of(si)
    assert share_of(record, ss.FREQUENCY_PARAMETER) == Decimal("0.5")
    assert grade_.shares["expert"] == "0.5" and grade_.expert == (ss.FREQUENCY_PARAMETER,)
    assert grade_.grade is ConfidenceGrade.D, grade_.reason


def test_a_customer_recovery_inside_an_experts_product_never_raises_the_grade():
    """HIGH 1, the reviewer's (e): an expert's repeat_count (a range 2-200) x a
    customer's loss x (1 - a customer's recovery). The count scales the whole loss:
    a third of it at every recovery, and the same grade at 0.5, 0.9 and 0.99 (before:
    D, C and A -- a recovery that LOWERS the loss raised the grade)."""
    grades = {}
    for rate in ("0.5", "0.9", "0.99"):
        product = _repeat("repeat", p("e.count", "count", "2", "20", "200", source="EXPERT_ESTIMATE"),
                          p("c.loss", "money_per_unit", "100000"), p("c.rate", "ratio", rate))
        grade_, record = _grade_of(ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (product,)),)))
        assert near(share_of(record, "e.count"), Decimal(1) / 3), rate
        grades[rate] = grade_.grade
    assert set(grades.values()) == {ConfidenceGrade.D}, grades


def test_every_lines_shares_sum_to_one_and_are_computed_from_bases():
    """HIGH 1: the shares of a line sum to one (exactly, before they are written to
    ten places) and depend on the bases only: a range and its base collapsed give the
    same level record."""
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "1", "2", "4")
    ranged = p("e.count", "count", "2", "20", "200", source="EXPERT_ESTIMATE")
    fixed = p("e.count", "count", "20", source="EXPERT_ESTIMATE")
    policy = InsurancePolicy(p("ins.deductible", "money", "50000"), p("ins.limit", "money", "1500000"))
    records = []
    for count in (ranged, fixed):
        product = _repeat("repeat", count, p("c.loss", "money_per_unit", "100000"), p("c.rate", "ratio", "0.3"))
        fine = lump("fine", p("c.fine", "money", "250000"), "regulatory_compliance")
        si = ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (product, fine)),), policy=policy,
                              stated={ss.FREQUENCY_PARAMETER: stated("poisson", rate="2")}, frequency=frequency)
        _, record = analysed(si, draws=2_000)
        for line in (ss.GROSS_CASH, ss.RETAINED_CASH):
            total = sum(Decimal(e["share"]) for e in record["level"][line]["parameters"])
            assert near(total, 1, "1E-8"), (line, total)
        records.append(record["level"])
    for line in (ss.GROSS_CASH, ss.RETAINED_CASH):
        shares = [{e["name"]: e["share"] for e in level[line]["parameters"]} for level in records]
        assert shares[0] == shares[1], line


# ----------------------------------------------------------------------
# The retained cash under a policy (review round 2, MEDIUM 2)
# ----------------------------------------------------------------------


def _policy_case(components, *, deductible="0", limit="10000000", deductible_source="CUSTOMER_PROVIDED",
                 limit_source="CUSTOMER_PROVIDED", sublimits=None, exclusions=(), waiting=None, frequency=None):
    policy = InsurancePolicy(
        p("ins.deductible", "money", deductible, source=deductible_source),
        p("ins.limit", "money", limit, source=limit_source),
        sublimits={family: p(f"ins.sublimit.{family}", "money", figure) for family, figure in (sublimits or {}).items()},
        exclusions=frozenset(exclusions),
        waiting_period_hours=None if waiting is None else p("ins.waiting", "hours", waiting[0], source=waiting[1]),
    )
    stated_ = {}
    if frequency is not None:
        stated_ = {ss.FREQUENCY_PARAMETER: stated("poisson", rate="2")}
        frequency = p(ss.FREQUENCY_PARAMETER, "count", "1", "2", "4", source=frequency)
    si = ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", tuple(components)),), policy=policy, stated=stated_,
                          frequency=frequency)
    return si


def _both(si):
    """The gross and the retained grade of ``si`` as the card makes them, the
    headline, and the analysis."""
    gross, record = _grade_of(si)
    retained, _ = _grade_of(si, line=ss.RETAINED_CASH)
    return gross, retained, g.headline(gross, retained), record


def test_an_expert_deductible_that_is_the_retained_cash_lowers_the_headline_grade():
    """MEDIUM 2 (the reviewer's insurance probe): a customer gross of 1,000,000 and
    frequency, an expert's deductible of 50,000 and a customer limit of 10M. The
    retained cash per occurrence IS the deductible: the retained line's level is the
    frequency's half and the deductible's half, so the retained grade is D (C less one
    step) while the gross is A; the headline is the lower, D. Before: A, 100% customer."""
    si = _policy_case([lump("response", p("c.cost", "money", "1000000"), "legal")], deductible="50000",
                      deductible_source="EXPERT_ESTIMATE", frequency="CUSTOMER_PROVIDED")
    gross, retained, (line, headline), record = _both(si)
    assert share_of(record, "ins.deductible", ss.RETAINED_CASH) == Decimal("0.5")
    assert share_of(record, "c.cost", ss.RETAINED_CASH) == 0 and "ins.deductible" not in level_of(record)
    assert record["level"][ss.RETAINED_CASH]["base"] == "50000"
    assert gross.grade is ConfidenceGrade.A and retained.grade is ConfidenceGrade.D, retained.reason
    assert (line, headline.grade) == (ss.RETAINED_CASH, ConfidenceGrade.D)


def test_an_expert_limit_that_the_retained_cash_passes_lowers_the_headline_grade():
    """MEDIUM 2: deductible 0 and an expert's limit of 950,000 under a customer gross of
    1,000,000: the 50,000 past the limit is split 1,000,000 : 950,000 between the covered
    cash and the limit (their elasticities at base); the retained grade is C."""
    si = _policy_case([lump("response", p("c.cost", "money", "1000000"), "legal")], limit="950000",
                      limit_source="EXPERT_ESTIMATE", frequency="CUSTOMER_PROVIDED")
    gross, retained, (line, headline), record = _both(si)
    assert near(share_of(record, "ins.limit", ss.RETAINED_CASH), Decimal("0.5") * 95 / 195)
    assert near(share_of(record, "c.cost", ss.RETAINED_CASH), Decimal("0.5") * 100 / 195)
    assert gross.grade is ConfidenceGrade.A and retained.grade is ConfidenceGrade.C, retained.reason
    assert (line, headline.grade) == (ss.RETAINED_CASH, ConfidenceGrade.C)


def test_the_retained_pieces_sum_to_step_4s_retained_cash():
    """MEDIUM 2: uncovered cash (an excluded family), business interruption a waiting
    period above zero leaves uncovered (one half the waiting period's), a family's excess
    over its sublimit, the deductible and the cash past the limit: the pieces sum to the
    retained cash step 4's Decimal insurance gives at base, to the last digit."""
    bi = evaluate("outage", "business_interruption", "interruption", 1, {
        "interruption_hours": p("c.hours", "hours", "10"), "value_per_hour": p("c.value", "money_per_hour", "5000")},
        as_of=AS_OF)
    components = [
        lump("response", p("c.legal", "money", "900000"), "legal"),
        lump("fine", p("c.fine", "money", "300000"), "regulatory_compliance"),
        lump("notify", p("c.notify", "money", "120000"), "notification"),
        bi,
    ]
    cases = {
        "sublimit and limit": dict(deductible="25000", limit="500000", sublimits={"legal": "400000"}),
        "excluded family": dict(deductible="25000", exclusions=("regulatory_compliance",)),
        "waiting period above zero": dict(deductible="25000", waiting=("8", "EXPERT_ESTIMATE")),
        "waiting period zero": dict(deductible="25000", waiting=("0", "CUSTOMER_PROVIDED")),
        "deductible above the covered cash": dict(deductible="5000000"),
        "a sublimit at the kink": dict(deductible="25000", sublimits={"legal": "900000"}),
    }
    for name, terms in cases.items():
        si = _policy_case(components, **terms)
        plan = ss.plan(si)
        level = sens.level_shares(plan)[ss.RETAINED_CASH]
        exact = plan.exact_scenario[ss.RETAINED_CASH]
        assert level["defined"] and Decimal(level["base"]) == exact, (name, level["base"], exact)
        assert sum(Decimal(piece["base"]) for piece in level["pieces"]) == exact, name
        total = sum(Decimal(e["share"]) for e in level["parameters"])
        assert near(total, 1, "1E-8"), (name, total)
    # The waiting period carries one half of the business interruption it leaves uncovered.
    plan = ss.plan(_policy_case(components, deductible="25000", waiting=("8", "EXPERT_ESTIMATE")))
    level = sens.level_shares(plan)[ss.RETAINED_CASH]
    (piece,) = [x for x in level["pieces"] if x["kind"] == "uncovered_by_waiting_period"]
    split = {row["parameter"]: Decimal(row["share"]) for row in piece["split"]}
    assert near(split["ins.waiting"], Decimal(piece["share"]) / 2)
    # At zero it carries nothing: the interruption is covered.
    plan = ss.plan(_policy_case(components, deductible="25000", waiting=("0", "CUSTOMER_PROVIDED")))
    assert Decimal(level_of({"level": sens.level_shares(plan)}, ss.RETAINED_CASH)["ins.waiting"]["share"]) == 0


def test_a_retained_cash_of_zero_at_base_has_no_level():
    """MEDIUM 2: a policy that recovers everything at base leaves no retained level to
    weigh: the retained grade is Unknown, and so is the headline (the lower)."""
    si = _policy_case([lump("response", p("c.cost", "money", "1000000"), "legal")])
    gross, retained, (line, headline), record = _both(si)
    assert record["level"][ss.RETAINED_CASH]["defined"] is False
    assert gross.grade is ConfidenceGrade.A and retained.grade is ConfidenceGrade.UNKNOWN
    assert (line, headline.grade) == (ss.RETAINED_CASH, ConfidenceGrade.UNKNOWN)


def test_the_headline_grade_is_the_lower_of_the_gross_and_the_retained():
    a = graded([w("x", "CUSTOMER_PROVIDED", "1")])
    d = graded([w("x", "EXPERT_ESTIMATE", "1")])
    unknown = graded([])
    assert g.headline(a, None) == ("gross_cash", a)
    assert g.headline(a, d) == ("retained_cash", d) and g.headline(d, a) == ("gross_cash", d)
    assert g.headline(a, a) == ("retained_cash", a)  # equal: the line the headline figures are
    assert g.headline(d, unknown)[1].grade is ConfidenceGrade.UNKNOWN
    assert g.version_record()["lines"] == g.HEADLINE_RULE


def _grade_of(si, seed=7, draws=5_000, line=ss.GROSS_CASH):
    """A line's grade as the card makes it, from the stored-form inputs and analysis."""
    from assurance.economics import validity_service

    run, record = analysed(si, seed=seed, draws=draws)
    weighted = validity_service._weighted(dict(run.inputs), record, line)
    return g.grade(refusal=None, unknown_cash_components=[], weighted=weighted,
                   per_occurrence=record["per_occurrence"],
                   undefined=record["level"][line]["undefined_because"]), record


LADDER = (ConfidenceGrade.A, ConfidenceGrade.B, ConfidenceGrade.C, ConfidenceGrade.D)


def _collapse(parameter: Parameter) -> Parameter:
    base = parameter.base
    return Parameter(parameter.name, parameter.unit, parameter.source_type, base, base, base, parameter.evidence_ref,
                     effective_date=parameter.effective_date, fresh_until=parameter.fresh_until)


def _invariant_cases():
    fine = p("fine.amt", "money", "4000000", "5000000", "6000000", source="EXPERT_ESTIMATE")
    cost = p("cost.amt", "money", "0", "100000", "500000")
    gamma = {"cost.amt": stated("gamma", shape="4", scale="25000")}
    poisson = {ss.FREQUENCY_PARAMETER: stated("poisson", rate="2")}
    frequency = p(ss.FREQUENCY_PARAMETER, "count", "1", "2", "4")
    ones = [p(f"c{i:02d}.amt", "money", "1") for i in range(20)]
    count = p("r.repeat_count", "count", "5", "10", "20", source="EXPERT_ESTIMATE")
    amount = p("r.loss_per_event", "money_per_unit", "10000", "12000", "15000", source="EXPERT_ESTIMATE")
    recovery = p("r.recovery_rate", "ratio", "0.10", "0.50", "0.90", source="EXPERT_ESTIMATE")
    small = p("small.amt", "money", "0", "30000", "200000", source="EXPERT_ESTIMATE")
    big = p("big.amt", "money", "1000000")
    deductible = p("ins.deductible", "money", "25000", "50000", "100000", source="EXPERT_ESTIMATE")
    limit = p("ins.limit", "money", "600000", "800000", "1200000", source="EXPERT_ESTIMATE")
    return {
        # The reviewer's three cases (round 1, H1).
        "fine_range_and_customer_gamma": ([("fine", fine), ("cost", cost)], gamma, None),
        "the_same_with_a_frequency": ([("fine", fine), ("cost", cost)], {**gamma, **poisson}, frequency),
        "twenty_customer_dollars_and_an_expert_fine": ([("fine", fine)] + [(f"c{i:02d}", o) for i, o in enumerate(ones)],
                                                        {}, None),
        # A product, every factor an expert range.
        "a_product_of_expert_ranges": ([("direct", (count, amount, recovery))], {}, None),
        # A wide expert range carrying most of the variance and little of the level.
        "a_small_wide_expert_range": ([("small", small), ("big", big)], {}, None),
        # Review round 2, MEDIUM 2: an expert's deductible and limit, ranges, under a
        # policy: the headline grade (the lower of the two lines) never rises either.
        "expert_policy_terms_under_a_policy": ([("big", big), ("cost", cost)], {**gamma, **poisson}, frequency,
                                               (deductible, limit)),
    }


def _scenario(lines, stated_by_name, frequency, policy=None, collapsed=frozenset()):
    def take(parameter):
        return _collapse(parameter) if parameter.name in collapsed else parameter

    components = []
    for key, value in lines:
        if isinstance(value, tuple):
            count, amount, recovery = (take(x) for x in value)
            components.append(evaluate(key, "direct_financial", "repeat_loss", 1, {
                "repeat_count": count, "loss_per_event": amount, "recovery_rate": recovery}, as_of=AS_OF))
        else:
            components.append(lump(key, take(value), "legal"))
    stated_now = {name: d for name, d in stated_by_name.items() if name not in collapsed}
    insurance = None if policy is None else InsurancePolicy(*(take(term) for term in policy))
    return ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", tuple(components)),), stated=stated_now,
                            frequency=frequency, policy=insurance)


def _headline_of(si):
    """The card's grade: the gross cash's, or under a policy the lower of the two lines'."""
    gross, record = _grade_of(si)
    if si.policy is None:
        return gross, record
    retained, _ = _grade_of(si, line=ss.RETAINED_CASH)
    return g.headline(gross, retained)[1], record


@pytest.mark.parametrize("case", sorted(_invariant_cases()))
def test_collapsing_a_range_to_its_base_never_raises_the_grade(case):
    """Review round 1, H1: the required invariant. Each range of the case, alone and
    all together, collapsed to one figure at its base: the grade is never higher on
    the ladder. The reviewer's 20 x $1 customer + $5M expert never grades A. Under a
    policy, the headline grade (review round 2, MEDIUM 2)."""
    lines, stated_by_name, frequency, *policy = _invariant_cases()[case]
    policy = policy[0] if policy else None
    figures = [x for _, v in lines for x in (v if isinstance(v, tuple) else (v,))] + list(policy or ())
    names = sorted({x.name for x in figures if x.low != x.high})
    ranged, _ = _headline_of(_scenario(lines, stated_by_name, frequency, policy))
    assert ranged.grade in LADDER, ranged.reason
    for collapsed in [frozenset({name}) for name in names] + [frozenset(names)]:
        point, record = _headline_of(_scenario(lines, stated_by_name, frequency, policy, collapsed))
        assert point.grade in LADDER, point.reason
        assert LADDER.index(point.grade) >= LADDER.index(ranged.grade), (case, sorted(collapsed), point.reason,
                                                                         ranged.reason)
    if case == "twenty_customer_dollars_and_an_expert_fine":
        assert ranged.grade is not ConfidenceGrade.A and point.grade is not ConfidenceGrade.A
        assert point.grade is ConfidenceGrade.D
    if case in ("fine_range_and_customer_gamma", "the_same_with_a_frequency"):
        assert point.grade is ConfidenceGrade.D, point.reason
    if case == "expert_policy_terms_under_a_policy":
        # The gross alone (customer figures and frequency) would be A.
        assert ranged.grade is not ConfidenceGrade.A and point.grade is not ConfidenceGrade.A, point.reason


def test_a_derived_value_is_weighed_by_the_contributor_that_supplies_its_base():
    """Review round 1, L8: the derived value's level share rests on the source of
    the contributor whose base it takes (the larger loss), not on CALCULATED."""
    from assurance.economics import validity_service

    expert = p("e1.amt", "money", "100000", "200000", "300000", source="EXPERT_ESTIMATE")
    customer = p("e2.amt", "money", "150000")
    merged = p("ev:amt", "money", "150000", "200000", "300000", source="CALCULATED")
    other = p("other.amt", "money", "200000")
    si = ss.ScenarioInput("s", "USD", (LossEvent("ev", "USD", (lump("a", merged), lump("b", other, "legal"))),),
                          derived={"ev:amt": (expert, customer)})
    run, record = analysed(si)
    entry = level_of(record)["ev:amt"]
    assert entry["derived_from"] == ["e1.amt", "e2.amt"] and entry["supplied_by"] == ["e1.amt"]
    weighted = {item.name: item for item in validity_service._weighted(dict(run.inputs), record)}
    assert weighted["ev:amt"].sources == (SourceType.EXPERT_ESTIMATE,) and weighted["ev:amt"].derived
    result = g.grade(refusal=None, unknown_cash_components=[], weighted=list(weighted.values()))
    assert result.shares["expert"] == "0.5" and result.shares["calculated"] == "0"
    assert result.expert == ("ev:amt",) and result.derived == ("ev:amt",)
