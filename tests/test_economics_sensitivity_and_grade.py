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
  importance, never by count; the thresholds are in its version digest.
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


def w(name, source, importance, *, expert=False, derived=False, sources=None):
    return g.Weighted(name, tuple(sources or (source,)), Decimal(importance), expert=expert, derived=derived)


def graded(weighted, *, stale=(), refusal=None, unknown=()):
    return g.grade(refusal=refusal, unknown_cash_components=unknown, weighted=weighted, stale=stale)


def test_customer_and_observed_figures_that_are_fresh_grade_a():
    result = graded([w("txn", "CUSTOMER_PROVIDED", "0.6"), w("window", "MYTHOS_OBSERVED", "0.4")])
    assert result.grade is ConfidenceGrade.A and result.base is ConfidenceGrade.A and result.downgrades == ()
    assert result.shares["customer"] == "0.6" and result.shares["observed"] == "0.4"
    assert result.reason.startswith("A: weighed by sensitivity importance")


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
    base = [w("txn", "CUSTOMER_PROVIDED", "0.97"), w("guess", "EXPERT_ESTIMATE", "0.03", expert=True)]
    assert graded(base).grade is ConfidenceGrade.A
    # Two stale figures are one step, not two.
    stale = graded(base, stale=["txn", "guess"])
    assert stale.grade is ConfidenceGrade.B and stale.downgrades == (g.STALE,)
    # A material expert range: one step, however many.
    experts = [w("txn", "CUSTOMER_PROVIDED", "0.85"), w("e1", "CUSTOMER_PROVIDED", "0.10", expert=True),
               w("e2", "CUSTOMER_PROVIDED", "0.05", expert=True)]
    assert graded(experts).downgrades == (g.EXPERT,) and graded(experts).grade is ConfidenceGrade.B
    # A material derived value: one step.
    derived = [w("txn", "CUSTOMER_PROVIDED", "0.9"),
               w("ev:window", "CALCULATED", "0.1", derived=True, sources=("MYTHOS_OBSERVED", "CUSTOMER_PROVIDED"))]
    assert graded(derived).downgrades == (g.DERIVED,) and graded(derived).grade is ConfidenceGrade.B
    # All three: three steps, A to D; never below D.
    everything = [w("txn", "CUSTOMER_PROVIDED", "0.85"), w("e1", "CUSTOMER_PROVIDED", "0.10", expert=True),
                  w("ev:w", "CALCULATED", "0.05", derived=True, sources=("CUSTOMER_PROVIDED", "MYTHOS_OBSERVED"))]
    result = graded(everything, stale=["txn"])
    assert result.downgrades == (g.STALE, g.EXPERT, g.DERIVED) and result.grade is ConfidenceGrade.D
    assert graded([w("x", "EXPERT_ESTIMATE", "1", expert=True)], stale=["x"]).grade is ConfidenceGrade.D


def test_the_grade_weighs_by_importance_not_by_count():
    """One customer figure and one expert range, either way round: the grade
    follows the one that carries the variance. By count both would be one half."""
    customer_drives = graded([w("txn", "CUSTOMER_PROVIDED", "0.97"), w("guess", "EXPERT_ESTIMATE", "0.03", expert=True)])
    expert_drives = graded([w("txn", "CUSTOMER_PROVIDED", "0.03"), w("guess", "EXPERT_ESTIMATE", "0.97", expert=True)])
    assert customer_drives.grade is ConfidenceGrade.A
    assert expert_drives.grade is ConfidenceGrade.D
    assert customer_drives.expert == () and expert_drives.expert == ("guess",)
    # Nothing uncertain: every parameter counts alike, and the card says so.
    flat = graded([w("txn", "CUSTOMER_PROVIDED", "0"), w("rate", "CUSTOMER_PROVIDED", "0")])
    assert flat.weighting == g.EQUAL and flat.grade is ConfidenceGrade.A


def test_a_derived_value_rests_on_its_contributors():
    result = graded([w("ev:window", "CALCULATED", "1", derived=True, sources=("MYTHOS_OBSERVED", "EXPERT_ESTIMATE"))])
    assert result.shares["observed"] == "0.5" and result.shares["expert"] == "0.5" and result.shares["calculated"] == "0"


def test_the_thresholds_are_constants_in_the_grades_version_digest(monkeypatch):
    record = g.version_record()
    assert record["thresholds"]["A"] == {"evidence_at_least": "0.8", "assumption_at_most": "0.05"}
    assert record["material_importance"] == "0.05"
    digest = g.version_digest()
    assert graded([w("txn", "CUSTOMER_PROVIDED", "1")]).as_dict()["version_digest"] == digest
    monkeypatch.setattr(g, "MATERIAL_IMPORTANCE", Decimal("0.10"))
    assert g.version_digest() != digest
    # No parameter past the tornado's limit can be material: twenty-one at the
    # materiality would sum past one.
    assert (sens.MAX_SWINGS + 1) * Decimal("0.05") > 1


def test_every_source_type_has_a_class():
    assert set(g.CLASSES) == set(SourceType)
    assert set(g.CLASSES.values()) == set(g.CLASS_ORDER)
