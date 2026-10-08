"""The banking pack's six templates, with no database (``docs/economics/spec-v1.md``,
section 23).

- each template is well formed: every component's formula exists and computes its
  family, every formula input has exactly one source, a parameter-set variable or an
  effect attribute of the input's own unit, and no template holds a figure;
- every effect type is covered, and where two templates cover one effect the
  precedence assigns it to exactly one;
- a source that holds nothing leaves its input unbound, so the component is unknown,
  never zero;
- a worked example per template, every figure computed by hand in the comments,
  labelled SYNTHETIC / ILLUSTRATIVE: section 30's bank payment agent comes out
  exactly as #146's known answer, and so does section 31's cross-customer exposure.
"""

from __future__ import annotations

import ast
import dataclasses
from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest

from assurance.economics.engine import formulas
from assurance.economics.engine import parameter_set as pset
from assurance.economics.engine import templates as tpl
from assurance.economics.engine.formulas import ESTIMATED, UNKNOWN, evaluate
from assurance.economics.engine.loss import InsurancePolicy, LossEvent, assess
from assurance.economics.engine.money import Money
from assurance.economics.engine.parameters import MONEY_UNITS, POINTS, Parameter, Unit
from tests import test_economics_known_answers as known

LABEL = "SYNTHETIC / ILLUSTRATIVE"
AS_OF = date(2026, 10, 6)
MODULE = Path(tpl.__file__)


def p(name, unit, low, base=None, high=None, source="CUSTOMER_PROVIDED", why="made up") -> Parameter:
    unit = Unit(unit)
    base = low if base is None else base
    high = base if high is None else high

    def value(figure):
        return Money(Decimal(figure), "USD") if unit in MONEY_UNITS else Decimal(figure)

    return Parameter(name, unit, source, value(low), value(base), value(high), f"{LABEL}: {why}")


def figures(component) -> tuple[Decimal, ...]:
    return tuple(component.at(point).amount for point in POINTS)


def total(range_) -> tuple[Decimal, ...]:
    return tuple(range_.at(point).amount for point in POINTS)


def run(template_id, variables, attributes) -> LossEvent:
    """The template's components for an effect, computed by #146's formulas from the
    parameters the template binds: what the builder writes, without the database."""
    chosen = tpl.CATALOGUE[(template_id, 1)]
    components = tuple(
        evaluate(
            planned.spec.component_key,
            planned.spec.family,
            planned.spec.formula_id,
            planned.spec.formula_version,
            planned.bindings(),
            as_of=AS_OF,
        )
        for planned in tpl.plan(chosen, variables, attributes)
    )
    return LossEvent(f"{template_id}-example", "USD", components)


def by_key(event) -> dict:
    return {c.component_id: c for c in event.components}


# ================================================================ the catalogue


def test_the_pack_is_six_of_the_eight_banking_families():
    assert [t.template_id for t in tpl.TEMPLATES] == [
        "payment_agent_misuse",
        "cross_customer_data_exposure",
        "customer_service_ai_misstatement",
        "fraud_aml_workflow_failure",
        "agent_approval_bypass",
        "third_party_provider_outage",
    ]
    # Each models one of the specification's section 22 families, by its name there.
    assert [t.name for t in tpl.TEMPLATES] == [
        "Payment / wire / ACH agent misuse",
        "Cross-customer data exposure",
        "Customer-service AI misstatement",
        "Fraud/AML workflow failure",
        "Agent approval bypass",
        "Third-party model/provider outage",
    ]
    # The precedence is a total order: one rank per template, 1 to 6.
    assert [t.precedence for t in tpl.TEMPLATES] == [1, 2, 3, 4, 5, 6]
    assert set(tpl.CATALOGUE) == {(t.template_id, 1) for t in tpl.TEMPLATES}
    assert tpl.PACK == "mythos.economics.banking-pack/v1"


@pytest.mark.parametrize("chosen", tpl.TEMPLATES, ids=lambda t: t.template_id)
def test_every_component_is_well_formed(chosen):
    """Every component's formula is in the catalogue and computes its family; every
    input of the formula has exactly one source, and that source is a variable of
    the parameter set or an attribute of the pack in the input's own unit; component
    keys are distinct within the template."""
    keys = [c.component_key for c in chosen.components]
    assert len(keys) == len(set(keys))
    assert chosen.direction_notes and all(n.strip() for n in chosen.direction_notes)
    for spec in chosen.components:
        formula = formulas.formula(spec.formula_id, spec.formula_version)
        assert spec.family in formula.families, (spec.component_key, spec.family)
        assert set(spec.sources) == {i.name for i in formula.inputs}, spec.component_key
        for name, source in spec.sources.items():
            unit = formula.input(name).unit
            if source.kind is tpl.SourceKind.PARAMETER_SET:
                assert pset.VARIABLES[source.name].unit is unit, (spec.component_key, name)
            else:
                assert source.kind is tpl.SourceKind.EFFECT_ATTRIBUTE
                assert tpl.ATTRIBUTES[source.name].unit is unit, (spec.component_key, name)


def test_a_template_holds_no_figure():
    """A source is a kind and a name, nothing else; no template, component or source
    holds a number. Read off the dataclasses and the module's own text: the only
    numbers written in the template module are versions, precedences and the key
    width, never a value a formula reads."""
    assert {f.name for f in dataclasses.fields(tpl.Source)} == {"kind", "name"}
    assert {f.name for f in dataclasses.fields(tpl.ComponentSpec)} == {
        "component_key", "family", "formula_id", "formula_version", "sources"
    }
    numbers = sorted(
        {
            node.value
            for node in ast.walk(ast.parse(MODULE.read_text(encoding="utf-8")))
            if isinstance(node, ast.Constant) and type(node.value) in (int, float)
        }
    )
    # 0: the first of the covering templates; 1 to 6: versions and precedences; 120: a
    # refusal's detail is cut at 120 characters.
    assert numbers == [0, 1, 2, 3, 4, 5, 6, 120], numbers
    assert not any(
        isinstance(node, ast.Constant) and isinstance(node.value, str) and node.value.replace(".", "").isdigit()
        for node in ast.walk(ast.parse(MODULE.read_text(encoding="utf-8")))
    )


def test_every_attribute_is_read_and_every_effect_type_is_covered():
    read = {
        source.name
        for t in tpl.TEMPLATES
        for c in t.components
        for source in c.sources.values()
        if source.kind is tpl.SourceKind.EFFECT_ATTRIBUTE
    }
    assert read == set(tpl.ATTRIBUTES)
    for effect_type in tpl.EffectType:
        assert effect_type in tpl.EFFECT_TYPES
        for process in tpl.BusinessProcess:
            assert tpl.select(effect_type, process).template.covers(effect_type, process)


OVERLAPS = [
    ("approval_bypassed", "payments", "payment_agent_misuse", ["payment_agent_misuse", "agent_approval_bypass"]),
    ("approval_bypassed", "fraud_aml", "fraud_aml_workflow_failure",
     ["fraud_aml_workflow_failure", "agent_approval_bypass"]),
    ("approval_bypassed", "lending", "agent_approval_bypass", ["agent_approval_bypass"]),
    ("funds_transfer_altered", "payments", "payment_agent_misuse", ["payment_agent_misuse"]),
]


@pytest.mark.parametrize("effect_type, process, chosen, candidates", OVERLAPS)
def test_an_effect_two_templates_cover_is_assigned_to_one_by_precedence(effect_type, process, chosen, candidates):
    selection = tpl.select(effect_type, process)
    assert selection.template.template_id == chosen
    assert [t.template_id for t in selection.in_scope_of] == candidates
    assert selection.as_dict()["chosen_by"] == ("precedence" if len(candidates) > 1 else "only_template_in_scope")


def test_the_vocabularies_are_pinned():
    assert [t.value for t in tpl.EffectType] == [
        "funds_transfer_altered", "approval_bypassed", "cross_customer_disclosure", "customer_misstatement",
        "fraud_aml_control_failure", "provider_outage",
    ]
    assert [b.value for b in tpl.BusinessProcess] == [
        "payments", "lending", "account_servicing", "customer_service", "fraud_aml", "operations"
    ]
    assert [o.value for o in tpl.Origin] == ["observed", "hypothetical"]
    assert [r.value for r in tpl.FindingRole] == ["prerequisite", "amplifier", "alternate_path"]
    assert len(tpl.ATTRIBUTES) == 27
    # The models spell the origin and role codes themselves (off the template module).
    from assurance.economics.models import EFFECT_ORIGINS, FINDING_ROLES

    assert list(EFFECT_ORIGINS) == [o.value for o in tpl.Origin]
    assert list(FINDING_ROLES) == [r.value for r in tpl.FindingRole]


def test_each_code_refuses_what_it_names():
    for check, value, code in (
        (tpl.check_effect_type, "wire_fraud", "effect_type_unrecognised"),
        (tpl.check_business_process, "Payments", "business_process_unrecognised"),
        (tpl.check_origin, "simulated", "origin_unrecognised"),
        (tpl.check_role, "cause", "finding_role_unrecognised"),
        (tpl.check_effect_key, "Has Spaces", "effect_key_malformed"),
        (tpl.check_effect_key, "x" * 61, "effect_key_malformed"),
        (tpl.check_effect_type, 7, "effect_type_unrecognised"),
    ):
        with pytest.raises(tpl.BuildRefused) as refused:
            check(value)
        assert refused.value.code == code
    assert set(tpl.REFUSALS) >= {
        "effect_out_of_scope", "effect_without_finding", "observed_source_on_hypothetical", "finding_not_found",
        "asset_not_found", "observed_effect_not_found", "observed_effect_not_in_force", "parameter_set_not_found",
    }


def test_attributes_are_read_exactly():
    entry = {"unit": "ratio", "low": "0.35", "base": "0.35", "high": "0.35", "source_type": "MYTHOS_OBSERVED",
             "evidence_ref": "7 of 20", "effective_date": "2026-10-01"}
    read = tpl.parse_attributes("redirect", {"success_rate": entry}, "attributes", origin=tpl.Origin.OBSERVED)
    assert read["success_rate"].name == "redirect.success_rate" and read["success_rate"].base == Decimal("0.35")
    for raw, code in (
        ({"ebitda": entry}, "attribute_unrecognised"),
        ({"success_rate": {**entry, "unit": "count"}}, "unit_mismatch"),
        ({"success_rate": {**entry, "low": 0.35}}, "not_decimal"),
        ({"success_rate": {**entry, "high": "1.2"}}, "ratio_out_of_range"),
        ({"success_rate": {**entry, "note": "x"}}, "field_unrecognised"),
        ([entry], "attribute_unrecognised"),
    ):
        with pytest.raises(Exception) as refused:
            tpl.parse_attributes("redirect", raw, "attributes", origin=tpl.Origin.OBSERVED)
        assert getattr(refused.value, "code", None) == code, (raw, refused.value)
    # Nothing was observed of a hypothetical effect.
    with pytest.raises(tpl.BuildRefused) as refused:
        tpl.parse_attributes("redirect", {"success_rate": entry}, "attributes", origin=tpl.Origin.HYPOTHETICAL)
    assert refused.value.code == "observed_source_on_hypothetical"


# ====================================================== unknown, never zero


@pytest.mark.parametrize("chosen", tpl.TEMPLATES, ids=lambda t: t.template_id)
def test_a_source_that_holds_nothing_leaves_the_component_unknown_never_zero(chosen):
    """With no parameter set and no attribute, every input is unbound: every
    component is unknown, names every input it lacks, and has no amount; the
    event's cash total is incomplete and reads 'at least'."""
    planned = tpl.plan(chosen, {}, {})
    for each in planned:
        assert not each.bound and set(each.missing) == set(each.spec.sources)
    event = run(chosen.template_id, {}, {})
    for component in event.components:
        assert component.status == UNKNOWN and component.unknown_reason == "input_missing"
        assert set(component.missing) == set(by_spec(chosen)[component.component_id].sources)
        with pytest.raises(ValueError):
            component.at(POINTS[1])
    gross = assess(event).gross.total
    assert not gross.complete and total(gross) == (Decimal(0),) * 3
    assert gross.as_dict()["reads_as"] == "at least: the known components only"


def by_spec(chosen) -> dict:
    return {c.component_key: c for c in chosen.components}


# ===================================================== the worked examples
#
# SYNTHETIC / ILLUSTRATIVE. Every figure is made up (section 30's are the
# specification's own illustrative ones), and none is a customer's or a benchmark.


def section_30_variables() -> dict:
    return {
        "transactions_per_day": p("transactions_per_day", "count_per_day", "18000", why="section 30"),
        "average_transaction_value": p("average_transaction_value", "money_per_unit", "25000", why="section 30"),
        "recovery_rate": p("recovery_rate", "ratio", "0.70", "0.825", "0.95", why="section 30"),
    }


def section_30_attributes() -> dict:
    return {
        "success_rate": p("redirect.success_rate", "ratio", "0.35", source="MYTHOS_OBSERVED",
                          why="section 30, 7 unauthorized effects in 20 attempts"),
        "exploitable_window_hours": p("redirect.exploitable_window_hours", "hours", "0.5", "1.25", "2.0",
                                      source="EXPERT_ESTIMATE", why="section 30, repeatable window"),
        "incident_response_cost": p("redirect.incident_response_cost", "money", "80000", "165000", "250000",
                                    source="EXPERT_ESTIMATE", why="section 30, incident response"),
        "legal_response_cost": p("redirect.legal_response_cost", "money", "150000", "825000", "1500000",
                                 source="EXPERT_ESTIMATE", why="section 30, legal/regulatory response"),
    }


def test_payment_agent_misuse_is_section_30_exactly():
    """Section 30, built through the template, equals #146's known answer computed
    by hand: direct loss 164,062.50 / 1,435,546.875 / 3,937,500, and gross cash loss
    394,062.50 / 2,425,546.875 / 5,687,500 (see tests/test_economics_known_answers.py
    for every step)."""
    event = run("payment_agent_misuse", section_30_variables(), section_30_attributes())
    built = by_key(event)
    assert figures(built["direct-loss"]) == (Decimal("164062.50"), Decimal("1435546.875"), Decimal("3937500"))
    assert figures(built["incident-response"]) == (Decimal(80000), Decimal(165000), Decimal(250000))
    assert figures(built["legal-regulatory-response"]) == (Decimal(150000), Decimal(825000), Decimal(1500000))
    result = assess(event)
    assert result.gross.total.complete
    assert total(result.gross.total) == (Decimal("394062.50"), Decimal("2425546.875"), Decimal("5687500"))
    by_hand = assess(known.example_a())
    for point in POINTS:
        assert result.gross.total.at(point) == by_hand.gross.total.at(point)
    for mine, theirs in zip(event.components, known.example_a().components, strict=True):
        assert (mine.family, mine.formula.key, figures(mine)) == (theirs.family, theirs.formula.key, figures(theirs))


def section_31_variables() -> dict:
    return {
        "notification_unit_cost": p("notification_unit_cost", "money_per_unit", "1.50", "2.00", "3.00"),
        "notification_fixed_cost": p("notification_fixed_cost", "money", "25000", "40000", "60000"),
        "support_agent_hourly_rate": p("support_agent_hourly_rate", "money_per_hour", "40", "55", "70"),
        "security_responder_hourly_rate": p("security_responder_hourly_rate", "money_per_hour", "300", "400", "500"),
        "legal_retainer": p("legal_retainer", "money", "25000", "50000", "100000"),
        "external_counsel_hourly_rate": p("external_counsel_hourly_rate", "money_per_hour", "450", "600", "800"),
    }


def section_31_attributes(**extra) -> dict:
    attributes = {
        "affected_customers": p("exposure.affected_customers", "count", "20000", "50000", "120000",
                                source="EXPERT_ESTIMATE", why="reachable records and tested retrieval"),
        "contact_rate": p("exposure.contact_rate", "ratio", "0.05", "0.10", "0.20", source="INDUSTRY_BENCHMARK"),
        "handling_hours": p("exposure.handling_hours", "hours", "0.10", "0.15", "0.25"),
        "forensics_fixed_cost": p("exposure.forensics_fixed_cost", "money", "50000", "75000", "100000"),
        "investigation_hours": p("exposure.investigation_hours", "hours", "200", "400", "800", source="EXPERT_ESTIMATE"),
        "counsel_hours": p("exposure.counsel_hours", "hours", "100", "300", "800", source="EXPERT_ESTIMATE"),
        "regulatory_response_cost": p("exposure.regulatory_response_cost", "money", "0", "100000", "500000",
                                      source="EXPERT_ESTIMATE", why="scenario bounds pending legal review"),
        # A benchmark, not the customer's own churn: customer loss is unknown.
        "churn_rate": p("exposure.churn_rate", "ratio", "0.01", "0.02", "0.04", source="INDUSTRY_BENCHMARK"),
        "margin_per_customer_per_year": p("exposure.margin_per_customer_per_year", "money_per_unit", "120", "150", "200"),
        "churn_recovery_years": p("exposure.churn_recovery_years", "years", "1", "1", "2", source="EXPERT_ESTIMATE"),
    }
    attributes.update(extra)
    return attributes


def test_cross_customer_data_exposure_is_section_31_exactly():
    """Section 31, through the template, equals #146's known answer: gross cash loss
    at least 239,000 / 746,250 / 2,580,000 (customer loss unknown: its churn is a
    benchmark), and with the policy, at least 100,000 / 231,250 / 1,580,000
    retained. The market-value line is unknown (no market capitalisation stated)
    and is not cash."""
    event = run("cross_customer_data_exposure", section_31_variables(), section_31_attributes())
    built = by_key(event)
    hand = {c.component_id: c for c in known.example_b_components()}
    for mine, theirs in (("notification", "notification"), ("support", "support"), ("forensics", "forensics"),
                         ("legal", "legal"), ("regulatory", "regulatory")):
        assert figures(built[mine]) == figures(hand[theirs]), mine
    assert (built["customer-loss"].status, built["customer-loss"].unknown_reason) == (
        UNKNOWN, "input_source_not_accepted"
    )
    assert built["share-price-reaction"].status == UNKNOWN and built["share-price-reaction"].family == "market_value"
    result = assess(event, known.example_b_policy())
    assert total(result.gross.total) == (Decimal(239000), Decimal(746250), Decimal(2580000))
    assert result.gross.total.unknown == ("customer-loss",)
    assert total(result.insured.retained) == (Decimal(100000), Decimal(231250), Decimal(1580000))
    assert result.as_dict()["market_value"]["never_added_to_cash"] is True


def test_a_market_value_line_is_computed_and_kept_out_of_cash():
    """Public-company analysis: a market capitalisation of USD 2bn and a decline of
    1% / 2% / 5% give a market-value line of 20m / 40m / 100m, on its own line; the
    gross cash loss is exactly what it was without it."""
    extra = {
        "market_capitalisation": p("exposure.market_capitalisation", "money", "2000000000"),
        "share_price_decline": p("exposure.share_price_decline", "ratio", "0.01", "0.02", "0.05",
                                 source="EXPERT_ESTIMATE"),
    }
    result = assess(run("cross_customer_data_exposure", section_31_variables(), section_31_attributes(**extra)))
    assert total(result.market_value) == (Decimal(20000000), Decimal(40000000), Decimal(100000000))
    assert total(result.gross.total) == (Decimal(239000), Decimal(746250), Decimal(2580000))


def test_customer_service_ai_misstatement():
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
    event = run("customer_service_ai_misstatement", variables, attributes)
    built = by_key(event)
    # Restitution = affected x amount each: 1,000 x 40 = 40,000; 2,000 x 50 = 100,000;
    # 5,000 x 80 = 400,000.
    assert figures(built["restitution"]) == (Decimal(40000), Decimal(100000), Decimal(400000))
    # Complaint handling = affected x contact rate x hours x rate:
    #   low:  1,000 x 0.10 =   100 x 0.20 =  20 h x 40 =    800
    #   base: 2,000 x 0.20 =   400 x 0.25 = 100 h x 50 =  5,000
    #   high: 5,000 x 0.30 = 1,500 x 0.50 = 750 h x 60 = 45,000
    assert figures(built["complaint-handling"]) == (Decimal(800), Decimal(5000), Decimal(45000))
    # Legal = retainer + counsel rate x hours: 20,000 + 400 x 20 = 28,000;
    # 25,000 + 500 x 40 = 45,000; 30,000 + 600 x 100 = 90,000.
    assert figures(built["legal"]) == (Decimal(28000), Decimal(45000), Decimal(90000))
    assert figures(built["compliance-review"]) == (Decimal(10000), Decimal(25000), Decimal(60000))
    # Gross: 40,000 + 800 + 28,000 + 10,000 = 78,800; 100,000 + 5,000 + 45,000 + 25,000
    # = 175,000; 400,000 + 45,000 + 90,000 + 60,000 = 595,000.
    assert total(assess(event).gross.total) == (Decimal(78800), Decimal(175000), Decimal(595000))


def bank_variables() -> dict:
    return {
        "recovery_rate": p("recovery_rate", "ratio", "0.20", "0.30", "0.50"),
        "security_responder_hourly_rate": p("security_responder_hourly_rate", "money_per_hour", "150", "200", "250"),
        "engineering_hourly_rate": p("engineering_hourly_rate", "money_per_hour", "120", "150", "180"),
        "margin_per_hour": p("margin_per_hour", "money_per_hour", "10000", "12000", "15000"),
    }


def test_fraud_aml_workflow_failure():
    attributes = {
        "missed_cases": p("aml.missed_cases", "count", "10", "20", "40", source="EXPERT_ESTIMATE"),
        "loss_per_missed_case": p("aml.loss_per_missed_case", "money_per_unit", "5000", "8000", "12000"),
        "rework_cost": p("aml.rework_cost", "money", "15000", "30000", "60000", source="EXPERT_ESTIMATE"),
        "forensics_fixed_cost": p("aml.forensics_fixed_cost", "money", "10000", "20000", "30000"),
        "investigation_hours": p("aml.investigation_hours", "hours", "40", "80", "160", source="EXPERT_ESTIMATE"),
        "regulatory_response_cost": p("aml.regulatory_response_cost", "money", "0", "50000", "250000",
                                      source="EXPERT_ESTIMATE"),
    }
    event = run("fraud_aml_workflow_failure", bank_variables(), attributes)
    built = by_key(event)
    # Missed fraud = cases x loss each x (1 - recovery); recovery decreases the loss,
    # so the LOW reads recovery's HIGH (50%) and the HIGH its LOW (20%):
    #   low:  10 x  5,000 x 0.50 =  25,000
    #   base: 20 x  8,000 x 0.70 = 112,000
    #   high: 40 x 12,000 x 0.80 = 384,000
    assert figures(built["missed-fraud"]) == (Decimal(25000), Decimal(112000), Decimal(384000))
    assert figures(built["case-rework"]) == (Decimal(15000), Decimal(30000), Decimal(60000))
    # Investigation = fixed + responder rate x hours: 10,000 + 150 x 40 = 16,000;
    # 20,000 + 200 x 80 = 36,000; 30,000 + 250 x 160 = 70,000.
    assert figures(built["investigation"]) == (Decimal(16000), Decimal(36000), Decimal(70000))
    assert figures(built["regulatory-response"]) == (Decimal(0), Decimal(50000), Decimal(250000))
    # Gross: 25,000 + 15,000 + 16,000 + 0 = 56,000; 112,000 + 30,000 + 36,000 + 50,000
    # = 228,000; 384,000 + 60,000 + 70,000 + 250,000 = 764,000.
    assert total(assess(event).gross.total) == (Decimal(56000), Decimal(228000), Decimal(764000))


def test_agent_approval_bypass():
    attributes = {
        "repeat_count": p("bypass.repeat_count", "count", "1", "3", "6", source="EXPERT_ESTIMATE"),
        "loss_per_event": p("bypass.loss_per_event", "money_per_unit", "10000", "12000", "15000"),
        "recovery_fixed_cost": p("bypass.recovery_fixed_cost", "money", "5000", "8000", "12000"),
        "recovery_hours": p("bypass.recovery_hours", "hours", "16", "40", "80", source="EXPERT_ESTIMATE"),
        "incident_response_cost": p("bypass.incident_response_cost", "money", "20000", "40000", "80000",
                                    source="EXPERT_ESTIMATE"),
    }
    event = run("agent_approval_bypass", bank_variables(), attributes)
    built = by_key(event)
    # Unauthorized effect = repeats x loss each x (1 - recovery):
    #   low:  1 x 10,000 x 0.50 =  5,000
    #   base: 3 x 12,000 x 0.70 = 25,200
    #   high: 6 x 15,000 x 0.80 = 72,000
    assert figures(built["unauthorized-effect"]) == (Decimal(5000), Decimal(25200), Decimal(72000))
    # Control recovery = fixed + engineering rate x hours: 5,000 + 120 x 16 = 6,920;
    # 8,000 + 150 x 40 = 14,000; 12,000 + 180 x 80 = 26,400.
    assert figures(built["control-recovery"]) == (Decimal(6920), Decimal(14000), Decimal(26400))
    assert figures(built["incident-response"]) == (Decimal(20000), Decimal(40000), Decimal(80000))
    # Gross: 5,000 + 6,920 + 20,000 = 31,920; 25,200 + 14,000 + 40,000 = 79,200;
    # 72,000 + 26,400 + 80,000 = 178,400.
    assert total(assess(event).gross.total) == (Decimal(31920), Decimal(79200), Decimal(178400))


def test_third_party_provider_outage():
    attributes = {
        "outage_hours": p("outage.outage_hours", "hours", "2", "6", "12", source="EXPERT_ESTIMATE"),
        "recovery_fixed_cost": p("outage.recovery_fixed_cost", "money", "5000", "8000", "12000"),
        "recovery_hours": p("outage.recovery_hours", "hours", "8", "16", "40", source="EXPERT_ESTIMATE"),
        "sla_credit_per_hour": p("outage.sla_credit_per_hour", "money_per_hour", "1000", "2000", "3000"),
        "sla_credit_cap": p("outage.sla_credit_cap", "money", "10000", "10000", "25000"),
    }
    event = run("third_party_provider_outage", bank_variables(), attributes)
    built = by_key(event)
    # Interruption = hours x margin per hour: 2 x 10,000 = 20,000; 6 x 12,000 = 72,000;
    # 12 x 15,000 = 180,000.
    assert figures(built["interruption"]) == (Decimal(20000), Decimal(72000), Decimal(180000))
    # Failover = fixed + engineering rate x hours: 5,000 + 120 x 8 = 5,960;
    # 8,000 + 150 x 16 = 10,400; 12,000 + 180 x 40 = 19,200.
    assert figures(built["failover-recovery"]) == (Decimal(5960), Decimal(10400), Decimal(19200))
    # SLA credits = min(credit per hour x outage hours, cap): min(2,000, 10,000) = 2,000;
    # min(12,000, 10,000) = 10,000; min(36,000, 25,000) = 25,000.
    assert figures(built["sla-credits"]) == (Decimal(2000), Decimal(10000), Decimal(25000))
    # Gross: 20,000 + 5,960 + 2,000 = 27,960; 72,000 + 10,400 + 10,000 = 92,400;
    # 180,000 + 19,200 + 25,000 = 224,200.
    assert total(assess(event).gross.total) == (Decimal(27960), Decimal(92400), Decimal(224200))
    # The outage's length is one parameter, read by both components that need it.
    reads = [c.parameter.name for comp in event.components for c in comp.inputs if c.input.name in
             ("interruption_hours", "breach_hours")]
    assert reads == ["outage.outage_hours", "outage.outage_hours"]


def test_every_estimated_input_names_its_recorded_source():
    """A template value never appears unless its source is recorded: every input of
    every estimated component in the worked examples is a parameter with a source
    type and evidence, and it is the very parameter the template's source names."""
    cases = [
        ("payment_agent_misuse", section_30_variables(), section_30_attributes()),
        ("cross_customer_data_exposure", section_31_variables(), section_31_attributes()),
    ]
    for template_id, variables, attributes in cases:
        chosen = tpl.CATALOGUE[(template_id, 1)]
        for planned, component in zip(tpl.plan(chosen, variables, attributes),
                                      run(template_id, variables, attributes).components, strict=True):
            if component.status != ESTIMATED:
                continue
            for cited in component.inputs:
                source, parameter = planned.bound[cited.input.name]
                held = variables if source.kind is tpl.SourceKind.PARAMETER_SET else attributes
                assert cited.parameter is parameter is held[source.name]
                assert parameter.evidence_ref.strip() and parameter.source_type


def test_a_policy_is_never_a_template_input():
    """Insurance is applied once, when an event is assessed, from the parameter set's
    policy; no template binds a deductible, a limit or a sublimit, and none computes
    the insurance family."""
    for t in tpl.TEMPLATES:
        for spec in t.components:
            assert spec.family != "insurance"
            for source in spec.sources.values():
                assert not source.name.startswith("insurance_"), (t.template_id, source.name)
    assert InsurancePolicy  # the policy type the assessment reads
