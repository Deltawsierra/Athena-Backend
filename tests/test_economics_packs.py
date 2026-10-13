"""The industry packs (Economic Exposure E7; ``docs/economics/spec-v1.md``, section
37), pure: no database.

- the registry: banking, unchanged, and each industry pack, versioned in its id, with
  its templates, loss families and customer-input schema; one template id in one pack;
- every component of every template is well formed, every attribute and input is read,
  every effect type is covered, and every template reads each attribute one way;
- KNOWN ANSWERS: every template of every industry pack, at low, base and high, three
  ways -- the engine, an independent closed form of each formula written here, and the
  figures pinned below -- which agree;
- precedence: each pack's order pinned, and an effect two templates cover assigned to
  ONE, the lower, and in ONE event;
- the schema: a missing input refused with its code, never defaulted, and every other
  refusal code;
- bias and fairness: no pack holds a figure, and none a geographic or company-size
  weight, read off both its data and its module's source;
- safety: harm to a person is never priced; a physical-world template carries the
  caution;
- the spec documents every template, as the code states it, and every code.

SYNTHETIC / ILLUSTRATIVE: every figure here is made up.
"""

from __future__ import annotations

import ast
import re
from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest

from assurance.economics.engine import formulas, pack_inputs, pack_registry
from assurance.economics.engine import parameter_set as pset
from assurance.economics.engine import templates as tpl
from assurance.economics.engine.money import Money
from assurance.economics.engine.pack_base import HARM_EXCLUDED, PHYSICAL_WORLD_CAUTION
from assurance.economics.engine.parameters import (
    MONEY_UNITS,
    POINTS,
    Parameter,
    ParameterRefused,
    Point,
    Unit,
)
from assurance.economics.engine.provenance import SourceType

REPO = Path(__file__).resolve().parent.parent
ENGINE = REPO / "assurance" / "economics" / "engine"
SPEC = REPO / "docs" / "economics" / "spec-v1.md"
AS_OF = date(2026, 10, 6)

PACKS = pack_registry.PACKS
VERTICAL = tuple(p for p in PACKS.values() if not p.banking)
VERTICAL_TEMPLATES = tuple(t for p in VERTICAL for t in p.templates)
PACK_MODULES = ("pack_inputs.py", "pack_base.py", "pack_registry.py", "pack_insurance.py", "pack_healthcare.py",
                "pack_saas.py", "pack_regulated_enterprise.py", "pack_government.py", "pack_manufacturing.py",
                "pack_mobility.py")


# ======================================================================
# The registry
# ======================================================================


def test_the_registry_holds_banking_and_each_industry_pack_versioned():
    assert list(PACKS) == [
        "mythos.economics.banking-pack/v1",
        "mythos.economics.insurance-pack/v1",
        "mythos.economics.healthcare-pack/v1",
        "mythos.economics.saas-pack/v1",
        "mythos.economics.regulated-enterprise-pack/v1",
        "mythos.economics.government-pack/v1",
        "mythos.economics.manufacturing-pack/v1",
        "mythos.economics.mobility-pack/v1",
    ]
    for pack in PACKS.values():
        assert re.fullmatch(r"mythos\.economics\.[a-z][a-z-]*-pack/v[1-9][0-9]*", pack.pack_id), pack.pack_id
        assert pack.pack_id == f"mythos.economics.{pack.vertical}-pack/v1"
        assert pack.templates and pack.families and pack.effect_types and pack.business_processes
    # Every industry pack has its customer-input schema; banking's is the thirty variables.
    assert set(pack_inputs.SCHEMAS) == {p.pack_id for p in VERTICAL}
    for pack in VERTICAL:
        schema = pack_inputs.SCHEMAS[pack.pack_id]
        assert dict(pack.inputs) == dict(schema.inputs) and schema.vertical == pack.vertical
        assert schema.required, pack.pack_id
        # No input shares a name with a variable: a pack input is never read as one.
        assert not set(pack.inputs) & set(pset.VARIABLES), pack.pack_id
    assert pack_registry.BANKING.inputs == {}
    assert pack_inputs.BANKING_PACK == tpl.PACK == pack_registry.BANKING.pack_id


def test_the_banking_pack_is_the_template_module_unchanged():
    banking = pack_registry.BANKING
    assert banking.templates == tpl.TEMPLATES
    assert dict(banking.attributes) == dict(tpl.ATTRIBUTES)
    assert banking.effect_type_codes is tpl.EffectType and banking.business_process_codes is tpl.BusinessProcess
    for chosen in tpl.TEMPLATES:
        assert chosen.pack == tpl.PACK and chosen.cautions == ()
        document = chosen.as_dict()
        assert document["pack"] == tpl.PACK and "cautions" not in document
        assert pack_registry.template(chosen.template_id, chosen.version) is chosen
    # Its selection is the template module's, effect by effect.
    for effect_type in tpl.EffectType:
        for process in tpl.BusinessProcess:
            assert banking.select(effect_type, process) == tpl.select(effect_type, process)


def test_a_template_id_is_the_registrys():
    ids = [t.template_id for p in PACKS.values() for t in p.templates]
    assert len(ids) == len(set(ids))
    for pack in PACKS.values():
        for chosen in pack.templates:
            assert chosen.pack == pack.pack_id
            assert pack_registry.pack_of_template(chosen.template_id, chosen.version) is pack
            assert chosen.template_id.startswith(pack.vertical.replace("-", "_") + "_") or pack.banking
    assert pack_registry.template("no_such_template", 1) is None


def test_pack_of_reads_one_spelling():
    assert pack_registry.pack_of(None) is pack_registry.BANKING
    for pack in VERTICAL:
        assert pack_registry.pack_of(pack.pack_id) is pack
    for value in (tpl.PACK, "mythos.economics.insurance-pack/v2", "insurance", 7, ["x"]):
        with pytest.raises(ParameterRefused) as refused:
            pack_registry.pack_of(value)
        assert refused.value.code == "pack_unrecognised", value


@pytest.mark.parametrize("chosen", VERTICAL_TEMPLATES, ids=lambda t: t.template_id)
def test_every_component_of_every_pack_is_well_formed(chosen):
    """Every component's formula is in the catalogue and computes its family; every
    input of the formula has exactly one source: a variable of the parameter set, an
    attribute of the pack or an input of the pack's schema, in the input's own unit;
    component keys are distinct; the template states its direction notes."""
    pack = PACKS[chosen.pack]
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
            elif source.kind is tpl.SourceKind.PACK_INPUT:
                assert pack.inputs[source.name].unit is unit, (spec.component_key, name)
            else:
                assert source.kind is tpl.SourceKind.EFFECT_ATTRIBUTE
                assert pack.attributes[source.name].unit is unit, (spec.component_key, name)


@pytest.mark.parametrize("pack", VERTICAL, ids=lambda p: p.vertical)
def test_every_attribute_and_input_is_read_and_every_effect_type_covered(pack):
    read = {(s.kind, s.name) for t in pack.templates for c in t.components for s in c.sources.values()}
    assert {n for k, n in read if k is tpl.SourceKind.EFFECT_ATTRIBUTE} == set(pack.attributes)
    assert {n for k, n in read if k is tpl.SourceKind.PACK_INPUT} == set(pack.inputs)
    for effect_type in pack.effect_type_codes:
        assert effect_type.value in pack.effect_types
        for process in pack.business_process_codes:
            assert pack.select(effect_type, process).template.covers(effect_type, process)
    # An observable attribute is a rate, a count or a duration; never money.
    for attribute in pack.attributes.values():
        if attribute.observable:
            assert attribute.unit in (Unit.RATIO, Unit.COUNT, Unit.HOURS, Unit.YEARS), attribute.name
        if attribute.unit in MONEY_UNITS:
            assert not attribute.observable, attribute.name
        # One name, one meaning: an attribute the banking pack states is stated as it is.
        if attribute.name in tpl.ATTRIBUTES:
            assert attribute == tpl.ATTRIBUTES[attribute.name], attribute.name


@pytest.mark.parametrize("chosen", VERTICAL_TEMPLATES, ids=lambda t: t.template_id)
def test_every_template_reads_each_attribute_in_one_direction(chosen):
    readings = tpl.readings(chosen)
    assert set(readings) == {
        s.name for c in chosen.components for s in c.sources.values() if s.kind is tpl.SourceKind.EFFECT_ATTRIBUTE
    }


# ======================================================================
# Known answers: the engine, an independent closed form, and the pinned figures
# ======================================================================


def _money(value):
    return Money(Decimal(value), "USD")


def _param(name, unit, low, base=None, high=None, source=SourceType.CUSTOMER_PROVIDED):
    base = low if base is None else base
    high = base if high is None else high
    unit = Unit(unit)
    value = _money if unit in MONEY_UNITS else Decimal
    return Parameter(name, unit, source, value(low), value(base), value(high),
                     evidence_ref="SYNTHETIC / ILLUSTRATIVE", effective_date=date(2026, 9, 1))


#: The shared variables every pack's templates read: SYNTHETIC.
VARIABLES = {
    "recovery_rate": ("ratio", "0.10", "0.25", "0.40"),
    "legal_retainer": ("money", "25000", "50000", "100000"),
    "external_counsel_hourly_rate": ("money_per_hour", "450", "600", "800"),
    "support_agent_hourly_rate": ("money_per_hour", "40", "55", "70"),
    "security_responder_hourly_rate": ("money_per_hour", "300", "400", "500"),
    "engineering_hourly_rate": ("money_per_hour", "150", "200", "250"),
    "margin_per_hour": ("money_per_hour", "5000", "8000", "12000"),
    "notification_unit_cost": ("money_per_unit", "1.50", "2.00", "3.00"),
    "notification_fixed_cost": ("money", "25000", "40000", "60000"),
    "vendor_exit_cost": ("money_per_unit", "50000", "100000", "250000"),
}

#: Every pack's inputs and every attribute any pack states: SYNTHETIC.
INPUTS = {
    # insurance
    "claims_per_day": ("1200",),
    "policy_count": ("200000",),
    "average_annual_premium": ("1100", "1200", "1300"),
    "loss_ratio": ("0.60", "0.65", "0.70"),
    "regulatory_jurisdiction_count": ("3", "3", "5"),
    "manual_claim_handling_cost": ("40", "60", "90"),
    # healthcare
    "patient_record_count": ("500000",),
    "breach_cost_per_record": ("10", "20", "40"),
    "care_disruption_cost_per_hour": ("8000", "15000", "30000"),
    "research_asset_value": ("2000000", "5000000", "10000000"),
    "batch_value": ("200000", "350000", "500000"),
    # saas
    "tenant_count": ("2000",),
    "recurring_margin_per_tenant": ("20000", "30000", "40000"),
    "contract_sla_credit_per_hour": ("5000", "8000", "12000"),
    "contract_sla_credit_cap": ("100000", "150000", "250000"),
    "cloud_spend_per_hour": ("300", "400", "600"),
    # regulated enterprise
    "control_obligation_count": ("400",),
    "contract_count": ("1500",),
    "process_margin_per_hour": ("2000", "4000", "8000"),
    # government
    "mission_cost_per_hour": ("10000", "25000", "60000"),
    "response_team_hourly_rate": ("120", "160", "220"),
    "oversight_body_count": ("2", "3", "4"),
    # manufacturing
    "units_per_day": ("4800",),
    "margin_per_unit": ("30", "40", "55"),
    "downtime_cost_per_hour": ("5000", "8000", "15000"),
    "equipment_count": ("120",),
    "equipment_value": ("250000", "400000", "600000"),
    "safety_response_cost": ("50000", "120000", "300000"),
    # mobility: the owner's worked example C (section 32) where it gives a figure
    "fleet_size": ("2500",),
    "trips_per_day": ("30000",),
    "contribution_margin_per_trip": ("18",),
    "vehicle_asset_cost": ("40000", "55000", "70000"),
    "recall_cost_per_vehicle": ("150", "300", "600"),
}
ATTRIBUTES = {
    # shared with banking
    "exploitable_window_hours": ("2", "8", "24"),
    "rework_cost": ("20000", "50000", "120000"),
    "incident_response_cost": ("50000", "100000", "200000"),
    "contact_rate": ("0.05", "0.10", "0.20"),
    "handling_hours": ("0.25", "0.5", "1"),
    "counsel_hours": ("50", "150", "400"),
    "forensics_fixed_cost": ("30000", "60000", "100000"),
    "investigation_hours": ("100", "300", "600"),
    "churn_rate": ("0.01", "0.02", "0.05"),
    "churn_recovery_years": ("1", "1", "2"),
    "outage_hours": ("2", "6", "18"),
    "recovery_fixed_cost": ("10000", "25000", "50000"),
    "recovery_hours": ("40", "120", "300"),
    "repeat_count": ("2", "5", "12"),
    "loss_per_event": ("10000", "25000", "60000"),
    "regulatory_response_cost": ("0", "100000", "400000"),
    # insurance
    "overpaid_claim_rate": ("0.02", "0.05", "0.10"),
    "overpayment_per_claim": ("800", "1500", "3000"),
    "wrongly_denied_claims": ("100", "400", "1500"),
    "interest_and_penalty_per_claim": ("150", "300", "800"),
    "regulatory_response_per_regulator": ("20000", "50000", "150000"),
    "exposed_policy_share": ("0.01", "0.05", "0.20"),
    "margin_per_policy_per_year": ("100", "150", "220"),
    "mispriced_policy_share": ("0.005", "0.02", "0.05"),
    "premium_shortfall_share": ("0.05", "0.10", "0.25"),
    "wrongly_accepted_policy_share": ("0.001", "0.005", "0.01"),
    "excess_claims_share": ("0.20", "0.40", "0.80"),
    "manual_handling_share": ("0.5", "0.8", "1"),
    # healthcare
    "exposed_record_share": ("0.01", "0.05", "0.20"),
    "disruption_hours": ("4", "12", "48"),
    "clinical_review_cost": ("20000", "60000", "150000"),
    "altered_record_share": ("0.001", "0.005", "0.02"),
    "correction_cost_per_record": ("15", "25", "50"),
    "compromised_share": ("0.05", "0.20", "0.50"),
    "affected_batches": ("1", "2", "5"),
    "quarantine_fixed_cost": ("25000", "50000", "100000"),
    # saas
    "affected_tenant_share": ("0.01", "0.05", "0.15"),
    "notification_cost_per_tenant": ("500", "1000", "2500"),
    "breach_credit_per_tenant": ("1000", "5000", "10000"),
    "affected_people": ("10000", "50000", "200000"),
    "abuse_hours": ("2", "12", "48"),
    "abuse_load_share": ("0.10", "0.30", "0.80"),
    # regulated enterprise
    "affected_contract_share": ("0.005", "0.02", "0.05"),
    "response_cost_per_contract": ("2000", "5000", "15000"),
    "affected_obligation_share": ("0.01", "0.03", "0.10"),
    "compliance_response_per_obligation": ("5000", "15000", "40000"),
    "interruption_hours": ("2", "8", "24"),
    "vendors_to_replace": ("0", "1", "2"),
    # government
    "reporting_cost_per_body": ("10000", "25000", "60000"),
    "affected_components": ("1", "3", "10"),
    "replacement_cost_per_component": ("20000", "50000", "150000"),
    # manufacturing
    "affected_line_share": ("0.1", "0.25", "0.5"),
    "damaged_equipment_share": ("0.01", "0.02", "0.05"),
    "damage_ratio": ("0.1", "0.3", "1"),
    "shutdown_hours": ("8", "24", "72"),
    "expedite_cost": ("20000", "60000", "150000"),
    "contract_penalty_cost": ("0", "50000", "250000"),
    # mobility: the owner's worked example C (section 32) where it gives a figure
    "affected_fleet_share": ("0.01", "0.03", "0.08"),
    "field_recovery_cost_per_vehicle": ("75", "200", "450"),
    "operations_response_cost": ("120000", "300000", "600000"),
    "disrupted_trip_share": ("0.05", "0.15", "0.4"),
    "compensation_per_trip": ("2", "5", "10"),
    "damaged_fleet_share": ("0.0004", "0.002", "0.01"),
    "recall_share": ("0", "0.1", "0.4"),
}


def world(pack):
    """The variables, the pack's inputs and its attributes, as parameters."""
    variables = {name: _param(name, *figures) for name, figures in VARIABLES.items()}
    inputs = {
        name: _param(pack_inputs.PACK_INPUT_PREFIX + name, entry.unit.value, *INPUTS[name])
        for name, entry in pack.inputs.items()
    }
    attributes = {
        name: _param(f"effect.{name}", attribute.unit.value, *ATTRIBUTES[name])
        for name, attribute in pack.attributes.items()
    }
    return variables, inputs, attributes


def engine_components(chosen):
    variables, inputs, attributes = world(PACKS[chosen.pack])
    return [
        formulas.evaluate(
            planned.spec.component_key, planned.spec.family, planned.spec.formula_id, planned.spec.formula_version,
            planned.bindings(), as_of=AS_OF,
        )
        for planned in tpl.plan(chosen, variables, attributes, inputs)
    ]


#: The formula inputs that DECREASE the loss: their low result reads the high figure.
#: Written here, apart from the catalogue's own directions.
DECREASING = frozenset({"recovery_rate"})


def _at(figures: tuple, point: Point, decreasing: bool) -> Decimal:
    low, base, high = (figures * 3)[:3] if len(figures) == 1 else figures
    ends = {Point.LOW: low, Point.BASE: base, Point.HIGH: high}
    if decreasing and point is not Point.BASE:
        ends = {Point.LOW: high, Point.HIGH: low}
    return Decimal(ends[point])


def closed_form(formula_id: str, v: dict) -> Decimal:
    """Each formula of the catalogue, written again here as its expression says."""
    one = Decimal(1)
    return {
        "repeat_loss": lambda: v["repeat_count"] * v["loss_per_event"] * (one - v["recovery_rate"]),
        "repeat_in_window": lambda: v["transactions_per_day"] / 24 * v["window_hours"] * v["success_rate"]
        * v["value_per_transaction"] * (one - v["recovery_rate"]),
        "interruption": lambda: v["interruption_hours"] * v["value_per_hour"],
        "fixed_plus_hours": lambda: v["fixed_cost"] + v["hourly_rate"] * v["hours"],
        "per_affected_plus_fixed": lambda: v["affected"] * v["unit_cost"] + v["fixed_cost"],
        "per_affected": lambda: v["affected"] * v["amount_per_affected"],
        "support_contacts": lambda: v["affected"] * v["contact_rate"] * v["handling_hours"] * v["loaded_rate"],
        "capped_credit": lambda: min(v["credit_per_hour"] * v["breach_hours"], v["contract_cap"]),
        "replacement_share": lambda: v["replacement_cost"] * v["share_compromised"],
        "churned_margin": lambda: v["customers"] * v["churn_rate"] * v["margin_per_customer_per_year"]
        * v["recovery_years"],
        "lump_sum": lambda: v["amount"],
        "throughput_loss": lambda: v["units_per_day"] / 24 * v["hours"] * v["affected_share"] * v["amount_per_unit"],
        "share_of_units": lambda: v["units"] * v["affected_share"] * v["amount_per_unit"],
        "share_of_units_value": lambda: v["units"] * v["affected_share"] * v["amount_per_unit"] * v["value_share"],
        "excess_over_expected": lambda: v["units"] * v["affected_share"] * v["amount_per_unit"]
        * v["expected_ratio"] * v["excess_share"],
        "per_unit_response": lambda: v["units"] * v["cost_per_unit"],
        "churned_share_margin": lambda: v["units"] * v["affected_share"] * v["churn_rate"]
        * v["margin_per_unit_per_year"] * v["recovery_years"],
        "share_of_spend": lambda: v["hours"] * v["spend_per_hour"] * v["added_share"],
    }[formula_id]()


def closed_form_components(chosen) -> dict[str, tuple[Decimal, Decimal, Decimal]]:
    """Every component of ``chosen`` by its closed form, from the fixtures above."""
    figures = {**{n: f[1:] for n, f in VARIABLES.items()}}
    found = {}
    for spec in chosen.components:
        results = []
        for point in POINTS:
            values = {}
            for name, source in spec.sources.items():
                table = {
                    tpl.SourceKind.PARAMETER_SET: figures,
                    tpl.SourceKind.PACK_INPUT: INPUTS,
                    tpl.SourceKind.EFFECT_ATTRIBUTE: ATTRIBUTES,
                }[source.kind]
                values[name] = _at(table[source.name], point, name in DECREASING)
            results.append(closed_form(spec.formula_id, values))
        found[spec.component_key] = tuple(results)
    return found


#: Every industry template's gross cash loss (low, base, high) from the fixtures above,
#: in USD. Two are worked by hand; the closed form above gives every one.
#:
#: insurance_claims_overpayment (1,200 claims a day is 50 an hour):
#:   overpaid-claims  low  50 x 2 h x 0.02 x 800 x (1 - 0.40)     =     960
#:                    base 50 x 8 h x 0.05 x 1,500 x (1 - 0.25)   =  22,500
#:                    high 50 x 24 h x 0.10 x 3,000 x (1 - 0.10)  = 324,000
#:   claims-rework 20,000 / 50,000 / 120,000; incident-response 50,000 / 100,000 / 200,000
#:   gross 70,960 / 172,500 / 644,000
#: saas_platform_outage:
#:   sla-credits  min(5,000 x 2, 100,000) = 10,000; min(8,000 x 6, 150,000) = 48,000;
#:                min(12,000 x 18, 250,000) = 216,000
#:   failover-recovery 10,000 + 150 x 40 = 16,000; 25,000 + 200 x 120 = 49,000;
#:                     50,000 + 250 x 300 = 125,000
#:   tenant-churn 2,000 x 0.01 x 0.01 x 20,000 x 1 = 4,000; 2,000 x 0.05 x 0.02 x 30,000 x 1 = 60,000;
#:                2,000 x 0.15 x 0.05 x 40,000 x 2 = 1,200,000
#:   gross 30,000 / 157,000 / 1,541,000
#: insurance_pricing_underwriting_error:
#:   premium-shortfall 200,000 x 0.005 x 1,100 x 0.05 = 55,000; 200,000 x 0.02 x 1,200 x 0.10 = 480,000;
#:                     200,000 x 0.05 x 1,300 x 0.25 = 3,250,000
#:   excess-claims     200,000 x 0.001 x 1,100 x 0.60 x 0.20 = 26,400; 200,000 x 0.005 x 1,200 x 0.65 x 0.40
#:                     = 312,000; 200,000 x 0.01 x 1,300 x 0.70 x 0.80 = 1,456,000
#:   repricing-rework 20,000 / 50,000 / 120,000; market-conduct-response 3 x 20,000 = 60,000;
#:                     3 x 50,000 = 150,000; 5 x 150,000 = 750,000
#:   gross 161,400 / 992,000 / 5,576,000
#: manufacturing_equipment_impact (4,800 units a day is 200 an hour):
#:   equipment-damage 120 x 0.01 x 250,000 x 0.1 = 30,000; 120 x 0.02 x 400,000 x 0.3 = 288,000;
#:                    120 x 0.05 x 600,000 x 1 = 3,600,000
#:   production-loss  200 x 2 h x 0.1 x 30 = 1,200; 200 x 8 h x 0.25 x 40 = 16,000; 200 x 24 h x 0.5 x 55 = 132,000
#:   idle-cost        2 h x 5,000 = 10,000; 8 h x 8,000 = 64,000; 24 h x 15,000 = 360,000
#:   gross 41,200 / 368,000 / 4,092,000
#: mobility_fleet_downtime is the owner's worked example C (section 32; see its own test below).
KNOWN_GROSS = {
    "insurance_claims_overpayment": ("70960", "172500", "644000"),
    "insurance_wrongful_denial": ("122550", "411100", "2391000"),
    "insurance_policyholder_data_exposure": ("197500", "560000", "2630000"),
    "insurance_pricing_underwriting_error": ("161400", "992000", "5576000"),
    "insurance_provider_outage": ("28000", "111400", "422000"),
    "insurance_agent_approval_bypass": ("78000", "242750", "973000"),
    "healthcare_phi_exposure": ("157500", "920000", "5220000"),
    "healthcare_clinical_workflow_interruption": ("68000", "289000", "1715000"),
    "healthcare_record_access_misuse": ("67500", "342500", "1300000"),
    "healthcare_research_ip_loss": ("207500", "1320000", "5820000"),
    "healthcare_gmp_deviation": ("241000", "899000", "3125000"),
    "saas_tenant_isolation_breach": ("94000", "840000", "5350000"),
    "saas_data_exfiltration": ("151500", "620000", "3080000"),
    "saas_agent_tool_misuse": ("78000", "242750", "973000"),
    "saas_api_abuse": ("66060", "150440", "348040"),
    "saas_platform_outage": ("30000", "157000", "1541000"),
    "regulated_enterprise_document_exposure": ("162500", "610000", "2605000"),
    "regulated_enterprise_workflow_manipulation": ("36000", "305750", "2440000"),
    "regulated_enterprise_agent_permissions": ("92000", "453750", "2648000"),
    "regulated_enterprise_vendor_ai_failure": ("29000", "299000", "1819000"),
    "government_sensitive_data_exposure": ("102000", "323000", "1132000"),
    "government_mission_interruption": ("54800", "319200", "1796000"),
    "government_supply_chain_compromise": ("92000", "358000", "2022000"),
    "government_autonomous_agent_effect": ("46800", "212950", "1004000"),
    "manufacturing_safety_system_compromise": ("54800", "268000", "1096000"),
    "manufacturing_equipment_impact": ("41200", "368000", "4092000"),
    "manufacturing_production_interruption": ("27200", "129000", "617000"),
    "manufacturing_supply_chain_disruption": ("21200", "126000", "532000"),
    "mobility_vehicle_asset_damage": ("64000", "337500", "2750000"),
    "mobility_fleet_downtime": ("122325", "319050", "722400"),
    "mobility_route_disruption": ("125000", "351750", "1272000"),
    "mobility_service_interruption": ("18500", "74875", "377000"),
}


@pytest.mark.parametrize("chosen", VERTICAL_TEMPLATES, ids=lambda t: t.template_id)
def test_known_answer_of_every_template(chosen):
    """The engine's components equal the closed form at low, base and high, and the
    gross cash loss is the figure pinned for the template."""
    components = engine_components(chosen)
    expected = closed_form_components(chosen)
    assert [c.component_id for c in components] == list(expected)
    for component in components:
        assert component.status == formulas.ESTIMATED, (component.component_id, component.missing)
        assert tuple(component.at(p).amount for p in POINTS) == expected[component.component_id], component.component_id
        for cited in component.inputs:
            assert cited.parameter.evidence_ref and cited.parameter.source_type
    gross = tuple(
        sum((c.at(p).amount for c in components if c.cash), Decimal(0)) for p in POINTS
    )
    assert gross == tuple(sum((e[i] for k, e in expected.items()), Decimal(0)) for i in range(3))
    assert gross == tuple(Decimal(x) for x in KNOWN_GROSS[chosen.template_id]), (chosen.template_id, gross)


def test_every_industry_template_has_a_pinned_known_answer():
    assert set(KNOWN_GROSS) == {t.template_id for t in VERTICAL_TEMPLATES}


def test_fleet_downtime_is_the_specifications_worked_example_c():
    """The owner's worked example C (section 32), Hermes fleet disruption: a fleet of
    2,500 vehicles making 12 trips each a day (30,000 a day, 1,250 an hour), 1 to 8 per
    cent of it affected, a contribution margin of USD 18 a trip, an outage of 2 to 18
    hours, a field recovery of USD 75 to 450 a vehicle and an operations response of USD
    120,000 to 600,000; the base figures (3 per cent, 6 hours, USD 200, USD 300,000) are
    this test's, SYNTHETIC. Physical damage is the separate template; safety is not
    priced.

      lost-trips      1,250 x 2 h x 0.01 x 18 =    450;  1,250 x 6 h x 0.03 x 18 =  4,050;
                      1,250 x 18 h x 0.08 x 18 = 32,400
      field-recovery  2,500 x 0.01 x 75 = 1,875;  2,500 x 0.03 x 200 = 15,000;  2,500 x 0.08 x 450 = 90,000
      operations      120,000 / 300,000 / 600,000
      gross           122,325 / 319,050 / 722,400
    """
    chosen = pack_registry.template("mobility_fleet_downtime", 1)
    components = {c.component_id: tuple(c.at(p).amount for p in POINTS) for c in engine_components(chosen)}
    assert components == {
        "lost-trips": (Decimal(450), Decimal(4050), Decimal(32400)),
        "field-recovery": (Decimal(1875), Decimal(15000), Decimal(90000)),
        "operations-response": (Decimal(120000), Decimal(300000), Decimal(600000)),
    }
    assert chosen.cautions == (PHYSICAL_WORLD_CAUTION,)
    assert "mobility_vehicle_asset_damage" in " ".join(chosen.direction_notes)


@pytest.mark.parametrize("chosen", VERTICAL_TEMPLATES, ids=lambda t: t.template_id)
def test_a_missing_variable_or_attribute_leaves_its_component_unknown_never_zero(chosen):
    """Step 4's rule holds in every pack for the shared variables and an effect's
    attributes: with none, every component is unknown and names what it lacks (a pack
    input is refused before a build plans: see the builder's tests)."""
    _, inputs, _ = world(PACKS[chosen.pack])
    for planned in tpl.plan(chosen, {}, {}, inputs):
        component = formulas.evaluate(
            planned.spec.component_key, planned.spec.family, planned.spec.formula_id, planned.spec.formula_version,
            planned.bindings(), as_of=AS_OF,
        )
        reads_other = any(s.kind is not tpl.SourceKind.PACK_INPUT for s in planned.spec.sources.values())
        if reads_other:
            assert component.status == formulas.UNKNOWN and component.unknown_reason == "input_missing"
            assert component.low is None and component.base is None and component.high is None


# ======================================================================
# Precedence: one effect, one template, one event
# ======================================================================

PRECEDENCE = {
    "mythos.economics.insurance-pack/v1": [
        "insurance_claims_overpayment", "insurance_wrongful_denial", "insurance_policyholder_data_exposure",
        "insurance_pricing_underwriting_error", "insurance_provider_outage", "insurance_agent_approval_bypass",
    ],
    "mythos.economics.healthcare-pack/v1": [
        "healthcare_phi_exposure", "healthcare_clinical_workflow_interruption", "healthcare_record_access_misuse",
        "healthcare_research_ip_loss", "healthcare_gmp_deviation",
    ],
    "mythos.economics.saas-pack/v1": [
        "saas_tenant_isolation_breach", "saas_data_exfiltration", "saas_agent_tool_misuse", "saas_api_abuse",
        "saas_platform_outage",
    ],
    "mythos.economics.regulated-enterprise-pack/v1": [
        "regulated_enterprise_document_exposure", "regulated_enterprise_workflow_manipulation",
        "regulated_enterprise_agent_permissions", "regulated_enterprise_vendor_ai_failure",
    ],
    "mythos.economics.government-pack/v1": [
        "government_sensitive_data_exposure", "government_mission_interruption", "government_supply_chain_compromise",
        "government_autonomous_agent_effect",
    ],
    "mythos.economics.manufacturing-pack/v1": [
        "manufacturing_safety_system_compromise", "manufacturing_equipment_impact",
        "manufacturing_production_interruption", "manufacturing_supply_chain_disruption",
    ],
    "mythos.economics.mobility-pack/v1": [
        "mobility_vehicle_asset_damage", "mobility_fleet_downtime", "mobility_route_disruption",
        "mobility_service_interruption",
    ],
}

#: (pack, effect type, process) -> the templates that cover it, in precedence order; the
#: first takes it.
OVERLAPS = {
    ("mythos.economics.insurance-pack/v1", "approval_bypassed", "claims"):
        ["insurance_claims_overpayment", "insurance_agent_approval_bypass"],
    ("mythos.economics.insurance-pack/v1", "approval_bypassed", "underwriting"):
        ["insurance_pricing_underwriting_error", "insurance_agent_approval_bypass"],
    ("mythos.economics.insurance-pack/v1", "approval_bypassed", "pricing"):
        ["insurance_pricing_underwriting_error", "insurance_agent_approval_bypass"],
    ("mythos.economics.insurance-pack/v1", "approval_bypassed", "customer_service"):
        ["insurance_agent_approval_bypass"],
    ("mythos.economics.healthcare-pack/v1", "record_access_unauthorised", "patient_records"):
        ["healthcare_phi_exposure", "healthcare_record_access_misuse"],
    ("mythos.economics.healthcare-pack/v1", "record_access_unauthorised", "clinical_care"):
        ["healthcare_record_access_misuse"],
    ("mythos.economics.saas-pack/v1", "data_exfiltrated", "tenant_platform"):
        ["saas_tenant_isolation_breach", "saas_data_exfiltration"],
    ("mythos.economics.saas-pack/v1", "data_exfiltrated", "data_platform"):
        ["saas_data_exfiltration"],
    ("mythos.economics.regulated-enterprise-pack/v1", "agent_permission_exceeded", "legal"):
        ["regulated_enterprise_document_exposure", "regulated_enterprise_agent_permissions"],
    ("mythos.economics.regulated-enterprise-pack/v1", "agent_permission_exceeded", "hr"):
        ["regulated_enterprise_document_exposure", "regulated_enterprise_agent_permissions"],
    ("mythos.economics.regulated-enterprise-pack/v1", "agent_permission_exceeded", "finance"):
        ["regulated_enterprise_workflow_manipulation", "regulated_enterprise_agent_permissions"],
    ("mythos.economics.regulated-enterprise-pack/v1", "agent_permission_exceeded", "procurement"):
        ["regulated_enterprise_workflow_manipulation", "regulated_enterprise_agent_permissions"],
    ("mythos.economics.regulated-enterprise-pack/v1", "agent_permission_exceeded", "it"):
        ["regulated_enterprise_agent_permissions"],
    ("mythos.economics.government-pack/v1", "autonomous_action_unapproved", "mission_operations"):
        ["government_mission_interruption", "government_autonomous_agent_effect"],
    ("mythos.economics.government-pack/v1", "autonomous_action_unapproved", "logistics"):
        ["government_autonomous_agent_effect"],
    ("mythos.economics.manufacturing-pack/v1", "equipment_damaged", "safety_systems"):
        ["manufacturing_safety_system_compromise", "manufacturing_equipment_impact"],
    ("mythos.economics.manufacturing-pack/v1", "equipment_damaged", "production"):
        ["manufacturing_equipment_impact"],
    ("mythos.economics.mobility-pack/v1", "rider_service_interrupted", "dispatch"):
        ["mobility_fleet_downtime", "mobility_service_interruption"],
    ("mythos.economics.mobility-pack/v1", "rider_service_interrupted", "rider_service"):
        ["mobility_service_interruption"],
}


@pytest.mark.parametrize("pack", VERTICAL, ids=lambda p: p.vertical)
def test_each_packs_precedence_is_a_pinned_total_order(pack):
    assert [t.template_id for t in pack.templates] == PRECEDENCE[pack.pack_id]
    assert [t.precedence for t in pack.templates] == list(range(1, len(pack.templates) + 1))
    assert set(pack.catalogue) == {(t.template_id, 1) for t in pack.templates}


@pytest.mark.parametrize("case", sorted(OVERLAPS), ids=lambda c: f"{c[1]}-on-{c[2]}")
def test_an_effect_two_templates_cover_is_assigned_to_the_lower_precedence(case):
    pack_id, effect_type, process = case
    pack = PACKS[pack_id]
    selection = pack.select(effect_type, process)
    assert [t.template_id for t in selection.in_scope_of] == OVERLAPS[case]
    assert selection.template.template_id == OVERLAPS[case][0]
    assert selection.as_dict()["chosen_by"] == ("precedence" if len(OVERLAPS[case]) > 1 else "only_template_in_scope")


def test_every_pack_has_an_overlap_resolved_by_precedence():
    assert {c[0] for c, found in OVERLAPS.items() if len(found) > 1} == {p.pack_id for p in VERTICAL}


@pytest.mark.parametrize("case", sorted(c for c, found in OVERLAPS.items() if len(found) > 1),
                         ids=lambda c: f"{c[1]}-on-{c[2]}")
def test_one_effect_two_templates_cover_is_one_event_with_the_effect_its_own_template_takes(case):
    """Two effects on one asset and process -- one of the type only the lower template
    covers, one of the overlapping type -- are ONE loss event of that template: one
    effect, one event, never one per template."""
    from assurance.economics import builder

    pack_id, effect_type, process = case
    pack = PACKS[pack_id]
    winner = pack.select(effect_type, process).template
    own_type = next(s.effect_type for s in winner.scope if s.business_processes is None)
    asset = "a" * 8 + "-0000-4000-8000-" + "0" * 12

    def effect(key, kind):
        return builder.EffectInput(
            key=key, origin=tpl.Origin.HYPOTHETICAL, effect_type=pack.check_effect_type(kind),
            asset=asset, business_process=pack.check_business_process(process),
        )

    effects = [effect("own", own_type), effect("overlap", effect_type)]
    links = [builder.LinkInput("f" * 8 + "-0000-4000-8000-" + "0" * 12, e.key, tpl.FindingRole.PREREQUISITE)
             for e in effects]
    (plan,) = builder.group(effects, links, pack=pack)
    assert plan.template is winner
    assert {e.key for e in plan.effects} == {"own", "overlap"}
    assert plan.selections["overlap"].in_scope_of[1:] and plan.selections["overlap"].template is winner


# ======================================================================
# The schema: refused with its code, never defaulted
# ======================================================================


def _entry(unit, low, base=None, high=None, *, source="CUSTOMER_PROVIDED", **over):
    base = low if base is None else base
    high = base if high is None else high
    entry = {"unit": unit, "low": low, "base": base, "high": high, "source_type": source,
             "evidence_ref": "CFO questionnaire (SYNTHETIC)", "effective_date": "2026-09-30"}
    if Unit(unit) in MONEY_UNITS:
        entry["currency"] = "USD"
    entry.update(over)
    return entry


def pack_document(of, *, drop=(), **over) -> dict:
    """A parameter-set document for the pack ``of``: a few variables and every input
    of its schema, less ``drop``; ``over`` replaces a top-level field."""
    inputs = {
        name: _entry(entry.unit.value, *INPUTS[name])
        for name, entry in of.inputs.items()
        if name not in drop
    }
    document = {
        "variables": {"legal_retainer": _entry("money", "25000", "50000", "100000")},
        "pack": of.pack_id,
        "pack_inputs": inputs,
    }
    document.update(over)
    return document


def _refused(document) -> str:
    with pytest.raises(ParameterRefused) as refused:
        pset.parse_document(document)
    return refused.value.code


@pytest.mark.parametrize("pack", VERTICAL, ids=lambda p: p.vertical)
def test_a_pack_document_is_read_and_its_digest_is_its_rows(pack):
    content = pset.parse_document(pack_document(pack))
    assert content.pack == pack.pack_id and set(content.pack_inputs) == set(pack.inputs)
    for name, parameter in content.pack_inputs.items():
        assert parameter.name == pack_inputs.PACK_INPUT_PREFIX + name
    document = content.as_dict()
    assert document["pack"] == pack.pack_id and set(document["pack_inputs"]) == set(pack.inputs)
    again = pset.content_of(content.parameters(), content.exclusions, content.distributions, pack=pack.pack_id)
    assert again.digest() == content.digest() and dict(again.pack_inputs) == dict(content.pack_inputs)
    for parameter in content.parameters():
        assert pset.variable_unit(parameter.name, pack.pack_id) is parameter.unit


REQUIRED = [(p.pack_id, name) for p in VERTICAL for name in pack_inputs.SCHEMAS[p.pack_id].required]


@pytest.mark.parametrize("case", REQUIRED, ids=lambda c: c[1])
def test_a_missing_required_input_is_refused_never_defaulted(case):
    pack_id, name = case
    pack = PACKS[pack_id]
    with pytest.raises(ParameterRefused) as refused:
        pset.parse_document(pack_document(pack, drop={name}))
    assert refused.value.code == "pack_input_missing"
    assert name in refused.value.detail
    # And the content refuses it too, however it is made: from stored rows as well.
    content = pset.parse_document(pack_document(pack))
    kept = [p for p in content.parameters() if p.name != pack_inputs.PACK_INPUT_PREFIX + name]
    with pytest.raises(ParameterRefused) as refused:
        pset.content_of(kept, (), pack=pack_id)
    assert refused.value.code == "pack_input_missing"


@pytest.mark.parametrize("pack", VERTICAL, ids=lambda p: p.vertical)
def test_a_pack_with_no_inputs_stated_is_refused(pack):
    assert _refused(pack_document(pack, drop=set(pack.inputs))) == "pack_input_missing"
    document = pack_document(pack)
    del document["pack_inputs"]
    assert _refused(document) == "pack_input_missing"


def test_an_optional_input_is_needed_only_by_the_templates_that_read_it():
    """An input the pack does not require may be left out of the set, and the version
    is recorded; a build whose effect is assigned to a template that reads it is
    refused (``pack_input_missing``), never defaulted, never left unknown."""
    optional = [(p, n) for p in VERTICAL for n, e in p.inputs.items() if not e.required]
    assert optional
    for pack, name in optional:
        content = pset.parse_document(pack_document(pack, drop={name}))
        readers = [t for t in pack.templates
                   if any(s.kind is tpl.SourceKind.PACK_INPUT and s.name == name
                          for c in t.components for s in c.sources.values())]
        assert readers, name
        for chosen in readers:
            with pytest.raises(ParameterRefused) as refused:
                pack.check_template_inputs(chosen, content.pack_inputs)
            assert refused.value.code == "pack_input_missing" and name in refused.value.detail
        for chosen in pack.templates:
            if chosen not in readers:
                pack.check_template_inputs(chosen, content.pack_inputs)


@pytest.mark.parametrize("pack", VERTICAL, ids=lambda p: p.vertical)
def test_every_schema_refusal_has_its_code(pack):
    name, entry = next(iter(sorted(pack.inputs.items())))
    wrong_unit = Unit.HOURS if entry.unit is not Unit.HOURS else Unit.DAYS
    cases = {
        "pack_unrecognised": [
            pack_document(pack, pack="mythos.economics.no-such-pack/v1"),
            pack_document(pack, pack=tpl.PACK),
            pack_document(pack, pack=None),
            pack_document(pack, pack=pack.pack_id.replace("/v1", "/v2")),
        ],
        "field_unrecognised": [
            {"variables": {"legal_retainer": _entry("money", "1")}, "pack_inputs": {}},
        ],
        "field_malformed": [pack_document(pack, pack_inputs=["x"])],
        "pack_input_unrecognised": [
            pack_document(pack, pack_inputs={**pack_document(pack)["pack_inputs"],
                                             "units_shipped_per_week": _entry("count", "9")}),
            pack_document(pack, pack_inputs={**pack_document(pack)["pack_inputs"], "legal_retainer": _entry("money", "1")}),
        ],
        "unit_mismatch": [
            pack_document(pack, pack_inputs={**pack_document(pack)["pack_inputs"],
                                             name: _entry(wrong_unit.value, "1")}),
        ],
        "safety_monetisation_refused": [
            pack_document(pack, pack_inputs={**pack_document(pack)["pack_inputs"],
                                             "injury_cost_per_person": _entry("money_per_unit", "1")}),
            pack_document(pack, pack_inputs={**pack_document(pack)["pack_inputs"],
                                             "value_of_statistical_life": _entry("money", "1")}),
        ],
    }
    money_input = next((n for n, e in pack.inputs.items() if e.unit in MONEY_UNITS), None)
    if money_input is not None:
        observed = dict(pack_document(pack)["pack_inputs"])
        observed[money_input] = {**observed[money_input], "source_type": "MYTHOS_OBSERVED"}
        cases["observed_source_not_observable"] = [pack_document(pack, pack_inputs=observed)]
    for code, documents in cases.items():
        for document in documents:
            assert _refused(document) == code, (code, document.get("pack"))


def test_a_banking_set_is_the_document_it_was():
    """A set that names no pack is the banking pack's: its canonical document has no
    pack and no inputs, as every set before E7, so its digest is the one it had."""
    document = {"variables": {"legal_retainer": _entry("money", "25000", "50000", "100000")}}
    content = pset.parse_document(document)
    assert content.pack == "" and content.pack_inputs == {}
    assert set(content.as_dict()) == {"schema", "variables", "insurance_sublimits", "insurance_exclusions"}
    # A stored input on a set that names no pack is not a variable.
    with pytest.raises(ParameterRefused) as refused:
        pset.variable_unit(pack_inputs.PACK_INPUT_PREFIX + "policy_count")
    assert refused.value.code == "field_unrecognised"
    with pytest.raises(ParameterRefused) as refused:
        pset.variable_unit(pack_inputs.PACK_INPUT_PREFIX + "fleet_size", "mythos.economics.insurance-pack/v1")
    assert refused.value.code == "pack_input_unrecognised"


def test_the_pack_checks_name_their_codes():
    insurance = PACKS["mythos.economics.insurance-pack/v1"]
    for pack, set_pack in ((insurance, ""), (insurance, "mythos.economics.saas-pack/v1"),
                           (pack_registry.BANKING, insurance.pack_id)):
        with pytest.raises(ParameterRefused) as refused:
            pack.check_set(set_pack)
        assert refused.value.code == "pack_mismatch"
    insurance.check_set(insurance.pack_id)
    pack_registry.BANKING.check_set("")
    with pytest.raises(ParameterRefused) as refused:
        insurance.check_inputs({})
    assert refused.value.code == "pack_input_missing"
    with pytest.raises(tpl.BuildRefused) as refused:
        insurance.check_effect_type("funds_transfer_altered")
    assert refused.value.code == "effect_type_unrecognised"
    with pytest.raises(tpl.BuildRefused) as refused:
        insurance.check_business_process("payments")
    assert refused.value.code == "business_process_unrecognised"
    with pytest.raises(tpl.BuildRefused) as refused:
        insurance.parse_attributes("e", {"success_rate": _entry("ratio", "0.1")}, "attributes",
                                   origin=tpl.Origin.HYPOTHETICAL)
    assert refused.value.code == "attribute_unrecognised"


# ======================================================================
# Bias and fairness: no figure, and no geographic or company-size weight
# ======================================================================

#: Words that key a figure to a place or a size. A name holding one (its words split
#: at "_", "-" and ".") is read only as a customer input of a pack's schema, stated by
#: the customer with its provenance (the owner's specification, section 27).
REGION_OR_SIZE = frozenset(
    {
        "region", "regional", "regions", "country", "countries", "geography", "geographic", "geo", "continent",
        "territory", "territories", "jurisdiction", "jurisdictions", "nation", "national", "locale", "zip",
        "postal", "postcode", "city", "cities", "urban", "rural", "emea", "apac", "latam", "eu", "us", "uk",
        "domestic", "foreign", "offshore", "state", "states", "province", "size", "sized", "small", "large",
        "medium", "midsize", "big", "sme", "smb", "midmarket", "headcount", "employees",
        "employee", "tier", "tiers", "band", "bands", "bracket", "turnover",
    }
)
_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]*")


def _keyed(name: str) -> bool:
    return bool(set(re.split(r"[_\-.]+", name.lower())) & REGION_OR_SIZE)


def _inputs_of_every_pack() -> set[str]:
    return {name for schema in pack_inputs.SCHEMAS.values() for name in schema.inputs}


@pytest.mark.parametrize("module", PACK_MODULES)
def test_a_pack_module_holds_no_figure_and_no_place_or_size_weight(module):
    """Read off each pack module's source: no float, no number written as text, no
    Decimal, Money or Fraction made, no integer but a version or a precedence (at most
    nine); no variable, function or constant named for a place or a size; and a name
    of a place or a size written as text only where it is a customer input of a
    pack's schema."""
    tree = ast.parse((ENGINE / module).read_text(encoding="utf-8"))
    inputs = _inputs_of_every_pack()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant):
            value = node.value
            assert type(value) is not float, (module, value)
            if type(value) is int:
                assert 0 <= value <= 9, (module, value)
            if isinstance(value, str):
                assert not re.fullmatch(r"-?[0-9]+(\.[0-9]+)?", value.strip()), (module, value)
                if _IDENTIFIER.fullmatch(value) and _keyed(value):
                    assert value in inputs, (module, value)
        if isinstance(node, ast.Call):
            called = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
            assert called not in {"Decimal", "Money", "Fraction", "float"}, (module, called)
        for name in _names(node):
            assert not _keyed(name), (module, name)


def _names(node) -> list[str]:
    if isinstance(node, ast.Name):
        return [node.id]
    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
        return [node.name]
    if isinstance(node, ast.arg):
        return [node.arg]
    if isinstance(node, ast.alias):
        return [node.asname or node.name]
    return []


@pytest.mark.parametrize("pack", tuple(PACKS.values()), ids=lambda p: p.vertical)
def test_a_pack_reads_a_place_or_a_size_only_as_the_customers_stated_input(pack):
    """Read off each pack's data: a template's source, an attribute, an effect type, a
    process, a template or a component is never named for a place or a size; only a
    customer input of the schema may be, and a template reads it only as that input."""
    for chosen in pack.templates:
        assert not _keyed(chosen.template_id), chosen.template_id
        for spec in chosen.components:
            assert not _keyed(spec.component_key), spec.component_key
            for source in spec.sources.values():
                if _keyed(source.name):
                    assert source.kind is tpl.SourceKind.PACK_INPUT, (chosen.template_id, source.name)
                    assert source.name in pack.inputs
    for name in (*pack.attributes, *pack.effect_types, *pack.business_processes):
        assert not _keyed(name), (pack.pack_id, name)
    # A source is a kind and a name: nothing else, no figure.
    import dataclasses

    assert {f.name for f in dataclasses.fields(tpl.Source)} == {"kind", "name"}


# ======================================================================
# Safety: harm to a person is never priced; the physical-world caution
# ======================================================================


def test_no_pack_names_harm_to_a_person():
    for pack in PACKS.values():
        names = [*pack.attributes, *pack.effect_types, *pack.business_processes, *pack.inputs,
                 *(t.template_id for t in pack.templates),
                 *(c.component_key for t in pack.templates for c in t.components)]
        assert not [n for n in names if pack_inputs.names_harm(n)], pack.pack_id
    for name in ("injury_cost", "passenger_injured", "fatality", "patient_harm", "value_of_statistical_life",
                 "bodily-injury", "deaths_per_year", "qaly_lost"):
        assert pack_inputs.names_harm(name), name
    for name in ("pharmacy", "harmonised", "deadline", "claims", "fleet_size", "wrongly_denied_claims"):
        assert not pack_inputs.names_harm(name), name


@pytest.mark.parametrize("pack", VERTICAL, ids=lambda p: p.vertical)
def test_a_harm_named_effect_type_or_attribute_is_refused(pack):
    for value in ("passenger_injured", "patient_harmed", "fatality"):
        with pytest.raises(ParameterRefused) as refused:
            pack.check_effect_type(value)
        assert refused.value.code == "safety_monetisation_refused"
    with pytest.raises(ParameterRefused) as refused:
        pack.parse_attributes("e", {"injury_cost": _entry("money", "1")}, "attributes", origin=tpl.Origin.HYPOTHETICAL)
    assert refused.value.code == "safety_monetisation_refused"
    assert HARM_EXCLUDED in pack.excluded


def test_the_banking_pack_refuses_as_it_did():
    """Banking is unchanged: a harm-named type is an unrecognised one there, as before."""
    with pytest.raises(tpl.BuildRefused) as refused:
        pack_registry.BANKING.check_effect_type("passenger_injured")
    assert refused.value.code == "effect_type_unrecognised"
    assert pack_registry.BANKING.excluded == ()


def test_a_physical_world_template_carries_the_caution():
    physical = {
        "healthcare_clinical_workflow_interruption",
        "healthcare_gmp_deviation",
        "government_mission_interruption",
        "government_autonomous_agent_effect",
        *PRECEDENCE["mythos.economics.manufacturing-pack/v1"],
        *PRECEDENCE["mythos.economics.mobility-pack/v1"],
    }
    for chosen in VERTICAL_TEMPLATES:
        if chosen.template_id in physical:
            assert chosen.cautions == (PHYSICAL_WORLD_CAUTION,)
            assert chosen.as_dict()["cautions"] == [PHYSICAL_WORLD_CAUTION]
        else:
            assert chosen.cautions == () and "cautions" not in chosen.as_dict()
    for words in ("sections 32 and 37", "never a prediction", "heavy-tail", "safety_monetisation_refused"):
        assert words in PHYSICAL_WORLD_CAUTION


def test_the_registry_document_serves_every_pack():
    document = pack_registry.registry_document()
    assert [p["pack"] for p in document["packs"]] == list(PACKS)
    insurance = document["packs"][1]
    assert insurance["customer_inputs"]["claims_per_day"] == {
        "unit": "count_per_day", "meaning": "claims the claims workflow decides per day", "required": True,
        "special_data": "claims volume",
    }
    assert insurance["loss_families"] == list(PACKS[insurance["pack"]].families)
    assert document["packs"][0]["customer_inputs"] == {} and document["packs"][0]["excluded"] == []


# ======================================================================
# The spec documents every template as the code states it
# ======================================================================


def _where(source) -> str:
    return {
        tpl.SourceKind.PARAMETER_SET: "from the set",
        tpl.SourceKind.EFFECT_ATTRIBUTE: "from the effect",
        tpl.SourceKind.PACK_INPUT: "from the pack's inputs",
    }[source.kind]


def _scope(chosen) -> str:
    parts = []
    for scope in chosen.scope:
        where = "any process" if scope.business_processes is None else ", ".join(
            f"`{p}`" for p in sorted(str(p) for p in scope.business_processes))
        parts.append(f"`{scope.effect_type}` on {where}")
    return "; ".join(parts)


def render_template(chosen) -> str:
    """The spec's block for ``chosen``: its heading, scope, components and notes."""
    lines = [
        f"#### `{chosen.template_id}`, version {chosen.version}, precedence {chosen.precedence}: {chosen.name}",
        "",
        f"Covers {_scope(chosen)}.",
        "",
        "| Component | Family | Formula | Inputs: direction, source |",
        "|---|---|---|---|",
    ]
    for spec in chosen.components:
        formula = formulas.formula(spec.formula_id, spec.formula_version)
        inputs = "; ".join(
            f"`{i.name}` ({'+' if i.direction is formulas.Direction.INCREASES else '-'}) {_where(spec.sources[i.name])}: "
            f"`{spec.sources[i.name].name}`"
            for i in formula.inputs
        )
        lines.append(f"| `{spec.component_key}` | `{spec.family}` | `{spec.formula_id}` v{spec.formula_version} | {inputs} |")
    lines += ["", "Direction notes:", ""] + [f"- {note}" for note in chosen.direction_notes]
    if chosen.cautions:
        lines += ["", "Caution (`PHYSICAL_WORLD_CAUTION`): " + "; ".join(chosen.cautions) + "."]
    return "\n".join(lines)


def render_schema(pack) -> str:
    lines = ["| Input | Unit | Required | Special data (section 23) | Meaning |", "|---|---|---|---|---|"]
    for name, entry in pack.inputs.items():
        lines.append(f"| `{name}` | `{entry.unit}` | {'yes' if entry.required else 'no: its templates require it'} | "
                     f"{entry.special_data} | {entry.meaning} |")
    return "\n".join(lines)


def render_attributes(pack) -> str:
    lines = ["| Attribute | Unit | Meaning | Observable |", "|---|---|---|---|"]
    for name, a in pack.attributes.items():
        lines.append(f"| `{name}` | `{a.unit}` | {a.meaning} | {'yes' if a.observable else 'no'} |")
    return "\n".join(lines)


def render_vocabulary(pack) -> str:
    lines = ["| Effect type | Meaning |", "|---|---|"]
    lines += [f"| `{code}` | {meaning} |" for code, meaning in pack.effect_types.items()]
    lines += ["", "Business processes: " + ", ".join(f"`{p}`" for p in pack.business_processes) + "."]
    return "\n".join(lines)


def _spec_text() -> str:
    return SPEC.read_text(encoding="utf-8")


@pytest.mark.parametrize("chosen", VERTICAL_TEMPLATES, ids=lambda t: t.template_id)
def test_the_spec_documents_every_template_as_the_code_states_it(chosen):
    assert render_template(chosen) in _spec_text()


@pytest.mark.parametrize("pack", VERTICAL, ids=lambda p: p.vertical)
def test_the_spec_documents_every_packs_schema_attributes_and_vocabulary(pack):
    text = _spec_text()
    assert render_schema(pack) in text, pack.pack_id
    assert render_attributes(pack) in text, pack.pack_id
    assert render_vocabulary(pack) in text, pack.pack_id


def test_the_spec_names_every_pack_code():
    text = _spec_text()
    codes = [
        *PACKS, *(p.vertical for p in VERTICAL),
        *(f"{f}" for f in ("pack_unrecognised", "pack_input_unrecognised", "pack_input_missing", "pack_mismatch",
                           "safety_monetisation_refused")),
        "pack_input", "pack_inputs", pack_inputs.PACK_INPUT_PREFIX, "economics-packs", "PHYSICAL_WORLD_CAUTION",
        "HARM_EXCLUDED", "0076_parameter_set_pack",
        *(module.removesuffix(".py") for module in PACK_MODULES),
    ]
    missing = sorted({c for c in codes if f"`{c}`" not in text})
    assert not missing, missing
