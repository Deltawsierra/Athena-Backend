"""The industry packs (Economic Exposure E7; ``docs/economics/spec-v1.md``, section
37), pure: no database.

- the registry: banking, unchanged, and each industry pack, versioned in its id and
  held with the digest it was released with (a version's content never changes under
  its id; a new version stands beside the old one), with its templates, loss families
  and customer-input schema; one template id in one vertical;
- every component of every template is well formed, every attribute and input is read,
  every effect type is covered, and every template reads each attribute one way;
- KNOWN ANSWERS: every template of every industry pack, at low, base and high, three
  ways -- the engine, an independent closed form of each formula written here, and the
  figures pinned below -- which agree;
- precedence: each pack's order pinned, and an effect two templates cover assigned to
  ONE, the lower, and in ONE event;
- the schema: nothing required at record time; a build refused, with its code, for an
  input a template it uses reads (never defaulted), and every other refusal code; an
  optional component made only where its input is stated;
- bias and fairness: no pack holds a figure, and none a geographic or company-size
  weight, read off its data, its module's source and the formulas the packs add; every
  name a pack uses is on a reviewed allow-list;
- safety: harm to a person is never priced; a physical-world template carries the
  caution;
- the spec documents every template, as the code states it, and every code.

SYNTHETIC / ILLUSTRATIVE: every figure here is made up.
"""

from __future__ import annotations

import ast
import dataclasses
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
                "pack_saas.py")


# ======================================================================
# The registry
# ======================================================================


def test_the_registry_holds_banking_and_each_industry_pack_versioned():
    assert list(PACKS) == [
        "mythos.economics.banking-pack/v1",
        "mythos.economics.insurance-pack/v1",
        "mythos.economics.healthcare-pack/v1",
        "mythos.economics.saas-pack/v1",
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
        # Every input is required by the builds of the templates that read it, or read
        # only by an optional component (choice 2).
        for name in pack.inputs:
            assert pack.required_by[name] or name in OPTIONAL_INPUTS, (pack.pack_id, name)
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
            assert pack_registry.packs_of_template(chosen.template_id, chosen.version) == (pack,)
            assert pack_registry.template(chosen.template_id, chosen.version, pack.pack_id) is chosen
            assert chosen.template_id.startswith(pack.vertical + "_") or pack.banking
    assert pack_registry.template("no_such_template", 1) is None
    assert pack_registry.packs_of_template("no_such_template", 1) == ()


# ----------------------------------------------------------------------
# Each version held with its digest; a new version beside the old (F1)
# ----------------------------------------------------------------------

#: The digest every pack version was released with, pinned here apart from the
#: registry's own table. A changed digest is a pack changed under its version: release
#: a NEW version (``.../v<n+1>``) beside it, never edit a released one in place.
PACK_DIGESTS = {
    "mythos.economics.banking-pack/v1": "sha256:fcdd2f17987866c66d1d4f3597adb7518443cdf35d7fead689540c20a39afd1d",
    "mythos.economics.insurance-pack/v1": "sha256:4e1700e81775337c1c21474d582daad8a8730a87805def937ea7ee481c7ba19a",
    "mythos.economics.healthcare-pack/v1": "sha256:9ebc335e1c902db504afa4cbcad4c45c9a3c64584fcf02804156ea55054667d9",
    "mythos.economics.saas-pack/v1": "sha256:a7e9242a22206623f3bce6b7b567998544109985a5c70c80e8303c8956b6d6eb",
}


def test_each_pack_version_is_held_with_the_digest_it_was_released_with():
    """The registry holds (pack, version, digest): every pack it holds is a released
    version whose content is the digest it was released with, pinned here as well; the
    route serves each with its digest."""
    assert dict(pack_registry.RELEASED) == PACK_DIGESTS, "a changed digest needs a new /vN, never an in-place edit"
    assert set(PACKS) == set(PACK_DIGESTS)
    for pack_id, pack in PACKS.items():
        assert pack.digest == PACK_DIGESTS[pack_id], f"{pack_id} changed under its version: release a new /vN"
        assert re.fullmatch(r"sha256:[0-9a-f]{64}", pack.digest)
    served = {p["pack"]: p["digest"] for p in pack_registry.registry_document()["packs"]}
    assert served == PACK_DIGESTS


def _version(pack, n: int, *, change=None):
    """``pack`` as version ``n``: the same content, every template named for the new
    version; ``change`` replaces what a new version changes."""
    pack_id = pack.pack_id.rsplit("/v", 1)[0] + f"/v{n}"
    fields = {"pack_id": pack_id, "templates": tuple(dataclasses.replace(t, pack=pack_id) for t in pack.templates)}
    fields.update(change or {})
    return dataclasses.replace(pack, **fields)


def test_a_new_version_stands_beside_the_old_one():
    """A changed template is a new template version in a new pack version, released with
    its own digest: the registry holds both, each read exactly, and the template the two
    versions share unchanged is one template of both."""
    insurance = PACKS["mythos.economics.insurance-pack/v1"]
    bumped = dataclasses.replace(insurance.templates[0], version=2, name="Claims overpayment, revised")
    v2 = _version(insurance, 2)
    v2 = _version(insurance, 2, change={"templates": (dataclasses.replace(bumped, pack=v2.pack_id), *v2.templates[1:])})
    released = {**pack_registry.RELEASED, v2.pack_id: v2.digest}
    packs, templates = pack_registry._index((*PACKS.values(), v2), released)
    assert packs[insurance.pack_id] is insurance and packs[v2.pack_id] is v2
    assert v2.digest != insurance.digest
    first = insurance.templates[0]
    assert templates[(first.template_id, 1)] is first and templates[(first.template_id, 2)].pack == v2.pack_id
    shared = insurance.templates[1]
    assert templates[shared.key] is shared  # indexed as the first version holds it
    assert v2.catalogue[shared.key].as_dict() == {**shared.as_dict(), "pack": v2.pack_id}


def _winning_pair(pack, chosen):
    """An effect type and process ``chosen`` takes in ``pack``, by precedence."""
    return next(
        (t, p) for t in pack.effect_type_codes for p in pack.business_process_codes
        if pack.select(t, p).template is chosen
    )


@pytest.mark.parametrize("chosen", VERTICAL_TEMPLATES, ids=lambda t: t.template_id)
def test_a_build_records_the_digest_and_the_statements_of_its_pack(chosen):
    """F1 and F5, for every template of every industry pack: the build document of an
    effect the template takes records the digest the pack was released with and what
    its figures are read with -- the template's cautions and what the pack never
    prices -- so a report and a card state them from the build; a banking build's
    document records neither."""
    from assurance.economics import builder

    pack = PACKS[chosen.pack]
    effect_type, process = _winning_pair(pack, chosen)
    effect = builder.EffectInput(
        key="e", origin=tpl.Origin.HYPOTHETICAL, effect_type=effect_type,
        asset="a" * 8 + "-0000-4000-8000-" + "0" * 12, business_process=process,
    )
    common = {"deployment_uuid": "d" * 8 + "-0000-4000-8000-" + "0" * 12,
              "parameter_set": {"set_key": "s", "version": 1}, "currency": "USD", "as_of": AS_OF,
              "effects": [effect], "links": []}
    document = builder.build_document(**common, pack=pack)
    assert document["pack"] == pack.pack_id
    assert document["pack_digest"] == pack.digest == pack_registry.RELEASED[pack.pack_id]
    assert document["pack_statements"] == {"cautions": list(chosen.cautions), "excluded": list(pack.excluded)}
    banking = builder.build_document(**{**common, "effects": []})
    assert "pack_digest" not in banking and "pack_statements" not in banking


def test_a_released_version_changed_in_place_is_refused():
    """An edit of a released version under its own id -- a template's name, an input's
    meaning -- is refused when the registry is built, whatever else agrees with it."""
    insurance = PACKS["mythos.economics.insurance-pack/v1"]
    others = tuple(p for p in PACKS.values() if p is not insurance)
    edits = {
        "a template renamed": {
            "templates": (dataclasses.replace(insurance.templates[0], name="renamed"), *insurance.templates[1:])
        },
        "an input's meaning": {
            "inputs": {
                **insurance.inputs,
                "manual_claim_handling_cost": dataclasses.replace(
                    insurance.inputs["manual_claim_handling_cost"], meaning="doubled for a weekend surge"
                ),
            }
        },
    }
    for what, change in edits.items():
        edited = dataclasses.replace(insurance, **change)
        assert edited.digest != insurance.digest, what
        with pytest.raises(ValueError, match="not the digest it was released with"):
            pack_registry._index((*others, edited))
    # The same registry with the version as released builds.
    pack_registry._index(tuple(PACKS.values()))


def test_a_template_changed_under_its_own_version_is_refused():
    """Two versions of a pack holding one template id and version hold ONE content: a
    template changed in a new pack version without its own version bumped is refused;
    and a template id is one vertical's."""
    insurance = PACKS["mythos.economics.insurance-pack/v1"]
    v2 = _version(insurance, 2)
    v2 = _version(insurance, 2, change={
        "templates": (dataclasses.replace(v2.templates[0], name="renamed, same version"), *v2.templates[1:])
    })
    with pytest.raises(ValueError, match="a changed template is a new template version"):
        pack_registry._index((*PACKS.values(), v2), {**pack_registry.RELEASED, v2.pack_id: v2.digest})
    saas = PACKS["mythos.economics.saas-pack/v1"]
    saas_v2 = saas.pack_id.replace("/v1", "/v2")
    stolen = _version(saas, 2, change={"templates": (dataclasses.replace(insurance.templates[0], pack=saas_v2),)})
    with pytest.raises(ValueError, match="two verticals"):
        pack_registry._index((*PACKS.values(), stolen), {**pack_registry.RELEASED, stolen.pack_id: stolen.digest})
    unreleased = _version(saas, 2)
    with pytest.raises(ValueError, match="released with"):
        pack_registry._index((*PACKS.values(), unreleased))


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
    "usage_margin_per_hour": ("1000", "2000", "4000"),
    "contract_sla_credit_per_hour": ("5000", "8000", "12000"),
    "contract_sla_credit_cap": ("100000", "150000", "250000"),
    "abuse_spend_cap_per_hour": ("3000", "4000", "6000"),
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
#:   without usage billing (the optional usage-revenue absent): 30,000 / 157,000 / 1,541,000
#:   usage-revenue (choice 8) 2 h x 1,000 = 2,000; 6 h x 2,000 = 12,000; 18 h x 4,000 = 72,000
#:   gross 32,000 / 169,000 / 1,613,000
#: saas_tenant_isolation_breach gains legal and regulatory (F3, worked example B):
#:   legal 25,000 + 450 x 50 = 47,500; 50,000 + 600 x 150 = 140,000; 100,000 + 800 x 400 = 420,000
#:   regulatory 0 / 100,000 / 400,000
#:   gross 94,000 + 47,500 = 141,500; 840,000 + 240,000 = 1,080,000; 5,350,000 + 820,000 = 6,170,000
#: saas_api_abuse (F7: the abuse reads a share of the named cap, abuse_spend_cap_per_hour):
#:   abuse-compute 2 h x 3,000 x 0.10 = 600; 12 h x 4,000 x 0.30 = 14,400; 48 h x 6,000 x 0.80 = 230,400
#:   abuse-mitigation 16,000 / 49,000 / 125,000; incident-response 50,000 / 100,000 / 200,000
#:   gross 66,600 / 163,400 / 555,400
#: insurance_pricing_underwriting_error:
#:   premium-shortfall 200,000 x 0.005 x 1,100 x 0.05 = 55,000; 200,000 x 0.02 x 1,200 x 0.10 = 480,000;
#:                     200,000 x 0.05 x 1,300 x 0.25 = 3,250,000
#:   excess-claims     200,000 x 0.001 x 1,100 x 0.60 x 0.20 = 26,400; 200,000 x 0.005 x 1,200 x 0.65 x 0.40
#:                     = 312,000; 200,000 x 0.01 x 1,300 x 0.70 x 0.80 = 1,456,000
#:   repricing-rework 20,000 / 50,000 / 120,000; market-conduct-response 3 x 20,000 = 60,000;
#:                     3 x 50,000 = 150,000; 5 x 150,000 = 750,000
#:   gross 161,400 / 992,000 / 5,576,000
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
    "saas_tenant_isolation_breach": ("141500", "1080000", "6170000"),
    "saas_data_exfiltration": ("151500", "620000", "3080000"),
    "saas_agent_tool_misuse": ("78000", "242750", "973000"),
    "saas_api_abuse": ("66600", "163400", "555400"),
    "saas_platform_outage": ("32000", "169000", "1613000"),
}
#: The SaaS outage of a platform that bills by subscription alone: its set states no
#: usage margin, and the optional usage-revenue component is absent (choice 8).
OUTAGE_WITHOUT_USAGE = ("30000", "157000", "1541000")


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


#: The loss families a template that loses an effect by precedence prices and the
#: winner does not: each accepted gap named here (as banking's own precedence drops
#: recovery on payments), so a new one fails until it is reviewed. A SaaS cross-tenant
#: exposure drops none: its winner prices legal and regulatory (F3).
ACCEPTED_GAPS = {
    ("mythos.economics.insurance-pack/v1", "approval_bypassed", "underwriting"): {"incident_response"},
    ("mythos.economics.insurance-pack/v1", "approval_bypassed", "pricing"): {"incident_response"},
    ("mythos.economics.healthcare-pack/v1", "record_access_unauthorised", "patient_records"): {"recovery"},
}


@pytest.mark.parametrize("case", sorted(c for c, found in OVERLAPS.items() if len(found) > 1),
                         ids=lambda c: f"{c[1]}-on-{c[2]}")
def test_the_precedence_winner_prices_every_family_it_takes_or_the_gap_is_accepted(case):
    pack = PACKS[case[0]]
    winner, *losers = (pack.catalogue[(template_id, 1)] for template_id in OVERLAPS[case])
    lost = set().union(*({c.family for c in t.components} for t in losers)) - {c.family for c in winner.components}
    assert lost == ACCEPTED_GAPS.get(case, set()), (case, sorted(lost))


def test_a_saas_cross_tenant_exposure_prices_legal_and_regulatory():
    """F3 (worked example B of the owner's specification): data taken across tenants is
    taken by the isolation-breach template, which prices legal and regulatory as the
    exfiltration template does, from the same sources."""
    saas = PACKS["mythos.economics.saas-pack/v1"]
    chosen = saas.select("data_exfiltrated", "tenant_platform").template
    assert chosen.template_id == "saas_tenant_isolation_breach"
    exfiltration = saas.catalogue[("saas_data_exfiltration", 1)]
    for key in ("legal", "regulatory"):
        mine = next(c for c in chosen.components if c.component_key == key)
        theirs = next(c for c in exfiltration.components if c.component_key == key)
        assert mine == theirs, key
    assert {c.family for c in exfiltration.components} <= {c.family for c in chosen.components}
    legal, regulatory = (closed_form_components(chosen)[k] for k in ("legal", "regulatory"))
    assert legal == (Decimal(47500), Decimal(140000), Decimal(420000))
    assert regulatory == (Decimal(0), Decimal(100000), Decimal(400000))


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


READ_INPUTS = [(p.pack_id, name) for p in VERTICAL for name in p.inputs if p.required_by[name]]


@pytest.mark.parametrize("case", READ_INPUTS, ids=lambda c: c[1])
def test_no_input_is_required_at_record_time_and_a_build_that_reads_one_requires_it(case):
    """Choice 2 (interim): a set records without the input -- never pushed to state a
    zero for it -- however it is made, from a document or from stored rows; a build
    whose effect is assigned to a template that reads it is refused
    (``pack_input_missing``, naming the template and the input), never defaulted; a
    template that does not read it builds without it."""
    pack_id, name = case
    pack = PACKS[pack_id]
    content = pset.parse_document(pack_document(pack, drop={name}))
    assert content.pack == pack_id and name not in content.pack_inputs
    full = pset.parse_document(pack_document(pack))
    kept = [p for p in full.parameters() if p.name != pack_inputs.PACK_INPUT_PREFIX + name]
    assert name not in pset.content_of(kept, (), pack=pack_id).pack_inputs
    for chosen in pack.templates:
        if chosen.template_id in pack.required_by[name]:
            with pytest.raises(ParameterRefused) as refused:
                pack.check_template_inputs(chosen, content.pack_inputs)
            assert refused.value.code == "pack_input_missing"
            assert name in refused.value.detail and chosen.template_id in refused.value.detail
        else:
            pack.check_template_inputs(chosen, content.pack_inputs)


@pytest.mark.parametrize("pack", VERTICAL, ids=lambda p: p.vertical)
def test_a_set_with_no_inputs_records_and_a_build_that_reads_one_is_refused(pack):
    bare = pack_document(pack, drop=set(pack.inputs))
    del bare["pack_inputs"]
    for document in (pack_document(pack, drop=set(pack.inputs)), bare):
        content = pset.parse_document(document)
        assert content.pack == pack.pack_id and content.pack_inputs == {}
        for chosen in pack.templates:
            reads = {s.name for c in chosen.components if not chosen.is_optional(c) for s in c.sources.values()
                     if s.kind is tpl.SourceKind.PACK_INPUT}
            if reads:
                with pytest.raises(ParameterRefused) as refused:
                    pack.check_template_inputs(chosen, content.pack_inputs)
                assert refused.value.code == "pack_input_missing"
            else:
                pack.check_template_inputs(chosen, content.pack_inputs)


#: Every optional component of every pack (choice 8), and the inputs that switch them
#: on, pinned: a new optional component is reviewed before it is one.
OPTIONAL_COMPONENTS = {("saas_platform_outage", "usage-revenue")}
OPTIONAL_INPUTS = {"usage_margin_per_hour"}


def test_every_optional_component_is_pinned_and_switched_on_by_a_stated_input():
    found = {(t.template_id, c.component_key) for t in VERTICAL_TEMPLATES for c in t.components if t.is_optional(c)}
    assert found == OPTIONAL_COMPONENTS
    switches = {s.name for t in VERTICAL_TEMPLATES for c in t.components if t.is_optional(c)
                for s in c.sources.values() if s.kind is tpl.SourceKind.PACK_INPUT}
    assert switches == OPTIONAL_INPUTS
    # An input that switches an optional component on is read by no other component.
    assert not {s.name for t in VERTICAL_TEMPLATES for c in t.components if not t.is_optional(c)
                for s in c.sources.values() if s.kind is tpl.SourceKind.PACK_INPUT} & OPTIONAL_INPUTS
    assert not any(t.optional_components for t in tpl.TEMPLATES)
    banking = tpl.TEMPLATES[0]
    for key in (banking.components[0].component_key, "no-such-component"):
        with pytest.raises(ValueError, match="reads no pack input"):
            dataclasses.replace(banking, optional_components=frozenset({key}))


def _gross(chosen, inputs) -> tuple[Decimal, ...]:
    variables, _, attributes = world(PACKS[chosen.pack])
    components = [
        formulas.evaluate(p.spec.component_key, p.spec.family, p.spec.formula_id, p.spec.formula_version,
                          p.bindings(), as_of=AS_OF)
        for p in tpl.plan(chosen, variables, attributes, inputs)
    ]
    return tuple(sum((c.at(p).amount for c in components if c.cash), Decimal(0)) for p in POINTS)


def test_a_saas_outage_prices_usage_revenue_only_where_the_set_states_its_usage_margin():
    """Choice 8 (interim): an AI-heavy SaaS platform that bills by usage loses usage
    revenue at its margin while it is down; one that bills by subscription alone states
    no usage margin, and the component is absent -- never zero, never unknown, never a
    refusal -- and the outage is priced as before."""
    saas = PACKS["mythos.economics.saas-pack/v1"]
    outage = saas.catalogue[("saas_platform_outage", 1)]
    _, inputs, _ = world(saas)
    without = {k: v for k, v in inputs.items() if k != "usage_margin_per_hour"}
    assert _gross(outage, inputs) == tuple(Decimal(x) for x in KNOWN_GROSS["saas_platform_outage"])
    assert _gross(outage, without) == tuple(Decimal(x) for x in OUTAGE_WITHOUT_USAGE)
    variables, _, attributes = world(saas)
    keys = [p.spec.component_key for p in tpl.plan(outage, variables, attributes, without)]
    assert "usage-revenue" not in keys and keys == [c.component_key for c in outage.components
                                                    if not outage.is_optional(c)]
    usage = next(c for c in outage.components if c.component_key == "usage-revenue")
    assert usage.family == "business_interruption" and outage.optional_components == {"usage-revenue"}
    served = {c["component_key"]: c for c in outage.as_dict()["components"]}
    assert served["usage-revenue"]["optional"] is True and "optional" not in served["sla-credits"]
    assert closed_form_components(outage)["usage-revenue"] == (Decimal(2000), Decimal(12000), Decimal(72000))
    saas.check_template_inputs(outage, without)  # never required
    assert saas.required_by["usage_margin_per_hour"] == ()


def test_the_saas_api_abuse_cap_is_a_named_input_the_customer_states():
    """F7: the most abuse can add to the platform's spend per hour is a named input of the
    SaaS schema, stated with its source and documented in the spec, never a constant:
    the abuse reads a share of it, so a denial of wallet many times the baseline spend
    is stated as such (here a cap ten times a 400-an-hour baseline)."""
    saas = PACKS["mythos.economics.saas-pack/v1"]
    cap = saas.inputs["abuse_spend_cap_per_hour"]
    assert cap.unit is Unit.MONEY_PER_HOUR and cap.special_data == "cloud spend" and "API-abuse cap" in cap.meaning
    assert "cloud_spend_per_hour" not in saas.inputs
    abuse = saas.catalogue[("saas_api_abuse", 1)]
    compute = next(c for c in abuse.components if c.component_key == "abuse-compute")
    assert compute.sources["spend_per_hour"] == tpl.I("abuse_spend_cap_per_hour")
    assert saas.required_by["abuse_spend_cap_per_hour"] == ("saas_api_abuse",)
    assert closed_form("share_of_spend", {"hours": Decimal(12), "spend_per_hour": Decimal(4000),
                                          "added_share": Decimal(1)}) == Decimal(48000)
    text = _spec_text()
    limits = text[text.index("### 37.12"):text.index("### Choices for the owner (E7)")]
    assert "`abuse_spend_cap_per_hour`" in limits and "the API-abuse cap" in limits


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
            pack_document(pack, pack_inputs={**pack_document(pack)["pack_inputs"], "fleet_size": _entry("count", "9")}),
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
        insurance.check_template_inputs(insurance.templates[0], {})
    assert refused.value.code == "pack_input_missing"
    assert not hasattr(insurance, "check_inputs")  # nothing is required but what a build reads (choice 2)
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


def _words(name: str) -> set[str]:
    """``name``'s words, split at camelCase humps and at any character not a letter --
    written here apart from the pack code's own splitter."""
    spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])", "_", name)
    return {w for w in re.split(r"[^a-z]+", spaced.lower()) if w}


def _keyed(name: str) -> bool:
    return bool(_words(name) & REGION_OR_SIZE)


def test_a_place_or_size_word_is_read_in_every_spelling():
    for name in ("small_tenant_penalty", "smallTenantPenalty", "SMBUplift", "regionWeight", "EU-surcharge",
                 "tier2_multiplier", "size.factor"):
        assert _keyed(name), name
    for name in ("tenant_count", "abuseSpendCap", "policy_count", "smallpox"):
        assert not _keyed(name), name


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
    assert {f.name for f in dataclasses.fields(tpl.Source)} == {"kind", "name"}


#: The formulas the packs add (spec, section 37.7). Their blocks in ``formulas.py`` and
#: ``twins.py`` -- and everything those blocks reach by name in the module -- are read
#: with the pack modules' rules (F8): a hidden constant there would pass the known
#: answers, which its twin and its fixture would be written to match.
PACK_FORMULAS = frozenset(
    {"throughput_loss", "share_of_units", "share_of_units_value", "excess_over_expected", "per_unit_response",
     "churned_share_margin", "share_of_spend"}
)
#: The only figures a pack formula may hold: one (a complement, an empty product) and
#: the hours in a day (a per-day count read per hour), each a unit, never a weight.
_UNIT_FIGURES = frozenset({1, 24})
_NOT_FOLLOWED = frozenset({"Formula", "Twin", "Input"})


def _pack_formula_blocks(module: str) -> tuple[set[str], list[ast.AST]]:
    """The pack formulas ``module`` holds a ``Formula(...)`` or ``Twin(...)`` of, and
    every node to read: those calls and each module-level function or constant they
    reach by name, followed to the end."""
    tree = ast.parse((ENGINE / module).read_text(encoding="utf-8"))
    top: dict[str, ast.AST] = {}
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
            top[node.name] = node
        elif isinstance(node, ast.Assign):
            top.update({t.id: node for t in node.targets if isinstance(t, ast.Name)})
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            top[node.target.id] = node
    blocks = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) in {"Formula", "Twin"}
        and node.args and isinstance(node.args[0], ast.Constant) and node.args[0].value in PACK_FORMULAS
    ]
    reached: list[ast.AST] = []
    queue, seen = list(blocks), set()
    while queue:
        node = queue.pop()
        if id(node) in seen:
            continue
        seen.add(id(node))
        reached.append(node)
        queue.extend(top[n.id] for n in ast.walk(node)
                     if isinstance(n, ast.Name) and n.id in top and n.id not in _NOT_FOLLOWED)
    return {b.args[0].value for b in blocks}, reached


@pytest.mark.parametrize("module", ("formulas.py", "twins.py"))
def test_the_pack_formulas_hold_no_figure_and_no_place_or_size_weight(module):
    """F8: every formula the packs add, and its twin, read off its module's source with
    the pack modules' rules -- no figure but a unit (one, the hours in a day), no
    Decimal, Money or Fraction made but of one, no name of a place or a size -- along
    with every helper and constant they reach."""
    found, reached = _pack_formula_blocks(module)
    assert found == PACK_FORMULAS, (module, sorted(PACK_FORMULAS - found))
    inputs = _inputs_of_every_pack()
    for block in reached:
        for node in ast.walk(block):
            if isinstance(node, ast.Constant):
                value = node.value
                if type(value) is float:
                    assert value in _UNIT_FIGURES, (module, value)
                if type(value) is int:
                    assert 0 <= value <= 9 or value in _UNIT_FIGURES, (module, value)
                if isinstance(value, str):
                    assert not re.fullmatch(r"-?[0-9]+(\.[0-9]+)?", value.strip()), (module, value)
                    if _IDENTIFIER.fullmatch(value) and _keyed(value):
                        assert value in inputs, (module, value)
            if isinstance(node, ast.Call):
                called = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                if called == "Decimal":
                    (argument,) = node.args
                    assert isinstance(argument, ast.Constant) and type(argument.value) is int, (module, called)
                    assert argument.value in _UNIT_FIGURES, (module, argument.value)
                else:
                    assert called not in {"Money", "Fraction", "float"}, (module, called)
            for name in _names(node):
                assert not _keyed(name), (module, name)


#: Every name a pack uses -- an effect type, a process, an attribute, an input, a
#: template id, a component key, a source's name -- reviewed as naming no place and no
#: size (the owner's section 27). Choice 5, tightened: the place-and-size word list is
#: a deny-list; this is the allow-list beside it, so a name neither catches fails until
#: it is reviewed and added here.
REVIEWED_NAMES = frozenset(
    {
        "abuse-compute", "abuse-mitigation", "abuse_hours", "abuse_load_share", "abuse_spend_cap_per_hour",
        "access-investigation", "affected_batches", "affected_people", "affected_tenant_share",
        "agent_tool_misused", "agent_tools", "altered_record_share", "api_abused", "approval_bypassed",
        "average_annual_premium", "batch-loss", "batch_value", "billing", "breach-response",
        "breach_cost_per_record", "breach_credit_per_tenant", "care-disruption", "care_disruption_cost_per_hour",
        "churn_rate", "churn_recovery_years", "claim_overpaid", "claim_wrongly_denied", "claimant-restitution",
        "claims", "claims-backlog", "claims-rework", "claims_per_day", "clinical-review", "clinical_care",
        "clinical_review_cost", "clinical_workflow_interrupted", "complaint-handling", "compliance-review",
        "compromised_share", "contact_rate", "contract_sla_credit_cap", "contract_sla_credit_per_hour",
        "control-recovery", "correction_cost_per_record", "counsel_hours", "customer_service", "data_exfiltrated",
        "data_platform", "deviation-investigation", "disruption_hours", "engineering_hourly_rate", "excess-claims",
        "excess_claims_share", "exploitable_window_hours", "exposed_policy_share", "exposed_record_share",
        "external_counsel_hourly_rate", "failover-recovery", "forensics", "forensics_fixed_cost", "gmp_deviation",
        "handling_hours", "healthcare_clinical_workflow_interruption", "healthcare_gmp_deviation",
        "healthcare_phi_exposure", "healthcare_record_access_misuse", "healthcare_research_ip_loss",
        "incident-response", "incident_response_cost", "insurance_agent_approval_bypass",
        "insurance_claims_overpayment", "insurance_policyholder_data_exposure",
        "insurance_pricing_underwriting_error", "insurance_provider_outage", "insurance_wrongful_denial",
        "interest_and_penalty_per_claim", "interruption", "investigation_hours", "legal", "legal_retainer",
        "loss_per_event", "loss_ratio", "manual_claim_handling_cost", "manual_handling_share",
        "manufacturing_quality", "margin_per_hour", "margin_per_policy_per_year", "market-conduct-response",
        "mispriced_policy_share", "notification", "notification-campaign", "notification_cost_per_tenant",
        "notification_fixed_cost", "notification_unit_cost", "operations", "outage_hours", "overpaid-claims",
        "overpaid_claim_rate", "overpayment_per_claim", "patient_record_count", "patient_records", "phi_disclosure",
        "platform_outage", "policy_count", "policy_servicing", "policyholder-loss", "policyholder_data_disclosure",
        "premium-shortfall", "premium_shortfall_share", "pricing", "pricing_underwriting_error", "provider_outage",
        "public_api", "quarantine_fixed_cost", "record-correction", "record_access_unauthorised",
        "recovery_fixed_cost", "recovery_hours", "recovery_rate", "recurring_margin_per_tenant", "regulatory",
        "regulatory-response", "regulatory_jurisdiction_count", "regulatory_response_cost",
        "regulatory_response_per_regulator", "repeat_count", "repricing-rework", "research", "research-asset-loss",
        "research_asset_value", "research_data_compromised", "rework_cost", "saas_agent_tool_misuse",
        "saas_api_abuse", "saas_data_exfiltration", "saas_platform_outage", "saas_tenant_isolation_breach",
        "scheduling", "security_responder_hourly_rate", "sla-credits", "support", "support_agent_hourly_rate",
        "tenant-churn", "tenant-credits", "tenant-notification", "tenant_count", "tenant_isolation_breach",
        "tenant_platform", "unauthorized-effect", "underwriting", "usage-revenue", "usage_margin_per_hour",
        "workflow-recovery", "wrongly_accepted_policy_share", "wrongly_denied_claims",
    }
)


def _used_names() -> set[str]:
    used: set[str] = set()
    for pack in VERTICAL:
        used |= {*pack.attributes, *pack.effect_types, *pack.business_processes, *pack.inputs}
        for chosen in pack.templates:
            used.add(chosen.template_id)
            for spec in chosen.components:
                used.add(spec.component_key)
                used |= {source.name for source in spec.sources.values()}
    return used


def test_every_name_a_pack_uses_is_on_the_reviewed_allow_list():
    used = _used_names()
    assert not used - REVIEWED_NAMES, f"review and add: {sorted(used - REVIEWED_NAMES)}"
    assert not REVIEWED_NAMES - used, f"no longer used: {sorted(REVIEWED_NAMES - used)}"
    assert not [n for n in REVIEWED_NAMES if _keyed(n) and n not in _inputs_of_every_pack()]


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


#: Harm to a person in the spellings the guard first missed (F4): every one refused.
HARM_SPELLINGS = (
    "loss_of_life", "lives_lost", "killed_count", "wounded", "illness_cost", "disability_claims",
    "adverse_event_cost", "patient_outcome_cost", "pain_and_suffering", "patient_safety_cost",
    "public_safety_cost", "PassengerInjured", "patientSafetyCost", "LossOfLife", "VSLCost", "qaly2",
    "worker-safety:incidents", "value.of.a.life", "humanLivesLost", "lethal_dose_events",
)
#: Names that hold no harm, some sharing letters or a word with one: never refused. A
#: manufacturer's safety system is a control, so "safety" alone is not harm.
NOT_HARM = (
    "pharmacy", "harmonised", "deadline", "claims", "fleet_size", "wrongly_denied_claims", "safety_system_bypassed",
    "safety_recertification_cost", "life_sciences", "lifetime_value", "outcome_review", "adverse_selection",
    "public_api", "patient_records", "killswitch", "die_casting_line", "Deadline", "SafetySystem",
)


def test_the_harm_guard_reads_every_spelling():
    """F4: a word or a phrase of harm to a person, in snake_case, kebab-case, dotted,
    camelCase or with digits, is refused wherever it stands in a name; the pack effect
    type, attribute and input checks refuse it with its code."""
    for name in HARM_SPELLINGS:
        assert pack_inputs.names_harm(name), name
    for name in NOT_HARM:
        assert not pack_inputs.names_harm(name), name
    saas = PACKS["mythos.economics.saas-pack/v1"]
    for name in ("patientSafetyCost", "loss_of_life", "adverse_event_cost"):
        with pytest.raises(ParameterRefused) as refused:
            saas.check_effect_type(name)
        assert refused.value.code == "safety_monetisation_refused", name
        with pytest.raises(ParameterRefused) as refused:
            pset.parse_document(pack_document(saas, pack_inputs={name: _entry("money", "1")}))
        assert refused.value.code == "safety_monetisation_refused", name
    assert pack_inputs.words_of("PassengerInjured") == ("passenger", "injured")
    assert pack_inputs.words_of("VSLCost2026") == ("vsl", "cost")


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
        "unit": "count_per_day", "meaning": "claims the claims workflow decides per day",
        "special_data": "claims volume",
        "required_by": ["insurance_claims_overpayment", "insurance_provider_outage"],
    }
    assert insurance["digest"] == PACK_DIGESTS[insurance["pack"]]
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
        key = f"`{spec.component_key}`" + (" (optional)" if chosen.is_optional(spec) else "")
        lines.append(f"| {key} | `{spec.family}` | `{spec.formula_id}` v{spec.formula_version} | {inputs} |")
    lines += ["", "Direction notes:", ""] + [f"- {note}" for note in chosen.direction_notes]
    if chosen.cautions:
        lines += ["", "Caution (`PHYSICAL_WORLD_CAUTION`): " + "; ".join(chosen.cautions) + "."]
    return "\n".join(lines)


def render_schema(pack) -> str:
    lines = ["| Input | Unit | Required at build by | Special data (section 23) | Meaning |", "|---|---|---|---|---|"]
    for name, entry in pack.inputs.items():
        readers = ", ".join(f"`{t}`" for t in pack.required_by[name]) or "none: an optional component's"
        lines.append(f"| `{name}` | `{entry.unit}` | {readers} | {entry.special_data} | {entry.meaning} |")
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
                           "safety_monetisation_refused", "set_pack_changed")),
        "pack_input", "pack_inputs", pack_inputs.PACK_INPUT_PREFIX, "economics-packs", "PHYSICAL_WORLD_CAUTION",
        "HARM_EXCLUDED", "0076_parameter_set_pack", "pack_registry.RELEASED", "pack_digest", "pack_statements",
        "required_by", "pack_inputs.HARM_PHRASES", "abuse_spend_cap_per_hour", "usage_margin_per_hour", "ScenarioBuild.pack_record",
        *(module.removesuffix(".py") for module in PACK_MODULES),
    ]
    missing = sorted({c for c in codes if f"`{c}`" not in text})
    assert not missing, missing
