"""The manufacturing and critical-infrastructure pack: production interruption,
equipment and robotics impact, supply-chain disruption and compromised safety systems
(Economic Exposure E7; the owner's specification, section 23;
``docs/economics/spec-v1.md``, section 37.15).

Its customer inputs are the special data of section 23 -- units an hour (stated per
day: the engine has no per-hour count and converts none), downtime cost, equipment
value, safety response -- each a parameter the customer states with its source. Every
template is of the physical world and carries the physical-world caution; none prices
harm to a person: a safety system compromised is priced by its response, its
recertification and the production it stops, and the harm is excluded.

Pure: no Django, no database.
"""

from __future__ import annotations

from enum import StrEnum

from . import pack_inputs as schemas
from .pack_base import HARM_EXCLUDED, PHYSICAL_WORLD_CAUTION, Pack, attributes, shared
from .parameters import Unit
from .taxonomy import LossFamily
from .templates import A, Attribute, ComponentSpec, I, P, Scope, Template

PACK_ID = "mythos.economics.manufacturing-pack/v1"


class EffectType(StrEnum):
    """What an effect does, for the manufacturing and critical-infrastructure pack."""

    PRODUCTION_INTERRUPTED = "production_interrupted"
    EQUIPMENT_DAMAGED = "equipment_damaged"
    SUPPLY_CHAIN_DISRUPTED = "supply_chain_disrupted"
    SAFETY_SYSTEM_COMPROMISED = "safety_system_compromised"


EFFECT_TYPES = {
    EffectType.PRODUCTION_INTERRUPTED: "a production line or a plant's operation stopped or slowed",
    EffectType.EQUIPMENT_DAMAGED: "an agent's or a controller's action damaged equipment or a robot",
    EffectType.SUPPLY_CHAIN_DISRUPTED: "a supplier, a shipment or a planning system the production depends on failed",
    EffectType.SAFETY_SYSTEM_COMPROMISED: (
        "a safety instrumented system or interlock was bypassed, disabled or tripped by the effect"
    ),
}


class BusinessProcess(StrEnum):
    """The business process an effect touches, for the manufacturing pack."""

    PRODUCTION = "production"
    MAINTENANCE = "maintenance"
    QUALITY = "quality"
    LOGISTICS = "logistics"
    SAFETY_SYSTEMS = "safety_systems"
    IT_OT = "it_ot"


def _attributes() -> dict[str, Attribute]:
    U = Unit
    return attributes(
        *shared("regulatory_response_cost", "recovery_fixed_cost", "recovery_hours").values(),
        Attribute("interruption_hours", U.HOURS, "how long the production is stopped or slowed", observable=True),
        Attribute(
            "affected_line_share",
            U.RATIO,
            "the share of the plant's production the interruption stops",
            observable=True,
        ),
        Attribute(
            "damaged_equipment_share",
            U.RATIO,
            "the share of the customer's production equipment the effect damages",
            observable=True,
        ),
        Attribute(
            "damage_ratio",
            U.RATIO,
            "the share of a damaged unit's value lost: from a repair to its whole replacement",
        ),
        Attribute(
            "shutdown_hours",
            U.HOURS,
            "how long the safety stand-down and recertification stop production",
            observable=True,
        ),
        Attribute("expedite_cost", U.MONEY, "expediting substitute supply, as a range its evidence gives"),
        Attribute(
            "contract_penalty_cost",
            U.MONEY,
            "late-delivery penalties the customer's contracts owe, as a range its evidence gives",
        ),
    )


F = LossFamily
E = EffectType
B = BusinessProcess

_REMEDIATION = (
    "remediation of the finding is a mitigation's price, never a component of this event (spec, section 22, "
    "decision 2)"
)
_THROUGHPUT = (
    "the production lost is the customer's own units a day, over the hours stopped, at the share of production "
    "stopped and its own margin per unit, never its revenue"
)
_NO_HARM = (
    "harm to a person is never priced (safety_monetisation_refused): the template prices the response, the "
    "equipment and the production, and the harm is excluded"
)


def _production(hours: str) -> ComponentSpec:
    return ComponentSpec(
        "production-loss",
        F.BUSINESS_INTERRUPTION,
        "throughput_loss",
        1,
        {
            "units_per_day": I("units_per_day"),
            "hours": A(hours),
            "affected_share": A("affected_line_share"),
            "amount_per_unit": I("margin_per_unit"),
        },
    )


def _templates() -> tuple[Template, ...]:
    idle = ComponentSpec(
        "idle-cost",
        F.PHYSICAL_OPERATIONAL,
        "interruption",
        1,
        {"interruption_hours": A("interruption_hours"), "value_per_hour": I("downtime_cost_per_hour")},
    )
    damage = ComponentSpec(
        "equipment-damage",
        F.PHYSICAL_OPERATIONAL,
        "share_of_units_value",
        1,
        {
            "units": I("equipment_count"),
            "affected_share": A("damaged_equipment_share"),
            "amount_per_unit": I("equipment_value"),
            "value_share": A("damage_ratio"),
        },
    )
    caution = (PHYSICAL_WORLD_CAUTION,)
    return (
        Template(
            "manufacturing_safety_system_compromise",
            1,
            "Safety system compromised",
            1,
            (
                Scope(E.SAFETY_SYSTEM_COMPROMISED),
                # Equipment damaged on the safety systems is the safety system compromised:
                # this template, not manufacturing_equipment_impact (precedence 1 against 2).
                Scope(E.EQUIPMENT_DAMAGED, frozenset({B.SAFETY_SYSTEMS})),
            ),
            (
                ComponentSpec(
                    "safety-response", F.INCIDENT_RESPONSE, "lump_sum", 1, {"amount": I("safety_response_cost")}
                ),
                _production("shutdown_hours"),
                ComponentSpec(
                    "recertification",
                    F.REGULATORY_COMPLIANCE,
                    "lump_sum",
                    1,
                    {"amount": A("regulatory_response_cost")},
                ),
                damage,
            ),
            (
                "the safety response is the customer's own cost of one: shutdown, inspection, recertification",
                "equipment damaged on the safety systems is taken here by precedence, and the damage itself is "
                "priced here as manufacturing_equipment_impact prices it, from the same sources (the lead's "
                "decision on F3): taking the effect drops no physical-operational family that template prices",
                _THROUGHPUT,
                _NO_HARM,
                _REMEDIATION,
            ),
            pack=PACK_ID,
            cautions=caution,
        ),
        Template(
            "manufacturing_equipment_impact",
            1,
            "Equipment / robotics impact",
            2,
            (Scope(E.EQUIPMENT_DAMAGED),),
            (
                damage,
                _production("interruption_hours"),
                idle,
            ),
            (
                "physical damage is its own heavy-tail component, at the customer's own equipment value and the "
                "effect's damage ratio, never folded into the production lost",
                _THROUGHPUT,
                "the idle hours cost the customer's own downtime cost per hour beyond the margin lost",
                _NO_HARM,
            ),
            pack=PACK_ID,
            cautions=caution,
        ),
        Template(
            "manufacturing_production_interruption",
            1,
            "Production interruption",
            3,
            (Scope(E.PRODUCTION_INTERRUPTED),),
            (
                _production("interruption_hours"),
                idle,
                ComponentSpec(
                    "restart-recovery",
                    F.RECOVERY,
                    "fixed_plus_hours",
                    1,
                    {
                        "fixed_cost": A("recovery_fixed_cost"),
                        "hourly_rate": P("engineering_hourly_rate"),
                        "hours": A("recovery_hours"),
                    },
                ),
            ),
            (
                "the hours stopped drive the production lost and the idle cost alike: one parameter, read by both in "
                "the same direction",
                _THROUGHPUT,
                _REMEDIATION,
            ),
            pack=PACK_ID,
            cautions=caution,
        ),
        Template(
            "manufacturing_supply_chain_disruption",
            1,
            "Supply-chain disruption",
            4,
            (Scope(E.SUPPLY_CHAIN_DISRUPTED),),
            (
                _production("interruption_hours"),
                ComponentSpec("expedite", F.RECOVERY, "lump_sum", 1, {"amount": A("expedite_cost")}),
                ComponentSpec("contract-penalties", F.CONTRACTUAL, "lump_sum", 1, {"amount": A("contract_penalty_cost")}),
            ),
            (
                _THROUGHPUT,
                "expediting and the contracts' penalties are lump sums, read as their evidence gives them",
            ),
            pack=PACK_ID,
            cautions=caution,
        ),
    )


PACK = Pack(
    pack_id=PACK_ID,
    vertical="manufacturing",
    name="Manufacturing and critical infrastructure",
    effect_type_codes=EffectType,
    effect_types={t.value: meaning for t, meaning in EFFECT_TYPES.items()},
    business_process_codes=BusinessProcess,
    attributes=_attributes(),
    templates=_templates(),
    inputs=schemas.SCHEMAS[PACK_ID].inputs,
    excluded=(HARM_EXCLUDED,),
)

__all__ = ["PACK", "PACK_ID", "BusinessProcess", "EffectType"]
