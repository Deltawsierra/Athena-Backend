"""The Hermes and mobility pack: fleet downtime, route disruption, vehicle and asset
damage, and rider-service interruption, with the incident investigation each owes
(Economic Exposure E7; the owner's specification, sections 23 and 32;
``docs/economics/spec-v1.md``, section 37.16).

Its customer inputs are the special data of section 23 -- fleet size, trips a day,
revenue per trip (read as contribution margin: revenue lost is not all loss), asset
cost and the recall variables -- each a parameter the customer states with its source.
``mobility_fleet_downtime`` is the owner's worked example C (section 32): a fleet's
lost trips at the affected share, the field recovery per affected vehicle and the
operations response, with physical damage a separate heavy-tail template of its own.

Every template is of the physical world and carries the physical-world caution
(section 37 of the owner's specification: Hermes evidence shows an effect is
technically plausible, not that it happens at this size). Safety and injury are never
priced: no owner-approved model exists, so a safety variable that prices harm is
refused (``safety_monetisation_refused``) and listed as excluded; a recall's cost --
inspecting, updating and returning a vehicle to service -- is priced.

Pure: no Django, no database.
"""

from __future__ import annotations

from enum import StrEnum

from . import pack_inputs as schemas
from .pack_base import HARM_EXCLUDED, PHYSICAL_WORLD_CAUTION, Pack, attributes, shared
from .parameters import Unit
from .taxonomy import LossFamily
from .templates import A, Attribute, ComponentSpec, I, P, Scope, Template

PACK_ID = "mythos.economics.mobility-pack/v1"


class EffectType(StrEnum):
    """What an effect does, for the Hermes and mobility pack."""

    FLEET_IMMOBILISED = "fleet_immobilised"
    ROUTE_DISRUPTED = "route_disrupted"
    VEHICLE_OR_ASSET_DAMAGED = "vehicle_or_asset_damaged"
    RIDER_SERVICE_INTERRUPTED = "rider_service_interrupted"


EFFECT_TYPES = {
    EffectType.FLEET_IMMOBILISED: "vehicles of the fleet were taken out of service by the effect",
    EffectType.ROUTE_DISRUPTED: "routing or dispatch was degraded: trips delayed, rerouted or cancelled",
    EffectType.VEHICLE_OR_ASSET_DAMAGED: "a vehicle or a fleet asset was physically damaged by the effect",
    EffectType.RIDER_SERVICE_INTERRUPTED: "the booking, dispatch or rider service was unavailable",
}


class BusinessProcess(StrEnum):
    """The business process an effect touches, for the mobility pack."""

    FLEET_OPERATIONS = "fleet_operations"
    DISPATCH = "dispatch"
    ROUTING = "routing"
    VEHICLE_SYSTEMS = "vehicle_systems"
    RIDER_SERVICE = "rider_service"
    MAINTENANCE = "maintenance"


def _attributes() -> dict[str, Attribute]:
    U = Unit
    return attributes(
        *shared(
            "outage_hours", "forensics_fixed_cost", "investigation_hours", "recovery_fixed_cost", "recovery_hours"
        ).values(),
        Attribute(
            "affected_fleet_share",
            U.RATIO,
            "the share of the fleet the effect takes out of service",
            observable=True,
        ),
        Attribute(
            "field_recovery_cost_per_vehicle",
            U.MONEY_PER_UNIT,
            "recovering one affected vehicle in the field: a technician, a tow, a reset",
        ),
        Attribute(
            "operations_response_cost",
            U.MONEY,
            "the operations response and incident investigation, as a range its evidence gives",
        ),
        Attribute(
            "disruption_hours", U.HOURS, "how long routing or dispatch is disrupted", observable=True
        ),
        Attribute(
            "disrupted_trip_share",
            U.RATIO,
            "the share of the trips in the hours disrupted that are delayed, rerouted or cancelled",
            observable=True,
        ),
        Attribute(
            "compensation_per_trip",
            U.MONEY_PER_UNIT,
            "what the customer owes or refunds a rider for one disrupted trip under its terms",
        ),
        Attribute(
            "damaged_fleet_share",
            U.RATIO,
            "the share of the fleet the effect physically damages",
            observable=True,
        ),
        Attribute(
            "damage_ratio",
            U.RATIO,
            "the share of a damaged vehicle's value lost: from a repair to its whole replacement",
        ),
        Attribute("recall_share", U.RATIO, "the share of the fleet the effect puts under recall"),
    )


F = LossFamily
E = EffectType
B = BusinessProcess

_TRIPS = (
    "the trips lost are the customer's own trips a day, over the hours, at the share reached and its own "
    "contribution margin per trip, never its revenue (the specification's worked example C)"
)
_NO_HARM = (
    "safety and injury are never priced (safety_monetisation_refused): only if the scenario's evidence supports a "
    "safety or legal component, and an owner-approved model exists, could it be; it is excluded and listed as such "
    "(specification, section 32)"
)


def _templates() -> tuple[Template, ...]:
    operations = ComponentSpec(
        "operations-response", F.INCIDENT_RESPONSE, "lump_sum", 1, {"amount": A("operations_response_cost")}
    )
    caution = (PHYSICAL_WORLD_CAUTION,)
    return (
        Template(
            "mobility_vehicle_asset_damage",
            1,
            "Vehicle / asset damage",
            1,
            (Scope(E.VEHICLE_OR_ASSET_DAMAGED),),
            (
                ComponentSpec(
                    "asset-damage",
                    F.PHYSICAL_OPERATIONAL,
                    "share_of_units_value",
                    1,
                    {
                        "units": I("fleet_size"),
                        "affected_share": A("damaged_fleet_share"),
                        "amount_per_unit": I("vehicle_asset_cost"),
                        "value_share": A("damage_ratio"),
                    },
                ),
                ComponentSpec(
                    "incident-investigation",
                    F.INCIDENT_RESPONSE,
                    "fixed_plus_hours",
                    1,
                    {
                        "fixed_cost": A("forensics_fixed_cost"),
                        "hourly_rate": P("security_responder_hourly_rate"),
                        "hours": A("investigation_hours"),
                    },
                ),
                ComponentSpec(
                    "recall",
                    F.RECOVERY,
                    "share_of_units",
                    1,
                    {
                        "units": I("fleet_size"),
                        "affected_share": A("recall_share"),
                        "amount_per_unit": I("recall_cost_per_vehicle"),
                    },
                ),
            ),
            (
                "physical damage is a separate heavy-tail template of its own, never folded into the fleet's downtime "
                "(specification, section 32): conditional on the damage the evidence supports",
                "a damaged vehicle loses the damage ratio of the customer's own asset cost",
                "a recall is priced at the customer's own cost of recalling one vehicle",
                _NO_HARM,
            ),
            pack=PACK_ID,
            cautions=caution,
        ),
        Template(
            "mobility_fleet_downtime",
            1,
            "Fleet downtime",
            2,
            (
                Scope(E.FLEET_IMMOBILISED),
                # Dispatch unavailable idles the fleet: this template, not
                # mobility_service_interruption (precedence 2 against 4).
                Scope(E.RIDER_SERVICE_INTERRUPTED, frozenset({B.DISPATCH})),
            ),
            (
                ComponentSpec(
                    "lost-trips",
                    F.BUSINESS_INTERRUPTION,
                    "throughput_loss",
                    1,
                    {
                        "units_per_day": I("trips_per_day"),
                        "hours": A("outage_hours"),
                        "affected_share": A("affected_fleet_share"),
                        "amount_per_unit": I("contribution_margin_per_trip"),
                    },
                ),
                ComponentSpec(
                    "field-recovery",
                    F.RECOVERY,
                    "share_of_units",
                    1,
                    {
                        "units": I("fleet_size"),
                        "affected_share": A("affected_fleet_share"),
                        "amount_per_unit": A("field_recovery_cost_per_vehicle"),
                    },
                ),
                operations,
            ),
            (
                "the affected share of the fleet drives the trips lost and the field recovery alike: one parameter, "
                "read by both in the same direction",
                _TRIPS,
                "physical damage is not here: it is mobility_vehicle_asset_damage, a separate heavy-tail template",
                _NO_HARM,
            ),
            pack=PACK_ID,
            cautions=caution,
        ),
        Template(
            "mobility_route_disruption",
            1,
            "Route disruption",
            3,
            (Scope(E.ROUTE_DISRUPTED),),
            (
                ComponentSpec(
                    "lost-trips",
                    F.BUSINESS_INTERRUPTION,
                    "throughput_loss",
                    1,
                    {
                        "units_per_day": I("trips_per_day"),
                        "hours": A("disruption_hours"),
                        "affected_share": A("disrupted_trip_share"),
                        "amount_per_unit": I("contribution_margin_per_trip"),
                    },
                ),
                ComponentSpec(
                    "rider-compensation",
                    F.CUSTOMER_RESTITUTION,
                    "throughput_loss",
                    1,
                    {
                        "units_per_day": I("trips_per_day"),
                        "hours": A("disruption_hours"),
                        "affected_share": A("disrupted_trip_share"),
                        "amount_per_unit": A("compensation_per_trip"),
                    },
                ),
                operations,
            ),
            (
                "the disrupted share of the trips drives the margin lost and the riders' compensation alike",
                _TRIPS,
                _NO_HARM,
            ),
            pack=PACK_ID,
            cautions=caution,
        ),
        Template(
            "mobility_service_interruption",
            1,
            "Rider-service interruption",
            4,
            (Scope(E.RIDER_SERVICE_INTERRUPTED),),
            (
                ComponentSpec(
                    "lost-trips",
                    F.BUSINESS_INTERRUPTION,
                    "throughput_loss",
                    1,
                    {
                        "units_per_day": I("trips_per_day"),
                        "hours": A("outage_hours"),
                        "affected_share": A("disrupted_trip_share"),
                        "amount_per_unit": I("contribution_margin_per_trip"),
                    },
                ),
                ComponentSpec(
                    "failover-recovery",
                    F.RECOVERY,
                    "fixed_plus_hours",
                    1,
                    {
                        "fixed_cost": A("recovery_fixed_cost"),
                        "hourly_rate": P("engineering_hourly_rate"),
                        "hours": A("recovery_hours"),
                    },
                ),
                ComponentSpec(
                    "rider-compensation",
                    F.CUSTOMER_RESTITUTION,
                    "throughput_loss",
                    1,
                    {
                        "units_per_day": I("trips_per_day"),
                        "hours": A("outage_hours"),
                        "affected_share": A("disrupted_trip_share"),
                        "amount_per_unit": A("compensation_per_trip"),
                    },
                ),
            ),
            (
                "the outage's length drives the trips lost and the riders' compensation alike",
                _TRIPS,
                _NO_HARM,
            ),
            pack=PACK_ID,
            cautions=caution,
        ),
    )


PACK = Pack(
    pack_id=PACK_ID,
    vertical="mobility",
    name="Hermes and mobility",
    effect_type_codes=EffectType,
    effect_types={t.value: meaning for t, meaning in EFFECT_TYPES.items()},
    business_process_codes=BusinessProcess,
    attributes=_attributes(),
    templates=_templates(),
    inputs=schemas.SCHEMAS[PACK_ID].inputs,
    excluded=(HARM_EXCLUDED,),
)

__all__ = ["PACK", "PACK_ID", "BusinessProcess", "EffectType"]
