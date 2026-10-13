"""The government and mission pack: mission interruption, classified or sensitive
data, a supply-chain compromise and an autonomous agent's unapproved effect (Economic
Exposure E7; the owner's specification, section 23; ``docs/economics/spec-v1.md``,
section 37.14).

Its customer inputs are the special data of section 23 -- mission criticality and
downtime (the agency's own cost of an hour of the mission's interruption),
response/recovery (its staff's rate), public-sector constraints (the oversight bodies
it answers) -- each a parameter the agency states with its source. No template holds a
figure, none prices harm to national security or to a person, and a template whose
effect may be physical carries the physical-world caution.

Pure: no Django, no database.
"""

from __future__ import annotations

from enum import StrEnum

from . import pack_inputs as schemas
from .pack_base import HARM_EXCLUDED, PHYSICAL_WORLD_CAUTION, Pack, attributes, shared
from .parameters import Unit
from .taxonomy import LossFamily
from .templates import A, Attribute, ComponentSpec, I, P, Scope, Template

PACK_ID = "mythos.economics.government-pack/v1"


class EffectType(StrEnum):
    """What an effect does, for the government and mission pack."""

    MISSION_INTERRUPTED = "mission_interrupted"
    SENSITIVE_DATA_DISCLOSURE = "sensitive_data_disclosure"
    SUPPLY_CHAIN_COMPROMISED = "supply_chain_compromised"
    AUTONOMOUS_ACTION_UNAPPROVED = "autonomous_action_unapproved"


EFFECT_TYPES = {
    EffectType.MISSION_INTERRUPTED: "a mission's operation or a public service was interrupted or degraded",
    EffectType.SENSITIVE_DATA_DISCLOSURE: (
        "classified, controlled or personal data reached someone not cleared or entitled to it"
    ),
    EffectType.SUPPLY_CHAIN_COMPROMISED: "a component, model or supplier the mission depends on was compromised",
    EffectType.AUTONOMOUS_ACTION_UNAPPROVED: "an autonomous agent took an action without the approval it needed",
}


class BusinessProcess(StrEnum):
    """The business process an effect touches, for the government and mission pack."""

    MISSION_OPERATIONS = "mission_operations"
    CITIZEN_SERVICES = "citizen_services"
    RECORDS = "records"
    PROCUREMENT = "procurement"
    LOGISTICS = "logistics"


def _attributes() -> dict[str, Attribute]:
    U = Unit
    return attributes(
        *shared(
            "forensics_fixed_cost",
            "investigation_hours",
            "recovery_fixed_cost",
            "recovery_hours",
            "repeat_count",
            "loss_per_event",
        ).values(),
        Attribute("affected_people", U.COUNT, "people whose sensitive data the effect reached", observable=True),
        Attribute(
            "interruption_hours", U.HOURS, "how long the mission or the service is interrupted", observable=True
        ),
        Attribute(
            "reporting_cost_per_body",
            U.MONEY_PER_UNIT,
            "reporting to and answering one oversight body, as scenario bounds its evidence grounds",
        ),
        Attribute(
            "affected_components",
            U.COUNT,
            "components, models or suppliers the compromise obliges the agency to replace",
            observable=True,
        ),
        Attribute(
            "replacement_cost_per_component",
            U.MONEY_PER_UNIT,
            "replacing and re-qualifying one compromised component, model or supplier",
        ),
    )


F = LossFamily
E = EffectType
B = BusinessProcess

_REMEDIATION = (
    "remediation of the finding is a mitigation's price, never a component of this event (spec, section 22, "
    "decision 2)"
)
_OVERSIGHT = (
    "each oversight body the agency states it answers is answered once, at the effect's stated cost: a count of its "
    "own, never a weight by place"
)
_NO_HARM = (
    "harm to national security or to a person is never priced (safety_monetisation_refused): the template prices "
    "the response, the recovery and the interruption, and the harm is excluded"
)


def _templates() -> tuple[Template, ...]:
    oversight = ComponentSpec(
        "oversight-reporting",
        F.REGULATORY_COMPLIANCE,
        "per_unit_response",
        1,
        {"units": I("oversight_body_count"), "cost_per_unit": A("reporting_cost_per_body")},
    )
    recovery = ComponentSpec(
        "mission-recovery",
        F.RECOVERY,
        "fixed_plus_hours",
        1,
        {
            "fixed_cost": A("recovery_fixed_cost"),
            "hourly_rate": I("response_team_hourly_rate"),
            "hours": A("recovery_hours"),
        },
    )
    investigation = {
        "fixed_cost": A("forensics_fixed_cost"),
        "hourly_rate": I("response_team_hourly_rate"),
        "hours": A("investigation_hours"),
    }
    return (
        Template(
            "government_sensitive_data_exposure",
            1,
            "Classified / sensitive data exposure",
            1,
            (Scope(E.SENSITIVE_DATA_DISCLOSURE),),
            (
                ComponentSpec(
                    "notification",
                    F.NOTIFICATION,
                    "per_affected_plus_fixed",
                    1,
                    {
                        "affected": A("affected_people"),
                        "unit_cost": P("notification_unit_cost"),
                        "fixed_cost": P("notification_fixed_cost"),
                    },
                ),
                ComponentSpec("damage-assessment", F.INCIDENT_RESPONSE, "fixed_plus_hours", 1, investigation),
                oversight,
            ),
            (
                "the damage assessment is the agency's own staff's work, at its own loaded rate",
                _OVERSIGHT,
                _NO_HARM,
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "government_mission_interruption",
            1,
            "Mission interruption",
            2,
            (
                Scope(E.MISSION_INTERRUPTED),
                # An autonomous agent's unapproved action on mission operations interrupts
                # the mission: this template, not government_autonomous_agent_effect
                # (precedence 2 against 4).
                Scope(E.AUTONOMOUS_ACTION_UNAPPROVED, frozenset({B.MISSION_OPERATIONS})),
            ),
            (
                ComponentSpec(
                    "mission-interruption",
                    F.BUSINESS_INTERRUPTION,
                    "interruption",
                    1,
                    {"interruption_hours": A("interruption_hours"), "value_per_hour": I("mission_cost_per_hour")},
                ),
                recovery,
                oversight,
            ),
            (
                "an hour of the mission's interruption is read at the agency's own cost of one, stated with its source: "
                "the replacement service, overtime, deferred obligations",
                _OVERSIGHT,
                _NO_HARM,
                _REMEDIATION,
            ),
            pack=PACK_ID,
            cautions=(PHYSICAL_WORLD_CAUTION,),
        ),
        Template(
            "government_supply_chain_compromise",
            1,
            "Supply-chain compromise",
            3,
            (Scope(E.SUPPLY_CHAIN_COMPROMISED),),
            (
                ComponentSpec(
                    "component-replacement",
                    F.RECOVERY,
                    "per_affected_plus_fixed",
                    1,
                    {
                        "affected": A("affected_components"),
                        "unit_cost": A("replacement_cost_per_component"),
                        "fixed_cost": A("recovery_fixed_cost"),
                    },
                ),
                ComponentSpec("investigation", F.INCIDENT_RESPONSE, "fixed_plus_hours", 1, investigation),
                oversight,
            ),
            (
                "each compromised component, model or supplier is replaced and re-qualified at the effect's stated "
                "cost",
                _OVERSIGHT,
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "government_autonomous_agent_effect",
            1,
            "Autonomous agent effect",
            4,
            (Scope(E.AUTONOMOUS_ACTION_UNAPPROVED),),
            (
                ComponentSpec(
                    "unauthorized-effect",
                    F.DIRECT_FINANCIAL,
                    "repeat_loss",
                    1,
                    {
                        "repeat_count": A("repeat_count"),
                        "loss_per_event": A("loss_per_event"),
                        "recovery_rate": P("recovery_rate"),
                    },
                ),
                recovery,
                oversight,
            ),
            (
                "recovery_rate decreases the loss: the LOW result reads the HIGHEST recovery, the HIGH the lowest",
                "the size of one unapproved action is the effect's own, stated with its source",
                _OVERSIGHT,
                _NO_HARM,
            ),
            pack=PACK_ID,
            cautions=(PHYSICAL_WORLD_CAUTION,),
        ),
    )


PACK = Pack(
    pack_id=PACK_ID,
    vertical="government",
    name="Government and mission",
    effect_type_codes=EffectType,
    effect_types={t.value: meaning for t, meaning in EFFECT_TYPES.items()},
    business_process_codes=BusinessProcess,
    attributes=_attributes(),
    templates=_templates(),
    inputs=schemas.SCHEMAS[PACK_ID].inputs,
    excluded=(HARM_EXCLUDED,),
)

__all__ = ["PACK", "PACK_ID", "BusinessProcess", "EffectType"]
