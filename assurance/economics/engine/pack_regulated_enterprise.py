"""The regulated-enterprise pack: an internal agent's permissions exceeded, document
and data exposure, workflow manipulation and a vendor AI's failure (Economic Exposure
E7; the owner's specification, section 23; ``docs/economics/spec-v1.md``, section
37.13).

Its customer inputs are the special data of section 23 -- business processes (the
margin an affected process yields an hour), control obligations and contracts -- each
a parameter the customer states with its source. No template holds a figure.

Pure: no Django, no database.
"""

from __future__ import annotations

from enum import StrEnum

from . import pack_inputs as schemas
from .pack_base import HARM_EXCLUDED, Pack, attributes, shared
from .parameters import Unit
from .taxonomy import LossFamily
from .templates import A, Attribute, ComponentSpec, I, P, Scope, Template

PACK_ID = "mythos.economics.regulated-enterprise-pack/v1"


class EffectType(StrEnum):
    """What an effect does, for the regulated-enterprise pack."""

    AGENT_PERMISSION_EXCEEDED = "agent_permission_exceeded"
    DOCUMENT_EXPOSURE = "document_exposure"
    WORKFLOW_MANIPULATED = "workflow_manipulated"
    VENDOR_AI_FAILURE = "vendor_ai_failure"


EFFECT_TYPES = {
    EffectType.AGENT_PERMISSION_EXCEEDED: "an internal agent acted beyond the permissions its role grants",
    EffectType.DOCUMENT_EXPOSURE: "documents or data reached someone inside or outside not entitled to them",
    EffectType.WORKFLOW_MANIPULATED: (
        "a business workflow was steered to an outcome its controls forbid: an approval, a payment, a record changed"
    ),
    EffectType.VENDOR_AI_FAILURE: "a vendor's AI service a business process depends on failed or misbehaved",
}


class BusinessProcess(StrEnum):
    """The business process an effect touches, for the regulated-enterprise pack."""

    FINANCE = "finance"
    HR = "hr"
    LEGAL = "legal"
    PROCUREMENT = "procurement"
    OPERATIONS = "operations"
    IT = "it"


def _attributes() -> dict[str, Attribute]:
    U = Unit
    return attributes(
        *shared(
            "forensics_fixed_cost",
            "investigation_hours",
            "counsel_hours",
            "outage_hours",
            "recovery_fixed_cost",
            "repeat_count",
            "loss_per_event",
        ).values(),
        Attribute("affected_people", U.COUNT, "people whose documents or data the effect reached", observable=True),
        Attribute(
            "affected_contract_share",
            U.RATIO,
            "the share of the customer's contracts whose obligations the effect breaches",
            observable=True,
        ),
        Attribute(
            "response_cost_per_contract",
            U.MONEY_PER_UNIT,
            "answering one breached contract's counterparty: the notice, the remedy, the renegotiation",
        ),
        Attribute(
            "affected_obligation_share",
            U.RATIO,
            "the share of the customer's control obligations the effect breaches",
            observable=True,
        ),
        Attribute(
            "compliance_response_per_obligation",
            U.MONEY_PER_UNIT,
            "re-establishing one breached obligation: re-testing, re-attestation, the regulator's or auditor's notice "
            "(never a predicted penalty)",
        ),
        Attribute(
            "interruption_hours", U.HOURS, "how long the business process is interrupted or degraded", observable=True
        ),
        Attribute("vendors_to_replace", U.COUNT, "critical vendors the failure obliges the customer to exit or replace"),
    )


F = LossFamily
E = EffectType
B = BusinessProcess

_REMEDIATION = (
    "remediation of the finding is a mitigation's price, never a component of this event (spec, section 22, "
    "decision 2)"
)
_RECOVERY = "recovery_rate decreases the loss: the LOW result reads the HIGHEST recovery, the HIGH the lowest"
_OBLIGATIONS = (
    "the breached share is of the customer's own control obligations and contracts, each answered at the effect's "
    "stated cost: a count of its own, never a weight by size"
)


def _templates() -> tuple[Template, ...]:
    forensics = ComponentSpec(
        "forensics",
        F.INCIDENT_RESPONSE,
        "fixed_plus_hours",
        1,
        {
            "fixed_cost": A("forensics_fixed_cost"),
            "hourly_rate": P("security_responder_hourly_rate"),
            "hours": A("investigation_hours"),
        },
    )
    contracts = ComponentSpec(
        "contract-obligations",
        F.CONTRACTUAL,
        "share_of_units",
        1,
        {
            "units": I("contract_count"),
            "affected_share": A("affected_contract_share"),
            "amount_per_unit": A("response_cost_per_contract"),
        },
    )
    obligations = ComponentSpec(
        "control-obligations",
        F.REGULATORY_COMPLIANCE,
        "share_of_units",
        1,
        {
            "units": I("control_obligation_count"),
            "affected_share": A("affected_obligation_share"),
            "amount_per_unit": A("compliance_response_per_obligation"),
        },
    )
    unauthorized = ComponentSpec(
        "unauthorized-effect",
        F.DIRECT_FINANCIAL,
        "repeat_loss",
        1,
        {"repeat_count": A("repeat_count"), "loss_per_event": A("loss_per_event"), "recovery_rate": P("recovery_rate")},
    )
    return (
        Template(
            "regulated_enterprise_document_exposure",
            1,
            "Document / data exposure",
            1,
            (
                Scope(E.DOCUMENT_EXPOSURE),
                # An agent beyond its permissions on the legal or HR process reaches their
                # documents: an exposure, this template, not
                # regulated_enterprise_agent_permissions (precedence 1 against 3).
                Scope(E.AGENT_PERMISSION_EXCEEDED, frozenset({B.LEGAL, B.HR})),
            ),
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
                contracts,
                forensics,
                ComponentSpec(
                    "legal",
                    F.LEGAL,
                    "fixed_plus_hours",
                    1,
                    {
                        "fixed_cost": P("legal_retainer"),
                        "hourly_rate": P("external_counsel_hourly_rate"),
                        "hours": A("counsel_hours"),
                    },
                ),
            ),
            (
                "the people reached drive notification; the contracts breached drive the counterparties' remedies",
                _OBLIGATIONS,
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "regulated_enterprise_workflow_manipulation",
            1,
            "Workflow manipulation",
            2,
            (
                Scope(E.WORKFLOW_MANIPULATED),
                # An agent beyond its permissions on finance or procurement moves a
                # workflow's outcome: this template, not regulated_enterprise_agent_permissions.
                Scope(E.AGENT_PERMISSION_EXCEEDED, frozenset({B.FINANCE, B.PROCUREMENT})),
            ),
            (
                unauthorized,
                ComponentSpec(
                    "process-interruption",
                    F.BUSINESS_INTERRUPTION,
                    "interruption",
                    1,
                    {"interruption_hours": A("interruption_hours"), "value_per_hour": I("process_margin_per_hour")},
                ),
                obligations,
            ),
            (
                _RECOVERY,
                "the process is read at the customer's own margin per hour, not its revenue",
                _OBLIGATIONS,
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "regulated_enterprise_agent_permissions",
            1,
            "Internal-agent permissions exceeded",
            3,
            (Scope(E.AGENT_PERMISSION_EXCEEDED),),
            (
                unauthorized,
                ComponentSpec(
                    "access-review",
                    F.INCIDENT_RESPONSE,
                    "fixed_plus_hours",
                    1,
                    {
                        "fixed_cost": A("forensics_fixed_cost"),
                        "hourly_rate": P("security_responder_hourly_rate"),
                        "hours": A("investigation_hours"),
                    },
                ),
                obligations,
            ),
            (
                _RECOVERY,
                "the size of one action beyond the agent's permissions is the effect's own, stated with its source; the "
                "repeat count is how often it recurs before the permission is restored",
                _OBLIGATIONS,
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "regulated_enterprise_vendor_ai_failure",
            1,
            "Vendor AI failure",
            4,
            (Scope(E.VENDOR_AI_FAILURE),),
            (
                ComponentSpec(
                    "process-interruption",
                    F.BUSINESS_INTERRUPTION,
                    "interruption",
                    1,
                    {"interruption_hours": A("outage_hours"), "value_per_hour": I("process_margin_per_hour")},
                ),
                ComponentSpec(
                    "vendor-replacement",
                    F.RECOVERY,
                    "per_affected_plus_fixed",
                    1,
                    {
                        "affected": A("vendors_to_replace"),
                        "unit_cost": P("vendor_exit_cost"),
                        "fixed_cost": A("recovery_fixed_cost"),
                    },
                ),
                contracts,
            ),
            (
                "the vendor's failure is read at the customer's own margin per hour of the process it serves",
                "exiting a vendor is read at the customer's own cost of exiting one (spec, section 19.1)",
                _OBLIGATIONS,
            ),
            pack=PACK_ID,
        ),
    )


PACK = Pack(
    pack_id=PACK_ID,
    vertical="regulated-enterprise",
    name="Regulated enterprise",
    effect_type_codes=EffectType,
    effect_types={t.value: meaning for t, meaning in EFFECT_TYPES.items()},
    business_process_codes=BusinessProcess,
    attributes=_attributes(),
    templates=_templates(),
    inputs=schemas.SCHEMAS[PACK_ID].inputs,
    excluded=(HARM_EXCLUDED,),
)

__all__ = ["PACK", "PACK_ID", "BusinessProcess", "EffectType"]
