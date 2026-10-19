"""The AI-heavy SaaS pack: tenant isolation, data exfiltration, agent tool misuse,
API abuse and platform outage (Economic Exposure E7; the owner's specification,
section 23; ``docs/economics/spec-v1.md``, section 37.6).

Its customer inputs are the special data of section 23 -- ARR (read as recurring
margin per tenant: revenue lost is not all loss; and, for a platform that bills by
usage, its usage margin per hour), customer count and the multi-tenant architecture
(the tenants), SLA terms and cloud spend (read as the API-abuse cap: the most abuse
can add to the platform's spend per hour) -- each a parameter the customer states
with its source. No template holds a figure, and no cap is a constant.

Pure: no Django, no database.
"""

from __future__ import annotations

from enum import StrEnum

from . import pack_inputs as schemas
from .pack_base import HARM_EXCLUDED, Pack, attributes, shared
from .parameters import Unit
from .taxonomy import LossFamily
from .templates import A, Attribute, ComponentSpec, I, P, Scope, Template

PACK_ID = "mythos.economics.saas-pack/v1"


class EffectType(StrEnum):
    """What an effect does, for the SaaS pack."""

    TENANT_ISOLATION_BREACH = "tenant_isolation_breach"
    DATA_EXFILTRATED = "data_exfiltrated"
    AGENT_TOOL_MISUSED = "agent_tool_misused"
    API_ABUSED = "api_abused"
    PLATFORM_OUTAGE = "platform_outage"


EFFECT_TYPES = {
    EffectType.TENANT_ISOLATION_BREACH: "one tenant's data or actions reached another tenant",
    EffectType.DATA_EXFILTRATED: "data left the platform to someone not entitled to it",
    EffectType.AGENT_TOOL_MISUSED: "an agent called a tool outside its authority, or for a purpose it was not given",
    EffectType.API_ABUSED: (
        "the API was used beyond its limits or its terms: scraping, credential stuffing, resource exhaustion"
    ),
    EffectType.PLATFORM_OUTAGE: "the platform, or a model or provider it depends on, was unavailable",
}


class BusinessProcess(StrEnum):
    """The business process an effect touches, for the SaaS pack."""

    TENANT_PLATFORM = "tenant_platform"
    AGENT_TOOLS = "agent_tools"
    PUBLIC_API = "public_api"
    DATA_PLATFORM = "data_platform"
    BILLING = "billing"
    SUPPORT = "support"


def _attributes() -> dict[str, Attribute]:
    U = Unit
    return attributes(
        *shared(
            "forensics_fixed_cost",
            "investigation_hours",
            "counsel_hours",
            "regulatory_response_cost",
            "churn_rate",
            "churn_recovery_years",
            "outage_hours",
            "recovery_fixed_cost",
            "recovery_hours",
            "repeat_count",
            "loss_per_event",
            "incident_response_cost",
        ).values(),
        Attribute(
            "affected_tenant_share",
            U.RATIO,
            "the share of the tenants the effect reached",
            observable=True,
        ),
        Attribute(
            "notification_cost_per_tenant",
            U.MONEY_PER_UNIT,
            "notifying and handling one affected tenant: the notice, account management, its questions",
        ),
        Attribute(
            "breach_credit_per_tenant",
            U.MONEY_PER_UNIT,
            "the credit or concession one affected tenant is owed under its contract for the breach",
        ),
        Attribute("affected_people", U.COUNT, "people whose data left the platform", observable=True),
        Attribute("abuse_hours", U.HOURS, "how long the abuse lasts before it is stopped", observable=True),
        Attribute(
            "abuse_load_share",
            U.RATIO,
            "the share of the API-abuse cap (abuse_spend_cap_per_hour, a pack input) the abuse used while it lasted",
        ),
    )


F = LossFamily
E = EffectType
B = BusinessProcess

_REMEDIATION = (
    "remediation of the finding is a mitigation's price, never a component of this event (spec, section 22, "
    "decision 2)"
)
_CHURN = (
    "tenant loss is computed only from the customer's own churn figure (CUSTOMER_PROVIDED), at its own recurring "
    "margin per tenant; any other churn source makes it unknown (specification, section 31)"
)
_REGULATORY = "regulatory response is scenario bounds its evidence grounds, never a predicted penalty"


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
    legal = ComponentSpec(
        "legal",
        F.LEGAL,
        "fixed_plus_hours",
        1,
        {"fixed_cost": P("legal_retainer"), "hourly_rate": P("external_counsel_hourly_rate"), "hours": A("counsel_hours")},
    )
    churn = ComponentSpec(
        "tenant-churn",
        F.CUSTOMER_LOSS,
        "churned_share_margin",
        1,
        {
            "units": I("tenant_count"),
            "affected_share": A("affected_tenant_share"),
            "churn_rate": A("churn_rate"),
            "margin_per_unit_per_year": I("recurring_margin_per_tenant"),
            "recovery_years": A("churn_recovery_years"),
        },
    )
    recovery = {
        "fixed_cost": A("recovery_fixed_cost"),
        "hourly_rate": P("engineering_hourly_rate"),
        "hours": A("recovery_hours"),
    }
    incident = ComponentSpec("incident-response", F.INCIDENT_RESPONSE, "lump_sum", 1, {"amount": A("incident_response_cost")})
    regulatory = ComponentSpec(
        "regulatory", F.REGULATORY_COMPLIANCE, "lump_sum", 1, {"amount": A("regulatory_response_cost")}
    )
    return (
        Template(
            "saas_tenant_isolation_breach",
            1,
            "Tenant isolation breach",
            1,
            (
                Scope(E.TENANT_ISOLATION_BREACH),
                # Data taken from the tenant platform reached it through another tenant:
                # an isolation breach, this template, not saas_data_exfiltration
                # (precedence 1 against 2).
                Scope(E.DATA_EXFILTRATED, frozenset({B.TENANT_PLATFORM})),
            ),
            (
                ComponentSpec(
                    "tenant-notification",
                    F.NOTIFICATION,
                    "share_of_units",
                    1,
                    {
                        "units": I("tenant_count"),
                        "affected_share": A("affected_tenant_share"),
                        "amount_per_unit": A("notification_cost_per_tenant"),
                    },
                ),
                ComponentSpec(
                    "tenant-credits",
                    F.CONTRACTUAL,
                    "share_of_units",
                    1,
                    {
                        "units": I("tenant_count"),
                        "affected_share": A("affected_tenant_share"),
                        "amount_per_unit": A("breach_credit_per_tenant"),
                    },
                ),
                forensics,
                legal,
                regulatory,
                churn,
            ),
            (
                "the affected share of the customer's own tenants drives notification, credits and tenant loss "
                "alike: one parameter, read by each in the same direction",
                "a cross-tenant exposure is the owner's worked example B (specification, section 31): legal and "
                "regulatory are priced here as saas_data_exfiltration prices them, so taking the effect by "
                "precedence drops no family that template prices",
                _REGULATORY,
                _CHURN,
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "saas_data_exfiltration",
            1,
            "Data exfiltration",
            2,
            (Scope(E.DATA_EXFILTRATED),),
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
                forensics,
                legal,
                regulatory,
                churn,
            ),
            (
                "the people whose data left drive notification; the tenants it reached drive tenant loss",
                _REGULATORY,
                _CHURN,
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "saas_agent_tool_misuse",
            1,
            "Agent tool misuse",
            3,
            (Scope(E.AGENT_TOOL_MISUSED),),
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
                ComponentSpec("control-recovery", F.RECOVERY, "fixed_plus_hours", 1, recovery),
                incident,
            ),
            (
                "recovery_rate decreases the loss: the LOW result reads the HIGHEST recovery, the HIGH the lowest",
                "the size of one misuse is the effect's own, stated with its source; the repeat count is how often it "
                "recurs before the tool's authority is restored",
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "saas_api_abuse",
            1,
            "API abuse",
            4,
            (Scope(E.API_ABUSED),),
            (
                ComponentSpec(
                    "abuse-compute",
                    F.DIRECT_FINANCIAL,
                    "share_of_spend",
                    1,
                    {
                        "hours": A("abuse_hours"),
                        "spend_per_hour": I("abuse_spend_cap_per_hour"),
                        "added_share": A("abuse_load_share"),
                    },
                ),
                ComponentSpec("abuse-mitigation", F.RECOVERY, "fixed_plus_hours", 1, recovery),
                incident,
            ),
            (
                "the abuse costs the share of the API-abuse cap it used, for as long as it lasts: the cap "
                "(abuse_spend_cap_per_hour) is the customer's stated figure for the most abuse can add to its spend "
                "per hour, never a constant, and may be many times its baseline spend (denial of wallet)",
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "saas_platform_outage",
            1,
            "Platform outage",
            5,
            (Scope(E.PLATFORM_OUTAGE),),
            (
                ComponentSpec(
                    "sla-credits",
                    F.CONTRACTUAL,
                    "capped_credit",
                    1,
                    {
                        "credit_per_hour": I("contract_sla_credit_per_hour"),
                        "breach_hours": A("outage_hours"),
                        "contract_cap": I("contract_sla_credit_cap"),
                    },
                ),
                ComponentSpec("failover-recovery", F.RECOVERY, "fixed_plus_hours", 1, recovery),
                churn,
                ComponentSpec(
                    "usage-revenue",
                    F.BUSINESS_INTERRUPTION,
                    "interruption",
                    1,
                    {"interruption_hours": A("outage_hours"), "value_per_hour": I("usage_margin_per_hour")},
                    optional=True,
                ),
            ),
            (
                "a subscription is paid ahead: an outage's loss is the SLA credits the contracts owe, the recovery "
                "and the tenants who leave, never the subscription revenue of its hours",
                "usage-billed revenue (tokens, API calls, metered seats) is lost while the platform is down: "
                "usage-revenue prices it at the customer's own usage margin per hour, and is made only where the set "
                "states that margin (an optional component, choice 8); a platform that bills by subscription alone "
                "states none, and the component is absent, never zero",
                "SLA credits are capped by the customer's own contracts' cap; a higher cap never lowers the loss",
                _CHURN,
            ),
            pack=PACK_ID,
        ),
    )


PACK = Pack(
    pack_id=PACK_ID,
    vertical="saas",
    name="AI-heavy SaaS",
    effect_type_codes=EffectType,
    effect_types={t.value: meaning for t, meaning in EFFECT_TYPES.items()},
    business_process_codes=BusinessProcess,
    attributes=_attributes(),
    templates=_templates(),
    inputs=schemas.SCHEMAS[PACK_ID].inputs,
    excluded=(HARM_EXCLUDED,),
)

__all__ = ["PACK", "PACK_ID", "BusinessProcess", "EffectType"]
