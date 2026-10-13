"""The insurance pack: claims-agent overpayment and wrongful denial, policyholder
data exposure, pricing and underwriting errors, a third-party model outage and an
agent's unapproved action (Economic Exposure E7; the owner's specification, section
23; ``docs/economics/spec-v1.md``, section 37.4).

Its customer inputs are the special data of section 23 -- claims volume, policy
count and premium, loss ratio, regulatory jurisdictions
(:data:`.pack_inputs.SCHEMAS`) -- each a parameter the customer states with its
source. No template holds a figure; a geographic figure is read only as the customer's
own count of jurisdictions, never as a weight.

Pure: no Django, no database.
"""

from __future__ import annotations

from enum import StrEnum

from . import pack_inputs as schemas
from .pack_base import HARM_EXCLUDED, Pack, attributes, shared
from .parameters import Unit
from .taxonomy import LossFamily
from .templates import A, Attribute, ComponentSpec, I, P, Scope, Template

PACK_ID = "mythos.economics.insurance-pack/v1"


class EffectType(StrEnum):
    """What an effect does, for the insurance pack."""

    CLAIM_OVERPAID = "claim_overpaid"
    CLAIM_WRONGLY_DENIED = "claim_wrongly_denied"
    POLICYHOLDER_DATA_DISCLOSURE = "policyholder_data_disclosure"
    PRICING_UNDERWRITING_ERROR = "pricing_underwriting_error"
    PROVIDER_OUTAGE = "provider_outage"
    APPROVAL_BYPASSED = "approval_bypassed"


EFFECT_TYPES = {
    EffectType.CLAIM_OVERPAID: "an agent approved or paid claims above what the policies owe",
    EffectType.CLAIM_WRONGLY_DENIED: "an agent denied or under-paid claims the policies cover",
    EffectType.POLICYHOLDER_DATA_DISCLOSURE: (
        "a policyholder's or claimant's personal data reached someone not entitled to it"
    ),
    EffectType.PRICING_UNDERWRITING_ERROR: (
        "an agent priced, rated or underwrote policies on wrong inputs or wrong logic"
    ),
    EffectType.PROVIDER_OUTAGE: "a third-party model or provider a critical operation depends on was unavailable",
    EffectType.APPROVAL_BYPASSED: "an agent's action took effect without the approval it needed",
}


class BusinessProcess(StrEnum):
    """The business process an effect touches, for the insurance pack."""

    CLAIMS = "claims"
    UNDERWRITING = "underwriting"
    PRICING = "pricing"
    POLICY_SERVICING = "policy_servicing"
    CUSTOMER_SERVICE = "customer_service"
    OPERATIONS = "operations"


def _attributes() -> dict[str, Attribute]:
    U = Unit
    return attributes(
        *shared(
            "exploitable_window_hours",
            "rework_cost",
            "incident_response_cost",
            "contact_rate",
            "handling_hours",
            "counsel_hours",
            "forensics_fixed_cost",
            "investigation_hours",
            "churn_rate",
            "churn_recovery_years",
            "outage_hours",
            "recovery_fixed_cost",
            "recovery_hours",
            "repeat_count",
            "loss_per_event",
        ).values(),
        Attribute(
            "overpaid_claim_rate",
            U.RATIO,
            "the share of the claims decided in the window that were overpaid, as tested",
            observable=True,
        ),
        Attribute("overpayment_per_claim", U.MONEY_PER_UNIT, "the amount overpaid on one affected claim"),
        Attribute(
            "wrongly_denied_claims",
            U.COUNT,
            "claims the agent denied or under-paid that the policies cover",
            observable=True,
        ),
        Attribute(
            "interest_and_penalty_per_claim",
            U.MONEY_PER_UNIT,
            "interest, late-payment penalties and re-handling owed on one wrongly denied claim under the policies' "
            "terms (the claim itself was owed, and is not a loss)",
        ),
        Attribute(
            "regulatory_response_per_regulator",
            U.MONEY_PER_UNIT,
            "answering one regulator, as scenario bounds its evidence grounds (never a predicted penalty)",
        ),
        Attribute(
            "exposed_policy_share",
            U.RATIO,
            "the share of the policies in force whose policyholders' or claimants' data the effect reaches",
            observable=True,
        ),
        Attribute("margin_per_policy_per_year", U.MONEY_PER_UNIT, "recurring margin per policy per year"),
        Attribute(
            "mispriced_policy_share",
            U.RATIO,
            "the share of the policies in force the error priced or rated",
            observable=True,
        ),
        Attribute("premium_shortfall_share", U.RATIO, "the share of the correct premium the error left uncharged"),
        Attribute(
            "wrongly_accepted_policy_share",
            U.RATIO,
            "the share of the policies in force accepted outside the underwriting rules",
            observable=True,
        ),
        Attribute(
            "excess_claims_share",
            U.RATIO,
            "how far the wrongly accepted policies' expected claims exceed the book's, as a share of the book's "
            "(at most as much again)",
        ),
        Attribute(
            "manual_handling_share",
            U.RATIO,
            "the share of the claims arriving during the outage that are handled by hand",
        ),
    )


F = LossFamily
E = EffectType
B = BusinessProcess

_LUMP = (
    "a lump-sum range is read as its evidence gives it, low, base and high (spec, section 22, decision 5)"
)
_REMEDIATION = (
    "remediation of the finding is a mitigation's price, never a component of this event (spec, section 22, "
    "decision 2)"
)
_RECOVERY = "recovery_rate decreases the loss: the LOW result reads the HIGHEST recovery, the HIGH the lowest"
_REGULATORS = (
    "a regulator's response is scenario bounds its evidence grounds, never a predicted penalty, read once per "
    "jurisdiction the customer states it answers in: a count of its own, never a weight by place"
)


def _templates() -> tuple[Template, ...]:
    market_conduct = ComponentSpec(
        "market-conduct-response",
        F.REGULATORY_COMPLIANCE,
        "per_unit_response",
        1,
        {"units": I("regulatory_jurisdiction_count"), "cost_per_unit": A("regulatory_response_per_regulator")},
    )
    legal = ComponentSpec(
        "legal",
        F.LEGAL,
        "fixed_plus_hours",
        1,
        {"fixed_cost": P("legal_retainer"), "hourly_rate": P("external_counsel_hourly_rate"), "hours": A("counsel_hours")},
    )
    recovery = ComponentSpec(
        "control-recovery",
        F.RECOVERY,
        "fixed_plus_hours",
        1,
        {
            "fixed_cost": A("recovery_fixed_cost"),
            "hourly_rate": P("engineering_hourly_rate"),
            "hours": A("recovery_hours"),
        },
    )
    incident = ComponentSpec("incident-response", F.INCIDENT_RESPONSE, "lump_sum", 1, {"amount": A("incident_response_cost")})
    return (
        Template(
            "insurance_claims_overpayment",
            1,
            "Claims-agent overpayment",
            1,
            (
                Scope(E.CLAIM_OVERPAID),
                # An approval bypassed on the claims process pays a claim: this template,
                # not insurance_agent_approval_bypass, takes it (precedence 1 against 6).
                Scope(E.APPROVAL_BYPASSED, frozenset({B.CLAIMS})),
            ),
            (
                ComponentSpec(
                    "overpaid-claims",
                    F.DIRECT_FINANCIAL,
                    "repeat_in_window",
                    1,
                    {
                        "transactions_per_day": I("claims_per_day"),
                        "window_hours": A("exploitable_window_hours"),
                        "success_rate": A("overpaid_claim_rate"),
                        "value_per_transaction": A("overpayment_per_claim"),
                        "recovery_rate": P("recovery_rate"),
                    },
                ),
                ComponentSpec("claims-rework", F.RECOVERY, "lump_sum", 1, {"amount": A("rework_cost")}),
                incident,
            ),
            (
                _RECOVERY,
                "the claims decided per day are the customer's own volume, never the test's; the overpaid rate is "
                "the tested share of them, and the amount per claim the effect's own: a claim's full payment is never "
                "read as its overpayment",
                "the exploitable window is the largest uncertainty; a longer window never lowers the loss",
                _LUMP,
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "insurance_wrongful_denial",
            1,
            "Claims-agent wrongful denial",
            2,
            (Scope(E.CLAIM_WRONGLY_DENIED),),
            (
                ComponentSpec(
                    "claimant-restitution",
                    F.CUSTOMER_RESTITUTION,
                    "per_affected",
                    1,
                    {"affected": A("wrongly_denied_claims"), "amount_per_affected": A("interest_and_penalty_per_claim")},
                ),
                ComponentSpec(
                    "complaint-handling",
                    F.NOTIFICATION,
                    "support_contacts",
                    1,
                    {
                        "affected": A("wrongly_denied_claims"),
                        "contact_rate": A("contact_rate"),
                        "handling_hours": A("handling_hours"),
                        "loaded_rate": P("support_agent_hourly_rate"),
                    },
                ),
                legal,
                market_conduct,
            ),
            (
                "the claims wrongly denied drive restitution and complaint handling alike: one parameter, read by "
                "both in the same direction",
                "a wrongly denied claim was owed: paying it is not a loss; the loss is the interest, the penalties "
                "and the re-handling its delay costs",
                _REGULATORS,
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "insurance_policyholder_data_exposure",
            1,
            "Policyholder PII leakage",
            3,
            (Scope(E.POLICYHOLDER_DATA_DISCLOSURE),),
            (
                ComponentSpec(
                    "notification",
                    F.NOTIFICATION,
                    "share_of_units",
                    1,
                    {
                        "units": I("policy_count"),
                        "affected_share": A("exposed_policy_share"),
                        "amount_per_unit": P("notification_unit_cost"),
                    },
                ),
                ComponentSpec(
                    "notification-campaign", F.NOTIFICATION, "lump_sum", 1, {"amount": P("notification_fixed_cost")}
                ),
                ComponentSpec(
                    "forensics",
                    F.INCIDENT_RESPONSE,
                    "fixed_plus_hours",
                    1,
                    {
                        "fixed_cost": A("forensics_fixed_cost"),
                        "hourly_rate": P("security_responder_hourly_rate"),
                        "hours": A("investigation_hours"),
                    },
                ),
                legal,
                ComponentSpec(
                    "regulatory",
                    F.REGULATORY_COMPLIANCE,
                    "per_unit_response",
                    1,
                    {"units": I("regulatory_jurisdiction_count"), "cost_per_unit": A("regulatory_response_per_regulator")},
                ),
                ComponentSpec(
                    "policyholder-loss",
                    F.CUSTOMER_LOSS,
                    "churned_share_margin",
                    1,
                    {
                        "units": I("policy_count"),
                        "affected_share": A("exposed_policy_share"),
                        "churn_rate": A("churn_rate"),
                        "margin_per_unit_per_year": A("margin_per_policy_per_year"),
                        "recovery_years": A("churn_recovery_years"),
                    },
                ),
            ),
            (
                "the exposed share of the customer's own policies in force drives notification and policyholder "
                "loss alike: one parameter, read by both in the same direction",
                "policyholder loss is computed only from the customer's own churn figure (CUSTOMER_PROVIDED); any "
                "other source makes it unknown (specification, section 31)",
                _REGULATORS,
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "insurance_pricing_underwriting_error",
            1,
            "Pricing / underwriting error",
            4,
            (
                Scope(E.PRICING_UNDERWRITING_ERROR),
                # An approval bypassed on underwriting or pricing writes or prices a policy:
                # this template, not insurance_agent_approval_bypass, takes it.
                Scope(E.APPROVAL_BYPASSED, frozenset({B.UNDERWRITING, B.PRICING})),
            ),
            (
                ComponentSpec(
                    "premium-shortfall",
                    F.DIRECT_FINANCIAL,
                    "share_of_units_value",
                    1,
                    {
                        "units": I("policy_count"),
                        "affected_share": A("mispriced_policy_share"),
                        "amount_per_unit": I("average_annual_premium"),
                        "value_share": A("premium_shortfall_share"),
                    },
                ),
                ComponentSpec(
                    "excess-claims",
                    F.DIRECT_FINANCIAL,
                    "excess_over_expected",
                    1,
                    {
                        "units": I("policy_count"),
                        "affected_share": A("wrongly_accepted_policy_share"),
                        "amount_per_unit": I("average_annual_premium"),
                        "expected_ratio": I("loss_ratio"),
                        "excess_share": A("excess_claims_share"),
                    },
                ),
                ComponentSpec("repricing-rework", F.RECOVERY, "lump_sum", 1, {"amount": A("rework_cost")}),
                market_conduct,
            ),
            (
                "the premium shortfall is the share of the correct premium the error left uncharged on the share of "
                "policies it priced, for one policy year",
                "a policy's expected claims are its premium times the customer's own loss ratio (the loss ratio's "
                "definition); a wrongly accepted policy costs the share by which its risk's claims exceed that, for "
                "one policy year",
                "the shares are of the customer's own policies in force, never a benchmark's book",
                _REGULATORS,
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "insurance_provider_outage",
            1,
            "Third-party model outage",
            5,
            (Scope(E.PROVIDER_OUTAGE),),
            (
                ComponentSpec(
                    "interruption",
                    F.BUSINESS_INTERRUPTION,
                    "interruption",
                    1,
                    {"interruption_hours": A("outage_hours"), "value_per_hour": P("margin_per_hour")},
                ),
                ComponentSpec(
                    "claims-backlog",
                    F.RECOVERY,
                    "throughput_loss",
                    1,
                    {
                        "units_per_day": I("claims_per_day"),
                        "hours": A("outage_hours"),
                        "affected_share": A("manual_handling_share"),
                        "amount_per_unit": I("manual_claim_handling_cost"),
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
            ),
            (
                "the outage's length drives the interruption and the claims backlog alike: one parameter, read by "
                "both in the same direction",
                "the interruption is read at the critical service's MARGIN per hour, not its revenue",
                "the backlog is the claims arriving during the outage that are handled by hand, at the customer's "
                "own cost of handling one by hand",
            ),
            pack=PACK_ID,
        ),
        Template(
            "insurance_agent_approval_bypass",
            1,
            "Agent approval bypass",
            6,
            (Scope(E.APPROVAL_BYPASSED),),
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
                incident,
            ),
            (
                _RECOVERY,
                "the size of one unauthorized effect is the effect's own, stated with its source; the repeat count is "
                "how often it recurs before the approval control is restored",
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
    )


PACK = Pack(
    pack_id=PACK_ID,
    vertical="insurance",
    name="Insurance",
    effect_type_codes=EffectType,
    effect_types={t.value: meaning for t, meaning in EFFECT_TYPES.items()},
    business_process_codes=BusinessProcess,
    attributes=_attributes(),
    templates=_templates(),
    inputs=schemas.SCHEMAS[PACK_ID].inputs,
    excluded=(HARM_EXCLUDED,),
)

__all__ = ["PACK", "PACK_ID", "BusinessProcess", "EffectType"]
