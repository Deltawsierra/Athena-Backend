"""The healthcare and life-sciences pack: PHI exposure, clinical workflow
interruption, an agent's access to records, research and IP loss, and GMP-related
operational issues (Economic Exposure E7; the owner's specification, section 23;
``docs/economics/spec-v1.md``, section 37.5).

Its customer inputs are the special data of section 23 -- patients and records, care
disruption, OCR breach data, research value -- each a parameter the customer states
with its source; OCR breach data is a benchmark the customer may state as one, a
prior and never its truth. No template holds a figure, and none prices harm to a
patient: a clinical template prices the work and the disruption, never the harm, and
carries the physical-world caution.

Pure: no Django, no database.
"""

from __future__ import annotations

from enum import StrEnum

from . import pack_inputs as schemas
from .pack_base import HARM_EXCLUDED, PHYSICAL_WORLD_CAUTION, Pack, attributes, shared
from .parameters import Unit
from .taxonomy import LossFamily
from .templates import A, Attribute, ComponentSpec, I, P, Scope, Template

PACK_ID = "mythos.economics.healthcare-pack/v1"


class EffectType(StrEnum):
    """What an effect does, for the healthcare and life-sciences pack."""

    PHI_DISCLOSURE = "phi_disclosure"
    RECORD_ACCESS_UNAUTHORISED = "record_access_unauthorised"
    CLINICAL_WORKFLOW_INTERRUPTED = "clinical_workflow_interrupted"
    RESEARCH_DATA_COMPROMISED = "research_data_compromised"
    GMP_DEVIATION = "gmp_deviation"


EFFECT_TYPES = {
    EffectType.PHI_DISCLOSURE: "protected health information reached someone not entitled to it",
    EffectType.RECORD_ACCESS_UNAUTHORISED: "an agent read or changed patient records beyond its authority",
    EffectType.CLINICAL_WORKFLOW_INTERRUPTED: (
        "a clinical workflow (scheduling, triage, orders, documentation) was interrupted or degraded"
    ),
    EffectType.RESEARCH_DATA_COMPROMISED: "research data, models or IP were exfiltrated, corrupted or lost",
    EffectType.GMP_DEVIATION: (
        "a manufacturing or quality step a GMP process requires was skipped, altered or mis-recorded"
    ),
}


class BusinessProcess(StrEnum):
    """The business process an effect touches, for the healthcare pack."""

    CLINICAL_CARE = "clinical_care"
    PATIENT_RECORDS = "patient_records"
    SCHEDULING = "scheduling"
    RESEARCH = "research"
    MANUFACTURING_QUALITY = "manufacturing_quality"
    BILLING = "billing"


def _attributes() -> dict[str, Attribute]:
    U = Unit
    return attributes(
        *shared(
            "forensics_fixed_cost",
            "investigation_hours",
            "counsel_hours",
            "regulatory_response_cost",
            "recovery_fixed_cost",
            "recovery_hours",
        ).values(),
        Attribute(
            "exposed_record_share",
            U.RATIO,
            "the share of the patient records held that the effect exposed",
            observable=True,
        ),
        Attribute(
            "disruption_hours",
            U.HOURS,
            "how long the clinical workflow is interrupted or degraded",
            observable=True,
        ),
        Attribute(
            "clinical_review_cost",
            U.MONEY,
            "reviewing the clinical decisions made while the workflow was degraded, as a range its evidence gives "
            "(the work of the review, never harm to a patient)",
        ),
        Attribute(
            "altered_record_share",
            U.RATIO,
            "the share of the patient records held that the agent read or changed beyond its authority",
            observable=True,
        ),
        Attribute("correction_cost_per_record", U.MONEY_PER_UNIT, "reviewing and correcting one affected record"),
        Attribute(
            "compromised_share",
            U.RATIO,
            "the share of the research asset's value exfiltrated, corrupted or lost",
        ),
        Attribute("affected_batches", U.COUNT, "manufacturing batches the deviation affects", observable=True),
        Attribute(
            "quarantine_fixed_cost",
            U.MONEY,
            "the fixed part of quarantining and dispositioning the affected batches",
        ),
    )


F = LossFamily
E = EffectType
B = BusinessProcess

_REMEDIATION = (
    "remediation of the finding is a mitigation's price, never a component of this event (spec, section 22, "
    "decision 2)"
)
_REGULATORY = "regulatory response is scenario bounds its evidence grounds, never a predicted penalty"
_NO_HARM = (
    "harm to a patient is never priced (safety_monetisation_refused): the template prices the work and the "
    "disruption, and the harm is excluded"
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
    legal = ComponentSpec(
        "legal",
        F.LEGAL,
        "fixed_plus_hours",
        1,
        {"fixed_cost": P("legal_retainer"), "hourly_rate": P("external_counsel_hourly_rate"), "hours": A("counsel_hours")},
    )
    recovery = {
        "fixed_cost": A("recovery_fixed_cost"),
        "hourly_rate": P("engineering_hourly_rate"),
        "hours": A("recovery_hours"),
    }
    return (
        Template(
            "healthcare_phi_exposure",
            1,
            "PHI exposure",
            1,
            (
                Scope(E.PHI_DISCLOSURE),
                # An agent's unauthorised access on the patient-records process reaches the
                # records themselves: a breach (HIPAA's presumption), this template, not
                # healthcare_record_access_misuse (precedence 1 against 3).
                Scope(E.RECORD_ACCESS_UNAUTHORISED, frozenset({B.PATIENT_RECORDS})),
            ),
            (
                ComponentSpec(
                    "breach-response",
                    F.NOTIFICATION,
                    "share_of_units",
                    1,
                    {
                        "units": I("patient_record_count"),
                        "affected_share": A("exposed_record_share"),
                        "amount_per_unit": I("breach_cost_per_record"),
                    },
                ),
                forensics,
                legal,
                ComponentSpec(
                    "regulatory", F.REGULATORY_COMPLIANCE, "lump_sum", 1, {"amount": A("regulatory_response_cost")}
                ),
            ),
            (
                "the exposed share is of the customer's own patient records, never a benchmark's",
                "breach response per record is the customer's own figure, or OCR breach data it states as an "
                "INDUSTRY_BENCHMARK: a prior, never its truth, and graded as one",
                _REGULATORY,
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "healthcare_clinical_workflow_interruption",
            1,
            "Clinical workflow interruption",
            2,
            (Scope(E.CLINICAL_WORKFLOW_INTERRUPTED),),
            (
                ComponentSpec(
                    "care-disruption",
                    F.BUSINESS_INTERRUPTION,
                    "interruption",
                    1,
                    {"interruption_hours": A("disruption_hours"), "value_per_hour": I("care_disruption_cost_per_hour")},
                ),
                ComponentSpec("workflow-recovery", F.RECOVERY, "fixed_plus_hours", 1, recovery),
                ComponentSpec(
                    "clinical-review", F.INCIDENT_RESPONSE, "lump_sum", 1, {"amount": A("clinical_review_cost")}
                ),
            ),
            (
                "an hour of disruption is read at the customer's own cost of one: diversion, deferred procedures, "
                "overtime",
                _NO_HARM,
                _REMEDIATION,
            ),
            pack=PACK_ID,
            cautions=(PHYSICAL_WORLD_CAUTION,),
        ),
        Template(
            "healthcare_record_access_misuse",
            1,
            "Agent access to records",
            3,
            (Scope(E.RECORD_ACCESS_UNAUTHORISED),),
            (
                ComponentSpec(
                    "record-correction",
                    F.RECOVERY,
                    "share_of_units",
                    1,
                    {
                        "units": I("patient_record_count"),
                        "affected_share": A("altered_record_share"),
                        "amount_per_unit": A("correction_cost_per_record"),
                    },
                ),
                ComponentSpec(
                    "access-investigation",
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
                    "compliance-review",
                    F.REGULATORY_COMPLIANCE,
                    "lump_sum",
                    1,
                    {"amount": A("regulatory_response_cost")},
                ),
            ),
            (
                "the affected share is of the customer's own patient records; each affected record is reviewed and, "
                "where changed, corrected",
                _REGULATORY,
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "healthcare_research_ip_loss",
            1,
            "Research / IP loss",
            4,
            (Scope(E.RESEARCH_DATA_COMPROMISED),),
            (
                ComponentSpec(
                    "research-asset-loss",
                    F.DATA_AND_IP,
                    "replacement_share",
                    1,
                    {"replacement_cost": I("research_asset_value"), "share_compromised": A("compromised_share")},
                ),
                forensics,
                legal,
            ),
            (
                "the research asset is the customer's own valuation of what replacing it would cost, never a market "
                "value",
                _REMEDIATION,
            ),
            pack=PACK_ID,
        ),
        Template(
            "healthcare_gmp_deviation",
            1,
            "GMP-related operational issue",
            5,
            (Scope(E.GMP_DEVIATION),),
            (
                ComponentSpec(
                    "batch-loss",
                    F.PHYSICAL_OPERATIONAL,
                    "per_affected_plus_fixed",
                    1,
                    {
                        "affected": A("affected_batches"),
                        "unit_cost": I("batch_value"),
                        "fixed_cost": A("quarantine_fixed_cost"),
                    },
                ),
                ComponentSpec("deviation-investigation", F.RECOVERY, "fixed_plus_hours", 1, recovery),
                ComponentSpec(
                    "regulatory-response",
                    F.REGULATORY_COMPLIANCE,
                    "lump_sum",
                    1,
                    {"amount": A("regulatory_response_cost")},
                ),
            ),
            (
                "an affected batch is read at the customer's own batch value: lost whole, never part-recovered here",
                _NO_HARM,
                _REGULATORY,
                _REMEDIATION,
            ),
            pack=PACK_ID,
            cautions=(PHYSICAL_WORLD_CAUTION,),
        ),
    )


PACK = Pack(
    pack_id=PACK_ID,
    vertical="healthcare",
    name="Healthcare and life sciences",
    effect_type_codes=EffectType,
    effect_types={t.value: meaning for t, meaning in EFFECT_TYPES.items()},
    business_process_codes=BusinessProcess,
    attributes=_attributes(),
    templates=_templates(),
    inputs=schemas.SCHEMAS[PACK_ID].inputs,
    excluded=(HARM_EXCLUDED,),
)

__all__ = ["PACK", "PACK_ID", "BusinessProcess", "EffectType"]
