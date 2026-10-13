"""The customer-input schema of each industry pack (Economic Exposure E7;
``docs/economics/spec-v1.md``, section 37).

An industry pack (:mod:`.pack_registry`) prices the effects of one vertical through
its own templates; the figures they read beyond the thirty shared variables of the
parameter set (:data:`.parameter_set.VARIABLES`) are the vertical's SPECIAL DATA,
the owner's specification, section 23: an insurer's claims volume, loss ratio and
policy count, a hospital's patient records and its cost of care disruption, a SaaS
platform's tenants, recurring margin, SLA terms and cloud spend. This module is that
schema, and nothing else: each pack's inputs, each with its unit, meaning and whether
the pack requires it.

A parameter set names the pack it answers (``pack``) and states the pack's inputs
(``pack_inputs``) beside its variables (:func:`.parameter_set.parse_document`). The
rules:

- every input the pack REQUIRES is stated, or the version is refused
  (``pack_input_missing``): a missing input is never defaulted, never read as zero;
- an input the pack does not hold is refused (``pack_input_unrecognised``), and so is
  one in another unit (``unit_mismatch``);
- an OPTIONAL input is needed only by the templates that read it: a build whose
  effects are assigned to such a template, on a set that does not state the input, is
  refused (``pack_input_missing``), never defaulted;
- nothing that prices harm to a person -- an injury, a death, a patient's or the
  public's safety -- is an input, an attribute or an effect type of any pack: naming
  one is refused (``safety_monetisation_refused``). No owner-approved model of it
  exists (section 37, "Choices for the owner").

Every input is a parameter like any other (section 14): a range with its unit, its
``source_type`` and its evidence. A geographic or a company-size figure may be an
input only as the customer states it, with that provenance: no pack holds a figure of
its own, and ``tests/test_economics_packs.py`` scans every pack for one.

Pure data: no Django, and it imports no template, so the parameter set, which is on
Django's load path, reads the schema without importing a pack's templates (spec,
section 2).
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from .parameters import ParameterRefused, Unit

#: The banking pack (``templates.PACK``): the thirty variables are its whole schema. A
#: parameter set that names no pack is the banking pack's, as every set recorded
#: before E7 is; naming it is refused, so a banking set has one spelling.
BANKING_PACK = "mythos.economics.banking-pack/v1"

#: A pack input is stored as a parameter of its set named this prefix and its name,
#: as an insurance sublimit is named ``insurance_sublimit:`` and its family.
PACK_INPUT_PREFIX = "pack_input:"

#: Words that name harm to a person. An effect type, an attribute or an input whose
#: name holds one as a word (its words are split at ``_``, ``-``, ``.`` and ``:``) is
#: refused (``safety_monetisation_refused``): no pack monetises injury, death or a
#: patient's or the public's safety without a model the owner has approved, and none
#: is approved.
HARM_WORDS = frozenset(
    {
        "injury", "injuries", "injured", "injure", "fatal", "fatality", "fatalities", "death", "deaths", "dead",
        "casualty", "casualties", "bodily", "harm", "harms", "harmed", "morbidity", "mortality", "vsl", "qaly",
        "daly",
    }
)
#: Phrases that name the value of a life, wherever they stand in a name.
_HARM_PHRASES = re.compile(r"statistical_life|life_value|value_of_life|value_of_a_life")


def names_harm(name) -> bool:
    """Whether ``name`` names harm to a person (:data:`HARM_WORDS`)."""
    if not isinstance(name, str):
        return False
    lowered = name.lower()
    return bool(set(re.split(r"[_\-.:\s]+", lowered)) & HARM_WORDS) or _HARM_PHRASES.search(lowered) is not None


def refuse_harm(name, path: str) -> None:
    """``safety_monetisation_refused`` where ``name`` names harm to a person."""
    if names_harm(name):
        raise ParameterRefused("safety_monetisation_refused", f"{path} {str(name)!r}")


@dataclass(frozen=True)
class PackInput:
    """One input of a pack's customer-input schema: its name, unit and meaning,
    whether the pack requires it (``required``; an optional one is required by the
    templates that read it), and which special data of the owner's specification,
    section 23, it captures."""

    name: str
    unit: Unit
    meaning: str
    required: bool
    special_data: str

    def as_dict(self) -> dict:
        return {
            "unit": self.unit.value,
            "meaning": self.meaning,
            "required": self.required,
            "special_data": self.special_data,
        }


@dataclass(frozen=True)
class PackSchema:
    """One pack's customer-input schema: the pack, its vertical and its inputs."""

    pack_id: str
    vertical: str
    inputs: Mapping[str, PackInput]

    def __post_init__(self):
        object.__setattr__(self, "inputs", MappingProxyType(dict(self.inputs)))

    @property
    def required(self) -> tuple[str, ...]:
        return tuple(sorted(name for name, entry in self.inputs.items() if entry.required))

    def as_dict(self) -> dict:
        return {
            "pack": self.pack_id,
            "vertical": self.vertical,
            "inputs": {name: entry.as_dict() for name, entry in sorted(self.inputs.items())},
        }


def _schema(pack_id: str, vertical: str, *inputs: PackInput) -> PackSchema:
    return PackSchema(pack_id, vertical, {entry.name: entry for entry in inputs})


def _schemas() -> tuple[PackSchema, ...]:
    U = Unit
    return (
        _schema(
            "mythos.economics.insurance-pack/v1",
            "insurance",
            PackInput(
                "claims_per_day", U.COUNT_PER_DAY, "claims the claims workflow decides per day", True, "claims volume"
            ),
            PackInput("policy_count", U.COUNT, "policies in force", True, "policy counts"),
            PackInput(
                "average_annual_premium",
                U.MONEY_PER_UNIT,
                "average written premium per policy per year (read with the loss ratio: the claims a policy is "
                "expected to cost are its premium times the loss ratio)",
                True,
                "loss ratios",
            ),
            PackInput(
                "loss_ratio", U.RATIO, "incurred claims as a share of earned premium, the customer's own book", True,
                "loss ratios",
            ),
            PackInput(
                "regulatory_jurisdiction_count",
                U.COUNT,
                "jurisdictions whose regulator a disclosure or a conduct finding is answered in: a count the customer "
                "states, never a weight by place",
                True,
                "regulatory jurisdictions",
            ),
            PackInput(
                "manual_claim_handling_cost",
                U.MONEY_PER_UNIT,
                "the customer's loaded cost of handling one claim by hand while its model is out",
                False,
                "claims volume",
            ),
        ),
        _schema(
            "mythos.economics.healthcare-pack/v1",
            "healthcare",
            PackInput("patient_record_count", U.COUNT, "patient records held", True, "patients/records"),
            PackInput(
                "breach_cost_per_record",
                U.MONEY_PER_UNIT,
                "breach response per exposed record (notification, identity services, call handling): the customer's "
                "own figure, or OCR breach data it states with that source, a prior and never its truth",
                True,
                "OCR breach data",
            ),
            PackInput(
                "care_disruption_cost_per_hour",
                U.MONEY_PER_HOUR,
                "the customer's own cost of one hour of disrupted clinical workflow: diversion, deferred procedures, "
                "overtime (never harm to a patient)",
                True,
                "care disruption",
            ),
            PackInput(
                "research_asset_value",
                U.MONEY,
                "the customer's valuation of the research data, models or IP at risk",
                False,
                "research value",
            ),
            PackInput(
                "batch_value",
                U.MONEY_PER_UNIT,
                "the value of one manufacturing batch (life sciences)",
                False,
                "GMP-related operational issues",
            ),
        ),
        _schema(
            "mythos.economics.saas-pack/v1",
            "saas",
            PackInput(
                "tenant_count", U.COUNT, "paying customer tenants of the multi-tenant platform", True,
                "customer count, multi-tenant architecture",
            ),
            PackInput(
                "recurring_margin_per_tenant",
                U.MONEY_PER_UNIT,
                "a tenant's recurring revenue a year less its cost to serve (ARR read as margin: revenue lost is not "
                "all loss)",
                True,
                "ARR",
            ),
            PackInput(
                "contract_sla_credit_per_hour",
                U.MONEY_PER_HOUR,
                "SLA credits the customer's contracts owe per hour of outage, across its tenants",
                True,
                "SLA",
            ),
            PackInput("contract_sla_credit_cap", U.MONEY, "the contracts' cap on those credits", True, "SLA"),
            PackInput(
                "cloud_spend_per_hour", U.MONEY_PER_HOUR, "the platform's cloud spend per hour", True, "cloud spend"
            ),
        ),
    )


#: Every vertical pack's schema, by pack id. Read-only. The banking pack has none: its
#: schema is the thirty variables.
SCHEMAS: Mapping[str, PackSchema] = MappingProxyType({s.pack_id: s for s in _schemas()})


def schema(pack_id, path: str = "pack") -> PackSchema:
    """The schema of the vertical pack ``pack_id``, or ``pack_unrecognised``: an
    unknown pack, a value that is not text, or the banking pack named (a set or a
    build that names no pack is the banking pack's)."""
    found = SCHEMAS.get(pack_id) if isinstance(pack_id, str) else None
    if found is None:
        named = "the banking pack is named by naming no pack" if pack_id == BANKING_PACK else "no such pack"
        raise ParameterRefused("pack_unrecognised", f"{path} {str(pack_id)!r}: {named}")
    return found


def input_unit(pack_id: str, name: str) -> Unit:
    """The unit a stored input ``name`` (without its prefix) of ``pack_id``'s schema
    has, or ``pack_input_unrecognised``."""
    entry = schema(pack_id).inputs.get(name)
    if entry is None:
        raise ParameterRefused("pack_input_unrecognised", f"{name!r} is not an input of {pack_id}")
    return entry.unit


__all__ = [
    "BANKING_PACK",
    "HARM_WORDS",
    "PACK_INPUT_PREFIX",
    "SCHEMAS",
    "PackInput",
    "PackSchema",
    "input_unit",
    "names_harm",
    "refuse_harm",
    "schema",
]
