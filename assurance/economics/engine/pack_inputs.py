"""The customer-input schema of each industry pack (Economic Exposure E7;
``docs/economics/spec-v1.md``, section 37).

An industry pack (:mod:`.pack_registry`) prices the effects of one vertical through
its own templates; the figures they read beyond the thirty shared variables of the
parameter set (:data:`.parameter_set.VARIABLES`) are the vertical's SPECIAL DATA,
the owner's specification, section 23: an insurer's claims volume, loss ratio and
policy count, a hospital's patient records and its cost of care disruption, a SaaS
platform's tenants, recurring margin, SLA terms and cloud spend. This module is that
schema, and nothing else: each pack's inputs, each with its unit and meaning.

A parameter set names the pack it answers (``pack``) and states the pack's inputs
(``pack_inputs``) beside its variables (:func:`.parameter_set.parse_document`). The
rules:

- an input is required only by a build that reads it, never at record time (choice 2,
  an interim lead decision the owner may change): a build whose effects are assigned
  to a template that reads an input the set does not state is refused
  (``pack_input_missing``), never defaulted and never read as zero, and a set is never
  pushed to state a zero for an input none of its builds reads;
- an input the pack does not hold is refused (``pack_input_unrecognised``), and so is
  one in another unit (``unit_mismatch``);
- nothing that prices harm to a person -- an injury, a death, a patient's or the
  public's safety -- is an input, an attribute or an effect type of any pack: naming
  one is refused (``safety_monetisation_refused``; :func:`names_harm` reads every
  spelling: ``snake_case``, ``kebab-case``, ``camelCase``). No owner-approved model of
  it exists (section 37, "Choices for the owner").

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
#: name holds one as a word (:func:`words_of`) is refused
#: (``safety_monetisation_refused``): no pack monetises injury, death, illness or a
#: patient's or the public's safety without a model the owner has approved, and none
#: is approved.
HARM_WORDS = frozenset(
    {
        "injury", "injuries", "injured", "injure", "injuring", "fatal", "fatality", "fatalities", "death", "deaths",
        "dead", "died", "dying", "casualty", "casualties", "bodily", "harm", "harms", "harmed", "harming",
        "morbidity", "mortality", "vsl", "qaly", "qalys", "daly", "dalys", "killed", "wounded", "wounds",
        "wounding", "maimed", "lethal", "illness", "illnesses", "sickness", "disability", "disabilities",
        "suffering",
    }
)
#: Phrases that name harm to a person, as runs of words wherever they stand in a name:
#: the value or the loss of a life, an adverse event or a patient's outcome, and a
#: person's safety. "safety" alone is not one: a manufacturer's safety system is a
#: control, priced by what restoring it costs.
HARM_PHRASES = frozenset(
    {
        ("statistical", "life"), ("life", "value"), ("value", "of", "life"), ("value", "of", "a", "life"),
        ("loss", "of", "life"), ("lives", "lost"), ("life", "lost"), ("lost", "lives"), ("lost", "life"),
        ("human", "life"), ("human", "lives"), ("adverse", "event"), ("adverse", "events"),
        ("patient", "outcome"), ("patient", "outcomes"), ("health", "outcome"), ("health", "outcomes"),
        ("patient", "safety"), ("public", "safety"), ("passenger", "safety"), ("worker", "safety"),
        ("occupant", "safety"), ("pedestrian", "safety"), ("personal", "safety"), ("human", "safety"),
        ("life", "safety"),
    }
)
#: A camelCase hump: before an upper-case letter that follows a lower-case one or a
#: digit, and before the last of a run of capitals that starts a word ("VSLCost").
_CAMEL_HUMP = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")


def words_of(name: str) -> tuple[str, ...]:
    """``name``'s words, lower-cased: split at every camelCase hump and at every
    character that is not a letter (``_``, ``-``, ``.``, ``:``, a space, a digit)."""
    return tuple(w for w in re.split(r"[^a-z]+", _CAMEL_HUMP.sub("_", name).lower()) if w)


def names_harm(name) -> bool:
    """Whether ``name`` names harm to a person: a word of :data:`HARM_WORDS`, or a run
    of words of :data:`HARM_PHRASES`, in any spelling (:func:`words_of`)."""
    if not isinstance(name, str):
        return False
    words = words_of(name)
    if set(words) & HARM_WORDS:
        return True
    return any(
        words[start:start + len(phrase)] == phrase
        for phrase in HARM_PHRASES
        for start in range(len(words) - len(phrase) + 1)
    )


def refuse_harm(name, path: str) -> None:
    """``safety_monetisation_refused`` where ``name`` names harm to a person."""
    if names_harm(name):
        raise ParameterRefused("safety_monetisation_refused", f"{path} {str(name)!r}")


@dataclass(frozen=True)
class PackInput:
    """One input of a pack's customer-input schema: its name, unit and meaning, and
    which special data of the owner's specification, section 23, it captures. No input
    is required at record time: a build requires every input a template it uses reads
    (choice 2; :meth:`.pack_base.Pack.check_template_inputs`)."""

    name: str
    unit: Unit
    meaning: str
    special_data: str

    def as_dict(self) -> dict:
        return {
            "unit": self.unit.value,
            "meaning": self.meaning,
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
            PackInput("claims_per_day", U.COUNT_PER_DAY, "claims the claims workflow decides per day", "claims volume"),
            PackInput("policy_count", U.COUNT, "policies in force", "policy counts"),
            PackInput(
                "average_annual_premium",
                U.MONEY_PER_UNIT,
                "average written premium per policy per year (read with the loss ratio: the claims a policy is "
                "expected to cost are its premium times the loss ratio)",
                "loss ratios",
            ),
            PackInput(
                "loss_ratio", U.RATIO, "incurred claims as a share of earned premium, the customer's own book",
                "loss ratios",
            ),
            PackInput(
                "regulatory_jurisdiction_count",
                U.COUNT,
                "jurisdictions whose regulator a disclosure or a conduct finding is answered in: a count the customer "
                "states, never a weight by place",
                "regulatory jurisdictions",
            ),
            PackInput(
                "manual_claim_handling_cost",
                U.MONEY_PER_UNIT,
                "the customer's loaded cost of handling one claim by hand while its model is out",
                "claims volume",
            ),
        ),
        _schema(
            "mythos.economics.healthcare-pack/v1",
            "healthcare",
            PackInput("patient_record_count", U.COUNT, "patient records held", "patients/records"),
            PackInput(
                "breach_cost_per_record",
                U.MONEY_PER_UNIT,
                "breach response per exposed record (notification, identity services, call handling): the customer's "
                "own figure, or OCR breach data it states with that source, a prior and never its truth",
                "OCR breach data",
            ),
            PackInput(
                "care_disruption_cost_per_hour",
                U.MONEY_PER_HOUR,
                "the customer's own cost of one hour of disrupted clinical workflow: diversion, deferred procedures, "
                "overtime (never harm to a patient)",
                "care disruption",
            ),
            PackInput(
                "research_asset_value",
                U.MONEY,
                "the customer's valuation of the research data, models or IP at risk",
                "research value",
            ),
            PackInput(
                "batch_value",
                U.MONEY_PER_UNIT,
                "the value of one manufacturing batch (life sciences)",
                "GMP-related operational issues",
            ),
        ),
        _schema(
            "mythos.economics.saas-pack/v1",
            "saas",
            PackInput(
                "tenant_count", U.COUNT, "paying customer tenants of the multi-tenant platform",
                "customer count, multi-tenant architecture",
            ),
            PackInput(
                "recurring_margin_per_tenant",
                U.MONEY_PER_UNIT,
                "a tenant's recurring revenue a year less its cost to serve (ARR read as margin: revenue lost is not "
                "all loss)",
                "ARR",
            ),
            PackInput(
                "usage_margin_per_hour",
                U.MONEY_PER_HOUR,
                "usage-billed revenue (tokens, API calls, metered seats) the platform earns per hour, less its cost "
                "to serve: stated only by a platform that bills by usage; a set that does not state it bills by "
                "subscription alone, and an outage loses no usage revenue (choice 8)",
                "ARR (usage-billed)",
            ),
            PackInput(
                "contract_sla_credit_per_hour",
                U.MONEY_PER_HOUR,
                "SLA credits the customer's contracts owe per hour of outage, across its tenants",
                "SLA",
            ),
            PackInput("contract_sla_credit_cap", U.MONEY, "the contracts' cap on those credits", "SLA"),
            PackInput(
                "abuse_spend_cap_per_hour",
                U.MONEY_PER_HOUR,
                "the API-abuse cap: the most the platform's cloud and inference spend can rise per hour while the API "
                "is abused -- its provider's quota, rate limit or billing cap, or, where none binds, the customer's "
                "own worst plausible figure, its source saying which; it may be many times the baseline spend "
                "(denial of wallet)",
                "cloud spend",
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
