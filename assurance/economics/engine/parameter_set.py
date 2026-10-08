"""The customer parameter set: the customer's own figures, as a typed schema.

Customer-specific data should dominate an estimate wherever it exists (owner's
specification, section 14). A parameter set is one deployment's answers to the
executive questionnaire, versioned: each version is a document of
:data:`VARIABLES` (thirty variables in nine domains, each with its unit), the
per-family insurance sublimits, and the excluded families
(``docs/economics/spec-v1.md``, section 19).

:func:`parse_document` reads a document exactly or refuses it, with the field's
path in the refusal's detail:

- a field or variable the schema does not hold is ``field_unrecognised``; one it
  requires and does not find is ``field_missing``; one of the wrong JSON type is
  ``field_malformed``;
- every variable states its unit, and a unit that is not the schema's is
  ``unit_mismatch`` (a client that thinks transactions are per hour is refused,
  not silently read as per day);
- a money variable states its currency, a quantity never does;
- every value is a decimal string in the one spelling of section 13
  (``Money.parse``): a JSON number is ``not_decimal``;
- every variable states its ``source_type``, its evidence and the date it holds
  from, and may state the last date it is fresh;
- the result is a set of :class:`.parameters.Parameter`, so every rule a
  parameter holds (a range, no negative, a ratio at most 1) holds here too.

A version's identity is :meth:`ParameterSetContent.digest`: ``sha256:`` and the
SHA-256 of its canonical JSON (sorted keys, the one decimal spelling), the same
whether it is read from the request or back from its stored rows.
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from enum import StrEnum
from types import MappingProxyType

from .formulas import CASH_FAMILIES
from .loss import InsurancePolicy
from .money import Money, MoneyRefused, parse_decimal
from .parameters import MONEY_UNITS, Parameter, ParameterRefused, Unit, check_source_type

#: The document schema this module reads.
SCHEMA_VERSION = "mythos.economics.parameter-set/v1"

#: A stored sublimit is a parameter named this prefix and its family.
SUBLIMIT_PREFIX = "insurance_sublimit:"

#: The longest evidence reference a variable may carry (its column's width).
EVIDENCE_REF_MAX = 500

_SET_KEY = re.compile(r"[a-z0-9][a-z0-9_-]{0,99}")
_DATE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")


class Domain(StrEnum):
    """The questionnaire's domains (section 14), less public-market context, which
    is market value and never a cash input."""

    SCALE = "scale"
    TRANSACTIONS = "transactions"
    DATA = "data"
    OPERATIONS = "operations"
    LABOR = "labor"
    LEGAL = "legal"
    VENDORS = "vendors"
    INSURANCE = "insurance"
    REMEDIATION = "remediation"


@dataclass(frozen=True)
class Variable:
    """One schema variable: its name, domain, unit and meaning."""

    name: str
    domain: Domain
    unit: Unit
    meaning: str

    def as_dict(self) -> dict:
        return {"domain": self.domain.value, "unit": self.unit.value, "meaning": self.meaning}


def _variables() -> tuple[Variable, ...]:
    D, U = Domain, Unit
    return (
        Variable("annual_revenue", D.SCALE, U.MONEY_PER_YEAR, "annual revenue"),
        Variable("operating_margin", D.SCALE, U.RATIO, "operating margin, as a fraction of revenue"),
        Variable("customer_count", D.SCALE, U.COUNT, "customers"),
        Variable("transactions_per_day", D.TRANSACTIONS, U.COUNT_PER_DAY, "transactions per day"),
        Variable("average_transaction_value", D.TRANSACTIONS, U.MONEY_PER_UNIT, "average transaction value"),
        Variable("maximum_transaction_value", D.TRANSACTIONS, U.MONEY_PER_UNIT, "largest transaction value"),
        Variable("recovery_rate", D.TRANSACTIONS, U.RATIO, "share of a misdirected amount settled back or recovered"),
        Variable("customer_record_count", D.DATA, U.COUNT, "customer records held"),
        Variable("regulated_record_count", D.DATA, U.COUNT, "health, payment or other regulated records held"),
        Variable("retention_days", D.DATA, U.DAYS, "how long records are retained"),
        Variable("revenue_per_hour", D.OPERATIONS, U.MONEY_PER_HOUR, "revenue of the critical service per hour"),
        Variable("margin_per_hour", D.OPERATIONS, U.MONEY_PER_HOUR, "margin of the critical service per hour"),
        Variable("recovery_time_objective_hours", D.OPERATIONS, U.HOURS, "recovery time objective (RTO)"),
        Variable("security_responder_hourly_rate", D.LABOR, U.MONEY_PER_HOUR, "loaded hourly rate of an incident responder"),
        Variable("engineering_hourly_rate", D.LABOR, U.MONEY_PER_HOUR, "loaded hourly rate of an engineer"),
        Variable("support_agent_hourly_rate", D.LABOR, U.MONEY_PER_HOUR, "loaded hourly rate of a support or call-center agent"),
        Variable("incident_team_size", D.LABOR, U.COUNT, "people on the incident team"),
        Variable("external_counsel_hourly_rate", D.LEGAL, U.MONEY_PER_HOUR, "external counsel's hourly rate"),
        Variable("legal_retainer", D.LEGAL, U.MONEY, "external counsel's retainer"),
        Variable("notification_unit_cost", D.LEGAL, U.MONEY_PER_UNIT, "cost of notifying one person"),
        Variable("notification_fixed_cost", D.LEGAL, U.MONEY, "fixed cost of a notification campaign"),
        Variable("critical_vendor_count", D.VENDORS, U.COUNT, "critical vendors"),
        Variable("vendor_exit_cost", D.VENDORS, U.MONEY_PER_UNIT, "cost of exiting or recovering one critical vendor"),
        Variable("vendor_liability_cap", D.VENDORS, U.MONEY, "contractual cap on a vendor's liability or indemnity"),
        Variable("insurance_deductible", D.INSURANCE, U.MONEY, "deductible or self-insured retention"),
        Variable("insurance_limit", D.INSURANCE, U.MONEY, "aggregate policy limit"),
        Variable("insurance_waiting_period_hours", D.INSURANCE, U.HOURS, "waiting period before business interruption cover"),
        Variable("remediation_engineering_hours", D.REMEDIATION, U.HOURS, "engineering hours a remediation takes"),
        Variable("remediation_license_cost_per_year", D.REMEDIATION, U.MONEY_PER_YEAR, "yearly licensing cost of a remediation"),
        Variable("remediation_duration_days", D.REMEDIATION, U.DAYS, "days a remediation takes to implement"),
    )


#: Every variable, by name. Read-only; pinned by tests/test_economics_scenarios.py.
VARIABLES: Mapping[str, Variable] = MappingProxyType({v.name: v for v in _variables()})

_ENTRY_REQUIRED = frozenset({"unit", "low", "base", "high", "source_type", "evidence_ref", "effective_date"})
_ENTRY_OPTIONAL = frozenset({"currency", "fresh_until"})
_DOCUMENT_REQUIRED = frozenset({"variables"})
_DOCUMENT_OPTIONAL = frozenset({"insurance_sublimits", "insurance_exclusions"})


def check_set_key(value) -> str:
    """A parameter set's key: 1 to 100 of lowercase ASCII letters, digits, ``-`` and
    ``_``, starting with a letter or digit (``set_key_malformed``)."""
    if not isinstance(value, str) or not _SET_KEY.fullmatch(value):
        raise ParameterRefused("set_key_malformed", repr(value)[:120])
    return value


def _date(value, path: str) -> date:
    if not isinstance(value, str) or not _DATE.fullmatch(value):
        raise MoneyRefused("date_malformed", f"{path} is not a YYYY-MM-DD date")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise MoneyRefused("date_malformed", f"{path} {value!r} is not a calendar date") from None


def _object(value, path: str, required: frozenset, optional: frozenset) -> dict:
    if not isinstance(value, dict):
        raise ParameterRefused("field_malformed", f"{path} is not an object")
    unknown = sorted(str(k) for k in value if k not in required | optional)
    if unknown:
        raise ParameterRefused("field_unrecognised", f"{path}: {unknown}")
    missing = sorted(required - set(value))
    if missing:
        raise ParameterRefused("field_missing", f"{path}: {missing}")
    return value


def _parameter(name: str, unit: Unit, entry, path: str) -> Parameter:
    entry = _object(entry, path, _ENTRY_REQUIRED, _ENTRY_OPTIONAL)
    stated = entry["unit"]
    if not isinstance(stated, str):
        raise ParameterRefused("field_malformed", f"{path}.unit is not text")
    try:
        stated_unit = Unit(stated)
    except ValueError:
        raise ParameterRefused("unit_unrecognised", f"{path}.unit {stated!r}") from None
    if stated_unit is not unit:
        raise ParameterRefused("unit_mismatch", f"{path}.unit is {stated}; the schema's {name} is {unit}")
    if unit in MONEY_UNITS:
        if "currency" not in entry:
            raise ParameterRefused("field_missing", f"{path}: ['currency']")
        currency = entry["currency"]

        def value(point: str):
            return Money(parse_decimal(entry[point], f"{path}.{point}"), currency)

    else:
        if "currency" in entry:
            raise ParameterRefused("field_unrecognised", f"{path}: ['currency'] on a quantity ({unit})")

        def value(point: str):
            return parse_decimal(entry[point], f"{path}.{point}")

    evidence = entry["evidence_ref"]
    if not isinstance(evidence, str):
        raise ParameterRefused("field_malformed", f"{path}.evidence_ref is not text")
    if len(evidence) > EVIDENCE_REF_MAX:
        raise ParameterRefused("field_malformed", f"{path}.evidence_ref is longer than {EVIDENCE_REF_MAX}")
    source = entry["source_type"]
    if not isinstance(source, str):
        raise ParameterRefused("source_type_unrecognised", f"{path}.source_type {source!r}")
    fresh = entry.get("fresh_until")
    return Parameter(
        name=name,
        unit=unit,
        source_type=check_source_type(source),
        low=value("low"),
        base=value("base"),
        high=value("high"),
        evidence_ref=evidence,
        effective_date=_date(entry["effective_date"], f"{path}.effective_date"),
        fresh_until=_date(fresh, f"{path}.fresh_until") if fresh is not None else None,
    )


def _cash_family(value, path: str) -> str:
    if not isinstance(value, str) or value not in CASH_FAMILIES:
        raise ParameterRefused("loss_family_unrecognised", f"{path} {value!r} is not one of the fifteen families")
    return value


@dataclass(frozen=True)
class ParameterSetContent:
    """One version's content: its variables, its sublimits by family, and its
    excluded families, sorted."""

    variables: Mapping[str, Parameter]
    sublimits: Mapping[str, Parameter]
    exclusions: tuple[str, ...]

    def __post_init__(self):
        object.__setattr__(self, "variables", MappingProxyType(dict(sorted(self.variables.items()))))
        object.__setattr__(self, "sublimits", MappingProxyType(dict(sorted(self.sublimits.items()))))
        object.__setattr__(self, "exclusions", tuple(sorted(self.exclusions)))
        if not self.variables:
            raise ParameterRefused("field_missing", "variables: a version holds at least one variable")
        for name, parameter in self.variables.items():
            variable = VARIABLES.get(name)
            if variable is None:
                raise ParameterRefused("field_unrecognised", f"variables: [{name!r}]")
            if parameter.name != name or parameter.unit is not variable.unit:
                raise ParameterRefused("unit_mismatch", f"{name} is {variable.unit}")
        for family, parameter in self.sublimits.items():
            _cash_family(family, "insurance_sublimits")
            if parameter.name != SUBLIMIT_PREFIX + family or parameter.unit is not Unit.MONEY:
                raise ParameterRefused("unit_mismatch", f"the {family} sublimit is money, named {SUBLIMIT_PREFIX}{family}")
        if len(set(self.exclusions)) != len(self.exclusions):
            raise ParameterRefused("duplicate_id", "insurance_exclusions names a family twice")
        for family in self.exclusions:
            _cash_family(family, "insurance_exclusions")
        # The policy's terms are one currency, or the set is refused now rather than
        # when a scenario first reads it.
        self.insurance_policy()

    def parameters(self) -> list[Parameter]:
        """Every parameter of the version, variables then sublimits: the rows it is
        stored as."""
        return [*self.variables.values(), *self.sublimits.values()]

    def as_dict(self) -> dict:
        """The canonical document: what the digest is taken over."""

        def entry(parameter: Parameter) -> dict:
            row = parameter.as_dict()
            del row["name"], row["parameter_id"]
            if row["currency"] is None:
                del row["currency"]
            return row

        return {
            "schema": SCHEMA_VERSION,
            "variables": {name: entry(p) for name, p in self.variables.items()},
            "insurance_sublimits": {family: entry(p) for family, p in self.sublimits.items()},
            "insurance_exclusions": list(self.exclusions),
        }

    def digest(self) -> str:
        canonical = json.dumps(self.as_dict(), sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def insurance_policy(self) -> InsurancePolicy | None:
        """The policy the version states, or ``None`` when it states no deductible or
        no limit: insurance is then not applied, and nothing assumes a policy."""
        deductible = self.variables.get("insurance_deductible")
        limit = self.variables.get("insurance_limit")
        if deductible is None or limit is None:
            return None
        return InsurancePolicy(
            deductible=deductible,
            limit=limit,
            sublimits=self.sublimits,
            exclusions=frozenset(self.exclusions),
            waiting_period_hours=self.variables.get("insurance_waiting_period_hours"),
        )


def parse_document(document) -> ParameterSetContent:
    """A parameter-set version read from ``document``, or refused. See the module's
    rules."""
    document = _object(document, "document", _DOCUMENT_REQUIRED, _DOCUMENT_OPTIONAL)
    raw = document["variables"]
    if not isinstance(raw, dict):
        raise ParameterRefused("field_malformed", "variables is not an object")
    variables: dict[str, Parameter] = {}
    for name in raw:
        if name not in VARIABLES:
            raise ParameterRefused("field_unrecognised", f"variables: [{str(name)!r}]")
        variables[name] = _parameter(name, VARIABLES[name].unit, raw[name], f"variables.{name}")
    sublimits: dict[str, Parameter] = {}
    raw = document.get("insurance_sublimits", {})
    if not isinstance(raw, dict):
        raise ParameterRefused("field_malformed", "insurance_sublimits is not an object")
    for family in raw:
        _cash_family(family, "insurance_sublimits")
        sublimits[family] = _parameter(
            SUBLIMIT_PREFIX + family, Unit.MONEY, raw[family], f"insurance_sublimits.{family}"
        )
    exclusions = document.get("insurance_exclusions", [])
    if not isinstance(exclusions, list):
        raise ParameterRefused("field_malformed", "insurance_exclusions is not a list")
    for position, family in enumerate(exclusions):
        _cash_family(family, f"insurance_exclusions[{position}]")
    return ParameterSetContent(variables, sublimits, tuple(exclusions))


def content_of(parameters, exclusions) -> ParameterSetContent:
    """A version's content read back from its stored ``parameters`` and
    ``exclusions``."""
    variables: dict[str, Parameter] = {}
    sublimits: dict[str, Parameter] = {}
    for parameter in parameters:
        target, key = (
            (sublimits, parameter.name[len(SUBLIMIT_PREFIX):])
            if parameter.name.startswith(SUBLIMIT_PREFIX)
            else (variables, parameter.name)
        )
        if key in target:
            raise ParameterRefused("duplicate_id", parameter.name)
        target[key] = parameter
    return ParameterSetContent(variables, sublimits, tuple(exclusions))


def variable_unit(name: str) -> Unit:
    """The unit a stored set parameter of ``name`` must have: its variable's, or
    money for a sublimit; ``field_unrecognised`` for any other name."""
    if name.startswith(SUBLIMIT_PREFIX):
        _cash_family(name[len(SUBLIMIT_PREFIX):], "sublimit")
        return Unit.MONEY
    variable = VARIABLES.get(name)
    if variable is None:
        raise ParameterRefused("field_unrecognised", f"{name!r} is not a parameter-set variable")
    return variable.unit
