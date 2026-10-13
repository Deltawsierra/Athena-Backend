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
- every entry may state the distribution it draws from in a simulation (step
  7a's catalogue, read exactly by :func:`stated_distribution` and kept in its one
  spelling), and the document may state the scenario's ``frequency``: a count of
  events a year that always states its count distribution (spec, section 19.2).
  Whether a distribution holds its entry's figures is checked when the version is
  recorded, by the simulation's own test (``scenario_simulation.check_stated``),
  the same test a run applies;
- the result is a set of :class:`.parameters.Parameter`, so every rule a
  parameter holds (a range, no negative, a ratio at most 1) holds here too.

A version's identity is :meth:`ParameterSetContent.digest`: ``sha256:`` and the
SHA-256 of its canonical JSON (sorted keys, the one decimal spelling), the same
whether it is read from the request or back from its stored rows. A version that
states no distribution and no frequency has the canonical document, and so the
digest, it had before either could be stated.

Only a document that states a distribution imports the probabilistic engine (and
numpy), and only when it is read: nothing Django loads at start does (spec,
section 23.10).
"""

from __future__ import annotations

import hashlib
import importlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum
from types import MappingProxyType

from . import pack_inputs as packs
from .formulas import CASH_FAMILIES
from .loss import InsurancePolicy
from .money import Money, MoneyRefused, parse_decimal
from .parameters import MONEY_UNITS, Parameter, ParameterRefused, Unit, check_source_type
from .provenance import SourceType

#: The document schema this module reads.
SCHEMA_VERSION = "mythos.economics.parameter-set/v1"

#: A stored sublimit is a parameter named this prefix and its family.
SUBLIMIT_PREFIX = "insurance_sublimit:"

#: The longest evidence reference a variable may carry (its column's width).
EVIDENCE_REF_MAX = 500

#: The scenario's frequency: events a year, a count, stored as a parameter of this
#: name (``scenario_simulation.FREQUENCY_PARAMETER``, spelled here so this module
#: never imports the probabilistic engine to name it).
FREQUENCY = "frequency"

#: The module that reads a stated distribution: imported only for a document that
#: states one.
_PROBABILISTIC_ENGINE = "assurance.economics.engine.scenario_simulation"

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
_ENTRY_OPTIONAL = frozenset({"currency", "fresh_until", "distribution"})
_DOCUMENT_REQUIRED = frozenset({"variables"})
_DOCUMENT_OPTIONAL = frozenset({"insurance_sublimits", "insurance_exclusions", FREQUENCY, "pack", "pack_inputs"})


class StatedDistributionRefused(ParameterRefused):
    """A stated distribution the probabilistic engine refuses, with that engine's
    code and meaning, carried with the refusal so that this module never imports
    the engine to name them. A :class:`.parameters.ParameterRefused`, so one
    ``except`` still catches every refusal of the engine."""

    def __init__(self, code: str, meaning: str, detail: str = ""):
        self.code = code
        self.meaning = meaning
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        ValueError.__init__(self, f"{code}: {meaning}{suffix}")


class ProbabilisticEngineUnavailable(RuntimeError):
    """The probabilistic engine (or numpy) will not import, so a stated
    distribution cannot be read now. Nothing is recorded; a document that states
    no distribution never needs the engine."""


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


def probabilistic_engine(path: str):
    """The probabilistic engine (``scenario_simulation``, and numpy with it), imported
    now, or :class:`ProbabilisticEngineUnavailable`: ANY fault importing it, as a run
    maps any to ``engine_unavailable`` (review round 1, NIT-2). Only the fault's type is
    kept: its message may name a path or a library."""
    try:
        return importlib.import_module(_PROBABILISTIC_ENGINE)
    except Exception as error:  # noqa: BLE001 - any import fault of numpy or the engine is a returned 503
        raise ProbabilisticEngineUnavailable(
            f"{path}: the probabilistic engine will not import ({type(error).__name__})"
        ) from None


def stated_distribution(entry, path: str) -> dict | None:
    """The distribution ``entry`` states, in its one stored spelling (read exactly by
    ``scenario_simulation.parse_stated``: a catalogue id and version, native
    parameters as decimal strings), or ``None`` where it states none. A malformed
    one is refused with the engine's code (:class:`StatedDistributionRefused`).
    Whether it holds the entry's own figures is the record's check, the run's test."""
    if not isinstance(entry, dict) or "distribution" not in entry:
        return None
    engine = probabilistic_engine(f"{path}.distribution")
    try:
        stated = engine.parse_stated(entry["distribution"], f"{path}.distribution")
    except engine.ScenarioSimulationRefused as refused:
        raise StatedDistributionRefused(refused.code, engine.REFUSALS[refused.code], refused.detail) from None
    # The stored form, deep-copied: nothing the caller holds reaches the content.
    return json.loads(json.dumps(stated.as_json()))


def _money_is_not_observed(parameter: Parameter, path: str) -> Parameter:
    """``parameter``, a figure of the parameter set, or ``observed_source_not_observable``
    when it is money (a lump sum, or per unit, hour or year) resting on
    ``MYTHOS_OBSERVED``: an assessment observes a rate, a count or a duration, never
    what the customer's money figures are (the builder's rule for an effect's
    attributes, spec section 24.2). Held here, on the set's own parsing: a quantity
    may still be observed, and an effect's attribute keeps its own rule."""
    if parameter.unit in MONEY_UNITS and parameter.source_type is SourceType.MYTHOS_OBSERVED:
        raise ParameterRefused("observed_source_not_observable", path)
    return parameter


def _cash_family(value, path: str) -> str:
    if not isinstance(value, str) or value not in CASH_FAMILIES:
        raise ParameterRefused("loss_family_unrecognised", f"{path} {value!r} is not one of the fifteen families")
    return value


@dataclass(frozen=True)
class ParameterSetContent:
    """One version's content: its variables, its sublimits by family, and its
    excluded families, sorted; the distributions its parameters state, by the
    parameter's name, in their stored spelling; and the scenario's frequency, if it
    states one (a count of events a year, which always states its distribution)."""

    variables: Mapping[str, Parameter]
    sublimits: Mapping[str, Parameter]
    exclusions: tuple[str, ...]
    distributions: Mapping[str, dict] = field(default_factory=dict)
    frequency: Parameter | None = None
    #: The industry pack the version answers (E7, spec section 37): ``""`` for the
    #: banking pack, whose schema is the thirty variables, as every version recorded
    #: before E7 is; and the pack's inputs, by input name, each a parameter named
    #: :data:`.pack_inputs.PACK_INPUT_PREFIX` and its name.
    pack: str = ""
    pack_inputs: Mapping[str, Parameter] = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "variables", MappingProxyType(dict(sorted(self.variables.items()))))
        object.__setattr__(self, "sublimits", MappingProxyType(dict(sorted(self.sublimits.items()))))
        object.__setattr__(self, "pack_inputs", MappingProxyType(dict(sorted(dict(self.pack_inputs).items()))))
        object.__setattr__(self, "exclusions", tuple(sorted(self.exclusions)))
        object.__setattr__(
            self, "distributions", MappingProxyType({k: v for k, v in sorted(dict(self.distributions).items())})
        )
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
        self._check_pack()
        frequency = self.frequency
        if frequency is not None:
            if frequency.name != FREQUENCY or frequency.unit is not Unit.COUNT:
                raise ParameterRefused("unit_mismatch", f"the frequency is a count of events a year, named {FREQUENCY}")
            if FREQUENCY not in self.distributions:
                raise ParameterRefused(
                    "field_missing", f"{FREQUENCY}: ['distribution']: a frequency states its count distribution"
                )
        named = {p.name for p in self.parameters()}
        for name, stated in self.distributions.items():
            if name not in named:
                raise ParameterRefused(
                    "field_unrecognised", f"a distribution for {name!r}, which the version does not hold"
                )
            if not isinstance(stated, dict):
                raise ParameterRefused("field_malformed", f"{name}.distribution is not an object")
        # The policy's terms are one currency, or the set is refused now rather than
        # when a scenario first reads it.
        self.insurance_policy()

    def _check_pack(self) -> None:
        """The pack's inputs as its schema gives them (spec, section 37): only a
        version that names a pack holds any (``field_unrecognised``); each is an input
        of its schema (``pack_input_unrecognised``), named for it and in its unit
        (``unit_mismatch``); none names harm to a person
        (``safety_monetisation_refused``); and every input the pack requires is
        stated (``pack_input_missing``): never defaulted, never read as zero."""
        if not self.pack:
            if self.pack_inputs:
                raise ParameterRefused("field_unrecognised", "pack_inputs: a version that names no pack holds none")
            return
        schema = packs.schema(self.pack)
        for name, parameter in self.pack_inputs.items():
            packs.refuse_harm(name, "pack_inputs")
            entry = schema.inputs.get(name)
            if entry is None:
                raise ParameterRefused("pack_input_unrecognised", f"pack_inputs: [{name!r}] is not an input of {self.pack}")
            if parameter.name != packs.PACK_INPUT_PREFIX + name or parameter.unit is not entry.unit:
                raise ParameterRefused(
                    "unit_mismatch", f"the {self.pack} input {name} is {entry.unit}, named {packs.PACK_INPUT_PREFIX}{name}"
                )
        missing = [name for name in schema.required if name not in self.pack_inputs]
        if missing:
            raise ParameterRefused("pack_input_missing", f"pack_inputs: {missing} (required by {self.pack})")

    def parameters(self) -> list[Parameter]:
        """Every parameter of the version, variables, then sublimits, then the pack's
        inputs, then the frequency: the rows it is stored as."""
        frequency = [self.frequency] if self.frequency is not None else []
        return [*self.variables.values(), *self.sublimits.values(), *self.pack_inputs.values(), *frequency]

    def as_dict(self) -> dict:
        """The canonical document: what the digest is taken over."""

        def entry(parameter: Parameter) -> dict:
            row = parameter.as_dict()
            del row["name"], row["parameter_id"]
            if row["currency"] is None:
                del row["currency"]
            # Only where one is stated: a version that states none keeps the
            # canonical document, and the digest, it had before one could be.
            if parameter.name in self.distributions:
                row["distribution"] = self.distributions[parameter.name]
            return row

        document = {
            "schema": SCHEMA_VERSION,
            "variables": {name: entry(p) for name, p in self.variables.items()},
            "insurance_sublimits": {family: entry(p) for family, p in self.sublimits.items()},
            "insurance_exclusions": list(self.exclusions),
        }
        if self.frequency is not None:
            document[FREQUENCY] = entry(self.frequency)
        # Only where a pack is named: a banking version keeps the canonical document,
        # and the digest, it had before a pack could be named.
        if self.pack:
            document["pack"] = self.pack
            document["pack_inputs"] = {name: entry(p) for name, p in self.pack_inputs.items()}
        return document

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
    distributions: dict[str, dict] = {}

    def read(name: str, unit: Unit, entry, path: str) -> Parameter:
        parameter = _parameter(name, unit, entry, path)
        stated = stated_distribution(entry, path)
        if stated is not None:
            distributions[name] = stated
        return parameter

    variables: dict[str, Parameter] = {}
    for name in raw:
        if name not in VARIABLES:
            raise ParameterRefused("field_unrecognised", f"variables: [{str(name)!r}]")
        variables[name] = _money_is_not_observed(
            read(name, VARIABLES[name].unit, raw[name], f"variables.{name}"), f"variables.{name}"
        )
    sublimits: dict[str, Parameter] = {}
    raw = document.get("insurance_sublimits", {})
    if not isinstance(raw, dict):
        raise ParameterRefused("field_malformed", "insurance_sublimits is not an object")
    for family in raw:
        _cash_family(family, "insurance_sublimits")
        sublimits[family] = _money_is_not_observed(
            read(SUBLIMIT_PREFIX + family, Unit.MONEY, raw[family], f"insurance_sublimits.{family}"),
            f"insurance_sublimits.{family}",
        )
    exclusions = document.get("insurance_exclusions", [])
    if not isinstance(exclusions, list):
        raise ParameterRefused("field_malformed", "insurance_exclusions is not a list")
    for position, family in enumerate(exclusions):
        _cash_family(family, f"insurance_exclusions[{position}]")
    frequency = None
    if FREQUENCY in document:
        entry = document[FREQUENCY]
        if isinstance(entry, dict) and "distribution" not in entry:
            # Nothing defaults: a PERT is not a count (spec, section 25.1).
            raise ParameterRefused(
                "field_missing", f"{FREQUENCY}: ['distribution']: a frequency states its count distribution"
            )
        frequency = read(FREQUENCY, Unit.COUNT, entry, FREQUENCY)
    # The industry pack the version answers, and its inputs (spec, section 37).
    pack = ""
    inputs: dict[str, Parameter] = {}
    if "pack" in document:
        schema = packs.schema(document["pack"])
        pack = schema.pack_id
        raw = document.get("pack_inputs", {})
        if not isinstance(raw, dict):
            raise ParameterRefused("field_malformed", "pack_inputs is not an object")
        for name in raw:
            packs.refuse_harm(name, "pack_inputs")
            entry = schema.inputs.get(name) if isinstance(name, str) else None
            if entry is None:
                raise ParameterRefused("pack_input_unrecognised", f"pack_inputs: [{str(name)!r}] is not an input of {pack}")
            inputs[name] = _money_is_not_observed(
                read(packs.PACK_INPUT_PREFIX + name, entry.unit, raw[name], f"pack_inputs.{name}"), f"pack_inputs.{name}"
            )
    elif "pack_inputs" in document:
        raise ParameterRefused("field_unrecognised", "pack_inputs: a version that names no pack holds none")
    return ParameterSetContent(variables, sublimits, tuple(exclusions), distributions, frequency, pack, inputs)


def content_of(parameters, exclusions, distributions=None, pack: str = "") -> ParameterSetContent:
    """A version's content read back from its stored ``parameters``, ``exclusions``
    and the ``distributions`` its rows state, by name (each in its stored
    spelling), for the industry pack it names (``pack``; ``""`` for banking)."""
    variables: dict[str, Parameter] = {}
    sublimits: dict[str, Parameter] = {}
    inputs: dict[str, Parameter] = {}
    frequency = None
    for parameter in parameters:
        if parameter.name == FREQUENCY:
            if frequency is not None:
                raise ParameterRefused("duplicate_id", parameter.name)
            frequency = parameter
            continue
        if parameter.name.startswith(SUBLIMIT_PREFIX):
            target, key = sublimits, parameter.name[len(SUBLIMIT_PREFIX):]
        elif parameter.name.startswith(packs.PACK_INPUT_PREFIX):
            target, key = inputs, parameter.name[len(packs.PACK_INPUT_PREFIX):]
        else:
            target, key = variables, parameter.name
        if key in target:
            raise ParameterRefused("duplicate_id", parameter.name)
        target[key] = parameter
    return ParameterSetContent(
        variables, sublimits, tuple(exclusions), dict(distributions or {}), frequency, pack, inputs
    )


def variable_unit(name: str, pack: str = "") -> Unit:
    """The unit a stored set parameter of ``name`` must have: its variable's, money
    for a sublimit, a count for the frequency, or, for a version of the industry pack
    ``pack``, its input's; ``field_unrecognised`` for any other name (an input on a
    version that names no pack included), ``pack_input_unrecognised`` for an input
    the pack does not hold."""
    if name.startswith(SUBLIMIT_PREFIX):
        _cash_family(name[len(SUBLIMIT_PREFIX):], "sublimit")
        return Unit.MONEY
    if name == FREQUENCY:
        return Unit.COUNT
    if name.startswith(packs.PACK_INPUT_PREFIX) and pack:
        return packs.input_unit(pack, name[len(packs.PACK_INPUT_PREFIX):])
    variable = VARIABLES.get(name)
    if variable is None:
        raise ParameterRefused("field_unrecognised", f"{name!r} is not a parameter-set variable")
    return variable.unit
