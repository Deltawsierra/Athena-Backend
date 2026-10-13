"""One remediation option of a scenario version, and its economics (MVP step 13;
``docs/economics/spec-v1.md``, section 28; the owner's specification, section 21).

Pure: no Django, no database, no clock, no numpy. Two halves:

- **The option's form** (:func:`parse_option`): what a remediation costs -- its
  implementation cost and its annual recurring cost, each money with a low, base
  and high, a currency and a source, read as a parameter set reads a variable --,
  how long it takes, what it depends on (text, or SPINE ids, never copies), and its
  control effect: a frequency reduction ``r_f`` and/or a magnitude reduction
  ``r_m``, each a ratio in [0, 1] with a low, base and high and a source, acting
  on every component or on the loss families or components it names. The option
  is held to one canonical document, and its identity is that document's digest
  (:func:`option_digest`). A reduction rests on ``MYTHOS_OBSERVED`` only where the
  control effect cites the retest it was observed in, and a control effect that
  cites one is observed (:data:`REFUSALS`).
- **Its economics** (:func:`economics`): from two stored runs' headline lines --
  the scenario as it is and the residual run with the option's control effect --
  the expected annual exposure of each, the expected reduction, the first-year
  investment, the risk-adjusted ROI and the payback period, each with the reason
  it is not meaningful where it is not (never a negative or infinite payback), and
  the tail reduction at P90 and P95. Money at the currency's minor unit, half-even;
  the ROI and the payback to fixed places, half-even. Computed from the runs' full
  precision; nothing rounded is computed with again.

The hard security veto is not decided here: it reads SPINE's records
(``assurance.economics.remediation_service``). Here, only that a vetoed ROI is
display-only and says so (:data:`VETO_STATEMENT`).
"""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal
from types import MappingProxyType

from . import parameter_set as pset
from .formulas import COMPONENT_FAMILIES
from .money import Money, MoneyRefused, compute, decimal_text
from .parameters import POINTS, Parameter, ParameterRefused, Unit
from .provenance import SourceType

#: The option's canonical document.
OPTION_SCHEMA = "mythos.economics.remediation-option/v1"
#: The ROI document a scenario's option is served as.
ROI_SCHEMA = "mythos.economics.roi/v1"
#: How a retest record is cited: the digest of this document of it.
RETEST_CITATION_SCHEMA = "mythos.economics.retest-citation/v1"

#: The names the control effect's two reductions take in a run: never a
#: parameter's (a scenario parameter of the same name is refused, ``duplicate_id``).
FREQUENCY_REDUCTION = "remediation.frequency_reduction"
MAGNITUDE_REDUCTION = "remediation.magnitude_reduction"
REDUCTIONS = (FREQUENCY_REDUCTION, MAGNITUDE_REDUCTION)
#: The option's two costs, read as parameters (never simulated).
IMPLEMENTATION_COST = "remediation.implementation_cost"
RECURRING_COST = "remediation.recurring_cost"

#: Bounds of the option's document.
TITLE_MAX = 255
TEXT_MAX = 500
MAX_DEPENDENCIES = 20
MAX_TARGETS = 50
MAX_DAYS = 3650
DEPENDENCY_KINDS = ("text", "finding", "asset")

#: The places the ROI (a ratio) and the payback (years) are shown to, half-even.
ROI_PLACES = 4
PAYBACK_PLACES = 2

#: What an ROI is, in every document that states one.
DECISION_SUPPORT = (
    "risk-adjusted ROI: the expected reduction in annual exposure over the first-year investment; decision support "
    "from modelled exposure, not a guaranteed return"
)
#: What a vetoed ROI says (the owner's specification, "Hard security veto").
VETO_STATEMENT = "remediation is required regardless of ROI"

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_TARGET = re.compile(r"[a-z0-9][a-z0-9_-]{0,99}/[a-z0-9][a-z0-9_-]{0,99}")

_REQUIRED = frozenset({"title", "implementation_cost", "recurring_cost", "time_to_implement_days", "control_effect"})
_OPTIONAL = frozenset({"dependencies", "utility_evidence"})
_EFFECT_OPTIONAL = frozenset({"frequency_reduction", "magnitude_reduction", "acts_on", "observed_by"})
_COST_REQUIRED = frozenset({"unit", "low", "base", "high", "currency", "source_type", "evidence_ref", "effective_date"})
_COST_OPTIONAL = frozenset({"fresh_until"})

#: What each of this step's refusal codes means. Codes the money and scenario
#: engines publish (``field_malformed``, ``unit_mismatch``, ``currency_mismatch``,
#: ``observed_source_not_observable`` and the rest) are raised as theirs.
REFUSALS: Mapping[str, str] = MappingProxyType(
    {
        "control_effect_missing": "a control effect states a frequency reduction, a magnitude reduction, or both",
        "acts_on_malformed": (
            "a control effect acts on every component, or on the loss families or the scenario's components "
            "(<event key>/<component key>) it names: one or the other, at least one, each once"
        ),
        "dependency_malformed": (
            f"a dependency is text (1 to {TEXT_MAX} characters) or a SPINE finding or asset named by its uuid, never "
            f"a copy; at most {MAX_DEPENDENCIES}"
        ),
        "dependency_not_found": "a finding or asset the option depends on is not one of this deployment's",
        "observed_effect_uncited": (
            "a reduction resting on MYTHOS_OBSERVED cites the retest it was observed in (the control effect's "
            "observed_by): nothing else makes a control effect observed"
        ),
        "observed_effect_not_stated": (
            "a control effect that cites a retest is observed: each reduction it states rests on MYTHOS_OBSERVED"
        ),
        "retest_unverifiable": (
            "the digest cited names no retest record of a finding this scenario rests on, in this deployment: a "
            "citation that cannot be verified is refused, never taken on trust"
        ),
        "retest_control_not_held": (
            "the cited retest does not show the control held: it is not its finding's latest record, or the retest "
            "gate's own verdict refuses it (every reason is named)"
        ),
        "remediation_target_unknown": "a component the control effect names is not one of the scenario's",
        "remediation_engine_unavailable": "the probabilistic engine will not import, so the reductions cannot be checked",
    }
)


class RemediationRefused(ValueError):
    """An option refused by this step's rules. ``code`` is one of :data:`REFUSALS`."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        super().__init__(f"{code}: {REFUSALS[code]}{suffix}")


# ------------------------------------------------------------ the option


@dataclass(frozen=True)
class Option:
    """An option as its document states it: the two costs and the two reductions as
    parameters (a reduction absent is ``None``), what the control effect acts on
    (``None``: every component), the citations, and the document in its one
    spelling (:attr:`document`), which the digest is taken over."""

    title: str
    implementation_cost: Parameter
    recurring_cost: Parameter
    time_to_implement_days: int
    dependencies: tuple[Mapping, ...]
    frequency_reduction: Parameter | None
    magnitude_reduction: Parameter | None
    distributions: Mapping[str, dict]
    families: tuple[str, ...] | None
    components: tuple[str, ...] | None
    observed_by: str | None
    utility_evidence: str | None
    document: Mapping

    @property
    def currency(self) -> str:
        return self.implementation_cost.currency

    def reductions(self) -> list[Parameter]:
        return [p for p in (self.frequency_reduction, self.magnitude_reduction) if p is not None]


def _entry_of(parameter: Parameter, distribution: dict | None = None, *, money: bool = False) -> dict:
    """A parameter in the document's one spelling: the parameter-set entry form."""
    entry = {
        "unit": parameter.unit.value,
        "low": Parameter.text(parameter.low),
        "base": Parameter.text(parameter.base),
        "high": Parameter.text(parameter.high),
        "source_type": parameter.source_type.value,
        "evidence_ref": parameter.evidence_ref,
        "effective_date": parameter.effective_date.isoformat(),
        "fresh_until": parameter.fresh_until.isoformat() if parameter.fresh_until else None,
    }
    if money:
        entry["currency"] = parameter.currency
    else:
        entry["distribution"] = distribution
    return entry


def _cost(entry, name: str, path: str) -> Parameter:
    entry = pset._object(entry, path, _COST_REQUIRED, _COST_OPTIONAL)
    if entry.get("fresh_until", "") is None:
        entry = {k: v for k, v in entry.items() if k != "fresh_until"}
    parameter = pset._parameter(name, Unit.MONEY, entry, path)
    return pset._money_is_not_observed(parameter, path)


def _reduction(entry, name: str, path: str, stated) -> tuple[Parameter, dict | None]:
    if not isinstance(entry, dict):
        raise ParameterRefused("field_malformed", f"{path} is not an object")
    entry = {k: v for k, v in entry.items() if not (k in ("fresh_until", "distribution") and v is None)}
    parameter = pset._parameter(name, Unit.RATIO, entry, path)
    distribution = stated(entry, path) if "distribution" in entry else None
    return parameter, distribution


def _digest_or_none(value, path: str) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise ParameterRefused("field_malformed", f"{path} is a retest record's digest, sha256: and 64 hex digits")
    return value


def _dependencies(value) -> tuple[dict, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or len(value) > MAX_DEPENDENCIES:
        raise RemediationRefused("dependency_malformed", f"dependencies is a list of at most {MAX_DEPENDENCIES}")
    found = []
    for index, item in enumerate(value):
        path = f"dependencies[{index}]"
        if not isinstance(item, dict) or set(item) not in ({"kind", "text"}, {"kind", "id"}):
            raise RemediationRefused("dependency_malformed", f"{path} is {{kind, text}} or {{kind, id}}")
        kind = item["kind"]
        if kind == "text" and "text" in item:
            text = item["text"]
            if not isinstance(text, str) or not text.strip() or len(text) > TEXT_MAX:
                raise RemediationRefused("dependency_malformed", f"{path}.text")
            found.append({"kind": "text", "text": text})
        elif kind in ("finding", "asset") and "id" in item:
            ident = item["id"]
            if not isinstance(ident, str) or not _UUID.fullmatch(ident):
                raise RemediationRefused("dependency_malformed", f"{path}.id is a {kind}'s uuid")
            found.append({"kind": kind, "id": ident})
        else:
            raise RemediationRefused("dependency_malformed", f"{path}.kind is one of {list(DEPENDENCY_KINDS)}")
    if len({json.dumps(item, sort_keys=True) for item in found}) != len(found):
        raise RemediationRefused("dependency_malformed", "a dependency is named twice")
    return tuple(found)


def _acts_on(value) -> tuple[tuple[str, ...] | None, tuple[str, ...] | None]:
    if value is None:
        return None, None
    if not isinstance(value, dict) or len(value) != 1 or not set(value) <= {"families", "components"}:
        raise RemediationRefused("acts_on_malformed", "acts_on is {families: [...]} or {components: [...]}")
    [(kind, names)] = value.items()
    if not isinstance(names, list) or not names or len(names) > MAX_TARGETS or len(set(map(str, names))) != len(names):
        raise RemediationRefused("acts_on_malformed", f"acts_on.{kind} names 1 to {MAX_TARGETS}, each once")
    for name in names:
        if kind == "families" and (not isinstance(name, str) or name not in COMPONENT_FAMILIES):
            raise RemediationRefused("acts_on_malformed", f"{name!r} is not a loss family or market value")
        if kind == "components" and (not isinstance(name, str) or not _TARGET.fullmatch(name)):
            raise RemediationRefused("acts_on_malformed", f"{name!r} is not <event key>/<component key>")
    names = tuple(sorted(names))
    return (names, None) if kind == "families" else (None, names)


def parse_option(body, *, stated=pset.stated_distribution) -> Option:
    """The option ``body`` states, held to every rule of its form, or refused: a
    money code, a parameter code or one of :data:`REFUSALS`. ``stated`` reads a
    reduction's stated distribution (the parameter set's reader: it imports the
    probabilistic engine only for one that states a distribution)."""
    body = pset._object(body, "body", _REQUIRED, _OPTIONAL)
    title = body["title"]
    if not isinstance(title, str) or not title.strip() or len(title) > TITLE_MAX:
        raise ParameterRefused("field_malformed", f"title is text of 1 to {TITLE_MAX} characters")
    implementation = _cost(body["implementation_cost"], IMPLEMENTATION_COST, "implementation_cost")
    recurring = _cost(body["recurring_cost"], RECURRING_COST, "recurring_cost")
    if implementation.currency != recurring.currency:
        raise MoneyRefused(
            "currency_mismatch",
            f"the implementation cost is in {implementation.currency}, the recurring cost in {recurring.currency}",
        )
    days = body["time_to_implement_days"]
    if isinstance(days, bool) or not isinstance(days, int) or not 0 <= days <= MAX_DAYS:
        raise ParameterRefused("field_malformed", f"time_to_implement_days is a whole number from 0 to {MAX_DAYS}")
    dependencies = _dependencies(body.get("dependencies"))
    effect = pset._object(body["control_effect"], "control_effect", frozenset(), _EFFECT_OPTIONAL)
    reductions: dict[str, tuple[Parameter, dict | None]] = {}
    for key, name in (("frequency_reduction", FREQUENCY_REDUCTION), ("magnitude_reduction", MAGNITUDE_REDUCTION)):
        if effect.get(key) is not None:
            reductions[name] = _reduction(effect[key], name, f"control_effect.{key}", stated)
    if not reductions:
        raise RemediationRefused("control_effect_missing")
    families, components = _acts_on(effect.get("acts_on"))
    observed_by = _digest_or_none(effect.get("observed_by"), "control_effect.observed_by")
    observed = [name for name, (p, _) in reductions.items() if p.source_type is SourceType.MYTHOS_OBSERVED]
    if observed and observed_by is None:
        raise RemediationRefused("observed_effect_uncited", ", ".join(observed))
    if observed_by is not None and len(observed) != len(reductions):
        unobserved = sorted(set(reductions) - set(observed))
        raise RemediationRefused("observed_effect_not_stated", ", ".join(unobserved))
    utility = _digest_or_none(body.get("utility_evidence"), "utility_evidence")
    frequency = reductions.get(FREQUENCY_REDUCTION)
    magnitude = reductions.get(MAGNITUDE_REDUCTION)
    document = {
        "title": title,
        "implementation_cost": _entry_of(implementation, money=True),
        "recurring_cost": _entry_of(recurring, money=True),
        "time_to_implement_days": days,
        "dependencies": [dict(item) for item in dependencies],
        "control_effect": {
            "frequency_reduction": None if frequency is None else _entry_of(*frequency),
            "magnitude_reduction": None if magnitude is None else _entry_of(*magnitude),
            "acts_on": None if families is None and components is None
            else ({"families": list(families)} if families is not None else {"components": list(components)}),
            "observed_by": observed_by,
        },
        "utility_evidence": utility,
    }
    return Option(
        title=title,
        implementation_cost=implementation,
        recurring_cost=recurring,
        time_to_implement_days=days,
        dependencies=dependencies,
        frequency_reduction=None if frequency is None else frequency[0],
        magnitude_reduction=None if magnitude is None else magnitude[0],
        distributions=MappingProxyType({name: d for name, (_, d) in reductions.items() if d is not None}),
        families=families,
        components=components,
        observed_by=observed_by,
        utility_evidence=utility,
        document=MappingProxyType(json.loads(json.dumps(document))),
    )


def canonical_digest(document) -> str:
    """``sha256:`` and the SHA-256 of a document's canonical JSON (sorted keys, no
    whitespace, ASCII, no NaN): the form every economics digest takes."""
    text = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)
    return "sha256:" + hashlib.sha256(text.encode("ascii")).hexdigest()


def option_digest(scenario_id: str, document: Mapping) -> str:
    """An option's identity: the digest of its schema, its scenario version and its
    document in the one spelling. The same option of the same version, in any key
    order, is one digest; any changed figure, source, target or citation is another."""
    return canonical_digest({"schema": OPTION_SCHEMA, "scenario": scenario_id, "document": dict(document)})


# ------------------------------------------------------------ the economics


@dataclass(frozen=True)
class Line:
    """One run's headline line, as its record states it (decimal strings read as
    Decimal): its expected annual exposure (``None`` without a frequency), its P90,
    and its P95 (``None`` unless the run's severe-but-plausible percentile is 95)."""

    expected_annual: Decimal | None
    p90: Decimal | None
    p95: Decimal | None


def line_of(record: Mapping) -> tuple[str, Line]:
    """The headline line of a completed run's record: its name (``retained_cash``
    under a policy, else ``gross_cash``, as the card and the receipt read it) and
    its figures at full precision."""
    scenario = record["scenario"]
    name = scenario["headline"]
    block = scenario[name]

    def decimal(text):
        return None if text is None else Decimal(text)

    p95 = decimal(block["severe_plausible"]) if Decimal(record["severe_percentile"]) == 95 else None
    return name, Line(decimal(block.get("expected_annual_exposure")), decimal(block["p90"]), p95)


def first_year_investment(option: Option) -> dict[str, Decimal]:
    """The implementation cost and one year of recurring cost, at each point, in
    the option's currency (full precision)."""
    return {
        point.value: compute(lambda p=point: option.implementation_cost.at(p).amount + option.recurring_cost.at(p).amount)
        for point in POINTS
    }


def _shown(amount: Decimal | None, currency: str) -> str | None:
    if amount is None:
        return None
    return format(Money(amount, currency).display_amount(), "f")


def _fixed(value: Decimal, places: int) -> str:
    return format(compute(lambda: value.quantize(Decimal(1).scaleb(-places), rounding=ROUND_HALF_EVEN)), "f")


def economics(current: Line, residual: Line, investment: Mapping[str, Decimal], currency: str, *, vetoed: bool
              ) -> dict:
    """The option's economics from the two runs' headline lines (spec, section 28):
    every money figure at the currency's minor unit, half-even; the ROI to
    :data:`ROI_PLACES` and the payback to :data:`PAYBACK_PLACES`, half-even; each
    from full precision. A figure that is not meaningful is ``None`` with the
    reason: an ROI over an investment of zero; a payback where the expected
    reduction is not above zero (never a negative or infinite one); anything of an
    expected annual exposure where the scenario has no frequency. ``vetoed``: the
    hard security veto applies, so the ROI and the payback are display-only."""
    base = investment["base"]
    if current.expected_annual is None or residual.expected_annual is None:
        why = "no expected annual exposure: the scenario states no frequency, so a run is per occurrence"
        reduction = None
        roi = {"value": None, "not_meaningful": why}
        payback = {"value": None, "not_meaningful": why}
    else:
        reduction = compute(lambda: current.expected_annual - residual.expected_annual)
        if base == 0:
            roi = {"value": None, "not_meaningful": "the first-year investment is zero: a ratio to it is not meaningful"}
        else:
            roi = {"value": _fixed(compute(lambda: reduction / base), ROI_PLACES), "not_meaningful": None}
        if reduction <= 0:
            payback = {
                "value": None,
                "not_meaningful": "the expected annual reduction is not above zero: modelled avoided loss never repays "
                "the investment, and no negative or infinite payback is shown",
            }
        else:
            payback = {"value": _fixed(compute(lambda: base / reduction), PAYBACK_PLACES), "not_meaningful": None}
    roi.update(statement=DECISION_SUPPORT, places=ROI_PLACES, display_only=vetoed)
    payback.update(unit="years", places=PAYBACK_PLACES, display_only=vetoed,
                   statement="the first-year investment over the expected annual reduction, where that reduction is "
                   "above zero")

    def tail(now: Decimal | None, after: Decimal | None, why: str) -> dict:
        if now is None or after is None:
            return {"current": _shown(now, currency), "residual": _shown(after, currency), "reduction": None,
                    "not_reported": why}
        return {"current": _shown(now, currency), "residual": _shown(after, currency),
                "reduction": _shown(compute(lambda: now - after), currency), "not_reported": None}

    return {
        "current_expected_annual_exposure": _shown(current.expected_annual, currency),
        "residual_expected_annual_exposure": _shown(residual.expected_annual, currency),
        "expected_reduction": _shown(reduction, currency),
        "first_year_investment": {point: _shown(amount, currency) for point, amount in investment.items()},
        "risk_adjusted_roi": roi,
        "payback": payback,
        "tail_reduction": {
            "p90": tail(current.p90, residual.p90, "a run without a P90"),
            "p95": tail(current.p95, residual.p95, "the runs' severe-but-plausible percentile is not 95"),
            "basis": "annual loss where the scenario states a frequency, else per occurrence",
        },
    }


#: The confidence grades in order, best first (spec, section 26.2); Unknown is not a
#: rung of the ladder.
_GRADE_ORDER = ("A", "B", "C", "D")


def confidence_delta(current: str | None, residual: str | None) -> dict:
    """The residual card's grade against the current card's, both as the card
    documents state them where they verify (``None``: no card, or one that does not
    verify): ``improved``, ``unchanged`` or ``worsened`` between two grades A to D,
    else ``not_comparable`` with the reason."""
    if current in _GRADE_ORDER and residual in _GRADE_ORDER:
        step = _GRADE_ORDER.index(current) - _GRADE_ORDER.index(residual)
        change = "improved" if step > 0 else "worsened" if step < 0 else "unchanged"
        return {"current": current, "residual": residual, "change": change, "not_comparable": None}
    missing = [side for side, grade in (("current", current), ("residual", residual)) if grade not in _GRADE_ORDER]
    return {
        "current": current,
        "residual": residual,
        "change": "not_comparable",
        "not_comparable": f"the {' and '.join(missing)} run's card is graded Unknown, is not recorded, or does not "
        "verify: there is no grade to compare",
    }


def lower_grade(current: str | None, residual: str | None) -> str | None:
    """The lower of two verified grades A to D (the worse evidence of the two runs
    the economics rest on); ``Unknown`` where either is Unknown, ``None`` where
    either has no verified card."""
    if current is None or residual is None:
        return None
    if current not in _GRADE_ORDER or residual not in _GRADE_ORDER:
        return "Unknown"
    return max(current, residual, key=_GRADE_ORDER.index)


def reduction_text(parameter: Parameter | None) -> dict | None:
    """A reduction's figures as a document shows them: as recorded (a parameter's
    figures are shown as entered, spec section 27.5)."""
    if parameter is None:
        return None
    return {point.value: decimal_text(parameter.at(point)) for point in POINTS} | {
        "source_type": parameter.source_type.value
    }


__all__ = [
    "DECISION_SUPPORT",
    "FREQUENCY_REDUCTION",
    "IMPLEMENTATION_COST",
    "MAGNITUDE_REDUCTION",
    "OPTION_SCHEMA",
    "RECURRING_COST",
    "REDUCTIONS",
    "REFUSALS",
    "RETEST_CITATION_SCHEMA",
    "ROI_SCHEMA",
    "VETO_STATEMENT",
    "Line",
    "Option",
    "RemediationRefused",
    "canonical_digest",
    "confidence_delta",
    "economics",
    "first_year_investment",
    "line_of",
    "lower_grade",
    "option_digest",
    "parse_option",
    "reduction_text",
]
