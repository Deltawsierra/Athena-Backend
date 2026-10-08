"""The formula catalogue: deterministic low, base and high loss per component.

Each formula is a named, versioned function in plain explicit form, with a
formula id recorded beside every result it gives (``docs/economics/spec-v1.md``,
section 15). The rules:

- **Money arithmetic only.** A formula multiplies ``Money`` by ``Decimal``
  factors and adds ``Money`` to ``Money`` in one currency, at the engine's 60
  significant digits (section 11). Inputs in two currencies are
  ``currency_mismatch``; nothing converts here (that is the normalization's job,
  done before).
- **Units are checked.** Every input names its unit, and a parameter of another
  unit is ``unit_mismatch``.
- **A missing input is unknown, never zero.** A component with an input unbound
  is ``unknown``, naming what is missing, and carries no amount at all; so is one
  whose input rests on a source the formula does not accept (customer loss needs
  the customer's own churn figure). Totals never read an unknown as zero (see
  :mod:`.loss`).
- **Direction.** Every input says which way it moves the loss
  (:class:`Direction`): ``increases`` (a higher value never lowers the loss: a
  count, a duration, a rate, a unit cost) or ``decreases`` (a higher value never
  raises it: a recovery rate). The LOW result is computed from each input's low
  where it increases the loss and its high where it decreases it; the HIGH result
  the other way round; the BASE from every base. Every formula is monotone in
  every input over the values a parameter may hold (non-negative, ratios at most
  1), so the low result is the smallest the ranges allow and the high the largest.
- **Invariants.** ``0 <= low <= base <= high`` for every result, checked on every
  evaluation (:class:`InvariantBroken`, a defect, never an input's fault), and the
  same inputs give the same result: there is no randomness and no seed.

A formula serves the loss families it names. ``market_value`` is a component
family outside the fifteen (section 4.1): a share-price reaction, computed only
by ``share_price_reaction`` and never added to cash loss.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import date
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType

from .money import Money, MoneyRefused, check_date, check_text, compute
from .parameters import POINTS, Parameter, ParameterRefused, Point, Unit
from .provenance import SourceType
from .taxonomy import LossFamily

#: The component family of a market-value reaction: never a loss family, never cash.
MARKET_VALUE = "market_value"
#: The fifteen loss families: every one is cash loss.
CASH_FAMILIES = frozenset(family.value for family in LossFamily)
#: Every family a component may name.
COMPONENT_FAMILIES = CASH_FAMILIES | {MARKET_VALUE}

#: A component's status.
ESTIMATED = "estimated"
UNKNOWN = "unknown"

#: Why a component is unknown. An unknown component has no amount, and nothing
#: reads it as zero.
UNKNOWN_REASONS: Mapping[str, str] = MappingProxyType(
    {
        "input_missing": "an input the formula needs has no parameter: the component is unknown, never zero",
        "input_source_not_accepted": (
            "an input rests on a source the formula does not accept for it (customer loss is computed only from "
            "the customer's own churn figure): the component is unknown"
        ),
    }
)

#: How a stored or computed component is held with respect to insurance: always
#: gross. Insurance is applied once, after the gross components (:mod:`.loss`).
GROSS = "gross"


class Direction(StrEnum):
    """Which way an input moves the loss."""

    INCREASES = "increases"
    DECREASES = "decreases"


class InvariantBroken(AssertionError):
    """A formula broke one of its own invariants (``low <= base <= high``, never
    negative). A defect in the engine, never an input's fault: inputs the engine
    accepts cannot break them."""


@dataclass(frozen=True)
class Input:
    """One input a formula takes: its name, unit, direction and meaning, and, where
    the formula restricts it, the source types it accepts."""

    name: str
    unit: Unit
    direction: Direction
    meaning: str
    accepted_sources: frozenset[SourceType] | None = None

    def end(self, point: Point) -> Point:
        """Which of the parameter's values this input reads for ``point``."""
        if point is Point.BASE:
            return Point.BASE
        low_end = Point.LOW if self.direction is Direction.INCREASES else Point.HIGH
        high_end = Point.HIGH if self.direction is Direction.INCREASES else Point.LOW
        return low_end if point is Point.LOW else high_end

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "unit": self.unit.value,
            "direction": self.direction.value,
            "meaning": self.meaning,
            "accepted_sources": sorted(s.value for s in self.accepted_sources) if self.accepted_sources else None,
        }


@dataclass(frozen=True)
class Formula:
    """One versioned formula: its id, version, expression in words, the families it
    serves, its inputs, and the function that computes it from one value per input."""

    formula_id: str
    version: int
    expression: str
    families: frozenset[str]
    inputs: tuple[Input, ...]
    calculate: Callable[[Mapping[str, Money | Decimal]], Money] = field(repr=False, compare=False)

    def __post_init__(self):
        # Plain codes, so a family read from a row and one named by the enum match.
        object.__setattr__(self, "families", frozenset(str(family) for family in self.families))

    @property
    def key(self) -> tuple[str, int]:
        return (self.formula_id, self.version)

    def input(self, name: str) -> Input:
        return next(i for i in self.inputs if i.name == name)

    def as_dict(self) -> dict:
        return {
            "formula_id": self.formula_id,
            "version": self.version,
            "expression": self.expression,
            "families": sorted(self.families),
            "inputs": [i.as_dict() for i in self.inputs],
        }


# ---------------------------------------------------------------- arithmetic


def _product(*factors: Decimal) -> Decimal:
    """The product of ``factors`` at the engine's precision."""

    def multiply() -> Decimal:
        result = Decimal(1)
        for factor in factors:
            result = result * factor
        return result

    return compute(multiply)


def _complement(ratio: Decimal) -> Decimal:
    """``1 - ratio``: what is NOT recovered, for a ratio from 0 to 1."""
    return compute(lambda: Decimal(1) - ratio)


def _per_hour(per_day: Decimal) -> Decimal:
    """A per-day count as a per-hour rate: ``per_day / 24``."""
    return compute(lambda: per_day / Decimal(24))


def _smaller(a: Money, b: Money) -> Money:
    return a if a <= b else b


INC = Direction.INCREASES
DEC = Direction.DECREASES

_ALL_CASH = CASH_FAMILIES
_FIXED_PLUS_HOURS_FAMILIES = frozenset(
    {
        LossFamily.INCIDENT_RESPONSE,
        LossFamily.RECOVERY,
        LossFamily.LEGAL,
        LossFamily.REGULATORY_COMPLIANCE,
        LossFamily.REMEDIATION_INVESTMENT,
        LossFamily.THIRD_PARTY_DOWNSTREAM,
        LossFamily.DATA_AND_IP,
        LossFamily.PHYSICAL_OPERATIONAL,
    }
)


def _formulas() -> tuple[Formula, ...]:
    return (
        Formula(
            "repeat_loss",
            1,
            "repeat_count x loss_per_event x (1 - recovery_rate)",
            frozenset({LossFamily.DIRECT_FINANCIAL}),
            (
                Input("repeat_count", Unit.COUNT, INC, "how many times the loss repeats"),
                Input("loss_per_event", Unit.MONEY_PER_UNIT, INC, "the amount lost each time"),
                Input("recovery_rate", Unit.RATIO, DEC, "the share of the amount recovered (a higher rate lowers loss)"),
            ),
            lambda v: v["loss_per_event"].times(_product(v["repeat_count"], _complement(v["recovery_rate"]))),
        ),
        Formula(
            "repeat_in_window",
            1,
            "transactions_per_day / 24 x window_hours x success_rate x value_per_transaction x (1 - recovery_rate)",
            frozenset({LossFamily.DIRECT_FINANCIAL}),
            (
                Input("transactions_per_day", Unit.COUNT_PER_DAY, INC, "relevant transactions per day"),
                Input("window_hours", Unit.HOURS, INC, "how long the condition stays exploitable before detection"),
                Input("success_rate", Unit.RATIO, INC, "the share of attempts that create the unauthorized effect"),
                Input("value_per_transaction", Unit.MONEY_PER_UNIT, INC, "the average relevant transaction value"),
                Input("recovery_rate", Unit.RATIO, DEC, "the share of the amount recovered (a higher rate lowers loss)"),
            ),
            lambda v: v["value_per_transaction"].times(
                _product(
                    _per_hour(v["transactions_per_day"]),
                    v["window_hours"],
                    v["success_rate"],
                    _complement(v["recovery_rate"]),
                )
            ),
        ),
        Formula(
            "interruption",
            1,
            "interruption_hours x value_per_hour",
            frozenset({LossFamily.BUSINESS_INTERRUPTION, LossFamily.PHYSICAL_OPERATIONAL}),
            (
                Input("interruption_hours", Unit.HOURS, INC, "how long the service or operation is interrupted"),
                Input("value_per_hour", Unit.MONEY_PER_HOUR, INC, "revenue or margin lost per hour (its evidence says which)"),
            ),
            lambda v: v["value_per_hour"].times(v["interruption_hours"]),
        ),
        Formula(
            "fixed_plus_hours",
            1,
            "fixed_cost + hourly_rate x hours",
            _FIXED_PLUS_HOURS_FAMILIES,
            (
                Input("fixed_cost", Unit.MONEY, INC, "a fixed amount: a retainer, a fixed fee, a campaign"),
                Input("hourly_rate", Unit.MONEY_PER_HOUR, INC, "a loaded hourly rate"),
                Input("hours", Unit.HOURS, INC, "the hours worked"),
            ),
            lambda v: v["fixed_cost"] + v["hourly_rate"].times(v["hours"]),
        ),
        Formula(
            "per_affected_plus_fixed",
            1,
            "affected x unit_cost + fixed_cost",
            frozenset(
                {
                    LossFamily.NOTIFICATION,
                    LossFamily.CUSTOMER_RESTITUTION,
                    LossFamily.THIRD_PARTY_DOWNSTREAM,
                    LossFamily.PHYSICAL_OPERATIONAL,
                    LossFamily.RECOVERY,
                }
            ),
            (
                Input("affected", Unit.COUNT, INC, "how many people, records, vendors or assets are affected"),
                Input("unit_cost", Unit.MONEY_PER_UNIT, INC, "the cost per affected one"),
                Input("fixed_cost", Unit.MONEY, INC, "a fixed amount: a campaign, a field team"),
            ),
            lambda v: v["unit_cost"].times(v["affected"]) + v["fixed_cost"],
        ),
        Formula(
            "per_affected",
            1,
            "affected x amount_per_affected",
            frozenset(
                {LossFamily.CUSTOMER_RESTITUTION, LossFamily.NOTIFICATION, LossFamily.THIRD_PARTY_DOWNSTREAM}
            ),
            (
                Input("affected", Unit.COUNT, INC, "how many customers or partners are owed"),
                Input("amount_per_affected", Unit.MONEY_PER_UNIT, INC, "the amount owed to each"),
            ),
            lambda v: v["amount_per_affected"].times(v["affected"]),
        ),
        Formula(
            "support_contacts",
            1,
            "affected x contact_rate x handling_hours x loaded_rate",
            frozenset({LossFamily.NOTIFICATION, LossFamily.CUSTOMER_RESTITUTION}),
            (
                Input("affected", Unit.COUNT, INC, "affected customers"),
                Input("contact_rate", Unit.RATIO, INC, "the share of them who contact support"),
                Input("handling_hours", Unit.HOURS, INC, "average handling time per contact"),
                Input("loaded_rate", Unit.MONEY_PER_HOUR, INC, "the loaded labor rate of a support agent"),
            ),
            lambda v: v["loaded_rate"].times(_product(v["affected"], v["contact_rate"], v["handling_hours"])),
        ),
        Formula(
            "capped_credit",
            1,
            "min(credit_per_hour x breach_hours, contract_cap)",
            frozenset({LossFamily.CONTRACTUAL}),
            (
                Input("credit_per_hour", Unit.MONEY_PER_HOUR, INC, "the SLA credit owed per hour of breach"),
                Input("breach_hours", Unit.HOURS, INC, "hours the SLA is breached"),
                Input("contract_cap", Unit.MONEY, INC, "the contract's cap on credits (a higher cap never lowers loss)"),
            ),
            lambda v: _smaller(v["credit_per_hour"].times(v["breach_hours"]), v["contract_cap"]),
        ),
        Formula(
            "replacement_share",
            1,
            "replacement_cost x share_compromised",
            frozenset({LossFamily.DATA_AND_IP}),
            (
                Input("replacement_cost", Unit.MONEY, INC, "what replacing the asset, data or model would cost"),
                Input("share_compromised", Unit.RATIO, INC, "the share of it compromised"),
            ),
            lambda v: v["replacement_cost"].times(v["share_compromised"]),
        ),
        Formula(
            "churned_margin",
            1,
            "customers x churn_rate x margin_per_customer_per_year x recovery_years",
            frozenset({LossFamily.CUSTOMER_LOSS}),
            (
                Input("customers", Unit.COUNT, INC, "customers exposed to the event"),
                Input(
                    "churn_rate",
                    Unit.RATIO,
                    INC,
                    "the extra share who leave because of it, from the customer's own retention data",
                    frozenset({SourceType.CUSTOMER_PROVIDED}),
                ),
                Input("margin_per_customer_per_year", Unit.MONEY_PER_UNIT, INC, "recurring margin per customer per year"),
                Input("recovery_years", Unit.YEARS, INC, "years until the lost margin is won back"),
            ),
            lambda v: v["margin_per_customer_per_year"].times(
                _product(v["customers"], v["churn_rate"], v["recovery_years"])
            ),
        ),
        Formula(
            "premium_increase",
            1,
            "premium_increase_per_year x years",
            frozenset({LossFamily.INSURANCE}),
            (
                Input("premium_increase_per_year", Unit.MONEY_PER_YEAR, INC, "the yearly rise in the insurance premium"),
                Input("years", Unit.YEARS, INC, "years the rise lasts"),
            ),
            lambda v: v["premium_increase_per_year"].times(v["years"]),
        ),
        Formula(
            "lump_sum",
            1,
            "amount",
            _ALL_CASH - {LossFamily.CUSTOMER_LOSS},
            (Input("amount", Unit.MONEY, INC, "an amount given as a range by its source (a quote, a benchmark, an estimate)"),),
            lambda v: v["amount"],
        ),
        Formula(
            "share_price_reaction",
            1,
            "market_capitalisation x price_decline",
            frozenset({MARKET_VALUE}),
            (
                Input("market_capitalisation", Unit.MONEY, INC, "the company's market capitalisation"),
                Input("price_decline", Unit.RATIO, INC, "the share-price decline attributed to the event"),
            ),
            lambda v: v["market_capitalisation"].times(v["price_decline"]),
        ),
    )


#: Every formula, by ``(formula_id, version)``. Read-only. A changed formula is a
#: new version; an old version stays, so a recorded result is recomputed exactly.
CATALOGUE: Mapping[tuple[str, int], Formula] = MappingProxyType({f.key: f for f in _formulas()})


def formula(formula_id: str, version: int) -> Formula:
    """The formula ``formula_id`` at ``version``; ``formula_unknown`` otherwise."""
    found = CATALOGUE.get((formula_id, version)) if isinstance(formula_id, str) and type(version) is int else None
    if found is None:
        raise ParameterRefused("formula_unknown", f"{formula_id!r} version {version!r}")
    return found


def check_family(family) -> str:
    if not isinstance(family, str) or family not in COMPONENT_FAMILIES:
        raise ParameterRefused("loss_family_unrecognised", repr(family))
    return family


# ------------------------------------------------------------------ results


@dataclass(frozen=True)
class CitedInput:
    """One input as a component read it: the parameter (with its source type and
    evidence), which of its values each result used, and those values."""

    input: Input
    parameter: Parameter
    stale: bool

    def value(self, point: Point) -> Money | Decimal:
        return self.parameter.at(self.input.end(point))

    def as_dict(self) -> dict:
        return {
            "input": self.input.name,
            "unit": self.input.unit.value,
            "direction": self.input.direction.value,
            "low_reads": self.input.end(Point.LOW).value,
            "high_reads": self.input.end(Point.HIGH).value,
            "values": {point.value: Parameter.text(self.value(point)) for point in POINTS},
            "stale": self.stale,
            "parameter": self.parameter.as_dict(),
        }


@dataclass(frozen=True)
class LossComponent:
    """One component of one loss event: its family, the formula that computed it
    and every parameter it read; ``estimated`` with a low, base and high, or
    ``unknown`` with none and the reason. Always gross of insurance."""

    component_id: str
    family: str
    formula: Formula
    as_of: date
    status: str
    currency: str | None
    inputs: tuple[CitedInput, ...]
    low: Money | None = None
    base: Money | None = None
    high: Money | None = None
    unknown_reason: str | None = None
    missing: tuple[str, ...] = ()
    insurance_treatment: str = GROSS

    @property
    def cash(self) -> bool:
        return self.family != MARKET_VALUE

    def at(self, point: Point) -> Money:
        if self.status != ESTIMATED:
            raise ValueError(f"component {self.component_id} is {self.status}: it has no {point} amount")
        return {Point.LOW: self.low, Point.BASE: self.base, Point.HIGH: self.high}[Point(point)]

    @property
    def stale_inputs(self) -> tuple[str, ...]:
        return tuple(cited.input.name for cited in self.inputs if cited.stale)

    def as_dict(self) -> dict:
        estimated = self.status == ESTIMATED
        return {
            "component_id": self.component_id,
            "family": self.family,
            "cash": self.cash,
            "formula": {
                "formula_id": self.formula.formula_id,
                "version": self.formula.version,
                "expression": self.formula.expression,
            },
            "status": self.status,
            "currency": self.currency,
            "low": self.low.as_dict()["amount"] if estimated else None,
            "base": self.base.as_dict()["amount"] if estimated else None,
            "high": self.high.as_dict()["amount"] if estimated else None,
            "unknown": None if estimated else {"reason": self.unknown_reason, "inputs": list(self.missing)},
            "insurance_treatment": self.insurance_treatment,
            "as_of": self.as_of.isoformat(),
            "stale_inputs": list(self.stale_inputs),
            "inputs": [cited.as_dict() for cited in self.inputs],
        }


def evaluate(
    component_id: str,
    family: str,
    formula_id: str,
    version: int,
    bindings: Mapping[str, Parameter],
    *,
    as_of: date,
) -> LossComponent:
    """The component ``component_id`` of ``family``, computed by the formula
    ``formula_id`` at ``version`` from ``bindings`` (formula input name to
    parameter), as of ``as_of``. See the module's rules."""
    check_text(component_id=component_id)
    check_family(family)
    chosen = formula(formula_id, version)
    if family not in chosen.families:
        raise ParameterRefused("formula_not_for_family", f"{formula_id} v{version} does not compute {family}")
    check_date(as_of, "as_of")
    if not isinstance(bindings, Mapping):
        raise TypeError("bindings map a formula input's name to a Parameter")
    names = {i.name for i in chosen.inputs}
    unrecognised = sorted(str(name) for name in bindings if name not in names)
    if unrecognised:
        raise ParameterRefused("input_unrecognised", f"{formula_id} v{version} takes no {unrecognised}")

    cited: list[CitedInput] = []
    seen: dict[str, Parameter] = {}
    for spec in chosen.inputs:
        parameter = bindings.get(spec.name)
        if parameter is None:
            continue
        if not isinstance(parameter, Parameter):
            raise TypeError(f"{spec.name} is bound to a {type(parameter).__name__}, not a Parameter")
        for key in (parameter.name, parameter.parameter_id):
            if key and key in seen and seen[key] != parameter:
                raise ParameterRefused("duplicate_id", f"two different parameters are both {key!r}")
        seen[parameter.name] = parameter
        if parameter.parameter_id:
            seen[parameter.parameter_id] = parameter
        if parameter.unit is not spec.unit:
            raise ParameterRefused(
                "unit_mismatch", f"{spec.name} takes {spec.unit}; {parameter.name} is {parameter.unit}"
            )
        cited.append(CitedInput(spec, parameter, parameter.check_as_of(as_of)))

    currencies = sorted({c.parameter.currency for c in cited if c.parameter.currency is not None})
    if len(currencies) > 1:
        raise MoneyRefused("currency_mismatch", f"{component_id} reads {currencies} without a conversion")
    currency = currencies[0] if currencies else None

    def unknown(reason: str, which: list[str]) -> LossComponent:
        return LossComponent(
            component_id=component_id,
            family=family,
            formula=chosen,
            as_of=as_of,
            status=UNKNOWN,
            currency=currency,
            inputs=tuple(cited),
            unknown_reason=reason,
            missing=tuple(which),
        )

    missing = [spec.name for spec in chosen.inputs if spec.name not in bindings]
    if missing:
        return unknown("input_missing", missing)
    refused = [
        c.input.name
        for c in cited
        if c.input.accepted_sources is not None and c.parameter.source_type not in c.input.accepted_sources
    ]
    if refused:
        return unknown("input_source_not_accepted", refused)

    results = {}
    for point in POINTS:
        result = chosen.calculate({c.input.name: c.value(point) for c in cited})
        if not isinstance(result, Money) or result.currency != currency:
            raise InvariantBroken(f"{formula_id} v{version} did not return Money in {currency}")
        results[point] = result
    low, base, high = (results[point] for point in POINTS)
    if not (Decimal(0) <= low.amount <= base.amount <= high.amount):
        raise InvariantBroken(
            f"{formula_id} v{version} gave low {low}, base {base}, high {high}: not 0 <= low <= base <= high"
        )
    return LossComponent(
        component_id=component_id,
        family=family,
        formula=chosen,
        as_of=as_of,
        status=ESTIMATED,
        currency=currency,
        inputs=tuple(cited),
        low=low,
        base=base,
        high=high,
    )
