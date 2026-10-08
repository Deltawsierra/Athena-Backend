"""Loss events, their totals, insurance, and the market-value line kept apart.

A loss event is the scenario that creates a financial consequence; its components
are the losses it causes, one per family and formula (owner's specification,
sections 6 and 15; ``docs/economics/spec-v1.md``, sections 16 and 17). The rules:

- **One id, one thing.** An event's components have distinct ids, and one
  parameter name denotes one parameter across the event (``duplicate_id``): a
  parameter read twice is the same parameter, never two that happen to share a
  name.
- **One currency.** Every component of an event is in the event's currency
  (``currency_mismatch``): amounts are normalized into it before (section 12).
- **Unknown is never zero.** The cash total of an event with an unknown cash
  component is ``complete: false``: its figures are the sum of the KNOWN
  components only, a floor, and the unknown components are named beside it. A
  report shows it as "at least", never as the event's loss.
- **Market value is never cash.** A ``market_value`` component is reported on its
  own line and never added to cash loss or to any family's total
  (``market_value_in_cash``; section 3, rule 5).
- **Insurance is applied once, after the gross components** (:func:`apply_insurance`),
  never to a loss already net of it (``insurance_applied_twice``), and the
  retained loss is never negative. Per point, the covered amount of each cash
  family is the sum of its components unless the family is excluded, capped at
  its sublimit; the recovery is ``min(max(covered - deductible, 0), limit)``; the
  retained loss is the gross loss less the recovery. The deductible and a waiting
  period move the retained loss up, the limit and a sublimit down, and the low,
  base and high retained loss read each term at the end that gives the smallest,
  the middle and the largest retained loss, as the formulas do (section 15).
  Insurance-family components (a premium rise) are never covered by the policy
  they are the cost of, and a policy with a waiting period does not cover
  business interruption at all in this version: the engine does not apportion an
  outage across the waiting period, so it takes the side that never understates
  the retained loss.
- The low total is the sum of the components' lows, the high the sum of their
  highs: each component is at the end of its own ranges, so a parameter two
  components read in opposite directions widens the range rather than narrowing
  it.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType

from .formulas import (
    CASH_FAMILIES,
    ESTIMATED,
    GROSS,
    MARKET_VALUE,
    Direction,
    InvariantBroken,
    LossComponent,
    check_family,
)
from .money import Money, MoneyRefused, check_money_currency, check_text
from .parameters import POINTS, Parameter, ParameterRefused, Point, Unit
from .taxonomy import LossFamily

#: Families a policy never covers, whatever its terms: an insurance-family
#: component is the policy's own cost (a premium rise), not a loss it pays.
NEVER_COVERED = frozenset({LossFamily.INSURANCE.value})

#: How each policy term moves the retained loss.
TERM_DIRECTIONS: Mapping[str, Direction] = MappingProxyType(
    {
        "deductible": Direction.INCREASES,
        "limit": Direction.DECREASES,
        "sublimit": Direction.DECREASES,
        "waiting_period_hours": Direction.INCREASES,
    }
)


def _end(direction: Direction, point: Point) -> Point:
    if point is Point.BASE:
        return Point.BASE
    if direction is Direction.INCREASES:
        return point
    return Point.HIGH if point is Point.LOW else Point.LOW


@dataclass(frozen=True)
class LossEvent:
    """One causal loss event and its components, every one in ``currency``."""

    loss_event_id: str
    currency: str
    components: tuple[LossComponent, ...]

    def __post_init__(self):
        check_text(loss_event_id=self.loss_event_id)
        check_money_currency(self.currency, "event currency")
        object.__setattr__(self, "components", tuple(self.components))
        ids: set[str] = set()
        named: dict[str, Parameter] = {}
        for component in self.components:
            if not isinstance(component, LossComponent):
                raise TypeError(f"an event holds LossComponents, not {type(component).__name__}")
            if component.component_id in ids:
                raise ParameterRefused("duplicate_id", f"component {component.component_id!r} twice in one event")
            ids.add(component.component_id)
            if component.currency is not None and component.currency != self.currency:
                raise MoneyRefused(
                    "currency_mismatch",
                    f"component {component.component_id} is in {component.currency}; the event is in {self.currency}",
                )
            for cited in component.inputs:
                for key in (cited.parameter.name, cited.parameter.parameter_id):
                    if key and key in named and named[key] != cited.parameter:
                        raise ParameterRefused(
                            "duplicate_id", f"two different parameters are both {key!r} in event {self.loss_event_id}"
                        )
                    if key:
                        named[key] = cited.parameter

    @property
    def cash_components(self) -> tuple[LossComponent, ...]:
        return tuple(c for c in self.components if c.family != MARKET_VALUE)

    @property
    def market_value_components(self) -> tuple[LossComponent, ...]:
        return tuple(c for c in self.components if c.family == MARKET_VALUE)


@dataclass(frozen=True)
class Total:
    """The sum of some components at each point. ``complete`` is false when any of
    them is unknown: the figures are then the known components' sum, a floor, and
    ``unknown`` names the rest."""

    currency: str
    low: Money
    base: Money
    high: Money
    complete: bool
    unknown: tuple[str, ...] = ()

    def at(self, point: Point) -> Money:
        return {Point.LOW: self.low, Point.BASE: self.base, Point.HIGH: self.high}[Point(point)]

    def as_dict(self) -> dict:
        return {
            "currency": self.currency,
            "low": self.low.as_dict()["amount"],
            "base": self.base.as_dict()["amount"],
            "high": self.high.as_dict()["amount"],
            "display": {point.value: self.at(point).display() for point in POINTS},
            "complete": self.complete,
            "reads_as": "the loss" if self.complete else "at least: the known components only",
            "unknown_components": list(self.unknown),
        }


def _total(components: Iterable[LossComponent], currency: str) -> Total:
    components = tuple(components)
    known = [c for c in components if c.status == ESTIMATED]
    unknown = tuple(c.component_id for c in components if c.status != ESTIMATED)
    sums = {point: Money.total((c.at(point) for c in known), currency) for point in POINTS}
    return Total(currency, sums[Point.LOW], sums[Point.BASE], sums[Point.HIGH], not unknown, unknown)


def cash_total(components: Iterable[LossComponent], currency: str) -> Total:
    """The gross cash loss of ``components``. A market-value component is refused
    (``market_value_in_cash``), never added."""
    components = tuple(components)
    for component in components:
        if component.family == MARKET_VALUE:
            raise ParameterRefused("market_value_in_cash", component.component_id)
    return _total(components, currency)


def market_value_total(components: Iterable[LossComponent], currency: str) -> Total:
    """The market-value line: market-value components only, reported apart."""
    components = tuple(components)
    for component in components:
        if component.family != MARKET_VALUE:
            raise ParameterRefused("loss_family_unrecognised", f"{component.component_id} is not market value")
    return _total(components, currency)


@dataclass(frozen=True)
class GrossLoss:
    """An event's cash loss before insurance: its cash components and their total."""

    event: LossEvent
    total: Total

    @classmethod
    def of(cls, event: LossEvent) -> GrossLoss:
        return cls(event, cash_total(event.cash_components, event.currency))


@dataclass(frozen=True)
class InsurancePolicy:
    """The terms insurance is applied on: a deductible, an aggregate limit, per-family
    sublimits, excluded families and, optionally, a waiting period. Each amount is a
    money parameter, and the waiting period an hours parameter, so its provenance is
    kept like any other input's."""

    deductible: Parameter
    limit: Parameter
    sublimits: Mapping[str, Parameter] = field(default_factory=dict)
    exclusions: frozenset[str] = frozenset()
    waiting_period_hours: Parameter | None = None

    def __post_init__(self):
        for name, term in (("deductible", self.deductible), ("limit", self.limit)):
            self._money_term(name, term)
        object.__setattr__(self, "sublimits", MappingProxyType(dict(self.sublimits)))
        for family, term in self.sublimits.items():
            self._cash_family(family)
            self._money_term(f"sublimit {family}", term)
        object.__setattr__(self, "exclusions", frozenset(self.exclusions))
        for family in self.exclusions:
            self._cash_family(family)
        if self.waiting_period_hours is not None:
            if not isinstance(self.waiting_period_hours, Parameter):
                raise TypeError("the waiting period is a Parameter")
            if self.waiting_period_hours.unit is not Unit.HOURS:
                raise ParameterRefused("unit_mismatch", f"the waiting period is {self.waiting_period_hours.unit}")
        currencies = {self.deductible.currency, self.limit.currency} | {t.currency for t in self.sublimits.values()}
        if len(currencies) != 1:
            raise MoneyRefused("currency_mismatch", f"a policy's terms span {sorted(currencies)}")

    @staticmethod
    def _money_term(name: str, term) -> None:
        if not isinstance(term, Parameter):
            raise TypeError(f"the {name} is a Parameter")
        if term.unit is not Unit.MONEY:
            raise ParameterRefused("unit_mismatch", f"the {name} is {term.unit}, not money")

    @staticmethod
    def _cash_family(family) -> None:
        check_family(family)
        if family not in CASH_FAMILIES:
            raise ParameterRefused("loss_family_unrecognised", f"{family} is not cash loss: no policy covers it")

    @property
    def currency(self) -> str:
        return self.deductible.currency

    def term(self, name: str, parameter: Parameter, point: Point) -> Money:
        return parameter.at(_end(TERM_DIRECTIONS[name], point))

    def as_dict(self) -> dict:
        return {
            "deductible": self.deductible.as_dict(),
            "limit": self.limit.as_dict(),
            "sublimits": {family: term.as_dict() for family, term in sorted(self.sublimits.items())},
            "exclusions": sorted(self.exclusions),
            "waiting_period_hours": self.waiting_period_hours.as_dict() if self.waiting_period_hours else None,
            "never_covered": sorted(NEVER_COVERED),
            "term_directions": {name: direction.value for name, direction in TERM_DIRECTIONS.items()},
        }


@dataclass(frozen=True)
class InsuredPoint:
    """Insurance at one point: what was gross, covered, recovered and retained."""

    gross: Money
    covered: Money
    recovery: Money
    retained: Money
    covered_by_family: Mapping[str, Money]
    uncovered_families: tuple[str, ...]

    def as_dict(self) -> dict:
        return {
            "gross": self.gross.as_dict()["amount"],
            "covered": self.covered.as_dict()["amount"],
            "recovery": self.recovery.as_dict()["amount"],
            "retained": self.retained.as_dict()["amount"],
            "covered_by_family": {f: m.as_dict()["amount"] for f, m in sorted(self.covered_by_family.items())},
            "uncovered_families": list(self.uncovered_families),
        }


@dataclass(frozen=True)
class InsuredLoss:
    """An event's cash loss net of insurance, applied once. ``complete`` is the
    gross total's: insurance on the known components of an incomplete total gives
    a retained floor."""

    gross: GrossLoss
    policy: InsurancePolicy
    points: Mapping[Point, InsuredPoint]

    @property
    def retained(self) -> Total:
        total = self.gross.total
        return Total(
            total.currency,
            self.points[Point.LOW].retained,
            self.points[Point.BASE].retained,
            self.points[Point.HIGH].retained,
            total.complete,
            total.unknown,
        )

    def as_dict(self) -> dict:
        return {
            "applied": "once, after the gross components",
            "policy": self.policy.as_dict(),
            "points": {point.value: self.points[point].as_dict() for point in POINTS},
            "retained": self.retained.as_dict(),
        }


def apply_insurance(gross: GrossLoss, policy: InsurancePolicy) -> InsuredLoss:
    """``gross`` net of ``policy``, applied once. See the module's rules."""
    if isinstance(gross, InsuredLoss):
        raise ParameterRefused("insurance_applied_twice", "the loss is already net of insurance")
    if not isinstance(gross, GrossLoss):
        raise TypeError(f"insurance applies to a GrossLoss, not {type(gross).__name__}")
    if not isinstance(policy, InsurancePolicy):
        raise TypeError("insurance applies an InsurancePolicy")
    for component in gross.event.cash_components:
        if component.insurance_treatment != GROSS:
            raise ParameterRefused("insurance_applied_twice", f"{component.component_id} is not gross")
    currency = gross.total.currency
    if policy.currency != currency:
        raise MoneyRefused("currency_mismatch", f"the policy is in {policy.currency}; the loss in {currency}")
    zero = Money.total((), currency)
    known = [c for c in gross.event.cash_components if c.status == ESTIMATED]

    points: dict[Point, InsuredPoint] = {}
    for point in POINTS:
        waiting = (
            policy.waiting_period_hours.at(_end(TERM_DIRECTIONS["waiting_period_hours"], point))
            if policy.waiting_period_hours is not None
            else None
        )
        uncovered = set(policy.exclusions) | NEVER_COVERED
        if waiting is not None and waiting > 0:
            uncovered.add(LossFamily.BUSINESS_INTERRUPTION.value)
        by_family: dict[str, Money] = {}
        for component in known:
            if component.family in uncovered:
                continue
            by_family[component.family] = by_family.get(component.family, zero) + component.at(point)
        for family, amount in list(by_family.items()):
            if family in policy.sublimits:
                cap = policy.term("sublimit", policy.sublimits[family], point)
                by_family[family] = amount if amount <= cap else cap
        covered = Money.total(by_family.values(), currency)
        deductible = policy.term("deductible", policy.deductible, point)
        limit = policy.term("limit", policy.limit, point)
        excess = covered - deductible
        if excess < zero:
            excess = zero
        recovery = excess if excess <= limit else limit
        gross_amount = gross.total.at(point)
        retained = gross_amount - recovery
        points[point] = InsuredPoint(
            gross=gross_amount,
            covered=covered,
            recovery=recovery,
            retained=retained,
            covered_by_family=MappingProxyType(by_family),
            uncovered_families=tuple(sorted(uncovered)),
        )
    retained = [points[p].retained.amount for p in POINTS]
    if not (0 <= retained[0] <= retained[1] <= retained[2]):
        raise InvariantBroken(f"insurance broke its invariants: retained {retained}")
    return InsuredLoss(gross, policy, MappingProxyType(points))


@dataclass(frozen=True)
class Assessment:
    """An event assessed: its gross cash loss, the loss net of insurance where a
    policy is given, and the market-value line, never added to either."""

    event: LossEvent
    gross: GrossLoss
    insured: InsuredLoss | None
    market_value: Total

    def as_dict(self) -> dict:
        return {
            "loss_event_id": self.event.loss_event_id,
            "currency": self.event.currency,
            "gross_cash": self.gross.total.as_dict(),
            "insurance": self.insured.as_dict() if self.insured is not None else None,
            "retained_cash": self.insured.retained.as_dict() if self.insured is not None else None,
            "market_value": {
                **self.market_value.as_dict(),
                "never_added_to_cash": True,
                "components": [c.component_id for c in self.event.market_value_components],
            },
            "complete": self.gross.total.complete,
            "unknown_components": [c.component_id for c in self.event.components if c.status != ESTIMATED],
            "components": [c.as_dict() for c in self.event.components],
            "arithmetic": "Decimal, 60 significant digits, ROUND_HALF_EVEN; no seed, no sampling",
        }


def assess(event: LossEvent, policy: InsurancePolicy | None = None) -> Assessment:
    """Assess ``event``: gross cash loss, insurance once if ``policy`` is given, and
    the market-value line apart."""
    if not isinstance(event, LossEvent):
        raise TypeError(f"assess takes a LossEvent, not {type(event).__name__}")
    gross = GrossLoss.of(event)
    insured = apply_insurance(gross, policy) if policy is not None else None
    market = market_value_total(event.market_value_components, event.currency)
    return Assessment(event, gross, insured, market)
