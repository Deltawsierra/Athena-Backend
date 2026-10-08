"""Parameters: one named input to a loss formula, as a low, a base and a high
value, with its unit, the kind of source it rests on, and the evidence for it.

The rules (``docs/economics/spec-v1.md``, section 14):

- **A range, never one number.** A parameter has ``low <= base <= high``
  (``range_inverted`` otherwise). A value known exactly gives the same figure
  three times.
- **Units.** Every parameter names its :class:`Unit`. A money unit holds three
  ``Money`` in one currency (``currency_mismatch`` otherwise); a quantity unit
  holds three ``Decimal``. A ``Money`` given for a quantity, or a ``Decimal`` for
  money, is ``unit_mismatch``; a formula or a parameter-set variable that takes
  another unit refuses it with the same code. Nothing converts one unit into
  another: hours are never read as days.
- **Values.** Decimal only (``not_decimal``: a float is refused), finite
  (``not_finite``), never negative (``negative_value``: no benefit model exists
  yet), a ratio is a fraction from 0 to 1 (``ratio_out_of_range``), and a value
  has at most 30 digits before its point and 20 after (``value_too_long``).
- **Provenance.** Every parameter carries its ``source_type`` (section 4.2) and a
  non-blank evidence reference (``evidence_ref_missing``): what the figure rests
  on, a questionnaire answer, an evidence id, a benchmark's citation, the person
  who estimated it. Every component a formula computes carries each parameter it
  read, so the provenance stays attached to every output.
- **Dates.** ``effective_date`` is the date the value holds from; ``fresh_until``,
  when the source gives one, the last date it may be read as current. A
  ``fresh_until`` before ``effective_date`` is ``date_inversion``; a formula run
  as of a date before ``effective_date`` is ``date_inversion`` too, and one run
  after ``fresh_until`` flags the parameter stale.

Refusals the money engine already publishes (``not_decimal``, ``not_finite``,
``currency_mismatch``, ``date_malformed``, ``date_inversion``,
``required_field_blank``) are raised as :class:`.money.MoneyRefused` with their
own meaning; the new ones are :data:`REFUSALS`, raised as
:class:`ParameterRefused`, which is a ``MoneyRefused`` too, so one ``except``
catches every refusal of the engine.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType

from .money import Money, MoneyRefused, check_date, check_decimal, check_text, decimal_text
from .provenance import SourceType

#: What each refusal code of the scenario engine means. A code the money engine
#: publishes is raised as that engine's, with its meaning, and is not repeated here.
REFUSALS: Mapping[str, str] = MappingProxyType(
    {
        "unit_unrecognised": "a unit is one of the engine's units (money, count, ratio, hours and the rest)",
        "unit_mismatch": (
            "the parameter's unit is not the unit its formula input or parameter-set variable takes, or a money "
            "unit holds a quantity, or a quantity unit holds money: nothing converts one unit into another"
        ),
        "source_type_unrecognised": "a parameter's source_type is one of the eight source types",
        "evidence_ref_missing": "every parameter names the evidence or source it rests on",
        "negative_value": (
            "a count, duration, ratio or amount is never negative: no benefit model is enabled, so nothing "
            "reduces a loss below zero"
        ),
        "ratio_out_of_range": "a ratio is a fraction from 0 to 1",
        "value_too_long": (
            "a value has at most 30 digits before the point and 20 after it: a longer one is refused, never "
            "rounded, truncated or read as zero"
        ),
        "range_inverted": "a parameter's low is at most its base, and its base at most its high",
        "duplicate_id": (
            "one id names one thing: two parameters of one name, two components of one id in an event, or two "
            "variables of one name in a parameter set are refused, never one silently kept"
        ),
        "formula_unknown": "the formula id and version are not in the catalogue",
        "formula_not_for_family": "the formula does not compute a component of that loss family",
        "input_unrecognised": "a parameter is bound to an input the formula does not take",
        "loss_family_unrecognised": "a component family is one of the fifteen loss families or market_value",
        "insurance_applied_twice": (
            "insurance is applied once, to gross components: a loss already net of insurance, or a component "
            "not marked gross, is never insured again"
        ),
        "market_value_in_cash": (
            "a market-value component (a share-price or market-capitalisation reaction) is never added to cash "
            "loss or to any loss family's total"
        ),
        "field_unrecognised": "the parameter-set document holds a field or variable its schema does not",
        "field_missing": "the parameter-set document lacks a field its schema requires",
        "field_malformed": "a parameter-set field is not of the form its schema gives it (an object, a list, text)",
        "set_key_malformed": (
            "a parameter set's key is 1 to 100 characters: lowercase ASCII letters and digits, '-' and '_', "
            "starting with a letter or digit"
        ),
        "parent_required": "a financial parameter belongs to exactly one scenario or one parameter-set version",
        "parameter_set_sealed": (
            "a parameter-set version holds exactly the parameters it was recorded with: nothing is added to a "
            "recorded version, and a change is a new version"
        ),
        "parameter_not_found": "a cited parameter is not a recorded financial parameter",
    }
)


class ParameterRefused(MoneyRefused):
    """An input the scenario engine refuses. ``code`` is one of :data:`REFUSALS`;
    ``detail`` says what was refused. A :class:`.money.MoneyRefused`, so callers
    catch every engine refusal with one ``except``."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        ValueError.__init__(self, f"{code}: {REFUSALS[code]}{suffix}")


class Unit(StrEnum):
    """What a parameter's number measures. The value is the stable code."""

    MONEY = "money"
    MONEY_PER_UNIT = "money_per_unit"
    MONEY_PER_HOUR = "money_per_hour"
    MONEY_PER_YEAR = "money_per_year"
    COUNT = "count"
    COUNT_PER_DAY = "count_per_day"
    RATIO = "ratio"
    HOURS = "hours"
    DAYS = "days"
    YEARS = "years"


#: What each unit means, published beside it.
UNITS: Mapping[Unit, str] = MappingProxyType(
    {
        Unit.MONEY: "an amount of money, in the parameter's currency",
        Unit.MONEY_PER_UNIT: (
            "an amount per one thing: per event, transaction, record, customer, notice, vendor or asset (the "
            "parameter's name and evidence say which)"
        ),
        Unit.MONEY_PER_HOUR: "an amount per hour: a loaded labor rate, revenue or margin per hour",
        Unit.MONEY_PER_YEAR: "an amount per year: annual revenue, an annual license, a yearly premium increase",
        Unit.COUNT: "a number of things, possibly an expected (fractional) number",
        Unit.COUNT_PER_DAY: "a number of things per day: transactions per day",
        Unit.RATIO: "a fraction from 0 to 1: a recovery rate, a contact rate, a success rate, a margin",
        Unit.HOURS: "a duration in hours",
        Unit.DAYS: "a duration in days",
        Unit.YEARS: "a duration in years",
    }
)

#: The units whose values are ``Money``; every other unit's values are ``Decimal``.
MONEY_UNITS = frozenset({Unit.MONEY, Unit.MONEY_PER_UNIT, Unit.MONEY_PER_HOUR, Unit.MONEY_PER_YEAR})

#: The most digits a parameter's value has before its point, and after it. Fifty in
#: all, inside the engine's 60 significant digits, so a sum of values is exact; a
#: longer value is refused (``value_too_long``), never rounded, truncated or read
#: as zero.
MAX_INTEGER_DIGITS = 30
MAX_FRACTION_DIGITS = 20


class Point(StrEnum):
    """The three values every parameter and every result has."""

    LOW = "low"
    BASE = "base"
    HIGH = "high"


POINTS = (Point.LOW, Point.BASE, Point.HIGH)


def check_digits(value: Decimal, what: str) -> Decimal:
    """``value`` itself, when it has at most :data:`MAX_INTEGER_DIGITS` digits before
    its point and :data:`MAX_FRACTION_DIGITS` after it, as written (``1.000`` has three
    after); ``value_too_long`` otherwise. Read off the value's digits and exponent,
    so it costs nothing however long the value is."""
    _sign, digits, exponent = value.as_tuple()
    fraction = -exponent if exponent < 0 else 0
    integer = len(digits) + exponent
    if fraction > MAX_FRACTION_DIGITS or integer > MAX_INTEGER_DIGITS:
        raise ParameterRefused(
            "value_too_long",
            f"{what}: {max(integer, 0)} digits before the point and {fraction} after "
            f"(at most {MAX_INTEGER_DIGITS} and {MAX_FRACTION_DIGITS})",
        )
    return value


def check_unit(value) -> Unit:
    try:
        return Unit(value)
    except ValueError:
        raise ParameterRefused("unit_unrecognised", repr(value)) from None


def check_source_type(value) -> SourceType:
    try:
        return SourceType(value)
    except ValueError:
        raise ParameterRefused("source_type_unrecognised", repr(value)) from None


@dataclass(frozen=True)
class Parameter:
    """One named input: ``low``, ``base`` and ``high`` in ``unit``, resting on a
    ``source_type`` source named by ``evidence_ref``. See the module's rules.

    ``parameter_id`` is the stored row's id when there is one (the
    ``FinancialParameter``'s uuid), so a component cites the very row it read."""

    name: str
    unit: Unit
    source_type: SourceType
    low: Money | Decimal
    base: Money | Decimal
    high: Money | Decimal
    evidence_ref: str
    effective_date: date | None = None
    fresh_until: date | None = None
    parameter_id: str = ""

    def __post_init__(self):
        check_text(name=self.name)
        object.__setattr__(self, "unit", check_unit(self.unit))
        object.__setattr__(self, "source_type", check_source_type(self.source_type))
        values = (self.low, self.base, self.high)
        if self.unit in MONEY_UNITS:
            for point, value in zip(POINTS, values, strict=True):
                if not isinstance(value, Money):
                    raise ParameterRefused(
                        "unit_mismatch", f"{self.name} is {self.unit}, and its {point} is not Money"
                    )
            currencies = {value.currency for value in values}
            if len(currencies) != 1:
                raise MoneyRefused("currency_mismatch", f"{self.name} spans {sorted(currencies)}")
            amounts = [value.amount for value in values]
        else:
            for point, value in zip(POINTS, values, strict=True):
                if isinstance(value, Money):
                    raise ParameterRefused(
                        "unit_mismatch", f"{self.name} is {self.unit}, a quantity, and its {point} is Money"
                    )
                check_decimal(value, f"{self.name} {point}")
            amounts = list(values)
        for point, amount in zip(POINTS, amounts, strict=True):
            check_digits(amount, f"{self.name} {point}")
            if amount < 0:
                raise ParameterRefused("negative_value", f"{self.name} {point} is {amount}")
            if self.unit is Unit.RATIO and amount > 1:
                raise ParameterRefused("ratio_out_of_range", f"{self.name} {point} is {amount}")
        if not amounts[0] <= amounts[1] <= amounts[2]:
            raise ParameterRefused(
                "range_inverted", f"{self.name}: low {amounts[0]}, base {amounts[1]}, high {amounts[2]}"
            )
        if not isinstance(self.evidence_ref, str) or not self.evidence_ref.strip():
            raise ParameterRefused("evidence_ref_missing", self.name)
        if self.effective_date is not None:
            check_date(self.effective_date, f"{self.name} effective_date")
        if self.fresh_until is not None:
            check_date(self.fresh_until, f"{self.name} fresh_until")
            if self.effective_date is not None and self.fresh_until < self.effective_date:
                raise MoneyRefused(
                    "date_inversion",
                    f"{self.name} is fresh until {self.fresh_until}, before it holds from {self.effective_date}",
                )
        if not isinstance(self.parameter_id, str):
            raise TypeError("parameter_id is text")

    @property
    def currency(self) -> str | None:
        """The currency of a money parameter; ``None`` for a quantity."""
        return self.low.currency if isinstance(self.low, Money) else None

    def at(self, point: Point) -> Money | Decimal:
        """The value at ``point``."""
        return {Point.LOW: self.low, Point.BASE: self.base, Point.HIGH: self.high}[Point(point)]

    def check_as_of(self, as_of: date) -> bool:
        """Refuse a run as of a date before the value holds (``date_inversion``);
        return whether the value is stale on ``as_of`` (past ``fresh_until``)."""
        check_date(as_of, "as_of")
        if self.effective_date is not None and as_of < self.effective_date:
            raise MoneyRefused(
                "date_inversion", f"{self.name} holds from {self.effective_date}, after the run's as-of {as_of}"
            )
        return self.fresh_until is not None and as_of > self.fresh_until

    @staticmethod
    def text(value: Money | Decimal) -> str:
        """A value's amount in the one decimal spelling (section 12.6)."""
        return decimal_text(value.amount if isinstance(value, Money) else value)

    def as_dict(self) -> dict:
        return {
            "name": self.name,
            "parameter_id": self.parameter_id or None,
            "unit": self.unit.value,
            "currency": self.currency,
            "low": self.text(self.low),
            "base": self.text(self.base),
            "high": self.text(self.high),
            "source_type": self.source_type.value,
            "evidence_ref": self.evidence_ref,
            "effective_date": self.effective_date.isoformat() if self.effective_date else None,
            "fresh_until": self.fresh_until.isoformat() if self.fresh_until else None,
        }
