"""Money: a ``Decimal`` amount and the ISO 4217 code it is in.

The rules (owner's specification, sections 9 and 19; ``docs/economics/spec-v1.md``,
section 11):

- **Representation.** ``Money(amount, currency)``: the amount is a ``Decimal`` and
  nothing else. A float is refused on entry (``not_decimal``) -- ``0.1`` is not one
  tenth, and a figure built on it is wrong before anything is computed -- and so is
  an int or a string; :meth:`Money.parse` reads a decimal string. NaN and Infinity
  are refused (``not_finite``). The currency is a code core's table holds
  (``currency_unknown``) that has a minor unit (``currency_retired``, core's code
  for a code no amount is written in). A retired code with a minor unit (DEM, HRK)
  is a valid NATIVE amount -- a 1999 invoice was in marks -- but never a base or
  reporting currency (:func:`.currency.reporting_refusal`).
- **Precision.** Arithmetic runs in :func:`compute_context`: :data:`PRECISION`
  significant digits, :data:`ROUNDING`. Adding, subtracting and multiplying values
  of fewer digits than that is exact; a division (an inverted quote, an index
  ratio, an interpolation weight) is rounded at the 60th significant digit.
  Nothing is rounded to the minor unit while it is computed.
- **Display.** :meth:`Money.display_amount` rounds to the currency's minor unit
  with :data:`DISPLAY_ROUNDING`, ROUND_HALF_EVEN (banker's rounding: a tie goes to
  the even digit, so 0.125 USD shows as 0.12 and 0.135 as 0.14, 2.5 JPY as 2 and
  3.5 as 4). It returns a value to show, never a ``Money``: a rounded figure does
  not re-enter a calculation.
- **No mixing.** Two amounts in different currencies never add, subtract or
  compare (``currency_mismatch``, core's code): an amount changes currency only by
  a conversion that records its rate (:mod:`.fx`).
- **Never overwritten.** A ``Money`` is frozen. Converting or indexing one makes a
  new one, and the original stays in the provenance chain.

The refusal codes of the money, FX, cost-index and normalization engine are
:data:`REFUSALS`; :class:`MoneyRefused` carries one.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import date, datetime
from decimal import (
    ROUND_HALF_EVEN,
    Context,
    Decimal,
    DecimalException,
    DivisionByZero,
    InvalidOperation,
    Overflow,
    localcontext,
)
from types import MappingProxyType
from typing import ClassVar

from . import currency as _currency
from .governance import snapshot_hash_refusal

#: Significant digits every internal operation keeps.
PRECISION = 60
#: How an operation that cannot be exact at PRECISION digits rounds (a division).
ROUNDING = ROUND_HALF_EVEN
#: How an amount is rounded to its currency's minor unit, for display only.
DISPLAY_ROUNDING = ROUND_HALF_EVEN

#: What each refusal code of the E1 engine means. Codes that core or the E0
#: governance rules already publish keep their spelling and their meaning.
REFUSALS: Mapping[str, str] = MappingProxyType(
    {
        "not_decimal": (
            "an amount, a rate, an index value or a factor is a Decimal (in a snapshot, a decimal string): "
            "never a float, an int or a JSON number"
        ),
        "not_finite": "NaN and Infinity are not values any amount, rate or index may hold",
        "out_of_range": "the result is too large or too small to hold at the engine's precision",
        "currency_unknown": "the code is not an ISO 4217 code the table holds",
        "currency_retired": (
            "no amount is reported in this code: it is retired, or it has no minor unit; a retired code with a "
            "minor unit may still be a native amount, never a base or reporting currency"
        ),
        "currency_mismatch": (
            "two amounts in different currencies never add, subtract or compare, and an amount is never indexed "
            "or converted as if it were in another currency: it changes currency only by a recorded conversion"
        ),
        "rate_not_positive": "an exchange rate is greater than zero: a zero or negative rate is refused, never inverted",
        "rate_type_unrecognised": "a rate type is one of reference, mid, bid and ask",
        "pair_malformed": "an exchange rate's base and quote are two different codes",
        "index_value_not_positive": "a cost-index value is greater than zero",
        "index_series_mismatch": (
            "one cost-index series is one geography and one category: a series that mixes them, or a ratio of "
            "two different series, is refused"
        ),
        "period_malformed": "a cost-index period is a calendar month, written YYYY-MM",
        "date_malformed": "a date is a calendar date, and an instant a timezone-aware date and time",
        "date_inversion": (
            "a later date given as an earlier one: an event after its valuation date, or an index value "
            "published before its period ended"
        ),
        "observation_duplicate": (
            "two observations of the same provider, pair, rate type and date, or of the same series, period and "
            "vintage: a snapshot holds each once"
        ),
        "snapshot_hash_malformed": "a snapshot hash is 'sha256:' followed by 64 lowercase hexadecimal digits",
        "snapshot_hash_mismatch": "an observation carries the snapshot hash of the source version it was read from",
        "snapshot_malformed": "the snapshot document breaks its schema",
        "required_field_blank": "a required field is blank",
        "policy_invalid": "a normalization policy names a rule, a rate type, a provider or a limit this engine does not have",
        "value_precision": (
            "the value has more digits than its column holds exactly: it is refused, never rounded to fit"
        ),
    }
)


class MoneyRefused(ValueError):
    """An input the money, FX, cost-index or normalization engine refuses.
    ``code`` is one of :data:`REFUSALS`; ``detail`` says what was refused."""

    def __init__(self, code: str, detail: str = ""):
        self.code = code
        self.detail = detail
        suffix = f" ({detail})" if detail else ""
        super().__init__(f"{code}: {REFUSALS[code]}{suffix}")


def compute_context() -> Context:
    """The context every internal operation runs in: PRECISION significant digits,
    ROUNDING, and an invalid operation, a division by zero or an overflow raised,
    never turned into NaN or Infinity."""
    return Context(
        prec=PRECISION,
        rounding=ROUNDING,
        Emin=-999_999,
        Emax=999_999,
        traps=[InvalidOperation, DivisionByZero, Overflow],
    )


def compute(operation: Callable[[], Decimal]) -> Decimal:
    """Run ``operation`` in :func:`compute_context`; an arithmetic fault is
    ``out_of_range``, never a NaN carried on."""
    try:
        with localcontext(compute_context()):
            result = operation()
    except DecimalException as exc:
        raise MoneyRefused("out_of_range", type(exc).__name__) from None
    if not result.is_finite():
        raise MoneyRefused("out_of_range", str(result))
    return result


def check_decimal(value, what: str) -> Decimal:
    """``value`` itself when it is a finite ``Decimal``; refused otherwise. A float,
    an int, a bool and a string are all refused: only a ``Decimal`` is a value."""
    if not isinstance(value, Decimal):
        raise MoneyRefused("not_decimal", f"{what} is a {type(value).__name__}")
    if not value.is_finite():
        raise MoneyRefused("not_finite", f"{what} is {value}")
    return value


def parse_decimal(text, what: str) -> Decimal:
    """A finite ``Decimal`` read from a decimal string; anything else refused."""
    if not isinstance(text, str):
        raise MoneyRefused("not_decimal", f"{what} is a {type(text).__name__}, not a decimal string")
    try:
        value = Decimal(text.strip())
    except (InvalidOperation, ValueError):
        raise MoneyRefused("not_decimal", f"{what} {text!r} is not a decimal") from None
    return check_decimal(value, what)


def decimal_text(value: Decimal) -> str:
    """The one spelling of a value in a provenance record: plain notation, no
    exponent, no trailing zeros after the point (``1.1000`` and ``1.100000000`` are
    both ``1.1``), so a value read from a file and the same value read back from a
    column are written the same."""
    # Normalised at exactly its own number of digits, so nothing is rounded.
    exact = Context(prec=max(1, len(value.as_tuple().digits)), Emin=-999_999, Emax=999_999)
    text = format(value.normalize(exact), "f")
    return "0" if text in {"-0", "0"} else text


def check_text(**fields) -> None:
    """Every one of ``fields`` is text that is not blank (``required_field_blank``)."""
    for name, value in fields.items():
        if not isinstance(value, str) or not value.strip():
            raise MoneyRefused("required_field_blank", name)


def check_date(value, what: str) -> date:
    """A calendar date, never a datetime (which is a date too, in Python)."""
    if not isinstance(value, date) or isinstance(value, datetime):
        raise MoneyRefused("date_malformed", f"{what} is a {type(value).__name__}, not a date")
    return value


def check_instant(value, what: str) -> datetime:
    """A timezone-aware datetime: an instant no reader can place in two time zones."""
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
        raise MoneyRefused("date_malformed", f"{what} is not a timezone-aware datetime")
    return value


def check_snapshot_hash(value, what: str = "source_snapshot_hash") -> str:
    """``sha256:`` and 64 lowercase hex, the form the platform's digests take."""
    if snapshot_hash_refusal(value) is not None:
        raise MoneyRefused("snapshot_hash_malformed", what)
    return value


#: Why a value is unavailable. An unavailable value is a result, not an error: it
#: says which step had nothing to go on, and nothing is computed past it.
UNAVAILABLE_REASONS: Mapping[str, str] = MappingProxyType(
    {
        "rate_missing": (
            "no rate for the date: no provider the policy names published one for that day (or, on a day it does "
            "not publish, for its last publication day), and the policy does not allow an estimate, or no "
            "observation brackets the date closely enough to estimate one"
        ),
        "index_missing": (
            "no value of the cost-index series for the period, in any vintage published by the as-of date, "
            "within the lag the policy allows"
        ),
    }
)


@dataclass(frozen=True)
class Unavailable:
    """An explicit 'unavailable': the step that had nothing to go on, why
    (:data:`UNAVAILABLE_REASONS`), and what it looked for. Never a number, never
    an interpolation the policy did not ask for."""

    step: str
    reason: str
    detail: str

    status: ClassVar[str] = "unavailable"

    def __post_init__(self):
        if self.reason not in UNAVAILABLE_REASONS:
            raise ValueError(f"unknown unavailable reason {self.reason!r}")

    def as_dict(self) -> dict:
        return {"step": self.step, "reason": self.reason, "detail": self.detail}


def check_money_currency(code, what: str = "currency") -> str:
    """A code an amount may be written in: one the table holds, with a minor unit.
    A retired code with a minor unit passes (a native historical amount). Raises
    :class:`.currency.CurrencyTableInvalid` while core's table is not the pinned one."""
    _currency.require_pinned()
    if not isinstance(code, str) or code not in _currency.CURRENCIES:
        raise MoneyRefused("currency_unknown", f"{what} {code!r}")
    if _currency.CURRENCIES[code].minor_units is None:
        raise MoneyRefused("currency_retired", f"{what} {code} has no minor unit: no amount is written in it")
    return code


def check_reporting_currency(code, what: str = "reporting currency") -> str:
    """A code an amount may be REPORTED in (also a base currency): active, with a
    minor unit. Core's codes, for core's reasons."""
    refusal = _currency.reporting_refusal(code)
    if refusal is None:
        return code
    if refusal == _currency.CURRENCY_RETIRED:
        known = _currency.CURRENCIES[code]
        why = f"retired, succeeded by {known.successor}" if known.successor else "a code with no minor unit"
        raise MoneyRefused(refusal, f"{what} {code} is {why}")
    raise MoneyRefused(refusal, f"{what} {code!r}")


@dataclass(frozen=True)
class Money:
    """An amount and its currency. See the module's rules."""

    amount: Decimal
    currency: str

    def __post_init__(self):
        check_decimal(self.amount, "amount")
        check_money_currency(self.currency)

    @classmethod
    def parse(cls, text: str, currency: str) -> Money:
        """``Money`` from a decimal string (``"1234.56"``), never from a float."""
        return cls(parse_decimal(text, "amount"), currency)

    @classmethod
    def total(cls, amounts: Iterable[Money], currency: str) -> Money:
        """The sum of ``amounts``, every one of them in ``currency``; zero for none."""
        result = cls(Decimal(0), currency)
        for amount in amounts:
            result = result + amount
        return result

    # -- arithmetic: same currency only, full precision

    def _same(self, other, operation: str) -> Money:
        if not isinstance(other, Money):
            raise TypeError(f"{operation} takes Money, not {type(other).__name__}")
        if other.currency != self.currency:
            raise MoneyRefused(
                "currency_mismatch", f"{operation} of {self.currency} and {other.currency} without a conversion"
            )
        return other

    def __add__(self, other: Money) -> Money:
        other = self._same(other, "addition")
        return Money(compute(lambda: self.amount + other.amount), self.currency)

    def __sub__(self, other: Money) -> Money:
        other = self._same(other, "subtraction")
        return Money(compute(lambda: self.amount - other.amount), self.currency)

    def __neg__(self) -> Money:
        return Money(compute(lambda: -self.amount), self.currency)

    def times(self, factor: Decimal) -> Money:
        """This amount multiplied by ``factor`` (a ``Decimal``), in the same currency."""
        check_decimal(factor, "factor")
        return Money(compute(lambda: self.amount * factor), self.currency)

    def __mul__(self, factor) -> Money:
        return self.times(factor)

    __rmul__ = __mul__

    def __lt__(self, other: Money) -> bool:
        return self.amount < self._same(other, "comparison").amount

    def __le__(self, other: Money) -> bool:
        return self.amount <= self._same(other, "comparison").amount

    def __gt__(self, other: Money) -> bool:
        return self.amount > self._same(other, "comparison").amount

    def __ge__(self, other: Money) -> bool:
        return self.amount >= self._same(other, "comparison").amount

    # -- display: the minor unit, ROUND_HALF_EVEN, and nothing else

    def display_amount(self) -> Decimal:
        """The amount rounded to the currency's minor unit with DISPLAY_ROUNDING, to
        show. Never a ``Money``: a shown figure is not computed with again."""
        exponent = Decimal(1).scaleb(-_currency.minor_units(self.currency))
        return compute(lambda: self.amount.quantize(exponent, rounding=DISPLAY_ROUNDING))

    def display(self) -> str:
        """``"1309.52 EUR"``, ``"13271 JPY"``, ``"379.627 KWD"``."""
        return f"{self.display_amount():f} {self.currency}"

    def as_dict(self) -> dict:
        """The amount at full precision (:func:`decimal_text`) and its code."""
        return {"amount": decimal_text(self.amount), "currency": self.currency}

    def __str__(self) -> str:
        return f"{decimal_text(self.amount)} {self.currency}"
