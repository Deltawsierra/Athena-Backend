"""Normalization: a historical native amount, in the reporting currency at the
valuation date, with every rate and index it went through.

The order is fixed (owner's specification, section 9; ``docs/economics/spec-v1.md``,
sections 3 and 12), and it is :data:`ORDER`:

1. the **native amount**, as recorded, never overwritten;
2. **event-date FX** into the base currency;
3. the **cost index** of the base currency, from the event date's month to the
   valuation date's;
4. **valuation-date FX** into the reporting currency.

Time-value change is applied in one currency, the base, between two FX steps that
each happen on their own date, so an exchange-rate move is never mixed with a
price move. Indexing first and converting at the valuation date instead applies
the base currency's inflation to an amount in another currency and prices a
historical cost at today's exchange rate: a different, wrong figure, and the
index step refuses to do it (``currency_mismatch``).

:func:`normalize` returns a :class:`Normalization`: ``normalized``, with its value
at full precision, its display figure, and the provenance chain; or
``unavailable``, naming the step that had nothing to go on and carrying the steps
done before it. It is never a number the policy did not allow. An estimate
(an interpolated rate) and a stale rate or index are flagged, and each carries a
confidence downgrade (:data:`DOWNGRADES`), which :meth:`Normalization.graded`
applies to a scenario's grade.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
from types import MappingProxyType

from .confidence import ConfidenceGrade, downgraded
from .cost_index import STALE_INDEX, IndexBook, IndexSelector, IndexStep, index
from .fx import ESTIMATED_RATE, STALE_RATE, FXBook, FXPolicy, FXStep, convert
from .money import (
    DISPLAY_ROUNDING,
    PRECISION,
    ROUNDING,
    Money,
    MoneyRefused,
    Unavailable,
    check_date,
    check_reporting_currency,
)

#: The normalization order. Nothing reorders it.
ORDER = ("event_fx", "cost_index", "valuation_fx")

NORMALIZED = "normalized"
UNAVAILABLE = "unavailable"

#: Every confidence downgrade a normalization may carry, and why.
DOWNGRADES = MappingProxyType(
    {
        ESTIMATED_RATE: "an exchange rate was interpolated because the policy allowed an estimate for a missing day",
        STALE_RATE: "an exchange rate is older than the policy's freshness limit for the day it was used for",
        STALE_INDEX: "the cost index for the valuation month was not published, and an earlier month was used",
    }
)


@dataclass(frozen=True)
class NormalizationPolicy:
    """The currencies and the rules one normalization runs under. The base and the
    reporting currency are each one an amount may be reported in (core's
    ``currency_unknown`` and ``currency_retired`` otherwise); the cost index is the
    base currency's."""

    base_currency: str
    reporting_currency: str
    fx: FXPolicy
    index: IndexSelector
    index_max_lag_months: int = 0

    def __post_init__(self):
        check_reporting_currency(self.base_currency, "base currency")
        check_reporting_currency(self.reporting_currency, "reporting currency")
        if not isinstance(self.fx, FXPolicy) or not isinstance(self.index, IndexSelector):
            raise MoneyRefused("policy_invalid", "a policy holds an FXPolicy and an IndexSelector")
        if self.index.currency != self.base_currency:
            raise MoneyRefused(
                "currency_mismatch",
                f"the cost index {self.index.series_id} prices {self.index.currency}; the base is {self.base_currency}",
            )
        if type(self.index_max_lag_months) is not int or self.index_max_lag_months < 0:
            raise MoneyRefused("policy_invalid", f"index_max_lag_months {self.index_max_lag_months!r}")

    def as_dict(self) -> dict:
        return {
            "base_currency": self.base_currency,
            "reporting_currency": self.reporting_currency,
            "fx": self.fx.as_dict(),
            "index": self.index.as_dict(),
            "index_max_lag_months": self.index_max_lag_months,
        }


@dataclass(frozen=True)
class Normalization:
    """A normalization's outcome. ``value`` is the reporting-currency amount at
    full precision, or ``None`` when ``status`` is ``unavailable``; ``native`` is
    the amount as given, unchanged; ``chain`` is every step done, in order."""

    status: str
    native: Money
    event_date: date
    valuation_date: date
    policy: NormalizationPolicy
    chain: tuple[FXStep | IndexStep, ...]
    value: Money | None = None
    unavailable: Unavailable | None = None

    @property
    def estimate(self) -> bool:
        return any(step.estimate for step in self.chain)

    @property
    def stale(self) -> bool:
        return any(step.stale for step in self.chain)

    @property
    def confidence_downgrades(self) -> tuple[str, ...]:
        return tuple(reason for step in self.chain for reason in step.downgrades)

    def graded(self, grade: ConfidenceGrade) -> ConfidenceGrade:
        """``grade`` lowered one step for each downgrade this normalization carries."""
        return downgraded(grade, len(self.confidence_downgrades))

    def display(self) -> str | None:
        return self.value.display() if self.value is not None else None

    def as_dict(self) -> dict:
        """The provenance record (``docs/economics/spec-v1.md``, section 12.6)."""
        return {
            "status": self.status,
            "native": self.native.as_dict(),
            "event_date": self.event_date.isoformat(),
            "valuation_date": self.valuation_date.isoformat(),
            "base_currency": self.policy.base_currency,
            "reporting_currency": self.policy.reporting_currency,
            "order": list(ORDER),
            "value": self.value.as_dict() if self.value is not None else None,
            "display": self.display(),
            "arithmetic": f"Decimal, {PRECISION} significant digits, {ROUNDING}",
            "display_rounding": f"{DISPLAY_ROUNDING} to the reporting currency's minor unit, for display only",
            "estimate": self.estimate,
            "stale": self.stale,
            "confidence_downgrades": list(self.confidence_downgrades),
            "unavailable": self.unavailable.as_dict() if self.unavailable is not None else None,
            "policy": self.policy.as_dict(),
            "chain": [step.as_dict() for step in self.chain],
        }


def normalize(
    native: Money,
    *,
    event_date: date,
    valuation_date: date,
    policy: NormalizationPolicy,
    fx_book: FXBook,
    index_book: IndexBook,
) -> Normalization:
    """``native``, recorded on ``event_date``, in ``policy.reporting_currency`` at
    ``valuation_date``, in :data:`ORDER`. See the module's rules."""
    if not isinstance(native, Money):
        raise TypeError(f"normalize takes Money, not {type(native).__name__}")
    if not isinstance(policy, NormalizationPolicy):
        raise TypeError("normalize runs under a NormalizationPolicy")
    check_date(event_date, "event_date")
    check_date(valuation_date, "valuation_date")
    if event_date > valuation_date:
        raise MoneyRefused("date_inversion", f"an event on {event_date} valued at {valuation_date}")

    def outcome(chain, value=None, unavailable=None):
        return Normalization(
            status=UNAVAILABLE if unavailable is not None else NORMALIZED,
            native=native,
            event_date=event_date,
            valuation_date=valuation_date,
            policy=policy,
            chain=tuple(chain),
            value=value,
            unavailable=unavailable,
        )

    chain: list[FXStep | IndexStep] = []
    # 2. Event-date FX into the base currency.
    step = convert(native, policy.base_currency, event_date, fx_book, policy.fx, step=ORDER[0])
    if isinstance(step, Unavailable):
        return outcome(chain, unavailable=step)
    chain.append(step)
    # 3. The base currency's cost index, event month to valuation month.
    step = index(
        step.output,
        event_date,
        valuation_date,
        index_book,
        policy.index,
        max_lag_months=policy.index_max_lag_months,
        as_of=valuation_date,
        step=ORDER[1],
    )
    if isinstance(step, Unavailable):
        return outcome(chain, unavailable=step)
    chain.append(step)
    # 4. Valuation-date FX into the reporting currency.
    step = convert(step.output, policy.reporting_currency, valuation_date, fx_book, policy.fx, step=ORDER[2])
    if isinstance(step, Unavailable):
        return outcome(chain, unavailable=step)
    chain.append(step)
    return outcome(chain, value=step.output)
