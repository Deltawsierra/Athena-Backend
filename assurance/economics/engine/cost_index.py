"""Cost indices: the observation contract, the book an indexing step reads, and
the step that moves an amount from one date's prices to another's.

An :class:`IndexPoint` is one published value of one series -- a consumer-price
index, a legal-services producer-price index (owner's specification, section 13)
-- for one calendar month, in one vintage: series id, geography, category, the
base it is expressed on (``2020-03=100``), period (``YYYY-MM``), value, the date
that vintage was published, and the snapshot it was read from. It is the pure mirror of
:class:`assurance.economics.models.CostIndexObservation`.

:func:`index` multiplies an amount by ``value(to period) / value(from period)``
(``docs/economics/spec-v1.md``, section 12):

- **One series, one base, one currency.** A series is one geography, one
  category and one base: a book whose series mixes them is refused
  (``index_series_mismatch``), so a ratio's two values are always on the same
  base -- a series rebased from ``2020-03=100`` to ``2026=100`` is two series, and
  dividing a value on one by a value on the other is refused, never read as
  inflation or deflation. An :class:`IndexSelector` names the series, its
  geography, category and base, and the currency its prices are in. An amount in
  any other currency is never indexed by it (``currency_mismatch``).
- **Vintages.** Each period's value is the latest vintage published on or before
  the as-of date (the valuation date unless the policy says otherwise), and the
  step records which.
- **A missing value is unavailable.** The event period's value is that month's or
  nothing. The valuation period's may be the latest published month within
  ``max_lag_months`` of it, when the policy allows a lag: the step records the
  rule and the lag, and is flagged stale, with a confidence downgrade
  (``stale_index``). Otherwise ``index_missing``. Nothing is interpolated.
- **Dates in order.** An index from a later date to an earlier one is
  ``date_inversion``.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date
from decimal import Decimal
from types import MappingProxyType

from .money import (
    Money,
    MoneyRefused,
    Unavailable,
    check_date,
    check_decimal,
    check_reporting_currency,
    check_snapshot_hash,
    check_text,
    compute,
    decimal_text,
)

_PERIOD = re.compile(r"([0-9]{4})-(0[1-9]|1[0-2])")

#: The rule an indexing step records for the valuation end.
EXACT_PERIOD = "exact_period"
LATEST_PUBLISHED_PERIOD = "latest_published_period"
#: The confidence downgrade a lagged index carries.
STALE_INDEX = "stale_index"


def check_period(value) -> str:
    """A calendar month, ``YYYY-MM``."""
    if not isinstance(value, str) or not _PERIOD.fullmatch(value):
        raise MoneyRefused("period_malformed", repr(value))
    return value


def period_of(day: date) -> str:
    return f"{day.year:04d}-{day.month:02d}"


def period_start(period: str) -> date:
    year, month = _PERIOD.fullmatch(check_period(period)).groups()
    return date(int(year), int(month), 1)


def shift_period(period: str, months: int) -> str:
    """The period ``months`` before ``period`` (``months`` >= 0)."""
    start = period_start(period)
    index = start.year * 12 + (start.month - 1) - months
    return f"{index // 12:04d}-{index % 12 + 1:02d}"


@dataclass(frozen=True)
class IndexPoint:
    """One published value of one cost-index series for one month, in one vintage."""

    series_id: str
    geography: str
    category: str
    #: What the values are expressed relative to (``2020-03=100``): part of the
    #: series' identity, so two values on different bases are never divided.
    base: str
    period: str
    value: Decimal
    vintage_date: date
    source_snapshot_hash: str
    source_key: str = ""
    source_version: int | None = None

    def __post_init__(self):
        check_text(series_id=self.series_id, geography=self.geography, category=self.category, base=self.base)
        check_period(self.period)
        check_decimal(self.value, "index value")
        if self.value <= 0:
            raise MoneyRefused("index_value_not_positive", f"{self.series_id} {self.period} {self.value}")
        check_date(self.vintage_date, "vintage_date")
        if self.vintage_date < period_start(self.period):
            raise MoneyRefused(
                "date_inversion",
                f"{self.series_id} {self.period} published on {self.vintage_date}, before the period began",
            )
        check_snapshot_hash(self.source_snapshot_hash)

    def as_provenance(self) -> dict:
        return {
            "series_id": self.series_id,
            "geography": self.geography,
            "category": self.category,
            "base": self.base,
            "period": self.period,
            "value": decimal_text(self.value),
            "vintage_date": self.vintage_date.isoformat(),
            "source_snapshot_hash": self.source_snapshot_hash,
            "source_key": self.source_key,
            "source_version": self.source_version,
        }


@dataclass(frozen=True)
class IndexSelector:
    """Which series an amount is indexed by -- its id, geography, category and
    base -- and the currency its prices are in."""

    series_id: str
    geography: str
    category: str
    base: str
    currency: str

    def __post_init__(self):
        check_text(series_id=self.series_id, geography=self.geography, category=self.category, base=self.base)
        check_reporting_currency(self.currency, "index currency")

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.geography, self.category, self.base)

    def as_dict(self) -> dict:
        return {
            "series_id": self.series_id,
            "geography": self.geography,
            "category": self.category,
            "base": self.base,
            "currency": self.currency,
        }


class IndexBook:
    """The index values an indexing step may read. A series is one geography, one
    category and one base; each (series, period, vintage) is held once."""

    def __init__(self, points: Iterable[IndexPoint]):
        series: dict[str, tuple[str, str, str]] = {}
        values: dict[str, dict[str, dict[date, IndexPoint]]] = {}
        for point in points:
            if not isinstance(point, IndexPoint):
                raise TypeError(f"an IndexBook holds IndexPoints, not {type(point).__name__}")
            own = (point.geography, point.category, point.base)
            identity = series.setdefault(point.series_id, own)
            if identity != own:
                raise MoneyRefused(
                    "index_series_mismatch",
                    f"{point.series_id} is (geography, category, base) {identity}, and also {own}",
                )
            vintages = values.setdefault(point.series_id, {}).setdefault(point.period, {})
            if point.vintage_date in vintages:
                raise MoneyRefused(
                    "observation_duplicate", f"{point.series_id} {point.period} vintage {point.vintage_date}"
                )
            vintages[point.vintage_date] = point
        self._series = MappingProxyType(series)
        self._values = MappingProxyType(values)

    def value(self, selector: IndexSelector, period: str, as_of: date) -> IndexPoint | None:
        """The latest vintage of ``selector``'s value for ``period`` published on or
        before ``as_of``, or ``None``."""
        identity = self._series.get(selector.series_id)
        if identity is None:
            return None
        if identity != selector.identity:
            raise MoneyRefused(
                "index_series_mismatch",
                f"{selector.series_id} is (geography, category, base) {identity}, not {selector.identity}",
            )
        vintages = self._values[selector.series_id].get(period, {})
        published = [vintage for vintage in vintages if vintage <= as_of]
        return vintages[max(published)] if published else None


@dataclass(frozen=True)
class IndexStep:
    """One indexing step, as the provenance chain records it."""

    step: str
    input: Money
    output: Money
    selector: IndexSelector
    from_date: date
    to_date: date
    as_of: date
    from_point: IndexPoint
    to_point: IndexPoint
    ratio: Decimal
    rule: str
    lag_months: int
    stale: bool

    status = "indexed"
    estimate = False

    @property
    def downgrades(self) -> tuple[str, ...]:
        return (STALE_INDEX,) if self.stale else ()

    def as_dict(self) -> dict:
        return {
            "step": self.step,
            **self.selector.as_dict(),
            "from_date": self.from_date.isoformat(),
            "to_date": self.to_date.isoformat(),
            "from_period": self.from_point.period,
            "to_period": period_of(self.to_date),
            "period_used": self.to_point.period,
            "as_of": self.as_of.isoformat(),
            "rule": self.rule,
            "lag_months": self.lag_months,
            "ratio": decimal_text(self.ratio),
            "stale": self.stale,
            "estimate": False,
            "downgrades": list(self.downgrades),
            "observations": [self.from_point.as_provenance(), self.to_point.as_provenance()],
            "input": self.input.as_dict(),
            "output": self.output.as_dict(),
        }


def index(
    amount: Money,
    from_date: date,
    to_date: date,
    book: IndexBook,
    selector: IndexSelector,
    *,
    max_lag_months: int = 0,
    as_of: date | None = None,
    step: str = "cost_index",
) -> IndexStep | Unavailable:
    """``amount`` at ``to_date``'s prices: multiplied by the series' value for
    ``to_date``'s month over its value for ``from_date``'s month. An
    :class:`IndexStep`, or an explicit :class:`Unavailable` (``index_missing``)."""
    if not isinstance(amount, Money):
        raise TypeError(f"index takes Money, not {type(amount).__name__}")
    if not isinstance(book, IndexBook) or not isinstance(selector, IndexSelector):
        raise TypeError("index reads an IndexBook through an IndexSelector")
    if amount.currency != selector.currency:
        raise MoneyRefused(
            "currency_mismatch",
            f"{selector.series_id} prices {selector.currency}; the amount is in {amount.currency}",
        )
    check_date(from_date, "from_date")
    check_date(to_date, "to_date")
    if from_date > to_date:
        raise MoneyRefused("date_inversion", f"indexing from {from_date} back to {to_date}")
    as_of = to_date if as_of is None else check_date(as_of, "as_of")
    if type(max_lag_months) is not int or max_lag_months < 0:
        raise MoneyRefused("policy_invalid", f"max_lag_months {max_lag_months!r}")
    from_period, to_period = period_of(from_date), period_of(to_date)
    start = book.value(selector, from_period, as_of)
    if start is None:
        return Unavailable(step, "index_missing", f"{selector.series_id} has no value for {from_period} by {as_of}")
    end, lag = None, 0
    for lag in range(max_lag_months + 1):
        candidate = shift_period(to_period, lag)
        if candidate < from_period:
            break
        end = book.value(selector, candidate, as_of)
        if end is not None:
            break
    if end is None:
        return Unavailable(
            step,
            "index_missing",
            f"{selector.series_id} has no value for {to_period}, or within {max_lag_months} month(s) before it, "
            f"by {as_of}",
        )
    ratio = compute(lambda: end.value / start.value)
    return IndexStep(
        step=step,
        input=amount,
        output=Money(compute(lambda: amount.amount * end.value / start.value), amount.currency),
        selector=selector,
        from_date=from_date,
        to_date=to_date,
        as_of=as_of,
        from_point=start,
        to_point=end,
        ratio=ratio,
        rule=EXACT_PERIOD if lag == 0 else LATEST_PUBLISHED_PERIOD,
        lag_months=lag,
        stale=lag > 0,
    )
