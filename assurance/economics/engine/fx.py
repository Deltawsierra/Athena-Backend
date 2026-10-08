"""Exchange rates: the observation contract, the book a conversion reads, the
policy it follows, and a conversion that returns its value WITH its provenance.

An :class:`FXRate` is one observed rate, quoted as ``1 base = rate quote`` (an
EUR/USD rate of 1.0850 means one euro buys 1.0850 dollars), with its rate type
(reference, mid, bid or ask), its provider, when it was observed, the date it is
the rate for, and the hash of the snapshot it was read from. It is the pure
mirror of :class:`assurance.economics.models.FXObservation`.

:func:`convert` changes an amount's currency on a date under an :class:`FXPolicy`
(owner's specification, sections 9 and 19; ``docs/economics/spec-v1.md``,
section 12):

- **Providers in order.** The policy lists providers, strongest first (a
  tenant-required provider, then an official reference, then a licensed market
  fallback); within each, the rate types it accepts, in order. The first that has
  a rate is used. None is an explicit :class:`.money.Unavailable`.
- **Reversed quotes.** A rate quoted the other way round (USD to EUR read from an
  EUR/USD observation) is inverted, and the step records ``inverted``, the rate as
  quoted, and the factor applied. A rate quoted both ways prefers the direct one.
- **Weekends and holidays.** On a day the provider does not publish -- a Saturday,
  a Sunday or a holiday in its calendar -- the LAST OFFICIAL RATE is used: the rate
  of its last publication day before it. The step records the rule, the date asked
  for and the date of the rate used. Policy ``none`` turns the rule off.
- **A missing rate is unavailable.** A day the provider publishes on with no rate
  in the book is a missing rate, and the conversion is ``rate_missing``. It is
  never filled from the day before (that is the weekend rule, and it is not a
  weekend) and never interpolated, unless the policy says ``interpolate``: then a
  rate is interpolated linearly between the observations either side, no more than
  ``max_interpolation_gap_days`` apart, and the step is an ESTIMATE that carries a
  confidence downgrade (``estimated_rate``). Nothing is extrapolated.
- **Stale.** A rate more than ``freshness_days`` older (or, interpolated, further)
  than the day it is used for is flagged ``stale`` and carries a downgrade
  (``stale_rate``).
- **The original is never overwritten.** The step holds the amount it was given and
  the new amount, and the observations it read.

A round trip through one rate (USD to EUR and back on one observation) returns the
amount to within :data:`ROUND_TRIP_TOLERANCE`, relative, and exactly at display.
No triangulation: a pair with no rate either way is unavailable, never crossed
through a third currency.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import date, datetime, timedelta
from decimal import Decimal
from enum import StrEnum
from types import MappingProxyType

from .money import (
    Money,
    MoneyRefused,
    Unavailable,
    check_date,
    check_decimal,
    check_instant,
    check_money_currency,
    check_snapshot_hash,
    check_text,
    compute,
    decimal_text,
)


class RateType(StrEnum):
    """What kind of rate an observation is. The value is the stable code."""

    REFERENCE = "reference"
    MID = "mid"
    BID = "bid"
    ASK = "ask"


RATE_TYPES: Mapping[RateType, str] = MappingProxyType(
    {
        RateType.REFERENCE: "an official reference rate (a central bank's daily fixing): informational, not a price "
        "anyone dealt at",
        RateType.MID: "the midpoint of a market's bid and ask",
        RateType.BID: "the price a market buys the base currency at",
        RateType.ASK: "the price a market sells the base currency at",
    }
)
_RATE_TYPE_CODES = frozenset(t.value for t in RateType)

#: The rule a conversion step records.
SAME_CURRENCY = "same_currency"
EXACT = "exact"
LAST_OFFICIAL_RATE = "last_official_rate"
LINEAR_INTERPOLATION = "linear_interpolation"
RULES: Mapping[str, str] = MappingProxyType(
    {
        SAME_CURRENCY: "the amount is already in the currency asked for: nothing is converted",
        EXACT: "the provider's rate for the day asked for",
        LAST_OFFICIAL_RATE: "the day asked for is a weekend or a holiday of the provider: its last official rate, "
        "from its last publication day before it",
        LINEAR_INTERPOLATION: "an ESTIMATE the policy allowed: interpolated linearly between the observations either "
        "side of a missing day",
    }
)

#: The weekend and holiday rules a policy may name.
NO_FALLBACK = "none"
WEEKEND_HOLIDAY_RULES = frozenset({LAST_OFFICIAL_RATE, NO_FALLBACK})
#: What a policy does about a missing rate.
UNAVAILABLE = "unavailable"
INTERPOLATE = "interpolate"
MISSING_RATE_RULES = frozenset({UNAVAILABLE, INTERPOLATE})

DIRECT = "direct"
INVERTED = "inverted"

#: The confidence downgrades a conversion step may carry.
ESTIMATED_RATE = "estimated_rate"
STALE_RATE = "stale_rate"

#: A round trip through one rate is within this, relative to the amount.
ROUND_TRIP_TOLERANCE = Decimal("1E-50")

#: The longest run of non-publication days the weekend or holiday rule walks back
#: over; a calendar that closes a provider for longer finds no last official rate.
MAX_NON_PUBLICATION_RUN = 31


@dataclass(frozen=True)
class FXRate:
    """One observed rate: ``1 base = rate quote``, of ``rate_type``, from
    ``provider``, observed at ``observed_at``, the rate for ``effective_date``, read
    from the snapshot ``source_snapshot_hash`` (and, when it was stored, the source
    version ``source_key`` v``source_version``)."""

    base: str
    quote: str
    rate: Decimal
    rate_type: str
    provider: str
    observed_at: datetime
    effective_date: date
    source_snapshot_hash: str
    source_key: str = ""
    source_version: int | None = None

    def __post_init__(self):
        check_money_currency(self.base, "base")
        check_money_currency(self.quote, "quote")
        if self.base == self.quote:
            raise MoneyRefused("pair_malformed", f"{self.base}/{self.quote}")
        check_decimal(self.rate, "rate")
        if self.rate <= 0:
            raise MoneyRefused("rate_not_positive", f"{self.base}/{self.quote} {self.rate}")
        if not isinstance(self.rate_type, str) or self.rate_type not in _RATE_TYPE_CODES:
            raise MoneyRefused("rate_type_unrecognised", repr(self.rate_type))
        check_text(provider=self.provider)
        check_instant(self.observed_at, "observed_at")
        check_date(self.effective_date, "effective_date")
        check_snapshot_hash(self.source_snapshot_hash)

    def as_provenance(self) -> dict:
        return {
            "provider": self.provider,
            "base": self.base,
            "quote": self.quote,
            "rate": decimal_text(self.rate),
            "rate_type": self.rate_type,
            "effective_date": self.effective_date.isoformat(),
            "observed_at": self.observed_at.isoformat(),
            "source_snapshot_hash": self.source_snapshot_hash,
            "source_key": self.source_key,
            "source_version": self.source_version,
        }


class FXBook:
    """The rates a conversion may read, and each provider's holidays.

    A provider publishes Monday to Friday, except on the holidays its calendar
    lists. Each (provider, rate type, base, quote, date) is held once; a second is
    ``observation_duplicate``, whatever its rate."""

    def __init__(self, rates: Iterable[FXRate], holidays: Mapping[str, Iterable[date]] | None = None):
        series: dict[tuple[str, str, str, str], dict[date, FXRate]] = {}
        for rate in rates:
            if not isinstance(rate, FXRate):
                raise TypeError(f"an FXBook holds FXRates, not {type(rate).__name__}")
            days = series.setdefault((rate.provider, rate.rate_type, rate.base, rate.quote), {})
            if rate.effective_date in days:
                raise MoneyRefused(
                    "observation_duplicate",
                    f"{rate.provider} {rate.rate_type} {rate.base}/{rate.quote} on {rate.effective_date}",
                )
            days[rate.effective_date] = rate
        self._series = MappingProxyType({key: MappingProxyType(days) for key, days in series.items()})
        calendars: dict[str, frozenset[date]] = {}
        for provider, days in (holidays or {}).items():
            check_text(provider=provider)
            calendars[provider] = frozenset(check_date(day, f"{provider} holiday") for day in days)
        self._holidays = MappingProxyType(calendars)

    def holidays(self, provider: str) -> frozenset[date]:
        return self._holidays.get(provider, frozenset())

    def publishes_on(self, provider: str, day: date) -> bool:
        """Whether ``provider`` publishes a rate on ``day``: a weekday that is not
        one of its holidays."""
        return day.weekday() < 5 and day not in self.holidays(provider)

    def observed(self, provider: str, rate_type: str, frm: str, to: str, day: date) -> tuple[FXRate, str] | None:
        """``provider``'s ``rate_type`` rate between ``frm`` and ``to`` for ``day``,
        and whether it is quoted ``direct`` (base ``frm``) or ``inverted``."""
        direct = self._series.get((provider, rate_type, frm, to), {}).get(day)
        if direct is not None:
            return direct, DIRECT
        inverse = self._series.get((provider, rate_type, to, frm), {}).get(day)
        if inverse is not None:
            return inverse, INVERTED
        return None

    def dates(self, provider: str, rate_type: str, base: str, quote: str) -> list[date]:
        """Every date with a ``base``/``quote`` rate of that provider and type, in order."""
        return sorted(self._series.get((provider, rate_type, base, quote), {}))

    def rate(self, provider: str, rate_type: str, base: str, quote: str, day: date) -> FXRate | None:
        return self._series.get((provider, rate_type, base, quote), {}).get(day)

    def last_observed_before(self, frm: str, to: str, day: date) -> date | None:
        """The latest date before ``day`` with any rate between the two codes, for
        saying what an unavailable conversion could have read."""
        found = [
            observed
            for (_, _, base, quote), days in self._series.items()
            if {base, quote} == {frm, to}
            for observed in days
            if observed < day
        ]
        return max(found, default=None)


def _is_whole(value) -> bool:
    return type(value) is int and value >= 0


@dataclass(frozen=True)
class FXPolicy:
    """How a conversion finds its rate. Every field is checked on construction
    (``policy_invalid``); the defaults are the strict ones: reference then mid
    rates, the last official rate on a weekend or holiday, a missing rate
    UNAVAILABLE, and a rate more than four days older than its day stale."""

    providers: tuple[str, ...]
    rate_types: tuple[str, ...] = (RateType.REFERENCE.value, RateType.MID.value)
    weekend_holiday_rule: str = LAST_OFFICIAL_RATE
    missing_rate: str = UNAVAILABLE
    max_interpolation_gap_days: int = 7
    freshness_days: int = 4

    def __post_init__(self):
        if (
            not isinstance(self.providers, tuple)
            or not self.providers
            or any(not isinstance(p, str) or not p.strip() for p in self.providers)
            or len(set(self.providers)) != len(self.providers)
        ):
            raise MoneyRefused("policy_invalid", f"providers {self.providers!r}")
        if (
            not isinstance(self.rate_types, tuple)
            or not self.rate_types
            or any(t not in _RATE_TYPE_CODES for t in self.rate_types)
            or len(set(self.rate_types)) != len(self.rate_types)
        ):
            raise MoneyRefused("policy_invalid", f"rate types {self.rate_types!r}")
        if self.weekend_holiday_rule not in WEEKEND_HOLIDAY_RULES:
            raise MoneyRefused("policy_invalid", f"weekend and holiday rule {self.weekend_holiday_rule!r}")
        if self.missing_rate not in MISSING_RATE_RULES:
            raise MoneyRefused("policy_invalid", f"missing-rate rule {self.missing_rate!r}")
        if not _is_whole(self.max_interpolation_gap_days) or not _is_whole(self.freshness_days):
            raise MoneyRefused("policy_invalid", "the day limits are whole numbers of days, zero or more")

    def as_dict(self) -> dict:
        return {
            "providers": list(self.providers),
            "rate_types": list(self.rate_types),
            "weekend_holiday_rule": self.weekend_holiday_rule,
            "missing_rate": self.missing_rate,
            "max_interpolation_gap_days": self.max_interpolation_gap_days,
            "freshness_days": self.freshness_days,
        }


@dataclass(frozen=True)
class FXStep:
    """One conversion, as the provenance chain records it: what came in, what went
    out, the rule, the rate (as quoted, and the factor applied) and every
    observation read."""

    step: str
    input: Money
    output: Money
    requested_date: date
    rule: str
    factor: Decimal
    provider: str | None = None
    rate_type: str | None = None
    direction: str | None = None
    quoted_rate: Decimal | None = None
    #: The date whose rate was used: the day asked for, the last publication day
    #: before it, or (interpolated) the day estimated.
    rate_date: date | None = None
    interpolation_weight: Decimal | None = None
    observations: tuple[FXRate, ...] = ()
    age_days: int = 0
    stale: bool = False
    estimate: bool = False

    status = "converted"

    @property
    def downgrades(self) -> tuple[str, ...]:
        return tuple(
            reason for reason, applies in ((ESTIMATED_RATE, self.estimate), (STALE_RATE, self.stale)) if applies
        )

    def as_dict(self) -> dict:
        return {
            "step": self.step,
            "from": self.input.currency,
            "to": self.output.currency,
            "requested_date": self.requested_date.isoformat(),
            "rule": self.rule,
            "provider": self.provider,
            "rate_type": self.rate_type,
            "direction": self.direction,
            "rate_date": self.rate_date.isoformat() if self.rate_date else None,
            "quoted_rate": decimal_text(self.quoted_rate) if self.quoted_rate is not None else None,
            "factor": decimal_text(self.factor),
            "interpolation_weight": (
                decimal_text(self.interpolation_weight) if self.interpolation_weight is not None else None
            ),
            "age_days": self.age_days,
            "stale": self.stale,
            "estimate": self.estimate,
            "downgrades": list(self.downgrades),
            "observations": [observation.as_provenance() for observation in self.observations],
            "input": self.input.as_dict(),
            "output": self.output.as_dict(),
        }


@dataclass(frozen=True)
class _Found:
    rule: str
    provider: str
    rate_type: str
    direction: str
    quoted: Decimal
    rate_date: date
    observations: tuple[FXRate, ...]
    weight: Decimal | None = None


def _last_publication_day(book: FXBook, provider: str, day: date) -> date | None:
    """The provider's last publication day before ``day``."""
    earlier = day
    for _ in range(MAX_NON_PUBLICATION_RUN):
        earlier -= timedelta(days=1)
        if book.publishes_on(provider, earlier):
            return earlier
    return None


def _find(frm: str, to: str, day: date, book: FXBook, policy: FXPolicy) -> _Found | None:
    # Pass 1: an official rate -- the day's own, or on a day the provider does not
    # publish, its last official one. Every provider, in order, before any estimate.
    for provider in policy.providers:
        for rate_type in policy.rate_types:
            hit = book.observed(provider, rate_type, frm, to, day)
            if hit is not None:
                return _Found(EXACT, provider, rate_type, hit[1], hit[0].rate, day, (hit[0],))
            if policy.weekend_holiday_rule == LAST_OFFICIAL_RATE and not book.publishes_on(provider, day):
                last = _last_publication_day(book, provider, day)
                hit = book.observed(provider, rate_type, frm, to, last) if last is not None else None
                if hit is not None:
                    return _Found(LAST_OFFICIAL_RATE, provider, rate_type, hit[1], hit[0].rate, last, (hit[0],))
    if policy.missing_rate != INTERPOLATE:
        return None
    # Pass 2, only where the policy says so: an estimate between the observations
    # either side of the missing day, never past the last one.
    for provider in policy.providers:
        target = day
        if policy.weekend_holiday_rule == LAST_OFFICIAL_RATE and not book.publishes_on(provider, day):
            target = _last_publication_day(book, provider, day) or day
        for rate_type in policy.rate_types:
            for base, quote, direction in ((frm, to, DIRECT), (to, frm, INVERTED)):
                dates = book.dates(provider, rate_type, base, quote)
                before = max((d for d in dates if d < target), default=None)
                after = min((d for d in dates if d > target), default=None)
                if before is None or after is None or (after - before).days > policy.max_interpolation_gap_days:
                    continue
                first = book.rate(provider, rate_type, base, quote, before)
                last = book.rate(provider, rate_type, base, quote, after)
                weight = compute(
                    lambda b=before, a=after, t=target: Decimal((t - b).days) / Decimal((a - b).days)
                )
                quoted = compute(lambda f=first, la=last, w=weight: f.rate + (la.rate - f.rate) * w)
                return _Found(
                    LINEAR_INTERPOLATION, provider, rate_type, direction, quoted, target, (first, last), weight
                )
    return None


def convert(amount: Money, to: str, on: date, book: FXBook, policy: FXPolicy, *, step: str = "fx") -> FXStep | Unavailable:
    """``amount`` in currency ``to``, at the rate for ``on``, under ``policy``: an
    :class:`FXStep` with its provenance, or an explicit :class:`Unavailable`
    (``rate_missing``). ``amount`` itself is never changed."""
    if not isinstance(amount, Money):
        raise TypeError(f"convert takes Money, not {type(amount).__name__}")
    check_money_currency(to, "target currency")
    check_date(on, "conversion date")
    if not isinstance(book, FXBook) or not isinstance(policy, FXPolicy):
        raise TypeError("convert reads an FXBook under an FXPolicy")
    if amount.currency == to:
        return FXStep(step, amount, amount, on, SAME_CURRENCY, Decimal(1))
    found = _find(amount.currency, to, on, book, policy)
    if found is None:
        last = book.last_observed_before(amount.currency, to, on)
        return Unavailable(
            step,
            "rate_missing",
            f"no {amount.currency}/{to} rate for {on.isoformat()} from {', '.join(policy.providers)} "
            f"({', '.join(policy.rate_types)}), missing rate rule {policy.missing_rate!r}; "
            f"the last rate between them before that day is "
            f"{last.isoformat() if last else 'none'}",
        )
    factor = found.quoted if found.direction == DIRECT else compute(lambda: Decimal(1) / found.quoted)
    dates = [observation.effective_date for observation in found.observations]
    age = max(abs((on - observed).days) for observed in dates)
    return FXStep(
        step=step,
        input=amount,
        output=Money(compute(lambda: amount.amount * factor), to),
        requested_date=on,
        rule=found.rule,
        factor=factor,
        provider=found.provider,
        rate_type=found.rate_type,
        direction=found.direction,
        quoted_rate=found.quoted,
        rate_date=found.rate_date,
        interpolation_weight=found.weight,
        observations=found.observations,
        age_days=age,
        stale=age > policy.freshness_days,
        estimate=found.rule == LINEAR_INTERPOLATION,
    )
