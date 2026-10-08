"""Money, FX and cost-index normalization (phase E1), with no database.

The owner's specification, section 27's currency and inflation rows, run against
:mod:`assurance.economics.engine.money`, ``.fx``, ``.cost_index`` and
``.normalization`` (``docs/economics/spec-v1.md``, sections 11 to 13):

- a USD/EUR round trip within the stated tolerance; reversed quotes; JPY with no
  decimals and KWD with three; a weekend and a holiday; a missing historical rate
  (``unavailable``, not interpolated); a stale rate flagged;
- a historical cost converted at the event date and indexed to the valuation
  date, and the same steps swapped giving a different, wrong answer;
- monotonicity: a larger native amount never converts to a smaller one;
- adversarial inputs: NaN, a float, a unit or currency mismatch, date inversion,
  a negative rate and a zero rate;
- the provenance chain, and the native amount never overwritten.

Every rate and index value is the committed snapshot, which is SYNTHETIC TEST
DATA (not real rates), or is built in the test.
"""

from __future__ import annotations

import contextlib
import dataclasses
import itertools
import json
from datetime import UTC, date, datetime, timedelta
from decimal import ROUND_HALF_EVEN, Decimal
from pathlib import Path

import pytest

from assurance.economics.engine import cost_index, fx, money, normalization, snapshot
from assurance.economics.engine.confidence import ConfidenceGrade, downgraded
from assurance.economics.engine.cost_index import IndexBook, IndexPoint, IndexSelector
from assurance.economics.engine.fx import FXBook, FXPolicy, FXRate
from assurance.economics.engine.money import Money, MoneyRefused, Unavailable, compute
from assurance.economics.engine.normalization import NormalizationPolicy, normalize

REPO = Path(__file__).resolve().parent.parent
SNAPSHOT_PATH = REPO / "assurance" / "economics" / "snapshots" / "synthetic-fx-and-cost-index-v1.json"
SPEC = REPO / "docs" / "economics" / "spec-v1.md"

#: The committed snapshot's hash: SHA-256 of its bytes. Registered as the
#: FinancialSource's snapshot_hash, and named in the spec. An edit to the file moves
#: it: change it here and in the spec, in the same reviewed change.
SNAPSHOT_HASH = "sha256:54ff61637f36e517d02bb146615e94e9867db5270355bc76eb0fd41b4b4001a5"

REF, MKT = "SYNTHETIC-REF", "SYNTHETIC-MKT"
CPI = "consumer prices, all items (SYNTHETIC)"
US_CPI = IndexSelector("SYN-CPI-US", "US", CPI, "USD")
EA_HICP = IndexSelector("SYN-HICP-EA", "EA", CPI, "EUR")
EVENT, VALUATION = date(2020, 3, 2), date(2026, 10, 8)
HASH = "sha256:" + "ab" * 32
OBSERVED = datetime(2020, 3, 2, 15, tzinfo=UTC)


@pytest.fixture(scope="module")
def snap():
    return snapshot.parse_snapshot(SNAPSHOT_PATH.read_bytes())


@pytest.fixture(scope="module")
def fx_book(snap):
    return snap.fx_book()


@pytest.fixture(scope="module")
def index_book(snap):
    return snap.index_book()


def usd(text: str) -> Money:
    return Money.parse(text, "USD")


def eur(text: str) -> Money:
    return Money.parse(text, "EUR")


def policy(base="USD", reporting="EUR", index=US_CPI, lag=0, **fx_rules) -> NormalizationPolicy:
    fx_rules.setdefault("providers", (REF,))
    return NormalizationPolicy(base, reporting, FXPolicy(**fx_rules), index, lag)


@contextlib.contextmanager
def refused(code: str):
    """``pytest.raises`` for a MoneyRefused carrying ``code``."""
    with pytest.raises(MoneyRefused) as info:
        yield info
    assert info.value.code == code, (info.value.code, str(info.value))


def rate(base="EUR", quote="USD", value="1.1", **over) -> FXRate:
    fields = {
        "base": base,
        "quote": quote,
        "rate": Decimal(value) if isinstance(value, str) else value,
        "rate_type": "reference",
        "provider": REF,
        "observed_at": OBSERVED,
        "effective_date": EVENT,
        "source_snapshot_hash": HASH,
    }
    fields.update(over)
    return FXRate(**fields)


def point(period="2020-03", value="100", vintage=date(2020, 4, 10), **over) -> IndexPoint:
    fields = {
        "series_id": US_CPI.series_id,
        "geography": "US",
        "category": CPI,
        "period": period,
        "value": Decimal(value) if isinstance(value, str) else value,
        "vintage_date": vintage,
        "source_snapshot_hash": HASH,
    }
    fields.update(over)
    return IndexPoint(**fields)


# =============================================================== representation


def test_money_is_a_decimal_and_a_code():
    amount = Money(Decimal("1234.56"), "USD")
    assert (amount.amount, amount.currency) == (Decimal("1234.56"), "USD")
    assert Money.parse("1234.56", "USD") == amount
    with pytest.raises(dataclasses.FrozenInstanceError):
        amount.amount = Decimal(0)


@pytest.mark.parametrize("value", [1.5, 0.1, float("nan"), float("inf"), 1, True, "1.5", None])
def test_a_float_is_refused_on_entry(value):
    """A float -- or anything but a Decimal -- never becomes an amount, a factor or
    a rate."""
    with refused("not_decimal"):
        Money(value, "USD")
    with refused("not_decimal"):
        usd("1").times(value)
    with refused("not_decimal"):
        dataclasses.replace(rate(), rate=value)
    with refused("not_decimal"):
        dataclasses.replace(point(), value=value)


def test_a_float_is_refused_by_every_entry_point():
    with refused("not_decimal"):
        Money.parse(1.5, "USD")
    with refused("not_decimal"):
        usd("10") * 1.5
    with refused("not_decimal"):
        1.5 * usd("10")
    with refused("not_decimal"):
        Money.parse("one", "USD")


@pytest.mark.parametrize("text", ["NaN", "sNaN", "Infinity", "-Infinity", "inf"])
def test_nan_and_infinity_are_refused(text):
    with refused("not_finite"):
        Money(Decimal(text), "USD")
    with refused("not_finite"):
        Money.parse(text, "USD")
    with refused("not_finite"):
        usd("1").times(Decimal(text))
    with refused("not_finite"):
        rate(value=Decimal(text))
    with refused("not_finite"):
        point(value=Decimal(text))


def test_the_currency_is_a_code_the_table_holds():
    for code in ("usd", "US$", "XYZ", "", None):
        with refused("currency_unknown"):
            Money(Decimal(1), code)
    # Gold has no minor unit: no amount is written in it.
    with refused("currency_retired"):
        Money(Decimal(1), "XAU")
    # A retired code with a minor unit is a valid NATIVE amount: a 1999 invoice in marks.
    assert Money.parse("1955.83", "DEM").display() == "1955.83 DEM"


def test_arithmetic_keeps_full_precision_and_rounds_only_for_display():
    assert usd("0.1") + usd("0.2") == usd("0.3")
    long = Money(Decimal("1234.567890123456789012345678901"), "USD")
    assert (long + long).amount == Decimal("2469.135780246913578024691357802")
    assert long.times(Decimal("3")).amount == Decimal("3703.703670370370367037037036703")
    # Three half-cents: rounded each for display, they would show 0.00 + 0.00 + 0.00;
    # summed at full precision and rounded once, 0.015 shows as 0.02.
    halves = [usd("0.005")] * 3
    assert all(h.display_amount() == Decimal("0.00") for h in halves)
    assert Money.total(halves, "USD").display() == "0.02 USD"
    # A division keeps PRECISION significant digits, not the minor unit's two.
    third = Money(compute(lambda: Decimal(1) / Decimal(3)), "USD")
    assert len(third.amount.as_tuple().digits) == money.PRECISION == 60
    assert third.display() == "0.33 USD"


@pytest.mark.parametrize(
    "amount, code, shown",
    [
        ("0.125", "USD", "0.12"),
        ("0.135", "USD", "0.14"),
        ("0.1251", "USD", "0.13"),
        ("-0.125", "USD", "-0.12"),
        ("2.5", "JPY", "2"),
        ("3.5", "JPY", "4"),
        ("13270.875", "JPY", "13271"),
        ("1.0005", "KWD", "1.000"),
        ("1.0015", "KWD", "1.002"),
        ("379.6272", "KWD", "379.627"),
        ("1309.523809", "EUR", "1309.52"),
        ("7", "CLF", "7.0000"),
    ],
)
def test_display_rounds_half_even_to_the_minor_unit(amount, code, shown):
    """The stated rounding mode: ROUND_HALF_EVEN, to the currency's minor unit."""
    assert money.DISPLAY_ROUNDING == ROUND_HALF_EVEN
    value = Money.parse(amount, code)
    assert value.display() == f"{shown} {code}"
    assert isinstance(value.display_amount(), Decimal) and not isinstance(value.display_amount(), Money)
    # Display never changes the amount.
    assert value.amount == Decimal(amount)


def test_two_currencies_never_add_without_conversion():
    for operation in (
        lambda: usd("1") + eur("1"),
        lambda: usd("1") - eur("1"),
        lambda: usd("1") < eur("2"),
        lambda: usd("1") >= eur("2"),
        lambda: Money.total([usd("1"), eur("1")], "USD"),
    ):
        with refused("currency_mismatch"):
            operation()
    # sum() starts from 0, which is not Money: refused too, never coerced.
    with pytest.raises(TypeError):
        sum([usd("1"), usd("2")])
    assert Money.total([usd("1"), usd("2")], "USD") == usd("3")


def test_extreme_values_are_refused_not_carried_as_infinity():
    huge = Money(Decimal("1E+999990"), "USD")
    with refused("out_of_range"):
        huge.times(Decimal("1E+20"))


# ============================================================ reporting currency


def test_a_retired_or_non_reportable_currency_is_refused_as_a_reporting_currency():
    """Core's codes for core's reasons: HRK and DEM are retired, XAU has no minor
    unit, XYZ is not a code. None may be the base or the reporting currency."""
    from mythos_core import exposure_receipt as receipt

    for code, expected in (
        ("HRK", receipt.CURRENCY_RETIRED),
        ("DEM", receipt.CURRENCY_RETIRED),
        ("XAU", receipt.CURRENCY_RETIRED),
        ("XYZ", receipt.CURRENCY_UNKNOWN),
    ):
        with refused(expected):
            policy(reporting=code)
        with refused(expected):
            policy(base=code, index=dataclasses.replace(US_CPI, currency="USD"))
        with refused(expected):
            money.check_reporting_currency(code)
    assert policy(reporting="KWD").reporting_currency == "KWD"


def test_the_cost_index_is_the_base_currencys():
    with refused("currency_mismatch"):
        policy(base="USD", index=EA_HICP)
    assert policy(base="EUR", reporting="USD", index=EA_HICP).index is EA_HICP


# ========================================================================= FX


def test_a_usd_eur_round_trip_is_within_the_stated_tolerance(fx_book):
    rules = FXPolicy((REF,))
    assert fx.ROUND_TRIP_TOLERANCE == Decimal("1E-50")
    for text in ("0.01", "1", "1000.00", "123456789.99"):
        start = usd(text)
        there = fx.convert(start, "EUR", VALUATION, fx_book, rules)
        back = fx.convert(there.output, "USD", VALUATION, fx_book, rules)
        assert (there.direction, back.direction) == ("inverted", "direct")
        assert abs(back.output.amount - start.amount) <= start.amount * fx.ROUND_TRIP_TOLERANCE, text
        assert back.output.display() == start.display()


def test_a_reversed_quote_is_inverted_and_says_so(fx_book):
    rules = FXPolicy((REF,))
    # USD to EUR, read from an EUR/USD observation of 1.0500.
    step = fx.convert(usd("1000"), "EUR", VALUATION, fx_book, rules)
    assert (step.direction, step.quoted_rate) == ("inverted", Decimal("1.0500"))
    assert step.factor == compute(lambda: Decimal(1) / Decimal("1.05"))
    assert step.output.display() == "952.38 EUR"
    assert step.observations[0].base == "EUR" and step.observations[0].quote == "USD"
    # The same observation read the way it is quoted.
    direct = fx.convert(eur("1000"), "USD", VALUATION, fx_book, rules)
    assert (direct.direction, direct.factor, direct.output.display()) == ("direct", Decimal("1.0500"), "1050.00 USD")
    # JPY to USD from a USD/JPY observation of 107.50.
    yen = fx.convert(Money.parse("10000", "JPY"), "USD", EVENT, fx_book, rules)
    assert (yen.direction, yen.output.display()) == ("inverted", "93.02 USD")


def test_a_rate_quoted_both_ways_prefers_the_direct_one():
    book = FXBook([rate("EUR", "USD", "1.1"), rate("USD", "EUR", "0.9")])
    step = fx.convert(eur("100"), "USD", EVENT, book, FXPolicy((REF,)))
    assert (step.direction, step.factor) == ("direct", Decimal("1.1"))
    step = fx.convert(usd("100"), "EUR", EVENT, book, FXPolicy((REF,)))
    assert (step.direction, step.factor) == ("direct", Decimal("0.9"))


def test_jpy_has_no_decimals(fx_book):
    step = fx.convert(usd("123.45"), "JPY", EVENT, fx_book, FXPolicy((REF,)))
    assert step.output.amount == Decimal("13270.875")  # full precision kept
    assert step.output.display() == "13271 JPY"


def test_kwd_has_three_decimals(fx_book):
    step = fx.convert(usd("1234.56"), "KWD", VALUATION, fx_book, FXPolicy((REF,)))
    assert step.output.amount == Decimal("379.627200")
    assert step.output.display() == "379.627 KWD"


def test_a_weekend_uses_the_last_official_rate_and_records_the_rule(fx_book):
    rules = FXPolicy((REF,))
    for day, age in ((date(2020, 3, 7), 1), (date(2020, 3, 8), 2)):  # Saturday, Sunday
        step = fx.convert(eur("100"), "USD", day, fx_book, rules)
        assert step.rule == fx.LAST_OFFICIAL_RATE
        assert (step.requested_date, step.rate_date, step.quoted_rate) == (day, date(2020, 3, 6), Decimal("1.1400"))
        assert (step.age_days, step.stale, step.estimate) == (age, False, False)
        recorded = step.as_dict()
        assert (recorded["rule"], recorded["requested_date"], recorded["rate_date"]) == (
            "last_official_rate",
            day.isoformat(),
            "2020-03-06",
        )


def test_a_holiday_uses_the_last_official_rate(fx_book):
    """Good Friday and Easter Monday are holidays in SYNTHETIC-REF's calendar: the
    last official rate is Maundy Thursday's."""
    rules = FXPolicy((REF,))
    for day in (date(2020, 4, 10), date(2020, 4, 11), date(2020, 4, 12), date(2020, 4, 13)):
        step = fx.convert(eur("100"), "USD", day, fx_book, rules)
        assert (step.rule, step.rate_date, step.quoted_rate) == (
            fx.LAST_OFFICIAL_RATE,
            date(2020, 4, 9),
            Decimal("1.0900"),
        )
    assert step.age_days == 4 and not step.stale  # the default freshness limit is four days


def test_without_its_calendar_a_holiday_is_a_missing_day(snap):
    """No calendar, no holiday: Easter Monday is then a weekday the provider
    publishes on, so its missing rate is unavailable -- never filled in."""
    bare = FXBook(snap.fx_rates)
    step = fx.convert(eur("100"), "USD", date(2020, 4, 13), bare, FXPolicy((REF,)))
    assert isinstance(step, Unavailable) and step.reason == "rate_missing"


def test_the_weekend_rule_can_be_turned_off(fx_book):
    step = fx.convert(eur("100"), "USD", date(2020, 3, 7), fx_book, FXPolicy((REF,), weekend_holiday_rule="none"))
    assert isinstance(step, Unavailable) and step.reason == "rate_missing"


def test_a_missing_historical_rate_is_unavailable_not_interpolated(fx_book, index_book):
    """2020-03-04 is a Wednesday SYNTHETIC-REF publishes on, and the snapshot has
    no rate for it."""
    missing = date(2020, 3, 4)
    step = fx.convert(eur("100"), "USD", missing, fx_book, FXPolicy((REF,)))
    assert isinstance(step, Unavailable)
    assert (step.status, step.step, step.reason) == ("unavailable", "fx", "rate_missing")
    assert "2020-03-03" in step.detail  # what it could have read instead, said, not used
    result = normalize(
        eur("1000"),
        event_date=missing,
        valuation_date=VALUATION,
        policy=policy(),
        fx_book=fx_book,
        index_book=index_book,
    )
    assert (result.status, result.value, result.display()) == ("unavailable", None, None)
    assert (result.unavailable.step, result.unavailable.reason, result.chain) == ("event_fx", "rate_missing", ())
    assert not result.estimate and result.as_dict()["unavailable"]["reason"] == "rate_missing"


def test_interpolation_only_where_the_policy_says_so_and_then_an_estimate(fx_book, index_book):
    rules = FXPolicy((REF,), missing_rate="interpolate")
    step = fx.convert(eur("100"), "USD", date(2020, 3, 4), fx_book, rules)
    assert step.rule == fx.LINEAR_INTERPOLATION
    assert (step.quoted_rate, step.interpolation_weight) == (Decimal("1.1250"), Decimal("0.5"))
    assert [o.effective_date for o in step.observations] == [date(2020, 3, 3), date(2020, 3, 5)]
    assert step.estimate and step.downgrades == (fx.ESTIMATED_RATE,)
    result = normalize(
        eur("1000"),
        event_date=date(2020, 3, 4),
        valuation_date=VALUATION,
        policy=policy(missing_rate="interpolate"),
        fx_book=fx_book,
        index_book=index_book,
    )
    assert result.status == "normalized" and result.estimate
    assert result.confidence_downgrades == ("estimated_rate",)
    assert result.graded(ConfidenceGrade.A) is ConfidenceGrade.B
    # Too wide a gap is still unavailable, and nothing is extrapolated past the last rate.
    narrow = FXPolicy((REF,), missing_rate="interpolate", max_interpolation_gap_days=1)
    assert isinstance(fx.convert(eur("1"), "USD", date(2020, 3, 4), fx_book, narrow), Unavailable)
    assert isinstance(fx.convert(eur("1"), "USD", date(2026, 10, 9), fx_book, rules), Unavailable)


def test_providers_are_tried_in_the_policys_order(fx_book):
    """The hierarchy of section 19: the policy's providers, strongest first, then
    unavailable. SYNTHETIC-REF has no rate on 2020-03-04; SYNTHETIC-MKT has a mid."""
    step = fx.convert(eur("100"), "USD", date(2020, 3, 4), fx_book, FXPolicy((REF, MKT)))
    assert (step.provider, step.rate_type, step.quoted_rate, step.estimate) == (MKT, "mid", Decimal("1.1260"), False)
    # Both have 2026-10-08: the first named wins.
    assert fx.convert(eur("1"), "USD", VALUATION, fx_book, FXPolicy((REF, MKT))).provider == REF
    assert fx.convert(eur("1"), "USD", VALUATION, fx_book, FXPolicy((MKT, REF))).provider == MKT
    bid = fx.convert(eur("1"), "USD", VALUATION, fx_book, FXPolicy((MKT,), rate_types=("bid",)))
    assert (bid.rate_type, bid.quoted_rate) == ("bid", Decimal("1.0495"))


def test_a_stale_rate_is_flagged(fx_book, index_book):
    """Easter Monday's last official rate is four days old: past a freshness limit
    of three, it is flagged stale and carries a downgrade."""
    step = fx.convert(eur("100"), "USD", date(2020, 4, 13), fx_book, FXPolicy((REF,), freshness_days=3))
    assert (step.age_days, step.stale, step.downgrades) == (4, True, (fx.STALE_RATE,))
    result = normalize(
        eur("100"),
        event_date=date(2020, 4, 13),
        valuation_date=VALUATION,
        policy=policy(freshness_days=3),
        fx_book=fx_book,
        index_book=index_book,
    )
    assert result.status == "normalized" and result.stale and not result.estimate
    assert result.confidence_downgrades == ("stale_rate",)
    assert result.graded(ConfidenceGrade.B) is ConfidenceGrade.C
    assert result.as_dict()["chain"][0]["stale"] is True


def test_the_same_currency_is_not_converted(fx_book):
    step = fx.convert(usd("5"), "USD", EVENT, fx_book, FXPolicy((REF,)))
    assert (step.rule, step.factor, step.output, step.observations) == ("same_currency", Decimal(1), usd("5"), ())


def test_no_triangulation(fx_book):
    """EUR to JPY has no rate either way; it is never crossed through USD."""
    step = fx.convert(eur("100"), "JPY", EVENT, fx_book, FXPolicy((REF,)))
    assert isinstance(step, Unavailable) and step.reason == "rate_missing"


# =================================================================== inflation


def test_a_historical_cost_is_converted_at_the_event_date_and_indexed_to_the_valuation_date(fx_book, index_book):
    """EUR 1,000 on 2020-03-02, base USD, reported in EUR on 2026-10-08:
    1,000 x 1.1000 = USD 1,100 at the event date; x 125/100 = USD 1,375 at the
    valuation date's prices; / 1.0500 = EUR 1,309.52 at the valuation date's rate."""
    result = normalize(
        eur("1000.00"),
        event_date=EVENT,
        valuation_date=VALUATION,
        policy=policy(),
        fx_book=fx_book,
        index_book=index_book,
    )
    assert result.status == "normalized"
    event_fx, indexed, valuation_fx = result.chain
    assert [s.step for s in result.chain] == list(normalization.ORDER) == ["event_fx", "cost_index", "valuation_fx"]
    assert (event_fx.requested_date, event_fx.output) == (EVENT, usd("1100"))
    assert (indexed.ratio, indexed.output) == (Decimal("1.25"), usd("1375"))
    assert (indexed.from_point.period, indexed.to_point.period) == ("2020-03", "2026-10")
    assert valuation_fx.requested_date == VALUATION and valuation_fx.direction == "inverted"
    assert result.value.amount == compute(lambda: Decimal(1375) / Decimal("1.05"))
    assert result.display() == "1309.52 EUR"
    assert not result.estimate and not result.stale and result.confidence_downgrades == ()


def test_swapping_the_steps_gives_a_different_wrong_answer(fx_book, index_book):
    """Indexing before converting -- the base currency's inflation applied to an
    amount in another currency, then priced at the valuation date's rate -- gives
    EUR 1,250.00, not EUR 1,309.52. The engine never does it: indexing a EUR amount
    by the USD series is refused."""
    native = eur("1000.00")
    right = normalize(
        native, event_date=EVENT, valuation_date=VALUATION, policy=policy(), fx_book=fx_book, index_book=index_book
    )
    rules = FXPolicy((REF,))
    # Swapped: the cost index first, then FX at the valuation date into the base.
    indexed_first = native.times(Decimal("1.25"))
    in_base = fx.convert(indexed_first, "USD", VALUATION, fx_book, rules).output
    swapped = fx.convert(in_base, "EUR", VALUATION, fx_book, rules).output
    # Or FX at the valuation date first, then the cost index.
    late_fx = fx.convert(native, "USD", VALUATION, fx_book, rules).output
    late = fx.convert(late_fx.times(Decimal("1.25")), "EUR", VALUATION, fx_book, rules).output
    assert swapped.display() == late.display() == "1250.00 EUR"
    assert right.display() == "1309.52 EUR" != swapped.display()
    with refused("currency_mismatch"):
        cost_index.index(native, EVENT, VALUATION, index_book, US_CPI)


def test_the_index_reads_the_latest_vintage_published_by_the_as_of_date(index_book):
    assert index_book.value(US_CPI, "2026-09", date(2026, 10, 5)).value == Decimal("124.500")
    assert index_book.value(US_CPI, "2026-09", date(2026, 10, 6)).value == Decimal("124.600")
    assert index_book.value(US_CPI, "2026-09", date(2026, 9, 30)) is None
    step = cost_index.index(usd("100"), EVENT, date(2026, 9, 30), index_book, US_CPI, as_of=date(2026, 10, 5))
    assert step.to_point.vintage_date == date(2026, 10, 1)


def test_a_missing_index_is_unavailable_unless_a_lag_is_allowed(index_book):
    november = date(2026, 11, 15)
    step = cost_index.index(usd("100"), EVENT, november, index_book, US_CPI)
    assert isinstance(step, Unavailable) and step.reason == "index_missing"
    lagged = cost_index.index(usd("100"), EVENT, november, index_book, US_CPI, max_lag_months=1)
    assert (lagged.rule, lagged.lag_months, lagged.to_point.period) == ("latest_published_period", 1, "2026-10")
    assert lagged.stale and lagged.downgrades == (cost_index.STALE_INDEX,)
    # The event month's value is that month's or nothing.
    before = cost_index.index(usd("100"), date(2019, 12, 2), VALUATION, index_book, US_CPI, max_lag_months=6)
    assert isinstance(before, Unavailable) and before.reason == "index_missing"


def test_a_base_in_euros_reads_the_euro_series(fx_book, index_book):
    result = normalize(
        usd("1100"),
        event_date=EVENT,
        valuation_date=VALUATION,
        policy=policy(base="EUR", reporting="USD", index=EA_HICP),
        fx_book=fx_book,
        index_book=index_book,
    )
    # 1,100 / 1.1 = EUR 1,000; x 1.18 = EUR 1,180; x 1.05 = USD 1,239.00.
    assert result.display() == "1239.00 USD"


# ================================================================ monotonicity

AMOUNTS = [
    "0", "0.001", "0.004", "0.005", "0.006", "0.01", "0.015", "1", "999.99", "999.995", "1000", "1000.005",
    "1000.01", "123456789.12",
]


@pytest.mark.parametrize(
    "native_code, rules",
    [
        ("EUR", policy()),
        ("EUR", policy(reporting="JPY")),
        ("EUR", policy(reporting="KWD")),
        ("JPY", policy()),
        ("KWD", policy(reporting="USD")),
        ("EUR", policy(missing_rate="interpolate")),
    ],
)
def test_a_larger_native_amount_never_converts_to_a_smaller_one(fx_book, index_book, native_code, rules):
    event = date(2020, 3, 4) if rules.fx.missing_rate == "interpolate" else EVENT
    results = [
        normalize(
            Money.parse(text, native_code),
            event_date=event,
            valuation_date=VALUATION,
            policy=rules,
            fx_book=fx_book,
            index_book=index_book,
        )
        for text in AMOUNTS
    ]
    assert all(r.status == "normalized" for r in results), [r.unavailable for r in results]
    values = [r.value for r in results]
    assert values == sorted(values)
    assert all(a.amount < b.amount for a, b in itertools.pairwise(values))
    shown = [v.display_amount() for v in values]
    assert shown == sorted(shown)


# ================================================================= adversarial


def test_a_negative_or_zero_rate_is_refused():
    for value in ("-1.1", "0", "-0", "0E-9"):
        with refused("rate_not_positive"):
            rate(value=value)
    for value in ("-100", "0"):
        with refused("index_value_not_positive"):
            point(value=value)


def test_a_unit_or_currency_mismatch_is_refused(index_book):
    with refused("currency_mismatch"):
        cost_index.index(eur("1"), EVENT, VALUATION, index_book, US_CPI)
    with refused("pair_malformed"):
        rate("USD", "USD")
    with refused("rate_type_unrecognised"):
        rate(rate_type="spot")
    # One series is one geography and one category.
    with refused("index_series_mismatch"):
        IndexBook([point(), point(period="2020-04", vintage=date(2020, 5, 1), geography="EA")])
    with refused("index_series_mismatch"):
        index_book.value(dataclasses.replace(US_CPI, geography="GB"), "2020-03", VALUATION)
    with refused("period_malformed"):
        point(period="2020-13")


def test_date_inversion_is_refused(fx_book, index_book):
    with refused("date_inversion"):
        normalize(
            eur("1"), event_date=VALUATION, valuation_date=EVENT, policy=policy(), fx_book=fx_book,
            index_book=index_book,
        )
    with refused("date_inversion"):
        cost_index.index(usd("1"), VALUATION, EVENT, index_book, US_CPI)
    # A value published before its period began.
    with refused("date_inversion"):
        point(period="2020-03", vintage=date(2020, 2, 28))


def test_dates_are_dates_and_instants_are_aware():
    with refused("date_malformed"):
        rate(effective_date=datetime(2020, 3, 2, tzinfo=UTC))
    with refused("date_malformed"):
        rate(observed_at=datetime(2020, 3, 2, 15))
    with refused("date_malformed"):
        rate(effective_date="2020-03-02")


def test_duplicate_observations_are_refused():
    with refused("observation_duplicate"):
        FXBook([rate(value="1.1"), rate(value="1.2")])
    with refused("observation_duplicate"):
        IndexBook([point(value="100"), point(value="101")])


def test_a_malformed_policy_is_refused():
    for over in (
        {"providers": ()},
        {"providers": (REF, REF)},
        {"providers": [REF]},
        {"providers": (" ",)},
        {"providers": (REF,), "rate_types": ("spot",)},
        {"providers": (REF,), "rate_types": ()},
        {"providers": (REF,), "weekend_holiday_rule": "nearest"},
        {"providers": (REF,), "missing_rate": "carry_forward"},
        {"providers": (REF,), "freshness_days": -1},
        {"providers": (REF,), "freshness_days": True},
        {"providers": (REF,), "max_interpolation_gap_days": 1.5},
    ):
        with refused("policy_invalid"):
            FXPolicy(**over)
    with refused("policy_invalid"):
        policy(lag=-1)


# ============================================================ native and chain


def test_the_native_amount_and_currency_are_never_overwritten(fx_book, index_book):
    native = eur("1000.00")
    result = normalize(
        native, event_date=EVENT, valuation_date=VALUATION, policy=policy(), fx_book=fx_book, index_book=index_book
    )
    assert result.native is native and result.chain[0].input is native
    assert (native.amount, native.currency, native.amount.as_tuple().exponent) == (Decimal("1000.00"), "EUR", -2)
    assert result.as_dict()["native"] == {"amount": "1000", "currency": "EUR"}
    assert result.value.currency == "EUR" and result.value is not native


def _floats(value) -> list:
    if isinstance(value, float):
        return [value]
    if isinstance(value, dict):
        return [f for v in value.values() for f in _floats(v)]
    if isinstance(value, list):
        return [f for v in value for f in _floats(v)]
    return []


def test_the_chain_records_every_rate_and_index_with_its_provenance(fx_book, index_book):
    result = normalize(
        eur("1000"), event_date=EVENT, valuation_date=VALUATION, policy=policy(), fx_book=fx_book, index_book=index_book
    )
    record = result.as_dict()
    assert json.loads(json.dumps(record)) == record and not _floats(record)
    assert record["order"] == ["event_fx", "cost_index", "valuation_fx"]
    assert record["display"] == "1309.52 EUR"
    assert record["arithmetic"] == "Decimal, 60 significant digits, ROUND_HALF_EVEN"
    event_fx, indexed, valuation_fx = record["chain"]
    for step, day, direction in ((event_fx, "2020-03-02", "direct"), (valuation_fx, "2026-10-08", "inverted")):
        assert (step["rule"], step["rate_date"], step["direction"], step["rate_type"]) == (
            "exact", day, direction, "reference"
        )
        (observation,) = step["observations"]
        assert observation["provider"] == REF and observation["effective_date"] == day
        assert observation["source_snapshot_hash"] == SNAPSHOT_HASH
        assert observation["source_key"] == "synthetic-fx-and-cost-index"
    assert valuation_fx["quoted_rate"] == "1.05" and valuation_fx["factor"].startswith("0.952380952380")
    assert (indexed["ratio"], indexed["from_period"], indexed["period_used"]) == ("1.25", "2020-03", "2026-10")
    assert [o["vintage_date"] for o in indexed["observations"]] == ["2020-04-10", "2026-10-08"]
    assert {o["source_snapshot_hash"] for o in indexed["observations"]} == {SNAPSHOT_HASH}
    assert event_fx["output"] == indexed["input"] and indexed["output"] == valuation_fx["input"]
    assert valuation_fx["output"] == record["value"]


def test_a_downgrade_lowers_a_grade_no_further_than_d():
    assert downgraded(ConfidenceGrade.A, 0) is ConfidenceGrade.A
    assert downgraded(ConfidenceGrade.A, 2) is ConfidenceGrade.C
    assert downgraded(ConfidenceGrade.C, 5) is ConfidenceGrade.D
    assert downgraded(ConfidenceGrade.UNKNOWN, 1) is ConfidenceGrade.UNKNOWN
    with pytest.raises(ValueError):
        downgraded(ConfidenceGrade.A, -1)


# ==================================================================== snapshot


def test_the_snapshot_is_synthetic_test_data_and_its_hash_is_pinned(snap):
    data = SNAPSHOT_PATH.read_bytes()
    assert snapshot.snapshot_hash(data) == snap.snapshot_hash == SNAPSHOT_HASH
    assert snap.synthetic is True
    assert snap.label.startswith("SYNTHETIC TEST DATA") and snap.source["dataset"].startswith("SYNTHETIC TEST DATA")
    assert (snap.source["license_class"], snap.source["trust_tier"]) == ("open", "unverified")
    assert {r.provider for r in snap.fx_rates} == {REF, MKT}
    assert all(r.source_snapshot_hash == SNAPSHOT_HASH for r in snap.fx_rates)
    assert all(p.source_snapshot_hash == SNAPSHOT_HASH for p in snap.index_points)
    assert all("SYNTHETIC" in p.category for p in snap.index_points)
    assert SNAPSHOT_HASH in SPEC.read_text(encoding="utf-8")


def _edited(change) -> bytes:
    document = json.loads(SNAPSHOT_PATH.read_bytes())
    change(document)
    return json.dumps(document).encode("utf-8")


@pytest.mark.parametrize(
    "change, code",
    [
        (lambda d: d["fx"][0].update(rate=1.1), "not_decimal"),
        (lambda d: d["cost_index"][0].update(value=100), "not_decimal"),
        (lambda d: d["fx"][0].update(rate="NaN"), "not_finite"),
        (lambda d: d["fx"][0].update(rate="-1.1"), "rate_not_positive"),
        (lambda d: d["fx"][0].update(observed_at="2020-03-02T15:00:00"), "date_malformed"),
        (lambda d: d["fx"].append(dict(d["fx"][0])), "observation_duplicate"),
        (lambda d: d["source"].update(trust_tier="authoritative"), "snapshot_malformed"),
        (lambda d: d.update(label="test data"), "snapshot_malformed"),
        (lambda d: d["source"].update(dataset="FX rates"), "snapshot_malformed"),
        (lambda d: d.update(extra=1), "snapshot_malformed"),
        (lambda d: d.update(schema="something/v2"), "snapshot_malformed"),
        (lambda d: d["source"].update(license_class="free"), "snapshot_malformed"),
    ],
)
def test_a_broken_snapshot_is_refused(change, code):
    with refused(code):
        snapshot.parse_snapshot(_edited(change))


def test_the_snapshot_hash_moves_with_any_edit():
    edited = _edited(lambda d: d["fx"][0].update(rate="1.1001"))
    assert snapshot.parse_snapshot(edited).snapshot_hash != SNAPSHOT_HASH


def test_a_rate_is_never_read_as_a_float_from_a_snapshot(snap):
    assert all(type(r.rate) is Decimal for r in snap.fx_rates)
    assert all(type(p.value) is Decimal for p in snap.index_points)
    assert snap.fx_book().rate(REF, "reference", "EUR", "USD", EVENT).rate == Decimal("1.1000")


def test_an_interpolated_rate_records_its_weight_and_age():
    """Monday 1.1 and Wednesday 1.3: Tuesday, missing, is estimated at 1.2."""
    book = FXBook([rate(effective_date=EVENT), rate(effective_date=EVENT + timedelta(days=2), value="1.3")])
    step = fx.convert(eur("10"), "USD", EVENT + timedelta(days=1), book, FXPolicy((REF,), missing_rate="interpolate"))
    assert (step.quoted_rate, step.interpolation_weight, step.age_days) == (Decimal("1.2"), Decimal("0.5"), 1)
