"""Economic Exposure, MVP step 12 (part B): the primary source, a fallback past it, and
sources that disagree (``docs/economics/spec-v1.md``, section 12.8).

The lead's decision of 13 Oct 2026, as refined the same day: a conversion's PRIMARY is
the first provider in the policy's ``providers`` with a usable rate, never chosen by
value; where a later provider's rate is used the record says so
(``primary_unavailable``); every other usable source quoting the same pair on the same
date (or the same index series and month) more than the tolerance away from the value
used -- FX 0.5%, cost index 1.0%, relative to the primary -- is a conflict the
normalization record lists, with the downgrade ``source_disagreement``, one grade step
for the line. At or under the tolerance nothing is flagged.

The figures are those of the Minotaur answer key that measures this
(Minotaur-Engine #79, ``athena-economics-data``, cases 18 to 20): EUR 400,000 on 30
September 2026 in USD that day, the ECB quoting EUR/USD 1.1230 and H.10 1.1310. Every
rate here is made up for the test. SYNTHETIC / ILLUSTRATIVE.
"""

from __future__ import annotations

import json
import random
from datetime import date, datetime, timezone
from decimal import Decimal
from pathlib import Path

import pytest

from assurance.economics import normalization_service, snapshots
from assurance.economics.engine import cost_index, fx, money, normalization
from assurance.economics.engine.confidence import ConfidenceGrade
from assurance.economics.engine.cost_index import IndexBook, IndexPoint, IndexSelector
from assurance.economics.engine.fx import FXBook, FXPolicy, FXRate
from assurance.economics.engine.money import Money, MoneyRefused, Unavailable
from assurance.economics.engine.normalization import NormalizationPolicy, normalize
from assurance.economics.engine.snapshot import parse_snapshot
from assurance.models import Deployment

SPEC = Path(__file__).resolve().parent.parent / "docs" / "economics" / "spec-v1.md"
HASH = "sha256:" + "e" * 64
DAY = date(2026, 9, 30)
ECB, H10, TEST = "ecb-eur-reference-rates", "fed-h10-daily-rates", "minotaur-test-fx-and-index"
CPI = IndexSelector("MINOTAUR-TEST-CPI-US", "US", "Minotaur test consumer prices, all items", "2020-03=100", "USD")
#: The key's relative differences: 0.008 / 1.1230 and 0.008 / 1.1310, at 60 digits.
ECB_PRIMARY = "0.00712377560106856634016028495102404274265360641139804096170971"
H10_PRIMARY = "0.00707338638373121131741821396993810786914235190097259062776304"


def rate(provider: str, key: str, value: str, *, base="EUR", quote="USD", day=DAY, rate_type="reference") -> FXRate:
    return FXRate(base, quote, Decimal(value), rate_type, provider, datetime(2026, 9, 30, 15, tzinfo=timezone.utc), day,
                  HASH, source_key=key)


def cpi(period: str, value: str, *, provider="MINOTAUR-TEST-REF", key=TEST, vintage=None, series=CPI) -> IndexPoint:
    end = cost_index.period_end(period)
    return IndexPoint(series.series_id, series.geography, series.category, series.base, period, Decimal(value),
                      vintage or end, HASH, source_key=key, provider=provider)


INDEX = IndexBook([cpi("2026-09", "325.500")])


def eur_to_usd(rates, providers, *, index=INDEX, amount="400000", event=DAY, valuation=DAY, **rules):
    policy = NormalizationPolicy("USD", "USD", FXPolicy(tuple(providers), **rules), CPI)
    return normalize(Money(Decimal(amount), "EUR"), event_date=event, valuation_date=valuation, policy=policy,
                     fx_book=FXBook(rates), index_book=index)


def key_fields(conflict: dict) -> dict:
    """What the Minotaur key reads of a conflict (its ``CONFLICT_FIELDS``)."""
    names = ("pair", "date", "primary", "primary_value", "secondary", "secondary_value", "relative_difference")
    return {name: conflict[name] for name in names}


def the_two(h10_value: str, ecb_value: str = "1.1230") -> list[FXRate]:
    return [rate("ECB", ECB, ecb_value), rate("FRB-H10", H10, h10_value)]


# ====================================================================
# Over, at and under the tolerance (the key's cases 18 and 19)
# ====================================================================


def test_over_the_tolerance_the_primary_is_used_and_the_conflict_listed():
    result = eur_to_usd(the_two("1.1310"), ("ECB", "FRB-H10"))
    record = result.as_dict()
    assert (record["value"]["amount"], record["display"]) == ("449200", "449200.00 USD")
    assert record["chain"][0]["provider"] == "ECB" and record["chain"][0]["quoted_rate"] == "1.123"
    (conflict,) = record["conflicts"]
    assert key_fields(conflict) == {
        "pair": "EUR/USD", "date": "2026-09-30", "primary": ECB, "primary_value": "1.123", "secondary": H10,
        "secondary_value": "1.131", "relative_difference": ECB_PRIMARY,
    }
    assert (conflict["kind"], conflict["step"], conflict["tolerance"]) == ("fx", "event_fx", "0.005")
    assert (conflict["primary_provider"], conflict["secondary_provider"]) == ("ECB", "FRB-H10")
    assert record["confidence_downgrades"] == ["source_disagreement"]
    assert record["chain"][0]["downgrades"] == ["source_disagreement"] and record["chain"][0]["conflicts"] == [conflict]
    assert result.graded(ConfidenceGrade.A) is ConfidenceGrade.B
    assert record["primary_unavailable"] == []


@pytest.mark.parametrize(
    "h10_value, flagged",
    [
        ("1.128615", False),  # exactly 0.5% over the ECB's, relative to it: 0.005615 / 1.1230
        ("1.128616", True),  # a millionth more
        ("1.117385", False),  # exactly 0.5% under it
        ("1.117384", True),
        ("1.1280", False),  # under the tolerance
        ("1.1230", False),  # the same rate
    ],
)
def test_at_or_under_the_tolerance_nothing_is_flagged(h10_value, flagged):
    record = eur_to_usd(the_two(h10_value), ("ECB", "FRB-H10")).as_dict()
    assert record["display"] == "449200.00 USD" and record["chain"][0]["provider"] == "ECB"
    assert bool(record["conflicts"]) is flagged
    assert record["confidence_downgrades"] == (["source_disagreement"] if flagged else [])


# ====================================================================
# The favourable secondary is never chosen (the key's case 20)
# ====================================================================


def test_the_favourable_secondary_is_never_chosen():
    """H.10 is the policy's first: its 1.1310 is used, although the ECB's 1.1230 would
    state the smaller figure (449,200.00). The difference is relative to H.10."""
    record = eur_to_usd(the_two("1.1310"), ("FRB-H10", "ECB")).as_dict()
    assert (record["value"]["amount"], record["display"]) == ("452400", "452400.00 USD")
    assert record["chain"][0]["provider"] == "FRB-H10"
    (conflict,) = record["conflicts"]
    assert key_fields(conflict) == {
        "pair": "EUR/USD", "date": "2026-09-30", "primary": H10, "primary_value": "1.131", "secondary": ECB,
        "secondary_value": "1.123", "relative_difference": H10_PRIMARY,
    }
    assert record["confidence_downgrades"] == ["source_disagreement"]
    # The mirror: the ECB first and H.10 the lower: the ECB's figure, not H.10's 446,000.00.
    mirror = eur_to_usd(the_two("1.1150"), ("ECB", "FRB-H10")).as_dict()
    assert mirror["display"] == "449200.00 USD" and mirror["conflicts"][0]["secondary_value"] == "1.115"


def test_a_secondary_quoted_the_other_way_round_is_compared_in_the_pairs_direction():
    """H.10 quoting USD/EUR 0.8800 is EUR/USD 1/0.88 = 1.13636...: compared as that,
    relative to the ECB's 1.1230, and listed both ways."""
    rates = [rate("ECB", ECB, "1.1230"), rate("FRB-H10", H10, "0.8800", base="USD", quote="EUR")]
    record = eur_to_usd(rates, ("ECB", "FRB-H10")).as_dict()
    (conflict,) = record["conflicts"]
    inverted = money.compute(lambda: Decimal(1) / Decimal("0.88"))
    assert conflict["pair"] == "EUR/USD" and Decimal(conflict["secondary_value"]) == inverted
    assert Decimal(conflict["relative_difference"]) == money.compute(
        lambda: abs(inverted - Decimal("1.1230")) / Decimal("1.1230"))
    assert conflict["secondary_quoted"] == {"base": "USD", "quote": "EUR", "rate": "0.88", "direction": "inverted"}


def test_a_source_the_policy_leaves_out_is_still_compared():
    """A policy that names only the ECB cannot hide H.10's disagreement: every usable
    source in the books is compared. Only the policy's provider is ever used."""
    record = eur_to_usd(the_two("1.1310"), ("ECB",)).as_dict()
    assert record["display"] == "449200.00 USD"
    assert [c["secondary"] for c in record["conflicts"]] == [H10]


def test_disagreement_is_one_grade_step_for_the_whole_normalization():
    """Both conversions disagree (EUR to USD on the event date, USD back to EUR on the
    valuation date): both conflicts are listed, and the line is lowered one step."""
    rates = the_two("1.1310") + [rate("ECB", ECB, "1.1000", day=date(2026, 10, 30)),
                                 rate("FRB-H10", H10, "1.1100", day=date(2026, 10, 30))]
    index = IndexBook([cpi("2026-09", "325.500"), cpi("2026-10", "325.500")])
    policy = NormalizationPolicy("USD", "EUR", FXPolicy(("ECB", "FRB-H10")), CPI)
    result = normalize(Money(Decimal("400000"), "EUR"), event_date=DAY, valuation_date=date(2026, 10, 31),
                       policy=policy, fx_book=FXBook(rates), index_book=index)
    assert result.status == "normalized", result.as_dict()["unavailable"]
    record = result.as_dict()
    assert [c["step"] for c in record["conflicts"]] == ["event_fx", "valuation_fx"]
    assert record["chain"][2]["rule"] == "last_official_rate"  # Saturday the 31st reads Friday's rates
    assert record["conflicts"][1]["date"] == "2026-10-30"
    assert record["confidence_downgrades"] == ["source_disagreement"]
    assert result.graded(ConfidenceGrade.A) is ConfidenceGrade.B


def test_an_interpolated_estimate_is_not_compared():
    """An estimate is a rate no source quoted: there is nothing to compare it with."""
    rates = [rate("ECB", ECB, "1.1200", day=date(2026, 9, 29)), rate("ECB", ECB, "1.1260", day=date(2026, 10, 1)),
             rate("FRB-H10", H10, "1.2000")]
    record = eur_to_usd(rates, ("ECB",), missing_rate="interpolate").as_dict()
    assert record["chain"][0]["rule"] == "linear_interpolation" and record["conflicts"] == []
    assert record["confidence_downgrades"] == ["estimated_rate"]


# ====================================================================
# A fallback past the primary is never silent (the section 28 audit, T8)
# ====================================================================


def test_a_fallback_past_the_primary_carries_primary_unavailable_and_names_both():
    record = eur_to_usd([rate("FRB-H10", H10, "1.1310")], ("ECB", "FRB-H10")).as_dict()
    assert record["display"] == "452400.00 USD"
    step = record["chain"][0]
    assert (step["configured_primary"], step["provider"], step["primary_unavailable"]) == ("ECB", "FRB-H10", True)
    assert step["downgrades"] == ["primary_unavailable"]
    assert record["primary_unavailable"] == [{"step": "event_fx", "primary": "ECB", "used": "FRB-H10"}]
    assert record["confidence_downgrades"] == ["primary_unavailable"]
    # The primary there: no fallback, no downgrade.
    there = eur_to_usd(the_two("1.1240"), ("ECB", "FRB-H10")).as_dict()
    assert there["primary_unavailable"] == [] and there["confidence_downgrades"] == []
    assert there["chain"][0]["primary_unavailable"] is False


def test_a_weekend_reads_the_primarys_last_official_rate_not_a_fallback():
    saturday = date(2026, 10, 3)
    rates = [rate("ECB", ECB, "1.1230", day=date(2026, 10, 2)), rate("FRB-H10", H10, "1.1240", day=date(2026, 10, 2))]
    index = IndexBook([cpi("2026-10", "325.500", vintage=date(2026, 10, 31))])
    policy = NormalizationPolicy("USD", "USD", FXPolicy(("ECB", "FRB-H10")), CPI)
    result = normalize(Money(Decimal("1"), "EUR"), event_date=saturday, valuation_date=date(2026, 10, 31),
                       policy=policy, fx_book=FXBook(rates), index_book=index)
    step = result.as_dict()["chain"][0]
    assert (step["rule"], step["provider"], step["primary_unavailable"]) == ("last_official_rate", "ECB", False)


def test_a_fallback_and_a_disagreement_each_lower_the_line_once():
    """H.10 used past the ECB, and a third source disagreeing with it: two downgrades,
    two steps, each named once."""
    rates = [rate("FRB-H10", H10, "1.1310"), rate("OTHER", "other-rates", "1.2000")]
    result = eur_to_usd(rates, ("ECB", "FRB-H10"))
    assert result.confidence_downgrades == ("source_disagreement", "primary_unavailable")
    assert result.graded(ConfidenceGrade.A) is ConfidenceGrade.C
    assert result.as_dict()["conflicts"][0]["primary"] == H10


def test_no_primary_configured_is_step_3s_refusal():
    """With no provider named there is nothing to normalize: the policy is refused
    (policy_invalid), as section 12.2 always refused it. Nothing is chosen."""
    with pytest.raises(MoneyRefused) as refused:
        FXPolicy(())
    assert refused.value.code == "policy_invalid"


# ====================================================================
# A cost index: the same series and month from two sources, at 1.0%
# ====================================================================

MIRROR = "MIRROR-CPI"


def index_twice(mirror_value: str, *, mirror_vintage=None):
    return IndexBook([
        cpi("2026-08", "320.000"), cpi("2026-09", "325.500"),
        cpi("2026-08", "320.000", provider=MIRROR, key="mirror-cpi", vintage=mirror_vintage),
        cpi("2026-09", mirror_value, provider=MIRROR, key="mirror-cpi", vintage=mirror_vintage),
    ])


def indexed(book, providers=("MINOTAUR-TEST-REF",)):
    return cost_index.index(Money(Decimal("1000"), "USD"), date(2026, 8, 15), DAY, book, CPI, providers=providers)


@pytest.mark.parametrize(
    "mirror_value, flagged",
    [("328.755", False), ("328.756", True), ("322.245", False), ("322.244", True), ("326", False)],
)
def test_an_index_over_one_percent_is_flagged_and_at_it_is_not(mirror_value, flagged):
    """325.500 x 1.01 = 328.755: exactly 1.0% is not flagged, a thousandth more is."""
    step = indexed(index_twice(mirror_value))
    record = step.as_dict()
    assert record["provider"] == "MINOTAUR-TEST-REF" and record["ratio"] == money.decimal_text(
        money.compute(lambda: Decimal("325.500") / Decimal("320.000")))
    assert bool(record["conflicts"]) is flagged
    assert record["downgrades"] == (["source_disagreement"] if flagged else [])
    if flagged:
        (conflict,) = record["conflicts"]
        assert (conflict["kind"], conflict["series"], conflict["period"], conflict["primary"], conflict["secondary"]) == (
            "cost_index", CPI.series_id, "2026-09", TEST, "mirror-cpi")
        assert conflict["tolerance"] == "0.01"
        assert Decimal(conflict["relative_difference"]) == money.compute(
            lambda: abs(Decimal(mirror_value) - Decimal("325.5")) / Decimal("325.5"))


def test_an_index_reads_the_policys_source_never_the_favourable_one():
    """The mirror's lower September would index the cost by less; the policy's source is
    read all the same, and the mirror is listed against it."""
    step = indexed(index_twice("300.000"))
    assert step.provider == "MINOTAUR-TEST-REF" and step.to_point.value == Decimal("325.500")
    favoured = indexed(index_twice("300.000"), providers=(MIRROR, "MINOTAUR-TEST-REF"))
    assert favoured.provider == MIRROR and favoured.conflicts[0]["secondary_value"] == "325.5"


def test_an_index_no_policy_names_is_never_chosen_between_when_its_sources_disagree():
    book = index_twice("300.000")
    refused = indexed(book, providers=("ECB",))
    assert isinstance(refused, Unavailable) and refused.reason == "index_primary_unset"
    # Agreeing, the choice is immaterial: the first by name is read, and nothing is flagged.
    agreeing = indexed(index_twice("325.600"), providers=("ECB",))
    assert agreeing.provider == "MINOTAUR-TEST-REF" and agreeing.conflicts == () and agreeing.downgrades == ()
    assert agreeing.configured_primary is None


def test_an_index_past_its_primary_carries_primary_unavailable():
    """The policy's index source has no September yet; the mirror's is read, and the
    step says so."""
    book = IndexBook([cpi("2026-08", "320.000"), cpi("2026-08", "320.000", provider=MIRROR, key="mirror-cpi"),
                      cpi("2026-09", "325.500", provider=MIRROR, key="mirror-cpi")])
    step = indexed(book)
    record = step.as_dict()
    assert (record["provider"], record["configured_primary"], record["downgrades"]) == (
        MIRROR, "MINOTAUR-TEST-REF", ["primary_unavailable"])


def test_two_providers_may_publish_one_series_on_one_day():
    """Each provider's values are held apart: the same month and vintage from two
    publishers is no duplicate. From one, it still is."""
    book = index_twice("325.500")
    assert book.providers(CPI) == ["MINOTAUR-TEST-REF", MIRROR]
    with pytest.raises(MoneyRefused) as refused:
        IndexBook([cpi("2026-09", "325.500"), cpi("2026-09", "325.600")])
    assert refused.value.code == "observation_duplicate"


# ====================================================================
# Determinism
# ====================================================================


def test_the_record_is_the_same_whatever_order_the_books_were_filled_in():
    rates = the_two("1.1310") + [rate("OTHER", "other-rates", "1.2000"), rate("ZED", "zed-rates", "1.0000")]
    records = set()
    for seed in range(5):
        shuffled = rates[:]
        random.Random(seed).shuffle(shuffled)
        record = eur_to_usd(shuffled, ("ECB", "FRB-H10")).as_dict()
        assert json.loads(json.dumps(record)) == record
        records.add(json.dumps(record, sort_keys=True))
    (record,) = [json.loads(text) for text in records]
    assert [c["secondary"] for c in record["conflicts"]] == [H10, "other-rates", "zed-rates"]


# ====================================================================
# For a deployment: only the sources a run of it may use (section 12.8)
# ====================================================================


def _register(key, provider, *, fx_rates=(), points=(), tier="benchmark", licence="open", deployment=None,
              retrieved="2026-09-30T18:00:00+00:00"):
    document = {
        "schema": "mythos.economics.observation-snapshot/v1",
        "label": "Test data for the source-disagreement tests: made up, not a source for any figure",
        "synthetic": False,
        "source": {"source_key": key, "provider": provider, "dataset": f"{provider} test rates", "url": "",
                   "license_class": licence, "trust_tier": tier, "retrieved_at": retrieved, "schema_version": "1"},
        "calendars": {},
        "fx": [{"base": base, "quote": quote, "rate": value, "rate_type": "reference", "provider": provider,
                "observed_at": f"{day}T15:00:00+00:00", "effective_date": day} for base, quote, day, value in fx_rates],
        "cost_index": [{"series_id": CPI.series_id, "geography": CPI.geography, "category": CPI.category,
                        "base": CPI.base, "period": period, "value": value, "vintage_date": vintage}
                       for period, value, vintage in points],
    }
    version, _ = snapshots.register(parse_snapshot(json.dumps(document).encode()), deployment=deployment)
    return version


def _posted(h10_value="1.1310", *, ecb_tier="benchmark", h10_licence="open"):
    _register(ECB, "ECB", fx_rates=[("EUR", "USD", "2026-09-30", "1.1230")], tier=ecb_tier)
    _register(H10, "FRB-H10", fx_rates=[("EUR", "USD", "2026-09-30", h10_value)], licence=h10_licence,
              retrieved="2026-10-05T16:00:00+00:00")
    _register(TEST, "MINOTAUR-TEST-REF", points=[("2026-09", "325.500", "2026-09-30")])


def _normalized(deployment, providers):
    policy = NormalizationPolicy("USD", "USD", FXPolicy(tuple(providers)), CPI)
    return normalization_service.normalize_for(deployment, Money(Decimal("400000"), "EUR"), event_date=DAY,
                                               valuation_date=DAY, policy=policy)


@pytest.fixture
def staging():
    return Deployment.objects.create(name="payments-staging", environment="staging")


@pytest.mark.django_db
@pytest.mark.parametrize(
    "h10_value, providers, display, conflict",
    [
        ("1.1310", ("ECB", "FRB-H10"), "449200.00 USD", (ECB, "1.123", H10, "1.131", ECB_PRIMARY)),
        ("1.128615", ("ECB", "FRB-H10"), "449200.00 USD", None),
        ("1.1310", ("FRB-H10", "ECB"), "452400.00 USD", (H10, "1.131", ECB, "1.123", H10_PRIMARY)),
    ],
)
def test_the_keys_cases_for_a_deployment(staging, h10_value, providers, display, conflict):
    """Minotaur-Engine #79's cases 18 to 20, played on stored source versions: each
    conflict names the sources by their registry keys."""
    _posted(h10_value)
    record = _normalized(staging, providers).as_dict()
    assert record["display"] == display and record["chain"][0]["provider"] == providers[0]
    if conflict is None:
        assert record["conflicts"] == [] and record["confidence_downgrades"] == []
    else:
        (found,) = record["conflicts"]
        assert key_fields(found) == dict(zip(
            ("pair", "date", "primary", "primary_value", "secondary", "secondary_value", "relative_difference"),
            ("EUR/USD", "2026-09-30", *conflict)))
        assert record["confidence_downgrades"] == ["source_disagreement"]
    assert record["chain"][0]["observations"][0]["source_version"] == 1


@pytest.mark.django_db
def test_a_primary_the_gate_refuses_is_unavailable_and_never_silent():
    """A production deployment: the ECB's version is still unverified, which a
    production run may not use, so the ECB has no usable rate: H.10's is used, the
    record names both, and the ECB's unusable rate is not compared."""
    production = Deployment.objects.create(name="payments-prod", environment="production")
    _posted("1.1310", ecb_tier="unverified")
    record = _normalized(production, ("ECB", "FRB-H10")).as_dict()
    assert record["display"] == "452400.00 USD"
    assert record["primary_unavailable"] == [{"step": "event_fx", "primary": "ECB", "used": "FRB-H10"}]
    assert record["confidence_downgrades"] == ["primary_unavailable"] and record["conflicts"] == []


@pytest.mark.django_db
def test_a_secondary_the_gate_refuses_is_not_compared(staging):
    _posted("1.1310", h10_licence="unreviewed")
    record = _normalized(staging, ("ECB", "FRB-H10")).as_dict()
    assert record["display"] == "449200.00 USD" and record["conflicts"] == []
    assert [v.source_key for v in normalization_service.usable_versions(staging, DAY)] == [ECB, TEST]


@pytest.mark.django_db
def test_a_version_that_does_not_cover_the_date_is_not_read(staging):
    """H.10's newer version starts after the valuation date: it does not cover it, and
    is not read; the older one, which agrees with the ECB, is. Covering it, the newer
    one is read, and its disagreement is listed."""
    _posted("1.1240")
    later = _register(H10, "FRB-H10", fx_rates=[("EUR", "USD", "2026-10-02", "1.1600")],
                      retrieved="2026-10-07T16:00:00+00:00")
    assert later.version == 2
    used = {v.source_key: v.version for v in normalization_service.usable_versions(staging, DAY)}
    assert used[H10] == 1
    assert _normalized(staging, ("ECB", "FRB-H10")).as_dict()["conflicts"] == []
    _register(H10, "FRB-H10", fx_rates=[("EUR", "USD", "2026-09-30", "1.1500"), ("EUR", "USD", "2026-10-02", "1.1600")],
              retrieved="2026-10-08T16:00:00+00:00")
    assert {v.source_key: v.version for v in normalization_service.usable_versions(staging, DAY)}[H10] == 3
    record = _normalized(staging, ("ECB", "FRB-H10")).as_dict()
    assert [c["secondary_value"] for c in record["conflicts"]] == ["1.15"]


@pytest.mark.django_db
def test_tenancy_another_deployments_source_is_never_read(staging):
    """The second deployment's own source quotes EUR/USD 1.2000: its normalization
    lists the conflict; the first deployment's never reads that source."""
    other = Deployment.objects.create(name="another-bank", environment="staging")
    _posted("1.1240")
    _register("own-bank-rates", "OWN-BANK", fx_rates=[("EUR", "USD", "2026-09-30", "1.2000")], deployment=other)
    mine = _normalized(staging, ("ECB", "FRB-H10")).as_dict()
    theirs = _normalized(other, ("ECB", "FRB-H10")).as_dict()
    assert mine["conflicts"] == [] and mine["confidence_downgrades"] == []
    assert [c["secondary"] for c in theirs["conflicts"]] == ["own-bank-rates"]
    assert "own-bank-rates" not in {v.source_key for v in normalization_service.usable_versions(staging, DAY)}


@pytest.mark.django_db
def test_a_deployments_normalization_is_deterministic(staging):
    _posted("1.1310")
    first, second = (_normalized(staging, ("ECB", "FRB-H10")).as_dict() for _ in range(2))
    assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)


# ====================================================================
# The spec states it
# ====================================================================

PHRASES = (
    "12.8 The primary source, and sources that disagree (MVP step 12)",
    "is the first provider in the policy's `providers` that has a usable rate",
    "A fallback is never silent",
    "At or under the tolerance nothing is flagged.",
    "never the one that would state the smaller figure",
    "each lower a normalization ONE grade step however many of its steps carry them",
)


@pytest.mark.parametrize("phrase", PHRASES)
def test_the_spec_states_the_rules(phrase):
    text = " ".join(SPEC.read_text(encoding="utf-8").split())
    assert phrase in text


def test_the_tolerances_and_codes_are_the_published_ones():
    assert (fx.DISAGREEMENT_TOLERANCE, cost_index.DISAGREEMENT_TOLERANCE) == (Decimal("0.005"), Decimal("0.010"))
    assert {money.SOURCE_DISAGREEMENT, money.PRIMARY_UNAVAILABLE} <= set(normalization.DOWNGRADES)
    assert "index_primary_unset" in money.UNAVAILABLE_REASONS
