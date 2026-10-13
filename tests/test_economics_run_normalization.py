"""Economic Exposure: figures normalized into a run's reporting currency when its
scenario version is built (``docs/economics/spec-v1.md``, section 36).

A build that states a normalization policy normalizes each parameter-set figure it
reads that is stated in another currency than the build's, or at another date than its
as-of date (the run's valuation date), through the normalization route's own service
(``normalization_service.normalize_for``), over the source versions a run of the
deployment may use: event-date FX into the base currency, the cost index to the
valuation month, valuation-date FX into the reporting currency. The build reads the
normalized figure; its record is stored append-only, is in every run's canonical
inputs (so the input digest covers it), is listed by the report's currency bridge, and
its downgrades lower each line of the Validity Card that reads it. A build that
normalizes nothing is exactly what it was.

Every rate, index value and figure here is made up for the test. SYNTHETIC / ILLUSTRATIVE.
"""

from __future__ import annotations

import copy
import json
from dataclasses import replace
from datetime import date
from decimal import Decimal
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.contrib.auth import get_user_model
from mythos_core import exposure_receipt as core
from rest_framework.test import APIClient

from assurance.economics import builder, receipt_service, report, simulation_service, snapshots, validity_service
from assurance.economics.engine import grade
from assurance.economics.engine import scenario_simulation as ss
from assurance.economics.engine.money import MoneyRefused
from assurance.economics.engine.snapshot import parse_snapshot
from assurance.economics.models import (
    CustomerParameterSet,
    EconomicsRefused,
    FinancialParameter,
    FinancialScenario,
    SimulationResult,
)
from assurance.models import Asset, Deployment, Finding
from tests.test_economics_scenarios import _entry

pytestmark = pytest.mark.django_db
User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "docs" / "economics" / "spec-v1.md"
README = REPO / "README.md"
LABEL = "SYNTHETIC / ILLUSTRATIVE"
SET_KEY = "bank_fx_2026q3"
EVENT = "2020-03-02"  # a Monday
SATURDAY = "2020-02-29"
VALUATION = "2026-09-30"  # the last day of September: its index value is published that day
REF, ALT = "run-test-fx-and-index", "run-test-alt-fx"
SERIES = {"series_id": "RUN-TEST-CPI-US", "geography": "US",
          "category": "Run-normalization test consumer prices, all items", "base": "2020-03=100"}
POLICY = {"base_currency": "USD", "providers": ["RUN-TEST-REF"], "index": SERIES}
#: The test book: EUR/USD 1.1, USD/JPY 125 (a JPY figure reads it the other way
#: round: 1/125 = 0.008), KWD/USD 3.2 on the event date; EUR/USD 1.08 the Friday
#: before a Saturday; the index 100 in February and March 2020 and 125 in September
#: 2026, a ratio of 1.25.
REF_RATES = [
    ("EUR", "USD", EVENT, "1.1"), ("USD", "JPY", EVENT, "125"), ("KWD", "USD", EVENT, "3.2"),
    ("EUR", "USD", "2020-02-28", "1.08"),
]
REF_POINTS = [("2020-02", "100", "2020-03-12"), ("2020-03", "100", "2020-04-10"), ("2026-09", "125", VALUATION)]
#: The grade's v3 version digest, as master computes it: a run that normalized nothing
#: is graded exactly as before section 36.
GRADE_V3_DIGEST = "sha256:282d5436d851905e864c75ce0e11fdffdd5646465b7b2318b65d894cb6a0871e"


@pytest.fixture
def people():
    return {
        "admin": User.objects.create_user(username="ada", password="x", role="admin"),
        "analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
        "owner": User.objects.create_user(username="vic", password="x", role="viewer"),
    }


@pytest.fixture
def deployment(people):
    return Deployment.objects.create(name="payments-staging", environment="staging", owner=people["owner"])


def register(key, provider, *, fx_rates=(), points=(), licence="open", tier="benchmark", deployment=None,
             series=SERIES):
    document = {
        "schema": "mythos.economics.observation-snapshot/v1",
        "label": "Test data for the run-normalization tests: made up, not a source for any figure",
        "synthetic": False,
        "source": {"source_key": key, "provider": provider, "dataset": f"{provider} test rates", "url": "",
                   "license_class": licence, "trust_tier": tier, "retrieved_at": "2026-09-30T18:00:00+00:00",
                   "schema_version": "1"},
        "calendars": {},
        "fx": [{"base": base, "quote": quote, "rate": value, "rate_type": "reference", "provider": provider,
                "observed_at": f"{day}T15:00:00+00:00", "effective_date": day} for base, quote, day, value in fx_rates],
        "cost_index": [{**series, "period": period, "value": value, "vintage_date": vintage}
                       for period, value, vintage in points],
    }
    version, _ = snapshots.register(parse_snapshot(json.dumps(document).encode()), deployment=deployment)
    return version


def books(**kwargs):
    return register(REF, "RUN-TEST-REF", fx_rates=REF_RATES, points=REF_POINTS, **kwargs)


def money(unit, figure, currency, *, on=EVENT):
    return _entry(unit, figure, currency=currency, effective_date=on, evidence_ref=f"{LABEL}: the CFO's figure")


def attribute(unit, figure):
    entry = _entry(unit, figure, effective_date=VALUATION, evidence_ref=f"{LABEL}: an analyst's figure")
    if "currency" in entry:
        entry["currency"] = "USD"
    return entry


#: A USD scenario's figures: a EUR margin, a JPY engineering rate (0 decimal places)
#: and a KWD insurance policy (3), each stated on the event date.
FIGURES = {
    "margin_per_hour": money("money_per_hour", "800", "EUR"),
    "engineering_hourly_rate": money("money_per_hour", "25000", "JPY"),
    "insurance_deductible": money("money", "3125.125", "KWD"),
    "insurance_limit": money("money", "1000000", "KWD"),
}


#: Two events a year, for a run whose headline figures a receipt signs (an annual run).
FREQUENCY = {**_entry("count", "2", effective_date=VALUATION, evidence_ref=f"{LABEL}: loss history"),
             "distribution": {"id": "poisson", "version": 1, "params": {"rate": "2"}}}


def world(deployment, author, variables=None, *, frequency=None):
    document = {"variables": variables or FIGURES}
    if frequency is not None:
        document["frequency"] = frequency
    CustomerParameterSet.record(deployment, SET_KEY, document, author=author)
    asset = Asset.objects.create(deployment=deployment, kind="agent", name="core-banking-provider",
                                 identifier="agent://core-banking-provider")
    finding = Finding.objects.create(deployment=deployment, fingerprint="fp-outage", finding_type="provider_dependency",
                                     title="single provider, no failover", severity="high")
    return asset, finding


def body(asset, finding, *, policy=POLICY, as_of=VALUATION, title="Core banking provider outage"):
    effect = {
        "key": "outage", "origin": "hypothetical", "effect_type": "provider_outage",
        "asset": str(asset.uuid), "business_process": "payments",
        "attributes": {
            "outage_hours": attribute("hours", "10"),
            "recovery_fixed_cost": attribute("money", "5000"),
            "recovery_hours": attribute("hours", "8"),
            "sla_credit_per_hour": attribute("money_per_hour", "1000"),
            "sla_credit_cap": attribute("money", "7500"),
        },
    }
    document = {
        "title": title, "parameter_set": {"set_key": SET_KEY, "version": 1}, "currency": "USD", "as_of": as_of,
        "effects": [effect], "findings": [{"finding": str(finding.uuid), "effect": "outage", "role": "prerequisite"}],
    }
    if policy is not None:
        document["normalization"] = policy
    return document


def built(deployment, people, *, variables=None, policy=POLICY, frequency=None):
    asset, finding = world(deployment, people["analyst"], variables, frequency=frequency)
    scenario, created = builder.build(deployment, body(asset, finding, policy=policy), author=people["analyst"])
    assert created
    return scenario


def simulated(scenario) -> SimulationResult:
    outcome = simulation_service.simulate_scenario(scenario, seed=36, draws=1_000)
    assert outcome.completed, (outcome.code, outcome.detail)
    return outcome.result


def carded(scenario):
    result = simulated(scenario)
    outcome = validity_service.issue_card(result)
    assert outcome.card is not None, (outcome.code, outcome.detail)
    return result, outcome.card


def figure(scenario, name):
    return FinancialParameter.objects.get(scenario=scenario, name=f"normalized:{name}")


def figures(row):
    return row.currency, row.low, row.base, row.high


def records(result):
    return {record["figure"]: record for record in result.inputs["normalizations"]}


# ======================================================================
# The known answer: EUR, JPY (0 dp) and KWD (3 dp) into a USD run
# ======================================================================


def test_eur_jpy_and_kwd_figures_are_normalized_into_a_usd_run_in_closed_form(deployment, people):
    """EUR 800 an hour x 1.1 x 125/100 = USD 1,100; JPY 25,000 an hour x 1/125 (USD/JPY
    read the other way round) x 1.25 = USD 250; the KWD policy: KWD 3,125.125 x 3.2 x
    1.25 = USD 12,500.5 and KWD 1,000,000 x 3.2 x 1.25 = USD 4,000,000. The components,
    then: an interruption of 10 hours at USD 1,100 = 11,000; failover USD 5,000 + 8
    hours at USD 250 = 7,000; SLA credits min(10 x 1,000, 7,500) = 7,500; gross
    25,500, exactly, in the build and in the run."""
    books()
    scenario = built(deployment, people)
    assert figures(figure(scenario, "margin_per_hour")) == ("USD", "1100", "1100", "1100")
    assert figures(figure(scenario, "engineering_hourly_rate")) == ("USD", "250", "250", "250")
    assert figures(figure(scenario, "insurance_deductible")) == ("USD", "12500.5", "12500.5", "12500.5")
    assert figures(figure(scenario, "insurance_limit")) == ("USD", "4000000", "4000000", "4000000")
    # The native figures are never overwritten: the set's rows are as the customer stated them.
    native = {row.name: row for row in FinancialParameter.objects.filter(parameter_set__deployment=deployment)}
    assert (native["engineering_hourly_rate"].currency, native["engineering_hourly_rate"].base) == ("JPY", "25000")
    assert (native["insurance_deductible"].currency, native["insurance_deductible"].base) == ("KWD", "3125.125")

    described = builder.describe(scenario)
    (event,) = described["events"]
    by_id = {c["component_id"]: c for c in event["components"]}
    assert {key: by_id[key]["base"] for key in by_id} == {
        "interruption": "11000", "failover-recovery": "7000", "sla-credits": "7500"}
    assert described["totals"]["gross_cash"]["base"] == "25500"
    # The KWD policy, normalized: the contractual and recovery families are covered
    # (7,500 + 7,000), less the USD 12,500.5 deductible: USD 1,999.5 recovered, and
    # 23,500.5 retained.
    at_base = event["insurance"]["points"]["base"]
    assert (at_base["covered"], at_base["recovery"], at_base["retained"]) == ("14500", "1999.5", "23500.5")
    assert event["insurance"]["policy"]["deductible"]["name"] == "normalized:insurance_deductible"
    read = by_id["interruption"]["sources"]["value_per_hour"]["read"]
    assert read["name"] == "margin_per_hour" and read["normalized"]["currency"] == "EUR"

    result = simulated(scenario)
    assert result.record["scenario"]["gross_cash"]["p50"] == "25500"
    assert result.record["scenario"]["gross_cash"]["mean"] == "25500"
    assert result.record["scenario"]["retained_cash"]["p50"] == "23500.5"
    # The policy the run applies is the normalized one, in USD.
    terms = result.inputs["policy"]["terms"]
    assert (terms["deductible"], terms["limit"]) == ("normalized:insurance_deductible", "normalized:insurance_limit")


def test_each_record_is_its_figures_chain_with_the_reversed_quote_and_the_minor_units(deployment, people):
    books()
    result = simulated(built(deployment, people))
    held = records(result)
    assert sorted(held) == [f"normalized:{name}" for name in sorted(FIGURES)]
    jpy = held["normalized:engineering_hourly_rate"]
    assert jpy["native"]["currency"] == "JPY" and jpy["native"]["base"] == "25000"
    assert (jpy["event_date"], jpy["valuation_date"]) == (EVENT, VALUATION)
    step = jpy["points"]["base"]["chain"][0]
    assert (step["step"], step["direction"], step["quoted_rate"], step["factor"]) == (
        "event_fx", "inverted", "125", "0.008")
    assert step["observations"][0]["source_key"] == REF and step["observations"][0]["source_version"] == 1
    index = jpy["points"]["base"]["chain"][1]
    assert (index["step"], index["ratio"], index["from_period"], index["period_used"]) == (
        "cost_index", "1.25", "2020-03", "2026-09")
    assert jpy["points"]["base"]["chain"][2]["rule"] == "same_currency"
    kwd = held["normalized:insurance_deductible"]
    assert kwd["native"]["base"] == "3125.125" and kwd["points"]["base"]["value"]["amount"] == "12500.5"
    assert kwd["points"]["base"]["chain"][0]["direction"] == "direct"
    assert [s["source_key"] for s in kwd["sources"]] == [REF]
    for record in held.values():
        assert record["confidence_downgrades"] == [] and record["conflicts"] == []
        assert record["primary_unavailable"] == []
        assert record["policy"]["base_currency"] == "USD" and record["policy"]["reporting_currency"] == "USD"


def test_a_weekend_date_reads_the_newest_usable_rate_on_or_before_it(deployment, people):
    """A margin stated on Saturday 29 February 2020: the providers publish no rate on a
    Saturday, so Friday's (EUR/USD 1.08) is the last official rate: EUR 800 x 1.08 x
    125/100 (February 2020's index) = USD 1,080."""
    books()
    variables = {"margin_per_hour": money("money_per_hour", "800", "EUR", on=SATURDAY)}
    result = simulated(built(deployment, people, variables=variables))
    (record,) = result.inputs["normalizations"]
    step = record["points"]["base"]["chain"][0]
    assert (step["rule"], step["requested_date"], step["rate_date"], step["quoted_rate"]) == (
        "last_official_rate", SATURDAY, "2020-02-28", "1.08")
    assert record["points"]["base"]["chain"][1]["from_period"] == "2020-02"
    assert record["normalized"]["base"] == "1080"


# ======================================================================
# Refusals: never a number the policy did not allow
# ======================================================================


def _counts():
    return FinancialScenario.objects.count(), FinancialParameter.objects.filter(scenario__isnull=False).count()


def test_a_missing_rate_refuses_the_build_with_its_code(deployment, people):
    """No source quotes CHF: the build is refused ``rate_missing``, through the route too
    (400), and nothing is written."""
    books()
    variables = {**FIGURES, "margin_per_hour": money("money_per_hour", "800", "CHF")}
    asset, finding = world(deployment, people["analyst"], variables)
    before = _counts()
    with pytest.raises(MoneyRefused) as refused:
        builder.build(deployment, body(asset, finding), author=people["analyst"])
    assert refused.value.code == "rate_missing" and "margin_per_hour" in refused.value.detail
    client = APIClient()
    client.force_authenticate(user=people["analyst"])
    answer = client.post(f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/build/",
                         data=json.dumps(body(asset, finding)), content_type="application/json")
    assert answer.status_code == 400 and answer.json()["code"] == "rate_missing", answer.content
    assert _counts() == before


def test_without_a_policy_a_figure_in_another_currency_is_refused_as_before(deployment, people):
    books()
    asset, finding = world(deployment, people["analyst"])
    with pytest.raises(MoneyRefused) as refused:
        builder.build(deployment, body(asset, finding, policy=None), author=people["analyst"])
    assert refused.value.code == "currency_mismatch" and "states no normalization policy" in refused.value.detail


def test_a_figure_stating_a_distribution_is_not_normalized(deployment, people):
    books()
    stated = {**money("money_per_hour", "50000", "EUR"), "base": "100000", "high": "200000",
              "distribution": {"id": "gamma", "version": 1, "params": {"shape": "4", "scale": "25000"}}}
    asset, finding = world(deployment, people["analyst"], {"margin_per_hour": stated})
    with pytest.raises(MoneyRefused) as refused:
        builder.build(deployment, body(asset, finding), author=people["analyst"])
    assert refused.value.code == "distribution_not_normalizable"


def test_an_index_no_policy_provider_holds_and_two_disagree_refuses_index_primary_unset(deployment, people):
    """Two sources publish the series, the policy names neither, and they differ by
    more than 1%: no source is chosen between them (section 12.8), so the build is
    refused ``index_primary_unset``."""
    register(REF, "RUN-TEST-REF", fx_rates=REF_RATES)
    register("run-test-index-a", "RUN-TEST-IDX-A", points=REF_POINTS)
    register("run-test-index-b", "RUN-TEST-IDX-B",
             points=[("2020-03", "100", "2020-04-10"), ("2026-09", "130", VALUATION)])
    asset, finding = world(deployment, people["analyst"])
    with pytest.raises(MoneyRefused) as refused:
        builder.build(deployment, body(asset, finding), author=people["analyst"])
    assert refused.value.code == "index_primary_unset"


@pytest.mark.parametrize(
    "edit, code",
    [
        (lambda p: p.update(providers=[]), "field_malformed"),
        (lambda p: p.update(providers="RUN-TEST-REF"), "field_malformed"),
        (lambda p: p.update(index={**SERIES, "extra": "x"}), "field_unrecognised"),
        (lambda p: p.pop("index"), "field_missing"),
        (lambda p: p.update(index_max_lag_months=-1), "field_malformed"),
        (lambda p: p.update(weekend_holiday_rule="nearest"), "policy_invalid"),
        (lambda p: p.update(base_currency="usd"), "currency_unknown"),
        (lambda p: p.update(spare=True), "field_unrecognised"),
    ],
)
def test_the_policy_is_read_exactly(deployment, people, edit, code):
    policy = copy.deepcopy(POLICY)
    edit(policy)
    asset, finding = world(deployment, people["analyst"])
    with pytest.raises(MoneyRefused) as refused:
        builder.build(deployment, body(asset, finding, policy=policy), author=people["analyst"])
    assert refused.value.code == code
    if code.startswith("field_"):
        # The policy's own path: a request that may not state a policy at all is refused
        # at the body ("body: ['normalization']"), never here.
        assert refused.value.detail.startswith("normalization"), refused.value.detail


# ======================================================================
# Two sources: the primary is used, the conflict listed, the line that reads it lowered
# ======================================================================


def test_two_sources_over_the_tolerance_use_the_primary_list_the_conflict_and_lower_that_line_only(
        deployment, people):
    """A second source quotes KWD/USD 3.25 on the event date: 0.05 / 3.2 = 1.5625%, over
    the 0.5% tolerance. The policy's FIRST provider is used, the primary, never the
    fallback (KWD 3,125.125 x 3.2 x 1.25 = USD 12,500.5, never the other's
    12,695.82...), each KWD record lists the conflict and
    carries ``source_disagreement``, and on the card only the retained cash -- the line
    that reads the policy's terms -- is lowered, one step however many of its figures
    carry it; the gross cash, which reads no KWD figure, is not."""
    books()
    register(ALT, "RUN-TEST-ALT", fx_rates=[("KWD", "USD", EVENT, "3.25")])
    scenario = built(deployment, people, policy={**POLICY, "providers": ["RUN-TEST-REF", "RUN-TEST-ALT"]})
    assert figures(figure(scenario, "insurance_deductible"))[2] == "12500.5"
    assert figures(figure(scenario, "insurance_limit"))[2] == "4000000"
    result, card = carded(scenario)
    held = records(result)
    for name in ("normalized:insurance_deductible", "normalized:insurance_limit"):
        (conflict,) = held[name]["conflicts"]
        assert (conflict["primary"], conflict["secondary"], conflict["secondary_value"]) == (REF, ALT, "3.25")
        assert conflict["pair"] == "KWD/USD" and conflict["relative_difference"] == "0.015625"
        assert held[name]["confidence_downgrades"] == ["source_disagreement"]
        assert {s["source_key"] for s in held[name]["sources"]} == {REF, ALT}
    for name in ("normalized:margin_per_hour", "normalized:engineering_hourly_rate"):
        assert held[name]["conflicts"] == [] and held[name]["confidence_downgrades"] == []

    graded = card.card["fields"]["confidence_grade"]
    gross, retained = graded["lines"]["gross_cash"], graded["lines"]["retained_cash"]
    assert gross["grade"] == "A" and gross["normalization_downgrades"] == []
    assert retained["base_grade"] == "A" and retained["grade"] == "B"
    (lowered,) = retained["normalization_downgrades"]
    assert lowered["rule"] == "source_disagreement"
    assert lowered["figures"] == ["normalized:insurance_deductible", "normalized:insurance_limit"]
    assert (graded["grade"], graded["line"]) == ("B", "retained_cash")
    assert graded["version"] == grade.VERSION_NORMALIZED == gross["version"]
    assert card.confidence_grade == "B"

    bridge = report.build_report(result)["currency_bridge"]
    listed = {c["figure"]: c for c in bridge["conversions"]}
    assert listed["normalized:insurance_deductible"]["conflicts"][0]["secondary"] == ALT
    assert bridge["statement"] == report.CONVERTED


def test_a_fallback_past_the_primary_is_named_and_lowers_each_line_that_reads_it_once(deployment, people):
    """The policy's first provider quotes only KWD: the EUR and JPY figures fall back to
    the second, each record names both, and the gross cash -- which reads both -- is
    lowered ONE step for ``primary_unavailable``; the retained cash reads them too."""
    books()
    register(ALT, "RUN-TEST-ALT", fx_rates=[("KWD", "USD", EVENT, "3.2")])
    policy = {**POLICY, "providers": ["RUN-TEST-ALT", "RUN-TEST-REF"]}
    result, card = carded(built(deployment, people, policy=policy))
    held = records(result)
    assert held["normalized:margin_per_hour"]["primary_unavailable"][0] == {
        "step": "event_fx", "primary": "RUN-TEST-ALT", "used": "RUN-TEST-REF"}
    # The KWD rate is the policy's first provider's, and the index is the first named
    # provider that holds the series (section 12.8): no fallback on the policy's terms.
    assert held["normalized:insurance_deductible"]["primary_unavailable"] == []
    assert held["normalized:engineering_hourly_rate"]["confidence_downgrades"] == ["primary_unavailable"]
    lines = card.card["fields"]["confidence_grade"]["lines"]
    rules = [d["rule"] for d in lines["gross_cash"]["normalization_downgrades"]]
    assert rules == ["primary_unavailable"] and lines["gross_cash"]["grade"] == "B"


# ======================================================================
# The run: its inputs hold the records, its digest covers them, replay is exact
# ======================================================================


def test_the_records_are_in_the_runs_inputs_and_its_digest_covers_them(deployment, people):
    books()
    scenario = built(deployment, people)
    result = simulated(scenario)
    assert result.versions["normalization"] == "mythos.economics.run-normalization/v1"
    assert ss.digest_of(result.inputs) == result.input_digest
    si = simulation_service.load_input(scenario)
    assert ss.digest_of(ss.canonical_inputs(si, severe_percentile=Decimal(95))) == result.input_digest
    # A record changed by one digit is another input digest: the run would not be returned.
    changed = [copy.deepcopy(r) for r in si.normalizations]
    changed[0]["points"]["base"]["chain"][0]["quoted_rate"] = "1.2"
    edited = ss.canonical_inputs(replace(si, normalizations=tuple(changed)), severe_percentile=Decimal(95))
    assert ss.digest_of(edited) != result.input_digest
    # Without them the inputs are another digest too: the records are covered, not beside it.
    bare = ss.canonical_inputs(replace(si, normalizations=()), severe_percentile=Decimal(95))
    assert ss.digest_of(bare) != result.input_digest
    # The same scenario again is the same run.
    again = simulation_service.simulate_scenario(scenario, seed=36, draws=1_000)
    assert (again.result.pk, again.created) == (result.pk, False)


def test_a_stored_record_replays_and_a_changed_one_is_refused(deployment, people):
    from assurance.economics.engine import figure_normalization as fn
    from assurance.economics.models import FigureNormalization

    books()
    scenario = built(deployment, people)
    rows = list(FigureNormalization.objects.filter(scenario=scenario))
    assert len(rows) == 4
    for row in rows:
        assert fn.record_refusal(row.record, native=row.native.as_engine(), normalized=row.normalized.as_engine()) is None
    row = rows[0]
    edited = copy.deepcopy(row.record)
    edited["points"]["base"]["chain"][0]["factor"] = "1.2"
    assert "factor" in fn.record_refusal(edited, native=row.native.as_engine(), normalized=row.normalized.as_engine())
    copy_row = FigureNormalization(deployment=deployment, scenario=scenario, native=row.native,
                                   normalized=row.normalized, record=edited, record_digest=row.record_digest)
    with pytest.raises(EconomicsRefused) as refused:
        copy_row.save()
    assert refused.value.code == "normalization_record_malformed"


def test_a_pure_reporting_currency_run_is_as_before(deployment, people):
    """Every figure in USD: no record, no ``normalizations`` in the inputs, no
    ``normalization`` in the versions, the grade v3 with master's digest, the bridge
    empty with its old statement, and a policy stated beside such figures changes
    nothing the run reads."""
    books()
    usd = {"margin_per_hour": _entry("money_per_hour", "1100", effective_date=VALUATION),
           "engineering_hourly_rate": _entry("money_per_hour", "250", effective_date=VALUATION)}
    plain = built(deployment, people, variables=usd, policy=None)
    result, card = carded(plain)
    assert "normalizations" not in result.inputs and "normalization" not in result.versions
    assert grade.version_digest() == GRADE_V3_DIGEST
    graded = card.card["fields"]["confidence_grade"]
    assert graded["version"] == grade.VERSION and graded["version_digest"] == GRADE_V3_DIGEST
    assert "normalization_downgrades" not in graded
    assert card.card["fields"]["model_version"]["release"]["grade"] == grade.version_record()
    bridge = report.build_report(result)["currency_bridge"]
    assert bridge["conversions"] == [] and bridge["statement"] == report.NO_CONVERSION
    assert [s["snapshot_id"].split(":")[0] for s in receipt_service.source_snapshots(plain)] == [
        "parameter-set", "scenario-build", "scenario-parameters"]
    assert builder.build_document(
        deployment_uuid="d", parameter_set={}, currency="USD", as_of=date(2026, 9, 30), effects=[], links=[]
    ).keys() == {"builder", "grouping", "grouping_window_hours", "pack", "templates", "deployment", "parameter_set",
                 "currency", "as_of", "effects", "findings"}

    # The same figures built with a policy: nothing to normalize, so the run reads the same.
    asset = Asset.objects.get(deployment=deployment)
    finding = Finding.objects.get(deployment=deployment)
    with_policy, _ = builder.build(deployment, body(asset, finding, title="with a policy"), author=people["analyst"])
    other = simulated(with_policy)
    assert "normalizations" not in other.inputs

    def without_ids(inputs):
        text = json.dumps(inputs, sort_keys=True)
        for row in FinancialParameter.objects.filter(scenario__in=[plain, with_policy]):
            text = text.replace(str(row.uuid), "<parameter>")
        return text.replace(str(plain.uuid), "<scenario>").replace(str(with_policy.uuid), "<scenario>")

    assert without_ids(other.inputs) == without_ids(result.inputs)
    assert other.result_digest == result.result_digest or other.record["scenario"] == result.record["scenario"]


# ======================================================================
# The report's bridge, the receipt, licences and the E6 hook
# ======================================================================


def test_the_bridge_lists_every_conversion_as_the_inputs_hold_it(deployment, people):
    books()
    result = simulated(built(deployment, people))
    served = report.build_report(result)
    bridge = served["currency_bridge"]
    assert (bridge["valuation_date"], bridge["reporting_currency"]) == (VALUATION, "USD")
    assert [c["figure"] for c in bridge["conversions"]] == sorted(f"normalized:{n}" for n in FIGURES)
    assert bridge["conversions"] == result.inputs["normalizations"]  # open sources: served as stored
    assert served["schema"] == report.REPORT_SCHEMA and report.verifies(served)
    parameters = served["parameters"]
    assert parameters["normalized:insurance_deductible"]["base"] == "12500.5"


def test_a_restricted_sources_values_are_withheld_from_the_bridge_and_the_figures_stand(deployment, people):
    books(licence="licensed")
    result = simulated(built(deployment, people))
    bridge = report.build_report(result)["currency_bridge"]
    for conversion in bridge["conversions"]:
        assert "licensed" in conversion["withheld"]
        assert conversion["normalized"]["base"] is None
        step = conversion["points"]["base"]["chain"][0]
        assert "quoted_rate" not in step and "factor" not in step
        assert step["observations"][0]["withheld"] == "the raw value"
        assert step["observations"][0]["source_key"] == REF
        assert conversion["points"]["base"]["value"] is None
    # The stored inputs keep the whole record, and the figure the run read stands.
    assert records(result)["normalized:margin_per_hour"]["points"]["base"]["chain"][0]["quoted_rate"] == "1.1"
    assert result.record["scenario"]["gross_cash"]["p50"] == "25500"


def _raw(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def test_the_receipt_covers_the_bridge(deployment, people):
    from assurance.economics.models import FigureNormalization

    books()
    scenario = built(deployment, people, frequency=FREQUENCY)
    result, _card = carded(scenario)
    named = {s["snapshot_id"]: s["content_hash"] for s in receipt_service.source_snapshots(scenario)}
    held = [row.record for row in sorted(FigureNormalization.objects.filter(scenario=scenario),
                                         key=lambda row: row.normalized.name)]
    from assurance.economics.models import canonical_digest

    assert named[f"scenario-normalizations:{scenario.uuid}"] == canonical_digest(held)
    key, other = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    keyring = core.receipt_keyring([_raw(key)], other_roles={"engine-outcome": [_raw(other)]})
    outcome = receipt_service.issue_receipt(
        result, signer=lambda document: core.sign_receipt(document, key), keyring=keyring)
    assert outcome.receipt is not None, (outcome.code, outcome.detail)
    document = outcome.receipt.document
    assert document["simulation"]["parameter_set_digest"] == result.input_digest
    assert f"scenario-normalizations:{scenario.uuid}" in {s["snapshot_id"] for s in document["sources"]}
    # A record changed after the fact no longer gives its digest: no source snapshot is vouched for.
    row = FigureNormalization.objects.filter(scenario=scenario).first()
    edited = copy.deepcopy(row.record)
    edited["native"]["base"] = "1"
    FigureNormalization._base_manager.filter(pk=row.pk).update(record=edited)
    with pytest.raises(receipt_service.ReceiptRefused) as refused:
        receipt_service.source_snapshots(scenario)
    assert refused.value.code == "source_snapshot_mismatch"


def test_each_source_version_a_run_normalized_from_is_a_dependency_for_e6(deployment, people):
    from assurance.economics import run_normalization

    version = books()
    result = simulated(built(deployment, people))
    assert run_normalization.source_dependencies(result.inputs) == [
        {"source_key": REF, "tenant": "platform", "version": 1, "snapshot_hash": version.snapshot_hash}]
    assert run_normalization.source_dependencies({"events": []}) == []


def test_a_newer_source_version_is_a_new_build_not_the_old_one(deployment, people):
    """The source versions a build's normalizations read are inputs of the build: the
    same request after a newer usable version is a new scenario version."""
    books()
    asset, finding = world(deployment, people["analyst"])
    first, created = builder.build(deployment, body(asset, finding), author=people["analyst"])
    again, created_again = builder.build(deployment, body(asset, finding), author=people["analyst"])
    assert created and not created_again and again.pk == first.pk
    register(REF, "RUN-TEST-REF", fx_rates=[*REF_RATES, ("EUR", "USD", "2026-09-30", "1.17")], points=REF_POINTS)
    newer, created_newer = builder.build(deployment, body(asset, finding), author=people["analyst"])
    assert created_newer and newer.pk != first.pk


# ======================================================================
# Safety, and the documentation
# ======================================================================


def test_the_builds_transaction_only_writes_with_normalized_figures(deployment, people, monkeypatch):
    """Every normalization reads the source versions BEFORE the build's transaction,
    which holds only INSERTs (spec, section 24.6): a stop's write waits for the inserts
    alone, never for a normalization."""
    import contextlib
    import types

    from django.db import connection, transaction
    from django.test.utils import CaptureQueriesContext

    books()
    asset, finding = world(deployment, people["analyst"])
    captured = []
    real = transaction.atomic

    @contextlib.contextmanager
    def watched(*args, **kwargs):
        with CaptureQueriesContext(connection) as queries, real(*args, **kwargs):
            yield
        captured.append([q["sql"] for q in queries.captured_queries])

    monkeypatch.setattr(builder, "transaction", types.SimpleNamespace(atomic=watched))
    builder.build(deployment, body(asset, finding), author=people["analyst"])
    (inside,) = captured
    statements = [q for q in inside if not q.lstrip().upper().startswith(("SAVEPOINT", "RELEASE", "BEGIN", "COMMIT"))]
    assert statements and all(q.lstrip().upper().startswith("INSERT") for q in statements)
    assert any("figurenormalization" in q.lower() for q in statements)


def test_the_spec_and_the_readme_say_it():
    text = " ".join(SPEC.read_text(encoding="utf-8").split())
    assert "## 36. Figures normalized into a run's reporting currency" in SPEC.read_text(encoding="utf-8")
    for needle in ("`FigureNormalization`", "`0075_figure_normalizations.py`", "`distribution_not_normalizable`",
                   "`mythos.economics.confidence-grade/v4`", "`scenario-normalizations:<scenario>`",
                   "`run_normalization.source_dependencies`", "`normalization_record_malformed`",
                   "`mythos.economics.run-normalization/v1`"):
        assert needle in text, needle
    assert "section 36" in " ".join(README.read_text(encoding="utf-8").split())
