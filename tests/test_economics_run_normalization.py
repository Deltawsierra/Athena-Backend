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
    FigureNormalization,
    FinancialNormalizationPolicy,
    FinancialParameter,
    FinancialScenario,
    FinancialSource,
    ScenarioBuild,
    SimulationResult,
)
from assurance.models import Asset, Deployment, Finding
from tests.economics_review import approve_for_receipt
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
#: The stored normalization policy the builds name (section 36.1), platform-wide.
POLICY = {"base_currency": "USD", "providers": ["RUN-TEST-REF"], "index": SERIES}
KEY = "run-test-usd"
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


@pytest.fixture(autouse=True)
def stored_policy(people):
    """The platform-wide stored policy the builds name by default, recorded by an admin."""
    return FinancialNormalizationPolicy.record(KEY, POLICY, by=people["admin"])


def named(people, document, *, key="run-test-other", deployment=None) -> str:
    """A stored policy holding ``document`` (a new version of ``key``), by its key."""
    FinancialNormalizationPolicy.record(key, document, by=people["admin"], deployment=deployment)
    return key


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


def body(asset, finding, *, policy=KEY, as_of=VALUATION, title="Core banking provider outage"):
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


def built(deployment, people, *, variables=None, policy=KEY, frequency=None):
    """A build of the test world naming ``policy``: a stored policy's key, a document
    to store first (under another key), or ``None`` for none."""
    if isinstance(policy, dict):
        policy = named(people, policy)
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
    assert refused.value.code == "currency_mismatch" and "names no normalization policy" in refused.value.detail


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
def test_a_stored_policy_is_read_exactly_when_it_is_recorded(people, edit, code):
    policy = copy.deepcopy(POLICY)
    edit(policy)
    with pytest.raises(EconomicsRefused) as refused:
        FinancialNormalizationPolicy.record("run-test-bad", policy, by=people["admin"])
    assert refused.value.code == code
    if code.startswith("field_"):
        assert refused.value.detail.startswith("document"), refused.value.detail
    assert not FinancialNormalizationPolicy.objects.filter(policy_key="run-test-bad").exists()


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


def test_a_restricted_normalized_figure_is_withheld_wherever_it_would_let_a_reader_derive_the_rate(
        deployment, people):
    """Review round 1, LOW-1: beside the native figure the bridge shows, the normalized
    one would give the rate away. Its values are withheld in the report's parameters
    and sensitivity, the scenario document and the events route, provenance kept;
    the native figures and every total stand."""
    books(licence="licensed")
    scenario = built(deployment, people)
    result, card = carded(scenario)
    served = report.build_report(result)
    name = "normalized:margin_per_hour"
    held = served["parameters"][name]
    assert (held["low"], held["base"], held["high"]) == (None, None, None) and "licensed" in held["withheld"]
    assert held["currency"] == "USD" and held["evidence_ref"] and held["read_by"]
    assert served["integrity"]["verified"] is True and "not_reported" not in served["summary"]  # totals stand
    fixed = {entry["name"]: entry for entry in served["sensitivity"]["fixed"]}
    assert fixed[name]["value"] is None and "licensed" in fixed[name]["withheld"]
    assert fixed["outage.outage_hours"]["value"] == "10"
    document = report.scenario_document(scenario)
    rows = {row["name"]: row for row in document["parameters"]}
    assert rows[name]["base"] is None and "licensed" in rows[name]["withheld"]
    assert rows["margin_per_hour"]["base"] == "800"  # the native figure, as the customer stated it
    text = json.dumps(builder.describe(scenario))
    assert '"1100"' not in text and '"12500.5"' not in text and '"250"' not in text
    assert '"25500"' in text  # the totals stand


def _raw(key):
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def test_the_receipt_covers_the_bridge(deployment, people):
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
    # A signed receipt needs the row key (set for every test by tests/conftest.py, section
    # 35.9) and an approved review by a colleague who authored nothing it rests on (35.4).
    approve_for_receipt(result)
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


def test_a_newer_usable_source_version_stales_the_run_and_a_refresh_reads_it(deployment, people):
    """Review round 1, MEDIUM-4 (E6, section 34): each source version a run's normalized
    figures read is a dependency recorded with the run; a newer usable version of it
    makes the run stale, ``source_superseded``, naming the source and both versions; a
    refresh rebuilds a NEW version that reads the newer source, and its run is not
    stale for it. A run that normalized nothing records no such dependency."""
    from assurance.economics import continuous_service
    from assurance.economics.models import ExposureDependencies

    first = books()
    scenario = built(deployment, people)
    result = simulated(scenario)
    mapped = ExposureDependencies.objects.get(simulation=result).dependencies
    assert mapped["normalization_sources"] == {
        "as_of": VALUATION,
        "versions": [{"source_key": REF, "tenant": "platform", "version": 1, "snapshot_hash": first.snapshot_hash}],
    }
    # The run rests on the release that grades it (v4), read, so nothing but a moved
    # source stales it.
    assert mapped["release"]["digest"] and mapped["release"]["normalized"] is True
    assert mapped["release"]["record"]["grade"] == grade.version_record(normalized=True)
    assert continuous_service.assess(result).reasons == []
    # A newer version of the FX and index source: different rates, usable on the as-of date.
    register(REF, "RUN-TEST-REF", fx_rates=[(b, q, d, "1.2" if (b, q) == ("EUR", "USD") and d == EVENT else v)
                                            for b, q, d, v in REF_RATES], points=REF_POINTS)
    reasons = continuous_service.assess(result).reasons
    assert [(r["code"], r["dependency"], r["was"], r["now"]) for r in reasons] == [
        ("source_superseded", f"source:{REF}", "1", "2")]
    # The refresh: rebuilt from what the build recorded, naming the same stored policy,
    # reading version 2 now.
    client = APIClient()
    client.force_authenticate(user=people["analyst"])
    answer = client.post(f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario.uuid}/refresh/",
                         data=json.dumps({"seed": 36, "policy": "quick_10k", "as_of": VALUATION}),
                         content_type="application/json")
    assert answer.status_code == 201, answer.content
    rebuilt = FinancialScenario.objects.get(uuid=answer.json()["rebuilt"]["scenario"])
    assert rebuilt.supersedes_id == scenario.pk
    margin = FigureNormalization.objects.get(scenario=rebuilt, native__name="margin_per_hour")
    assert margin.record["points"]["base"]["chain"][0]["observations"][0]["source_version"] == 2
    assert margin.normalized.base == "1200"  # EUR 800 x 1.2 x 1.25
    fresh = SimulationResult.objects.get(uuid=answer.json()["simulation"]["uuid"])
    assert "source_superseded" not in {r["code"] for r in continuous_service.assess(fresh).reasons}
    # A run that normalized nothing records no normalization dependency.
    plain = built(Deployment.objects.create(name="usd-only", environment="staging", owner=people["owner"]), people,
                  variables={"margin_per_hour": _entry("money_per_hour", "1100", effective_date=VALUATION)},
                  policy=None)
    held = ExposureDependencies.objects.get(simulation=simulated(plain)).dependencies
    assert "normalization_sources" not in held and "normalized" not in held["release"]
    assert held["release"]["record"]["grade"] == grade.version_record()


def test_nit3_an_observation_changed_past_the_model_after_registration_is_never_read(deployment, people):
    """Review round 1, NIT-3: the loader records the digests of the FX and the
    cost-index observations it writes with a version, and every book read checks the
    rows against them. A rate or an index value changed past the model after
    registration, or a row removed, refuses the build (400 through the route, nothing
    written): no figure is normalized from it, so none is pinned by a record. Put back,
    the rows read as before.

    Two checks guard these rows, each with its own job (spec, section 36.2 beside
    35.3). Section 35.3's row digests find a plain rewrite first: the version is
    demoted (``snapshot_rows_mismatch`` on a book read of it), so a run passes it over
    (``feeds.used_version``) and the build, left with no rate, is refused. The same
    rewrite with every ``row_digest`` and the version's ``observations_digest``
    recomputed (:func:`row_digests_recomputed`) passes that check, and these observation
    digests still refuse it (``source_observations_changed``)."""
    from django.db.models import F

    from assurance.economics import normalization_service
    from assurance.economics.models import CostIndexObservation, FXObservation, observation_rows_digest

    version = books()
    rates = [row.as_engine() for row in FXObservation.objects.filter(source=version)]
    points = [row.as_engine() for row in CostIndexObservation.objects.filter(source=version)]
    assert rates and points
    assert (version.fx_observations_digest, version.index_observations_digest) == snapshots.observations_digests(
        rates, points)
    registered_rows_digest = version.observations_digest
    assert registered_rows_digest
    asset, finding = world(deployment, people["analyst"])
    client = APIClient()
    client.force_authenticate(user=people["analyst"])
    url = f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/build/"

    def row_digests_recomputed():
        """Past the model, as one who knows section 35.3's digests: every row's own
        digest and the version's digest over them recomputed from the rows as they now
        stand, so only the observation digests still tell."""
        digests = []
        for model in (FXObservation, CostIndexObservation):
            for row in model._base_manager.filter(source=version):
                model._base_manager.filter(pk=row.pk).update(row_digest=row.computed_digest())
                digests.append(row.computed_digest())
        FinancialSource._base_manager.filter(pk=version.pk).update(observations_digest=observation_rows_digest(digests))

    def refused_everywhere(code, kind=None):
        before = _counts()
        with pytest.raises((EconomicsRefused, MoneyRefused)) as refused:
            builder.build(deployment, body(asset, finding), author=people["analyst"])
        assert refused.value.code == code
        if kind is not None:
            assert f"{kind} observations of {REF} version 1" in refused.value.detail
        answer = client.post(url, data=json.dumps(body(asset, finding)), content_type="application/json")
        assert answer.status_code == 400 and answer.json()["code"] == code, answer.content
        assert _counts() == before

    def refused_by_both(kind):
        # The rows' own digests find it first (section 35.3): the version is demoted, a
        # book read of it refused, a run passes it over, and the build has no rate.
        assert version.pk not in {v.pk for v in normalization_service.usable_versions(
            deployment, date.fromisoformat(VALUATION))}
        with pytest.raises(EconomicsRefused) as demoted:
            snapshots.fx_book([version], deployment=deployment)
        assert demoted.value.code == "snapshot_rows_mismatch"
        refused_everywhere("rate_missing")
        # Every row digest and the version's recomputed: the observation digests still find it.
        row_digests_recomputed()
        assert version.pk in {v.pk for v in normalization_service.usable_versions(
            deployment, date.fromisoformat(VALUATION))}
        refused_everywhere("source_observations_changed", kind)

    used = FXObservation._base_manager.filter(source=version, base_currency="EUR", quote_currency="USD",
                                              effective_date=EVENT)
    held = used.get().rate
    used.update(rate=Decimal("1.2"))
    refused_by_both("FX")
    used.update(rate=held)
    row_digests_recomputed()
    index = CostIndexObservation._base_manager.filter(source=version)
    index.update(value=F("value") + 1)
    refused_by_both("cost-index")
    index.update(value=F("value") - 1)
    row_digests_recomputed()
    # A row nothing reads, removed: the version's rows are not the ones registered.
    gone = FXObservation._base_manager.filter(source=version).exclude(pk=used.get().pk).order_by("pk").first()
    FXObservation._base_manager.filter(pk=gone.pk).delete()
    refused_by_both("FX")
    # Every row as registered again (the removed one written back as it was): the
    # version builds as before, every digest the one recorded at registration.
    gone.pk = None
    FXObservation._base_manager.bulk_create([gone])
    row_digests_recomputed()
    assert FinancialSource._base_manager.get(pk=version.pk).observations_digest == registered_rows_digest
    scenario, _ = builder.build(deployment, body(asset, finding), author=people["analyst"])
    assert FigureNormalization.objects.filter(scenario=scenario).exists()


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
    for needle in ("`FigureNormalization`", "`0076_figure_normalizations.py`", "`distribution_not_normalizable`",
                   "`mythos.economics.confidence-grade/v4`", "`scenario-normalizations:<scenario>`",
                   "`run_normalization.source_dependencies`", "`normalization_record_malformed`",
                   "`mythos.economics.run-normalization/v1`"):
        assert needle in text, needle
    assert "section 36" in " ".join(README.read_text(encoding="utf-8").split())


# ======================================================================
# Review round 1: every read checks, the card checks its inputs, effect attributes
# are indexed, and the provider order is a stored policy's
# ======================================================================


def _strip_disagreement(scenario):
    """The reviewer's p3a: past the model, the KWD records' downgrades and conflicts
    removed, the digest left as it was."""
    for row in FigureNormalization.objects.filter(scenario=scenario, native__name__startswith="insurance_"):
        edited = copy.deepcopy(row.record)
        edited["confidence_downgrades"], edited["conflicts"] = [], []
        for point in edited["points"].values():
            point["confidence_downgrades"], point["conflicts"] = [], []
            for step in point["chain"]:
                step["conflicts"], step["downgrades"] = [], []
        FigureNormalization._base_manager.filter(pk=row.pk).update(record=edited)


def _refused_everywhere(scenario, deployment, people, result=None):
    """A version whose normalizations no longer hold: nothing reads them. The run is
    refused (and not recorded), the card refused, the report a refusal, the receipt's
    sources refused, the events route and the scenario document 409."""
    runs = SimulationResult.objects.filter(scenario=scenario).count()
    outcome = simulation_service.simulate_scenario(scenario, seed=99, draws=1_000)
    assert outcome.result is None and outcome.code == "normalization_record_malformed", (outcome.code, outcome.detail)
    assert SimulationResult.objects.filter(scenario=scenario).count() == runs
    if result is not None:
        card = validity_service.issue_card(result)
        assert card.card is None and card.code == "normalization_record_malformed", (card.code, card.detail)
        served = report.build_report(result)
        assert served["integrity"]["failed"] == ["normalizations"] and "normalizations" in served["integrity"]["checks"]
        assert served["refusal"]["code"] == report.STORED_ROW_UNVERIFIED and served["excluded_from_totals"] is True
        assert served["summary"] == {"not_reported": served["refusal"]["detail"]}
        assert all(event["gross_cash"]["base"] is None for event in served["loss_events"])
    with pytest.raises(receipt_service.ReceiptRefused) as refused:
        receipt_service.source_snapshots(scenario)
    assert refused.value.code == "source_snapshot_mismatch"
    client = APIClient()
    client.force_authenticate(user=people["owner"])
    base = f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario.uuid}/"
    for url in (base + "events/", base):
        answer = client.get(url)
        assert answer.status_code == 409 and answer.json()["code"] == "normalization_record_malformed", answer.content


def test_p3a_a_record_changed_past_the_model_is_never_run_graded_or_served(deployment, people):
    """Review round 1, MEDIUM-1 (the reviewer's p3a): the two-source KWD build, its
    records' conflicts and downgrades stripped past the model with the digest left
    stale. Before a run: no run. After one: no card, no figures, no receipt."""
    books()
    register(ALT, "RUN-TEST-ALT", fx_rates=[("KWD", "USD", EVENT, "3.25")])
    two = {**POLICY, "providers": ["RUN-TEST-REF", "RUN-TEST-ALT"]}
    scenario = built(deployment, people, policy=two)
    result = simulated(scenario)
    _strip_disagreement(scenario)
    _refused_everywhere(scenario, deployment, people, result)


def test_p3b_a_normalized_figure_changed_past_the_model_is_never_run_or_served(deployment, people):
    """Review round 1, MEDIUM-1 (the reviewer's p3b): ``normalized:margin_per_hour`` set
    to 1 past the model: it no longer is its record's value."""
    books()
    scenario = built(deployment, people)
    result = simulated(scenario)
    FinancialParameter._base_manager.filter(scenario=scenario, name="normalized:margin_per_hour").update(
        low="1", base="1", high="1")
    _refused_everywhere(scenario, deployment, people, result)


def test_p3c_a_card_is_never_graded_from_stored_inputs_that_fail_their_digest(deployment, people):
    """Review round 1, MEDIUM-2 (the reviewer's p3c): the run's stored inputs edited past
    the model after the run (each record's downgrades emptied). The card is refused,
    ``stored_row_unverified``, and nothing is recorded -- for every field it reads from
    the inputs, not only the downgrades."""
    from assurance.economics.models import FinancialValidityCard

    books()
    register(ALT, "RUN-TEST-ALT", fx_rates=[("KWD", "USD", EVENT, "3.25")])
    result = simulated(built(deployment, people, policy={**POLICY, "providers": ["RUN-TEST-REF", "RUN-TEST-ALT"]}))
    inputs = copy.deepcopy(result.inputs)
    for record in inputs["normalizations"]:
        record["confidence_downgrades"] = []
    SimulationResult._base_manager.filter(pk=result.pk).update(inputs=inputs)
    result.refresh_from_db()
    outcome = validity_service.issue_card(result)
    assert outcome.card is None and outcome.code == "stored_row_unverified", (outcome.code, outcome.detail)
    assert not FinancialValidityCard.objects.filter(simulation=result).exists()
    with pytest.raises(validity_service.StoredInputsUnverified):
        validity_service.build_card(result, sensitivity=None, issued={})
    # The same holds for a run that normalized nothing: a pre-existing gap, closed.
    plain = simulated(built(Deployment.objects.create(name="usd", environment="staging", owner=people["owner"]),
                            people, variables={"margin_per_hour": _entry("money_per_hour", "1100",
                                                                         effective_date=VALUATION)}, policy=None))
    edited = copy.deepcopy(plain.inputs)
    edited["parameters"]["margin_per_hour"]["source_type"] = "OFFICIAL_PUBLIC"
    SimulationResult._base_manager.filter(pk=plain.pk).update(inputs=edited)
    plain.refresh_from_db()
    assert validity_service.issue_card(plain).code == "stored_row_unverified"


def test_a_money_attribute_stated_at_another_date_is_indexed_like_a_set_figure(deployment, people):
    """Review round 1, MEDIUM-3: under a policy a USD effect attribute stated on the
    event date is indexed to the valuation date exactly as a set figure is, with its
    own record: a failover fixed cost of USD 5,000 in March 2020 is USD 6,250 (x 1.25),
    and failover is 6,250 + 8 x 250 = 8,250. Without a policy it is read as stated; one
    in another currency is refused, policy or none."""
    books()
    asset, finding = world(deployment, people["analyst"])
    dated = body(asset, finding)
    dated["effects"][0]["attributes"]["recovery_fixed_cost"]["effective_date"] = EVENT
    scenario, _ = builder.build(deployment, dated, author=people["analyst"])
    row = FigureNormalization.objects.get(scenario=scenario, native__name="outage.recovery_fixed_cost")
    assert row.record["native"]["parent"] == {"effect": "outage"}
    assert (row.normalized.name, row.normalized.base) == ("normalized:outage.recovery_fixed_cost", "6250")
    step = row.record["points"]["base"]["chain"][0]
    assert (step["rule"], row.record["points"]["base"]["chain"][1]["ratio"]) == ("same_currency", "1.25")
    (event,) = builder.describe(scenario)["events"]
    by_id = {c["component_id"]: c for c in event["components"]}
    assert by_id["failover-recovery"]["base"] == "8250"
    assert by_id["failover-recovery"]["sources"]["fixed_cost"]["read"]["normalized"]["native"] == str(row.native.uuid)
    result = simulated(scenario)
    assert "normalized:outage.recovery_fixed_cost" in records(result)
    # The attribute as stated stays, read by nothing; without a policy it is read as stated.
    plain = copy.deepcopy(dated)
    del plain["normalization"]
    plain["title"] = "without a policy"
    usd = {"margin_per_hour": _entry("money_per_hour", "1100", effective_date=VALUATION),
           "engineering_hourly_rate": _entry("money_per_hour", "250", effective_date=VALUATION)}
    other = Deployment.objects.create(name="usd-2", environment="staging", owner=people["owner"])
    asset2, finding2 = world(other, people["analyst"], usd)
    plain["effects"][0]["asset"] = str(asset2.uuid)
    plain["findings"][0]["finding"] = str(finding2.uuid)
    as_stated, _ = builder.build(other, plain, author=people["analyst"])
    (event,) = builder.describe(as_stated)["events"]
    assert {c["component_id"]: c for c in event["components"]}["failover-recovery"]["base"] == "7000"
    # One in another currency is refused, policy or none.
    euro = copy.deepcopy(dated)
    euro["effects"][0]["attributes"]["recovery_fixed_cost"]["currency"] = "EUR"
    euro["title"] = "a EUR attribute"
    with pytest.raises(MoneyRefused) as refused:
        builder.build(deployment, euro, author=people["analyst"])
    assert refused.value.code == "currency_mismatch"


def test_a_request_never_states_or_reorders_a_policy_it_names_a_stored_one(deployment, people):
    """Review round 1, LOW-2: the providers' order -- which is the primary -- is a stored
    policy's, never the build request's. A request that states a policy (or a list of
    providers) is refused; it names a stored policy by its key; a deployment's own
    version is read before the platform's; only an admin records one."""
    books()
    register(ALT, "RUN-TEST-ALT", fx_rates=[("KWD", "USD", EVENT, "3.21")])  # within the tolerance of 3.2
    asset, finding = world(deployment, people["analyst"])
    for stated in (POLICY, {**POLICY, "providers": ["RUN-TEST-ALT", "RUN-TEST-REF"]}, ["RUN-TEST-ALT"], 7, ""):
        with pytest.raises(MoneyRefused) as refused:
            builder.build(deployment, body(asset, finding, policy=stated), author=people["analyst"])
        assert refused.value.code == "field_malformed", stated
    with pytest.raises(MoneyRefused) as refused:
        builder.build(deployment, body(asset, finding, policy="no-such-policy"), author=people["analyst"])
    assert refused.value.code == "normalization_policy_not_found"
    # Through the route too: the body cannot carry the providers.
    client = APIClient()
    client.force_authenticate(user=people["analyst"])
    url = f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/build/"
    answer = client.post(url, data=json.dumps(body(asset, finding, policy={"providers": ["RUN-TEST-ALT"]})),
                         content_type="application/json")
    assert answer.status_code == 400 and answer.json()["code"] == "field_malformed"
    # The platform's policy names REF first: REF's 3.2 is used, whatever the request.
    scenario, _ = builder.build(deployment, body(asset, finding), author=people["analyst"])
    assert figure(scenario, "insurance_deductible").base == "12500.5"
    build_policy = ScenarioBuild.objects.get(scenario=scenario).inputs["normalization"]["policy"]
    assert (build_policy["key"], build_policy["scope"], build_policy["version"]) == (KEY, "platform", 1)
    # The deployment's own version of the key is read before the platform's.
    named(people, {**POLICY, "providers": ["RUN-TEST-ALT", "RUN-TEST-REF"]}, key=KEY, deployment=deployment)
    own, _ = builder.build(deployment, body(asset, finding, title="the deployment's own policy"),
                           author=people["analyst"])
    assert figure(own, "insurance_deductible").base == "12539.5640625"  # KWD 3,125.125 x 3.21 x 1.25
    record = FigureNormalization.objects.get(scenario=own, native__name="insurance_deductible").record
    assert record["stored_policy"]["scope"] == "deployment"
    # Only an admin records a policy.
    with pytest.raises(EconomicsRefused) as refused:
        FinancialNormalizationPolicy.record("run-test-analyst", POLICY, by=people["analyst"])
    assert refused.value.code == "admin_required"
