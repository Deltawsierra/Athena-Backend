"""Economic Exposure E5: a deployment's portfolio, aggregated from its scenarios'
draws (``docs/economics/spec-v1.md``, section 28; the owner's specification,
section 24).

- known answers: two independent scenarios sum their means within the band and
  never their percentiles; two co-driven scenarios have a wider tail; one shared
  effect in two scenarios, and five findings on one payment loss, are counted once;
  an Unknown scenario, and every other one not totalled, is excluded and named; a
  currency that cannot be normalised is excluded, and one that can is normalised
  before it is summed;
- contributions: they sum to the mean and to the expected shortfall, exactly, and
  the largest contributor to the mean may differ from the largest to the tail;
- determinism, tenancy and roles, strict JSON, and no transaction or lock during
  the draws (#158's probe: ``connection.in_atomic_block`` where the draws start);
- the report is built from the stored rows only, checks every one first, and is
  graded no higher than its lowest scenario; a fault in the portfolio never takes
  down a stop.

Every figure here is SYNTHETIC / ILLUSTRATIVE.
"""

from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import uuid
from datetime import date, datetime, timedelta
from datetime import timezone as dt_timezone
from decimal import Decimal
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from assurance.economics import builder, portfolio, portfolio_api, report, simulation_service, snapshots, validity_service
from assurance.economics.engine import portfolio as ep
from assurance.economics.engine import scenario_simulation as ss
from assurance.economics.models import (
    CausalEffect,
    CustomerParameterSet,
    EconomicsRefused,
    EconomicsRewriteRefused,
    EffectFinding,
    FinancialParameter,
    FinancialScenario,
    FinancialValidityCard,
    LossComponent,
    LossEvent,
    PortfolioResult,
    ScenarioBuild,
    canonical_digest,
)
from assurance.models import Asset, Deployment, Finding
from tests.test_economics_scenarios import _entry

pytestmark = pytest.mark.django_db
User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "docs" / "economics" / "spec-v1.md"
AS_OF = date(2026, 10, 6)
LABEL = "SYNTHETIC / ILLUSTRATIVE"
QUICK = "quick_10k"
#: A customer's amount around 100,000 (sd 10,000), and a rare large one around 5,000,000 (sd 1,000,000).
SMALL = (("80000", "100000", "120000"), {"id": "gamma", "version": 1, "params": {"shape": "100", "scale": "1000"}})
LARGE = (("3000000", "5000000", "7000000"), {"id": "gamma", "version": 1, "params": {"shape": "25", "scale": "200000"}})
SPINE = "sha256:" + "5a" * 32
WHEN = datetime(2026, 10, 1, 12, 0, tzinfo=dt_timezone.utc)


@pytest.fixture
def people():
    return {
        "admin": User.objects.create_user(username="ada", password="x", role="admin"),
        "analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
        "owner": User.objects.create_user(username="vic", password="x", role="viewer"),
        "other": User.objects.create_user(username="oto", password="x", role="viewer"),
    }


@pytest.fixture
def deployment(people):
    return Deployment.objects.create(name="payments-agent", owner=people["owner"])


@pytest.fixture
def other_deployment(people):
    return Deployment.objects.create(name="someone-elses", owner=people["other"])


def _parameter(scenario, name, unit, low, base=None, high=None, *, source="CUSTOMER_PROVIDED", distribution=None,
               currency="USD"):
    base = low if base is None else base
    high = base if high is None else high
    return FinancialParameter.objects.create(
        scenario=scenario, name=name, unit=unit, source_type=source,
        currency=currency if unit.startswith("money") else "", low=low, base=base, high=high,
        evidence_ref=f"{LABEL}: made up", effective_date=date(2026, 9, 1), distribution=distribution,
    )


def made(deployment, author, *, title="Payment agent", currency="USD", as_of=AS_OF, rate="2", amount=SMALL,
         spine=None, asset=None, occurred_at=WHEN, hypothetical=False, frequency=True, unknown=False, refused=False,
         policy=False, supersedes=None, frequency_source="INDUSTRY_BENCHMARK"):
    """A scenario version as rows: one payment loss event of one lump-sum component (a
    customer's amount stating a gamma), a Poisson frequency of ``rate`` a year (a
    benchmark's, unless ``frequency_source``), one effect -- observed, of the SPINE
    effect ``spine``, or hypothetical -- on ``asset`` enabled by one finding, and the
    build record. ``unknown``: the component cites nothing, so the grade is Unknown.
    ``refused``: the amount states no distribution, which the run refuses."""
    variables = {"notification_fixed_cost": _entry("money", "40000", currency=currency)}
    if policy:
        variables["insurance_deductible"] = _entry("money", "10000", currency=currency)
        variables["insurance_limit"] = _entry("money", "50000000", currency=currency)
        variables["insurance_waiting_period_hours"] = _entry("hours", "0")
    pset = CustomerParameterSet.record(deployment, f"set-{uuid.uuid4().hex[:10]}", {"variables": variables},
                                       author=author)
    # The portfolio keys each scenario's sub-streams by its uuid: a fixed one (by the
    # deployment's name, how many scenarios it holds, and the title) makes every run of
    # a test draw the same years.
    held = FinancialScenario.objects.filter(deployment=deployment).count()
    fixed = uuid.uuid5(uuid.NAMESPACE_URL, f"mythos-e5-test/{deployment.name}/{held}/{title}")
    scenario = FinancialScenario.objects.create(uuid=fixed, deployment=deployment, title=title, author=author,
                                                system_fingerprint="ab" * 32, supersedes=supersedes)
    figures, distribution = amount
    loss = _parameter(scenario, "pay.loss", "money", *figures, distribution=None if refused else distribution,
                      currency=currency)
    if frequency:
        _parameter(scenario, ss.FREQUENCY_PARAMETER, "count", rate, source=frequency_source,
                   distribution={"id": "poisson", "version": 1, "params": {"rate": rate}})
    event = LossEvent.objects.create(scenario=scenario, event_key="ev-pay", currency=currency,
                                     trigger="funds_transfer_altered", business_process="payments")
    LossComponent.objects.create(loss_event=event, component_key="loss", family="incident_response",
                                 formula_id="lump_sum", formula_version=1, as_of=as_of,
                                 cited_parameters={} if unknown else {"amount": str(loss.uuid)})
    if asset is None:
        asset = str(Asset.objects.create(deployment=deployment, kind="agent", name="payments-agent",
                                         identifier=f"agent://pay-{uuid.uuid4().hex[:6]}").uuid)
    observed = {} if hypothetical else {
        "observed_effect": str(uuid.uuid4()), "observation": "sha256:" + uuid.uuid4().hex * 2,
        "spine_effect": spine or "sha256:" + uuid.uuid4().hex * 2, "occurred_at": occurred_at,
    }
    effect = CausalEffect.objects.create(
        scenario=scenario, loss_event=event, effect_key="pay", origin="hypothetical" if hypothetical else "observed",
        effect_type="funds_transfer_altered", asset=asset, business_process="payments",
        template_id="payment_agent_misuse", template_version=1, in_scope_of=[["payment_agent_misuse", 1]], **observed,
    )
    finding = Finding.objects.create(deployment=deployment, fingerprint=f"fp-{uuid.uuid4().hex[:8]}",
                                     finding_type="approval_missing", title="approval missing", severity="high")
    EffectFinding.objects.create(effect=effect, finding=str(finding.uuid), role="prerequisite")
    inputs = {"fixture": str(scenario.uuid), "label": LABEL}
    ScenarioBuild.objects.create(
        scenario=scenario, deployment=deployment, parameter_set=pset, build_digest=builder.build_digest(inputs),
        builder_version="test-fixture", grouping_version="test-fixture", pack="test-fixture", currency=currency,
        as_of=as_of, inputs=inputs,
    )
    return scenario


def simulated(scenario, *, seed=7, draws=10_000, card=True):
    """The scenario simulated, and its Validity Card issued."""
    result = simulation_service.simulate_scenario(scenario, seed=seed, draws=draws).result
    assert result is not None
    if card:
        assert validity_service.issue_card(result).card is not None
    return result


def made_and_simulated(deployment, author, **kwargs):
    scenario = made(deployment, author, **kwargs)
    return scenario, simulated(scenario)


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


def _url(deployment):
    return f"/api/assurance/deployments/{deployment.uuid}/economics/portfolio/"


def _post(client, deployment, body=None, raw=False, **extra):
    body = {"seed": 2026, "policy": QUICK, "reporting_currency": "USD", "valuation_date": AS_OF.isoformat()} \
        if body is None else body
    data = body if raw else json.dumps(body)
    return client.post(_url(deployment) + "simulate/", data=data, content_type="application/json", **extra)


def _body(**over):
    return {"seed": 2026, "policy": QUICK, "reporting_currency": "USD", "valuation_date": AS_OF.isoformat(), **over}


def _totalled(deployment, people, **over):
    response = _post(_client(people["analyst"]), deployment, _body(**over))
    assert response.status_code in (200, 201), response.content
    return response.json()


def _document(client, deployment, result=None):
    query = "" if result is None else f"?result={result}"
    return client.get(_url(deployment) + query)


def _report_of(deployment, people, result=None):
    response = _document(_client(people["owner"]), deployment, result)
    assert response.status_code == 200, response.content
    return response.json()


def _totalled_report(deployment, people, **over):
    """A portfolio totalled for ``over``, and its report."""
    return _report_of(deployment, people, _totalled(deployment, people, **over)["portfolio"]["uuid"])


def _record(document):
    return PortfolioResult.objects.get(uuid=document["portfolio"]["uuid"]).record


def _stored(result, line="gross_cash"):
    return result.record["scenario"][line]


def _standard_error(block):
    return float(block["standard_error_of_mean"])


# ======================================================================
# Known answers
# ======================================================================


def test_two_independent_scenarios_sum_their_means_within_the_band_never_their_percentiles(deployment, people):
    """The portfolio's mean is the sum of the two scenarios' means, within the band of
    the three runs' standard errors; its tail is NOT the sum of their tails: two
    independent scenarios' P90 and P95 are each well below the sum of theirs."""
    a, ra = made_and_simulated(deployment, people["analyst"], title="A", rate="2")
    b, rb = made_and_simulated(deployment, people["analyst"], title="B", rate="2")
    document = _totalled_report(deployment, people)
    assert document["scenarios"]["excluded"] == []
    assert {m["scenario"] for m in document["scenarios"]["included"]} == {str(a.uuid), str(b.uuid)}
    record = _record(document)["lines"]["gross_cash"]
    mean = float(record["mean"])
    expected = float(_stored(ra)["mean"]) + float(_stored(rb)["mean"])
    band = 4 * math.sqrt(_standard_error(record) ** 2 + _standard_error(_stored(ra)) ** 2
                         + _standard_error(_stored(rb)) ** 2)
    assert abs(mean - expected) <= band, (mean, expected, band)
    # Never by summing percentiles: two independent scenarios' tails do not add.
    for figure in ("p90", "severe_plausible"):
        summed = float(_stored(ra)[figure]) + float(_stored(rb)[figure])
        assert float(record[figure]) < 0.9 * summed, (figure, record[figure], summed)
    assert document["summary"]["basis"] == "annual_loss"


def test_two_co_driven_scenarios_have_a_wider_tail_than_two_independent_ones(deployment, people):
    """One correlation group, one common driver a year: the same two scenarios' tail
    (P95 and the expected shortfall) is wider than when they are independent, and
    their mean is the same within the band."""
    a, _ = made_and_simulated(deployment, people["analyst"], title="A", rate="2")
    b, _ = made_and_simulated(deployment, people["analyst"], title="B", rate="2")
    independent = _report_of(deployment, people, _totalled(deployment, people)["portfolio"]["uuid"])
    group = {"group": "cloud-provider", "strength": "2", "source_type": "CUSTOMER_PROVIDED",
             "evidence_ref": f"{LABEL}: both rely on one provider", "scenarios": sorted([str(a.uuid), str(b.uuid)])}
    driven = _report_of(deployment, people, _totalled(deployment, people, groups=[group])["portfolio"]["uuid"])
    loose, tight = _record(independent)["lines"]["gross_cash"], _record(driven)["lines"]["gross_cash"]
    assert float(tight["severe_plausible"]) > 1.2 * float(loose["severe_plausible"])
    assert float(tight["expected_shortfall"]) > 1.2 * float(loose["expected_shortfall"])
    band = 4 * math.sqrt(_standard_error(loose) ** 2 + _standard_error(tight) ** 2)
    assert abs(float(tight["mean"]) - float(loose["mean"])) <= band
    assert driven["groups"][0]["applied_to"] == sorted([str(a.uuid), str(b.uuid)])
    drawn = _record(driven)["groups"]["cloud-provider"]
    assert drawn["driver"]["variance"] == "2" and drawn["drawn"] is True
    assert {m["group"] for m in driven["scenarios"]["included"]} == {"cloud-provider"}


def test_one_shared_effect_in_two_scenarios_is_counted_once(deployment, people):
    """The same SPINE effect in two scenarios is one loss event: counted once, in the
    scenario where it is largest (here equal: the first by uuid), and left out of the
    other's draws."""
    shared = str(Asset.objects.create(deployment=deployment, kind="agent", name="pay", identifier="agent://pay").uuid)
    a, ra = made_and_simulated(deployment, people["analyst"], title="A", spine=SPINE, asset=shared)
    # Observed a month apart: one SPINE effect is one event whatever the window (step 5).
    b, rb = made_and_simulated(deployment, people["analyst"], title="B", spine=SPINE, asset=shared,
                               occurred_at=WHEN + timedelta(days=30))
    document = _totalled_report(deployment, people)
    first, second = sorted([str(a.uuid), str(b.uuid)])
    (joined,) = document["shared_events"]
    assert joined["counted"]["scenario"] == first and joined["by"] == ["spine_effect"]
    assert [j["scenario"] for j in joined["joined"]] == [second]
    by = {m["scenario"]: m for m in document["scenarios"]["included"]}
    assert by[second]["events"] == []
    assert by[second]["counted_elsewhere"] == [{"event_key": "ev-pay",
                                                "counted_in": {"scenario": first, "event_key": "ev-pay"}}]
    record = _record(document)
    gross = record["lines"]["gross_cash"]
    single = _stored(ra)
    band = 4 * math.sqrt(_standard_error(gross) ** 2 + _standard_error(single) ** 2)
    assert abs(float(gross["mean"]) - float(single["mean"])) <= band  # once, not twice
    assert record["contributions"]["gross_cash"]["mean"]["by_scenario"][second] == "0"


def test_five_findings_on_one_payment_loss_never_quintuple_the_portfolio(deployment, people):
    """The specification's own test (section 27, at portfolio level): five scenarios,
    each from one finding enabling the same payment-loss event -- one SPINE effect,
    observed five times -- make ONE loss in the portfolio, not five."""
    shared = str(Asset.objects.create(deployment=deployment, kind="agent", name="pay", identifier="agent://pay").uuid)
    results = []
    for index in range(5):
        _, result = made_and_simulated(deployment, people["analyst"], title=f"finding {index}", spine=SPINE,
                                       asset=shared, occurred_at=WHEN + timedelta(days=index * 3))
        results.append(result)
    document = _totalled_report(deployment, people)
    assert len(document["scenarios"]["included"]) == 5
    (joined,) = document["shared_events"]
    assert len(joined["joined"]) == 4
    gross = _record(document)["lines"]["gross_cash"]
    single = _stored(results[0])
    band = 4 * math.sqrt(_standard_error(gross) ** 2 + _standard_error(single) ** 2)
    assert abs(float(gross["mean"]) - float(single["mean"])) <= band
    assert float(gross["mean"]) < 1.5 * float(single["mean"])  # never quintupled


def test_every_scenario_not_totalled_is_excluded_and_named_never_silently(deployment, people):
    """An Unknown scenario is excluded and named, and so is every other one a total may
    not take: refused, not graded, unverified, never simulated, not annual,
    superseded. Each with its code and its reason; the rest are totalled."""
    graded, _ = made_and_simulated(deployment, people["analyst"], title="graded")
    unknown, _ = made_and_simulated(deployment, people["analyst"], title="unknown", unknown=True)
    refused, _ = made_and_simulated(deployment, people["analyst"], title="refused", refused=True)
    ungraded = made(deployment, people["analyst"], title="ungraded")
    simulated(ungraded, card=False)
    never = made(deployment, people["analyst"], title="never simulated")
    occurrence, _ = made_and_simulated(deployment, people["analyst"], title="no frequency", frequency=False)
    tampered, tampered_result = made_and_simulated(deployment, people["analyst"], title="tampered")
    FinancialValidityCard._base_manager.filter(simulation=tampered_result).update(confidence_grade="A")
    old, _ = made_and_simulated(deployment, people["analyst"], title="old version")
    newer, _ = made_and_simulated(deployment, people["analyst"], title="new version", supersedes=old)
    posted = _totalled(deployment, people)
    document = _report_of(deployment, people)
    codes = {e["scenario"]: e["code"] for e in document["scenarios"]["excluded"]}
    assert codes == {
        str(unknown.uuid): "unknown",
        str(refused.uuid): "refused",
        str(ungraded.uuid): "no_card",
        str(never.uuid): "no_result",
        str(occurrence.uuid): "no_annual_loss",
        str(tampered.uuid): "unverified",
        str(old.uuid): "superseded",
    }
    for entry in document["scenarios"]["excluded"]:
        assert entry["reason"] and entry["meaning"] == portfolio.EXCLUSIONS[entry["code"]] and entry["title"]
    named = {e["scenario"]: e for e in document["scenarios"]["excluded"]}
    assert "graded Unknown" in named[str(unknown.uuid)]["reason"]
    assert named[str(old.uuid)]["reason"] == f"superseded by {newer.uuid}"
    assert {m["scenario"] for m in document["scenarios"]["included"]} == {str(graded.uuid), str(newer.uuid)}
    assert {e["scenario"] for e in posted["excluded"]} == set(codes)
    assert document["complete"] is False and document["reads_as"].startswith("at least")
    # Excluded scenarios add nothing: the figures are the included ones'.
    assert set(_record(document)["members"]) == {str(graded.uuid), str(newer.uuid)}


def test_nothing_to_total_is_recorded_as_a_refusal_with_every_reason(deployment, people):
    unknown, _ = made_and_simulated(deployment, people["analyst"], unknown=True)
    first = _post(_client(people["analyst"]), deployment)
    again = _post(_client(people["analyst"]), deployment)
    assert (first.status_code, again.status_code) == (201, 200), first.content
    assert first.json()["portfolio"]["refusal"]["code"] == "nothing_to_total"
    document = _report_of(deployment, people)
    assert document["status"] == "refused" and document["banner"] == report.UNKNOWN_BANNER
    assert document["excluded_from_totals"] is True and document["grade"]["grade"] is None
    assert document["summary"] == {"not_reported": "refused: nothing_to_total"}
    assert [e["scenario"] for e in document["scenarios"]["excluded"]] == [str(unknown.uuid)]


@pytest.fixture
def sources(tmp_path):
    """The committed snapshot's observations, registered as a NON-synthetic source a
    production run may read (a benchmark, open licence): SYNTHETIC TEST DATA all the
    same, as its label says."""
    document = json.loads(snapshots.SYNTHETIC_SNAPSHOT.read_bytes())
    document["synthetic"] = False
    document["source"].update(trust_tier="benchmark")
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return [snapshots.register_snapshot(path)]


def _normalization(sources):
    return {"base_currency": "USD", "providers": ["SYNTHETIC-REF"],
            "index": {"series_id": "SYN-CPI-US", "geography": "US", "category": "consumer prices, all items (SYNTHETIC)",
                      "base": "2020-03=100"},
            "sources": [str(s.uuid) for s in sources]}


def test_a_currency_that_cannot_be_normalised_is_excluded_and_one_that_can_is_normalised_first(
    deployment, people, sources
):
    """Each draw is normalised into the reporting currency before it is summed: a EUR
    scenario as of 2026-09-30, valued that day in USD, is multiplied by EUR/USD 1.05
    (step 3's order: event-date FX, the index, valuation-date FX). A JPY scenario
    whose rate is missing that day is excluded, with its reason; without a
    normalisation policy, so is every scenario not already in the reporting currency
    at the valuation date."""
    valued = date(2026, 9, 30)
    usd, ru = made_and_simulated(deployment, people["analyst"], title="USD", as_of=valued)
    eur, re = made_and_simulated(deployment, people["analyst"], title="EUR", currency="EUR", as_of=valued)
    jpy, _ = made_and_simulated(deployment, people["analyst"], title="JPY", currency="JPY", as_of=valued)
    without = _report_of(deployment, people, _totalled(deployment, people,
                                                       valuation_date="2026-09-30")["portfolio"]["uuid"])
    excluded = {e["scenario"]: e for e in without["scenarios"]["excluded"]}
    assert set(excluded) == {str(eur.uuid), str(jpy.uuid)}
    assert {e["code"] for e in excluded.values()} == {"currency_unnormalisable"}
    assert "names no normalisation policy" in excluded[str(eur.uuid)]["reason"]

    posted = _totalled(deployment, people, valuation_date="2026-09-30", normalization=_normalization(sources))
    document = _report_of(deployment, people, posted["portfolio"]["uuid"])
    excluded = {e["scenario"]: e for e in document["scenarios"]["excluded"]}
    assert set(excluded) == {str(jpy.uuid)}
    assert excluded[str(jpy.uuid)]["code"] == "currency_unnormalisable"
    assert excluded[str(jpy.uuid)]["reason"].startswith("rate_missing at event_fx")
    by = {m["scenario"]: m for m in document["scenarios"]["included"]}
    assert by[str(usd.uuid)]["normalization"]["rule"] == "identity"
    assert by[str(eur.uuid)]["normalization"]["factor"] == "1.05"
    assert by[str(eur.uuid)]["normalization"]["record"]["order"] == ["event_fx", "cost_index", "valuation_fx"]
    contribution = Decimal(_record(document)["contributions"]["gross_cash"]["mean"]["by_scenario"][str(eur.uuid)])
    native = float(_stored(re)["mean"])
    band = 4 * 1.05 * _standard_error(_stored(re)) * math.sqrt(2)
    assert abs(float(contribution) - 1.05 * native) <= band, (contribution, native)
    assert document["normalization"]["sources"][0]["uuid"] == str(sources[0].uuid)
    assert ru is not None


# ======================================================================
# Contributions
# ======================================================================


def test_contributions_sum_to_the_mean_and_to_the_expected_shortfall(deployment, people):
    """Each scenario's contribution to the mean sums to the portfolio's mean, and to
    the tail to its expected shortfall: in the stored record exactly, and shown at
    the minor unit exactly too. A frequent small loss is the largest contributor to
    the mean, a rare large one to the tail (specification, section 24)."""
    frequent, _ = made_and_simulated(deployment, people["analyst"], title="frequent", rate="5", amount=SMALL)
    rare, _ = made_and_simulated(deployment, people["analyst"], title="rare", rate="0.05", amount=LARGE)
    document = _totalled_report(deployment, people)
    record = _record(document)
    for line in ("gross_cash", "retained_cash"):
        held = record["contributions"][line]
        assert sum(Decimal(v) for v in held["mean"]["by_scenario"].values()) == Decimal(held["mean"]["total"])
        assert held["mean"]["total"] == record["lines"][line]["mean"] == record["lines"][line][
            "expected_annual_exposure"]
        assert sum(Decimal(v) for v in held["tail"]["by_scenario"].values()) == Decimal(held["tail"]["total"])
        assert held["tail"]["total"] == record["lines"][line]["expected_shortfall"]
        assert held["tail"]["draws"] == 500  # ceil(10,000 x (1 - 0.95))
        shown = document["contributions"][line]
        assert sum(Decimal(s["mean"]) for s in shown["scenarios"]) == Decimal(shown["mean"]["total"])
        assert sum(Decimal(s["tail"]) for s in shown["scenarios"]) == Decimal(shown["tail"]["total"])
        assert shown["mean"]["total"] == document["summary"]["lines"][line]["mean"]
        assert shown["tail"]["total"] == document["summary"]["lines"][line]["expected_shortfall"]
    gross = document["contributions"]["gross_cash"]
    assert gross["largest"] == {"mean": str(frequent.uuid), "tail": str(rare.uuid)}
    assert gross["largest_differ"] is True
    expected_shortfall = Decimal(record["lines"]["gross_cash"]["expected_shortfall"])
    assert expected_shortfall >= Decimal(record["lines"]["gross_cash"]["severe_plausible"])


def test_the_headline_is_the_retained_cash_where_a_scenario_is_insured(deployment, people):
    """Insurance is each scenario's own, per event occurrence: under a deductible of
    10,000 an occurrence of about 100,000 retains 10,000, so the retained line's mean
    is about the rate times 10,000, far below the gross; a scenario with no policy
    retains its gross."""
    insured, _ = made_and_simulated(deployment, people["analyst"], title="insured", policy=True)
    bare, _ = made_and_simulated(deployment, people["analyst"], title="bare")
    record = _record(_totalled_report(deployment, people))
    assert record["headline"] == "retained_cash"
    by_mean = {line: record["contributions"][line]["mean"]["by_scenario"] for line in ("gross_cash", "retained_cash")}
    assert by_mean["retained_cash"][str(bare.uuid)] == by_mean["gross_cash"][str(bare.uuid)]
    retained = Decimal(by_mean["retained_cash"][str(insured.uuid)])
    gross = Decimal(by_mean["gross_cash"][str(insured.uuid)])
    assert Decimal("15000") < retained < Decimal("25000") and gross > 8 * retained


def test_largest_remainder_shows_contributions_that_sum_to_the_shown_total():
    shown = report._Shown("USD")
    by = {"a": "0.333333", "b": "0.333333", "c": "0.333334"}
    allocated, total = portfolio._allocated(by, "1.000000", shown)
    assert total == "1.00" and sum(Decimal(v) for v in allocated.values()) == Decimal("1.00")
    assert allocated == {"a": "0.33", "b": "0.33", "c": "0.34"}
    jpy = report._Shown("JPY")
    allocated, total = portfolio._allocated({"a": "10.5", "b": "10.5"}, "21", jpy)
    assert total == "21" and allocated == {"a": "11", "b": "10"}


# ======================================================================
# Grade and banner
# ======================================================================


def test_the_grade_is_no_higher_than_the_lowest_scenario_and_lower_for_an_expert_strength(deployment, people):
    a, _ = made_and_simulated(deployment, people["analyst"], title="A")
    b, rb = made_and_simulated(deployment, people["analyst"], title="B")
    both = sorted([str(a.uuid), str(b.uuid)])
    plain = _report_of(deployment, people, _totalled(deployment, people)["portfolio"]["uuid"])
    grade = report.verified_grade(FinancialValidityCard.objects.get(simulation=rb), rb)
    assert grade == "B"
    assert plain["grade"]["grade"] == "B" and plain["grade"]["downgrades"] == []
    assert plain["banner"] is None and plain["excluded_from_totals"] is False
    customer = {"group": "provider", "strength": "0.5", "source_type": "CUSTOMER_PROVIDED", "evidence_ref": LABEL,
                "scenarios": both}
    expert = {**customer, "source_type": "EXPERT_ESTIMATE"}
    assert _report_of(deployment, people, _totalled(deployment, people, groups=[customer])["portfolio"]["uuid"])[
        "grade"]["grade"] == "B"
    lowered = _report_of(deployment, people, _totalled(deployment, people, groups=[expert])["portfolio"]["uuid"])
    assert lowered["grade"]["grade"] == "C" and lowered["grade"]["base"] == "B"
    assert lowered["grade"]["downgrades"] == [{"code": "expert_correlation", "groups": ["provider"]}]
    # An expert's frequency grades its scenario D: the portfolio is no higher, and never below D.
    made_and_simulated(deployment, people["analyst"], title="D", frequency_source="EXPERT_ESTIMATE")
    lowest = _report_of(deployment, people, _totalled(deployment, people, groups=[expert])["portfolio"]["uuid"])
    assert lowest["grade"]["base"] == "D" and lowest["grade"]["grade"] == "D"


# ======================================================================
# Determinism, storage and the report
# ======================================================================


def test_the_same_inputs_give_the_same_bytes(deployment, people):
    made_and_simulated(deployment, people["analyst"], title="A")
    made_and_simulated(deployment, people["analyst"], title="B", rate="3")
    analyst = _client(people["analyst"])
    first, again = _post(analyst, deployment), _post(analyst, deployment)
    assert (first.status_code, again.status_code) == (201, 200), first.content
    assert first.json()["portfolio"] == again.json()["portfolio"]
    assert PortfolioResult.objects.count() == 1
    reader = _client(people["owner"])
    one, two = _document(reader, deployment), _document(reader, deployment)
    assert one.status_code == 200 and one["Content-Type"] == "application/json"
    assert one.content == two.content
    body = one.json()
    assert one.content == report.canonical_bytes(body)
    assert report.verifies(body) and body["schema"] == portfolio.REPORT_SCHEMA
    row = PortfolioResult.objects.get()
    assert report.canonical_bytes(portfolio.build_document(row)) == one.content
    # Drawn again outside the route from the same inputs: the same record, bit for bit.
    redrawn = portfolio.simulate_portfolio(
        row.deployment, portfolio.parse_request(_body(), policies=portfolio_api.SIMULATION_POLICIES,
                                                parse_seed=portfolio_api.parse_simulate),
    )
    assert redrawn.result.pk == row.pk and not redrawn.created
    # Another seed is another result.
    other = _post(analyst, deployment, _body(seed=2027))
    assert other.status_code == 201 and PortfolioResult.objects.count() == 2
    assert other.json()["portfolio"]["result_digest"] != first.json()["portfolio"]["result_digest"]
    assert _report_of(deployment, people)["portfolio"]["uuid"] == other.json()["portfolio"]["uuid"]


def test_the_engine_is_deterministic_and_draws_each_scenario_on_its_own_sub_stream(deployment, people):
    """The engine alone: the same members give the same record; a scenario's draws
    depend on the seed and its own id, so adding another changes none of its own."""
    a, ra = made_and_simulated(deployment, people["analyst"], title="A")
    b, _ = made_and_simulated(deployment, people["analyst"], title="B")

    def member(scenario):
        return ep.Member(str(scenario.uuid), simulation_service.load_input(scenario), Decimal(1))

    alone = ep.run([member(a)], seed=5, draws=2_000, reporting_currency="USD", input_digest="sha256:" + "0" * 64)
    twice = ep.run([member(a)], seed=5, draws=2_000, reporting_currency="USD", input_digest="sha256:" + "0" * 64)
    assert alone.digest == twice.digest and dict(alone.record) == dict(twice.record)
    pair = ep.run(sorted([member(a), member(b)], key=lambda m: m.scenario_id), seed=5, draws=2_000,
                  reporting_currency="USD", input_digest="sha256:" + "0" * 64)
    mine = str(a.uuid)
    assert pair.record["contributions"]["gross_cash"]["mean"]["by_scenario"][mine] == \
        alone.record["contributions"]["gross_cash"]["mean"]["total"]
    assert pair.record["members"][mine]["occurrences"] == alone.record["members"][mine]["occurrences"]
    other_seed = ep.run([member(a)], seed=6, draws=2_000, reporting_currency="USD", input_digest="sha256:" + "0" * 64)
    assert other_seed.digest != alone.digest
    assert ra is not None


def test_the_report_runs_no_engine_and_reads_no_clock(deployment, people, monkeypatch):
    made_and_simulated(deployment, people["analyst"])
    _totalled(deployment, people)
    reader = _client(people["owner"])
    before = _document(reader, deployment).content

    def never(*args, **kwargs):
        raise AssertionError("the portfolio's report ran the engine")

    for target, name in ((ep, "run"), (ss, "_sample"), (portfolio, "simulate_portfolio"),
                         (simulation_service, "simulate_scenario")):
        monkeypatch.setattr(target, name, never)
    assert _document(reader, deployment).content == before


def _unverified(document, *failed):
    assert document["banner"] == report.UNKNOWN_BANNER and document["excluded_from_totals"] is True
    assert document["integrity"]["verified"] is False and document["integrity"]["failed"] == list(failed)
    assert document["refusal"]["code"] == report.STORED_ROW_UNVERIFIED
    assert document["summary"] == document["contributions"] == {"not_reported": document["banner_reason"]}
    assert document["grade"] is None and report.verifies(document)


def test_a_scenarios_tampered_row_is_never_served_in_a_portfolio(deployment, people):
    """Verified the way step 6's report is: an included scenario's card grade column
    edited past the append-only checks after the portfolio was totalled. The
    portfolio's report serves no figure of it, and says which scenario."""
    a, ra = made_and_simulated(deployment, people["analyst"], title="A")
    made_and_simulated(deployment, people["analyst"], title="B")
    _totalled(deployment, people)
    FinancialValidityCard._base_manager.filter(simulation=ra).update(confidence_grade="A")
    document = _report_of(deployment, people)
    _unverified(document, "member_rows")
    assert document["integrity"]["scenarios_failed"] == [
        {"scenario": str(a.uuid), "reason": "its stored rows fail card_grade"}
    ]


def test_a_tampered_portfolio_row_is_never_served(deployment, people):
    made_and_simulated(deployment, people["analyst"])
    _totalled(deployment, people)
    row = PortfolioResult.objects.get()
    record = json.loads(json.dumps(row.record))
    record["lines"]["gross_cash"]["p50"] = "1"
    PortfolioResult._base_manager.filter(pk=row.pk).update(record=record)
    _unverified(_report_of(deployment, people), "result_digest")
    inputs = json.loads(json.dumps(row.inputs))
    inputs["groups"] = [{"group": "x", "strength": "0.001", "source_type": "CUSTOMER_PROVIDED", "evidence_ref": "x",
                         "scenarios": [], "applied_to": []}]
    PortfolioResult._base_manager.filter(pk=row.pk).update(inputs=inputs, record=row.record)
    document = _report_of(deployment, people)
    _unverified(document, "input_digest")
    assert "not_reported" in document["groups"] and "not_reported" in document["scenarios"]


def test_a_portfolio_row_is_checked_and_append_only(deployment, people):
    made_and_simulated(deployment, people["analyst"])
    _totalled(deployment, people)
    row = PortfolioResult.objects.get()
    with pytest.raises(EconomicsRewriteRefused):
        row.save()
    with pytest.raises(EconomicsRewriteRefused):
        PortfolioResult.objects.filter(pk=row.pk).update(seed="8")
    fields = {f.name: getattr(row, f.name) for f in PortfolioResult._meta.concrete_fields
              if f.name not in ("id", "uuid", "recorded_at", "deployment")}
    with_a_float = {**row.record, "simulations": 10_000.5}
    for changes, code in (
        ({"result_digest": "sha256:" + "0" * 64}, "digest_mismatch"),
        ({"record": with_a_float, "result_digest": canonical_digest(with_a_float)}, "portfolio_record_malformed"),
        ({"seed": "08"}, "portfolio_record_malformed"),
        ({"reporting_currency": "EUR"}, "portfolio_record_malformed"),
        ({}, "duplicate_id"),
    ):
        copy = PortfolioResult(deployment=deployment, **{**fields, **changes})
        with pytest.raises(EconomicsRefused) as refused:
            copy.save()
        assert refused.value.code == code, changes
    assert PortfolioResult.objects.count() == 1


def test_a_refusal_the_inputs_decide_is_recorded_and_one_they_do_not_is_not(deployment, people, monkeypatch):
    made_and_simulated(deployment, people["analyst"])
    monkeypatch.setattr(portfolio_api, "REQUEST_BUDGET_SECONDS", 0.0)
    late = _post(_client(people["analyst"]), deployment)
    assert late.status_code == 503 and late.json()["code"] == "time_over_budget"
    assert not PortfolioResult.objects.exists()
    monkeypatch.undo()
    # A portfolio-only limit (in its inputs, so another digest): too many values to hold.
    monkeypatch.setattr(ep, "LINES_PER_MEMBER", 10_000)
    tight = _post(_client(people["analyst"]), deployment)
    assert tight.status_code == 201 and tight.json()["portfolio"]["refusal"]["code"] == "values_over_budget"
    assert _post(_client(people["analyst"]), deployment).status_code == 200


# ======================================================================
# The routes: tenancy, roles, strict JSON
# ======================================================================


def test_tenancy_and_roles(deployment, other_deployment, people):
    scenario, _ = made_and_simulated(deployment, people["analyst"])
    theirs, _ = made_and_simulated(other_deployment, people["admin"])
    owner, stranger, analyst = _client(people["owner"]), _client(people["other"]), _client(people["analyst"])
    # The owner (a viewer) reads, and never totals.
    assert _post(owner, deployment).status_code == 403
    created = _post(analyst, deployment)
    assert created.status_code == 201, created.content
    assert _post(_client(people["admin"]), deployment).status_code == 200
    assert _document(owner, deployment).status_code == 200
    # A deployment the caller cannot see is 404 on both routes.
    assert _document(stranger, deployment).status_code == 404
    assert _post(stranger, deployment).status_code == 404
    # Another deployment's result named on this one is not found; and its scenario
    # is never totalled here, nor named in a group here.
    _post(_client(people["admin"]), other_deployment)
    elsewhere = PortfolioResult.objects.get(deployment=other_deployment)
    assert _document(analyst, deployment, elsewhere.uuid).status_code == 404
    assert _document(analyst, deployment, "not-a-uuid").status_code == 404
    mine = PortfolioResult.objects.get(deployment=deployment)
    assert [m["scenario"] for m in mine.inputs["members"]] == [str(scenario.uuid)]
    group = {"group": "g", "strength": "1", "source_type": "CUSTOMER_PROVIDED", "evidence_ref": LABEL,
             "scenarios": [str(theirs.uuid)]}
    refused = _post(analyst, deployment, _body(groups=[group]))
    assert refused.status_code == 400 and refused.json()["code"] == "scenario_not_found"
    # Signed out: 401.
    assert _document(_client(), deployment).status_code == 401
    assert _post(_client(), deployment).status_code == 401
    assert PortfolioResult.objects.count() == 2
    nothing = Deployment.objects.create(name="empty", owner=people["owner"])
    assert _document(owner, nothing).status_code == 404


@pytest.mark.parametrize(
    "body, code",
    [
        ({}, "field_missing"),
        (_body(draws=5000), "field_unrecognised"),
        (_body(seed=-1), "seed_malformed"),
        (_body(seed="1" * 4301), "seed_malformed"),
        (_body(policy="standard_5"), "policy_unrecognised"),
        (_body(reporting_currency="ZZZ"), "currency_unknown"),
        (_body(reporting_currency=7), "field_malformed"),
        (_body(valuation_date="2026-13-01"), "date_malformed"),
        (_body(groups=[{"group": "Bad Key", "strength": "1", "source_type": "CUSTOMER_PROVIDED", "evidence_ref": "e",
                        "scenarios": [str(uuid.uuid4())]}]), "group_malformed"),
        (_body(groups=[{"group": "g", "strength": "0", "source_type": "CUSTOMER_PROVIDED", "evidence_ref": "e",
                        "scenarios": [str(uuid.uuid4())]}]), "group_malformed"),
        (_body(groups=[{"group": "g", "strength": "10.5", "source_type": "CUSTOMER_PROVIDED", "evidence_ref": "e",
                        "scenarios": [str(uuid.uuid4())]}]), "group_malformed"),
        (_body(groups=[{"group": "g", "strength": "1", "source_type": "A_GUESS", "evidence_ref": "e",
                        "scenarios": [str(uuid.uuid4())]}]), "group_malformed"),
        (_body(groups=[{"group": "g", "strength": 1, "source_type": "CUSTOMER_PROVIDED", "evidence_ref": "e",
                        "scenarios": [str(uuid.uuid4())]}]), "group_malformed"),
        (_body(groups=[{"group": "g", "strength": "1", "source_type": "CUSTOMER_PROVIDED", "evidence_ref": "e",
                        "scenarios": ["11111111-1111-4111-8111-111111111111"]},
                       {"group": "h", "strength": "1", "source_type": "CUSTOMER_PROVIDED", "evidence_ref": "e",
                        "scenarios": ["11111111-1111-4111-8111-111111111111"]}]), "group_malformed"),
        (_body(groups=[{"group": "g", "strength": "1", "source_type": "CUSTOMER_PROVIDED", "evidence_ref": "e",
                        "scenarios": [str(uuid.uuid4())]}]), "scenario_not_found"),
        (_body(normalization={"base_currency": "USD"}), "field_missing"),
        (_body(normalization={"base_currency": "USD", "providers": ["P"], "index": {"series_id": "S", "geography": "G",
                                                                                  "category": "C", "base": "B"},
                              "sources": [str(uuid.uuid4())]}), "source_not_found"),
    ],
)
def test_a_portfolio_body_is_read_exactly(deployment, people, body, code):
    made_and_simulated(deployment, people["analyst"])
    response = _post(_client(people["analyst"]), deployment, body)
    assert response.status_code == 400, response.content
    assert response.json()["code"] == code
    assert not PortfolioResult.objects.exists()


def test_a_synthetic_source_is_never_read_by_a_portfolio(deployment, people):
    made_and_simulated(deployment, people["analyst"])
    synthetic = snapshots.register_snapshot()
    response = _post(_client(people["analyst"]), deployment, _body(normalization=_normalization([synthetic])))
    assert response.status_code == 400 and response.json()["code"] == "synthetic_source"
    assert not PortfolioResult.objects.exists()


def test_a_portfolio_body_is_strict_json_of_at_most_64_kib(deployment, people):
    from assurance.economics.api import MAX_BODY_BYTES

    analyst = _client(people["analyst"])
    padded = json.dumps({**_body(), "padding": "x" * MAX_BODY_BYTES})
    assert _post(analyst, deployment, padded, raw=True).status_code == 413
    assert _post(analyst, deployment, CONTENT_LENGTH=str(MAX_BODY_BYTES + 1)).status_code == 413
    assert _post(analyst, deployment, '{"seed": 7, "seed": 8}', raw=True).status_code == 400
    form = analyst.post(_url(deployment) + "simulate/", {"seed": "7"}, format="multipart")
    assert form.status_code == 415
    for method in ("put", "patch", "delete"):
        assert getattr(analyst, method)(_url(deployment)).status_code == 405
    assert analyst.get(_url(deployment) + "simulate/").status_code == 405
    assert not PortfolioResult.objects.exists()


def test_without_the_currency_table_both_routes_are_503(deployment, people, monkeypatch):
    from assurance.economics.engine import currency as currency_engine

    made_and_simulated(deployment, people["analyst"])
    _totalled(deployment, people)

    def unavailable():
        raise currency_engine.CurrencyTableInvalid("injected")

    monkeypatch.setattr(currency_engine, "require_pinned", unavailable)
    assert _post(_client(people["analyst"]), deployment, _body(seed=9)).status_code == 503
    assert _document(_client(people["owner"]), deployment).status_code == 503
    assert PortfolioResult.objects.count() == 1


def test_an_engine_that_will_not_import_is_503_and_records_nothing(deployment, people, monkeypatch):
    made_and_simulated(deployment, people["analyst"])

    def broken():
        raise ImportError("numpy is unavailable")

    monkeypatch.setattr(portfolio, "_engine", broken)
    response = _post(_client(people["analyst"]), deployment)
    assert response.status_code == 503 and response.json()["code"] == "engine_unavailable"
    assert not PortfolioResult.objects.exists()


# ======================================================================
# Safety: no transaction or lock during the draws, and off every stop path
# ======================================================================


@pytest.mark.django_db(transaction=True)
def test_no_transaction_or_lock_is_held_during_the_draws(monkeypatch):
    """SAFETY RULE (#158's probe): where the draws start and while each scenario is
    drawn, under the full request handler, the connection is in autocommit and in no
    atomic block, so nothing holds the database's write lock and a stop's write never
    waits behind a portfolio. The one atomic block is the insert after the draws."""
    from django.db import connection

    people = {"analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
              "owner": User.objects.create_user(username="vic", password="x", role="viewer")}
    dep = Deployment.objects.create(name="payments-agent", owner=people["owner"])
    made_and_simulated(dep, people["analyst"], title="A")
    made_and_simulated(dep, people["analyst"], title="B")
    probes = []
    real_run, real_sample = ep.run, ss._sample

    def probe(stage):
        probes.append((stage, connection.in_atomic_block, connection.get_autocommit()))

    def run(*args, **kwargs):
        probe("run")
        return real_run(*args, **kwargs)

    def sample(*args, **kwargs):
        probe("scenario")
        # A stop's write meanwhile: it is not held back.
        Deployment.objects.filter(pk=dep.pk).update(name="payments-agent")
        return real_sample(*args, **kwargs)

    monkeypatch.setattr(ep, "run", run)
    monkeypatch.setattr(ss, "_sample", sample)
    response = _post(_client(people["analyst"]), dep)
    assert response.status_code == 201, response.content
    assert probes and [p[0] for p in probes].count("scenario") == 4  # two scenarios, sampled twice
    assert all(in_atomic is False and autocommit is True for _, in_atomic, autocommit in probes), probes


def test_a_portfolio_fault_never_takes_down_a_stop():
    """SAFETY. A fresh pytest, under a plugin that makes the portfolio raise at import,
    before Django loads, runs ``tests/economics_fault_cases.py``: Django loads, the
    scan's Stop is answered (202) and saved, ``deliver_owed_stops`` reaches its
    handler, ``manage.py check`` passes, and every other economics route is served;
    only the portfolio's two are not."""
    env = dict(
        os.environ,
        DJANGO_SECRET_KEY=os.environ.get("DJANGO_SECRET_KEY", "ci-secret-key-not-used-outside-ci"),
        ECONOMICS_FAULT="portfolio",
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-p", "tests.economics_broken_portfolio",
         "-q", "tests/economics_fault_cases.py"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600, check=False,
    )
    assert result.returncode == 0, (result.stdout[-4000:], result.stderr[-2000:])
    assert "4 passed" in result.stdout, result.stdout[-2000:]


def test_removing_an_operator_never_writes_a_portfolio(deployment, people):
    leaver = User.objects.create_user(username="leaver", password="x", role="analyst")
    made_and_simulated(deployment, leaver)
    _totalled(deployment, people)
    row = PortfolioResult.objects.get()
    assert _client(people["admin"]).delete(f"/api/accounts/users/{leaver.pk}/").status_code == 204
    assert PortfolioResult.objects.get(pk=row.pk).result_digest == row.result_digest
    deployment.delete()
    assert not PortfolioResult.objects.exists()


# ======================================================================
# The shared-event rule (pure)
# ======================================================================


def _ref(scenario, key="ev", *, asset="a", spine=(), at=(), hypothetical=False, base="100"):
    figure = Decimal(base)
    return ep.EventRef(scenario, key, ("payment_agent_misuse", 1, asset, "payments"), frozenset(spine), tuple(at),
                       hypothetical, (figure, figure, figure))


def test_events_one_spine_effect_joins_are_one_however_far_apart():
    joined = ep.shared_events([_ref("s1", spine={"x"}, at=(WHEN,)),
                               _ref("s2", spine={"x"}, at=(WHEN + timedelta(days=90),), asset="b")])
    (one,) = joined
    assert one.kept.scenario == "s1" and [e.scenario for e in one.joined] == ["s2"] and one.by == ("spine_effect",)


def test_the_window_joins_one_key_within_24_hours_inclusive_and_no_further():
    inside = [_ref("s1", spine={"x"}, at=(WHEN,)), _ref("s2", spine={"y"}, at=(WHEN + timedelta(hours=24),))]
    assert len(ep.shared_events(inside)) == 1 and ep.shared_events(inside)[0].by == ("window",)
    outside = [_ref("s1", spine={"x"}, at=(WHEN,)),
               _ref("s2", spine={"y"}, at=(WHEN + timedelta(hours=24, microseconds=1),))]
    assert ep.shared_events(outside) == ()
    other_asset = [_ref("s1", spine={"x"}, at=(WHEN,)), _ref("s2", spine={"y"}, at=(WHEN,), asset="b")]
    assert ep.shared_events(other_asset) == ()
    assert ep.WINDOW == builder.GROUPING_WINDOW


def test_the_largest_event_is_counted_and_the_order_never_matters():
    events = [_ref("s1", spine={"x"}, at=(WHEN,), base="100"), _ref("s2", spine={"x"}, at=(WHEN,), base="300"),
              _ref("s3", spine={"x"}, at=(WHEN,), base="200")]
    (one,) = ep.shared_events(events)
    assert one.kept.scenario == "s2" and [e.scenario for e in one.joined] == ["s1", "s3"]
    assert ep.shared_events(list(reversed(events))) == (one,)


def test_hypothetical_events_of_one_key_are_one_and_join_one_observed_event_where_they_add_the_most():
    hypothetical = [_ref("h1", hypothetical=True, base="500"), _ref("h2", hypothetical=True, base="50")]
    (one,) = ep.shared_events(hypothetical)
    assert one.kept.scenario == "h1" and one.by == ("hypothetical",)
    observed = [_ref("o1", spine={"x"}, at=(WHEN,), base="1000"),
                _ref("o2", spine={"y"}, at=(WHEN + timedelta(days=5),), base="10")]
    joined = ep.shared_events(hypothetical + observed)
    # The hypothetical events add 490 to o2's, nothing to o1's: they join o2's, and only it.
    (one,) = joined
    assert one.kept.scenario == "h1" and {e.scenario for e in one.joined} == {"h2", "o2"}
    assert "hypothetical" in one.by


def test_a_member_without_an_event_counted_elsewhere_reads_none_of_its_parameters(deployment, people):
    scenario = made(deployment, people["analyst"])
    si = simulation_service.load_input(scenario)
    assert ep.without_events(si, []) is si
    assert ep.without_events(si, ["ev-pay"]) is None


# ======================================================================
# The specification
# ======================================================================


SPEC_PHRASES = (
    "## 28. Portfolio aggregation (Economic Exposure E5)",
    "`POST deployments/<uuid>/economics/portfolio/simulate/`",
    "`GET deployments/<uuid>/economics/portfolio/`",
    "`mythos.economics.portfolio/v1`",
    "`mythos.economics.portfolio-report/v1`",
    "`mythos.economics.group-driver/v1`",
    "`mythos.economics.portfolio-shared-events/v1`",
    "never by summing percentiles",
    "expected shortfall",
    "Copulas",
    "### 28.10 Decisions this step takes, which the owner may change",
)


def test_the_spec_states_the_portfolio():
    text = SPEC.read_text(encoding="utf-8")
    for phrase in SPEC_PHRASES:
        assert phrase in text, phrase
    for code in portfolio.EXCLUSIONS:
        assert f"`{code}`" in text, code
    for code in ep.REFUSALS:
        assert f"`{code}`" in text, code
