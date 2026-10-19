"""Economic Exposure E5: a deployment's portfolio, aggregated from its scenarios'
draws (``docs/economics/spec-v1.md``, section 33; the owner's specification,
section 24).

- known answers: two independent scenarios sum their means within the band and
  never their percentiles; two co-driven scenarios have a wider tail; one shared
  effect in two scenarios, and five findings on one payment loss, are counted once
  a year, at the largest loss that year; an Unknown scenario, and every other one
  not totalled, is excluded and named; a currency that cannot be normalised is
  excluded, and one that can is normalised before it is summed;
- review round 1: the portfolio is at least each included scenario, year by year
  and at every figure it serves, and adding a scenario never lowers one (the
  reviewer's rare duplicate, and the narrow/wide pair); a residual run is never
  totalled; an edited input, a vanished card, a report not totalled and a record
  not of its inputs are each caught; a group names two scenarios and a strength
  above its floor;
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
import time
import uuid
from datetime import date, datetime, timedelta
from datetime import timezone as dt_timezone
from decimal import Decimal
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from assurance.economics import builder, portfolio, portfolio_api, report, simulation_service, snapshots, validity_service
from assurance.economics.engine import portfolio as ep
from assurance.economics.engine import scenario_simulation as ss
from assurance.economics.models import (
    CausalEffect,
    CorrelationGroup,
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
    SimulationResult,
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
#: The reviewer's rare duplicate (review round 1, HIGH-1): a marginally larger figure than SMALL.
DUPLICATE = (("80001", "100001", "120001"),
             {"id": "gamma", "version": 1, "params": {"shape": "100", "scale": "1000.01"}})
#: The reviewer's wide one (MEDIUM-1): a gamma of shape 1, mean 100,000.
WIDE = (("20000", "100000", "400000"), {"id": "gamma", "version": 1, "params": {"shape": "1", "scale": "100000"}})
SPINE = "sha256:" + "5a" * 32
WHEN = datetime(2026, 10, 1, 12, 0, tzinfo=dt_timezone.utc)
#: Every figure a portfolio serves for a line, and each included scenario's own.
FIGURES = ("p10", "p50", "p90", "severe_plausible", "mean", "expected_annual_loss", "expected_shortfall")


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


#: How many assets and findings one scan records for a deployment (:func:`_scanned`).
SCANNED = 16


def _scanned(deployment) -> tuple[str, Finding]:
    """An agent asset and a finding for one more scenario of ``deployment``, from those
    one scan recorded before the deployment's first run: E6 (spec, section 34) reads a
    run as stale where SPINE's graph moved after it -- an asset added moves every claim
    type's inputs, and a finding a later scan does not report reads ``cleared`` -- so
    the scenarios' assets and findings are recorded at once, at one time, and each
    scenario takes the next one no scenario uses yet."""
    pool = Asset.objects.filter(deployment=deployment, identifier__startswith="agent://scan-").order_by("id")
    if not pool.exists():
        scan = timezone.now()
        for index in range(SCANNED):
            Asset.objects.create(deployment=deployment, kind="agent", name="payments-agent",
                                 identifier=f"agent://scan-{index:02d}-{uuid.uuid4().hex[:6]}")
            Finding.objects.create(deployment=deployment, fingerprint=f"fp-scan-{index:02d}", first_seen=scan,
                                   last_seen=scan, finding_type="approval_missing", title="approval missing",
                                   severity="high")
    used_assets = set(CausalEffect.objects.filter(scenario__deployment=deployment).values_list("asset", flat=True))
    used_findings = set(
        EffectFinding.objects.filter(effect__scenario__deployment=deployment).values_list("finding", flat=True)
    )
    asset = next(str(row.uuid) for row in pool if str(row.uuid) not in used_assets)
    finding = next(
        row for row in Finding.objects.filter(deployment=deployment, fingerprint__startswith="fp-scan-").order_by("id")
        if str(row.uuid) not in used_findings
    )
    return asset, finding


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
    scanned, finding = _scanned(deployment)
    if asset is None:
        asset = scanned
    observed = {} if hypothetical else {
        "observed_effect": str(uuid.uuid4()), "observation": "sha256:" + uuid.uuid4().hex * 2,
        "spine_effect": spine or "sha256:" + uuid.uuid4().hex * 2, "occurred_at": occurred_at,
    }
    effect = CausalEffect.objects.create(
        scenario=scenario, loss_event=event, effect_key="pay", origin="hypothetical" if hypothetical else "observed",
        effect_type="funds_transfer_altered", asset=asset, business_process="payments",
        template_id="payment_agent_misuse", template_version=1, in_scope_of=[["payment_agent_misuse", 1]], **observed,
    )
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


def _post_group(client, deployment, body):
    return client.post(_url(deployment) + "groups/", data=json.dumps(body), content_type="application/json")


def _group_body(scenarios, *, key="provider", strength="2", source="CUSTOMER_PROVIDED", evidence=None):
    return {"group": key, "strength": strength, "source_type": source,
            "evidence_ref": evidence or f"{LABEL}: they rely on one provider",
            "scenarios": sorted(str(s.uuid) for s in scenarios)}


def _grouped(deployment, people, scenarios, **over):
    """A correlation group version recorded by the analyst, through its route: its uuid."""
    response = _post_group(_client(people["analyst"]), deployment, _group_body(scenarios, **over))
    assert response.status_code in (200, 201), response.content
    return response.json()["group"]["uuid"]


def _stored(result, line="gross_cash"):
    return result.record["scenario"][line]


def _standard_error(block):
    return float(block["standard_error_of_mean"])


def _at_least(larger, smaller, why):
    """Every figure served in ``larger`` is at least the same one in ``smaller``,
    both lines, at the minor unit."""
    for line in ("gross_cash", "retained_cash"):
        for figure in FIGURES:
            big, small = Decimal(larger[line][figure]), Decimal(smaller[line][figure])
            assert big >= small, (why, line, figure, big, small)


def _years(monkeypatch):
    """Each line's years as the engine summarises them, in order: every included
    scenario's own (by uuid), then the portfolio's."""
    seen = []
    real = ep._block

    def capture(vector, **kwargs):
        seen.append(vector.copy())
        return real(vector, **kwargs)

    monkeypatch.setattr(ep, "_block", capture)
    return seen


def _each_year_at_least_each_scenario(seen, members):
    per_line = members + 1
    assert len(seen) == 2 * per_line
    for at in range(2):
        *owns, total = seen[at * per_line:(at + 1) * per_line]
        for own in owns:
            assert (total >= own).all()


def _shared_asset(deployment):
    return str(Asset.objects.create(deployment=deployment, kind="agent", name="pay", identifier="agent://pay").uuid)


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
    group = _grouped(deployment, people, [a, b], key="cloud-provider", evidence=f"{LABEL}: both rely on one provider")
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


def test_one_shared_effect_in_two_scenarios_is_counted_once_a_year_at_the_larger_loss(deployment, people,
                                                                                      monkeypatch):
    """The same SPINE effect in two scenarios is one loss event. Each scenario keeps
    it, drawn at its own frequency; each year the portfolio counts it once, at the
    larger of the two losses of it that year (review round 1, HIGH-1): never below
    either scenario, year by year, and never their sum."""
    shared = _shared_asset(deployment)
    a, _ = made_and_simulated(deployment, people["analyst"], title="A", spine=SPINE, asset=shared)
    # Observed a month apart: one SPINE effect is one event whatever the window (step 5).
    b, _ = made_and_simulated(deployment, people["analyst"], title="B", spine=SPINE, asset=shared,
                              occurred_at=WHEN + timedelta(days=30))
    seen = _years(monkeypatch)
    document = _totalled_report(deployment, people)
    first, second = sorted([str(a.uuid), str(b.uuid)])
    (joined,) = document["shared_events"]
    assert [e["scenario"] for e in joined["events"]] == [first, second]
    assert joined["by"] == ["spine_effect"] and joined["links"] == [[0, 1]] and joined["sets"] == [[0], [1]]
    assert joined["counted"] == portfolio.COUNTED_ONCE
    by = {m["scenario"]: m for m in document["scenarios"]["included"]}
    # No event is dropped from either scenario.
    assert by[first]["events"] == by[second]["events"] == ["ev-pay"]
    assert by[first]["shared"] == [{"event_key": "ev-pay", "with": [{"scenario": second, "event_key": "ev-pay"}]}]
    _each_year_at_least_each_scenario(seen, 2)
    lines = document["summary"]["lines"]
    _at_least(lines, by[first]["own"], first)
    _at_least(lines, by[second]["own"], second)
    owns = [Decimal(by[sid]["own"]["gross_cash"]["mean"]) for sid in (first, second)]
    assert Decimal(lines["gross_cash"]["mean"]) < Decimal("0.9") * sum(owns)  # once a year, not twice
    years = joined["years"]["gross_cash"]
    assert sum(years["years_counted_by"].values()) == years["years_with_loss"]
    assert min(years["years_counted_by"].values()) > 0
    contributions = _record(document)["contributions"]["gross_cash"]["mean"]["by_scenario"]
    assert Decimal(contributions[first]) > 0 and Decimal(contributions[second]) > 0


def test_five_findings_on_one_payment_loss_never_quintuple_the_portfolio(deployment, people):
    """The specification's own test (section 27, at portfolio level): five scenarios,
    each from one finding enabling the same payment-loss event -- one SPINE effect,
    observed five times -- make ONE loss a year in the portfolio, not five: the
    largest of the five that year, so at least each and far below their sum."""
    shared = _shared_asset(deployment)
    for index in range(5):
        made_and_simulated(deployment, people["analyst"], title=f"finding {index}", spine=SPINE, asset=shared,
                           occurred_at=WHEN + timedelta(days=index * 3))
    document = _totalled_report(deployment, people)
    assert len(document["scenarios"]["included"]) == 5
    (joined,) = document["shared_events"]
    assert len(joined["events"]) == 5 and len(joined["links"]) == 10 and len(joined["sets"]) == 5
    lines = document["summary"]["lines"]
    owns = []
    for member in document["scenarios"]["included"]:
        _at_least(lines, member["own"], member["scenario"])
        owns.append(Decimal(member["own"]["gross_cash"]["mean"]))
    assert Decimal(lines["gross_cash"]["mean"]) < Decimal("0.5") * sum(owns)  # never quintupled


def test_a_rare_duplicate_never_hides_a_frequent_loss(deployment, people, monkeypatch):
    """Review round 1, HIGH-1, the reviewer's repro: B, a loss of about 100,000 five
    times a year, is totalled alone; then A -- the same SPINE effect and asset, 0.05 a
    year, a marginally larger figure -- is added. Counted once A YEAR, at the larger
    loss that year, the duplicate hides nothing: adding A lowers no figure served,
    and the portfolio is at least B and A, year by year and at every figure."""
    shared = _shared_asset(deployment)
    b, _ = made_and_simulated(deployment, people["analyst"], title="B", rate="5", spine=SPINE, asset=shared)
    alone = _totalled_report(deployment, people)
    a, _ = made_and_simulated(deployment, people["analyst"], title="A", rate="0.05", amount=DUPLICATE, spine=SPINE,
                              asset=shared, occurred_at=WHEN + timedelta(days=30))
    seen = _years(monkeypatch)
    both = _totalled_report(deployment, people)
    assert {m["scenario"] for m in both["scenarios"]["included"]} == {str(a.uuid), str(b.uuid)}
    assert len(both["shared_events"]) == 1
    _each_year_at_least_each_scenario(seen, 2)
    _at_least(both["summary"]["lines"], alone["summary"]["lines"], "adding A")
    by = {m["scenario"]: m for m in both["scenarios"]["included"]}
    for sid, member in by.items():
        _at_least(both["summary"]["lines"], member["own"], sid)
    # B's draws are its own: alone, it is the portfolio it was.
    for line in ("gross_cash", "retained_cash"):
        for figure in ("p10", "p50", "p90", "severe_plausible"):
            assert by[str(b.uuid)]["own"][line][figure] == alone["summary"]["lines"][line][figure]
    assert Decimal(both["summary"]["lines"]["gross_cash"]["mean"]) > Decimal(400_000)
    assert both["grade"]["grade"] == "B" and both["banner"] is None and both["complete"] is True


def test_no_included_scenario_states_a_larger_tail_than_the_portfolio(deployment, people):
    """Review round 1, MEDIUM-1, the reviewer's narrow/wide pair: two scenarios at 2 a
    year share one SPINE effect, a narrow figure (about 100,001) and a wide one (a
    gamma of shape 1, mean 100,000). The year's count is the larger loss that year,
    so the portfolio's P90, P95 and expected shortfall are at least the wide one's own
    over the portfolio's years, and within a few per cent of its own stored run's."""
    shared = _shared_asset(deployment)
    made_and_simulated(deployment, people["analyst"], title="narrow", amount=DUPLICATE, spine=SPINE, asset=shared)
    wide, stored = made_and_simulated(deployment, people["analyst"], title="wide", amount=WIDE, spine=SPINE,
                                      asset=shared, occurred_at=WHEN + timedelta(days=30))
    document = _totalled_report(deployment, people)
    lines = document["summary"]["lines"]
    for member in document["scenarios"]["included"]:
        _at_least(lines, member["own"], member["scenario"])
    own = next(m["own"] for m in document["scenarios"]["included"] if m["scenario"] == str(wide.uuid))
    for figure in ("p90", "severe_plausible", "expected_shortfall"):
        assert Decimal(lines["gross_cash"][figure]) >= Decimal(own["gross_cash"][figure])
    for figure in ("p90", "severe_plausible"):
        assert Decimal(lines["gross_cash"][figure]) >= Decimal("0.95") * Decimal(_stored(stored)[figure]), figure


def test_a_residual_run_is_never_totalled_and_never_hides_the_exposure_run(deployment, people):
    """Review round 1, MEDIUM-2: a remediation option's residual run is the scenario's
    latest row, yet the portfolio totals the scenario at its EXPOSURE run (the one
    results/ serves), never the residual run; and a stored portfolio rewritten to
    name the residual run is never served."""
    from tests.test_economics_remediation import option_body

    scenario, _ = made_and_simulated(deployment, people["analyst"], title="A")
    analyst = _client(people["analyst"])
    base = f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario.uuid}/"
    recorded = analyst.post(base + "mitigations/", data=json.dumps(option_body("0.5")),
                            content_type="application/json")
    assert recorded.status_code == 201, recorded.content
    option = recorded.json()["option"]["uuid"]
    ran = analyst.post(base + f"mitigations/{option}/simulate/", data=json.dumps({"seed": 7, "policy": QUICK}),
                       content_type="application/json")
    assert ran.status_code in (200, 201), ran.content
    residual = SimulationResult.objects.residual_runs().get(scenario=scenario)
    exposure = SimulationResult.objects.exposure_runs().filter(scenario=scenario).order_by("-id").first()
    assert residual.pk > exposure.pk and exposure.remediation_id is None
    document = _totalled_report(deployment, people)
    (member,) = document["scenarios"]["included"]
    assert member["result"] == str(exposure.uuid) and member["result_digest"] == exposure.result_digest
    assert document["scenarios"]["excluded"] == [] and document["complete"] is True
    assert str(residual.uuid) not in json.dumps(document)
    # The stored inputs rewritten, digest and all, to name the residual run: refused.
    row = PortfolioResult.objects.get()
    inputs = json.loads(json.dumps(row.inputs))
    inputs["members"][0].update(result=str(residual.uuid), result_digest=residual.result_digest,
                                input_digest=residual.input_digest)
    PortfolioResult._base_manager.filter(pk=row.pk).update(inputs=inputs, input_digest=canonical_digest(inputs))
    rewritten = _report_of(deployment, people)
    _unverified(rewritten, "record_binding", "member_rows")
    assert rewritten["integrity"]["scenarios_failed"] == [
        {"scenario": str(scenario.uuid), "reason": "the result is a residual run under a remediation option, never "
                                                   "exposure"}
    ]


def test_a_scenario_that_links_two_others_never_lowers_the_portfolio(deployment, people, monkeypatch):
    """Adding a scenario never lowers the portfolio, even one whose event links two
    events that were apart: A (one day) and C (two days later) of one key are two
    loss events; B, observed between them, is linked to each. The three are one
    chain, counted each year at the larger of A's and C's together, or B's -- never
    at the largest of the three, which could be below A's and C's together."""
    shared = _shared_asset(deployment)
    made_and_simulated(deployment, people["analyst"], title="A", asset=shared)
    made_and_simulated(deployment, people["analyst"], title="C", asset=shared, occurred_at=WHEN + timedelta(hours=40))
    apart = _years(monkeypatch)
    before = _totalled_report(deployment, people)
    assert before["shared_events"] == []
    made_and_simulated(deployment, people["analyst"], title="B", asset=shared, occurred_at=WHEN + timedelta(hours=20))
    monkeypatch.undo()
    chained = _years(monkeypatch)
    after = _totalled_report(deployment, people)
    (joined,) = after["shared_events"]
    assert joined["by"] == ["window"] and len(joined["links"]) == 2 and len(joined["sets"]) == 2
    assert joined["counted"] == portfolio.COUNTED_CHAIN
    _each_year_at_least_each_scenario(chained, 3)
    for at in range(2):
        assert (chained[at * 4 + 3] >= apart[at * 3 + 2]).all()
    _at_least(after["summary"]["lines"], before["summary"]["lines"], "adding B")


def test_a_shared_event_counted_too_many_ways_is_a_recorded_refusal(deployment, people, monkeypatch):
    shared = _shared_asset(deployment)
    made_and_simulated(deployment, people["analyst"], title="A", spine=SPINE, asset=shared)
    made_and_simulated(deployment, people["analyst"], title="B", spine=SPINE, asset=shared)
    monkeypatch.setattr(ep, "MAX_COUNTED_SETS", 1)
    posted = _totalled(deployment, people)
    assert posted["portfolio"]["refusal"]["code"] == "shared_too_complex" and posted["grade"] is None
    assert PortfolioResult.objects.get().status == "refused"


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


def test_an_edited_input_excludes_its_scenario_as_inputs_changed(deployment, people):
    """Review round 1, LOW-1 (the reviewer's M9): a parameter a scenario's run cites,
    edited past the append-only checks after the run: its stored rows no longer give
    the inputs it was run on, so it is excluded as ``inputs_changed`` with both
    digests named, and the rest is totalled."""
    edited, result = made_and_simulated(deployment, people["analyst"], title="edited")
    kept, _ = made_and_simulated(deployment, people["analyst"], title="kept")
    FinancialParameter._base_manager.filter(scenario=edited, name="pay.loss").update(base="100001")
    document = _totalled_report(deployment, people)
    (excluded,) = document["scenarios"]["excluded"]
    assert (excluded["scenario"], excluded["code"]) == (str(edited.uuid), "inputs_changed")
    assert excluded["reason"].startswith("sha256:") and excluded["reason"].endswith(f", not {result.input_digest}")
    assert [m["scenario"] for m in document["scenarios"]["included"]] == [str(kept.uuid)]


def test_a_report_refused_for_any_other_reason_is_excluded_as_not_totalled(deployment, people, monkeypatch):
    """Review round 1, LOW-1: a verified, completed and graded report that
    :func:`report.may_be_totalled` refuses all the same is excluded as
    ``not_totalled``: the portfolio totals through that one rule only."""
    scenario, _ = made_and_simulated(deployment, people["analyst"])
    monkeypatch.setattr(report, "may_be_totalled", lambda document: False)
    posted = _totalled(deployment, people)
    assert [(e["scenario"], e["code"]) for e in posted["excluded"]] == [(str(scenario.uuid), "not_totalled")]
    assert posted["portfolio"]["refusal"]["code"] == "nothing_to_total"


def test_a_vanished_card_refuses_the_portfolio_it_was_totalled_in(deployment, people):
    """Review round 1, LOW-1 (the reviewer's M12): an included scenario's Validity Card
    deleted after the portfolio was totalled. Step 6's checks accept a run with no
    card, so the portfolio's own recheck of the grade it totalled is what refuses
    it, naming the scenario."""
    a, ra = made_and_simulated(deployment, people["analyst"], title="A")
    made_and_simulated(deployment, people["analyst"], title="B")
    _totalled(deployment, people)
    FinancialValidityCard._base_manager.filter(simulation=ra).delete()
    document = _report_of(deployment, people)
    _unverified(document, "member_rows")
    assert document["integrity"]["scenarios_failed"] == [
        {"scenario": str(a.uuid), "reason": "its card's grade is not the one totalled"}
    ]


@pytest.fixture
def sources(tmp_path):
    """The committed snapshot's observations, registered as a NON-synthetic source a
    production run may read (a benchmark, open licence): SYNTHETIC TEST DATA all the
    same, as its label says. Registered as a feed's answer is, with the terms a
    reviewed registry line gives (a snapshot FILE's own statement is not read: spec,
    section 35.2)."""
    document = json.loads(snapshots.SYNTHETIC_SNAPSHOT.read_bytes())
    document["synthetic"] = False
    document["source"].update(trust_tier="benchmark")
    path = tmp_path / "snapshot.json"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return [snapshots.register(snapshots.read_snapshot(path))[0]]


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


@pytest.fixture
def restricted(tmp_path):
    """The committed snapshot again, registered as a source whose licence is
    ``restricted`` (its terms allow storing it and deriving figures from it, not
    redistributing its raw data). SYNTHETIC TEST DATA all the same."""
    document = json.loads(snapshots.SYNTHETIC_SNAPSHOT.read_bytes())
    document["synthetic"] = False
    document["source"].update(trust_tier="benchmark", license_class="restricted",
                              source_key="restricted-fx-and-cost-index")
    path = tmp_path / "restricted.json"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    # As a feed's answer is registered, with its registry line's terms (spec, section 35.2).
    return [snapshots.register(snapshots.read_snapshot(path))[0]]


def test_a_restricted_sources_raw_rates_never_reach_a_reader(deployment, people, restricted):
    """The section-28 audit's T7: a scenario normalised through a source whose licence
    forbids redistributing its raw data. The portfolio's report serves no raw rate or
    index value of it, and no number made from them (the factor, a step's rate, ratio
    or amounts): each observation is shown by its source, version, snapshot hash and
    dates only. The stored inputs keep the whole record, and the figures stand."""
    valued = date(2026, 9, 30)
    made_and_simulated(deployment, people["analyst"], title="USD", as_of=valued)
    eur, _ = made_and_simulated(deployment, people["analyst"], title="EUR", currency="EUR", as_of=valued)
    posted = _totalled(deployment, people, valuation_date="2026-09-30", normalization=_normalization(restricted))
    document = _report_of(deployment, people, posted["portfolio"]["uuid"])
    assert document["scenarios"]["excluded"] == [] and document["summary"]["lines"]["gross_cash"]["mean"]
    assert document["normalization"]["sources"][0]["license_class"] == "restricted"
    by = {m["scenario"]: m for m in document["scenarios"]["included"]}
    served = by[str(eur.uuid)]["normalization"]
    assert served["factor"] is None and "licensed restricted" in served["withheld"]
    record = served["record"]
    assert record["value"] is None and record["display"] is None and "native" not in record
    assert record["chain"] and all(
        not {"quoted_rate", "factor", "ratio", "input", "output", "interpolation_weight"} & set(step)
        for step in record["chain"]
    )
    observations = [o for step in record["chain"] for o in step["observations"]]
    assert observations
    for observation in observations:
        assert set(observation) <= {"source_key", "source_version", "source_snapshot_hash", "observations_version",
                                    "effective_date", "observed_at", "period", "vintage_date", "license_class",
                                    "withheld"}, observation
        assert observation["source_key"] == "restricted-fx-and-cost-index"
        assert observation["source_snapshot_hash"] == restricted[0].snapshot_hash
    # Stored whole (the licence allows storing), served nowhere.
    stored = next(m for m in PortfolioResult.objects.get().inputs["members"] if m["scenario"] == str(eur.uuid))
    assert stored["normalization"]["factor"] == "1.05"
    raw = {o.get("rate") or o.get("value") for step in stored["normalization"]["record"]["chain"]
           for o in step["observations"]}
    assert raw and None not in raw
    served_text = json.dumps(document)
    for value in raw | {"1.05"}:
        assert f'"{value}"' not in served_text, value
    assert by[[s for s in by if s != str(eur.uuid)][0]]["normalization"]["rule"] == "identity"


def test_a_conflict_naming_a_restricted_source_never_shows_its_values(deployment, people, sources, tmp_path):
    """The audit's T7 with step 12's conflicts (spec 12.8): an open source is read, and
    a restricted one quoting the same pair that day disagrees by 10%. The record lists
    the conflict with both values; the report shows which sources disagreed, never
    either value or how far apart."""
    document = json.loads(snapshots.SYNTHETIC_SNAPSHOT.read_bytes())
    document["synthetic"] = False
    document["source"].update(trust_tier="benchmark", license_class="restricted", source_key="restricted-other-ref")
    document["calendars"] = {"OTHER-REF": {"non_publication_dates": []}}
    document["fx"] = [
        {**rate, "provider": "OTHER-REF", "rate": "1.1550"} for rate in document["fx"]
        if (rate["base"], rate["quote"], rate["effective_date"], rate["rate_type"])
        == ("EUR", "USD", "2026-09-30", "reference")
    ]
    document["cost_index"] = []
    path = tmp_path / "other.json"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    # As a feed's answer is registered, with its registry line's terms (spec, section 35.2).
    other, _ = snapshots.register(snapshots.read_snapshot(path))
    valued = date(2026, 9, 30)
    eur, _ = made_and_simulated(deployment, people["analyst"], title="EUR", currency="EUR", as_of=valued)
    posted = _totalled(deployment, people, valuation_date="2026-09-30",
                       normalization=_normalization([*sources, other]))
    stored = PortfolioResult.objects.get().inputs["members"][0]["normalization"]
    (conflict,) = stored["record"]["conflicts"]
    assert (conflict["secondary"], conflict["secondary_value"]) == ("restricted-other-ref", "1.155")
    served = _report_of(deployment, people, posted["portfolio"]["uuid"])
    (member,) = served["scenarios"]["included"]
    normalization = member["normalization"]
    assert normalization["factor"] is None and "licensed restricted" in normalization["withheld"]
    (shown,) = normalization["record"]["conflicts"]
    assert (shown["primary"], shown["secondary"], shown["withheld"]) == (
        "synthetic-fx-and-cost-index", "restricted-other-ref", "both values")
    assert not {"primary_value", "secondary_value", "secondary_quoted", "relative_difference"} & set(shown)
    text = json.dumps(served)
    for value in ("1.155", "1.1550", conflict["relative_difference"]):
        assert f'"{value}"' not in text, value
    # The open source's own observation may be redistributed, and is shown.
    (observation,) = normalization["record"]["chain"][0]["observations"]
    assert (observation["source_key"], observation["rate"]) == ("synthetic-fx-and-cost-index", "1.05")
    assert str(eur.uuid) == member["scenario"]


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
    plain = _report_of(deployment, people, _totalled(deployment, people)["portfolio"]["uuid"])
    grade = report.verified_grade(FinancialValidityCard.objects.get(simulation=rb), rb)
    assert grade == "B"
    assert plain["grade"]["grade"] == "B" and plain["grade"]["downgrades"] == []
    assert plain["banner"] is None and plain["excluded_from_totals"] is False
    customer = _grouped(deployment, people, [a, b], strength="0.5")
    expert = _grouped(deployment, people, [a, b], strength="0.5", source="EXPERT_ESTIMATE")
    assert _report_of(deployment, people, _totalled(deployment, people, groups=[customer])["portfolio"]["uuid"])[
        "grade"]["grade"] == "B"
    lowered = _report_of(deployment, people, _totalled(deployment, people, groups=[expert])["portfolio"]["uuid"])
    assert lowered["grade"]["grade"] == "C" and lowered["grade"]["base"] == "B"
    assert lowered["grade"]["downgrades"] == [{"code": "expert_correlation", "groups": ["provider"]}]
    # An expert's frequency grades its scenario D: the portfolio is no higher, and never below D.
    made_and_simulated(deployment, people["analyst"], title="D", frequency_source="EXPERT_ESTIMATE")
    lowest = _report_of(deployment, people, _totalled(deployment, people, groups=[expert])["portfolio"]["uuid"])
    assert lowest["grade"]["base"] == "D" and lowest["grade"]["grade"] == "D"


def test_a_group_with_one_scenario_included_applies_to_none_and_lowers_no_grade(deployment, people):
    """Review round 1, LOW-4 and NIT-1: a group applies only where two of its scenarios
    at least are included. One whose other scenario is excluded (Unknown) applies to
    none: never drawn, its member drawn as its own frequency states, the figures
    those of no group, and an expert's strength for it lowers no grade."""
    a, _ = made_and_simulated(deployment, people["analyst"], title="A")
    unknown, _ = made_and_simulated(deployment, people["analyst"], title="unknown", unknown=True)
    group = _grouped(deployment, people, [a, unknown], source="EXPERT_ESTIMATE")
    plain = _totalled_report(deployment, people)
    grouped = _totalled_report(deployment, people, groups=[group])
    (shown,) = grouped["groups"]
    assert shown["applied_to"] == [] and shown["not_applied"].startswith("fewer than two of its scenarios")
    record = _record(grouped)
    assert record["groups"]["provider"]["drawn"] is False and record["groups"]["provider"]["members"] == []
    assert record["members"][str(a.uuid)]["group"] is None
    assert grouped["grade"]["grade"] == plain["grade"]["grade"] == "B" and grouped["grade"]["downgrades"] == []
    assert grouped["summary"] == plain["summary"]


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


def test_a_record_not_of_its_inputs_is_never_served(deployment, people):
    """Review round 1, LOW-3 (the reviewer's repro): a portfolio with an expert's group
    is graded C. Its inputs rewritten to a customer's source, their digest
    recomputed, give their digest; but the record still names the inputs it was
    drawn from, so the report is refused (``record_binding``, and ``group_rows`` as
    the group version is not recorded so), never served as B.
    So is a record rewritten, its digest recomputed, to draw a scenario apart from
    the group its inputs name."""
    a, _ = made_and_simulated(deployment, people["analyst"], title="A")
    b, _ = made_and_simulated(deployment, people["analyst"], title="B")
    group = _grouped(deployment, people, [a, b], strength="0.5", source="EXPERT_ESTIMATE")
    _totalled(deployment, people, groups=[group])
    assert _report_of(deployment, people)["grade"]["grade"] == "C"
    row = PortfolioResult.objects.get()
    inputs = json.loads(json.dumps(row.inputs))
    inputs["groups"][0]["source_type"] = "CUSTOMER_PROVIDED"
    PortfolioResult._base_manager.filter(pk=row.pk).update(inputs=inputs, input_digest=canonical_digest(inputs))
    # Refused twice over: the record is not of these inputs, and the group version
    # they name is not recorded so.
    _unverified(_report_of(deployment, people), "record_binding", "group_rows")
    record = json.loads(json.dumps(row.record))
    record["members"][str(a.uuid)]["group"] = None
    PortfolioResult._base_manager.filter(pk=row.pk).update(
        inputs=row.inputs, input_digest=row.input_digest, record=record, result_digest=canonical_digest(record)
    )
    _unverified(_report_of(deployment, people), "record_binding")


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
    monkeypatch.setattr(ep, "LINES_PER_EVENT", 10_000)
    tight = _post(_client(people["analyst"]), deployment)
    assert tight.status_code == 201 and tight.json()["portfolio"]["refusal"]["code"] == "values_over_budget"
    assert _post(_client(people["analyst"]), deployment).status_code == 200
    # A refused portfolio has no figures, so no grade (review round 1, NIT-2).
    refused = _report_of(deployment, people)
    assert tight.json()["grade"] is None and refused["grade"]["grade"] is None
    assert refused["grade"]["reason"] == "a refused portfolio has no figures and no grade"


# ======================================================================
# The routes: tenancy, roles, strict JSON
# ======================================================================


def test_tenancy_and_roles(deployment, other_deployment, people):
    scenario, _ = made_and_simulated(deployment, people["analyst"])
    theirs, _ = made_and_simulated(other_deployment, people["admin"])
    theirs_too = made(other_deployment, people["admin"], title="theirs too")
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
    refused = _post_group(analyst, deployment, _group_body([scenario, theirs]))
    assert refused.status_code == 400 and refused.json()["code"] == "scenario_not_found"
    # Nor is another deployment's group named here.
    other_group = _post_group(_client(people["admin"]), other_deployment, _group_body([theirs, theirs_too]))
    assert other_group.status_code == 201, other_group.content
    named = _post(analyst, deployment, _body(groups=[other_group.json()["group"]["uuid"]]))
    assert named.status_code == 400 and named.json()["code"] == "group_not_found"
    assert _post_group(stranger, deployment, _group_body([scenario, scenario])).status_code == 404
    assert _client(people["other"]).get(_url(deployment) + "groups/").status_code == 404
    # Signed out: 401.
    assert _document(_client(), deployment).status_code == 401
    assert _post(_client(), deployment).status_code == 401
    assert PortfolioResult.objects.count() == 2
    nothing = Deployment.objects.create(name="empty", owner=people["owner"])
    assert _document(owner, nothing).status_code == 404


U1, U2, U3 = (f"{n}{n}{n}{n}{n}{n}{n}{n}-{n}{n}{n}{n}-4{n}{n}{n}-8{n}{n}{n}-{n * 12}" for n in "123")


def _group(**over):
    return {"group": "g", "strength": "1", "source_type": "CUSTOMER_PROVIDED", "evidence_ref": "e",
            "scenarios": [U1, U2], **over}


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
        # A group is a recorded version, named by uuid: never stated in the request (the audit's T4).
        (_body(groups=[_group()]), "field_malformed"),
        (_body(groups=["not-a-uuid"]), "field_malformed"),
        (_body(groups=[U1, U1]), "field_malformed"),
        (_body(groups=[U1]), "group_not_found"),
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


@pytest.mark.parametrize(
    "body, code",
    [
        (_group(group="Bad Key"), "group_malformed"),
        (_group(strength="0"), "group_malformed"),
        (_group(strength="10.5"), "group_malformed"),
        # A floor (review round 1, LOW-2): below it, and where its float is subnormal or zero.
        (_group(strength="0.0000009"), "group_malformed"),
        (_group(strength="0." + "0" * 320 + "1"), "group_malformed"),
        (_group(strength="0." + "0" * 400 + "1"), "group_malformed"),
        (_group(strength="1e-3"), "group_malformed"),
        (_group(source_type="A_GUESS"), "group_malformed"),
        (_group(strength=1), "group_malformed"),
        # A group of one correlates with nothing (review round 1, LOW-4).
        (_group(scenarios=[U1]), "group_too_small"),
        (_group(), "scenario_not_found"),
        ({**_group(), "author": "someone-else"}, "field_unrecognised"),
        ({"group": "g"}, "field_missing"),
    ],
)
def test_a_group_body_is_read_exactly(deployment, people, body, code):
    made_and_simulated(deployment, people["analyst"])
    response = _post_group(_client(people["analyst"]), deployment, body)
    assert response.status_code == 400, response.content
    assert response.json()["code"] == code
    assert not CorrelationGroup.objects.exists()


def test_a_correlation_group_is_an_authored_versioned_record(deployment, people):
    """The section-28 audit's T4: a group is recorded by an admin or analyst, with
    its author and time, append-only; the same group again is the version already
    recorded (200); a changed one is the next version (201), never an edit. A
    viewer reads the versions and never records one."""
    a, _ = made_and_simulated(deployment, people["analyst"], title="A")
    b, _ = made_and_simulated(deployment, people["analyst"], title="B")
    analyst, owner = _client(people["analyst"]), _client(people["owner"])
    first = _post_group(analyst, deployment, _group_body([a, b], strength="0.50"))
    assert first.status_code == 201, first.content
    one = first.json()["group"]
    assert (one["group"], one["version"], one["strength"], one["author"]) == ("provider", 1, "0.5", "ann")
    assert one["scenarios"] == sorted([str(a.uuid), str(b.uuid)]) and one["recorded_at"]
    again = _post_group(analyst, deployment, _group_body([a, b], strength="0.5"))
    assert again.status_code == 200 and again.json()["group"] == one
    changed = _post_group(_client(people["admin"]), deployment, _group_body([a, b], strength="2"))
    assert changed.status_code == 201
    assert (changed.json()["group"]["version"], changed.json()["group"]["author"]) == (2, "ada")
    assert _post_group(owner, deployment, _group_body([a, b], strength="3")).status_code == 403
    listed = owner.get(_url(deployment) + "groups/")
    assert listed.status_code == 200
    assert [(g["group"], g["version"], g["author"]) for g in listed.json()["groups"]] == [
        ("provider", 1, "ann"), ("provider", 2, "ada")
    ]
    row = CorrelationGroup.objects.get(version=1)
    with pytest.raises(EconomicsRewriteRefused):
        row.save()
    with pytest.raises(EconomicsRewriteRefused):
        CorrelationGroup.objects.filter(pk=row.pk).update(strength="9")
    for changes, code in (
        ({"strength": "0.50"}, "group_record_malformed"),
        ({"strength": "11"}, "group_record_malformed"),
        ({"scenarios": [str(b.uuid), str(a.uuid)]}, "group_record_malformed"),
        ({"scenarios": sorted([str(a.uuid), U3])}, "cross_tenant_reference"),
        ({"source_type": "A_GUESS"}, "group_record_malformed"),
    ):
        fields = {"deployment": deployment, "key": "provider", "strength": "1", "source_type": "CUSTOMER_PROVIDED",
                  "evidence_ref": LABEL, "scenarios": sorted([str(a.uuid), str(b.uuid)]), **changes}
        with pytest.raises(EconomicsRefused) as refused:
            CorrelationGroup(**fields).save()
        assert refused.value.code == code, changes
    assert models_constants_agree()


def models_constants_agree():
    from assurance.economics import models as economics_models

    return (economics_models.GROUP_STRENGTH_MIN, economics_models.GROUP_STRENGTH_MAX) == (
        ep.STRENGTH_MIN, ep.STRENGTH_MAX
    ) and economics_models.GROUP_MAX_SCENARIOS == ep.MAX_SCENARIOS


def test_a_portfolio_records_the_group_versions_it_draws_with(deployment, people):
    """A portfolio names recorded group versions by uuid and records each with its
    author and time; one version of a key at most, and a scenario in one group at
    most. A group version changed past the append-only checks after the portfolio
    was totalled is caught when the report is read (``group_rows``)."""
    a, _ = made_and_simulated(deployment, people["analyst"], title="A")
    b, _ = made_and_simulated(deployment, people["analyst"], title="B")
    c, _ = made_and_simulated(deployment, people["analyst"], title="C")
    first = _grouped(deployment, people, [a, b])
    second = _grouped(deployment, people, [a, c])
    other = _grouped(deployment, people, [b, c], key="region")
    analyst = _client(people["analyst"])
    both_versions = _post(analyst, deployment, _body(groups=[first, second]))
    assert both_versions.status_code == 400 and both_versions.json()["code"] == "group_malformed"
    overlapping = _post(analyst, deployment, _body(groups=[second, other]))
    assert overlapping.status_code == 400 and overlapping.json()["code"] == "group_malformed"
    document = _totalled_report(deployment, people, groups=[first])
    (shown,) = document["groups"]
    stored = CorrelationGroup.objects.get(uuid=first)
    assert {k: shown[k] for k in stored.as_dict()} == stored.as_dict()
    assert (shown["uuid"], shown["version"], shown["author"]) == (first, 1, "ann")
    assert shown["applied_to"] == sorted([str(a.uuid), str(b.uuid)])
    CorrelationGroup._base_manager.filter(uuid=first).update(source_type="EXPERT_ESTIMATE")
    _unverified(_report_of(deployment, people), "group_rows")


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


def test_a_portfolio_at_capacity_is_refused_at_once_and_never_holds_a_stop(deployment, people, monkeypatch):
    """THE SAFETY RULE with the economics run cap (spec 32 and 33.9; the audit's S1):
    with the deployment's slot and the host's only slot held, the portfolio POST is
    answered at once, 503 ``economics_capacity`` with ``Retry-After``: nothing is drawn
    or recorded. A stranger is still 404 and a viewer 403 before any slot; the group
    route and the report take none; and the scan's Stop is answered 202 and saved
    meanwhile. Given back, the same POST totals (201)."""
    from assurance.economics import capacity
    from pentest.models import PentestScan

    monkeypatch.setenv("ATHENA_ECONOMICS_RUN_CAP", "1")
    monkeypatch.setenv("ATHENA_ECONOMICS_RUN_CAP_PER_TENANT", "1")
    made_and_simulated(deployment, people["analyst"])
    _totalled(deployment, people, seed=1)
    drawn = []
    real = portfolio.simulate_portfolio

    def counted(*args, **kwargs):
        drawn.append(args)
        return real(*args, **kwargs)

    monkeypatch.setattr(portfolio, "simulate_portfolio", counted)
    analyst = _client(people["analyst"])
    slots, why = capacity.acquire(str(deployment.uuid))
    assert slots is not None, why
    try:
        began = time.perf_counter()
        busy = _post(analyst, deployment)
        took = time.perf_counter() - began
        assert busy.status_code == 503, busy.content
        assert busy.json()["code"] == capacity.CODE and busy.json()["recorded"] is False
        assert busy["Retry-After"] == str(capacity.RETRY_AFTER_SECONDS) and took < 0.5, took
        other = Deployment.objects.create(name="another-tenant", owner=people["owner"])
        assert _post(analyst, other).json()["code"] == capacity.CODE  # the host's one slot is held
        assert _post(_client(people["other"]), deployment).status_code == 404
        assert _post(_client(people["owner"]), deployment).status_code == 403
        assert drawn == [] and PortfolioResult.objects.count() == 1
        reader = _client(people["owner"])
        assert reader.get(_url(deployment) + "groups/").status_code == 200
        assert _document(reader, deployment).status_code == 200
        # A stop never waits on a slot: the scan's Stop is answered and saved.
        scan = PentestScan.objects.create(user=people["analyst"], target_url="https://offline.invalid/",
                                          consent=True, status=PentestScan.STATUS_PENDING)
        stop = analyst.post(f"/api/pentest/scans/{scan.uuid}/stop/", {}, format="json")
        assert stop.status_code == 202 and stop.json()["stop_saved"] is True, stop.content
        scan.refresh_from_db()
        assert scan.stop_requested_at is not None
    finally:
        slots.release()
    assert _post(analyst, deployment).status_code == 201 and len(drawn) == 1
    assert PortfolioResult.objects.count() == 2


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
    assert "5 passed" in result.stdout, result.stdout[-2000:]


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
    assert [e.scenario for e in one.events] == ["s1", "s2"] and one.by == ("spine_effect",)
    assert one.links == ((0, 1),) and one.one_event and ep.counted_sets(one) == ((0,), (1,))


def test_the_window_joins_one_key_within_24_hours_inclusive_and_no_further():
    inside = [_ref("s1", spine={"x"}, at=(WHEN,)), _ref("s2", spine={"y"}, at=(WHEN + timedelta(hours=24),))]
    assert len(ep.shared_events(inside)) == 1 and ep.shared_events(inside)[0].by == ("window",)
    outside = [_ref("s1", spine={"x"}, at=(WHEN,)),
               _ref("s2", spine={"y"}, at=(WHEN + timedelta(hours=24, microseconds=1),))]
    assert ep.shared_events(outside) == ()
    other_asset = [_ref("s1", spine={"x"}, at=(WHEN,)), _ref("s2", spine={"y"}, at=(WHEN,), asset="b")]
    assert ep.shared_events(other_asset) == ()
    assert ep.WINDOW == builder.GROUPING_WINDOW


def test_each_scenario_is_a_set_and_the_order_never_matters():
    """Three scenarios' events of one SPINE effect, all linked: a year counts one
    scenario's loss of it, the largest that year, whatever their figures at base."""
    events = [_ref("s1", spine={"x"}, at=(WHEN,), base="100"), _ref("s2", spine={"x"}, at=(WHEN,), base="300"),
              _ref("s3", spine={"x"}, at=(WHEN,), base="200")]
    (one,) = ep.shared_events(events)
    assert one.one_event and ep.counted_sets(one) == ((0,), (1,), (2,))
    assert ep.shared_events(list(reversed(events))) == (one,)
    # A scenario's two events in it are one set: its loss of the event is their sum.
    (two,) = ep.shared_events([_ref("A", "a1", at=(WHEN,)), _ref("B", at=(WHEN + timedelta(hours=20),)),
                               _ref("A", "a2", at=(WHEN + timedelta(hours=40),))])
    assert [e.order for e in two.events] == [("A", "a1"), ("A", "a2"), ("B", "ev")]
    assert two.one_event and ep.counted_sets(two) == ((0, 1), (2,))
    assert ep.links_between(two.events[0], two.events[1]) == ()


def test_a_chain_is_counted_at_its_largest_set_of_events_no_two_linked():
    """A (day one), B (20 hours on) and C (40 hours on), of one key: A and C are each
    linked to B, not to each other. A year counts A's and C's together, or B's."""
    (one,) = ep.shared_events([_ref("A", at=(WHEN,)), _ref("B", at=(WHEN + timedelta(hours=20),)),
                               _ref("C", at=(WHEN + timedelta(hours=40),))])
    assert one.links == ((0, 1), (1, 2)) and not one.one_event and ep.counted_sets(one) == ((0, 2), (1,))
    long = ep.shared_events([_ref(f"s{i:02d}", at=(WHEN + timedelta(hours=20 * i),)) for i in range(20)])
    assert ep.counted_sets(long[0]) is None and len(ep.counted_sets(long[0], limit=10_000)) > ep.MAX_COUNTED_SETS


def test_an_event_of_hypothetical_effects_alone_is_linked_to_every_event_of_its_key():
    """Hypothetical events of one key are linked to each other, and each to every
    observed event of its key in another scenario; two observed events days apart
    are not linked to each other, so a year counts them together or one
    hypothetical one."""
    hypothetical = [_ref("h1", hypothetical=True, base="500"), _ref("h2", hypothetical=True, base="50")]
    (one,) = ep.shared_events(hypothetical)
    assert one.by == ("hypothetical",) and ep.counted_sets(one) == ((0,), (1,))
    observed = [_ref("o1", spine={"x"}, at=(WHEN,), base="1000"),
                _ref("o2", spine={"y"}, at=(WHEN + timedelta(days=5),), base="10")]
    (one,) = ep.shared_events(hypothetical + observed)
    assert [e.scenario for e in one.events] == ["h1", "h2", "o1", "o2"] and one.by == ("hypothetical",)
    assert one.links == ((0, 1), (0, 2), (0, 3), (1, 2), (1, 3)) and not one.one_event
    assert ep.counted_sets(one) == ((0,), (1,), (2, 3))
    # Another key, or no key at all, is never linked by it.
    assert ep.links_between(_ref("h1", hypothetical=True), _ref("o1", at=(WHEN,), asset="b")) == ()


def test_the_engine_refuses_links_that_are_not_the_rules(deployment, people):
    a = made(deployment, people["analyst"], title="A", spine=SPINE)
    b = made(deployment, people["analyst"], title="B", spine=SPINE)
    members = sorted((ep.Member(str(s.uuid), simulation_service.load_input(s), Decimal(1)) for s in (a, b)),
                     key=lambda m: m.scenario_id)
    (one,) = ep.shared_events([_ref(m.scenario_id, "ev-pay", spine={"x"}) for m in members])
    common = {"seed": 5, "draws": 1_000, "reporting_currency": "USD", "input_digest": "sha256:" + "0" * 64}
    for forged in (ep.Joined(one.events, one.by, ()), ep.Joined(one.events, ("window",), one.links),
                   ep.Joined(one.events[:1], one.by, ())):
        with pytest.raises(ep.PortfolioRefused) as refused:
            ep.run(members, shared=[forged], **common)
        assert refused.value.code == "shared_malformed"
    assert ep.run(members, shared=[one], **common).record["shared"][0]["sets"] == [[0], [1]]


# ======================================================================
# The specification
# ======================================================================


SPEC_PHRASES = (
    "## 33. Portfolio aggregation (Economic Exposure E5)",
    "`POST deployments/<uuid>/economics/portfolio/simulate/`",
    "`GET deployments/<uuid>/economics/portfolio/`",
    "`mythos.economics.portfolio/v1`",
    "`mythos.economics.portfolio-report/v1`",
    "`mythos.economics.group-driver/v1`",
    "`mythos.economics.portfolio-shared-events/v1`",
    "never by summing percentiles",
    "expected shortfall",
    "Copulas",
    "### 33.10 Decisions this step takes, which the owner may change",
)


def test_the_spec_states_the_portfolio():
    text = SPEC.read_text(encoding="utf-8")
    for phrase in SPEC_PHRASES:
        assert phrase in text, phrase
    for code in portfolio.EXCLUSIONS:
        assert f"`{code}`" in text, code
    for code in ep.REFUSALS:
        assert f"`{code}`" in text, code
