"""Economic Exposure step 6, PR B: the scenario endpoints and the deterministic report
JSON (``docs/economics/spec-v1.md``, section 27).

- the report is deterministic: the same stored rows give the same bytes, a key order
  the stored JSON happens to have changes nothing, and it carries the digest of its
  own canonical bytes; it runs no simulation and reads no clock;
- money is shown at the currency's minor unit (JPY 0 places, KWD 3);
- a result graded Unknown still shows its figures, with the banner and its exclusion
  from every total; a refused run is served as its refusal, never as figures;
- the routes: tenancy, permissions, strict JSON, idempotent simulation, 503 while the
  engine or the currency table is unavailable; the scenario's document links its
  evidence by SPINE id and never copies it; a fault in the report never takes down a
  stop;
- the chart series: made on the run's own draws, the exceedance curve at fixed
  probabilities and a histogram whose counts sum to the draws;
- review round 1 (#158): every stored row is checked before it is served, a total
  fails closed, a seed of any length is a 400, a keyring failure names only its type,
  the tornado's money is at the minor unit, and one deadline bounds a request.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
import types
import uuid
from datetime import date
from decimal import Decimal
from pathlib import Path

import numpy as np
import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.contrib.auth import get_user_model
from mythos_core import exposure_receipt as core
from rest_framework.test import APIClient

from assurance.economics import (
    builder,
    charts_service,
    receipt_service,
    report,
    report_api,
    simulation_service,
    validity_service,
)
from assurance.economics.engine import charts as ch
from assurance.economics.engine import currency as currency_engine
from assurance.economics.engine import scenario_simulation as ss
from assurance.economics.models import (
    CausalEffect,
    CustomerParameterSet,
    EconomicsRefused,
    EconomicsRewriteRefused,
    EffectFinding,
    FinancialExposureReceipt,
    FinancialParameter,
    FinancialScenario,
    FinancialValidityCard,
    LossComponent,
    LossEvent,
    ScenarioBuild,
    SimulationCharts,
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
SET_KEY = "bank_prod_2026q4"
GAMMA = {"id": "gamma", "version": 1, "params": {"shape": "4", "scale": "25000"}}
POISSON = {"id": "poisson", "version": 1, "params": {"rate": "2"}}
FINGERPRINT = "ab" * 32
QUICK = "quick_10k"


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


def _parameter(scenario, name, unit, low, base=None, high=None, *, source="EXPERT_ESTIMATE", distribution=None,
               currency="USD"):
    base = low if base is None else base
    high = base if high is None else high
    return FinancialParameter.objects.create(
        scenario=scenario, name=name, unit=unit, source_type=source,
        currency=currency if unit.startswith("money") else "", low=low, base=base, high=high,
        evidence_ref=f"{LABEL}: made up", effective_date=date(2026, 9, 1), distribution=distribution,
    )


def stored(deployment, author, *, currency="USD", frequency=True, refused=False, unknown=False, policy=False,
           set_key=SET_KEY, reverse_components=False):
    """A scenario version as rows (as step 8's tests make one): one event of two
    components, a notification (an expert-ranged population at a customer's unit
    cost) and a customer's regulatory range stating a gamma; a benchmark frequency
    where asked; one hypothetical effect on an asset, enabled by one finding; the
    build record. ``refused``: the regulatory range states no distribution, which the
    run refuses. ``unknown``: the notification cites the population only, so it is an
    unknown component and the grade is Unknown. ``reverse_components``: the two
    components inserted in the other order. SYNTHETIC / ILLUSTRATIVE."""
    variables = {
        "notification_unit_cost": _entry("money_per_unit", "2.375", currency=currency),
        "notification_fixed_cost": _entry("money", "40000", currency=currency),
    }
    if policy:
        variables["insurance_deductible"] = _entry("money", "100000", currency=currency)
        variables["insurance_limit"] = _entry("money", "1000000", currency=currency)
        variables["insurance_waiting_period_hours"] = _entry("hours", "0")
    pset = CustomerParameterSet.record(deployment, set_key, {"variables": variables}, author=author)
    scenario = FinancialScenario.objects.create(
        deployment=deployment, title="Cross-customer exposure", author=author, system_fingerprint=FINGERPRINT
    )
    affected = _parameter(scenario, "exposure.affected_customers", "count", "20000", "50000", "120000")
    amount = _parameter(scenario, "exposure.regulatory_response_cost", "money", "0", "100000", "500000",
                        source="CUSTOMER_PROVIDED", distribution=None if refused else GAMMA, currency=currency)
    if frequency:
        _parameter(scenario, ss.FREQUENCY_PARAMETER, "count", "1", "2", "4", source="INDUSTRY_BENCHMARK",
                   distribution=POISSON)
    rows = {row.name: row for row in pset.parameter_rows()}
    event = LossEvent.objects.create(scenario=scenario, event_key="ev-exposure", currency=currency,
                                     trigger="cross_customer_disclosure", business_process="customer_service")
    cited = {"affected": str(affected.uuid)}
    if not unknown:
        cited.update(unit_cost=str(rows["notification_unit_cost"].uuid),
                     fixed_cost=str(rows["notification_fixed_cost"].uuid))
    components = [
        dict(loss_event=event, component_key="notification", family="notification",
             formula_id="per_affected_plus_fixed", formula_version=1, as_of=AS_OF, cited_parameters=cited),
        dict(loss_event=event, component_key="regulatory", family="regulatory_compliance", formula_id="lump_sum",
             formula_version=1, as_of=AS_OF, cited_parameters={"amount": str(amount.uuid)}),
    ]
    for fields in reversed(components) if reverse_components else components:
        LossComponent.objects.create(**fields)
    asset = Asset.objects.create(deployment=deployment, kind="agent", name="support-agent",
                                 identifier=f"agent://support-{uuid.uuid4().hex[:6]}")
    finding = Finding.objects.create(deployment=deployment, fingerprint=f"fp-{uuid.uuid4().hex[:8]}",
                                     finding_type="tenant_isolation_missing", title="tenant isolation",
                                     severity="high")
    effect = CausalEffect.objects.create(
        scenario=scenario, loss_event=event, effect_key="exposure", origin="hypothetical",
        effect_type="cross_customer_disclosure", asset=str(asset.uuid), business_process="customer_service",
        template_id="cross_customer_data_exposure", template_version=1,
        in_scope_of=[["cross_customer_data_exposure", 1]],
    )
    EffectFinding.objects.create(effect=effect, finding=str(finding.uuid), role="prerequisite")
    inputs = {"fixture": str(scenario.uuid), "label": LABEL}
    ScenarioBuild.objects.create(
        scenario=scenario, deployment=deployment, parameter_set=pset, build_digest=builder.build_digest(inputs),
        builder_version="test-fixture", grouping_version="test-fixture", pack="test-fixture", currency=currency,
        as_of=AS_OF, inputs=inputs,
    )
    return scenario


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


def _base(deployment, scenario):
    return f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario.uuid}/"


def _simulate(client, deployment, scenario, body=None, raw=False, **extra):
    body = {"seed": 7, "policy": QUICK} if body is None else body
    data = body if raw else json.dumps(body)
    return client.post(_base(deployment, scenario) + "simulate/", data=data, content_type="application/json", **extra)


def _report(client, deployment, scenario, simulation=None):
    query = "" if simulation is None else f"?simulation={simulation}"
    return client.get(_base(deployment, scenario) + "results/" + query)


def _simulated(deployment, people, **kwargs):
    scenario = stored(deployment, people["analyst"], **kwargs)
    response = _simulate(_client(people["analyst"]), deployment, scenario)
    assert response.status_code == 201, response.content
    return scenario, response.json()


def _canonical(document) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


# ======================================================================
# Determinism and the digest
# ======================================================================


def test_the_same_stored_rows_give_byte_identical_reports(deployment, people):
    scenario, _ = _simulated(deployment, people)
    reader = _client(people["owner"])
    first, second = _report(reader, deployment, scenario), _report(reader, deployment, scenario)
    assert first.status_code == second.status_code == 200, first.content
    assert first["Content-Type"] == "application/json"
    assert first.content == second.content
    body = first.json()
    # Canonical: the bytes are the canonical JSON of what they parse to.
    assert first.content == _canonical(body)
    # Built again from the rows, outside the route: the same bytes.
    result = SimulationResult.objects.get(scenario=scenario)
    assert report.canonical_bytes(report.build_report(result)) == first.content


def _reordered(value):
    """``value`` with every object's keys in reverse order: the same JSON, another order."""
    if isinstance(value, dict):
        return {key: _reordered(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [_reordered(item) for item in value]
    return value


def test_a_key_order_shuffle_of_the_stored_inputs_gives_the_same_bytes(deployment, people):
    """Every JSON the report reads -- the result's inputs, versions and record, the
    card and its analysis, the series, the build's inputs -- rewritten in reverse key
    order past the append-only checks (the base manager, section 10): the digests
    still hold, and the report's bytes are the same."""
    scenario, _ = _simulated(deployment, people)
    reader = _client(people["owner"])
    before = _report(reader, deployment, scenario).content
    result = SimulationResult.objects.get(scenario=scenario)
    card = FinancialValidityCard.objects.get(simulation=result)
    charts = SimulationCharts.objects.get(simulation=result)
    for model, row, fields in (
        (SimulationResult, result, ("inputs", "versions", "record", "summaries")),
        (FinancialValidityCard, card, ("card", "sensitivity")),
        (SimulationCharts, charts, ("charts",)),
    ):
        shuffled = {name: _reordered(getattr(row, name)) for name in fields}
        assert any(json.dumps(shuffled[name]) != json.dumps(getattr(row, name)) for name in fields)
        model._base_manager.filter(pk=row.pk).update(**shuffled)
    build = ScenarioBuild.objects.get(scenario=scenario)
    ScenarioBuild._base_manager.filter(pk=build.pk).update(inputs=_reordered(build.inputs))
    after = _report(reader, deployment, scenario).content
    assert after == before


def test_the_digest_recomputes_and_covers_every_byte(deployment, people):
    scenario, _ = _simulated(deployment, people)
    body = _report(_client(people["owner"]), deployment, scenario).json()
    without = {key: value for key, value in body.items() if key != "digest"}
    assert body["digest"] == "sha256:" + hashlib.sha256(_canonical(without)).hexdigest()
    assert report.verifies(body)
    tampered = json.loads(json.dumps(body))
    tampered["summary"]["lines"]["gross_cash"]["p50"] = "1"
    assert not report.verifies(tampered)


def test_the_report_runs_no_simulation_and_reads_no_clock(deployment, people, monkeypatch):
    """A report is composed from the stored rows: with the engine's run, the series
    and the analysis made unusable it is served, the same bytes; and every time in it
    is a stored one."""
    scenario, _ = _simulated(deployment, people)
    reader = _client(people["owner"])
    before = _report(reader, deployment, scenario).content

    def never(*args, **kwargs):
        raise AssertionError("the report ran the engine")

    for target, name in ((ss, "run"), (ss, "_sample"), (ch, "series"), (simulation_service, "simulate_scenario"),
                         (validity_service, "issue_card"), (charts_service, "issue_charts")):
        monkeypatch.setattr(target, name, never)
    assert _report(reader, deployment, scenario).content == before
    result = SimulationResult.objects.get(scenario=scenario)
    card = FinancialValidityCard.objects.get(simulation=result)
    stored_times = {result.started_at.isoformat(), result.finished_at.isoformat(), result.recorded_at.isoformat(),
                    card.issued_at.isoformat(), scenario.recorded_at.isoformat()}
    found = set(re.findall(r"\d{4}-\d{2}-\d{2}T[0-9:.]+\+00:00", before.decode("ascii")))
    assert found and found <= stored_times, found - stored_times


# ======================================================================
# What the report carries
# ======================================================================


def test_the_report_carries_identity_events_summary_charts_tornado_and_card(deployment, people):
    scenario, simulated = _simulated(deployment, people)
    body = _report(_client(people["owner"]), deployment, scenario).json()
    result = SimulationResult.objects.get(scenario=scenario)
    card = FinancialValidityCard.objects.get(simulation=result)
    # Identity and versions.
    assert body["schema"] == report.REPORT_SCHEMA
    assert body["scenario"]["uuid"] == str(scenario.uuid) and body["scenario"]["deployment"] == str(deployment.uuid)
    assert body["simulation"]["uuid"] == str(result.uuid) == simulated["simulation"]["uuid"]
    assert (body["simulation"]["seed"], body["simulation"]["draws"]) == ("7", 10_000)
    assert body["simulation"]["input_digest"] == result.input_digest
    assert body["simulation"]["result_digest"] == result.result_digest
    assert body["versions"] == result.versions and body["versions"]["numpy"]
    assert body["model"]["version"].startswith("mythos.economics:simulation-")
    assert body["model"]["build_digest"] == card.card["fields"]["model_version"]["build_digest"]
    snapshots = {s["snapshot_id"].split(":")[0] for s in body["source_snapshots"]["snapshots"]}
    assert snapshots == {"parameter-set", "scenario-build", "scenario-parameters"}
    # Loss events and components, low, base and high, and what each input reads.
    (event,) = body["loss_events"]
    notification = next(c for c in event["components"] if c["component_id"] == "notification")
    assert notification["reads"] == {"affected": "exposure.affected_customers", "fixed_cost": "notification_fixed_cost",
                                     "unit_cost": "notification_unit_cost"}
    # 20,000 x 2.375 + 40,000 = 87,500 at low; 50,000 x 2.375 + 40,000 = 158,750 at base.
    assert (notification["low"], notification["base"]) == ("87500.00", "158750.00")
    assert body["parameters"]["notification_unit_cost"]["read_by"] == ["ev-exposure/notification.unit_cost"]
    assert body["parameters"][ss.FREQUENCY_PARAMETER]["read_by"] == ["frequency"]
    # The summary: every figure with its band, and why one is not reported.
    gross = body["summary"]["lines"]["gross_cash"]
    for figure in report.FIGURES:
        assert gross[figure] is not None, figure
    assert set(gross["bands"]) == {"p10", "p50", "p90", "severe_plausible", "mean"}
    assert body["summary"]["basis"] == "annual_loss" and gross["not_reported"] == {}
    assert body["summary"]["lines"]["retained_cash"] == {
        "not_reported": "no insurance policy: the parameter-set version states no deductible and limit"}
    assert body["summary"]["per_occurrence"]["gross_cash"]["expected_annual_loss"] is None
    assert "one occurrence" in body["summary"]["per_occurrence"]["gross_cash"]["not_reported"]["expected_annual_loss"]
    # Chart-ready series.
    series = body["charts"]["lines"]["gross_cash"]
    assert [p["probability"] for p in series["exceedance"]] == [str(p) for p in ch.EXCEEDANCE_PROBABILITIES]
    assert all(p["loss"] is not None for p in series["exceedance"])  # 10,000 draws reach 1 in 1,000
    losses = [Decimal(p["loss"]) for p in series["exceedance"]]
    assert losses == sorted(losses)
    histogram = series["histogram"]
    assert len(histogram["bins"]) == ch.HISTOGRAM_BINS
    assert sum(b["count"] for b in histogram["bins"]) + histogram["above"]["count"] == 10_000 == histogram["draws"]
    # The tornado, the grade, the card and the receipt reference.
    tornado = body["sensitivity"]["tornado"]
    assert tornado[0]["name"] == ss.FREQUENCY_PARAMETER and tornado[0]["swing"]["high_outcome"].count(".") == 1
    assert body["grade"] == card.confidence_grade == body["validity_card"]["grade"]
    assert body["validity_card"]["digest"] == card.card_digest
    assert body["receipt"] == {"not_reported": "no Financial Exposure Receipt is recorded for this result"}
    assert body["limitations"] == list(report.LIMITATIONS) and body["unknowns"] == []


def test_a_receipt_asked_for_is_signed_and_referenced(deployment, people, monkeypatch):
    key = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ring = core.receipt_keyring([key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)],
                                other_roles={"engine-outcome": [other]})
    monkeypatch.setattr(receipt_service, "engine_keyring", lambda: ring)
    monkeypatch.setattr(receipt_service, "engine_signer", lambda document: core.sign_receipt(document, key))
    scenario = stored(deployment, people["analyst"])
    response = _simulate(_client(people["analyst"]), deployment, scenario, {"seed": 7, "policy": QUICK,
                                                                           "receipt": True})
    assert response.status_code == 201, response.content
    assert response.json()["receipt"]["issued"] is True, response.json()["receipt"]
    stored_receipt = FinancialExposureReceipt.objects.get()
    body = _report(_client(people["owner"]), deployment, scenario).json()
    assert body["receipt"]["receipt_id"] == stored_receipt.receipt_id
    assert body["receipt"]["document_digest"] == canonical_digest(stored_receipt.document)
    assert body["receipt"]["validity_card_digest"] == body["validity_card"]["digest"]
    assert body["receipt"]["verified"] is False  # a reference this report did not verify (round 1, NIT)
    # Without the engine's keyring nothing is signed or recorded, and the run stands.
    def no_engine():
        raise RuntimeError("no engine")

    monkeypatch.setattr(receipt_service, "engine_keyring", no_engine)
    other = stored(deployment, people["analyst"], set_key="q3")
    response = _simulate(_client(people["analyst"]), deployment, other, {"seed": 7, "policy": QUICK, "receipt": True})
    assert response.status_code == 201 and response.json()["receipt"]["code"] == "keyring_unavailable"
    assert FinancialExposureReceipt.objects.count() == 1


# ======================================================================
# Unknown, and a refusal
# ======================================================================


def test_an_unknown_scenario_shows_its_figures_with_the_banner_and_its_exclusion(deployment, people):
    """The owner-adopted default: a result graded Unknown (here, a cash component is
    unknown) still shows its figures, with the banner and excluded from every total."""
    scenario, simulated = _simulated(deployment, people, unknown=True)
    assert simulated["validity_card"]["grade"] == "Unknown"
    body = _report(_client(people["owner"]), deployment, scenario).json()
    assert body["status"] == "completed" and body["grade"] == "Unknown"
    assert body["banner"] == "Unknown: not for capital decisions" == report.UNKNOWN_BANNER
    assert body["excluded_from_totals"] is True
    assert body["summary"]["lines"]["gross_cash"]["p50"] is not None  # the figures are still shown
    assert body["unknowns"][0]["id"] == "ev-exposure/notification"
    assert report.may_be_totalled(body) is False
    graded, _ = _simulated(deployment, people, set_key="q3")
    graded_body = _report(_client(people["owner"]), deployment, graded).json()
    assert graded_body["grade"] in {"A", "B", "C", "D"}
    assert graded_body["banner"] is None and graded_body["excluded_from_totals"] is False
    assert report.may_be_totalled(graded_body) is True


def test_a_result_with_no_card_is_not_for_capital_decisions(deployment, people, monkeypatch):
    monkeypatch.setattr(validity_service, "issue_card",
                        lambda result, **_: validity_service.CardOutcome(None, False, "card_failed", "injected"))
    scenario, simulated = _simulated(deployment, people)
    assert simulated["validity_card"] == {"issued": False, "code": "card_failed", "detail": "injected"}
    body = _report(_client(people["owner"]), deployment, scenario).json()
    assert body["grade"] is None and body["banner"] == report.UNKNOWN_BANNER and body["excluded_from_totals"] is True
    assert "not graded" in body["banner_reason"]


def test_a_refused_run_is_served_as_its_refusal_never_as_figures(deployment, people):
    scenario, simulated = _simulated(deployment, people, refused=True)
    assert simulated["simulation"]["status"] == "refused"
    assert simulated["simulation"]["refusal"]["code"] == "no_admissible_distribution"
    body = _report(_client(people["owner"]), deployment, scenario).json()
    assert body["status"] == "refused"
    assert body["refusal"]["code"] == "no_admissible_distribution"
    assert body["banner"] == report.UNKNOWN_BANNER and body["excluded_from_totals"] is True
    assert body["summary"] == {"not_reported": "refused: no_admissible_distribution"}
    assert body["charts"] == {"not_reported": "a refused run has no figures to chart"}
    assert "not_reported" in body["sensitivity"]
    # No amount anywhere: every money field of every event and component is null.
    for event in body["loss_events"]:
        for line in ("gross_cash",):
            assert all(event[line][point] is None for point in ("low", "base", "high"))
        for component in event["components"]:
            assert all(component[point] is None for point in ("low", "base", "high"))
    assert body["unknowns"][-1]["kind"] == "refusal"
    assert report.may_be_totalled(body) is False


# ======================================================================
# Money at the minor unit
# ======================================================================


@pytest.mark.parametrize("currency, places", [("JPY", 0), ("KWD", 3), ("USD", 2)])
def test_money_is_shown_at_the_currencys_minor_unit(deployment, people, currency, places):
    scenario, _ = _simulated(deployment, people, currency=currency)
    body = _report(_client(people["owner"]), deployment, scenario).json()
    assert body["currency"] == {"code": currency, "minor_unit": places, "rounding": report.ROUNDING}
    result = SimulationResult.objects.get(scenario=scenario)
    amounts = []
    gross = body["summary"]["lines"]["gross_cash"]
    amounts += [gross[f] for f in report.FIGURES] + [a for band in gross["bands"].values() for a in band]
    for event in body["loss_events"]:
        for component in event["components"]:
            amounts += [component[point] for point in ("low", "base", "high")]
    series = body["charts"]["lines"]["gross_cash"]
    amounts += [p["loss"] for p in series["exceedance"]] + [b["upper"] for b in series["histogram"]["bins"]]
    amounts += [e["swing"]["high_outcome"] for e in body["sensitivity"]["tornado"] if e["swing"]]
    for amount in amounts:
        exponent = Decimal(amount).as_tuple().exponent
        assert exponent == -places, (amount, places)
    # Each is the stored figure, rounded half-even to the minor unit.
    stored_p50 = Decimal(result.record["scenario"]["gross_cash"]["p50"])
    quantum = Decimal(1).scaleb(-places)
    assert Decimal(gross["p50"]) == stored_p50.quantize(quantum, rounding="ROUND_HALF_EVEN")
    # The parameters' own figures are as recorded: a unit cost below the minor unit stays.
    assert body["parameters"]["notification_unit_cost"]["base"] == "2.375"


# ======================================================================
# The routes
# ======================================================================


def test_a_simulation_is_idempotent_and_its_policy_is_named(deployment, people):
    scenario = stored(deployment, people["analyst"])
    analyst = _client(people["analyst"])
    first = _simulate(analyst, deployment, scenario)
    again = _simulate(analyst, deployment, scenario, {"seed": "7", "policy": QUICK})
    assert (first.status_code, again.status_code) == (201, 200)
    assert again.json()["simulation"] == first.json()["simulation"]
    assert again.json()["validity_card"]["created"] is False and again.json()["charts"]["created"] is False
    assert first.json()["policy"] == {"name": QUICK, "draws": 10_000, "severe_percentile": "95"}
    assert SimulationResult.objects.count() == FinancialValidityCard.objects.count() == 1
    assert SimulationCharts.objects.count() == 1
    other_seed = _simulate(analyst, deployment, scenario, {"seed": 8, "policy": QUICK})
    assert other_seed.status_code == 201 and SimulationResult.objects.count() == 2
    # The latest result is reported unless one is named.
    latest = _report(_client(people["owner"]), deployment, scenario).json()
    assert latest["simulation"]["uuid"] == other_seed.json()["simulation"]["uuid"]
    named = _report(_client(people["owner"]), deployment, scenario, first.json()["simulation"]["uuid"]).json()
    assert named["simulation"]["uuid"] == first.json()["simulation"]["uuid"]
    assert first.json()["report"].endswith(f"results/?simulation={first.json()['simulation']['uuid']}")


def test_tenancy_and_permissions(deployment, other_deployment, people):
    scenario, simulated = _simulated(deployment, people)
    theirs = stored(other_deployment, people["admin"])
    owner, stranger, analyst = _client(people["owner"]), _client(people["other"]), _client(people["analyst"])
    # The owner (a viewer) reads, and never simulates.
    assert owner.get(_base(deployment, scenario)).status_code == 200
    assert _report(owner, deployment, scenario).status_code == 200
    assert _simulate(owner, deployment, scenario).status_code == 403
    # A deployment the caller cannot see is 404 on every route, as one that does not exist.
    for response in (
        stranger.get(_base(deployment, scenario)),
        _report(stranger, deployment, scenario),
        _simulate(stranger, deployment, scenario),
        _simulate(analyst, other_deployment, scenario),  # a scenario under another deployment's path
        analyst.get(_base(deployment, theirs)),  # another deployment's scenario under this path
        _report(analyst, deployment, theirs),
    ):
        assert response.status_code == 404, response.content
    # A result of another scenario named on this one is not found.
    mine_too = stored(deployment, people["analyst"], set_key="q3")
    assert _report(owner, deployment, mine_too, simulated["simulation"]["uuid"]).status_code == 404
    assert _report(owner, deployment, mine_too).status_code == 404  # simulated never
    # Signed out: 401 everywhere.
    nobody = _client()
    assert nobody.get(_base(deployment, scenario)).status_code == 401
    assert _report(nobody, deployment, scenario).status_code == 401
    assert _simulate(nobody, deployment, scenario).status_code == 401
    assert SimulationResult.objects.count() == 1


@pytest.mark.parametrize(
    "body, code",
    [
        ({}, "field_missing"),
        ({"seed": 7, "draws": 5000}, "field_unrecognised"),
        ({"seed": -1}, "seed_malformed"),
        ({"seed": 2**64}, "seed_malformed"),
        ({"seed": 7.0}, "seed_malformed"),
        ({"seed": True}, "seed_malformed"),
        ({"seed": "007"}, "seed_malformed"),
        ({"seed": "1" * 21}, "seed_malformed"),
        ({"seed": "1" * 4301}, "seed_malformed"),  # past Python's 4300-digit limit: never a 500 (round 1, LOW-1)
        ({"seed": 7, "policy": "standard_5"}, "policy_unrecognised"),
        ({"seed": 7, "receipt": "yes"}, "field_malformed"),
    ],
)
def test_a_simulate_body_is_read_exactly(deployment, people, body, code):
    scenario = stored(deployment, people["analyst"])
    response = _simulate(_client(people["analyst"]), deployment, scenario, body)
    assert response.status_code == 400, response.content
    assert response.json()["code"] == code
    assert not SimulationResult.objects.exists()


def test_a_simulate_body_is_strict_json_of_at_most_64_kib(deployment, people):
    from assurance.economics.api import MAX_BODY_BYTES

    scenario = stored(deployment, people["analyst"])
    analyst = _client(people["analyst"])
    padded = json.dumps({"seed": 7, "padding": "x" * MAX_BODY_BYTES})
    assert _simulate(analyst, deployment, scenario, padded, raw=True).status_code == 413
    declared = _simulate(analyst, deployment, scenario, CONTENT_LENGTH=str(MAX_BODY_BYTES + 1))
    assert declared.status_code == 413
    assert _simulate(analyst, deployment, scenario, '{"seed": 7, "seed": 8}', raw=True).status_code == 400
    form = analyst.post(_base(deployment, scenario) + "simulate/", {"seed": "7"}, format="multipart")
    assert form.status_code == 415
    assert not SimulationResult.objects.exists()
    for method in ("put", "patch", "delete"):
        assert getattr(analyst, method)(_base(deployment, scenario) + "results/").status_code == 405


def test_an_engine_that_will_not_import_is_503_and_records_nothing(deployment, people, monkeypatch):
    scenario = stored(deployment, people["analyst"])

    def broken():
        raise ImportError("numpy is unavailable")

    monkeypatch.setattr(simulation_service, "_engine", broken)
    response = _simulate(_client(people["analyst"]), deployment, scenario)
    assert response.status_code == 503 and response.json()["code"] == "engine_unavailable"
    assert not SimulationResult.objects.exists()


def test_without_the_currency_table_every_route_is_503(deployment, people, monkeypatch):
    scenario, _ = _simulated(deployment, people)

    def unavailable():
        raise currency_engine.CurrencyTableInvalid("injected: the table is not the one pinned")

    monkeypatch.setattr(currency_engine, "require_pinned", unavailable)
    analyst = _client(people["analyst"])
    assert _simulate(analyst, deployment, scenario, {"seed": 9, "policy": QUICK}).status_code == 503
    assert _report(analyst, deployment, scenario).status_code == 503
    assert analyst.get(_base(deployment, scenario)).status_code == 503
    assert SimulationResult.objects.count() == 1


def test_the_scenario_document_links_its_evidence_by_id_and_names_every_parameters_provenance(deployment, people):
    scenario, simulated = _simulated(deployment, people)
    response = _client(people["owner"]).get(_base(deployment, scenario))
    assert response.status_code == 200, response.content
    body = response.json()
    assert body["schema"] == report.SCENARIO_SCHEMA and body["scenario"]["uuid"] == str(scenario.uuid)
    by_name = {p["name"]: p for p in body["parameters"]}
    assert by_name["exposure.regulatory_response_cost"]["parent"] == {"scenario": str(scenario.uuid)}
    assert by_name["exposure.regulatory_response_cost"]["distribution"] == GAMMA
    assert by_name["exposure.regulatory_response_cost"]["read_by"] == ["ev-exposure/regulatory.amount"]
    assert by_name["notification_unit_cost"]["parent"] == {"parameter_set": {"set_key": SET_KEY, "version": 1}}
    assert by_name[ss.FREQUENCY_PARAMETER]["read_by"] == ["frequency"]
    assert body["frequency"] == ss.FREQUENCY_PARAMETER
    (result,) = body["validity"]["simulations"]
    assert result["uuid"] == simulated["simulation"]["uuid"] and result["grade"] == simulated["validity_card"]["grade"]
    evidence = body["evidence"]
    effect = CausalEffect.objects.get(scenario=scenario)
    link = EffectFinding.objects.get(effect=effect)
    assert evidence["spine"]["nodes"] == [effect.asset]
    assert evidence["findings"] == [{"finding": link.finding, "effect_key": "exposure", "role": "prerequisite"}]
    # Ids, never copies: no title, description or evidence document of a finding is here.
    text = json.dumps(evidence)
    assert "tenant isolation" not in text and "effect_evidence" not in text


# ======================================================================
# The chart series
# ======================================================================


def test_a_tail_the_draws_do_not_reach_is_not_reported():
    ordered = np.sort(np.arange(1_000, dtype=np.float64))
    points = {p["probability"]: p for p in ch.exceedance(ordered)}
    assert points["0.01"]["loss"] is not None and points["0.01"]["draws_beyond"] == 10
    for probability in ("0.005", "0.002", "0.001"):
        assert points[probability]["loss"] is None and "fewer than 10" in points[probability]["not_reported"]
    # The loss at p is the type 7 quantile at 1 - p: here 999 x 0.99 = 989.01.
    assert points["0.01"]["loss"] == "989.01"


def test_the_histogram_edges_are_whole_minor_units_and_its_counts_the_draws():
    ordered = np.sort(np.concatenate([np.zeros(500), np.linspace(1.0, 1_000_000.0, 9_500)]))
    histogram = ch.histogram(ordered, "KWD")
    assert Decimal(histogram["width"]).as_tuple().exponent >= -3
    assert all(Decimal(b["upper"]) - Decimal(b["lower"]) == Decimal(histogram["width"]) for b in histogram["bins"])
    assert sum(b["count"] for b in histogram["bins"]) + histogram["above"]["count"] == ordered.size
    assert histogram["bins"][0]["count"] >= 500  # the zeros are in the first bin
    zeros = ch.histogram(np.zeros(1_000), "JPY")
    assert zeros["width"] == "1" and zeros["bins"][0]["count"] == 1_000


def test_the_series_are_made_on_the_runs_own_draws_or_not_at_all(deployment, people):
    scenario = stored(deployment, people["analyst"])
    outcome = simulation_service.simulate_scenario(scenario, seed=3, draws=2_000)
    result = outcome.result
    made = charts_service.issue_charts(result)
    assert made.created and made.charts.charts["outcomes_sha256"] == result.record["outcomes_sha256"]
    assert charts_service.issue_charts(result).charts.pk == made.charts.pk
    # Another result whose stored outcomes digest does not reproduce: no series, nothing recorded.
    other = simulation_service.simulate_scenario(scenario, seed=4, draws=2_000).result
    record = {**other.record, "outcomes_sha256": "sha256:" + "0" * 64}
    SimulationResult._base_manager.filter(pk=other.pk).update(record=record)
    other.refresh_from_db()
    refused = charts_service.issue_charts(other)
    assert (refused.charts, refused.code) == (None, "result_not_reproduced")
    assert SimulationCharts.objects.count() == 1


def test_a_series_row_is_checked_and_append_only(deployment, people):
    scenario = stored(deployment, people["analyst"])
    result = simulation_service.simulate_scenario(scenario, seed=3, draws=2_000).result
    row = charts_service.issue_charts(result).charts
    with pytest.raises(EconomicsRewriteRefused):
        row.save()
    with pytest.raises(EconomicsRewriteRefused):
        SimulationCharts.objects.filter(pk=row.pk).update(schema="x")
    another_seed = {**row.charts, "seed": "8"}
    with_a_float = {**row.charts, "lines": {"gross_cash": {"draws": 2_000.5}}}
    for charts, digest in (
        (row.charts, "sha256:" + "0" * 64),  # a digest that is not the series'
        (another_seed, canonical_digest(another_seed)),  # another result's series
        (with_a_float, row.charts_digest),  # a float
    ):
        copy = SimulationCharts(deployment=deployment, scenario=scenario, simulation=result, schema=row.schema,
                                charts=charts, charts_digest=digest)
        with pytest.raises(EconomicsRefused) as refused:
            copy.save()
        assert refused.value.code == "charts_record_malformed"
    duplicate = SimulationCharts(deployment=deployment, scenario=scenario, simulation=result, schema=row.schema,
                                 charts=row.charts, charts_digest=row.charts_digest)
    with pytest.raises(EconomicsRefused) as refused:
        duplicate.save()
    assert refused.value.code == "duplicate_id"
    assert SimulationCharts.objects.count() == 1


# ======================================================================
# Safety
# ======================================================================


def test_a_report_fault_never_takes_down_a_stop():
    """SAFETY. A fresh pytest, under a plugin that makes the report raise at import,
    before Django loads, runs ``tests/economics_fault_cases.py``: Django loads, the
    scan's Stop is answered (202) and saved, ``deliver_owed_stops`` reaches its
    handler, ``manage.py check`` passes, and the parameter-set and builder routes are
    still served; only the scenario endpoints and the report are not."""
    env = dict(
        os.environ,
        DJANGO_SECRET_KEY=os.environ.get("DJANGO_SECRET_KEY", "ci-secret-key-not-used-outside-ci"),
        ECONOMICS_FAULT="report",
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-p", "tests.economics_broken_report",
         "-q", "tests/economics_fault_cases.py"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600, check=False,
    )
    assert result.returncode == 0, (result.stdout[-4000:], result.stderr[-2000:])
    assert "4 passed" in result.stdout, result.stdout[-2000:]


def test_removing_an_operator_never_writes_a_series(deployment, people):
    """A series has no account column: removing an operator (a stop) answers 204 and
    leaves it as it was; it goes with its deployment."""
    leaver = User.objects.create_user(username="leaver", password="x", role="analyst")
    scenario = stored(deployment, leaver)
    result = simulation_service.simulate_scenario(scenario, seed=3, draws=2_000).result
    row = charts_service.issue_charts(result).charts
    admin = _client(people["admin"])
    assert admin.delete(f"/api/accounts/users/{leaver.pk}/").status_code == 204
    assert SimulationCharts.objects.get(pk=row.pk).charts_digest == row.charts_digest
    deployment.delete()
    assert not SimulationCharts.objects.exists()


# ======================================================================
# Review round 1 (#158): the reviewer's repros, each a test
# ======================================================================


def _unverified(body, *failed):
    """``body`` serves its result as an integrity refusal naming ``failed``: first what
    a reader sees (the banner, the exclusion, no figure), then the reason."""
    assert body["banner"] == report.UNKNOWN_BANNER and body["excluded_from_totals"] is True, body["banner"]
    assert report.may_be_totalled(body) is False
    for event in body["loss_events"]:
        assert all(event["gross_cash"][point] is None for point in ("low", "base", "high"))
        for component in event["components"]:
            assert all(component[point] is None for point in ("low", "base", "high"))
    assert body["banner_reason"].startswith(f"{report.STORED_ROW_UNVERIFIED}: the stored rows fail {failed[0]}")
    for part in ("summary", "charts", "sensitivity"):
        assert body[part] == {"not_reported": body["banner_reason"]}, part
    assert body["refusal"]["code"] == report.STORED_ROW_UNVERIFIED
    assert body["integrity"]["verified"] is False and body["integrity"]["failed"] == list(failed), body["integrity"]
    assert body["unknowns"][-1]["id"] == report.STORED_ROW_UNVERIFIED
    assert report.verifies(body)


def test_an_edited_grade_column_is_never_served(deployment, people):
    """MEDIUM-1, the reviewer's repro: the Unknown card's grade COLUMN edited to A past
    the append-only checks. The column is outside the card's digest, so only the
    cross-check finds it: the grade is the card document's, the card counts as no
    card, and the result is served as a refusal with the banner; no total takes it."""
    scenario, _ = _simulated(deployment, people, unknown=True)
    card = FinancialValidityCard.objects.get()
    FinancialValidityCard._base_manager.filter(pk=card.pk).update(confidence_grade="A")
    body = _report(_client(people["owner"]), deployment, scenario).json()
    assert body["grade"] is None, body["grade"]
    _unverified(body, "card_grade")
    assert "counts as no card" in body["validity_card"]["not_reported"]
    document = _client(people["owner"]).get(_base(deployment, scenario)).json()
    (listed,) = document["validity"]["simulations"]
    assert listed["grade"] is None and listed["card_verified"] is False


def test_an_edited_record_is_never_served(deployment, people):
    """MEDIUM-1: the record's gross P50 edited to 1.00. The record no longer gives the
    result's digest: no figure of it is served."""
    scenario, _ = _simulated(deployment, people)
    result = SimulationResult.objects.get()
    record = json.loads(json.dumps(result.record))
    record["scenario"]["gross_cash"]["p50"] = "1.00"
    SimulationResult._base_manager.filter(pk=result.pk).update(record=record)
    response = _report(_client(people["owner"]), deployment, scenario)
    body = response.json()
    _unverified(body, "result_digest")
    assert body["simulation"]["basis"] is None and body["simulation"]["outcomes_sha256"] is None


def test_an_inflated_histogram_bin_is_never_served(deployment, people):
    """MEDIUM-1: one histogram bin's count raised by 12,345. The series no longer gives
    its digest."""
    scenario, _ = _simulated(deployment, people)
    row = SimulationCharts.objects.get()
    charts = json.loads(json.dumps(row.charts))
    charts["lines"]["gross_cash"]["histogram"]["bins"][0]["count"] += 12345
    SimulationCharts._base_manager.filter(pk=row.pk).update(charts=charts)
    _unverified(_report(_client(people["owner"]), deployment, scenario).json(), "charts_digest")


def test_a_series_moved_to_another_result_is_never_served(deployment, people):
    """MEDIUM-1: the second result's series removed and the first's pointed at it. The
    series is intact, but it names the first result's seed and draws: the second's
    report serves no series of another run."""
    scenario = stored(deployment, people["analyst"])
    analyst = _client(people["analyst"])
    first = _simulate(analyst, deployment, scenario, {"seed": 7, "policy": QUICK}).json()["simulation"]["uuid"]
    second = _simulate(analyst, deployment, scenario, {"seed": 8, "policy": QUICK}).json()["simulation"]["uuid"]
    r1, r2 = SimulationResult.objects.get(uuid=first), SimulationResult.objects.get(uuid=second)
    SimulationCharts._base_manager.filter(simulation=r2).delete()
    SimulationCharts._base_manager.filter(simulation=r1).update(simulation=r2)
    _unverified(_report(_client(people["owner"]), deployment, scenario, second).json(), "charts_result")


def test_every_check_holds_on_rows_as_recorded(deployment, people):
    """The checks pass on every row as it was recorded: graded, Unknown and refused."""
    for kwargs in ({}, {"unknown": True, "set_key": "q2"}, {"refused": True, "set_key": "q3"}):
        scenario, _ = _simulated(deployment, people, **kwargs)
        body = _report(_client(people["owner"]), deployment, scenario).json()
        assert body["integrity"] == {"verified": True, "checks": list(report.INTEGRITY_CHECKS), "failed": []}


def test_a_total_fails_closed(deployment, people):
    """LOW-4. ``may_be_totalled`` takes a report only where its digest holds, its rows
    verified, and its grade is A to D (an allow-list): the reviewer's Unknown report
    with ``excluded_from_totals`` set false and its digest stale is refused, and so is
    one re-digested with the grade left Unknown."""
    graded, _ = _simulated(deployment, people)
    body = _report(_client(people["owner"]), deployment, graded).json()
    assert report.may_be_totalled(body) is True
    stale = json.loads(json.dumps(body))
    stale["summary"]["lines"]["gross_cash"]["p50"] = "1"
    assert report.may_be_totalled(stale) is False
    unknown, _ = _simulated(deployment, people, unknown=True, set_key="q2")
    forged = _report(_client(people["owner"]), deployment, unknown).json()
    forged["excluded_from_totals"] = False
    assert report.may_be_totalled(forged) is False  # the digest is stale
    forged["digest"] = report.digest_of(forged)
    assert report.verifies(forged) and report.may_be_totalled(forged) is False  # Unknown is not on the list
    ungraded = json.loads(json.dumps(body))
    ungraded["grade"] = None
    ungraded["digest"] = report.digest_of(ungraded)
    assert report.verifies(ungraded) and report.may_be_totalled(ungraded) is False  # nor is no grade at all
    assert report.GRADES_FOR_TOTALS == frozenset({"A", "B", "C", "D"})


class _EngineDown(Exception):
    status = 502


def test_a_keyring_failure_names_only_its_type_and_status(deployment, people, monkeypatch):
    """LOW-2, the reviewer's repro: the engine's keyring fetch fails with its response
    body and host in the error's text. The reply names the error's type and status
    only, as the signer's path does."""
    def down():
        raise _EngineDown("Engine error 502: CANARY-ENGINE-BODY host=engine.internal")

    monkeypatch.setattr(receipt_service, "engine_keyring", down)
    scenario = stored(deployment, people["analyst"])
    response = _simulate(_client(people["analyst"]), deployment, scenario, {"seed": 7, "policy": QUICK,
                                                                           "receipt": True})
    assert response.status_code == 201, response.content
    assert response.json()["receipt"] == {"issued": False, "code": "keyring_unavailable",
                                          "detail": "_EngineDown (status 502)"}
    assert b"CANARY-ENGINE-BODY" not in response.content and b"engine.internal" not in response.content


def test_a_refused_result_fetches_no_keyring(deployment, people, monkeypatch):
    """NIT: a refused run has no figures to sign, so the engine's keyring is never
    fetched for it."""
    fetched = []
    monkeypatch.setattr(receipt_service, "engine_keyring", lambda: fetched.append(1))
    scenario = stored(deployment, people["analyst"], refused=True)
    response = _simulate(_client(people["analyst"]), deployment, scenario, {"seed": 7, "policy": QUICK,
                                                                           "receipt": True})
    assert response.status_code == 201, response.content
    assert response.json()["receipt"]["code"] == "result_not_completed" and fetched == []
    assert response.json()["source_snapshots"] == report.served_snapshots(scenario)


@pytest.mark.parametrize("currency, places", [("JPY", 0), ("KWD", 3)])
def test_the_tornados_money_is_at_the_minor_unit(deployment, people, currency, places):
    """LOW-3, the reviewer's repro: in a JPY report the regulatory cost's P10, P50 and
    P90 were "42887.939189583936" and the like. A money parameter's quantiles are now at
    the minor unit, half-even; a count's are as the analysis has them."""
    scenario, _ = _simulated(deployment, people, currency=currency)
    body = _report(_client(people["owner"]), deployment, scenario).json()
    card = FinancialValidityCard.objects.get()
    analysed = {entry["name"]: entry["swing"] for entry in card.sensitivity["ranked"] if entry["swing"]}
    tornado = {entry["name"]: entry["swing"] for entry in body["sensitivity"]["tornado"] if entry["swing"]}
    money = tornado["exposure.regulatory_response_cost"]
    quantum = Decimal(1).scaleb(-places)
    for point in ("p10", "p50", "p90"):
        assert Decimal(money[point]).as_tuple().exponent == -places, money
        held = Decimal(analysed["exposure.regulatory_response_cost"][point])
        assert Decimal(money[point]) == held.quantize(quantum, rounding="ROUND_HALF_EVEN")
    count = tornado["exposure.affected_customers"]
    assert count["p50"] == analysed["exposure.affected_customers"]["p50"]


def test_components_are_in_key_order_whatever_order_they_were_inserted_in(deployment, people):
    """NIT: the report orders an event's components by key; the order the rows were
    inserted in, which step 7b's inputs keep, never decides it."""
    for kwargs in ({}, {"reverse_components": True, "set_key": "q2"}):
        scenario, _ = _simulated(deployment, people, **kwargs)
        body = _report(_client(people["owner"]), deployment, scenario).json()
        (event,) = body["loss_events"]
        assert [c["component_id"] for c in event["components"]] == ["notification", "regulatory"], kwargs


def test_one_deadline_bounds_a_simulate_request(deployment, people, monkeypatch):
    """LOW-5. The run, the card's analysis and the series share ONE deadline of 120 s,
    each given what remains: a run that takes 100 s leaves the card 20 s, and a card
    that takes 30 more leaves the series nothing, so it is not started. The request is
    503 time_over_budget; what was not issued is recorded nowhere; the same request
    again returns the stored result and issues the series."""
    now = [0.0]
    budgets: dict[str, list] = {"run": [], "card": [], "charts": []}
    real_run, real_card, real_charts = (simulation_service.simulate_scenario, validity_service.issue_card,
                                        charts_service.issue_charts)

    def spy(name, real, takes):
        def call(*args, **kwargs):
            budgets[name].append(kwargs.get("time_budget"))
            now[0] += takes
            return real(*args, **kwargs)
        return call

    monkeypatch.setattr(report_api, "time", types.SimpleNamespace(monotonic=lambda: now[0]), raising=False)
    monkeypatch.setattr(simulation_service, "simulate_scenario", spy("run", real_run, 100.0))
    monkeypatch.setattr(validity_service, "issue_card", spy("card", real_card, 30.0))
    monkeypatch.setattr(charts_service, "issue_charts", spy("charts", real_charts, 0.0))
    scenario = stored(deployment, people["analyst"])
    analyst = _client(people["analyst"])
    response = _simulate(analyst, deployment, scenario)
    assert budgets["run"] == [120.0] and budgets["card"] == [20.0] and budgets["charts"] == [], budgets
    assert response.status_code == 503 and response.json()["code"] == "time_over_budget", response.content
    assert response.json()["charts"]["code"] == "time_over_budget"
    assert SimulationResult.objects.count() == 1 and FinancialValidityCard.objects.count() == 1
    assert not SimulationCharts.objects.exists()
    monkeypatch.setattr(simulation_service, "simulate_scenario", spy("run", real_run, 0.0))
    monkeypatch.setattr(validity_service, "issue_card", spy("card", real_card, 0.0))
    again = _simulate(analyst, deployment, scenario)
    assert again.status_code == 200, again.content
    assert again.json()["charts"]["issued"] is True and again.json()["charts"]["created"] is True
    assert SimulationResult.objects.count() == 1 and SimulationCharts.objects.count() == 1


# ======================================================================
# The spec
# ======================================================================


SPEC_PHRASES = (
    "## 27. The scenario endpoints and the report (MVP step 6)",
    "`mythos.economics.report/v1`",
    "`Unknown: not for capital decisions`",
    "`excluded_from_totals: true`",
    "byte-identical",
    "`charts_record_malformed`",
    "`policy_unrecognised`",
    "`0067_simulation_charts.py`",
    "`stored_row_unverified`",
    "ONE deadline",
    "fails closed",
    "verified: false",
)


def test_the_spec_states_the_report():
    text = SPEC.read_text(encoding="utf-8")
    for phrase in SPEC_PHRASES:
        assert phrase in text, phrase
