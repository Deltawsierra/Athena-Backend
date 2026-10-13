"""Economic Exposure step 13: one remediation option per scenario version, its
residual run and its economics (``docs/economics/spec-v1.md``, section 28).

- known answers on a fixed scenario: a frequency reduction of one half halves the
  expected annual loss within the Monte Carlo band; a magnitude reduction of a
  quarter cuts it by a quarter; a reduction of zero reduces exactly nothing, the
  residual run's summaries byte-identical to the current run's (common random
  numbers); a reduction of one on every family leaves nothing;
- the ROI and payback arithmetic, a zero investment and a reduction that is not
  above zero;
- the hard security veto: applies, does not apply, and unknown;
- the banner on an Unknown, refused, card-less or unverified run;
- the ROI document is deterministic and carries its own digest;
- tenancy and roles; an unverifiable retest citation is refused; an observed
  control effect stands on the retest gate's own verdict;
- no transaction is held while either run computes; a remediation fault never
  takes down a stop.

Every figure is SYNTHETIC / ILLUSTRATIVE.
"""

from __future__ import annotations

import copy
import json
import os
import subprocess
import sys
import uuid
from decimal import Decimal
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from rest_framework.test import APIClient

from assurance.economics import remediation_service, report, validity_service
from assurance.economics.engine import remediation as er
from assurance.economics.engine import scenario_simulation as ss
from assurance.economics.engine import sensitivity
from assurance.economics.models import (
    CausalEffect,
    EconomicsRefused,
    EconomicsRewriteRefused,
    EffectFinding,
    FinancialValidityCard,
    LossEvent,
    RemediationOption,
    SimulationResult,
    canonical_digest,
)
from assurance.models import ClaimEvidence, Deployment, Finding
from assurance.retest_closure import INCOMPLETE_REPAIR, INCOMPLETE_REPAIR_PATTERNS, record_closure_evidence
from tests.repair_contracts import agree, replay
from tests.test_economics_report import LABEL, QUICK, stored

pytestmark = pytest.mark.django_db
User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "docs" / "economics" / "spec-v1.md"
NINETY_FIVE = Decimal(95)

#: A retest that ran every fixture class and pattern with the outcome a closure needs.
COMPLETE = {
    "vulnerable": {"ran": True, "outcome": "failed"},
    "repaired": {"ran": True, "outcome": "passed"},
    "benign": {"ran": True, "outcome": "passed"},
    INCOMPLETE_REPAIR: {p: {"ran": True, "outcome": "failed"} for p in INCOMPLETE_REPAIR_PATTERNS},
}


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


# ------------------------------------------------------------ the option's body


def cost(base, *, low=None, high=None, currency="USD", source="CUSTOMER_PROVIDED"):
    return {"unit": "money", "low": low or base, "base": base, "high": high or base, "currency": currency,
            "source_type": source, "evidence_ref": f"{LABEL}: a vendor's quote", "effective_date": "2026-10-01"}


def ratio(low, base=None, high=None, *, source="EXPERT_ESTIMATE", **extra):
    base = low if base is None else base
    high = base if high is None else high
    return {"unit": "ratio", "low": low, "base": base, "high": high, "source_type": source,
            "evidence_ref": f"{LABEL}: the control owner's estimate", "effective_date": "2026-10-01", **extra}


def option_body(rf=None, rm=None, *, acts_on=None, observed_by=None, implementation="150000", recurring="50000",
                currency="USD", **extra):
    effect = {}
    if rf is not None:
        effect["frequency_reduction"] = rf if isinstance(rf, dict) else ratio(rf)
    if rm is not None:
        effect["magnitude_reduction"] = rm if isinstance(rm, dict) else ratio(rm)
    if acts_on is not None:
        effect["acts_on"] = acts_on
    if observed_by is not None:
        effect["observed_by"] = observed_by
    body = {
        "title": "Re-approve every changed destination",
        "implementation_cost": cost(implementation, currency=currency),
        "recurring_cost": cost(recurring, currency=currency),
        "time_to_implement_days": 30,
        "control_effect": effect,
    }
    body.update(extra)
    return body


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


def _base(deployment, scenario):
    return f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario.uuid}/"


def _post(client, url, body, raw=False, **extra):
    return client.post(url, data=body if raw else json.dumps(body), content_type="application/json", **extra)


def _mitigate(client, deployment, scenario, body, **extra):
    return _post(client, _base(deployment, scenario) + "mitigations/", body, **extra)


def _simulate(client, deployment, scenario, option, body=None):
    body = {"seed": 7, "policy": QUICK} if body is None else body
    return _post(client, _base(deployment, scenario) + f"mitigations/{option}/simulate/", body)


def _roi(client, deployment, scenario, simulation=None):
    query = "" if simulation is None else f"?simulation={simulation}"
    return client.get(_base(deployment, scenario) + "roi/" + query)


def _finding_of(scenario) -> Finding:
    link = EffectFinding.objects.get(effect__scenario=scenario)
    return Finding.objects.get(uuid=link.finding)


def _set_finding(scenario, **fields):
    Finding.objects.filter(pk=_finding_of(scenario).pk).update(**fields)


def proposed(deployment, people, body=None, *, severity="medium", **stored_kwargs):
    """A stored scenario (step 6's fixture), its finding at ``severity``, its option
    recorded and simulated through the routes; the ROI document read back."""
    scenario = stored(deployment, people["analyst"], **stored_kwargs)
    _set_finding(scenario, severity=severity)
    client = _client(people["analyst"])
    recorded = _mitigate(client, deployment, scenario, option_body("0.5") if body is None else body)
    assert recorded.status_code == 201, recorded.content
    option = recorded.json()["option"]["uuid"]
    simulated = _simulate(client, deployment, scenario, option)
    assert simulated.status_code in (200, 201), simulated.content
    read = _roi(_client(people["owner"]), deployment, scenario)
    assert read.status_code == 200, read.content
    return scenario, simulated.json(), read.json()


def _service_runs(deployment, people, body, *, draws=20_000, severity="medium", **stored_kwargs):
    """The option recorded and both runs made through the services, not the routes."""
    scenario = stored(deployment, people["analyst"], **stored_kwargs)
    _set_finding(scenario, severity=severity)
    option, created = remediation_service.record_option(scenario, body, author=people["analyst"])
    assert created
    runs = remediation_service.simulate_option(option, seed=11, draws=draws, severe_percentile=NINETY_FIVE,
                                               time_budget=120.0)
    assert runs.code is None, (runs.code, runs.detail)
    return scenario, option, runs.current.result, runs.residual.result


def _eal(result) -> Decimal:
    return Decimal(result.record["scenario"]["gross_cash"]["expected_annual_exposure"])


# ======================================================================
# Known answers on a fixed scenario
# ======================================================================


def test_a_frequency_reduction_of_one_half_halves_the_expected_annual_loss(deployment, people):
    """r_f = 0.5: each occurrence is stopped with probability one half, so the
    expected annual loss halves, within the Monte Carlo band (four of the residual
    run's standard errors, which bound the thinning's noise: the residual run draws
    every parameter from the current run's streams)."""
    _, _, current, residual = _service_runs(deployment, people, option_body("0.5"))
    gross = residual.record["scenario"]["gross_cash"]
    error = Decimal(gross["standard_error_of_mean"])
    assert abs(_eal(residual) - _eal(current) / 2) <= 4 * error, (_eal(residual), _eal(current), error)
    assert residual.record["remediation"]["changes_the_run"] is True
    assert residual.remediation_id is not None and current.remediation_id is None


def test_a_magnitude_reduction_of_a_quarter_cuts_it_by_a_quarter(deployment, people):
    """r_m = 0.25 on every family: each occurrence of every component is three
    quarters of the current run's, draw for draw, so the expected annual loss is
    three quarters of it to binary64's rounding, not only within the band."""
    _, _, current, residual = _service_runs(deployment, people, option_body(None, "0.25"))
    ratio_ = _eal(residual) / _eal(current)
    assert abs(ratio_ - Decimal("0.75")) < Decimal("1e-12"), ratio_
    for key in ("p50", "p90", "severe_plausible"):
        now = Decimal(current.record["scenario"]["gross_cash"][key])
        after = Decimal(residual.record["scenario"]["gross_cash"][key])
        assert abs(after - now * Decimal("0.75")) <= now * Decimal("1e-12"), key


def test_a_reduction_of_zero_reduces_exactly_nothing(deployment, people):
    """r = 0 on both: with common random numbers the residual run IS the current run,
    its summaries byte-identical, and the reduction exactly zero. A residual run that
    drew its parameters from other streams would differ here."""
    _, _, current, residual = _service_runs(deployment, people, option_body("0", "0"))
    assert current.input_digest != residual.input_digest
    assert json.dumps(residual.summaries, sort_keys=True) == json.dumps(current.summaries, sort_keys=True)
    assert residual.record["outcomes_sha256"] == current.record["outcomes_sha256"]
    roi = remediation_service.roi_document(current.scenario, residual)
    assert roi["figures"]["expected_reduction"] == "0.00"
    assert roi["figures"]["tail_reduction"]["p90"]["reduction"] == "0.00"
    assert roi["figures"]["tail_reduction"]["p95"]["reduction"] == "0.00"
    assert roi["figures"]["payback"]["value"] is None
    assert "not above zero" in roi["figures"]["payback"]["not_meaningful"]
    assert roi["figures"]["risk_adjusted_roi"]["value"] == "0.0000"


def test_a_reduction_of_one_on_every_family_leaves_nothing(deployment, people):
    _, _, current, residual = _service_runs(deployment, people, option_body("1", "1"))
    gross = residual.record["scenario"]["gross_cash"]
    assert _eal(residual) == 0
    assert gross["p90"] == gross["severe_plausible"] == "0"
    roi = remediation_service.roi_document(current.scenario, residual)
    assert roi["figures"]["residual_expected_annual_exposure"] == "0.00"
    expected = format(Decimal(current.record["scenario"]["gross_cash"]["expected_annual_exposure"]).quantize(
        Decimal("0.01")), "f")
    assert roi["figures"]["expected_reduction"] == expected


def test_a_component_the_option_does_not_act_on_is_the_current_runs_draw_for_draw(deployment, people):
    """acts_on names one family: the other component's summary is the current run's,
    byte for byte; the named one is reduced."""
    _, _, current, residual = _service_runs(
        deployment, people, option_body(None, "1", acts_on={"families": ["notification"]})
    )

    def components(result):
        return {c["component_id"]: c for c in result.record["events"][0]["components"]}

    now, after = components(current), components(residual)
    assert after["regulatory"] == now["regulatory"]
    assert after["notification"]["summary"]["mean"] == "0" and after["notification"]["remediated"] is True
    assert residual.record["remediation"]["reduced_components"] == ["ev-exposure/notification"]


def test_the_reductions_are_drawn_by_the_distribution_rule_from_their_own_streams(deployment, people):
    """An expert range is a PERT; a fixed figure a point mass; each reduction draws
    from a stream no parameter draws from."""
    body = option_body(ratio("0.3", "0.5", "0.7"), "0.2")
    _, _, _, residual = _service_runs(deployment, people, body)
    record = residual.record["remediation"]
    assert record["frequency_reduction"]["rule"] == ss.RULE_PERT_DEFAULT
    assert record["frequency_reduction"]["distribution"]["id"] == "pert"
    assert record["frequency_reduction"]["stream"] == ss.remediation_stream(ss.FREQUENCY_REDUCTION)
    assert record["magnitude_reduction"]["rule"] == ss.RULE_POINT_MASS
    assert record["magnitude_reduction"]["stream"] is None
    streams = {entry["stream"] for entry in residual.record["parameters"].values() if entry["stream"]}
    assert record["frequency_reduction"]["stream"] not in streams
    assert record["kept_stream"] not in streams


def test_a_frequency_reduction_needs_a_frequency(deployment, people):
    """A scenario that states no frequency is run per occurrence: the residual run of
    a frequency reduction is refused, and recorded so; the ROI is not computed."""
    scenario, simulated, roi = proposed(deployment, people, frequency=False)
    assert simulated["current"]["run"]["status"] == "completed"
    assert simulated["residual"]["run"]["refusal"]["code"] == "remediation_needs_frequency"
    assert roi["status"] == "not_computed" and roi["banner"] == report.UNKNOWN_BANNER
    assert "no ROI is computed on a refusal" in roi["figures"]["not_reported"]


def test_a_magnitude_reduction_without_a_frequency_has_no_annual_economics(deployment, people):
    scenario, simulated, roi = proposed(deployment, people, option_body(None, "0.25"), frequency=False)
    assert roi["status"] == "completed"
    figures = roi["figures"]
    assert figures["expected_reduction"] is None
    assert "no expected annual exposure" in figures["risk_adjusted_roi"]["not_meaningful"]
    assert "no expected annual exposure" in figures["payback"]["not_meaningful"]


# ======================================================================
# ROI and payback arithmetic (no database)
# ======================================================================


def _line(eal, p90="0", p95="0"):
    return er.Line(None if eal is None else Decimal(eal), Decimal(p90), None if p95 is None else Decimal(p95))


def _investment(implementation, recurring):
    return {point: Decimal(implementation) + Decimal(recurring) for point in ("low", "base", "high")}


def test_roi_and_payback_arithmetic():
    figures = er.economics(_line("1000000", "3000000", "4500000"), _line("400000", "1250000", "2000000.005"),
                           _investment("150000", "50000"), "USD", vetoed=False)
    assert figures["expected_reduction"] == "600000.00"
    assert figures["first_year_investment"] == {"low": "200000.00", "base": "200000.00", "high": "200000.00"}
    assert figures["risk_adjusted_roi"]["value"] == "3.0000"
    assert figures["payback"]["value"] == "0.33"
    assert figures["tail_reduction"]["p90"]["reduction"] == "1750000.00"
    # 2,499,999.995 is shown half-even at the cent: 2,500,000.00.
    assert figures["tail_reduction"]["p95"]["reduction"] == "2500000.00"
    assert "not a guaranteed return" in figures["risk_adjusted_roi"]["statement"]
    assert figures["risk_adjusted_roi"]["display_only"] is False
    # Half-even at the last place: a payback of 1/8 year is 0.12, an ROI of 1/8 is 0.1250.
    eighth = er.economics(_line("8"), _line("0"), _investment("1", "0"), "USD", vetoed=False)
    assert eighth["payback"]["value"] == "0.12" and eighth["risk_adjusted_roi"]["value"] == "8.0000"
    third = er.economics(_line("1"), _line("0"), _investment("3", "0"), "USD", vetoed=False)
    assert third["risk_adjusted_roi"]["value"] == "0.3333" and third["payback"]["value"] == "3.00"


def test_a_zero_investment_has_no_roi_and_pays_back_at_once():
    figures = er.economics(_line("500"), _line("100"), _investment("0", "0"), "USD", vetoed=False)
    assert figures["risk_adjusted_roi"]["value"] is None
    assert "investment is zero" in figures["risk_adjusted_roi"]["not_meaningful"]
    assert figures["payback"]["value"] == "0.00"


@pytest.mark.parametrize("residual", ["500", "600"])
def test_a_reduction_not_above_zero_has_no_payback(residual):
    """Never a negative or infinite payback: a reduction of zero, or below it."""
    figures = er.economics(_line("500"), _line(residual), _investment("1000", "0"), "USD", vetoed=False)
    assert figures["payback"]["value"] is None
    assert "no negative or infinite payback" in figures["payback"]["not_meaningful"]
    assert figures["risk_adjusted_roi"]["value"] in ("0.0000", "-0.1000")


def test_without_a_frequency_nothing_annual_is_meaningful():
    figures = er.economics(_line(None, "10", None), _line(None, "5", None), _investment("1", "1"), "USD", vetoed=False)
    assert figures["expected_reduction"] is None
    for key in ("risk_adjusted_roi", "payback"):
        assert figures[key]["value"] is None and "no expected annual exposure" in figures[key]["not_meaningful"]
    assert figures["tail_reduction"]["p95"]["reduction"] is None


@pytest.mark.parametrize("currency, shown", [("JPY", "600001"), ("KWD", "600000.500"), ("USD", "600000.50")])
def test_money_is_at_the_minor_unit_half_even(currency, shown):
    """600,000.5005 at the minor unit: 600001 yen; 600000.500 dinars, the tie going
    to the even digit (half-up would show .501); 600000.50 dollars."""
    figures = er.economics(_line("1000000.5005"), _line("400000"), _investment("1", "0"), currency, vetoed=False)
    assert figures["expected_reduction"] == shown


def test_a_vetoed_roi_is_display_only():
    figures = er.economics(_line("1000"), _line("10"), _investment("10", "0"), "USD", vetoed=True)
    assert figures["risk_adjusted_roi"]["display_only"] is True and figures["payback"]["display_only"] is True


def test_the_confidence_delta_compares_two_verified_grades():
    assert er.confidence_delta("C", "B")["change"] == "improved"
    assert er.confidence_delta("B", "B")["change"] == "unchanged"
    assert er.confidence_delta("A", "D")["change"] == "worsened"
    unknown = er.confidence_delta("B", "Unknown")
    assert unknown["change"] == "not_comparable" and "residual" in unknown["not_comparable"]
    assert er.confidence_delta(None, "A")["change"] == "not_comparable"
    assert er.lower_grade("A", "C") == "C" and er.lower_grade("B", "Unknown") == "Unknown"
    assert er.lower_grade(None, "A") is None


# ======================================================================
# The hard security veto
# ======================================================================


def test_the_veto_applies_to_a_finding_mythos_policy_blocks_release_on(deployment, people):
    """The scenario rests on an open HIGH finding, which places a deployment at
    needs_remediation: a hard release blocker. The ROI is display-only, and the
    document says remediation is required regardless of ROI."""
    _, _, roi = proposed(deployment, people, severity="high")
    veto = roi["veto"]
    assert veto["applies"] is True and veto["remediation_required"] is True
    assert veto["statement"] == er.VETO_STATEMENT == "remediation is required regardless of ROI"
    (blocker,) = veto["blockers"]
    assert blocker["kind"] == "finding" and blocker["places_the_deployment_at"] == "needs_remediation"
    assert roi["figures"]["risk_adjusted_roi"]["display_only"] is True
    assert roi["figures"]["payback"]["display_only"] is True
    # The figures are still shown -- display-only -- and nothing says accepting the
    # risk is preferable.
    assert roi["figures"]["risk_adjusted_roi"]["value"] is not None
    assert "accept" not in json.dumps(roi["figures"]).lower()


def test_a_critical_finding_places_it_at_not_recommended(deployment, people):
    _, _, roi = proposed(deployment, people, severity="critical")
    assert roi["veto"]["applies"] is True and roi["veto"]["statement"] == er.VETO_STATEMENT
    assert roi["veto"]["blockers"][0]["places_the_deployment_at"] == "not_recommended"


@pytest.mark.parametrize("fields", [{"severity": "medium"}, {"severity": "high", "status": "closed"},
                                    {"severity": "critical", "status": "accepted"}])
def test_the_veto_does_not_apply_where_no_blocker_stands(deployment, people, fields):
    """A medium finding places a deployment at ready_restricted; a closed or accepted
    one no longer counts against it (Mythos policy's resolved statuses)."""
    scenario = stored(deployment, people["analyst"])
    _set_finding(scenario, **fields)
    veto = remediation_service.veto(scenario)
    assert veto["applies"] is False and veto["statement"] is None and veto["remediation_required"] is False
    assert veto["blockers"] == [] and veto["unreadable"] == []


def test_the_veto_is_unknown_where_the_blocker_status_cannot_be_read_and_counts_as_applying(deployment, people):
    """An invalidated finding (its severity no longer trusted), a finding that is no
    longer the deployment's, an observed effect whose SPINE outcome cannot be found,
    and a fault reading SPINE: each is ``unknown``, which applies."""
    scenario, _, roi = proposed(deployment, people)
    assert roi["veto"]["applies"] is False
    _set_finding(scenario, status="invalidated")
    veto = remediation_service.veto(scenario)
    assert veto["applies"] == "unknown" and veto["statement"] == er.VETO_STATEMENT
    assert veto["remediation_required"] is True
    assert "can no longer be trusted" in veto["reason"]
    roi = _roi(_client(people["owner"]), deployment, scenario).json()
    assert roi["veto"]["applies"] == "unknown"
    assert roi["figures"]["risk_adjusted_roi"]["display_only"] is True

    _set_finding(scenario, status="open")
    effect = CausalEffect.objects.get(scenario=scenario)
    EffectFinding.objects.create(effect=effect, finding=str(uuid.uuid4()), role="amplifier")
    veto = remediation_service.veto(scenario)
    assert veto["applies"] == "unknown" and "not one of the deployment's findings" in veto["reason"]


def test_an_observed_effect_whose_outcome_cannot_be_read_is_unknown(deployment, people):
    scenario = stored(deployment, people["analyst"])
    _set_finding(scenario, severity="low")
    event = LossEvent.objects.get(scenario=scenario)
    CausalEffect.objects.create(
        scenario=scenario, loss_event=event, effect_key="observed-one", origin="observed",
        observed_effect=str(uuid.uuid4()), observation="sha256:" + "cd" * 32, effect_type="cross_customer_disclosure",
        asset=str(uuid.uuid4()), business_process="customer_service", template_id="cross_customer_data_exposure",
        template_version=1, in_scope_of=[["cross_customer_data_exposure", 1]],
    )
    veto = remediation_service.veto(scenario)
    assert veto["applies"] == "unknown" and veto["unreadable"][0]["kind"] == "effect"


def test_a_fault_reading_spine_is_unknown_never_raised(deployment, people, monkeypatch):
    scenario = stored(deployment, people["analyst"])

    def broken(*args, **kwargs):
        raise RuntimeError("the database went away")

    monkeypatch.setattr(remediation_service, "_linked_findings", broken)
    veto = remediation_service.veto(scenario)
    assert veto["applies"] == "unknown" and "RuntimeError" in veto["reason"]
    assert "went away" not in veto["reason"]


# ======================================================================
# The banner
# ======================================================================


def _bannered(roi, *, figures: bool):
    assert roi["banner"] == report.UNKNOWN_BANNER and roi["excluded_from_totals"] is True
    assert report.may_be_totalled(roi) is False
    assert report.verifies(roi)
    if not figures:
        assert roi["status"] == "not_computed" and "not_reported" in roi["figures"]


def test_a_clean_pair_carries_no_banner_and_may_be_totalled(deployment, people):
    _, _, roi = proposed(deployment, people)
    assert roi["banner"] is None and roi["excluded_from_totals"] is False and roi["banner_reason"] is None
    assert roi["grade"] in report.GRADES_FOR_TOTALS
    assert roi["integrity"] == {"verified": True, "checks": roi["integrity"]["checks"], "failed": []}
    assert report.may_be_totalled(roi) is True
    assert roi["confidence_delta"]["change"] == "unchanged"


def test_an_unknown_current_run_carries_the_banner(deployment, people):
    """The notification is an unknown component: the current card grades Unknown, and
    so does the residual's. The figures are shown, with the banner and the exclusion."""
    _, _, roi = proposed(deployment, people, unknown=True)
    _bannered(roi, figures=True)
    assert roi["banner_reason"].startswith("the current run: graded Unknown")
    assert roi["grade"] == "Unknown" and roi["confidence_delta"]["change"] == "not_comparable"


def test_a_refused_current_run_has_no_roi(deployment, people):
    """Both runs refused (a customer range with no distribution): no figure, no ROI
    computed on a refusal, the banner."""
    _, simulated, roi = proposed(deployment, people, refused=True)
    assert simulated["current"]["run"]["refusal"]["code"] == "no_admissible_distribution"
    _bannered(roi, figures=False)
    assert "no ROI is computed on a refusal" in roi["figures"]["not_reported"]


def test_a_residual_run_with_no_card_carries_the_banner(deployment, people, monkeypatch):
    real = validity_service.issue_card

    def no_card_for_the_residual(result, **kwargs):
        if result.remediation_id is not None:
            return validity_service.CardOutcome(None, False, "card_failed", "injected")
        return real(result, **kwargs)

    monkeypatch.setattr(validity_service, "issue_card", no_card_for_the_residual)
    _, simulated, roi = proposed(deployment, people)
    assert simulated["residual"]["validity_card"]["issued"] is False
    _bannered(roi, figures=True)
    assert roi["banner_reason"] == "the residual run: no Validity Card is recorded for this result: it is not graded"


def test_an_unverified_residual_run_shows_no_figure(deployment, people):
    """The residual run's record edited past the append-only checks: its digest no
    longer holds, so the ROI is served as an integrity refusal, with no figure."""
    scenario, _, roi = proposed(deployment, people)
    residual = SimulationResult.objects.get(scenario=scenario, remediation__isnull=False)
    record = copy.deepcopy(residual.record)
    record["scenario"]["gross_cash"]["expected_annual_exposure"] = "1"
    SimulationResult._base_manager.filter(pk=residual.pk).update(record=record)
    roi = _roi(_client(people["owner"]), deployment, scenario).json()
    _bannered(roi, figures=False)
    assert roi["banner_reason"].startswith(f"{report.STORED_ROW_UNVERIFIED}: the stored rows fail residual:")
    assert "residual:result_digest" in roi["integrity"]["failed"]


def test_an_edited_option_is_never_served_as_figures(deployment, people):
    scenario, _, _ = proposed(deployment, people)
    option = RemediationOption.objects.get(scenario=scenario)
    document = copy.deepcopy(option.document)
    document["implementation_cost"]["base"] = "1"
    RemediationOption._base_manager.filter(pk=option.pk).update(document=document)
    roi = _roi(_client(people["owner"]), deployment, scenario).json()
    _bannered(roi, figures=False)
    assert roi["integrity"]["failed"][0] == "option_digest"


# ======================================================================
# Determinism of the ROI document
# ======================================================================


def test_the_roi_document_is_deterministic_and_carries_its_digest(deployment, people):
    scenario, _, _ = proposed(deployment, people)
    reader = _client(people["owner"])
    first, second = _roi(reader, deployment, scenario), _roi(reader, deployment, scenario)
    assert first.status_code == second.status_code == 200
    assert first["Content-Type"] == "application/json"
    assert first.content == second.content
    body = first.json()
    assert first.content == json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    assert report.verifies(body) and body["digest"].startswith("sha256:")
    assert report.canonical_bytes(remediation_service.roi_document(scenario)) == first.content
    assert body["schema"] == er.ROI_SCHEMA
    assert body["limitations"] == list(remediation_service.ROI_LIMITATIONS)


def test_the_pair_is_bound_by_its_inputs(deployment, people):
    """The residual run's inputs are exactly the current run's with the option added:
    the current run's input digest is the digest of the residual's without it."""
    scenario, _, roi = proposed(deployment, people)
    residual = SimulationResult.objects.get(scenario=scenario, remediation__isnull=False)
    current = SimulationResult.objects.get(scenario=scenario, remediation__isnull=True)
    without = {key: value for key, value in residual.inputs.items() if key != "remediation"}
    assert canonical_digest(without) == current.input_digest
    assert roi["current"]["simulation"] == str(current.uuid) and roi["residual"]["simulation"] == str(residual.uuid)
    assert residual.inputs["remediation"]["option_digest"] == roi["option"]["digest"]


# ======================================================================
# The routes: tenancy, roles, strict JSON, idempotency
# ======================================================================


def test_tenancy_and_roles(deployment, other_deployment, people):
    scenario = stored(deployment, people["analyst"])
    body = option_body("0.5")
    assert _mitigate(_client(), deployment, scenario, body).status_code in (401, 403)
    assert _mitigate(_client(people["owner"]), deployment, scenario, body).status_code == 403
    assert _mitigate(_client(people["other"]), deployment, scenario, body).status_code == 404
    assert not RemediationOption.objects.exists()
    recorded = _mitigate(_client(people["admin"]), deployment, scenario, body)
    assert recorded.status_code == 201, recorded.content
    option = recorded.json()["option"]["uuid"]
    assert recorded.json()["option"]["author"] == "ada"
    # Another deployment's path never reaches this scenario or option.
    elsewhere = stored(other_deployment, people["analyst"])
    assert _mitigate(_client(people["admin"]), other_deployment, scenario, body).status_code == 404
    assert _simulate(_client(people["admin"]), other_deployment, scenario, option).status_code == 404
    assert _simulate(_client(people["admin"]), other_deployment, elsewhere, option).status_code == 404
    assert _simulate(_client(people["owner"]), deployment, scenario, option).status_code == 403
    assert _simulate(_client(people["other"]), deployment, scenario, option).status_code == 404
    assert _roi(_client(people["owner"]), deployment, scenario).status_code == 404  # nothing simulated yet
    assert _simulate(_client(people["analyst"]), deployment, scenario, option).status_code == 201
    assert _roi(_client(people["owner"]), deployment, scenario).status_code == 200
    assert _roi(_client(people["other"]), deployment, scenario).status_code == 404
    assert _roi(_client(people["admin"]), other_deployment, scenario).status_code == 404
    assert _roi(_client(), deployment, scenario).status_code in (401, 403)
    assert _client(people["admin"]).get(_base(deployment, scenario) + "mitigations/").status_code == 405


def test_an_option_is_recorded_once_and_its_runs_are_idempotent(deployment, people):
    scenario = stored(deployment, people["analyst"])
    client = _client(people["analyst"])
    first = _mitigate(client, deployment, scenario, option_body("0.5"))
    again = _mitigate(client, deployment, scenario, option_body("0.5"))
    assert (first.status_code, again.status_code) == (201, 200)
    assert first.json()["option"] == again.json()["option"]
    other = _mitigate(client, deployment, scenario, option_body("0.6"))
    assert other.status_code == 409 and other.json()["code"] == "remediation_option_held"
    option = first.json()["option"]["uuid"]
    made = _simulate(client, deployment, scenario, option)
    returned = _simulate(client, deployment, scenario, option)
    assert (made.status_code, returned.status_code) == (201, 200), returned.content
    assert made.json()["residual"]["run"]["uuid"] == returned.json()["residual"]["run"]["uuid"]
    assert SimulationResult.objects.filter(scenario=scenario).count() == 2
    assert FinancialValidityCard.objects.filter(scenario=scenario).count() == 2
    # The current run of the same seed and policy is step 6's: its simulate returns it.
    step6 = _post(client, _base(deployment, scenario) + "simulate/", {"seed": 7, "policy": QUICK})
    assert step6.status_code == 200 and step6.json()["simulation"]["uuid"] == made.json()["current"]["run"]["uuid"]


@pytest.mark.parametrize(
    "mutate, code",
    [
        (lambda b: b.update(control_effect={}), "control_effect_missing"),
        (lambda b: b.update(extra=1), "field_unrecognised"),
        (lambda b: b.pop("title"), "field_missing"),
        (lambda b: b.update(time_to_implement_days=-1), "field_malformed"),
        (lambda b: b["control_effect"].update(frequency_reduction=ratio("1.5")), "ratio_out_of_range"),
        (lambda b: b.update(recurring_cost=cost("1", currency="EUR")), "currency_mismatch"),
        (lambda b: b["control_effect"].update(acts_on={"families": ["no_such_family"]}), "acts_on_malformed"),
        (lambda b: b["control_effect"].update(acts_on={"components": ["ev-exposure/nothing"]}),
         "remediation_target_unknown"),
        (lambda b: b.update(dependencies=[{"kind": "finding", "id": str(uuid.uuid4())}]), "dependency_not_found"),
        (lambda b: b.update(dependencies=[{"kind": "text", "text": ""}]), "dependency_malformed"),
        (lambda b: b["control_effect"].update(frequency_reduction=ratio("0.4", "0.5", "0.6",
                                                                        source="CUSTOMER_PROVIDED")),
         "no_admissible_distribution"),
        (lambda b: b["control_effect"].update(frequency_reduction=ratio("0.5", source="MYTHOS_OBSERVED")),
         "observed_effect_uncited"),
        (lambda b: b.update(implementation_cost=cost("1", source="MYTHOS_OBSERVED")), "observed_source_not_observable"),
    ],
)
def test_an_option_is_read_exactly(deployment, people, mutate, code):
    scenario = stored(deployment, people["analyst"])
    body = option_body("0.5")
    mutate(body)
    response = _mitigate(_client(people["analyst"]), deployment, scenario, body)
    assert response.status_code == 400, response.content
    assert response.json()["code"] == code, response.json()
    assert not RemediationOption.objects.exists()


def test_a_cost_in_another_currency_than_the_scenario_is_refused(deployment, people):
    scenario = stored(deployment, people["analyst"])
    response = _mitigate(_client(people["analyst"]), deployment, scenario, option_body("0.5", currency="EUR"))
    assert response.status_code == 400 and response.json()["code"] == "currency_mismatch"


def test_a_body_is_strict_json_of_at_most_64_kib(deployment, people):
    scenario = stored(deployment, people["analyst"])
    client = _client(people["analyst"])
    twice = '{"title": "a", "title": "b"}'
    assert _mitigate(client, deployment, scenario, twice, raw=True).status_code == 400
    big = json.dumps(option_body("0.5", dependencies=[{"kind": "text", "text": "x" * 500}] * 200))
    assert _mitigate(client, deployment, scenario, big, raw=True).status_code in (400, 413)
    assert _mitigate(client, deployment, scenario, "{}", raw=True, CONTENT_LENGTH=str(65 * 1024)).status_code == 413
    form = client.post(_base(deployment, scenario) + "mitigations/", {"title": "a"})
    assert form.status_code == 415
    recorded = _mitigate(client, deployment, scenario, option_body("0.5")).json()["option"]["uuid"]
    receipt = _simulate(client, deployment, scenario, recorded, {"seed": 7, "receipt": True})
    assert receipt.status_code == 400 and receipt.json()["code"] == "field_unrecognised"
    seed = _simulate(client, deployment, scenario, recorded, {"seed": "1" * 4301})
    assert seed.status_code == 400 and seed.json()["code"] == "seed_malformed"
    assert not SimulationResult.objects.exists()


def test_without_the_currency_table_every_route_is_503(deployment, people, monkeypatch):
    from assurance.economics.engine import currency as currency_engine

    scenario, simulated, _ = proposed(deployment, people)

    def unavailable():
        raise currency_engine.CurrencyTableInvalid("injected")

    monkeypatch.setattr(currency_engine, "require_pinned", unavailable)
    monkeypatch.setattr(currency_engine, "minor_units", lambda code: unavailable())
    client = _client(people["analyst"])
    assert _mitigate(client, deployment, scenario, option_body("0.5")).status_code == 503
    assert _simulate(client, deployment, scenario, simulated["option"]).status_code == 503
    assert _roi(client, deployment, scenario).status_code == 503


def test_a_residual_run_is_never_served_as_the_scenarios_exposure(deployment, people):
    """The results route's latest result and the scenario document are the scenario's
    own runs; a residual run is the ROI route's."""
    scenario, simulated, _ = proposed(deployment, people)
    reader = _client(people["owner"])
    latest = reader.get(_base(deployment, scenario) + "results/").json()
    assert latest["simulation"]["uuid"] == simulated["current"]["run"]["uuid"]
    residual = simulated["residual"]["run"]["uuid"]
    assert reader.get(_base(deployment, scenario) + f"results/?simulation={residual}").status_code == 404
    document = reader.get(_base(deployment, scenario)).json()
    assert [r["uuid"] for r in document["validity"]["simulations"]] == [simulated["current"]["run"]["uuid"]]
    assert _roi(reader, deployment, scenario, simulated["current"]["run"]["uuid"]).status_code == 404
    assert _roi(reader, deployment, scenario, residual).status_code == 200
    # The events route's banner (#159) reads the scenario's own latest run too: the
    # residual run, recorded later, is not it -- even with its card's grade column
    # edited, which would put the banner on it.
    FinancialValidityCard._base_manager.filter(simulation__uuid=residual).update(confidence_grade="A")
    events = reader.get(_base(deployment, scenario) + "events/").json()
    assert events["banner"] is None and events["excluded_from_totals"] is False, events["banner_reason"]
    served = reader.get(_base(deployment, scenario) + "results/").json()
    assert {key: events[key] for key in ("grade", "banner", "excluded_from_totals", "banner_reason")} == {
        key: served[key] for key in ("grade", "banner", "excluded_from_totals", "banner_reason")
    }


# ======================================================================
# The observed control effect: a retest cited by its digest
# ======================================================================


def _retest(scenario, fixtures=None):
    """A retest of the finding the scenario rests on, recorded as the engine service
    records one, held to the finding's repair contract; and its citation digest."""
    finding = _finding_of(scenario)
    agree(finding)
    fixtures = copy.deepcopy(COMPLETE if fixtures is None else fixtures)
    record = record_closure_evidence(
        finding, fixtures=fixtures, origin=ClaimEvidence.Origin.INDEPENDENT, content_digest="sha256:" + "ef" * 32,
        document=replay(finding, fixtures),
    )
    return record, remediation_service.retest_digest(record, Finding.objects.get(pk=finding.pk))


def test_a_retest_that_shows_the_control_held_makes_the_control_effect_observed(deployment, people):
    scenario = stored(deployment, people["analyst"])
    _set_finding(scenario, severity="medium")
    record, digest = _retest(scenario)
    body = option_body(ratio("0.9", source="MYTHOS_OBSERVED"), observed_by=digest, utility_evidence=digest)
    client = _client(people["analyst"])
    recorded = _mitigate(client, deployment, scenario, body)
    assert recorded.status_code == 201, recorded.content
    option = recorded.json()["option"]["uuid"]
    assert _simulate(client, deployment, scenario, option).status_code == 201
    roi = _roi(client, deployment, scenario).json()
    observed = roi["option"]["control_effect"]["observed_by"]
    assert observed["verified"] is True and observed["record"] == str(record.uuid)
    assert roi["option"]["control_effect"]["frequency_reduction"]["source_type"] == "MYTHOS_OBSERVED"
    assert roi["utility_retained"]["status"] == "retained"
    assert roi["banner"] is None


def test_an_unverifiable_retest_citation_is_refused(deployment, people):
    scenario = stored(deployment, people["analyst"])
    body = option_body(ratio("0.9", source="MYTHOS_OBSERVED"), observed_by="sha256:" + "0" * 64)
    response = _mitigate(_client(people["analyst"]), deployment, scenario, body)
    assert response.status_code == 400 and response.json()["code"] == "retest_unverifiable"
    utility = option_body("0.5", utility_evidence="sha256:" + "1" * 64)
    response = _mitigate(_client(people["analyst"]), deployment, scenario, utility)
    assert response.status_code == 400 and response.json()["code"] == "retest_unverifiable"
    assert not RemediationOption.objects.exists()


def test_a_retest_of_another_deployments_finding_is_unverifiable(deployment, other_deployment, people):
    scenario = stored(deployment, people["analyst"])
    elsewhere = stored(other_deployment, people["analyst"])
    _, digest = _retest(elsewhere)
    body = option_body(ratio("0.9", source="MYTHOS_OBSERVED"), observed_by=digest)
    response = _mitigate(_client(people["analyst"]), deployment, scenario, body)
    assert response.status_code == 400 and response.json()["code"] == "retest_unverifiable"


def test_a_retest_that_does_not_show_the_control_held_is_refused(deployment, people):
    """A fooled retest -- an incomplete repair passed -- carries no closure by the
    gate's own verdict: no control effect is observed on it."""
    scenario = stored(deployment, people["analyst"])
    fooled = copy.deepcopy(COMPLETE)
    fooled[INCOMPLETE_REPAIR]["displaced_effects"] = {"ran": True, "outcome": "passed"}
    _, digest = _retest(scenario, fooled)
    body = option_body(ratio("0.9", source="MYTHOS_OBSERVED"), observed_by=digest)
    response = _mitigate(_client(people["analyst"]), deployment, scenario, body)
    assert response.status_code == 400 and response.json()["code"] == "retest_control_not_held"
    assert "displaced_effects" in response.json()["detail"]


def test_a_cited_retest_must_make_every_reduction_observed(deployment, people):
    scenario = stored(deployment, people["analyst"])
    _, digest = _retest(scenario)
    body = option_body("0.5", observed_by=digest)
    response = _mitigate(_client(people["analyst"]), deployment, scenario, body)
    assert response.status_code == 400 and response.json()["code"] == "observed_effect_not_stated"


def test_a_later_fooled_retest_unverifies_the_observed_effect(deployment, people):
    """The gate reads the latest retest: a fooled run recorded after the option
    leaves the observed effect unverified, and the ROI carries the banner."""
    scenario = stored(deployment, people["analyst"])
    _set_finding(scenario, severity="medium")
    _, digest = _retest(scenario)
    client = _client(people["analyst"])
    recorded = _mitigate(client, deployment, scenario,
                         option_body(ratio("0.9", source="MYTHOS_OBSERVED"), observed_by=digest)).json()
    assert _simulate(client, deployment, scenario, recorded["option"]["uuid"]).status_code == 201
    fooled = copy.deepcopy(COMPLETE)
    fooled[INCOMPLETE_REPAIR]["restored_persistence"] = {"ran": True, "outcome": "passed"}
    finding = _finding_of(scenario)
    record_closure_evidence(finding, fixtures=fooled, origin=ClaimEvidence.Origin.INDEPENDENT,
                            content_digest="sha256:" + "12" * 32, document=replay(finding, fooled))
    roi = _roi(client, deployment, scenario).json()
    assert roi["option"]["control_effect"]["observed_by"]["verified"] is False
    _bannered(roi, figures=True)
    assert roi["banner_reason"].startswith("the control effect's cited retest no longer shows the control held")


# ======================================================================
# The records
# ======================================================================


def test_an_option_row_is_checked_and_append_only(deployment, people):
    scenario = stored(deployment, people["analyst"])
    option, _ = remediation_service.record_option(scenario, option_body("0.5"), author=people["analyst"])
    with pytest.raises(EconomicsRewriteRefused):
        option.save()
    with pytest.raises(EconomicsRewriteRefused):
        RemediationOption.objects.filter(pk=option.pk).update(title="x")
    with pytest.raises(EconomicsRewriteRefused):
        option.delete()
    other = stored(deployment, people["analyst"])
    parsed = er.parse_option(option_body("0.5"))
    tampered = RemediationOption(
        deployment=deployment, scenario=other, title=parsed.title, document=dict(parsed.document),
        option_digest="sha256:" + "0" * 64, currency="USD", time_to_implement_days=30,
    )
    with pytest.raises(EconomicsRefused) as caught:
        tampered.check_new()
    assert caught.value.code == "remediation_record_malformed"
    second = RemediationOption(
        deployment=deployment, scenario=scenario, title=parsed.title, document=dict(parsed.document),
        option_digest=er.option_digest(str(scenario.uuid), parsed.document), currency="USD",
        time_to_implement_days=30,
    )
    with pytest.raises(EconomicsRefused) as caught:
        second.check_new()
    assert caught.value.code == "remediation_option_held"


def test_a_residual_run_names_its_own_option(deployment, people):
    """A run whose inputs name an option is residual, and names that option, of its
    own scenario version, in its column; any other run names none."""
    scenario, option, _, residual = _service_runs(deployment, people, option_body("0.5"), draws=2_000)
    other_scenario = stored(deployment, people["analyst"])
    other, _ = remediation_service.record_option(other_scenario, option_body("0.4"), author=people["analyst"])

    def row(remediation):
        return SimulationResult(
            deployment=deployment, scenario=scenario, seed="5", draws=2_000, severe_percentile="95",
            input_digest=residual.input_digest, result_digest="", status="refused", refusal_code="injected",
            refusal_detail="", inputs=residual.inputs, versions=residual.versions, summaries=None, record=None,
            started_at=residual.started_at, finished_at=residual.finished_at, duration_ms=1, remediation=remediation,
        )

    for wrong in (None, other):
        with pytest.raises(EconomicsRefused) as caught:
            row(wrong).check_new()
        assert caught.value.code == "result_malformed", wrong
    row(option).check_new()  # its own option: no refusal


def test_removing_the_author_never_writes_more_than_the_account_column(deployment, people):
    """The option names its author as a scenario does: removing that operator (a stop)
    answers 204, nulls the account and keeps the name; the option goes with its
    deployment."""
    leaver = User.objects.create_user(username="leaver", password="x", role="analyst")
    scenario = stored(deployment, people["analyst"])
    option, _ = remediation_service.record_option(scenario, option_body("0.5"), author=leaver)
    assert _client(people["admin"]).delete(f"/api/accounts/users/{leaver.pk}/").status_code == 204
    row = RemediationOption.objects.get(pk=option.pk)
    assert row.author_id is None and row.author_username == "leaver" and row.option_digest == option.option_digest
    deployment.delete()
    assert not RemediationOption.objects.exists()


# ======================================================================
# Safety
# ======================================================================


@pytest.mark.django_db(transaction=True)
def test_no_transaction_is_held_while_either_run_computes(monkeypatch):
    """``transaction=True`` IS THE TEST: under the ordinary fixture every test runs
    inside an atomic block, and the probe could not fail. Through the full request
    handler, the Monte Carlo of both runs and both cards' sensitivity analyses start
    outside any transaction (the probe #158's review used)."""
    people_ = {"analyst": User.objects.create_user(username="ann", password="x", role="analyst")}
    deployment = Deployment.objects.create(name="probe")
    scenario = stored(deployment, people_["analyst"])
    seen = []
    real_run, real_analyse = ss.run, sensitivity.analyse

    def run(*args, **kwargs):
        seen.append(("run", connection.in_atomic_block))
        return real_run(*args, **kwargs)

    def analyse(*args, **kwargs):
        seen.append(("analyse", connection.in_atomic_block))
        return real_analyse(*args, **kwargs)

    monkeypatch.setattr(ss, "run", run)
    monkeypatch.setattr(sensitivity, "analyse", analyse)
    client = _client(people_["analyst"])
    option = _mitigate(client, deployment, scenario, option_body("0.5")).json()["option"]["uuid"]
    assert _simulate(client, deployment, scenario, option).status_code == 201
    assert [stage for stage, _ in seen] == ["run", "analyse", "run", "analyse"], seen
    assert not any(held for _, held in seen), seen


def test_a_remediation_fault_never_takes_down_a_stop():
    """SAFETY. A fresh pytest, under a plugin that makes the remediation service raise
    at import before Django loads, runs ``tests/economics_fault_cases.py``: Django
    loads, the scan's Stop is answered (202) and saved, ``deliver_owed_stops`` reaches
    its handler, ``manage.py check`` passes, and every other economics route is still
    served; only the remediation option and ROI routes are not."""
    env = dict(
        os.environ,
        DJANGO_SECRET_KEY=os.environ.get("DJANGO_SECRET_KEY", "ci-secret-key-not-used-outside-ci"),
        ECONOMICS_FAULT="remediation",
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-p", "tests.economics_broken_remediation",
         "-q", "tests/economics_fault_cases.py"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600, check=False,
    )
    assert result.returncode == 0, (result.stdout[-4000:], result.stderr[-2000:])
    assert "4 passed" in result.stdout, result.stdout[-2000:]


def test_every_remediation_refusal_is_published_and_given():
    """Every code this step raises as its own is in ``engine.remediation.REFUSALS``,
    and every one published there is raised somewhere."""
    import ast

    raised = set()
    for path in (REPO / "assurance" / "economics" / "engine" / "remediation.py",
                 REPO / "assurance" / "economics" / "remediation_service.py"):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if (isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant)
                    and getattr(node.func, "attr", getattr(node.func, "id", "")) == "RemediationRefused"):
                raised.add(node.args[0].value)
            if (isinstance(node, ast.IfExp) and isinstance(node.body, ast.Constant)
                    and isinstance(node.orelse, ast.Constant) and str(node.body.value).startswith("retest_")):
                raised.update({node.body.value, node.orelse.value})
    raised.add("remediation_engine_unavailable")  # the route's 503, named from the table
    assert raised == set(er.REFUSALS), sorted(raised ^ set(er.REFUSALS))


SPEC_PHRASES = (
    "## 28. One remediation option, its residual run and its economics (MVP step 13)",
    "common random numbers",
    "remediation is required regardless of ROI",
    "`veto.applies` is `\"unknown\"`",
    "`excluded_from_totals: true`",
    "### 28.10 Decisions this step takes, which the owner may change",
    "No Bayesian update",
)


def test_the_spec_states_the_step():
    text = SPEC.read_text(encoding="utf-8")
    for phrase in SPEC_PHRASES:
        assert phrase in text, phrase
