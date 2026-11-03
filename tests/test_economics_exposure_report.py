"""Economic Exposure: a deployment's economic-exposure report, a document a customer can
be handed (owner decision 12; ``docs/economics/spec-v1.md``, section 38).

- ``GET deployments/<uuid>/economics/exposure-report/?output=html|pdf`` shows the most
  recent APPROVED scenario version's exposure, from its latest completed run whose stored
  rows verify; a draft figure, or one whose rows fail a check, is never shown, and with
  none the report says so;
- every gap is named, and a report with one reads ``AUDIT_INCOMPLETE``;
- every text is escaped, in the HTML and in the PDF;
- the route is deployment-scoped (another tenant's is 404), no stop, answered
  ``no-store``, and writes, signs and verifies nothing;
- the deployment total is the latest portfolio's own figures, equal to what
  ``GET .../economics/portfolio/`` serves for the same deployment and never
  recomputed; a version the portfolio does not total is named with its reason and is
  not in the figures; one run the portfolio cannot vouch for, or a totalled version
  that is not approved, withholds the figures or makes the total read
  ``AUDIT_INCOMPLETE``; another deployment's portfolio is never read.

Every figure is SYNTHETIC / ILLUSTRATIVE.
"""

from __future__ import annotations

import ast
import html
import inspect
import json
import re
import sys
from decimal import Decimal
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext
from mythos_core import exposure_receipt as core
from mythos_core.persona import lint
from rest_framework.test import APIClient

from assurance.economics import (
    charts_service,
    exposure_report,
    portfolio,
    receipt_service,
    report,
    report_api,
    simulation_service,
    validity_service,
)
from assurance.economics.models import FinancialScenario, FinancialValidityCard, SimulationResult
from assurance.models import Deployment
from safety import stops
from tests.economics_review import approve_for_receipt
from tests.test_economics_portfolio import LARGE, made, simulated
from tests.test_economics_read_routes import _signing
from tests.test_economics_report import stored

pytestmark = pytest.mark.django_db
User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
HOSTILE = '<script>alert("x")</script> & <b>Co</b>'


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


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


def _url(deployment, query=""):
    return f"/api/assurance/deployments/{deployment.uuid}/economics/exposure-report/{query}"


def _version(deployment, author, *, approve, seed=7, set_key="exposure_a"):
    """A stored scenario version, run once (completed), approved where asked."""
    scenario = stored(deployment, author, set_key=set_key)
    result = simulation_service.simulate_scenario(scenario, seed=seed, draws=10_000).result
    assert result is not None and result.status == "completed"
    if approve:
        approve_for_receipt(scenario)
    return scenario, result


def _receipted(deployment, author, monkeypatch):
    """An approved version run, carded, charted and receipted through the services (a
    test keyring and signer). Not through the simulate route: that route takes a run
    slot, which a server without fcntl (Windows) cannot read, and answers 503."""
    _, signed = _signing(monkeypatch)
    scenario, result = _version(deployment, author, approve=True)
    assert validity_service.issue_card(result).card is not None
    assert charts_service.issue_charts(result).charts is not None
    issued = receipt_service.issue_receipt(result, keyring=receipt_service.engine_keyring())
    assert issued.receipt is not None, (issued.code, issued.detail)
    return scenario, issued.receipt, None, signed[-1]


def _eal(result) -> str:
    built = report.build_report(result)
    return f"USD {built['summary']['lines']['gross_cash']['expected_annual_loss']}"


def _page(client, deployment, query=""):
    response = client.get(_url(deployment, query))
    assert response.status_code == 200, response.content
    return response.content.decode("utf-8")


def _text(page: str) -> str:
    page = re.sub(r"<style>.*?</style>", " ", page)
    return " ".join(html.unescape(re.sub(r"<[^>]+>", " ", page)).split())


# ======================================================================
# The selection rule
# ======================================================================


def test_an_approved_version_is_shown_over_a_newer_draft(deployment, people):
    approved, approved_run = _version(deployment, people["analyst"], approve=True)
    draft, draft_run = _version(deployment, people["analyst"], approve=False, seed=8, set_key="exposure_b")
    assert _eal(approved_run) != _eal(draft_run)
    page = _page(_client(people["owner"]), deployment)
    assert _eal(approved_run) in page
    assert _eal(draft_run) not in page
    text = _text(page)
    assert f"{approved.uuid}; recorded" in text and "shown in this report" in text
    assert f"scenario version “{draft.title}” ({draft.uuid}) is not approved" in text
    assert "AUDIT_INCOMPLETE" in text


def test_the_most_recent_of_two_approved_versions_is_shown(deployment, people):
    _, older_run = _version(deployment, people["analyst"], approve=True)
    newer, newer_run = _version(deployment, people["analyst"], approve=True, seed=8, set_key="exposure_b")
    page = _page(_client(people["owner"]), deployment)
    assert _eal(newer_run) in page and _eal(older_run) not in page
    assert f"{newer.title} ({newer.uuid})" in _text(page)


def test_a_deployment_with_only_drafts_shows_no_figure(deployment, people):
    _, run = _version(deployment, people["analyst"], approve=False)
    client = _client(people["owner"])
    page = _page(client, deployment)
    assert _eal(run) not in page
    text = _text(page)
    assert exposure_report.NONE_SELECTED in text
    assert "Scenario shown none" in text and "AUDIT_INCOMPLETE" in text
    pdf = client.get(_url(deployment, "?output=pdf")).content
    assert pdf.startswith(b"%PDF") and _eal(run).encode() not in pdf


def test_an_integrity_failure_shows_no_figure_and_names_the_check(deployment, people):
    scenario, run = _version(deployment, people["analyst"], approve=True)
    figure = _eal(run)
    SimulationResult._base_manager.filter(pk=run.pk).update(result_digest="sha256:" + "0" * 64)
    page = _page(_client(people["owner"]), deployment)
    assert figure not in page
    text = _text(page)
    assert exposure_report.NONE_SELECTED in text
    assert f"({scenario.uuid}) is approved, but the stored rows of its latest completed run fail integrity checks: " \
           "result_digest" in text
    assert "integrity checks verified" not in text


def test_a_receipt_is_on_record_in_honest_words(deployment, people, monkeypatch):
    _, row, _, _ = _receipted(deployment, people["analyst"], monkeypatch)
    text = _text(_page(_client(people["owner"]), deployment))
    assert f"receipt on record ({row.receipt_id}" in text
    assert "integrity checks verified: " in text and ", none failed" in text
    assert "Its signature is not re-verified by this report" in text
    assert "signed and verified" not in text


def test_every_gap_is_named(deployment, people):
    """No policy (no net line), no remediation option, no receipt, no card: each named."""
    _version(deployment, people["analyst"], approve=True)
    text = _text(_page(_client(people["owner"]), deployment))
    gaps = text.partition("What is not measured")[2]
    assert "Net exposure (cash retained after insurance): not measured: no insurance policy" in gaps
    assert "Residual exposure after a remediation option: not measured: no remediation option is recorded" in gaps
    assert "Receipt: not measured: no Financial Exposure Receipt is recorded" in gaps
    assert report.UNKNOWN_BANNER in gaps
    assert "AUDIT_INCOMPLETE: " in text


# ======================================================================
# Escaping, access, headers, read-only
# ======================================================================


def test_every_text_is_escaped_in_the_html_and_the_pdf(deployment, people):
    scenario, _ = _version(deployment, people["analyst"], approve=True)
    FinancialScenario._base_manager.filter(pk=scenario.pk).update(title=HOSTILE)
    deployment.name = "<i>dep</i>"
    deployment.save()
    client = _client(people["owner"])
    page = _page(client, deployment)
    assert "<script" not in page and "<b>Co" not in page and "<i>dep" not in page
    assert html.escape(HOSTILE, quote=True) in page
    pdf = client.get(_url(deployment, "?output=pdf"))
    assert pdf.status_code == 200 and pdf.content.startswith(b"%PDF")
    # The title drawn as text, its angle brackets included, never read as markup.
    assert b"(<) Tj (script) Tj (>) Tj" in pdf.content


def test_another_tenant_and_strangers_get_nothing(deployment, people):
    _version(deployment, people["analyst"], approve=True)
    assert _client(people["other"]).get(_url(deployment)).status_code == 404
    assert _client(people["other"]).get(_url(deployment, "?output=pdf")).status_code == 404
    assert _client().get(_url(deployment)).status_code == 401
    assert _client(people["owner"]).post(_url(deployment)).status_code == 405
    assert _client(people["owner"]).get(_url(deployment, "?output=docx")).status_code == 400
    assert _client(people["owner"]).get(_url(deployment, "?inline=1")).status_code == 400
    assert _client(people["owner"]).get(_url(deployment, "?output=pdf&output=html")).status_code == 400


def test_the_headers_and_the_route_is_no_stop(deployment, people):
    client = _client(people["owner"])
    page = client.get(_url(deployment), HTTP_ACCEPT="application/pdf")
    assert page.status_code == 200
    assert page["Content-Type"] == "text/html; charset=utf-8"
    assert page["Cache-Control"] == "no-store" and page["X-Content-Type-Options"] == "nosniff"
    assert page["Content-Security-Policy"] == "default-src 'none'; style-src 'unsafe-inline'"
    pdf = client.get(_url(deployment, "?output=pdf"))
    assert pdf["Content-Type"] == "application/pdf" and pdf["Cache-Control"] == "no-store"
    assert pdf["Content-Disposition"] == f'attachment; filename="economic-exposure-{deployment.uuid}.pdf"'
    name = "deployment-economics-exposure-report"
    assert set(stops.NOT_STOPS[name]) == {"GET"}
    assert name not in stops.STOP_ROUTES and name not in stops.EXEMPT_ROUTES


def test_no_row_is_written_nothing_signed_and_the_same_rows_give_the_same_bytes(deployment, people, monkeypatch):
    _, row, _, _ = _receipted(deployment, people["analyst"], monkeypatch)

    def never(*args, **kwargs):
        raise AssertionError("the exposure report signs, verifies and asks no engine")

    for name in ("engine_signer", "engine_keyring", "verify_stored_receipt", "issue_receipt"):
        monkeypatch.setattr(receipt_service, name, never)
    monkeypatch.setattr(core, "sign_receipt", never)
    monkeypatch.setattr(core, "verify_receipt", never)
    client = _client(people["owner"])
    with CaptureQueriesContext(connection) as queries:
        first, second = client.get(_url(deployment)), client.get(_url(deployment))
        pdfs = [client.get(_url(deployment, "?output=pdf")) for _ in range(2)]
    assert first.content == second.content and pdfs[0].content == pdfs[1].content
    assert row.receipt_id in first.content.decode()
    writes = [q["sql"] for q in queries.captured_queries
              if q["sql"].lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE", "REPLACE"))]
    assert writes == []


#: What the report path never calls: a write, a run, a card, a series, a signature.
_NEVER = frozenset({
    "get_or_create", "update_or_create", "create", "bulk_create", "bulk_update", "save", "delete", "update",
    "issue_receipt", "issue_card", "issue_charts", "simulate_scenario", "sign_receipt", "verify_receipt",
    "engine_signer", "engine_keyring", "verify_stored_receipt", "record",
})


def test_the_report_path_never_writes_signs_or_runs():
    sources = [inspect.getsource(exposure_report), inspect.getsource(report_api.ExposureReportView)]
    for source in sources:
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute):
                assert node.attr not in _NEVER, node.attr
            if isinstance(node, ast.Name):
                assert node.id not in _NEVER, node.id
            if isinstance(node, ast.ImportFrom):
                names = {node.module or ""} | {alias.name for alias in node.names}
                assert not names & {"receipt_service", "simulation_service", "validity_service", "charts_service",
                                    "capacity", "builder"}, names


def test_the_report_text_meets_the_persona_lint(deployment, people, monkeypatch):
    """The charter's lexicon lint (``mythos_core.persona.lint``) on every word the report
    writes, with a figure shown and with none."""
    assert lint.lint(_text(_page(_client(people["owner"]), deployment))).ok
    _receipted(deployment, people["analyst"], monkeypatch)
    result = lint.lint(_text(_page(_client(people["owner"]), deployment)))
    assert result.ok, result.violations


# ======================================================================
# The deployment total: the portfolio's own figures, never recomputed
# ======================================================================


def _member(deployment, author, title, **kwargs):
    """An approved scenario version that a portfolio may total (annual, graded), run
    once and carded through the services, never the simulate route (a run slot)."""
    scenario = made(deployment, author, title=title, **kwargs)
    approve_for_receipt(scenario)
    return scenario, simulated(scenario)


def _totalled(deployment):
    """The deployment's portfolio, totalled through the service (the simulate route
    takes a run slot, which a server without fcntl cannot read)."""
    wanted = portfolio.parse_request(
        {"seed": 2026, "policy": "quick_10k", "reporting_currency": "USD", "valuation_date": "2026-10-06"},
        policies=report_api.SIMULATION_POLICIES, parse_seed=report_api.parse_simulate,
    )
    outcome = portfolio.simulate_portfolio(deployment, wanted)
    assert outcome.result is not None, (outcome.code, outcome.detail)
    return outcome.result


def _portfolio_api(client, deployment) -> dict:
    response = client.get(f"/api/assurance/deployments/{deployment.uuid}/economics/portfolio/")
    assert response.status_code == 200, response.content
    return json.loads(response.content)


def _total_rows(deployment) -> list[tuple[str, str]]:
    return dict(exposure_report.document(deployment)["sections"])[exposure_report.TOTAL_HEADING]


def _row(rows, label) -> str:
    (value,) = [value for name, value in rows if name == label]
    return value


def _api_totals(served: dict) -> dict[str, str]:
    """Every figure the portfolio's route serves for each line, as the report labels it."""
    severe = served["summary"]["severe_percentile"]
    figures = {}
    for line, block in served["summary"]["lines"].items():
        for key, figure in exposure_report.TOTAL_FIGURES:
            figure = f"{figure} (P{severe})" if key == "severe_plausible" else figure
            figures[f"{exposure_report.LINE_LABELS[line]}, total: {figure}"] = f"USD {block[key]}"
    return figures


def test_the_deployment_total_is_the_portfolios_own(deployment, people):
    """Two approved versions, totalled: the report's total is the portfolio route's,
    figure for figure (EAL, P10 to P90, severe, expected shortfall, both lines), in the
    document and on the page; never a sum of the scenarios' own figures."""
    _member(deployment, people["analyst"], "Payment agent")
    _member(deployment, people["analyst"], "Refund agent", amount=LARGE, rate="0.2")
    row = _totalled(deployment)
    client = _client(people["owner"])
    served = _portfolio_api(client, deployment)
    assert served["portfolio"]["uuid"] == str(row.uuid) and served["integrity"]["verified"] is True
    rows = _total_rows(deployment)
    expected = _api_totals(served)
    assert len(expected) == 2 * len(exposure_report.TOTAL_FIGURES)
    assert {label: value for label, value in rows if label in expected} == expected
    text = _text(_page(client, deployment))
    for label, value in expected.items():
        assert f"{label} {value}" in text
    # The portfolio's P90 is not the sum of the scenarios' own P90s (section 24).
    own = [m["own"]["gross_cash"]["p90"] for m in served["scenarios"]["included"]]
    summed = f"USD {sum(Decimal(v) for v in own)}"
    assert _row(rows, "Gross exposure (cash, before insurance), total: P90") != summed
    assert _row(rows, "Status of the total") == exposure_report.TOTAL_COMPLETE
    assert _row(rows, "Portfolio").startswith(f"{row.uuid}; recorded ")
    integrity = _row(rows, "Gross exposure (cash, before insurance), total: integrity")
    assert integrity.startswith("integrity checks verified: 5 checks of the portfolio's stored rows")
    assert integrity.endswith("; runs not verified: none") and "“Payment agent”" in integrity
    assert _row(rows, "Net exposure (cash retained after insurance), total: integrity") == integrity
    assert lint.lint(text).ok


def test_a_scenario_that_may_not_be_totalled_is_named_and_never_summed(deployment, people):
    """An Unknown version and one whose rows fail a check are named with the portfolio's
    reasons, neither is in the figures, and the total reads AUDIT_INCOMPLETE ("at
    least"), its integrity line naming the run it cannot vouch for."""
    _member(deployment, people["analyst"], "Payment agent")
    _member(deployment, people["analyst"], "Refund agent", amount=LARGE, rate="0.2")
    unknown, _ = _member(deployment, people["analyst"], "Unknown agent", unknown=True)
    tampered, tampered_run = _member(deployment, people["analyst"], "Tampered agent")
    FinancialValidityCard._base_manager.filter(simulation=tampered_run).update(confidence_grade="A")
    _totalled(deployment)
    client = _client(people["owner"])
    served = _portfolio_api(client, deployment)
    codes = {e["scenario"]: e["code"] for e in served["scenarios"]["excluded"]}
    assert codes == {str(unknown.uuid): "unknown", str(tampered.uuid): "unverified"}
    rows = _total_rows(deployment)
    assert {label: value for label, value in rows if label in _api_totals(served)} == _api_totals(served)
    not_totalled = [value for label, value in rows if label == "Not totalled"]
    assert len(not_totalled) == 2
    assert any(v.startswith(f"“Unknown agent” ({unknown.uuid}): unknown: ") for v in not_totalled)
    assert any(v.startswith(f"“Tampered agent” ({tampered.uuid}): unverified: ") for v in not_totalled)
    assert _row(rows, "Status of the total").startswith("AUDIT_INCOMPLETE: 2 gaps")
    assert _row(rows, "Reads as").startswith("at least")
    integrity = _row(rows, "Gross exposure (cash, before insurance), total: integrity")
    assert f"runs not verified: “Tampered agent” ({tampered.uuid}; run {tampered_run.uuid})" in integrity
    text = _text(_page(client, deployment))
    gaps = text.partition("What is not measured")[2]
    assert f"Deployment total: not totalled: “Unknown agent” ({unknown.uuid}): unknown" in gaps
    assert f"Deployment total: not totalled: “Tampered agent” ({tampered.uuid}): unverified" in gaps


def test_one_unverified_run_makes_the_total_audit_incomplete_and_shows_no_figure(deployment, people):
    """A totalled run's card edited after the portfolio was totalled: the portfolio's
    re-check refuses it, so the report shows no total, names the run, and reads
    AUDIT_INCOMPLETE; never the figures it held before."""
    a, run_a = _member(deployment, people["analyst"], "Payment agent")
    _member(deployment, people["analyst"], "Refund agent", amount=LARGE, rate="0.2")
    _totalled(deployment)
    client = _client(people["owner"])
    before = _api_totals(_portfolio_api(client, deployment))
    FinancialValidityCard._base_manager.filter(simulation=run_a).update(confidence_grade="A")
    served = _portfolio_api(client, deployment)
    assert served["integrity"]["failed"] == ["member_rows"]
    rows = _total_rows(deployment)
    assert not {label for label, _ in rows} & set(before)
    assert _row(rows, "Totals") == "not shown: named under “What is not measured”"
    assert _row(rows, "Status of the total").startswith("AUDIT_INCOMPLETE: ")
    integrity = _row(rows, "Integrity")
    assert integrity.startswith("integrity checks failed: member_rows; runs verified: “Refund agent”")
    assert f"runs not verified: “Payment agent” ({a.uuid}; run {run_a.uuid}): its stored rows fail card_grade" \
        in integrity
    text = _text(_page(client, deployment))
    assert not any(f"{label} {value}" in text for label, value in before.items())
    assert f"Deployment total: {report.UNKNOWN_BANNER}: {report.STORED_ROW_UNVERIFIED}" in text


def test_a_total_of_a_version_that_is_not_approved_is_never_shown(deployment, people):
    """The portfolio totals current versions, approved or not: a total that holds a
    draft is withheld and the draft named, never shown or re-summed without it."""
    _member(deployment, people["analyst"], "Payment agent")
    draft = made(deployment, people["analyst"], title="Draft agent")
    simulated(draft)
    _totalled(deployment)
    served = _portfolio_api(_client(people["owner"]), deployment)
    assert str(draft.uuid) in {m["scenario"] for m in served["scenarios"]["included"]}
    rows = _total_rows(deployment)
    assert not {label for label, _ in rows} & set(_api_totals(served))
    text = _text(_page(_client(people["owner"]), deployment))
    assert (f"Deployment total: scenario version “Draft agent” ({draft.uuid}) is totalled, but it is not approved: "
            "no review is recorded") in text


def test_another_deployments_portfolio_is_never_this_ones_total(deployment, people):
    """Another tenant's portfolio, totalled after this one's, is never read: the total
    is this deployment's latest portfolio, of its own scenario versions."""
    _member(deployment, people["analyst"], "Payment agent")
    mine = _totalled(deployment)
    elsewhere = Deployment.objects.create(name="someone-elses", owner=people["other"])
    _member(elsewhere, people["analyst"], "Their agent", amount=LARGE)
    theirs = _totalled(elsewhere)
    assert theirs.pk > mine.pk
    served = _portfolio_api(_client(people["owner"]), deployment)
    rows = _total_rows(deployment)
    assert _row(rows, "Portfolio").startswith(f"{mine.uuid};")
    assert {label: value for label, value in rows if label in _api_totals(served)} == _api_totals(served)
    text = _text(_page(_client(people["owner"]), deployment))
    assert "Their agent" not in text and str(theirs.uuid) not in text
    assert _row(rows, "Status of the total") == exposure_report.TOTAL_COMPLETE


def test_a_version_recorded_after_the_portfolio_is_named_and_no_portfolio_is_a_gap(deployment, people):
    text = _text(_page(_client(people["owner"]), deployment))
    assert f"Deployment total: not measured: {exposure_report.NO_PORTFOLIO}" in text
    assert "AUDIT_INCOMPLETE" in text
    _member(deployment, people["analyst"], "Payment agent")
    _totalled(deployment)
    later = made(deployment, people["analyst"], title="Later agent")
    rows = _total_rows(deployment)
    assert _row(rows, "Status of the total").startswith("AUDIT_INCOMPLETE: 1 gaps")
    text = _text(_page(_client(people["owner"]), deployment))
    assert (f"Deployment total: scenario version “Later agent” ({later.uuid}) is named nowhere in the portfolio: it "
            "was recorded after the portfolio was totalled") in text


def test_a_portfolio_fault_leaves_the_total_unmeasured_and_the_report_served(deployment, people, monkeypatch):
    import assurance.economics as package

    _version(deployment, people["analyst"], approve=True)
    monkeypatch.delattr(package, "portfolio")
    monkeypatch.setitem(sys.modules, "assurance.economics.portfolio", None)
    text = _text(_page(_client(people["owner"]), deployment))
    assert "Deployment total: not measured: the portfolio could not be read (ModuleNotFoundError)" in text
    assert "Expected annual loss (EAL)" in text


def test_the_total_is_escaped_read_only_and_signs_nothing(deployment, people, monkeypatch):
    """A totalled version's title is the customer's own text: escaped in the HTML and
    the PDF. Reading the total writes no row and runs, signs or verifies nothing."""
    _member(deployment, people["analyst"], HOSTILE)
    _totalled(deployment)

    def never(*args, **kwargs):
        raise AssertionError("the exposure report signs, verifies, runs and asks no engine")

    for name in ("engine_signer", "engine_keyring", "verify_stored_receipt", "issue_receipt"):
        monkeypatch.setattr(receipt_service, name, never)
    monkeypatch.setattr(portfolio, "simulate_portfolio", never)
    monkeypatch.setattr(portfolio, "_engine", never)
    client = _client(people["owner"])
    with CaptureQueriesContext(connection) as queries:
        page = _page(client, deployment)
        pdf = client.get(_url(deployment, "?output=pdf"))
    writes = [q["sql"] for q in queries.captured_queries
              if q["sql"].lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE", "REPLACE"))]
    assert writes == []
    assert "<script" not in page and html.escape(HOSTILE, quote=True) in page
    assert "Gross exposure (cash, before insurance), total: P90" in _text(page)
    assert pdf.status_code == 200 and b"(<) Tj (script) Tj (>) Tj" in pdf.content


# ======================================================================
# The spec and the README
# ======================================================================


@pytest.mark.parametrize("path, phrase", [
    ("docs/economics/spec-v1.md", "`deployment-economics-exposure-report`"),
    ("docs/economics/spec-v1.md", exposure_report.SELECTION_RULE),
    ("docs/economics/spec-v1.md", "never re-verified by the report"),
    ("README.md", "economics/exposure-report/"),
    ("docs/economics/spec-v1.md", exposure_report.TOTAL_RULE),
    ("README.md", "the deployment total"),
])
def test_the_spec_and_the_readme_state_the_report(path, phrase):
    assert phrase in " ".join((REPO / path).read_text(encoding="utf-8").split())
