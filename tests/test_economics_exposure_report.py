"""Economic Exposure: a deployment's economic-exposure report, a document a customer can
be handed (owner decision 12; ``docs/economics/spec-v1.md``, section 38).

- ``GET deployments/<uuid>/economics/exposure-report/?output=html|pdf`` shows the most
  recent APPROVED scenario version's exposure, from its latest completed run whose stored
  rows verify; a draft figure, or one whose rows fail a check, is never shown, and with
  none the report says so;
- every gap is named, and a report with one reads ``AUDIT_INCOMPLETE``;
- every text is escaped, in the HTML and in the PDF;
- the route is deployment-scoped (another tenant's is 404), no stop, answered
  ``no-store``, and writes, signs and verifies nothing.

Every figure is SYNTHETIC / ILLUSTRATIVE.
"""

from __future__ import annotations

import ast
import html
import inspect
import re
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext
from mythos_core import exposure_receipt as core
from mythos_core.persona import lint
from rest_framework.test import APIClient

from assurance.economics import exposure_report, receipt_service, report, report_api, simulation_service
from assurance.economics.models import FinancialScenario, SimulationResult
from assurance.models import Deployment
from safety import stops
from tests.economics_review import approve_for_receipt
from tests.test_economics_read_routes import _receipted
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
# The spec and the README
# ======================================================================


@pytest.mark.parametrize("path, phrase", [
    ("docs/economics/spec-v1.md", "`deployment-economics-exposure-report`"),
    ("docs/economics/spec-v1.md", exposure_report.SELECTION_RULE),
    ("docs/economics/spec-v1.md", "never re-verified by the report"),
    ("README.md", "economics/exposure-report/"),
])
def test_the_spec_and_the_readme_state_the_report(path, phrase):
    assert phrase in " ".join((REPO / path).read_text(encoding="utf-8").split())
