"""The scan -> deployment economic-exposure selection is READ-ONLY and picks the
honest row (Economic Exposure, PART 2, the backend side of ``pentest.views``).

There is no primary-scenario marker, so ``pentest.economics_exposure`` takes the
honest fallback: for the scan's deployment, the most recently RECORDED scenario
version (``FinancialScenario.recorded_at``) whose LATEST review APPROVED it and that
has a verified, completed exposure run. A draft or unreviewed version, a version with
no completed result, and a version whose stored record fails its own integrity are
never shown; a deployment with none shows nothing.

The scan -> Deployment bridge is a ``.filter(...).first()`` read on the same key
``assurance.ingest.deployment_for_scan`` would ``get_or_create`` -- never that
side-effecting call -- so rendering a report creates no Deployment row.

The review/result/report reads (``review_status``, ``latest_exposure_run``,
``build_report``, ``latest_review``) are recon'd read-only -- they read stored rows
and hash them, run no engine and write nothing -- and are stubbed here so the
selection POLICY is tested over REAL ``FinancialScenario`` rows (its real
``recorded_at`` ordering) without standing up the Monte Carlo engine, its signing
keys and a full ``SimulationResult``.
"""
from __future__ import annotations

import ast
import pathlib
import types
from datetime import datetime, timedelta, timezone

import pytest

from assurance.models import Deployment
from pentest import economics_exposure as ee

pytestmark = pytest.mark.django_db

_BASE = datetime(2026, 10, 10, 12, 0, tzinfo=timezone.utc)


def _version(deployment, title, *, day):
    from assurance.economics.models import FinancialScenario

    return FinancialScenario.objects.create(
        deployment=deployment, title=title, recorded_at=_BASE + timedelta(days=day)
    )


def _doc(*, verified=True, with_receipt=True, eal="1250000.00"):
    """A report document in the shape ``assurance.economics.report.build_report``
    returns: currency, the gross-cash summary figures, the integrity status, and the
    receipt reference."""
    return {
        "currency": {"code": "USD"},
        "summary": {"lines": {"gross_cash": {
            "expected_annual_loss": eal,
            "p10": "240000.00",
            "p90": "5100000.00",
            "severe_plausible": "9800000.00",
        }}},
        "integrity": {"verified": verified, "checks": [], "failed": [] if verified else ["result_digest"]},
        "receipt": {"receipt_id": "rcpt-1"} if with_receipt else {"not_reported": "no receipt"},
    }


def _stub(monkeypatch, *, status_of=None, result_for=None, doc_for=None):
    """Stub the recon'd read-only review/result/report reads. ``status_of`` maps a
    scenario to its review status (default: approved when 'approved' is in the title);
    ``result_for`` maps a scenario to a completed-run sentinel or None (default: a
    completed sentinel for approved versions); ``doc_for`` maps a sentinel to a
    document (default: a verified document with a receipt)."""

    def _status(scenario):
        if status_of is not None:
            return {"status": status_of(scenario)}
        return {"status": "approved" if "approved" in scenario.title.lower() else "draft"}

    def _run(scenario):
        if result_for is not None:
            return result_for(scenario)
        return types.SimpleNamespace(status=ee.SIMULATION_COMPLETED, scenario_id=scenario.id)

    def _build(result):
        return doc_for(result) if doc_for is not None else _doc()

    monkeypatch.setattr(ee, "review_status", _status)
    monkeypatch.setattr(ee, "latest_review", lambda scenario_id: types.SimpleNamespace(reviewed_at=_BASE))
    monkeypatch.setattr(ee.econ_report, "latest_exposure_run", _run)
    monkeypatch.setattr(ee.econ_report, "build_report", _build)


# --- selection: the most recent APPROVED version with a verified result -------


def test_the_most_recent_approved_version_is_selected_over_an_older_one_and_a_newer_draft(monkeypatch):
    dep = Deployment.objects.create(name="dep-select")
    _version(dep, "Approved old", day=1)
    _version(dep, "Approved recent", day=2)
    _version(dep, "Draft newest", day=3)  # newer, but unreviewed -> skipped
    _stub(monkeypatch)

    exposure = ee._select_exposure(dep)
    assert exposure is not None
    assert exposure["title"] == "Approved recent"  # the most recent APPROVED version
    assert exposure["reviewed_at"] == "2026-10-10"
    assert exposure["verified"] is True
    assert exposure["receipt_verified"] is True
    assert {f["label"]: f["value"] for f in exposure["figures"]}["Expected annual loss"] == "USD 1250000.00"
    assert any("240000.00" in f["value"] and "5100000.00" in f["value"] for f in exposure["figures"])


def test_a_draft_only_deployment_shows_no_exposure(monkeypatch):
    dep = Deployment.objects.create(name="dep-draft-only")
    _version(dep, "Draft one", day=1)
    _version(dep, "Draft two", day=2)
    _stub(monkeypatch)
    assert ee._select_exposure(dep) is None  # never a draft figure


def test_an_approved_version_with_no_completed_result_is_not_shown(monkeypatch):
    dep = Deployment.objects.create(name="dep-no-result")
    _version(dep, "Approved no result", day=1)
    _stub(monkeypatch, result_for=lambda scenario: None)
    assert ee._select_exposure(dep) is None


def test_an_approved_version_whose_record_fails_integrity_is_not_shown(monkeypatch):
    dep = Deployment.objects.create(name="dep-unverified")
    _version(dep, "Approved but tampered", day=1)
    _stub(monkeypatch, doc_for=lambda result: _doc(verified=False))
    assert ee._select_exposure(dep) is None  # withheld figures are never shown


def test_the_receipt_line_is_not_available_without_a_recorded_receipt(monkeypatch):
    dep = Deployment.objects.create(name="dep-no-receipt")
    _version(dep, "Approved no receipt", day=1)
    _stub(monkeypatch, doc_for=lambda result: _doc(verified=True, with_receipt=False))
    exposure = ee._select_exposure(dep)
    assert exposure is not None
    assert exposure["verified"] is True
    assert exposure["receipt_verified"] is False  # integrity ok, but no signed receipt on record


def test_a_deployment_with_no_scenarios_shows_no_exposure():
    dep = Deployment.objects.create(name="dep-empty")
    assert ee._select_exposure(dep) is None


# --- the scan -> deployment bridge is read-only: it creates no Deployment ------


def test_a_scan_that_maps_to_no_deployment_creates_none():
    assert Deployment.objects.count() == 0
    scan = types.SimpleNamespace(
        engagement_id=None, target_url="https://nope.example/x", target_shown="nope.example"
    )
    assert ee._read_only_deployment(scan) is None
    assert ee.economics_context(scan) == {}  # default-safe: nothing to show
    assert Deployment.objects.count() == 0  # the report path created NO deployment row


def test_the_bridge_finds_the_existing_deployment_without_creating_one():
    host = "api.example.com"
    dep = Deployment.objects.create(name=f"target:{host}", engagement=None)
    scan = types.SimpleNamespace(
        engagement_id=None, target_url=f"https://{host}/login", target_shown=host
    )
    found = ee._read_only_deployment(scan)
    assert found is not None and found.pk == dep.pk
    assert Deployment.objects.count() == 1  # found, never created


# --- end to end: economics_context returns the context the renderer displays ---


def test_economics_context_returns_the_exposure_for_a_mapped_deployment(monkeypatch):
    host = "shop.example.com"
    dep = Deployment.objects.create(name=f"target:{host}", engagement=None)
    _version(dep, "Approved current", day=2)
    _stub(monkeypatch)
    scan = types.SimpleNamespace(
        engagement_id=None, target_url=f"https://{host}/", target_shown=host
    )
    context = ee.economics_context(scan)
    assert "economics_exposure" in context
    assert context["economics_exposure"]["title"] == "Approved current"


def test_economics_context_is_default_safe_on_a_read_error(monkeypatch):
    host = "err.example.com"
    Deployment.objects.create(name=f"target:{host}", engagement=None)

    def _boom(deployment):
        raise RuntimeError("stored row unreadable")

    monkeypatch.setattr(ee, "_select_exposure", _boom)
    scan = types.SimpleNamespace(
        engagement_id=None, target_url=f"https://{host}/", target_shown=host
    )
    assert ee.economics_context(scan) == {}  # a read failure omits the section, never raises


# --- DISPLAY ONLY: the helper reaches no signing path -------------------------


def test_the_helper_imports_nothing_on_the_signing_path():
    """NO-SIGNED-CHANGE: the helper reads already-computed figures and the report's
    own read-only integrity status; it never imports the receipt-signing / engine-
    keyring / digest-chain-anchor writers, so it cannot re-sign, re-verify a receipt
    signature, or recompute exposure."""
    src = pathlib.Path(ee.__file__).read_text(encoding="utf-8")
    imported: list[str] = []
    for node in ast.walk(ast.parse(src)):
        if isinstance(node, ast.Import):
            imported += [alias.name for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            imported.append(node.module or "")
    forbidden = ("receipt_service", "cyberengine", "signing", "anchor", "chain_registry",
                 "crypto", "verify_stored_receipt")
    assert not [m for m in imported if any(bad in m for bad in forbidden)], imported
