"""Run only by ``tests/test_economics_engine.py::test_an_economics_fault_never_takes_down_a_stop``,
in a fresh pytest under one of two plugins that break Economic Exposure before
Django loads: ``tests.economics_broken_api`` (its route module does not import)
or ``tests.economics_missing_core`` (mythos-core's currency module does not
import). ``ECONOMICS_FAULT`` says which: ``api`` or ``core``. And by
``tests/test_economics_builder.py::test_a_builder_fault_never_takes_down_a_stop``
under ``tests.economics_broken_builder`` (the scenario builder and its template
module do not import): ``builder``. And by
``tests/test_economics_report.py::test_a_report_fault_never_takes_down_a_stop`` under
``tests.economics_broken_report`` (the report does not import): ``report``. And by
``tests/test_economics_portfolio.py::test_a_portfolio_fault_never_takes_down_a_stop``
under ``tests.economics_broken_portfolio`` (the portfolio does not import):
``portfolio``.

The safety rule (``docs/economics/spec-v1.md``, section 2): an economics fault
never blocks a stop. Under either fault Django loads, the scan's Stop is answered
and saved, ``deliver_owed_stops`` runs the system checks (the URL check among them)
and reaches its handler, and ``manage.py check`` passes; only economics refuses.

Its name does not match ``test_*.py``, so the suite never collects it on its own.
"""

from __future__ import annotations

import io
import os
import sys
from decimal import Decimal

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.urls import Resolver404, resolve
from rest_framework.test import APIClient

from assurance.models import Deployment
from pentest.models import PentestScan

pytestmark = pytest.mark.django_db

FAULT = os.environ["ECONOMICS_FAULT"]


def test_the_scan_stop_is_answered_and_saved():
    analyst = get_user_model().objects.create_user(username="analyst", password="x", role="analyst")
    scan = PentestScan.objects.create(
        user=analyst, target_url="https://offline.invalid/", consent=True, status=PentestScan.STATUS_PENDING
    )
    path = f"/api/pentest/scans/{scan.uuid}/stop/"
    assert resolve(path).view_name == "pentest:stop_pentest_scan"
    client = APIClient()
    client.force_authenticate(user=analyst)
    response = client.post(path, {}, format="json")
    # Owed (202): the scan names no run yet, so the Stop is saved and sent when it does.
    assert response.status_code == 202, response.content
    assert response.json()["stop_saved"] is True
    scan.refresh_from_db()
    assert scan.stop_requested_at is not None


def test_deliver_owed_stops_runs_its_checks_and_reaches_its_handler():
    out = io.StringIO()
    call_command("deliver_owed_stops", skip_checks=False, stdout=out, stderr=io.StringIO())
    assert "scan Stop(s) still owed" in out.getvalue()


def test_manage_py_check_passes():
    out = io.StringIO()
    call_command("check", stdout=out)
    assert "no issues" in out.getvalue()


def test_only_economics_is_refused():
    deployment = Deployment.objects.create(name="d")
    assert resolve(f"/api/assurance/deployments/{deployment.uuid}/").view_name == "deployment-detail"
    route = f"/api/assurance/deployments/{deployment.uuid}/economics/parameter-sets/q4/versions/"
    if FAULT == "report":
        # The scenario endpoints and the report are not served; the parameter-set
        # routes and the builder's still are.
        assert "assurance.economics.report_api" not in sys.modules
        assert "assurance.economics.report" not in sys.modules
        scenario = "00000000-0000-4000-8000-000000000000"
        for tail in ("", "simulate/", "results/"):
            with pytest.raises(Resolver404):
                resolve(f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario}/{tail}")
        # The portfolio totals by the report's rule (may_be_totalled), so it is not
        # served either; nothing else is affected.
        for tail in ("", "simulate/"):
            with pytest.raises(Resolver404):
                resolve(f"/api/assurance/deployments/{deployment.uuid}/economics/portfolio/{tail}")
        assert resolve(route).view_name == "deployment-economics-parameter-set-versions"
        built = resolve(f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/build/")
        assert built.view_name == "deployment-economics-scenario-build"
        # The events route applies the report's banner rule, imported inside its view and not at
        # load: the route module imports, so the URLconf serves it. It answers an error and serves
        # no figures (never figures without the banner), and nothing else is affected.
        events = resolve(f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario}/events/")
        assert events.view_name == "deployment-economics-scenario-events"
        from assurance.economics.models import FinancialScenario

        admin = get_user_model().objects.create_user(username="admin", password="x", role="admin")
        made = FinancialScenario.objects.create(deployment=deployment, title="t", author=admin)
        client = APIClient(raise_request_exception=False)
        client.force_authenticate(user=admin)
        served = client.get(f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{made.uuid}/events/")
        assert served.status_code == 500 and "json" not in served["Content-Type"], served.status_code
        assert "assurance.economics.report" not in sys.modules
        return
    if FAULT == "portfolio":
        # The portfolio's two routes are not served; every other economics route is.
        assert "assurance.economics.portfolio_api" not in sys.modules
        assert "assurance.economics.portfolio" not in sys.modules
        assert "assurance.economics.engine.portfolio" not in sys.modules
        for tail in ("", "simulate/"):
            with pytest.raises(Resolver404):
                resolve(f"/api/assurance/deployments/{deployment.uuid}/economics/portfolio/{tail}")
        assert resolve(route).view_name == "deployment-economics-parameter-set-versions"
        built = resolve(f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/build/")
        assert built.view_name == "deployment-economics-scenario-build"
        scenario = "00000000-0000-4000-8000-000000000000"
        results = resolve(f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario}/results/")
        assert results.view_name == "deployment-economics-scenario-results"
        return
    if FAULT == "builder":
        # The builder's routes are not served; the parameter-set routes still are.
        assert "assurance.economics.scenario_api" not in sys.modules
        assert "assurance.economics.builder" not in sys.modules
        assert "assurance.economics.engine.templates" not in sys.modules
        with pytest.raises(Resolver404):
            resolve(f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/build/")
        assert resolve(route).view_name == "deployment-economics-parameter-set-versions"
        return
    if FAULT == "api":
        assert "assurance.economics.api" not in sys.modules
        with pytest.raises(Resolver404):
            resolve(route)
        return
    assert FAULT == "core"
    from assurance.economics.engine import currency
    from assurance.economics.engine.money import Money

    assert sys.modules["mythos_core.currency"] is None
    assert currency.PIN_REFUSAL.startswith("mythos_core.currency cannot be imported")
    assert currency.CurrencyTableInvalid is currency.LocalCurrencyTableInvalid
    with pytest.raises(currency.CurrencyTableInvalid):
        Money(Decimal("1"), "USD")
    with pytest.raises(currency.CurrencyTableInvalid):
        currency.minor_units("USD")
    # The parameter-set route answers, and refuses the write it cannot check: 503,
    # nothing recorded.
    admin = get_user_model().objects.create_user(username="admin", password="x", role="admin")
    client = APIClient()
    client.force_authenticate(user=admin)
    entry = {"unit": "money", "currency": "USD", "low": "1", "base": "1", "high": "1",
             "source_type": "CUSTOMER_PROVIDED", "evidence_ref": "e", "effective_date": "2026-09-30"}
    response = client.post(route, {"variables": {"legal_retainer": entry}}, format="json")
    assert response.status_code == 503, response.content
    from assurance.economics.models import CustomerParameterSet

    assert not CustomerParameterSet.objects.exists()
