"""Run only by ``tests/test_economics_engine.py::test_an_economics_fault_never_takes_down_a_stop``,
in a fresh pytest under one of two plugins that break Economic Exposure before
Django loads: ``tests.economics_broken_api`` (its route module does not import)
or ``tests.economics_missing_core`` (mythos-core's currency module does not
import). ``ECONOMICS_FAULT`` says which: ``api`` or ``core``.

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
