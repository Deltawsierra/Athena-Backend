"""Run only by ``tests/test_economics_engine.py::test_a_changed_core_table_never_takes_down_the_scan_stop``,
in a fresh pytest under the plugin ``tests.economics_mismatched_core``, which changes
one entry of mythos-core's currency table before Django loads.

The safety rule, for Economic Exposure (``docs/economics/spec-v1.md``, section 2):
an economics fault never blocks a stop. With core's table changed, Django still
loads, the scan's Stop route still resolves and answers, and the Stop is saved;
only economics refuses, on use, with ``CurrencyTableInvalid``.

Its name does not match ``test_*.py``, so the suite never collects it on its own.
"""

from __future__ import annotations

from decimal import Decimal

import pytest
from django.contrib.auth import get_user_model
from django.urls import resolve
from rest_framework.test import APIClient

from assurance.economics.engine import currency
from assurance.economics.engine.money import Money
from pentest.models import PentestScan

pytestmark = pytest.mark.django_db


def test_the_table_in_force_is_not_the_pinned_one():
    import mythos_core.currency as core

    assert core.CURRENCIES["USD"].minor_units == 3
    assert currency.PIN_REFUSAL is not None and "athena-backend pinned" in currency.PIN_REFUSAL


def test_the_scan_stop_route_still_resolves_and_answers():
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


def test_economics_use_refuses():
    for use in (
        lambda: currency.currency("USD"),
        lambda: currency.minor_units("USD"),
        lambda: currency.current_successor("HRK"),
        lambda: currency.reporting_refusal("USD"),
        lambda: Money(Decimal("1"), "USD"),
        lambda: Money.parse("1", "EUR"),
    ):
        with pytest.raises(currency.CurrencyTableInvalid):
            use()
