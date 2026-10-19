"""Run only by ``tests/test_legal_obligation_routes.py::test_a_legal_obligations_fault_never_takes_down_a_stop``,
in a fresh pytest under ``tests.legal_obligations_broken``, which makes the
legal-obligations route module (``assurance.legal_api``) raise at import before Django
loads.

The safety rule: no fault may block or delay a stop. Under the fault Django loads, the
scan's Stop is answered and saved, ``deliver_owed_stops`` runs the system checks (the
URL check among them) and reaches its handler, and ``manage.py check`` passes; only the
three legal-obligations routes are not served.

Its name does not match ``test_*.py``, so the suite never collects it on its own.
"""

from __future__ import annotations

import io
import sys

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.urls import Resolver404, resolve
from rest_framework.test import APIClient

from assurance.models import Deployment
from pentest.models import PentestScan
from tests import legal_obligations_broken

pytestmark = pytest.mark.django_db


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


def test_only_the_legal_obligations_routes_are_refused():
    # The URLconf asked for the module and the guard caught its fault: not a URLconf
    # that never imported it.
    assert legal_obligations_broken.ASKED, "nothing tried to import assurance.legal_api"
    assert "assurance.legal_api" not in sys.modules
    deployment = Deployment.objects.create(name="d")
    base = f"/api/assurance/deployments/{deployment.uuid}/"
    obligation = "00000000-0000-4000-8000-000000000000"
    for tail in ("legal-obligations/", f"legal-obligations/{obligation}/", f"legal-obligations/{obligation}/supersede/"):
        with pytest.raises(Resolver404):
            resolve(base + tail)
    assert resolve(base).view_name == "deployment-detail"
    assert resolve(base + "recompute/").view_name == "deployment-recompute"
    assert resolve(base + "assurance-claims/").view_name == "deployment-assurance-claims"
    assert resolve(base + "economics/portfolio/").view_name == "deployment-economics-portfolio"
