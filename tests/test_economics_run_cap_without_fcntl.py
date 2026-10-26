"""The economics run cap on a host with no ``fcntl`` (Windows).

``capacity.py`` takes a slot with ``fcntl.flock``, and Windows has no ``fcntl``. The
design for that case is already in the module: slot files that cannot be locked
refuse the run with the 503 ``economics_capacity`` ("cannot be read"), never run it
uncapped. But ``import fcntl`` sat inside ``Slots.release`` and ``_take_one``, and
``acquire``'s ``except ImportError`` handler called ``Slots(held).release()``, which
imported ``fcntl`` again and raised again, from inside the handler: the economics
simulate routes answered 500, not the designed 503.

These tests run the Windows case on any host. They make ``import fcntl`` fail the way
it does on Windows (``sys.modules["fcntl"] = None``), and, for the module as it is left
when it was imported on such a host, they load a copy of ``capacity.py`` under that
condition. The flock-dependent tests in ``test_economics_run_cap.py`` assert the POSIX
behaviour and stay there; they cannot pass where no slot can be locked.
"""

from __future__ import annotations

import importlib.util
import inspect
import os
import sys

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from assurance.economics import capacity
from assurance.economics.models import SimulationResult
from assurance.models import Deployment
from tests.test_economics_report import QUICK, stored

User = get_user_model()


@pytest.fixture
def no_fcntl(monkeypatch):
    """This process as it is on Windows: ``import fcntl`` raises ``ImportError``, and
    ``capacity`` holds no ``fcntl`` (the value its guarded import leaves there)."""
    monkeypatch.setitem(sys.modules, "fcntl", None)
    monkeypatch.setattr(capacity, "fcntl", None, raising=False)


def test_without_fcntl_every_run_is_refused_as_unreadable_and_nothing_raises(no_fcntl):
    assert capacity.acquire("tenant-a") == (None, "unreadable")
    assert capacity.acquire("tenant-b") == (None, "unreadable")


def test_without_fcntl_releasing_slots_only_closes_them_and_never_raises(no_fcntl, tmp_path):
    descriptor = os.open(tmp_path / "run-0.lock", os.O_RDWR | os.O_CREAT)
    slots = capacity.Slots([descriptor])
    slots.release()
    with pytest.raises(OSError):
        os.fstat(descriptor)
    slots.release()  # released together, once: a second release has nothing left to do


def test_the_module_imported_on_a_host_without_fcntl_loads_and_refuses(monkeypatch):
    """The import itself: ``capacity.py`` executed with no ``fcntl`` to import."""
    monkeypatch.setitem(sys.modules, "fcntl", None)
    spec = importlib.util.spec_from_file_location("economics_capacity_without_fcntl", inspect.getsourcefile(capacity))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.fcntl is None
    assert module.acquire("tenant-a") == (None, "unreadable")
    module.Slots([]).release()


@pytest.mark.django_db
def test_a_simulate_without_fcntl_is_the_503_and_not_a_500(no_fcntl):
    analyst = User.objects.create_user(username="ann-nofcntl", password="x", role="analyst")
    deployment = Deployment.objects.create(name="no-fcntl")
    scenario = stored(deployment, analyst)
    client = APIClient(raise_request_exception=False)  # an exception is the 500 a user would see
    client.force_authenticate(user=analyst)
    before = SimulationResult.objects.count()
    response = client.post(
        f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario.uuid}/simulate/",
        {"seed": 51, "policy": QUICK},
        format="json",
    )
    assert response.status_code == 503, response.status_code
    assert response["Retry-After"] == str(capacity.RETRY_AFTER_SECONDS)
    body = response.json()
    assert body["code"] == "economics_capacity" and body["recorded"] is False, body
    assert "cannot be read" in body["detail"], body
    assert SimulationResult.objects.count() == before
