"""
Failures together, not one at a time.

Every guard here was tested on its own. This file asks whether they interfere:
whether a refused authorisation still writes a row, whether an engine that
never answers leaves a scan half-recorded, and whether the answers change when
all of it happens at once. A guard that is right alone and wrong in company is
the failure mode that produced the kill-switch and pagination regressions.
"""

import threading
from datetime import timedelta
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from ai_engine.services.cyberengine_client import EngineError
from pentest import views
from pentest.models import Engagement, PentestScan

pytestmark = pytest.mark.django_db(transaction=True)

User = get_user_model()
IN_SCOPE = "https://app.client.example/login"


@pytest.fixture()
def factory():
    return APIRequestFactory()


@pytest.fixture()
def analyst():
    return User.objects.create_user(username="compound", password="x", role=User.Roles.ANALYST)


@pytest.fixture()
def engagement(analyst):
    now = timezone.now()
    return Engagement.objects.create(
        created_by=analyst,
        name="Compounding",
        status="running",
        scope_hosts=["client.example"],
        testing_window_start=now - timedelta(hours=1),
        testing_window_end=now + timedelta(hours=1),
    )


def launch(factory, user, body, engine=None):
    request = factory.post("/api/pentest/scan/", body, format="json")
    force_authenticate(request, user=user)

    engine = engine or mock.Mock(**{"run_scan.return_value": {"results": [{"type": "info"}]}})
    with mock.patch("pentest.views.target_is_out_of_bounds", return_value=None), \
            mock.patch("pentest.views.CyberEngineClient") as client, \
            mock.patch("pentest.views.render_scan_pdf_bytes", return_value=b"%PDF-"), \
            mock.patch("pentest.views.save_pdf_to_scan"), \
            mock.patch("pentest.views.send_pentest_scan_email"):
        client.from_settings.return_value = engine
        return views.run_pentest_scan(request)


def side_effects():
    rows = PentestScan.objects.all()
    return {
        "rows": rows.count(),
        "completed": rows.filter(status=PentestScan.STATUS_COMPLETED).count(),
        "failed": rows.filter(status=PentestScan.STATUS_FAILED).count(),
        "pending": rows.filter(status=PentestScan.STATUS_PENDING).count(),
    }


# ---------------------------------------------------------------------------
# A refusal is a refusal all the way down
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        ("out of scope", lambda e: setattr(e, "scope_hosts", ["someone-else.example"])),
        ("not running", lambda e: setattr(e, "status", "paused")),
        ("window closed", lambda e: setattr(e, "testing_window_end", timezone.now() - timedelta(hours=1))),
    ],
)
def test_a_refused_authorisation_leaves_nothing_behind(
    factory, analyst, engagement, label, mutate
):
    mutate(engagement)
    engagement.save()

    response = launch(
        factory, analyst, {"url": IN_SCOPE, "consent": True, "engagement_id": engagement.pk}
    )

    assert response.status_code == 403, label
    assert side_effects() == {"rows": 0, "completed": 0, "failed": 0, "pending": 0}, label


def test_an_engine_that_never_answers_leaves_a_failed_row_not_a_pending_one(
    factory, analyst, engagement
):
    """
    A scan stuck in a non-terminal state is worse than no row: it says
    "still running" forever. The row is created before the request goes out,
    so it must be closed out on every path back.
    """
    engine = mock.Mock()
    engine.run_scan.side_effect = EngineError("Read timed out")

    response = launch(
        factory, analyst,
        {"url": IN_SCOPE, "consent": True, "engagement_id": engagement.pk},
        engine=engine,
    )

    assert response.status_code == 502
    assert side_effects() == {"rows": 1, "completed": 0, "failed": 1, "pending": 0}


def test_an_engine_refusal_and_a_revocation_at_the_same_time(factory, analyst, engagement):
    """
    Two things go wrong on the same request: the engine refuses the target by
    policy, and the engagement is cancelled while it does. The scan must end
    once, in one state, with no report.
    """
    def refuse_and_revoke(_url, **_kwargs):
        Engagement.objects.filter(pk=engagement.pk).update(status="cancelled")
        return {"results": [{"type": "error", "message": "Refused by egress policy"}]}

    engine = mock.Mock()
    engine.run_scan.side_effect = refuse_and_revoke

    response = launch(
        factory, analyst,
        {"url": IN_SCOPE, "consent": True, "engagement_id": engagement.pk},
        engine=engine,
    )

    assert response.status_code == 502
    assert side_effects() == {"rows": 1, "completed": 0, "failed": 1, "pending": 0}


# ---------------------------------------------------------------------------
# All at once
# ---------------------------------------------------------------------------


def test_a_mixed_burst_answers_each_arm_the_way_it_would_alone(factory, analyst, engagement):
    """
    Twenty-four requests at once: refused authorisation, malformed bodies, an
    engine that times out, an engine that refuses, and the happy path. Each
    arm must produce the status it produces in isolation, nothing may escape
    the stack, and the rows that exist must match the requests that succeeded.

    The patches are installed once, around the whole burst. mock.patch
    replaces a module global, so patching per thread means one thread's engine
    is visible to another and the arms answer each other's questions.
    """
    behaviour = threading.local()

    def run_scan(_url, **_kwargs):
        mode = getattr(behaviour, "mode", "ok")
        if mode == "timeout":
            raise EngineError("Read timed out")
        if mode == "refuse":
            return {"results": [{"type": "error", "message": "Refused by egress policy"}]}
        return {"results": [{"type": "info"}]}

    engine = mock.Mock()
    engine.run_scan.side_effect = run_scan

    arms = []
    for _ in range(4):
        arms.append(("out of scope", "ok", {"url": "https://other.example/", "consent": True,
                                            "engagement_id": engagement.pk}, 403))
        arms.append(("no engagement", "ok", {"url": IN_SCOPE, "consent": True}, 403))
        arms.append(("malformed body", "ok", [], 400))
        arms.append(("engine timeout", "timeout", {"url": IN_SCOPE, "consent": True,
                                                   "engagement_id": engagement.pk}, 502))
        arms.append(("engine refusal", "refuse", {"url": IN_SCOPE, "consent": True,
                                                  "engagement_id": engagement.pk}, 502))
        arms.append(("happy path", "ok", {"url": IN_SCOPE, "consent": True,
                                          "engagement_id": engagement.pk}, 200))

    results = []
    errors = []

    def run(label, mode, body, expected):
        behaviour.mode = mode
        try:
            request = factory.post("/api/pentest/scan/", body, format="json")
            force_authenticate(request, user=analyst)
            response = views.run_pentest_scan(request)
            results.append((label, response.status_code, expected))
        except Exception as exc:  # noqa: BLE001 - the point is that none escape
            errors.append((label, repr(exc)))

    with mock.patch("pentest.views.target_is_out_of_bounds", return_value=None), \
            mock.patch("pentest.views.CyberEngineClient") as client, \
            mock.patch("pentest.views.render_scan_pdf_bytes", return_value=b"%PDF-"), \
            mock.patch("pentest.views.save_pdf_to_scan"), \
            mock.patch("pentest.views.send_pentest_scan_email"):
        client.from_settings.return_value = engine

        threads = [threading.Thread(target=run, args=arm) for arm in arms]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert errors == [], "a request escaped the stack"

    wrong = [(label, got, want) for label, got, want in results if got != want]
    assert wrong == [], f"arms answered differently under load: {wrong}"

    state = side_effects()
    assert state["pending"] == 0, "a scan was left in a non-terminal state"
    assert state["completed"] == 4, state
    # Four timeouts and four engine refusals, each of which records a failure.
    assert state["failed"] == 8, state
    assert state["rows"] == 12, state

    # Every row points at the engagement that authorised it, and that
    # engagement still covers the target.
    for scan in PentestScan.objects.all():
        assert scan.engagement_id == engagement.pk
    assert engagement.covers("app.client.example")


def test_twenty_concurrent_scans_under_one_engagement_do_not_interfere(
    factory, analyst, engagement
):
    """
    The patches are installed once, around all twenty threads. `mock.patch`
    replaces a module global, so patching inside each thread means one
    thread's teardown reverts the engine while another is mid-call — and that
    thread gets a bare MagicMock back instead of a result. It fails roughly
    one run in three, and it is the test racing itself, not the code.
    """
    results = []
    errors = []

    engine = mock.Mock()
    engine.run_scan.return_value = {"results": [{"type": "info"}]}

    def run():
        try:
            request = factory.post(
                "/api/pentest/scan/",
                {"url": IN_SCOPE, "consent": True, "engagement_id": engagement.pk},
                format="json",
            )
            force_authenticate(request, user=analyst)
            results.append(views.run_pentest_scan(request).status_code)
        except Exception as exc:  # noqa: BLE001
            errors.append(repr(exc))

    patches = mock.patch.multiple(
        "pentest.views",
        target_is_out_of_bounds=mock.DEFAULT,
        CyberEngineClient=mock.DEFAULT,
        render_scan_pdf_bytes=mock.DEFAULT,
        save_pdf_to_scan=mock.DEFAULT,
        send_pentest_scan_email=mock.DEFAULT,
    )
    with patches as mocks:
        mocks["target_is_out_of_bounds"].return_value = None
        mocks["render_scan_pdf_bytes"].return_value = b"%PDF-"
        mocks["CyberEngineClient"].from_settings.return_value = engine

        threads = [threading.Thread(target=run) for _ in range(20)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()

    assert errors == []
    assert results == [200] * 20
    assert PentestScan.objects.count() == 20
    assert PentestScan.objects.values("uuid").distinct().count() == 20
    assert PentestScan.objects.filter(status=PentestScan.STATUS_PENDING).count() == 0
