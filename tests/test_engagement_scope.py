"""
Scope enforcement.

The Engagement model recorded an authorised scope and a testing window, and a
migration had removed its link to scans, so nothing read either. Authorisation
to attack a third party was a `consent: true` boolean the caller asserted about
themselves. These tests hold the line that a scan runs only under an engagement
that actually authorises it.
"""

from datetime import timedelta
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from pentest import views
from pentest.models import Engagement, PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()
TARGET = "https://app.client.example/login"


@pytest.fixture()
def factory():
    return APIRequestFactory()


@pytest.fixture()
def analyst():
    return User.objects.create_user(username="analyst", password="x", role=User.Roles.ANALYST)


def make_engagement(user, **overrides):
    now = timezone.now()
    values = {
        "created_by": user,
        "name": "Client Q3",
        "status": "running",
        "scope_hosts": ["client.example"],
        "testing_window_start": now - timedelta(hours=1),
        "testing_window_end": now + timedelta(hours=1),
    }
    values.update(overrides)
    return Engagement.objects.create(**values)


def launch(factory, user, url=TARGET, engagement=None, **extra):
    body = {"url": url, "consent": True, **extra}
    if engagement is not None:
        body["engagement_id"] = engagement.pk
    request = factory.post("/api/pentest/scan/", body, format="json")
    force_authenticate(request, user=user)

    engine = mock.Mock()
    engine.run_scan.return_value = {"results": [{"type": "info"}]}
    # The preflight answers clean: these tests are about the engagement's scope, not the gate, and a
    # bare Mock's answers are no verdict, which holds a launch in every mode (G14).
    with mock.patch("pentest.views.target_is_out_of_bounds", return_value=None), \
            mock.patch("pentest.views.preflight.check", return_value={"verdict": "ok"}), \
            mock.patch("pentest.views.CyberEngineClient") as client, \
            mock.patch("pentest.views.render_scan_pdf_bytes", return_value=b"%PDF-"), \
            mock.patch("pentest.views.save_pdf_to_scan"):
        client.from_settings.return_value = engine
        response = views.run_pentest_scan(request)
    return response, engine


# ---------------------------------------------------------------------------
# An engagement is required, and it must authorise this target
# ---------------------------------------------------------------------------


def test_a_scan_without_an_engagement_is_refused(factory, analyst):
    response, engine = launch(factory, analyst, engagement=None)

    assert response.status_code == 403
    assert "engagement_id is required" in response.data["error"]
    engine.run_scan.assert_not_called()


def test_a_target_outside_the_recorded_scope_is_refused(factory, analyst):
    engagement = make_engagement(analyst, scope_hosts=["someone-else.example"])
    response, engine = launch(factory, analyst, engagement=engagement)

    assert response.status_code == 403
    assert "not in the authorised scope" in response.data["error"]
    engine.run_scan.assert_not_called()


def test_a_host_inside_the_recorded_scope_is_allowed(factory, analyst):
    engagement = make_engagement(analyst)
    response, engine = launch(factory, analyst, engagement=engagement)

    assert response.status_code == 200
    engine.run_scan.assert_called_once()
    assert PentestScan.objects.get(uuid=response.data["scan_id"]).engagement == engagement


def test_a_subdomain_of_an_in_scope_host_is_allowed(factory, analyst):
    engagement = make_engagement(analyst, scope_hosts=["client.example"])
    response, _engine = launch(factory, analyst, url="https://deep.api.client.example/x")

    # No engagement passed, so this must be refused for that reason, not scope.
    assert response.status_code == 403

    response, engine = launch(
        factory, analyst, url="https://deep.api.client.example/x", engagement=engagement
    )
    assert response.status_code == 200
    engine.run_scan.assert_called_once()


@pytest.mark.parametrize(
    "host",
    [
        # The suffix match must not be a substring match: an attacker who owns
        # these should not inherit the client's authorisation.
        "https://client.example.evil.test/",
        "https://notclient.example/",
        "https://client-example/",
    ],
)
def test_a_host_that_merely_looks_in_scope_is_refused(factory, analyst, host):
    engagement = make_engagement(analyst, scope_hosts=["client.example"])
    response, engine = launch(factory, analyst, url=host, engagement=engagement)

    assert response.status_code == 403, f"{host} was treated as in scope"
    engine.run_scan.assert_not_called()


# ---------------------------------------------------------------------------
# When, and under whose authority
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("state", ["planned", "paused", "completed", "cancelled"])
def test_an_engagement_that_is_not_running_does_not_authorise_a_scan(
    factory, analyst, state
):
    engagement = make_engagement(analyst, status=state)
    response, engine = launch(factory, analyst, engagement=engagement)

    assert response.status_code == 403
    assert state in response.data["error"]
    engine.run_scan.assert_not_called()


@pytest.mark.parametrize(
    ("start_offset", "end_offset"),
    [(-48, -24), (24, 48)],  # finished yesterday, or starts tomorrow
)
def test_a_scan_outside_the_testing_window_is_refused(
    factory, analyst, start_offset, end_offset
):
    now = timezone.now()
    engagement = make_engagement(
        analyst,
        testing_window_start=now + timedelta(hours=start_offset),
        testing_window_end=now + timedelta(hours=end_offset),
    )
    response, engine = launch(factory, analyst, engagement=engagement)

    assert response.status_code == 403
    assert "testing window" in response.data["error"]
    engine.run_scan.assert_not_called()


def test_an_engagement_with_no_window_authorises_nothing(factory, analyst):
    """An absent window is not an open-ended one."""
    engagement = make_engagement(
        analyst, testing_window_start=None, testing_window_end=None
    )
    response, engine = launch(factory, analyst, engagement=engagement)

    assert response.status_code == 403
    engine.run_scan.assert_not_called()


def test_one_analyst_cannot_scan_under_another_analysts_engagement(factory, analyst):
    other = User.objects.create_user(
        username="other", password="x", role=User.Roles.ANALYST
    )
    engagement = make_engagement(other)

    response, engine = launch(factory, analyst, engagement=engagement)

    assert response.status_code == 403
    assert "No such engagement" in response.data["error"]
    engine.run_scan.assert_not_called()


def test_an_admin_may_scan_under_any_engagement(factory, analyst):
    admin = User.objects.create_user(username="boss", password="x", role=User.Roles.ADMIN)
    engagement = make_engagement(analyst)

    response, engine = launch(factory, admin, engagement=engagement)

    assert response.status_code == 200
    engine.run_scan.assert_called_once()


# ---------------------------------------------------------------------------
# The same rule on the LLM path
# ---------------------------------------------------------------------------


def test_an_llm_scan_also_requires_an_authorising_engagement(factory, analyst):
    request = factory.post(
        "/api/pentest/llm-scan/",
        {
            "base_url": "https://app.client.example/v1/chat/completions",
            "adapter": "openai_style",
            "consent": True,
        },
        format="json",
    )
    force_authenticate(request, user=analyst)

    with mock.patch("pentest.views.target_is_out_of_bounds", return_value=None), \
            mock.patch("pentest.views.CyberEngineClient") as client:
        response = views.run_llm_pentest_scan(request)

    assert response.status_code == 403
    client.from_settings.assert_not_called()


def test_the_engagement_covers_check_is_case_and_dot_insensitive():
    engagement = Engagement(scope_hosts=["Client.Example."])

    assert engagement.covers("app.client.example")
    assert engagement.covers("CLIENT.EXAMPLE")
    assert engagement.covers("client.example.")
    assert not engagement.covers("")
    assert not engagement.covers("client.example.attacker.test")
