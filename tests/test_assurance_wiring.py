"""
The engine's gates are on the path that points it at a customer.

Six subsystems were built into the engine -- the assurance tuple and change
gate, the authorization-to-effect ledger, the extension lifecycle gate, the
decision twin and remediation replay, route attestation, and the incident
evidence pack -- and a grep of this repository for "assurance",
"/api/extensions", "/api/authority" and "/api/evidence" returned nothing.
The change gate was consulted only by its own HTTP route and its own tests,
so a deployment whose model, tools, routes, policies, hooks and permissions
had all changed since approval ran every scan with nothing objecting.

extensions/gate.py names the realistic failure as "the engine ran for a week
with a changed scanner and nobody read the endpoint". That was not a risk,
it was the shipped configuration.
"""

from datetime import timedelta
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from ai_engine.services import preflight
from pentest import views
from pentest.models import Engagement, PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()
TARGET = "https://app.client.example/login"

CLEAN = {
    "assurance": {"verdict": "unchanged", "detail": "the deployment is the one that was approved"},
    "extensions": {"verdict": "ok", "detail": "every loaded extension is the one that was approved"},
    "unattributed": {"effects": []},
}


@pytest.fixture(autouse=True)
def _no_cached_verdict():
    preflight.clear_cache()
    yield
    preflight.clear_cache()


@pytest.fixture()
def factory():
    return APIRequestFactory()


@pytest.fixture()
def analyst():
    return User.objects.create_user(username="analyst", password="x",
                                    role=User.Roles.ANALYST)


@pytest.fixture()
def engagement(analyst):
    now = timezone.now()
    return Engagement.objects.create(
        created_by=analyst, name="Client Q3", status="running",
        scope_hosts=["client.example"],
        testing_window_start=now - timedelta(hours=1),
        testing_window_end=now + timedelta(hours=1),
    )


def launch(factory, user, engagement, answers=None, mode="observe"):
    answers = {**CLEAN, **(answers or {})}
    body = {"url": TARGET, "consent": True, "engagement_id": engagement.pk}
    request = factory.post("/api/pentest/scan/", body, format="json")
    force_authenticate(request, user=user)

    engine = mock.Mock()
    engine.run_scan.return_value = {"results": [{"type": "info"}]}
    engine.assurance_check.return_value = answers["assurance"]
    engine.extension_review.return_value = answers["extensions"]
    engine.unattributed_effects.return_value = answers["unattributed"]

    with mock.patch("pentest.views.target_is_out_of_bounds", return_value=None), \
            mock.patch("pentest.views.CyberEngineClient") as client, \
            mock.patch("pentest.views.render_scan_pdf_bytes", return_value=b"%PDF-"), \
            mock.patch("pentest.views.save_pdf_to_scan"), \
            mock.patch.object(preflight, "mode", return_value=mode):
        client.from_settings.return_value = engine
        response = views.run_pentest_scan(request)
    return response, engine


def test_the_gates_are_asked_before_the_engine_is_pointed_at_anyone(
    factory, analyst, engagement
):
    response, engine = launch(factory, analyst, engagement)

    assert engine.assurance_check.called, "the assurance gate was never consulted"
    assert engine.extension_review.called, "the extension gate was never consulted"
    assert engine.unattributed_effects.called, "the audit query was never asked"
    assert response.status_code < 400


def test_a_blocked_deployment_refuses_the_scan_under_enforce(
    factory, analyst, engagement
):
    blocked = {"assurance": {"verdict": "blocked",
                             "detail": "policies changed in a way that adds capability"}}
    response, engine = launch(factory, analyst, engagement, blocked, mode="enforce")

    assert response.status_code == 409
    assert not engine.run_scan.called, "the scan ran against a blocked deployment"


def test_a_blocked_deployment_is_recorded_but_proceeds_under_observe(
    factory, analyst, engagement
):
    """
    Observe is the default, matching the engine's own extension gate: a gate
    that blocks on the day it is switched on is one somebody turns off. The
    verdict is still recorded, so the record shows what would have been
    refused.
    """
    blocked = {"extensions": {"verdict": "blocked",
                              "detail": "revoked and still loaded: rce"}}
    response, engine = launch(factory, analyst, engagement, blocked, mode="observe")

    assert response.status_code < 400
    assert engine.run_scan.called

    scan = PentestScan.objects.latest("id")
    assert scan.assurance["verdict"] == "blocked"
    assert "rce" in scan.assurance["detail"]


def test_an_engine_that_cannot_be_asked_is_not_an_engine_that_said_yes(
    factory, analyst, engagement
):
    from ai_engine.services.cyberengine_client import ENGINE_UNREACHABLE, EngineError

    request = factory.post("/api/pentest/scan/",
                           {"url": TARGET, "consent": True,
                            "engagement_id": engagement.pk}, format="json")
    force_authenticate(request, user=analyst)

    engine = mock.Mock()
    engine.assurance_check.side_effect = EngineError("connection refused", kind=ENGINE_UNREACHABLE)

    with mock.patch("pentest.views.target_is_out_of_bounds", return_value=None), \
            mock.patch("pentest.views.CyberEngineClient") as client, \
            mock.patch.object(preflight, "mode", return_value="enforce"):
        client.from_settings.return_value = engine
        response = views.run_pentest_scan(request)

    assert response.status_code == 409
    assert not engine.run_scan.called


def test_an_unapproved_deployment_is_blocked_not_unchanged(
    factory, analyst, engagement
):
    """
    "nobody approved this" and "this is what was approved" must not share an
    outcome, or the gate reports a deployment nobody ever signed off as one
    that still matches its approval.
    """
    unapproved = {"assurance": {"verdict": "unapproved",
                                "detail": "no approval on record"}}
    response, _ = launch(factory, analyst, engagement, unapproved, mode="enforce")
    assert response.status_code == 409


def test_the_verdict_is_stored_on_the_scan_it_governed(
    factory, analyst, engagement
):
    """A verdict in a log file is not next to the work it governed."""
    # The route-attestation gate needs a deployment whose assets it can
    # enumerate. Without one it reports "no deployment record matches the
    # declared deployment_id" and the verdict is review -- correctly, since an
    # inventory we do not hold is not an inventory of no routes. Creating the
    # row keeps this test about where the verdict is STORED, which is its point.
    from assurance.models import Deployment

    Deployment.objects.create(name="mythos-platform", owner=analyst)
    launch(factory, analyst, engagement)

    scan = PentestScan.objects.latest("id")
    assert scan.assurance is not None
    assert scan.assurance["verdict"] == "ok"
    assert scan.assurance["deployment_id"] == "mythos-platform"


def test_unattributed_effects_are_reported_without_blocking(
    factory, analyst, engagement
):
    """A fact about the past, not about this scan -- but it belongs in the record."""
    noisy = {"unattributed": {"effects": [{"host": "somewhere.example"}]}}
    response, engine = launch(factory, analyst, engagement, noisy, mode="enforce")

    assert response.status_code < 400
    assert engine.run_scan.called
    scan = PentestScan.objects.latest("id")
    assert scan.assurance["verdict"] == "review"
    assert "no authority" in scan.assurance["detail"]


def test_the_declaration_names_every_component_the_engine_requires(self=None):
    """
    The engine refuses a partial tuple rather than filling the gaps in: a
    component that is absent is not "there are none", it is "nobody said".
    """
    declared = preflight.declaration()
    assert set(declared["components"]) == {
        "model", "prompts", "tools", "routes",
        "retrieval", "policies", "hooks", "permissions",
    }


def test_a_missing_yaml_refuses_the_gate_and_not_the_whole_application():
    """
    preflight is imported by pentest.views, which is imported by pentest.urls,
    which is imported by the root URL conf. A module-scope `import yaml` there
    meant a dependency missing from the light requirements set took down every
    route in the application -- the login page included -- rather than the
    governance check. CI caught it as ModuleNotFoundError during URL loading.

    A gate that cannot answer should refuse scans, not the front door.
    """
    import builtins
    from unittest import mock

    real_import = builtins.__import__

    def no_yaml(name, *args, **kwargs):
        if name == "yaml":
            raise ImportError("No module named 'yaml'")
        return real_import(name, *args, **kwargs)

    with mock.patch.object(builtins, "__import__", side_effect=no_yaml):
        with pytest.raises(preflight.DeploymentNotApproved) as refusal:
            preflight.declaration()

    assert "PyYAML" in str(refusal.value)
