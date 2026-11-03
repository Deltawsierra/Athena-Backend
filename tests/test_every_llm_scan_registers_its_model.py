"""Every LLM scan registers the model it tested, and keeps no secret doing so (AB-LLM-ASSET).

assurance.assets registers a declared LLM target -- ``PentestScan.target_config``,
``{"kind": "llm", adapter, base_url, model}`` -- as a model Provider and Asset when a
scan's findings are ingested. The unrouted ``PentestLLMScanView`` was the only code
that wrote it, and it was deleted (AB-DEADVIEW); the routed LLM scan
(``pentest.views.run_llm_pentest_scan``) never did. So the asset inventory, and the
authority chains, the leftover-authority inventory and the recovery views that read
it, never learned which model an LLM scan tested.

The routed scan now keeps what it tested, and only that: the adapter, the model, the
target's name and the endpoint (scheme, host, port and path). A key the caller sent
-- as a field, in a header, in a mapping, in the URL's login, query or fragment, or
inside a model that is not a string -- reaches neither the record nor the assets.
And it is written only after the preflight lets the launch go: a held or refused
launch records no scan and registers no model.

Driven through the route against the same preflight answers
``tests/test_no_effect_launches_without_the_preflight.py`` uses.
"""

from __future__ import annotations

import json
from datetime import timedelta
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from assurance.models import Asset, Provider
from pentest.models import Engagement, PentestScan
from tests.test_every_operation_says_how_it_degrades import _engine
from tests.test_no_effect_launches_without_the_preflight import _Answers

LLM_SCAN = "/api/pentest/llm-scan/"
ENDPOINT = "https://client.example/v1/chat/completions"
MODEL = "client-model-7"

#: The planted key: it must appear nowhere in what the scan keeps or registers.
KEY = "sk-planted-0123456789abcdef0123456789"


@pytest.fixture()
def admin(db):
    return get_user_model().objects.create_user(
        username="llm-asset-admin", password="x", role="admin", is_staff=True, is_superuser=True
    )


@pytest.fixture()
def engagement(admin):
    now = timezone.now()
    return Engagement.objects.create(
        created_by=admin, name="LLM-ASSET", status="running", scope_hosts=["client.example"],
        testing_window_start=now - timedelta(hours=1), testing_window_end=now + timedelta(hours=1),
    )


@pytest.fixture()
def engine_at():
    import http.server
    import threading

    servers = []

    def start(handler):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


@pytest.fixture(autouse=True)
def _fresh_preflight():
    from ai_engine.services import preflight

    preflight.clear_cache()
    yield
    preflight.clear_cache()


def _body(engagement, **extra):
    return {
        "target_name": "Client LLM",
        "base_url": ENDPOINT,
        "adapter": "openai_style",
        "model": MODEL,
        "attacks": ["metaprompt_extraction"],
        "max_turns": 2,
        "consent": True,
        "engagement_id": engagement.pk,
        **extra,
    }


def _post(admin, client, gate_mode, body, *, captured):
    """POST the LLM scan as ``admin`` against ``client``'s preflight answers, its
    findings ingested on commit as they are in service. Returns (response, launch)."""
    from ai_engine.services import cyberengine_client, preflight

    api = APIClient(raise_request_exception=False)
    api.force_authenticate(user=admin)
    launch = mock.Mock(return_value={"results": [
        {"type": "prompt_injection", "signature_id": "P1", "report_severity": "medium",
         "signature_description": "Prompt injection"},
    ]})
    with mock.patch("pentest.views.target_is_out_of_bounds", return_value=None), \
            mock.patch("pentest.views.CyberEngineClient") as factory, \
            mock.patch.object(cyberengine_client, "ENGINE_TIMEOUT", (0.3, 0.3)), \
            mock.patch.object(preflight, "mode", return_value=gate_mode), \
            mock.patch.object(type(client), "run_llm_scan", launch, create=True), \
            mock.patch("pentest.views.render_scan_pdf_bytes", return_value=b"%PDF-"), \
            mock.patch("pentest.views.save_pdf_to_scan"), \
            captured(execute=True):
        factory.from_settings.return_value = client
        response = api.post(LLM_SCAN, body, format="json")
    return response, launch


def _models():
    return list(Asset.objects.filter(kind=Asset.Kind.MODEL))


def _everything_kept(scan):
    """Every text the scan's declared target and the assets and providers hold."""
    rows = [json.dumps(scan.target_config, sort_keys=True)]
    for asset in Asset.objects.all():
        rows.append(json.dumps([asset.identifier, asset.name, asset.metadata], sort_keys=True, default=str))
    rows.extend(Provider.objects.values_list("name", flat=True))
    return "\n".join(rows)


# --- A launch the preflight lets go registers the model it tested ---------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("gate_mode", ["observe", "enforce"])
def test_an_llm_scan_registers_the_model_it_tested(admin, engagement, gate_mode, django_capture_on_commit_callbacks):
    response, launch = _post(
        admin, _Answers("unchanged"), gate_mode, _body(engagement), captured=django_capture_on_commit_callbacks
    )
    assert response.status_code == 200, response.content
    assert launch.call_count == 1

    scan = PentestScan.objects.get()
    assert scan.status == PentestScan.STATUS_COMPLETED
    assert scan.target_config == {
        "kind": "llm",
        "adapter": "openai_style",
        "base_url": ENDPOINT,
        "model": MODEL,
        "target_name": "Client LLM",
    }

    [model] = _models()
    assert model.identifier == f"{ENDPOINT}|{MODEL}"
    assert model.name == MODEL
    assert model.provider is not None
    assert model.provider.kind == Provider.Kind.MODEL_PROVIDER
    assert model.provider.name == "client.example"
    assert model.metadata == {"adapter": "openai_style", "base_url": ENDPOINT, "model": MODEL}
    # The scan's finding hangs off the model it concerns, as assurance.assets attaches it.
    assert {finding.asset_id for finding in model.deployment.findings.all()} == {model.pk}


@pytest.mark.django_db
def test_an_llm_scan_that_names_no_model_registers_its_endpoint(admin, engagement, django_capture_on_commit_callbacks):
    body = _body(engagement)
    del body["model"]
    response, _launch = _post(admin, _Answers("unchanged"), "enforce", body, captured=django_capture_on_commit_callbacks)
    assert response.status_code == 200, response.content
    [model] = _models()
    assert model.identifier == ENDPOINT
    assert PentestScan.objects.get().target_config["model"] == ""


# --- No secret is kept --------------------------------------------------------------------


PLANTED = {
    "as fields": {
        "api_key": KEY,
        "headers": {"Authorization": f"Bearer {KEY}", "X-API-Key": KEY},
        "request_mapping": {"headers": {"Authorization": f"Bearer {KEY}"}},
        "response_mapping": {"token": KEY},
        "client_id": KEY,
        "tenant_id": KEY,
    },
    "in the endpoint's login": {"base_url": f"https://operator:{KEY}@client.example/v1/chat/completions"},
    "in the endpoint's query": {"base_url": f"{ENDPOINT}?api_key={KEY}&api-version=1"},
    "in the endpoint's parameters and fragment": {"base_url": f"{ENDPOINT};session={KEY}#{KEY}"},
}


@pytest.mark.django_db
@pytest.mark.parametrize("where", list(PLANTED))
def test_no_planted_key_is_kept_by_the_scan_or_its_assets(admin, engagement, where, django_capture_on_commit_callbacks):
    response, launch = _post(
        admin, _Answers("unchanged"), "enforce", _body(engagement, **PLANTED[where]),
        captured=django_capture_on_commit_callbacks,
    )
    assert response.status_code == 200, response.content
    assert launch.call_count == 1
    scan = PentestScan.objects.get()
    assert scan.status == PentestScan.STATUS_COMPLETED

    assert set(scan.target_config) == {"kind", "adapter", "base_url", "model", "target_name"}
    assert scan.target_config["base_url"] == ENDPOINT
    [model] = _models()
    assert model.identifier == f"{ENDPOINT}|{MODEL}"
    kept = _everything_kept(scan)
    assert KEY not in kept, kept


@pytest.mark.django_db
def test_a_model_that_is_not_a_string_is_not_kept(admin, engagement, django_capture_on_commit_callbacks):
    """A model sent as an object (or a list) is not a model's name: nothing of it is
    kept, and the endpoint alone is registered."""
    body = _body(engagement, model={"name": MODEL, "api_key": KEY}, target_name=[KEY])
    response, _launch = _post(admin, _Answers("unchanged"), "enforce", body, captured=django_capture_on_commit_callbacks)
    assert response.status_code == 200, response.content
    scan = PentestScan.objects.get()
    assert scan.target_config["model"] == ""
    assert scan.target_config["target_name"] == ""
    [model] = _models()
    assert model.identifier == ENDPOINT
    assert KEY not in _everything_kept(scan)


# --- The preflight stays first: a held or refused launch registers nothing -----------------


@pytest.mark.django_db
@pytest.mark.parametrize("gate_mode", ["observe", "enforce"])
@pytest.mark.parametrize("fault", ["raises", "hangs", "malformed"])
def test_a_held_launch_registers_no_model(admin, engagement, engine_at, fault, gate_mode,
                                          django_capture_on_commit_callbacks):
    """The engine could not be asked: the launch is held (409) in every mode, and
    neither a scan nor a model, a provider or any asset is recorded."""
    response, launch = _post(
        admin, _engine(fault, engine_at), gate_mode, _body(engagement, api_key=KEY),
        captured=django_capture_on_commit_callbacks,
    )
    assert response.status_code == 409, response.content
    assert response.json()["assurance"]["verdict"] == "unknown"
    assert not launch.called
    assert not PentestScan.objects.exists()
    assert not Asset.objects.exists()
    assert not Provider.objects.exists()


@pytest.mark.django_db
def test_a_refused_launch_registers_no_model(admin, engagement, django_capture_on_commit_callbacks):
    """The gate blocks and the mode is enforce: refused (409), nothing recorded."""
    response, launch = _post(
        admin, _Answers("blocked"), "enforce", _body(engagement), captured=django_capture_on_commit_callbacks
    )
    assert response.status_code == 409, response.content
    assert response.json()["assurance"]["verdict"] == "blocked"
    assert not launch.called
    assert not PentestScan.objects.exists()
    assert not Asset.objects.exists()
    assert not Provider.objects.exists()


@pytest.mark.django_db
def test_a_scan_the_engine_failed_registers_no_model(admin, engagement, django_capture_on_commit_callbacks):
    """The preflight let it go and the engine failed it: the scan is recorded failed
    with what it targeted, and nothing was tested, so no model is registered."""
    from ai_engine.services.cyberengine_client import ENGINE_UNREACHABLE, EngineError

    client = _Answers("unchanged")
    api = APIClient(raise_request_exception=False)
    api.force_authenticate(user=admin)
    with mock.patch("pentest.views.target_is_out_of_bounds", return_value=None), \
            mock.patch("pentest.views.CyberEngineClient") as factory, \
            mock.patch("ai_engine.services.preflight.mode", return_value="enforce"), \
            mock.patch.object(_Answers, "run_llm_scan",
                              side_effect=EngineError("Engine unreachable", kind=ENGINE_UNREACHABLE)), \
            django_capture_on_commit_callbacks(execute=True):
        factory.from_settings.return_value = client
        response = api.post(LLM_SCAN, _body(engagement), format="json")
    assert response.status_code == 502, response.content
    scan = PentestScan.objects.get()
    assert scan.status == PentestScan.STATUS_FAILED
    assert scan.target_config["model"] == MODEL
    assert not _models()
