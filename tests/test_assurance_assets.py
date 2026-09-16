"""Athena Phase 1.1 — AI Asset Discovery.

Proves the assurance graph's nodes are populated from what a scan honestly knows:
the scanned host (classified by scope), declared scope hosts, endpoint assets from
findings that carry a location, and a declared LLM target as a model Provider +
Asset — with every finding attached to the asset it concerns. Derivation is
idempotent and never overwrites a human's re-classification. The LLM-scan view's
broken target field is fixed and now persists its declared target.
"""

from __future__ import annotations

from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import ingest
from assurance.assets import derive_assets
from assurance.models import Asset, Deployment, Finding, Provider
from assurance.views import AssetViewSet
from pentest.models import Engagement, PentestScan
from pentest.views_llm import PentestLLMScanView

pytestmark = pytest.mark.django_db

User = get_user_model()

FINDINGS = [
    {"type": "sql_injection", "signature_id": "S1", "report_severity": "high",
     "signature_description": "SQLi in search"},
]


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _scan(user, target_url, *, engagement=None, findings=FINDINGS, target_config=None):
    return PentestScan.objects.create(
        user=user,
        target_url=target_url,
        consent=True,
        status=PentestScan.STATUS_COMPLETED,
        engagement=engagement,
        engine_response={"findings": findings} if findings is not None else None,
        target_config=target_config,
    )


def test_scanned_host_in_scope_is_a_known_asset():
    user = _user()
    eng = Engagement.objects.create(name="Acme", created_by=user, scope_hosts=["client.example"])
    scan = _scan(user, "https://app.client.example/login", engagement=eng)
    ingest.ingest_scan(scan)

    dep = Deployment.objects.get()
    host = dep.assets.get(kind=Asset.Kind.API, identifier="app.client.example")
    assert host.classification == Asset.Classification.KNOWN


def test_scanned_host_out_of_scope_is_unmanaged():
    """A reachable host the engagement did not authorise is a shadow asset."""
    user = _user()
    eng = Engagement.objects.create(name="Acme", created_by=user, scope_hosts=["other.example"])
    dep = Deployment.objects.create(name="d", owner=user)
    scan = PentestScan.objects.create(
        user=user, target_url="https://shadow.example/", consent=True, engagement=eng
    )
    derive_assets(dep, scan)
    asset = dep.assets.get(kind=Asset.Kind.API, identifier="shadow.example")
    assert asset.classification == Asset.Classification.UNMANAGED


def test_declared_scope_hosts_become_approved_assets():
    user = _user()
    eng = Engagement.objects.create(
        name="Acme", created_by=user, scope_hosts=["a.example", "b.example"]
    )
    dep = Deployment.objects.create(name="d", owner=user)
    scan = PentestScan.objects.create(
        user=user, target_url="https://a.example/", consent=True, engagement=eng
    )
    derive_assets(dep, scan)
    # The scanned host is known; a declared-but-unscanned scope host is approved.
    assert dep.assets.get(identifier="a.example").classification == Asset.Classification.KNOWN
    assert dep.assets.get(identifier="b.example").classification == Asset.Classification.APPROVED


def test_finding_with_location_becomes_an_endpoint_asset_and_is_attached():
    user = _user()
    dep = Deployment.objects.create(name="d", owner=user)
    scan = PentestScan.objects.create(user=user, target_url="https://app.example/", consent=True)
    finding = Finding.objects.create(
        deployment=dep, fingerprint="fp1", finding_type="xss", title="XSS",
        severity="high", location="https://app.example/search",
    )
    derive_assets(dep, scan)
    endpoint = dep.assets.get(kind=Asset.Kind.API, identifier="app.example/search")
    finding.refresh_from_db()
    assert finding.asset_id == endpoint.pk


def test_finding_without_location_attaches_to_the_host_asset():
    user = _user()
    dep = Deployment.objects.create(name="d", owner=user)
    scan = PentestScan.objects.create(user=user, target_url="https://app.example/", consent=True)
    finding = Finding.objects.create(
        deployment=dep, fingerprint="fp1", finding_type="x", title="X", severity="low"
    )
    derive_assets(dep, scan)
    host = dep.assets.get(kind=Asset.Kind.API, identifier="app.example")
    finding.refresh_from_db()
    assert finding.asset_id == host.pk


def test_derive_is_idempotent_and_preserves_human_classification():
    user = _user()
    dep = Deployment.objects.create(name="d", owner=user)
    scan = PentestScan.objects.create(user=user, target_url="https://app.example/", consent=True)
    derive_assets(dep, scan)
    host = dep.assets.get(identifier="app.example")
    host.classification = Asset.Classification.HIGH_RISK  # a human reclassifies
    host.save()

    derive_assets(dep, scan)  # re-scan
    assert dep.assets.filter(identifier="app.example").count() == 1  # no duplicate
    host.refresh_from_db()
    assert host.classification == Asset.Classification.HIGH_RISK  # human decision preserved


def test_declared_llm_target_becomes_a_model_provider_and_asset():
    user = _user()
    dep = Deployment.objects.create(name="d", owner=user)
    scan = PentestScan.objects.create(
        user=user, target_url="https://api.llm.test/v1", consent=True,
        target_config={"kind": "llm", "adapter": "openai_style",
                       "base_url": "https://api.llm.test/v1", "model": "gpt-x"},
    )
    finding = Finding.objects.create(
        deployment=dep, fingerprint="fp1", finding_type="prompt_injection",
        title="Prompt injection", severity="high",
    )
    derive_assets(dep, scan)

    model_asset = dep.assets.get(kind=Asset.Kind.MODEL)
    assert model_asset.name == "gpt-x"
    assert model_asset.provider is not None
    assert model_asset.provider.kind == Provider.Kind.MODEL_PROVIDER
    # Declared, not measured.
    assert model_asset.provider.evidence_class == Provider.evidence_class.field.default
    assert model_asset.metadata.get("adapter") == "openai_style"
    finding.refresh_from_db()
    assert finding.asset_id == model_asset.pk  # the LLM finding belongs to the model


def test_ingesting_a_scan_populates_assets_end_to_end():
    user = _user()
    eng = Engagement.objects.create(name="Acme", created_by=user, scope_hosts=["client.example"])
    ingest.ingest_scan(_scan(user, "https://app.client.example/login", engagement=eng))
    dep = Deployment.objects.get()
    assert dep.assets.filter(kind=Asset.Kind.API, identifier="app.client.example").exists()
    assert dep.findings.get().asset is not None  # the finding was attached


def test_asset_api_lists_with_finding_count_and_scopes():
    admin = _user("boss", role=User.Roles.ADMIN)
    eng = Engagement.objects.create(name="Acme", created_by=admin, scope_hosts=["client.example"])
    ingest.ingest_scan(_scan(admin, "https://app.client.example/login", engagement=eng))

    factory = APIRequestFactory()
    view = AssetViewSet.as_view({"get": "list"})
    request = factory.get("/api/assurance/assets/?kind=api")
    force_authenticate(request, user=admin)
    resp = view(request)
    assert resp.status_code == 200
    rows = resp.data["results"] if isinstance(resp.data, dict) else resp.data
    host = next(r for r in rows if r["identifier"] == "app.client.example")
    assert host["classification"] == "known"
    assert host["finding_count"] == 1

    # A viewer who owns nothing sees no assets.
    viewer = _user("viewer", role=User.Roles.VIEWER)
    vreq = factory.get("/api/assurance/assets/")
    force_authenticate(vreq, user=viewer)
    vresp = view(vreq)
    count = vresp.data["count"] if isinstance(vresp.data, dict) else len(vresp.data)
    assert count == 0


def test_llm_scan_view_is_fixed_and_persists_its_declared_target():
    """The old view passed a `target=` kwarg the model has no field for (a 500);
    it now stores the base_url as target_url and the declared config."""
    user = _user()
    factory = APIRequestFactory()
    engine_response = {"findings": [
        {"type": "prompt_injection", "signature_id": "P1", "report_severity": "high",
         "signature_description": "Prompt injection"},
    ]}
    with mock.patch("pentest.views_llm.CyberEngineClient") as Client:
        Client.return_value.run_llm_scan.return_value = engine_response
        request = factory.post(
            "/api/llm-scan",
            {"base_url": "https://api.llm.test/v1", "model": "gpt-x", "adapter": "openai_style"},
            format="json",
        )
        force_authenticate(request, user=user)
        resp = PentestLLMScanView.as_view()(request)

    assert resp.status_code == 201
    scan = PentestScan.objects.get(id=resp.data["scan_id"])
    assert scan.status == PentestScan.STATUS_COMPLETED
    assert scan.target_url == "https://api.llm.test/v1"
    assert scan.target_config["model"] == "gpt-x"
    assert scan.target_config["kind"] == "llm"
