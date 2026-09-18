"""Live posture wiring — per-tenant posture bindings and the injectable fetcher,
proven WITHOUT any network.

A configured domain (an operational per-tenant binding) is assessed against the
resource the binding points at, through an INJECTED fetcher — a fake here, never a
real HTTP client. The honesty invariant is held: an unconfigured domain (the
default) is inert (``connected: false``, catalog only), a "no findings" result is
never a pass, and a fetch error reads ``unknown``, not a clean pass. No test makes
a real outbound call, and the default (no-key, no-binding) behaviour is unchanged.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import override_settings
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.models import Deployment, PostureBinding
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()

TEST_KEY = Fernet.generate_key().decode()
with_key = override_settings(ASSURANCE_CREDENTIAL_KEY=TEST_KEY)


class _Resp:
    def __init__(self, body: Any, status_code: int = 200):
        self._body = body if body is not None else {}
        self.status_code = status_code

    def json(self) -> Any:
        return self._body


class FixtureFetcher:
    """Canned posture data per resource, records reads. The ONLY fetcher here."""

    def __init__(self, fixture: dict[str, Any]):
        self.fixture = fixture
        self.calls: list[str] = []

    def fetch(self, resource: str, *, params: dict | None = None) -> _Resp:
        self.calls.append(resource)
        return _Resp(self.fixture.get(resource, {}))


class BoomFetcher:
    """Every read raises — a fetch that fails must read unknown, never pass."""

    def fetch(self, resource: str, *, params: dict | None = None):
        raise ConnectionError("upstream down")


CLOUD_FIXTURE = {
    "storage": {"buckets": [{"name": "assets", "public": True, "encrypted": True}]},
}


def _admin(name="boss"):
    return User.objects.create_user(username=name, password="x", role=User.Roles.ADMIN)


def _deployment(owner):
    return Deployment.objects.create(
        name="checkout-assistant", owner=owner, environment=Deployment.Environment.PRODUCTION
    )


@pytest.fixture()
def deployment():
    return _deployment(_admin("owner"))


def _cloud_binding(deployment, *, secret="cloud-tok"):
    binding = PostureBinding(
        deployment=deployment,
        domain="cloud",
        endpoint={"account": "acct-1", "base_url": "https://cloud.local"},
    )
    if secret is not None:
        binding.set_secret(secret)
    binding.save()
    return binding


# ---------------------------------------------------------------------------
# Binding-level: configured yields real findings, unconfigured is inert
# ---------------------------------------------------------------------------


@with_key
def test_configured_binding_assesses_live_and_emits_findings(deployment):
    binding = _cloud_binding(deployment)
    assert binding.is_operational() is True
    assessment = binding.build_assessment()
    fetcher = FixtureFetcher(CLOUD_FIXTURE)
    report = assessment.assess(fetcher=fetcher)
    assert report["connected"] is True
    assert fetcher.calls  # it actually read the live resource
    by_check = {f["check"]: f for f in report["findings"]}
    # A real, observed gap from the fixture — a publicly readable bucket.
    assert by_check["cloud_storage_public"]["status"] == "gap"


@with_key
def test_configured_binding_fetch_error_reads_unknown_not_pass(deployment):
    binding = _cloud_binding(deployment)
    report = binding.build_assessment().assess(fetcher=BoomFetcher())
    assert report["connected"] is True
    # Every check had no data (the fetch failed) → unknown, never pass.
    statuses = {f["status"] for f in report["findings"]}
    assert "pass" not in statuses
    assert statuses == {"unknown"}


def test_unconfigured_binding_is_inert_without_key(deployment):
    # A binding built under a key, then read with no key → inert (connected false).
    with with_key:
        binding = _cloud_binding(deployment)
    assert binding.is_operational() is False


# ---------------------------------------------------------------------------
# View-level: the configured path uses the binding; unconfigured stays inert
# ---------------------------------------------------------------------------


@with_key
def test_view_configured_path_uses_binding_and_injected_fetcher(deployment, monkeypatch):
    _cloud_binding(deployment)
    # Inject a fake fetcher so the configured path is exercised with ZERO network.
    monkeypatch.setattr(
        DeploymentViewSet,
        "_posture_fetcher_for",
        lambda self, binding: FixtureFetcher(CLOUD_FIXTURE),
    )
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "cloud_posture"})
    req = factory.get(f"/api/assurance/deployments/{deployment.uuid}/cloud-posture")
    force_authenticate(req, user=_admin())
    resp = view(req, uuid=str(deployment.uuid))
    assert resp.status_code == 200
    assert resp.data["connected"] is True
    by_check = {f["check"]: f for f in resp.data["findings"]}
    assert by_check["cloud_storage_public"]["status"] == "gap"


def test_view_unconfigured_posture_is_inert(deployment):
    # No binding, no key → the domain short-circuits before any fetcher: connected
    # false, catalog only, and no "pass" fabricated.
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "cloud_posture"})
    req = factory.get(f"/api/assurance/deployments/{deployment.uuid}/cloud-posture")
    force_authenticate(req, user=_admin())
    resp = view(req, uuid=str(deployment.uuid))
    assert resp.data["connected"] is False
    assert resp.data["findings"] == []
    assert resp.data["checks"]  # the catalog it WOULD run


# ---------------------------------------------------------------------------
# Posture config CRUD — admin-gated, write-only secret
# ---------------------------------------------------------------------------


def _put_config(user, deployment, domain, body):
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"put": "posture_config"})
    request = factory.put(
        f"/api/assurance/deployments/{deployment.uuid}/posture/{domain}/config",
        body, format="json",
    )
    force_authenticate(request, user=user)
    return view(request, uuid=str(deployment.uuid), domain=domain)


def test_posture_config_put_is_admin_only(deployment):
    analyst = User.objects.create_user(username="ana", password="x", role=User.Roles.ANALYST)
    resp = _put_config(analyst, deployment, "cloud", {"enabled": True})
    assert resp.status_code == 403


@with_key
def test_posture_config_put_stores_secret_write_only(deployment):
    admin = _admin()
    resp = _put_config(
        admin, deployment, "cloud",
        {"endpoint": {"account": "acct-1", "base_url": "https://cloud.local"}, "secret": "cloud-tok"},
    )
    assert resp.status_code in (200, 201)
    assert resp.data["has_secret"] is True
    assert resp.data["operational"] is True
    assert "cloud-tok" not in str(resp.data)
    binding = PostureBinding.objects.get(deployment=deployment, domain="cloud")
    assert "cloud-tok" not in binding.secret_ciphertext
    assert binding.get_secret() == "cloud-tok"


def test_posture_config_put_refuses_secret_without_key(deployment):
    admin = _admin()
    resp = _put_config(admin, deployment, "cloud", {"secret": "cloud-tok"})
    assert resp.status_code == 400
    assert "encryption key" in resp.data["detail"].lower()


def test_posture_config_rejects_unknown_domain(deployment):
    admin = _admin()
    resp = _put_config(admin, deployment, "kubernetes", {"enabled": True})
    assert resp.status_code == 400


@with_key
def test_posture_list_reports_binding_configured_state(deployment):
    _cloud_binding(deployment)
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "posture"})
    req = factory.get(f"/api/assurance/deployments/{deployment.uuid}/posture")
    force_authenticate(req, user=_admin())
    resp = view(req, uuid=str(deployment.uuid))
    rows = {r["name"]: r for r in resp.data["domains"]}
    assert rows["cloud"]["configured"] is True
    assert rows["cloud"]["binding_operational"] is True
    assert rows["secrets"]["configured"] is False
