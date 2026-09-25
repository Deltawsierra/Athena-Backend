"""Commercial spine — per-tenant connector bindings, credential encryption, and the
automated-dispatch policy, proven WITHOUT any network.

Every push goes through an injected fake transport; no test constructs a real one
or reaches a live service. The properties under test are the ones that matter for
honesty and security:

- credentials are encrypted at rest and round-trip; with no key configured a
  binding cannot hold a secret and stays inert (never plaintext, never a fake pass);
- the dispatch trigger fires only for an enabled per-tenant policy on a qualifying
  finding, is idempotent (never double-pushes the same finding+connector), records
  every attempt honestly (sent / failed / skipped-inert / skipped-no-key), and a
  connector failure is recorded, not raised;
- the config CRUD API is admin-gated and never returns or accepts a plaintext
  secret in a non-write-only field.
"""

from __future__ import annotations

from typing import Any

import pytest
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import override_settings
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import crypto
from assurance.dispatch import (
    dispatch_finding,
    dispatch_for_blocking_decision,
    maybe_dispatch_finding,
)
from assurance.models import (
    ConnectorBinding,
    Deployment,
    DispatchAttempt,
    DispatchPolicy,
    Finding,
)
from assurance.views import DeploymentViewSet
from assurance.revision import accept_transition

pytestmark = pytest.mark.django_db

User = get_user_model()

# A real Fernet key, generated per test session. Only ever applied through
# override_settings, so the default (no key) posture is what the rest of the suite
# and the deployed default see.
TEST_KEY = Fernet.generate_key().decode()
with_key = override_settings(ASSURANCE_CREDENTIAL_KEY=TEST_KEY)


class FakeResponse:
    def __init__(self, status_code: int, body: Any = None, text: str = ""):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self._text = text

    def json(self) -> Any:
        return self._body

    @property
    def text(self) -> str:
        return self._text


class FakeTransport:
    """Records every post; the only transport in these tests."""

    def __init__(self, *responses: FakeResponse):
        self._responses = list(responses)
        self.calls: list[dict] = []

    def post(self, url, *, headers, json) -> FakeResponse:
        self.calls.append({"url": url, "headers": headers, "json": json})
        return self._responses.pop(0) if self._responses else FakeResponse(200, {})


def _admin(name="boss"):
    return User.objects.create_user(username=name, password="x", role=User.Roles.ADMIN)


def _deployment(owner):
    return Deployment.objects.create(
        name="checkout-assistant", owner=owner, environment=Deployment.Environment.PRODUCTION
    )


def _finding(dep, severity="high", **kw):
    defaults = dict(
        deployment=dep,
        fingerprint=f"fp-{severity}-{kw.get('title', 'x')}",
        finding_type="prompt_injection",
        title="Prompt injection via tool description",
        severity=severity,
        impact="An attacker can steer the agent.",
        recommendation="Sanitise tool metadata.",
        control_mapping={"owasp-llm": ["LLM01"]},
        location="/agent/tools",
    )
    defaults.update(kw)
    return Finding.objects.create(**defaults)


@pytest.fixture()
def deployment():
    return _deployment(_admin("owner"))


def _jira_binding(deployment, *, secret="jira-tok", enabled=True):
    binding = ConnectorBinding(
        deployment=deployment,
        connector="jira",
        enabled=enabled,
        endpoint={"base_url": "https://jira.example", "project_key": "SEC"},
    )
    if secret is not None:
        binding.set_secret(secret)  # requires a key in scope
    binding.save()
    return binding


# ---------------------------------------------------------------------------
# Encryption round-trip + the no-key inert path
# ---------------------------------------------------------------------------


def test_no_key_by_default_means_encryption_unavailable():
    # The suite's default settings carry no ASSURANCE_CREDENTIAL_KEY.
    assert crypto.encryption_available() is False
    # decrypt of anything is a safe None, and encrypt refuses rather than storing
    # plaintext.
    assert crypto.decrypt_secret("whatever") is None
    with pytest.raises(crypto.EncryptionUnavailable):
        crypto.encrypt_secret("s3cr3t")


@with_key
def test_encryption_round_trips_and_ciphertext_is_not_plaintext():
    assert crypto.encryption_available() is True
    token = crypto.encrypt_secret("s3cr3t-value")
    assert "s3cr3t-value" not in token  # never stored in the clear
    assert crypto.decrypt_secret(token) == "s3cr3t-value"


@with_key
def test_tampered_ciphertext_decrypts_to_none_not_a_crash():
    token = crypto.encrypt_secret("s3cr3t")
    assert crypto.decrypt_secret(token[:-4] + "AAAA") is None


def test_binding_set_secret_without_key_raises_and_stores_nothing(deployment):
    binding = ConnectorBinding(deployment=deployment, connector="jira", endpoint={})
    with pytest.raises(crypto.EncryptionUnavailable):
        binding.set_secret("jira-tok")
    assert binding.secret_ciphertext == ""


@with_key
def test_binding_is_operational_only_with_key_secret_and_fields(deployment):
    binding = _jira_binding(deployment)
    assert binding.has_secret is True
    assert binding.is_operational() is True
    # The stored column is ciphertext, never the plaintext token.
    assert "jira-tok" not in binding.secret_ciphertext
    assert binding.get_secret() == "jira-tok"


@with_key
def test_binding_with_secret_is_inert_when_key_disappears(deployment):
    binding = _jira_binding(deployment)
    assert binding.is_operational() is True
    # Remove the key: the stored credential can no longer be read, so the binding
    # is inert — never a plaintext fallback, never a fake pass.
    with override_settings(ASSURANCE_CREDENTIAL_KEY=""):
        assert binding.get_secret() is None
        assert binding.is_operational() is False


# ---------------------------------------------------------------------------
# Dispatch — trigger, idempotency, recording, resilience
# ---------------------------------------------------------------------------


@with_key
def test_dispatch_sends_to_operational_binding_and_records_sent(deployment):
    _jira_binding(deployment)
    finding = _finding(deployment)
    transport = FakeTransport(FakeResponse(201, {"key": "SEC-1"}))
    attempts = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=lambda: transport
    )
    assert len(attempts) == 1
    assert len(transport.calls) == 1  # exactly one outbound push
    a = attempts[0]
    assert a.outcome == DispatchAttempt.Outcome.SENT
    assert a.external_ref == "SEC-1"
    assert a.connector == "jira"


@with_key
def test_dispatch_is_idempotent_never_double_pushes(deployment):
    _jira_binding(deployment)
    finding = _finding(deployment)
    t1 = FakeTransport(FakeResponse(201, {"key": "SEC-1"}))
    dispatch_finding(finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=lambda: t1)
    # A second dispatch of the same finding+connector must NOT push again.
    t2 = FakeTransport(FakeResponse(201, {"key": "SEC-999"}))
    dispatch_finding(finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=lambda: t2)
    assert t2.calls == []  # the proof: no second outbound call
    assert DispatchAttempt.objects.filter(finding=finding, connector="jira").count() == 1
    a = DispatchAttempt.objects.get(finding=finding, connector="jira")
    assert a.outcome == DispatchAttempt.Outcome.SENT
    assert a.attempts == 1  # terminal, never re-attempted


@with_key
def test_connector_failure_is_recorded_not_raised(deployment):
    _jira_binding(deployment)
    finding = _finding(deployment)
    transport = FakeTransport(FakeResponse(400, {}, text="project required"))
    attempts = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=lambda: transport
    )
    assert attempts[0].outcome == DispatchAttempt.Outcome.FAILED
    assert "400" in attempts[0].detail


@with_key
def test_transport_exception_is_recorded_not_raised(deployment):
    """A connector never raises out of a push -- the original point of this test.

    What it records has become more precise: a bare ``ConnectionError`` says the
    connection broke and not WHEN, so the request may already have been on the
    wire and the provider may have committed it. That is UNKNOWN, not FAILED,
    because recording it FAILED is what licenses a retry that double-executes
    (Phase 3 item 8). The certain cases are covered in
    tests/test_dispatch_unknown_outcome.py.
    """
    _jira_binding(deployment)
    finding = _finding(deployment)

    class BoomTransport:
        def post(self, url, *, headers, json):
            raise ConnectionError("network down")

    attempts = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=lambda: BoomTransport()
    )
    assert attempts[0].outcome == DispatchAttempt.Outcome.UNKNOWN
    assert "transport error" in attempts[0].detail


@with_key
def test_a_refused_connection_is_recorded_as_a_plain_failure(deployment):
    """The one builtin case that is unambiguous: the peer refused, so nothing was
    sent, so this stays FAILED and stays retryable."""
    _jira_binding(deployment)
    finding = _finding(deployment)

    class RefusedTransport:
        def post(self, url, *, headers, json):
            raise ConnectionRefusedError("refused")

    attempts = dispatch_finding(
        finding,
        trigger=DispatchAttempt.Trigger.SEVERITY,
        transport_factory=lambda: RefusedTransport(),
    )
    assert attempts[0].outcome == DispatchAttempt.Outcome.FAILED
    assert attempts[0].blocks_retry is False


@with_key
def test_inert_binding_records_skipped_and_touches_no_transport(deployment):
    # A binding with no secret is inert even with a key configured.
    ConnectorBinding.objects.create(
        deployment=deployment,
        connector="jira",
        endpoint={"base_url": "https://jira.example", "project_key": "SEC"},
    )
    finding = _finding(deployment)
    transport = FakeTransport(FakeResponse(201, {"key": "X"}))
    attempts = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=lambda: transport
    )
    assert transport.calls == []  # never touched
    assert attempts[0].outcome == DispatchAttempt.Outcome.SKIPPED_INERT
    assert attempts[0].detail == "jira not configured"


def test_no_key_records_skipped_no_key_and_touches_no_transport(deployment):
    # A binding created under a key, then read with no key configured, records the
    # honest skipped_no_key rather than any push. We build the ciphertext under a
    # key, persist it, then dispatch with the default (no-key) settings.
    with with_key:
        _jira_binding(deployment)
    finding = _finding(deployment)
    transport = FakeTransport(FakeResponse(201, {"key": "X"}))
    attempts = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=lambda: transport
    )
    assert transport.calls == []
    assert attempts[0].outcome == DispatchAttempt.Outcome.SKIPPED_NO_KEY


@with_key
def test_disabled_binding_records_skipped_disabled(deployment):
    _jira_binding(deployment, enabled=False)
    finding = _finding(deployment)
    transport = FakeTransport(FakeResponse(201, {"key": "X"}))
    attempts = dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.SEVERITY, transport_factory=lambda: transport
    )
    assert transport.calls == []
    assert attempts[0].outcome == DispatchAttempt.Outcome.SKIPPED_DISABLED


# ---------------------------------------------------------------------------
# Policy gating
# ---------------------------------------------------------------------------


@with_key
def test_maybe_dispatch_is_noop_without_policy(deployment):
    _jira_binding(deployment)
    finding = _finding(deployment)
    assert maybe_dispatch_finding(finding, transport_factory=lambda: FakeTransport()) == []
    assert DispatchAttempt.objects.count() == 0


@with_key
def test_maybe_dispatch_is_noop_when_policy_disabled(deployment):
    _jira_binding(deployment)
    DispatchPolicy.objects.create(deployment=deployment, enabled=False, min_severity="high")
    finding = _finding(deployment)
    assert maybe_dispatch_finding(finding, transport_factory=lambda: FakeTransport()) == []
    assert DispatchAttempt.objects.count() == 0


@with_key
def test_maybe_dispatch_respects_severity_threshold(deployment):
    _jira_binding(deployment)
    DispatchPolicy.objects.create(deployment=deployment, enabled=True, min_severity="high")
    low = _finding(deployment, severity="low", title="low")
    assert maybe_dispatch_finding(low, transport_factory=lambda: FakeTransport()) == []
    high = _finding(deployment, severity="high", title="high")
    transport = FakeTransport(FakeResponse(201, {"key": "SEC-2"}))
    attempts = maybe_dispatch_finding(high, transport_factory=lambda: transport)
    assert len(attempts) == 1 and attempts[0].outcome == DispatchAttempt.Outcome.SENT


@with_key
def test_blocking_decision_trigger_dispatches_active_qualifying_findings(deployment):
    _jira_binding(deployment)
    DispatchPolicy.objects.create(
        deployment=deployment, enabled=True, min_severity="high", on_blocking_decision=True
    )
    _finding(deployment, severity="high", title="a")
    # Through the boundary: `Deployment.save` refuses the decision columns.
    accept_transition(deployment, to_decision=Deployment.Decision.NEEDS_REMEDIATION)
    transport = FakeTransport(FakeResponse(201, {"key": "SEC-3"}))
    attempts = dispatch_for_blocking_decision(deployment, transport_factory=lambda: transport)
    assert len(attempts) == 1 and attempts[0].outcome == DispatchAttempt.Outcome.SENT
    # Not-blocking decision → no-op.
    accept_transition(deployment, to_decision=Deployment.Decision.READY)
    assert dispatch_for_blocking_decision(deployment, transport_factory=lambda: FakeTransport()) == []


# ---------------------------------------------------------------------------
# Config CRUD API — admin-gated, write-only secret, never leaks a value
# ---------------------------------------------------------------------------


def _put_config(user, deployment, connector, body):
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"put": "connector_config"})
    request = factory.put(
        f"/api/assurance/deployments/{deployment.uuid}/connectors/{connector}/config",
        body,
        format="json",
    )
    force_authenticate(request, user=user)
    return view(request, uuid=str(deployment.uuid), connector=connector)


def test_connector_config_put_is_admin_only(deployment):
    analyst = User.objects.create_user(username="ana", password="x", role=User.Roles.ANALYST)
    resp = _put_config(analyst, deployment, "jira", {"enabled": True})
    assert resp.status_code == 403


@with_key
def test_connector_config_put_stores_secret_write_only(deployment):
    admin = _admin()
    resp = _put_config(
        admin,
        deployment,
        "jira",
        {"endpoint": {"base_url": "https://jira.example", "project_key": "SEC"}, "secret": "jira-tok"},
    )
    assert resp.status_code in (200, 201)
    # The response reveals only that a secret is on file, never its value.
    assert resp.data["has_secret"] is True
    assert resp.data["operational"] is True
    assert "secret" not in resp.data
    assert "jira-tok" not in str(resp.data)
    binding = ConnectorBinding.objects.get(deployment=deployment, connector="jira")
    assert "jira-tok" not in binding.secret_ciphertext
    assert binding.get_secret() == "jira-tok"


def test_connector_config_put_refuses_secret_without_key(deployment):
    admin = _admin()
    resp = _put_config(admin, deployment, "jira", {"secret": "jira-tok"})
    assert resp.status_code == 400
    assert "encryption key" in resp.data["detail"].lower()
    assert not ConnectorBinding.objects.filter(deployment=deployment).exists()


def test_connector_config_put_rejects_secret_in_endpoint(deployment):
    admin = _admin()
    resp = _put_config(
        admin, deployment, "jira", {"endpoint": {"base_url": "https://j", "token": "leak"}}
    )
    assert resp.status_code == 400
    assert "credential" in resp.data["detail"].lower()


def test_connector_config_rejects_unknown_connector(deployment):
    admin = _admin()
    resp = _put_config(admin, deployment, "pagerduty", {"enabled": True})
    assert resp.status_code == 400


@with_key
def test_connector_config_get_and_delete(deployment):
    admin = _admin()
    _put_config(
        admin, deployment, "jira",
        {"endpoint": {"base_url": "https://jira.example", "project_key": "SEC"}, "secret": "t"},
    )
    factory = APIRequestFactory()
    get_view = DeploymentViewSet.as_view({"get": "connector_config"})
    req = factory.get(f"/api/assurance/deployments/{deployment.uuid}/connectors/jira/config")
    force_authenticate(req, user=admin)
    resp = get_view(req, uuid=str(deployment.uuid), connector="jira")
    assert resp.status_code == 200 and resp.data["has_secret"] is True
    assert "secret" not in resp.data

    del_view = DeploymentViewSet.as_view({"delete": "connector_config"})
    dreq = factory.delete(f"/api/assurance/deployments/{deployment.uuid}/connectors/jira/config")
    force_authenticate(dreq, user=admin)
    dresp = del_view(dreq, uuid=str(deployment.uuid), connector="jira")
    assert dresp.status_code == 204
    assert not ConnectorBinding.objects.filter(deployment=deployment).exists()


@with_key
def test_connectors_list_reports_binding_configured_state(deployment):
    _jira_binding(deployment)
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "connectors"})
    req = factory.get(f"/api/assurance/deployments/{deployment.uuid}/connectors/")
    force_authenticate(req, user=_admin())
    resp = view(req, uuid=str(deployment.uuid))
    rows = {r["name"]: r for r in resp.data["connectors"]}
    assert rows["jira"]["configured"] is True
    assert rows["jira"]["binding_operational"] is True
    assert rows["jira"]["has_secret"] is True
    # Every other connector remains inert.
    assert rows["webhook"]["configured"] is False


# ---------------------------------------------------------------------------
# Dispatch policy + attempts API
# ---------------------------------------------------------------------------


def test_dispatch_policy_get_default_is_off(deployment):
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "dispatch_policy"})
    req = factory.get(f"/api/assurance/deployments/{deployment.uuid}/dispatch-policy")
    force_authenticate(req, user=_admin())
    resp = view(req, uuid=str(deployment.uuid))
    assert resp.data["configured"] is False and resp.data["enabled"] is False


def test_dispatch_policy_put_is_admin_only(deployment):
    analyst = User.objects.create_user(username="ana", password="x", role=User.Roles.ANALYST)
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"put": "dispatch_policy"})
    req = factory.put(
        f"/api/assurance/deployments/{deployment.uuid}/dispatch-policy",
        {"enabled": True}, format="json",
    )
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(deployment.uuid))
    assert resp.status_code == 403


@with_key
def test_finding_post_save_signal_auto_dispatches_on_commit(
    deployment, monkeypatch, django_capture_on_commit_callbacks
):
    """The full automatic path: a qualifying finding, saved under an enabled policy
    with an operational binding, is dispatched on commit. Hermetic — the default
    transport is monkeypatched to a fake, so NO real network call is ever made."""
    import assurance.dispatch as dispatch_mod

    transport = FakeTransport(FakeResponse(201, {"key": "SEC-7"}))
    monkeypatch.setattr(dispatch_mod, "_default_transport_factory", lambda: transport)

    _jira_binding(deployment)
    DispatchPolicy.objects.create(deployment=deployment, enabled=True, min_severity="high")

    with django_capture_on_commit_callbacks(execute=True):
        _finding(deployment, severity="high", title="signal")

    assert len(transport.calls) == 1  # the signal fired and pushed once
    attempt = DispatchAttempt.objects.get(connector="jira")
    assert attempt.outcome == DispatchAttempt.Outcome.SENT
    assert attempt.trigger == DispatchAttempt.Trigger.SEVERITY


@with_key
def test_finding_post_save_signal_is_inert_without_policy(
    deployment, django_capture_on_commit_callbacks
):
    """With no policy — the default — the signal fires but does nothing: no
    dispatch record, no outbound. The honesty invariant end-to-end."""
    _jira_binding(deployment)
    with django_capture_on_commit_callbacks(execute=True):
        _finding(deployment, severity="high", title="nopolicy")
    assert DispatchAttempt.objects.count() == 0


@with_key
def test_dispatch_attempts_endpoint_surfaces_records(deployment):
    _jira_binding(deployment)
    finding = _finding(deployment)
    dispatch_finding(
        finding, trigger=DispatchAttempt.Trigger.SEVERITY,
        transport_factory=lambda: FakeTransport(FakeResponse(201, {"key": "SEC-1"})),
    )
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "dispatch_attempts"})
    req = factory.get(f"/api/assurance/deployments/{deployment.uuid}/dispatch-attempts")
    force_authenticate(req, user=_admin())
    resp = view(req, uuid=str(deployment.uuid))
    assert len(resp.data["attempts"]) == 1
    row = resp.data["attempts"][0]
    assert row["connector"] == "jira" and row["outcome"] == "sent"
    assert row["external_ref"] == "SEC-1"
