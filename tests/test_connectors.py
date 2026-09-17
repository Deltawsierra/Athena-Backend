"""Commercial spine — the outbound connector framework, proven WITHOUT network.

Every push here goes through an injected :class:`FakeTransport`; no test ever
constructs a real transport or reaches a live service. The fake records the exact
call (url, headers, json), so a test asserts the request an adapter *formatted*
and the :class:`~assurance.connectors.ConnectorResult` it *parsed* — the whole
adapter contract — with nothing on the wire.

The safety property the roadmap directive turns on is exercised directly: an
**unconfigured** connector returns ``ok=False, "<name> not configured"`` and makes
**no** transport call at all (``FakeTransport.calls == []``). Inert by default.
"""

from __future__ import annotations

from typing import Any

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.connectors import (
    ConnectorResult,
    GitHubIssuesConfig,
    GitHubIssuesConnector,
    JiraConfig,
    JiraConnector,
    ServiceNowConfig,
    ServiceNowConnector,
    SplunkConfig,
    SplunkConnector,
    UnknownConnector,
    WebhookConfig,
    WebhookConnector,
    available_connectors,
    build_connector,
    get_connector_class,
)
from assurance.models import Deployment, Finding
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


# ---------------------------------------------------------------------------
# The fake transport — the ONLY transport in these tests
# ---------------------------------------------------------------------------


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
    """Records every ``post`` and returns queued responses. If a test asserts an
    adapter is inert, ``calls`` stays empty — the proof no network was touched."""

    def __init__(self, *responses: FakeResponse):
        self._responses = list(responses)
        self.calls: list[dict] = []

    def post(self, url, *, headers, json) -> FakeResponse:
        self.calls.append({"url": url, "headers": headers, "json": json})
        if self._responses:
            return self._responses.pop(0)
        return FakeResponse(200, {})


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _deployment(owner):
    return Deployment.objects.create(
        name="checkout-assistant",
        owner=owner,
        environment=Deployment.Environment.PRODUCTION,
    )


def _finding(dep):
    return Finding.objects.create(
        deployment=dep,
        fingerprint="fp1",
        finding_type="prompt_injection",
        title="Prompt injection via tool description",
        severity="high",
        impact="An attacker can steer the agent through a poisoned tool description.",
        recommendation="Sanitise tool metadata before it reaches the planner.",
        control_mapping={"owasp-llm": ["LLM01"], "mitre": ["T1059"]},
        location="/agent/tools",
    )


@pytest.fixture()
def finding():
    owner = _user("owner", role=User.Roles.ADMIN)
    return _finding(_deployment(owner))


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


def test_registry_maps_names_to_classes():
    assert get_connector_class("jira") is JiraConnector
    assert get_connector_class("servicenow") is ServiceNowConnector
    assert get_connector_class("github_issues") is GitHubIssuesConnector
    assert get_connector_class("splunk") is SplunkConnector
    assert get_connector_class("webhook") is WebhookConnector
    assert available_connectors() == [
        "github_issues",
        "jira",
        "servicenow",
        "splunk",
        "webhook",
    ]


def test_build_connector_returns_the_right_class():
    assert isinstance(build_connector("jira"), JiraConnector)
    assert isinstance(build_connector("webhook"), WebhookConnector)


def test_unknown_connector_name_errors_clearly():
    with pytest.raises(UnknownConnector) as exc:
        get_connector_class("pagerduty")
    assert "pagerduty" in str(exc.value)
    # The error names what IS available rather than failing blind.
    assert "jira" in str(exc.value)
    with pytest.raises(UnknownConnector):
        build_connector("nope")


# ---------------------------------------------------------------------------
# Inert by default — the safety property
# ---------------------------------------------------------------------------


def test_unconfigured_connector_is_inert_and_makes_no_call(finding):
    # Built from settings/env, which carry no connector credentials in this repo.
    for name in available_connectors():
        conn = build_connector(name)
        assert conn.configured is False
        transport = FakeTransport()
        result = conn.push_finding(finding, transport=transport)
        assert result.ok is False
        assert result.detail == f"{name} not configured"
        assert result.connector == name
        assert result.external_ref is None
        # The proof: the transport was NEVER called.
        assert transport.calls == []


def test_unconfigured_webhook_receipt_is_also_inert():
    conn = WebhookConnector(WebhookConfig())  # no url
    transport = FakeTransport()
    result = conn.push_receipt({"digest": "abc"}, transport=transport)
    assert result.ok is False
    assert result.detail == "webhook not configured"
    assert transport.calls == []


# ---------------------------------------------------------------------------
# Jira
# ---------------------------------------------------------------------------


def test_jira_formats_request_and_parses_success(finding):
    conn = JiraConnector(JiraConfig(base_url="https://jira.example/", project_key="SEC", token="t0k"))
    transport = FakeTransport(FakeResponse(201, {"key": "SEC-42"}))
    result = conn.push_finding(finding, transport=transport)

    assert len(transport.calls) == 1
    call = transport.calls[0]
    assert call["url"] == "https://jira.example/rest/api/2/issue"
    assert call["headers"]["Authorization"] == "Bearer t0k"
    fields = call["json"]["fields"]
    assert fields["project"] == {"key": "SEC"}
    assert fields["issuetype"] == {"name": "Bug"}
    assert fields["priority"] == {"name": "High"}  # high severity mapped
    assert fields["summary"] == finding.title
    # The narrative (impact + recommendation + controls) rides in the description.
    assert "poisoned tool description" in fields["description"]
    assert "owasp-llm: LLM01" in fields["description"]
    assert "severity-high" in fields["labels"]

    assert result == ConnectorResult(ok=True, external_ref="SEC-42", detail="jira issue SEC-42 created", connector="jira")


def test_jira_maps_an_error_response(finding):
    conn = JiraConnector(JiraConfig(base_url="https://jira.example", project_key="SEC", token="t0k"))
    transport = FakeTransport(FakeResponse(400, {}, text="project required"))
    result = conn.push_finding(finding, transport=transport)
    assert len(transport.calls) == 1
    assert result.ok is False
    assert result.external_ref is None
    assert "400" in result.detail and "project required" in result.detail


# ---------------------------------------------------------------------------
# ServiceNow
# ---------------------------------------------------------------------------


def test_servicenow_formats_request_and_parses_success(finding):
    conn = ServiceNowConnector(
        ServiceNowConfig(base_url="https://acme.service-now.com", table="incident", token="snow")
    )
    transport = FakeTransport(FakeResponse(201, {"result": {"sys_id": "abc123"}}))
    result = conn.push_finding(finding, transport=transport)

    call = transport.calls[0]
    assert call["url"] == "https://acme.service-now.com/api/now/table/incident"
    assert call["headers"]["Authorization"] == "Bearer snow"
    assert call["json"]["short_description"] == finding.title
    assert call["json"]["impact"] == "1"  # high -> 1
    assert call["json"]["correlation_id"] == str(finding.uuid)
    assert result.ok is True
    assert result.external_ref == "abc123"


def test_servicenow_maps_an_error_response(finding):
    conn = ServiceNowConnector(ServiceNowConfig(base_url="https://acme.service-now.com", table="incident", token="s"))
    transport = FakeTransport(FakeResponse(401, {}, text="unauthorized"))
    result = conn.push_finding(finding, transport=transport)
    assert result.ok is False
    assert "401" in result.detail


# ---------------------------------------------------------------------------
# GitHub Issues
# ---------------------------------------------------------------------------


def test_github_formats_request_and_parses_success(finding):
    conn = GitHubIssuesConnector(
        GitHubIssuesConfig(base_url="https://api.github.com", owner="acme", repo="app", token="gh")
    )
    transport = FakeTransport(FakeResponse(201, {"number": 7, "html_url": "https://github.com/acme/app/issues/7"}))
    result = conn.push_finding(finding, transport=transport)

    call = transport.calls[0]
    assert call["url"] == "https://api.github.com/repos/acme/app/issues"
    assert call["headers"]["Authorization"] == "Bearer gh"
    assert call["json"]["title"] == finding.title
    assert "severity:high" in call["json"]["labels"]
    assert result.ok is True
    assert result.external_ref == "7"


def test_github_maps_an_error_response(finding):
    conn = GitHubIssuesConnector(GitHubIssuesConfig(base_url="https://api.github.com", owner="a", repo="b", token="x"))
    transport = FakeTransport(FakeResponse(422, {}, text="validation failed"))
    result = conn.push_finding(finding, transport=transport)
    assert result.ok is False
    assert "422" in result.detail


# ---------------------------------------------------------------------------
# Splunk (HEC)
# ---------------------------------------------------------------------------


def test_splunk_formats_hec_event_and_parses_success(finding):
    conn = SplunkConnector(SplunkConfig(base_url="https://splunk.example:8088", token="hec-tok", index="sec"))
    transport = FakeTransport(FakeResponse(200, {"text": "Success", "code": 0}))
    result = conn.push_finding(finding, transport=transport)

    call = transport.calls[0]
    assert call["url"] == "https://splunk.example:8088/services/collector/event"
    # HEC uses the Splunk scheme, not Bearer.
    assert call["headers"]["Authorization"] == "Splunk hec-tok"
    assert call["json"]["event"]["title"] == finding.title
    assert call["json"]["event"]["severity"] == "high"
    assert call["json"]["index"] == "sec"
    assert result.ok is True


def test_splunk_treats_nonzero_hec_code_as_rejected(finding):
    conn = SplunkConnector(SplunkConfig(base_url="https://splunk.example:8088", token="hec-tok"))
    # A 2xx with a non-zero HEC code is a REJECTED event, not an accepted one.
    transport = FakeTransport(FakeResponse(200, {"text": "Incorrect index", "code": 7}))
    result = conn.push_finding(finding, transport=transport)
    assert result.ok is False
    assert "splunk rejected" in result.detail


def test_splunk_maps_a_transport_level_error(finding):
    conn = SplunkConnector(SplunkConfig(base_url="https://splunk.example:8088", token="hec-tok"))
    transport = FakeTransport(FakeResponse(403, {}, text="forbidden"))
    result = conn.push_finding(finding, transport=transport)
    assert result.ok is False
    assert "403" in result.detail


# ---------------------------------------------------------------------------
# Generic webhook
# ---------------------------------------------------------------------------


def test_webhook_posts_finding_with_optional_secret_header(finding):
    conn = WebhookConnector(WebhookConfig(url="https://hooks.example/athena", token="sh4red"))
    transport = FakeTransport(FakeResponse(200, {}))
    result = conn.push_finding(finding, transport=transport)

    call = transport.calls[0]
    assert call["url"] == "https://hooks.example/athena"
    assert call["headers"]["X-Athena-Token"] == "sh4red"
    assert call["json"]["kind"] == "finding"
    assert call["json"]["finding"]["uuid"] == str(finding.uuid)
    assert result.ok is True


def test_webhook_omits_header_when_no_token(finding):
    conn = WebhookConnector(WebhookConfig(url="https://hooks.example/athena"))
    transport = FakeTransport(FakeResponse(204, {}))
    conn.push_finding(finding, transport=transport)
    assert "X-Athena-Token" not in transport.calls[0]["headers"]


def test_webhook_pushes_a_receipt():
    conn = WebhookConnector(WebhookConfig(url="https://hooks.example/athena"))
    transport = FakeTransport(FakeResponse(200, {}))
    result = conn.push_receipt({"digest": "deadbeef", "receipt_version": "x/1.0"}, transport=transport)
    call = transport.calls[0]
    assert call["json"]["kind"] == "receipt"
    assert call["json"]["receipt"]["digest"] == "deadbeef"
    assert result.ok is True


def test_transport_exception_is_reported_not_raised(finding):
    class BoomTransport:
        def __init__(self):
            self.calls = []

        def post(self, url, *, headers, json):
            self.calls.append(url)
            raise ConnectionError("network down")

    conn = WebhookConnector(WebhookConfig(url="https://hooks.example/athena"))
    result = conn.push_finding(finding, transport=BoomTransport())
    assert result.ok is False
    assert "transport error" in result.detail


# ---------------------------------------------------------------------------
# API — admin-only, inert without credentials
# ---------------------------------------------------------------------------


def test_push_endpoint_is_admin_only(finding):
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"post": "connector_push"})
    analyst = _user("ana", role=User.Roles.ANALYST)
    request = factory.post(
        f"/api/assurance/deployments/{finding.deployment.uuid}/connectors/jira/push",
        {"finding": str(finding.uuid)},
        format="json",
    )
    force_authenticate(request, user=analyst)
    resp = view(request, uuid=str(finding.deployment.uuid), connector="jira")
    assert resp.status_code == 403


def test_push_endpoint_reports_not_configured_without_creds(finding):
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"post": "connector_push"})
    admin = _user("boss", role=User.Roles.ADMIN)
    request = factory.post(
        f"/api/assurance/deployments/{finding.deployment.uuid}/connectors/jira/push",
        {"finding": str(finding.uuid)},
        format="json",
    )
    force_authenticate(request, user=admin)
    resp = view(request, uuid=str(finding.deployment.uuid), connector="jira")
    # House idiom: 200, read `ok`. No credentials in this repo -> inert.
    assert resp.status_code == 200
    assert resp.data["ok"] is False
    assert resp.data["detail"] == "jira not configured"


def test_push_endpoint_rejects_unknown_connector(finding):
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"post": "connector_push"})
    admin = _user("boss", role=User.Roles.ADMIN)
    request = factory.post(
        f"/api/assurance/deployments/{finding.deployment.uuid}/connectors/pagerduty/push",
        {"finding": str(finding.uuid)},
        format="json",
    )
    force_authenticate(request, user=admin)
    resp = view(request, uuid=str(finding.deployment.uuid), connector="pagerduty")
    assert resp.status_code == 400


def test_connectors_list_endpoint_reports_configured_state(finding):
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "connectors"})
    analyst = _user("ana", role=User.Roles.ANALYST)
    request = factory.get(f"/api/assurance/deployments/{finding.deployment.uuid}/connectors/")
    force_authenticate(request, user=analyst)
    resp = view(request, uuid=str(finding.deployment.uuid))
    assert resp.status_code == 200
    names = {c["name"] for c in resp.data["connectors"]}
    assert names == set(available_connectors())
    # All inert in this repo.
    assert all(c["configured"] is False for c in resp.data["connectors"])
