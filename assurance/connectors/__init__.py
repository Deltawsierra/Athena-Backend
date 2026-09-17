"""Commercial spine — outbound connectors.

Adapters that carry a finding (or an assurance receipt) into the systems a
customer already runs: Jira, ServiceNow, GitHub issues, Splunk (HEC), and a
generic webhook. Built adapter-only behind a clean, transport-injected interface:
production-quality formatting and parsing, exercised against a fake transport in
tests. **Inert by default** — with no configured credentials a connector makes no
network call and reports ``"<name> not configured"``. Live wiring (a real
transport bound to per-tenant credentials) is a documented, deferred follow-up.

See :mod:`assurance.connectors.base` for the :class:`Connector` /
:class:`Transport` / :class:`ConnectorResult` interface and the design contract.
"""

from __future__ import annotations

from .base import (
    Connector,
    ConnectorConfig,
    ConnectorResult,
    RequestsTransport,
    Response,
    Transport,
    finding_body,
    finding_summary,
)
from .github_issues import GitHubIssuesConfig, GitHubIssuesConnector
from .jira import JiraConfig, JiraConnector
from .registry import (
    UnknownConnector,
    available_connectors,
    build_connector,
    get_connector_class,
)
from .servicenow import ServiceNowConfig, ServiceNowConnector
from .splunk import SplunkConfig, SplunkConnector
from .webhook import WebhookConfig, WebhookConnector

__all__ = [
    "Connector",
    "ConnectorConfig",
    "ConnectorResult",
    "GitHubIssuesConfig",
    "GitHubIssuesConnector",
    "JiraConfig",
    "JiraConnector",
    "RequestsTransport",
    "Response",
    "ServiceNowConfig",
    "ServiceNowConnector",
    "SplunkConfig",
    "SplunkConnector",
    "Transport",
    "UnknownConnector",
    "WebhookConfig",
    "WebhookConnector",
    "available_connectors",
    "build_connector",
    "finding_body",
    "finding_summary",
    "get_connector_class",
]
