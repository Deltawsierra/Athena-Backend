"""Jira connector — a finding becomes a Jira issue.

Formats the finding into a Jira Cloud/DC REST ``POST /rest/api/2/issue`` create
call and reads the created issue key back as the ``external_ref``. Config (base
URL, project key, bearer token) comes from settings/env only; with none of it
present the connector is inert and reports ``jira not configured``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.conf import settings

from .base import (
    Connector,
    ConnectorConfig,
    ConnectorResult,
    Response,
    error_detail,
    finding_body,
    finding_summary,
    is_success,
)


@dataclass(frozen=True)
class JiraConfig(ConnectorConfig):
    base_url: str | None = None
    project_key: str | None = None
    token: str | None = None
    issue_type: str = "Bug"

    def is_configured(self) -> bool:
        return bool(self.base_url and self.project_key and self.token)


# Jira has no native "info/low/medium/high/critical" priority, so we map onto its
# default priority scheme. A mapping, not an invention: an unmapped severity falls
# back to the middle rather than silently dropping.
_PRIORITY = {
    "critical": "Highest",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Lowest",
}


class JiraConnector(Connector):
    name = "jira"
    config_class = JiraConfig

    @classmethod
    def config_from_settings(cls) -> JiraConfig:
        return JiraConfig(
            base_url=getattr(settings, "CONNECTOR_JIRA_URL", None),
            project_key=getattr(settings, "CONNECTOR_JIRA_PROJECT_KEY", None),
            token=getattr(settings, "CONNECTOR_JIRA_TOKEN", None),
            issue_type=getattr(settings, "CONNECTOR_JIRA_ISSUE_TYPE", None) or "Bug",
        )

    def _format_finding(self, finding: Any) -> tuple[str, dict, dict]:
        cfg: JiraConfig = self.config  # type: ignore[assignment]
        summary = finding_summary(finding)
        url = f"{cfg.base_url.rstrip('/')}/rest/api/2/issue"
        headers = {
            "Authorization": f"Bearer {cfg.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        payload = {
            "fields": {
                "project": {"key": cfg.project_key},
                "summary": summary["title"][:255],
                "description": finding_body(summary),
                "issuetype": {"name": cfg.issue_type},
                "priority": {"name": _PRIORITY.get(summary["severity"], "Medium")},
                "labels": ["athena", f"severity-{summary['severity']}"],
            }
        }
        return url, headers, payload

    def _parse(self, response: Response) -> ConnectorResult:
        if is_success(response.status_code):
            try:
                key = response.json().get("key")
            except Exception:  # noqa: BLE001
                key = None
            return ConnectorResult(
                ok=True,
                external_ref=key,
                detail=f"jira issue {key} created" if key else "jira issue created",
                connector=self.name,
            )
        return ConnectorResult(
            ok=False,
            external_ref=None,
            detail=error_detail(self.name, response),
            connector=self.name,
        )
