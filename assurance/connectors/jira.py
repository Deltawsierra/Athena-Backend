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

from ..markers import legacy_labels, marker_for
from .base import (
    LOOK_PAGE_SIZE,
    Connector,
    ConnectorConfig,
    ConnectorResult,
    Hit,
    LookupRequest,
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
    secret_field = "token"
    settings_fields = ("base_url", "project_key", "issue_type")

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
        marker = marker_for(finding)
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
                # The marker's tag in the description: what makes this issue
                # verifiably this installation's (assurance.markers).
                "description": finding_body(summary) + f"\n{marker.body_line}",
                "issuetype": {"name": cfg.issue_type},
                "priority": {"name": _PRIORITY.get(summary["severity"], "Medium")},
                # The marker label is how a lost answer or a second runner finds
                # this issue again instead of creating another (find_existing).
                "labels": ["athena", f"severity-{summary['severity']}", marker.label],
            }
        }
        return url, headers, payload

    def _headers(self) -> dict:
        cfg: JiraConfig = self.config  # type: ignore[assignment]
        return {"Authorization": f"Bearer {cfg.token}", "Accept": "application/json"}

    def _lookup_requests(self, finding: Any):
        # Jira Cloud retired GET /rest/api/2/search (410 Gone, CHANGE-2046) for
        # /rest/api/3/search/jql; Data Center and Server have only the former
        # (404 on the new one). The new one first, the old one when it is missing.
        # One query finds every format this code has written: this marker's label,
        # round 2's `athena-<uuid>`, a bare uuid label, and -- for master's issues,
        # which carry no marker label -- the finding's uuid in their text. Oldest
        # first, so the original comes before any copy of it.
        cfg: JiraConfig = self.config  # type: ignore[assignment]
        base = cfg.base_url.rstrip("/")
        labels = ", ".join(f'"{label}"' for label in [marker_for(finding).label, *legacy_labels(finding)])
        params = {
            "jql": (
                f'project = "{cfg.project_key}" AND (labels in ({labels}) OR text ~ "\\"{finding.uuid}\\"") '
                "ORDER BY created ASC"
            ),
            "fields": "status,created,description",
            "maxResults": LOOK_PAGE_SIZE,
        }
        return [
            LookupRequest(f"{base}/rest/api/3/search/jql", self._headers(), dict(params), "v3", missing_means_next=True),
            LookupRequest(f"{base}/rest/api/2/search", self._headers(), {**params, "startAt": 0}, "v2"),
        ]

    def _fetch_request(self, ref: str):
        cfg: JiraConfig = self.config  # type: ignore[assignment]
        return LookupRequest(
            f"{cfg.base_url.rstrip('/')}/rest/api/2/issue/{ref}", self._headers(), {"fields": "status,created"}, "one"
        )

    @staticmethod
    def _hit(issue: dict) -> Hit:
        import json

        fields = issue.get("fields") or {}
        category = ((fields.get("status") or {}).get("statusCategory") or {}).get("key")
        description = fields.get("description")
        # v3 answers the description as a document (ADF), v2 as text: the marker
        # line is one run of text either way.
        text = description if isinstance(description, str) else json.dumps(description or "")
        return Hit(str(issue.get("key") or issue.get("id")), category == "done", fields.get("created"), text)

    def _parse_lookup(self, body: Any, kind: str):
        if kind == "one":
            return [self._hit(body)] if isinstance(body, dict) and (body.get("key") or body.get("id")) else None
        issues = body.get("issues") if isinstance(body, dict) else None
        if not isinstance(issues, list):
            return None
        return [self._hit(issue) for issue in issues if isinstance(issue, dict)]

    def _next_page(self, request, body, params, count):
        if request.kind == "v3":
            token = body.get("nextPageToken") if isinstance(body, dict) else None
            if not token or body.get("isLast"):
                return None
            return {**params, "nextPageToken": token}
        start = int(params.get("startAt", 0)) + count
        total = body.get("total") if isinstance(body, dict) else None
        if not count or (isinstance(total, int) and start >= total) or count < int(params["maxResults"]):
            return None
        return {**params, "startAt": start}

    def _comment_request(self, ref: str, text: str):
        cfg: JiraConfig = self.config  # type: ignore[assignment]
        url = f"{cfg.base_url.rstrip('/')}/rest/api/2/issue/{ref}/comment"
        headers = {
            "Authorization": f"Bearer {cfg.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        return url, headers, {"body": text}

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
