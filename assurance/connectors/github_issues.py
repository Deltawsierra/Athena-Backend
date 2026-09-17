"""GitHub Issues connector — a finding becomes a GitHub issue.

Formats the finding into a ``POST /repos/<owner>/<repo>/issues`` create call and
reads the created issue number back as the ``external_ref``. Config (API base URL,
owner, repo, token) comes from settings/env only; with none of it present the
connector is inert and reports ``github_issues not configured``.

The API base URL is configuration, not a default, so the same adapter serves
github.com (``https://api.github.com``) and a GitHub Enterprise host without a
committed hostname.
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
class GitHubIssuesConfig(ConnectorConfig):
    base_url: str | None = None
    owner: str | None = None
    repo: str | None = None
    token: str | None = None

    def is_configured(self) -> bool:
        return bool(self.base_url and self.owner and self.repo and self.token)


class GitHubIssuesConnector(Connector):
    name = "github_issues"
    config_class = GitHubIssuesConfig

    @classmethod
    def config_from_settings(cls) -> GitHubIssuesConfig:
        return GitHubIssuesConfig(
            base_url=getattr(settings, "CONNECTOR_GITHUB_API_URL", None),
            owner=getattr(settings, "CONNECTOR_GITHUB_OWNER", None),
            repo=getattr(settings, "CONNECTOR_GITHUB_REPO", None),
            token=getattr(settings, "CONNECTOR_GITHUB_TOKEN", None),
        )

    def _format_finding(self, finding: Any) -> tuple[str, dict, dict]:
        cfg: GitHubIssuesConfig = self.config  # type: ignore[assignment]
        summary = finding_summary(finding)
        url = f"{cfg.base_url.rstrip('/')}/repos/{cfg.owner}/{cfg.repo}/issues"
        headers = {
            "Authorization": f"Bearer {cfg.token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        }
        payload = {
            "title": summary["title"][:256],
            "body": finding_body(summary),
            "labels": ["athena", f"severity:{summary['severity']}"],
        }
        return url, headers, payload

    def _parse(self, response: Response) -> ConnectorResult:
        if is_success(response.status_code):
            try:
                number = response.json().get("number")
            except Exception:  # noqa: BLE001
                number = None
            ref = str(number) if number is not None else None
            return ConnectorResult(
                ok=True,
                external_ref=ref,
                detail=f"github issue #{number} created" if number is not None else "github issue created",
                connector=self.name,
            )
        return ConnectorResult(
            ok=False,
            external_ref=None,
            detail=error_detail(self.name, response),
            connector=self.name,
        )
