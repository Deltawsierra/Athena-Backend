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

import logging
import re
from dataclasses import dataclass
from typing import Any

from django.conf import settings

from .base import (
    Connector,
    ConnectorConfig,
    ConnectorResult,
    Response,
    error_detail,
    LookupRequest,
    finding_body,
    finding_marker,
    finding_summary,
    is_success,
)


logger = logging.getLogger(__name__)
_MARKER = re.compile(r"^athena-[0-9a-f]{6}-")


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
    secret_field = "token"
    settings_fields = ("base_url", "owner", "repo")

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
            # The marker in the body as well: a token without push access has its
            # labels dropped, and the body is where the look then finds it.
            "body": finding_body(summary) + f"\nAthena marker: {finding_marker(finding)}",
            # The marker label is how a lost answer or a second runner finds this
            # issue again instead of opening another (find_existing).
            "labels": ["athena", f"severity:{summary['severity']}", finding_marker(finding)],
        }
        return url, headers, payload

    def _lookup_requests(self, finding: Any):
        # First the issues LIST filtered by the marker label: read from the
        # repository itself, so an issue is there the moment it is created. A
        # token without push access has its labels silently dropped on create
        # (GitHub's documented behaviour), so "no labelled issue" is not the last
        # word: the marker is in the body too, and the search finds it there. The
        # search index lags a create by seconds; an uncertain push is only taken
        # as absent long after (see the dispatcher's age rule).
        cfg: GitHubIssuesConfig = self.config  # type: ignore[assignment]
        base = cfg.base_url.rstrip("/")
        headers = {"Authorization": f"Bearer {cfg.token}", "Accept": "application/vnd.github+json"}
        marker = finding_marker(finding)
        return [
            LookupRequest(
                f"{base}/repos/{cfg.owner}/{cfg.repo}/issues", headers,
                {"labels": marker, "state": "all", "per_page": 2}, "list", absent_means_next=True,
            ),
            LookupRequest(
                f"{base}/search/issues", headers,
                {"q": f'repo:{cfg.owner}/{cfg.repo} "{marker}" in:body type:issue', "per_page": 2}, "search",
            ),
        ]

    def _parse_lookup(self, body: Any, kind: str):
        items = body.get("items") if kind == "search" and isinstance(body, dict) else body
        if not isinstance(items, list):
            return None
        return [(str(item.get("number")), item.get("state") == "closed") for item in items]

    def _comment_request(self, ref: str, text: str):
        cfg: GitHubIssuesConfig = self.config  # type: ignore[assignment]
        url = f"{cfg.base_url.rstrip('/')}/repos/{cfg.owner}/{cfg.repo}/issues/{ref}/comments"
        headers = {
            "Authorization": f"Bearer {cfg.token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        }
        return url, headers, {"body": text}

    def _parse(self, response: Response) -> ConnectorResult:
        if is_success(response.status_code):
            try:
                body = response.json()
                number = body.get("number")
                labels = [label.get("name", "") for label in body.get("labels") or [] if isinstance(label, dict)]
            except Exception:  # noqa: BLE001
                number, labels = None, None
            ref = str(number) if number is not None else None
            detail = f"github issue #{number} created" if number is not None else "github issue created"
            if labels is not None and not any(_MARKER.match(name) for name in labels):
                # GitHub drops the labels of a token without push access, silently.
                # The number is recorded now, with this push; a later look finds the
                # issue by the marker in its body.
                detail += (
                    " -- WARNING: its marker label did not stick (does the token lack push access?); "
                    "it is recorded by number and found again by the marker in its body"
                )
                logger.warning("github issue #%s was created without its marker label", number)
            return ConnectorResult(ok=True, external_ref=ref, detail=detail, connector=self.name)
        return ConnectorResult(
            ok=False,
            external_ref=None,
            detail=error_detail(self.name, response),
            connector=self.name,
        )
