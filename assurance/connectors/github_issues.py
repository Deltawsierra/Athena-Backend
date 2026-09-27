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
        marker = marker_for(finding)
        url = f"{cfg.base_url.rstrip('/')}/repos/{cfg.owner}/{cfg.repo}/issues"
        headers = {
            "Authorization": f"Bearer {cfg.token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        }
        payload = {
            "title": summary["title"][:256],
            # The marker with its tag in the body: what makes this issue verifiably
            # this installation's (assurance.markers), and where the look finds it
            # when a token without push access has its labels dropped.
            "body": finding_body(summary) + f"\n{marker.body_line}",
            # The marker label is how a lost answer or a second runner finds this
            # issue again instead of opening another (find_existing).
            "labels": ["athena", f"severity:{summary['severity']}", marker.label],
        }
        return url, headers, payload

    def _headers(self) -> dict:
        cfg: GitHubIssuesConfig = self.config  # type: ignore[assignment]
        return {"Authorization": f"Bearer {cfg.token}", "Accept": "application/vnd.github+json"}

    def _lookup_requests(self, finding: Any):
        # First the issues LIST filtered by a label -- read from the repository
        # itself, so an issue is there the moment it is created: this marker's
        # label, then round 2's `athena-<uuid>` and a bare uuid label. Then the
        # SEARCH for the finding's uuid in bodies: every body this code has ever
        # written carries it ("Athena finding: <uuid>"), so it finds master's issues
        # (no marker label) and ones whose labels a token without push access had
        # dropped (GitHub's documented behaviour). The search index lags a create
        # by seconds; an uncertain push is only taken as absent long after (see the
        # dispatcher's age rule). Oldest first, 100 a page.
        cfg: GitHubIssuesConfig = self.config  # type: ignore[assignment]
        base = cfg.base_url.rstrip("/")
        listing = {"state": "all", "sort": "created", "direction": "asc", "per_page": LOOK_PAGE_SIZE, "page": 1}
        return [
            *(
                LookupRequest(f"{base}/repos/{cfg.owner}/{cfg.repo}/issues", self._headers(), {**listing, "labels": label}, "list")
                for label in [marker_for(finding).label, *legacy_labels(finding)]
            ),
            LookupRequest(
                f"{base}/search/issues", self._headers(),
                {
                    "q": f'repo:{cfg.owner}/{cfg.repo} "{finding.uuid}" in:body type:issue',
                    "sort": "created", "order": "asc", "per_page": LOOK_PAGE_SIZE, "page": 1,
                },
                "search",
            ),
        ]

    def _fetch_request(self, ref: str):
        cfg: GitHubIssuesConfig = self.config  # type: ignore[assignment]
        return LookupRequest(
            f"{cfg.base_url.rstrip('/')}/repos/{cfg.owner}/{cfg.repo}/issues/{ref}", self._headers(), {}, "one"
        )

    @staticmethod
    def _hit(item: dict) -> Hit:
        return Hit(str(item.get("number")), item.get("state") == "closed", item.get("created_at"), str(item.get("body") or ""))

    def _parse_lookup(self, body: Any, kind: str):
        if kind == "one":
            return [self._hit(body)] if isinstance(body, dict) and body.get("number") is not None else None
        items = body.get("items") if kind == "search" and isinstance(body, dict) else body
        if not isinstance(items, list):
            return None
        # The list answers pull requests too; a pull request is never the issue.
        return [self._hit(item) for item in items if isinstance(item, dict) and "pull_request" not in item]

    def _next_page(self, request, body, params, count):
        items = body.get("items") if request.kind == "search" and isinstance(body, dict) else body
        if not isinstance(items, list) or len(items) < int(params["per_page"]):
            return None
        return {**params, "page": int(params["page"]) + 1}

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
