"""ServiceNow connector — a finding becomes a ServiceNow record (an incident, or
any configured table row).

Formats the finding into a ServiceNow Table API ``POST /api/now/table/<table>``
create call and reads the created ``sys_id`` back as the ``external_ref``. Config
(instance base URL, table, bearer token) comes from settings/env only; with none
of it present the connector is inert and reports ``servicenow not configured``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from django.conf import settings

from ..markers import BODY_PREFIX
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
class ServiceNowConfig(ConnectorConfig):
    base_url: str | None = None
    table: str | None = None
    token: str | None = None

    def is_configured(self) -> bool:
        return bool(self.base_url and self.table and self.token)


# ServiceNow impact/urgency run 1 (high) .. 3 (low). A mapping onto that scale,
# with an unmapped severity resting in the middle rather than being dropped.
_IMPACT = {
    "critical": "1",
    "high": "1",
    "medium": "2",
    "low": "3",
    "info": "3",
}


class ServiceNowConnector(Connector):
    name = "servicenow"
    config_class = ServiceNowConfig
    secret_field = "token"
    settings_fields = ("base_url", "table")
    destination_fields = ("base_url", "table")

    @classmethod
    def config_from_settings(cls) -> ServiceNowConfig:
        return ServiceNowConfig(
            base_url=getattr(settings, "CONNECTOR_SERVICENOW_URL", None),
            table=getattr(settings, "CONNECTOR_SERVICENOW_TABLE", None),
            token=getattr(settings, "CONNECTOR_SERVICENOW_TOKEN", None),
        )

    def _format_finding(self, finding: Any, note: str = "") -> tuple[str, dict, dict]:
        cfg: ServiceNowConfig = self.config  # type: ignore[assignment]
        summary = finding_summary(finding)
        marker = self.marker(finding)
        url = f"{cfg.base_url.rstrip('/')}/api/now/table/{cfg.table}"
        headers = {
            "Authorization": f"Bearer {cfg.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        payload = {
            "short_description": summary["title"][:160],
            "description": finding_body(summary) + (f"\n\n{note}" if note else "") + f"\n{marker.body_line}",
            "impact": _IMPACT.get(summary["severity"], "2"),
            "urgency": _IMPACT.get(summary["severity"], "2"),
            # A stable correlation id so re-pushing the same finding reconciles to
            # the same record rather than opening a duplicate -- every release has
            # sent it, so it is what the look searches on.
            "correlation_id": summary["uuid"],
            # This installation's marker and its tag beside it (83 characters): what
            # makes the record verifiably this installation's (assurance.markers).
            "correlation_display": marker.text,
        }
        return url, headers, payload

    def _headers(self) -> dict:
        cfg: ServiceNowConfig = self.config  # type: ignore[assignment]
        return {"Authorization": f"Bearer {cfg.token}", "Accept": "application/json"}

    _FIELDS = "sys_id,active,sys_created_on,correlation_display,description"

    def _lookup_requests(self, finding: Any):
        # On the correlation id alone: every release has sent it, so this finds
        # master's records -- which carry no marker -- as well as this one's, and
        # the look tells them apart by the tag. Oldest first.
        cfg: ServiceNowConfig = self.config  # type: ignore[assignment]
        url = f"{cfg.base_url.rstrip('/')}/api/now/table/{cfg.table}"
        return [
            LookupRequest(url, self._headers(), {
                "sysparm_query": f"correlation_id={finding.uuid}^ORDERBYsys_created_on",
                "sysparm_fields": self._FIELDS,
                "sysparm_limit": LOOK_PAGE_SIZE,
                "sysparm_offset": 0,
            }, "table"),
        ]

    def _fetch_request(self, ref: str):
        cfg: ServiceNowConfig = self.config  # type: ignore[assignment]
        return LookupRequest(
            f"{cfg.base_url.rstrip('/')}/api/now/table/{cfg.table}/{ref}", self._headers(),
            {"sysparm_fields": self._FIELDS}, "one",
        )

    @staticmethod
    def _hit(row: dict) -> Hit:
        text = str(row.get("description") or "")
        if row.get("correlation_display"):
            text += f"\n{BODY_PREFIX}{row.get('correlation_display')}"
        return Hit(str(row.get("sys_id")), str(row.get("active", "true")).lower() == "false", row.get("sys_created_on"), text)

    def _parse_lookup(self, body: Any, kind: str):
        rows = body.get("result") if isinstance(body, dict) else None
        if kind == "one":
            return [self._hit(rows)] if isinstance(rows, dict) and rows.get("sys_id") else None
        if not isinstance(rows, list):
            return None
        return [self._hit(row) for row in rows if isinstance(row, dict)]

    def _next_page(self, request, body, params, count):
        if count < int(params["sysparm_limit"]):
            return None
        return {**params, "sysparm_offset": int(params["sysparm_offset"]) + count}

    def _parse(self, response: Response) -> ConnectorResult:
        if is_success(response.status_code):
            try:
                sys_id = (response.json().get("result") or {}).get("sys_id")
            except Exception:  # noqa: BLE001
                sys_id = None
            return ConnectorResult(
                ok=True,
                external_ref=sys_id,
                detail=f"servicenow record {sys_id} created" if sys_id else "servicenow record created",
                connector=self.name,
            )
        return ConnectorResult(
            ok=False,
            external_ref=None,
            detail=error_detail(self.name, response),
            connector=self.name,
        )
