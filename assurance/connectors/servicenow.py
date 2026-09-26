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

from .base import (
    Connector,
    ConnectorConfig,
    ConnectorResult,
    Response,
    error_detail,
    Lookup,
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

    @classmethod
    def config_from_settings(cls) -> ServiceNowConfig:
        return ServiceNowConfig(
            base_url=getattr(settings, "CONNECTOR_SERVICENOW_URL", None),
            table=getattr(settings, "CONNECTOR_SERVICENOW_TABLE", None),
            token=getattr(settings, "CONNECTOR_SERVICENOW_TOKEN", None),
        )

    def _format_finding(self, finding: Any) -> tuple[str, dict, dict]:
        cfg: ServiceNowConfig = self.config  # type: ignore[assignment]
        summary = finding_summary(finding)
        url = f"{cfg.base_url.rstrip('/')}/api/now/table/{cfg.table}"
        headers = {
            "Authorization": f"Bearer {cfg.token}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        payload = {
            "short_description": summary["title"][:160],
            "description": finding_body(summary),
            "impact": _IMPACT.get(summary["severity"], "2"),
            "urgency": _IMPACT.get(summary["severity"], "2"),
            # A stable correlation id so re-pushing the same finding reconciles to
            # the same record rather than opening a duplicate.
            "correlation_id": summary["uuid"],
        }
        return url, headers, payload

    def _lookup_request(self, finding: Any):
        cfg: ServiceNowConfig = self.config  # type: ignore[assignment]
        url = f"{cfg.base_url.rstrip('/')}/api/now/table/{cfg.table}"
        headers = {"Authorization": f"Bearer {cfg.token}", "Accept": "application/json"}
        return url, headers, {
            "sysparm_query": f"correlation_id={finding.uuid}",
            "sysparm_fields": "sys_id",
            "sysparm_limit": 1,
        }

    def _parse_lookup(self, body: Any) -> Lookup:
        rows = body.get("result")
        if not isinstance(rows, list):
            return Lookup.unknown("servicenow answer has no result list")
        if rows:
            sys_id = rows[0].get("sys_id")
            return Lookup(Lookup.FOUND, sys_id, f"servicenow record {sys_id} already exists")
        return Lookup(Lookup.ABSENT, None, "servicenow has no record for this finding")

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
