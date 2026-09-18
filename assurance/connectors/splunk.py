"""Splunk connector — a finding becomes a Splunk HEC event.

Formats the finding into an HTTP Event Collector ``POST /services/collector/event``
call, carrying the finding summary as the event body. Splunk answers HEC with a
JSON ``{"text": "Success", "code": 0}``; we treat ``code == 0`` on a 2xx as
accepted. Config (HEC base URL, token, optional index/sourcetype) comes from
settings/env only; with none of it present the connector is inert and reports
``splunk not configured``.

This same HEC shape carries a Microsoft Sentinel / generic SIEM event too — a
control-evidence signal into the customer's monitoring pipeline rather than a
ticket.
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
    finding_summary,
    is_success,
)


@dataclass(frozen=True)
class SplunkConfig(ConnectorConfig):
    base_url: str | None = None
    token: str | None = None
    index: str | None = None
    sourcetype: str = "athena:finding"

    def is_configured(self) -> bool:
        return bool(self.base_url and self.token)


class SplunkConnector(Connector):
    name = "splunk"
    config_class = SplunkConfig
    secret_field = "token"
    settings_fields = ("base_url", "index", "sourcetype")

    @classmethod
    def config_from_settings(cls) -> SplunkConfig:
        return SplunkConfig(
            base_url=getattr(settings, "CONNECTOR_SPLUNK_HEC_URL", None),
            token=getattr(settings, "CONNECTOR_SPLUNK_HEC_TOKEN", None),
            index=getattr(settings, "CONNECTOR_SPLUNK_INDEX", None),
            sourcetype=getattr(settings, "CONNECTOR_SPLUNK_SOURCETYPE", None) or "athena:finding",
        )

    def _format_finding(self, finding: Any) -> tuple[str, dict, dict]:
        cfg: SplunkConfig = self.config  # type: ignore[assignment]
        summary = finding_summary(finding)
        url = f"{cfg.base_url.rstrip('/')}/services/collector/event"
        headers = {
            # HEC authenticates with the "Splunk <token>" scheme, not Bearer.
            "Authorization": f"Splunk {cfg.token}",
            "Content-Type": "application/json",
        }
        payload = {
            "sourcetype": cfg.sourcetype,
            "event": summary,
        }
        if cfg.index:
            payload["index"] = cfg.index
        return url, headers, payload

    def _parse(self, response: Response) -> ConnectorResult:
        if is_success(response.status_code):
            try:
                body = response.json()
            except Exception:  # noqa: BLE001
                body = {}
            # HEC signals acceptance in the body: code 0 is Success. A 2xx with a
            # non-zero code is a rejected event, not an accepted one.
            if body.get("code", 0) == 0:
                return ConnectorResult(
                    ok=True,
                    external_ref=body.get("ackId") and str(body.get("ackId")) or None,
                    detail="splunk event accepted",
                    connector=self.name,
                )
            return ConnectorResult(
                ok=False,
                external_ref=None,
                detail=f"splunk rejected event: {body.get('text', body.get('code'))}",
                connector=self.name,
            )
        return ConnectorResult(
            ok=False,
            external_ref=None,
            detail=error_detail(self.name, response),
            connector=self.name,
        )
