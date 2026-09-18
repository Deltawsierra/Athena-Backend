"""Generic webhook connector — a finding (or an assurance receipt) is POSTed as
JSON to a configured URL.

The escape hatch for any system without a first-class adapter: it forwards the
finding summary (or a receipt payload) to one configured endpoint, optionally
carrying a shared secret in a header so the receiver can authenticate the call.
Config (URL, optional token/header name) comes from settings/env only; with no
URL configured the connector is inert and reports ``webhook not configured``.
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
    Transport,
    error_detail,
    finding_summary,
    is_success,
)


@dataclass(frozen=True)
class WebhookConfig(ConnectorConfig):
    url: str | None = None
    token: str | None = None
    # The header the shared secret rides in; defaults to a conventional one but is
    # overridable so the adapter fits whatever the receiver expects.
    token_header: str = "X-Athena-Token"

    def is_configured(self) -> bool:
        return bool(self.url)


class WebhookConnector(Connector):
    name = "webhook"
    config_class = WebhookConfig
    secret_field = "token"
    settings_fields = ("url", "token_header")

    @classmethod
    def config_from_settings(cls) -> WebhookConfig:
        return WebhookConfig(
            url=getattr(settings, "CONNECTOR_WEBHOOK_URL", None),
            token=getattr(settings, "CONNECTOR_WEBHOOK_TOKEN", None),
            token_header=getattr(settings, "CONNECTOR_WEBHOOK_TOKEN_HEADER", None)
            or "X-Athena-Token",
        )

    def _headers(self) -> dict:
        cfg: WebhookConfig = self.config  # type: ignore[assignment]
        headers = {"Content-Type": "application/json"}
        if cfg.token:
            headers[cfg.token_header] = cfg.token
        return headers

    def _format_finding(self, finding: Any) -> tuple[str, dict, dict]:
        cfg: WebhookConfig = self.config  # type: ignore[assignment]
        payload = {"kind": "finding", "finding": finding_summary(finding)}
        return cfg.url, self._headers(), payload

    def push_receipt(self, receipt: dict, *, transport: Transport) -> ConnectorResult:
        """Forward an assurance receipt payload (see
        :func:`assurance.receipt.build_assurance_receipt`) to the webhook. Same
        inert guard as :meth:`~assurance.connectors.base.Connector.push_finding`:
        an unconfigured connector makes no transport call and reports
        ``webhook not configured``."""
        if not self.configured:
            return self._not_configured()
        cfg: WebhookConfig = self.config  # type: ignore[assignment]
        payload = {"kind": "receipt", "receipt": receipt}
        try:
            response = transport.post(cfg.url, headers=self._headers(), json=payload)
        except Exception as exc:  # noqa: BLE001
            return ConnectorResult(
                ok=False,
                external_ref=None,
                detail=f"{self.name} transport error: {exc}",
                connector=self.name,
            )
        return self._parse(response)

    def _parse(self, response: Response) -> ConnectorResult:
        if is_success(response.status_code):
            return ConnectorResult(
                ok=True,
                external_ref=None,
                detail="webhook delivered",
                connector=self.name,
            )
        return ConnectorResult(
            ok=False,
            external_ref=None,
            detail=error_detail(self.name, response),
            connector=self.name,
        )
