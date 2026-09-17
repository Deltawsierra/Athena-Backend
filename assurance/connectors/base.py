"""Commercial spine — the connector framework: a finding becomes a ticket /
control evidence / release signal in an external system, without copy-paste.

Roadmap spine ("GRC / CI-CD / identity integrations"). A finding is the durable
assurance record; a connector is the *outbound* adapter that carries it into the
system a customer already runs — a Jira/ServiceNow ticket, a GitHub issue, a
Splunk HEC event, a generic webhook. One of the cheapest ways to raise switching
cost is to let the record leave here into the tools people live in.

Two design rules, held throughout this package:

- **The interface is stable; the transport is injected.** Every adapter formats
  its outbound request and parses the response, but it never reaches for the
  network itself. The single I/O primitive — :class:`Transport`, a ``post(url, *,
  headers, json)`` call — is passed in: a real HTTP client in production, a fake
  in tests. No adapter imports a network client, and **no network call is made at
  import or hardcoded anywhere in this package**.
- **Inert by default — no configured credentials, nothing happens.** Each adapter
  reads its config (base URL, project/table key, token) from settings/env via a
  config dataclass. When the config is absent it returns a clean
  ``ConnectorResult(ok=False, detail="<connector> not configured")`` and makes
  **no** transport call — it never crashes, never guesses a URL, never fires a
  half-formed request. No secret and no default URL is committed to source;
  credentials come from env/settings only.

Pushing a finding OUT is an outbound action that touches a customer's live GRC /
CI-CD / identity system, so this package is deliberately built **adapter-only**:
production-quality formatting and parsing behind a clean interface, exercised
entirely against a fake transport in tests. **Live wiring — a real
:class:`Transport` bound to per-tenant credentials, and the policy for when an
automated push is allowed to fire — is a deferred follow-up**, documented here on
purpose. Until that lands, an unconfigured connector is inert: it reports
``not configured`` and does nothing.

The :class:`ConnectorResult` is the honest report of what happened: ``ok`` says
whether the external system accepted the push, ``external_ref`` is the id it
handed back (a Jira key, a ServiceNow sys_id, a GitHub issue number) so the
finding can be reconciled against its ticket later, ``detail`` is a
human-readable line, and ``connector`` names which adapter produced it.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

# ---------------------------------------------------------------------------
# The transport seam — the only thing that ever touches the network
# ---------------------------------------------------------------------------


@runtime_checkable
class Response(Protocol):
    """The minimal response shape an adapter reads: a status code, a JSON body,
    and the raw text (for an error detail). ``requests.Response`` satisfies it, and
    so does the tiny fake the tests inject — the adapters depend on this protocol,
    never on a concrete HTTP library."""

    status_code: int

    def json(self) -> Any: ...

    @property
    def text(self) -> str: ...


@runtime_checkable
class Transport(Protocol):
    """The single I/O primitive every adapter is given. One ``post`` call, with
    the URL, headers and JSON body the adapter formatted. The real one wraps an
    HTTP client; the test one records the call and returns a canned
    :class:`Response`. Injecting it is what keeps the adapters free of any
    hardcoded network access."""

    def post(self, url: str, *, headers: dict, json: dict) -> Response: ...


class RequestsTransport:
    """The production :class:`Transport`: a thin wrapper over ``requests.post``.

    It is **never constructed at import** and **never invoked unless a caller
    both builds it and passes it to a *configured* connector** — an unconfigured
    connector short-circuits before any transport is touched. It carries a
    (connect, read) timeout so a hung external system cannot pin a worker, mirror-
    ing ``ai_engine.services.cyberengine_client``. No base URL lives here: the URL
    is always the one the adapter formatted from its injected config."""

    def __init__(self, timeout: tuple[float, float] = (3.05, 10.0)) -> None:
        self.timeout = timeout

    def post(self, url: str, *, headers: dict, json: dict) -> Response:
        # Imported lazily so merely importing this package pulls in no HTTP client
        # and, more to the point, so nothing here can be mistaken for a call site.
        import requests

        return requests.post(url, headers=headers, json=json, timeout=self.timeout)


# ---------------------------------------------------------------------------
# The result — the honest report of an outbound push
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConnectorResult:
    """What a push did, reported honestly.

    ``ok`` is whether the external system accepted it. ``external_ref`` is the id
    that system handed back (a Jira key, a ServiceNow sys_id, a GitHub issue
    number), or ``None`` when there is none — the handle to reconcile the finding
    against its ticket later. ``detail`` is a human-readable line (including the
    ``"<connector> not configured"`` inert case). ``connector`` names the adapter.
    """

    ok: bool
    external_ref: str | None
    detail: str
    connector: str

    def as_dict(self) -> dict:
        """A plain, JSON-safe dict — what an API surfaces to a caller."""
        return {
            "ok": self.ok,
            "external_ref": self.external_ref,
            "detail": self.detail,
            "connector": self.connector,
        }


# ---------------------------------------------------------------------------
# Config — read from settings/env, never from source defaults
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ConnectorConfig:
    """Base for a connector's configuration. A concrete config names the fields an
    adapter needs (base URL, project/table key, token) and answers one question:
    :meth:`is_configured`. It is built from settings/env by the adapter's
    ``config_from_settings`` classmethod — **no field carries a source default**,
    so an unconfigured environment yields a config that reports not-configured
    rather than a plausible-looking live target."""

    def is_configured(self) -> bool:
        """True only when every credential this connector needs is present. The
        base is conservative — never configured — so a subclass must state its own
        requirement explicitly and can never accidentally look ready."""
        return False


# ---------------------------------------------------------------------------
# The connector interface
# ---------------------------------------------------------------------------


class Connector(ABC):
    """The stable outbound interface. A concrete adapter formats a finding for one
    external system and parses the response into a :class:`ConnectorResult`.

    The transport is **injected per call**: ``push_finding(finding, transport=...)``
    — real HTTP in production, a fake in tests. The base enforces the inert-by-
    default contract in :meth:`push_finding` so every adapter gets it for free:
    when :attr:`config` is not configured, it returns the ``"<name> not
    configured"`` result and the concrete formatter is never reached, so **no
    transport call is made**. Subclasses implement :meth:`_format_finding`
    (build the request) and :meth:`_parse` (map the response), never the guard."""

    #: The stable registry name for this connector (e.g. ``"jira"``).
    name: str = "connector"

    #: The concrete config dataclass this connector reads.
    config_class: type[ConnectorConfig] = ConnectorConfig

    def __init__(self, config: ConnectorConfig) -> None:
        self.config = config

    @property
    def configured(self) -> bool:
        return self.config.is_configured()

    @classmethod
    def config_from_settings(cls) -> ConnectorConfig:
        """Build this connector's config from Django settings/env. Subclasses
        override to read their own keys; the base returns a never-configured
        config so a connector with no override is inert rather than crashing."""
        return cls.config_class()

    def _not_configured(self) -> ConnectorResult:
        return ConnectorResult(
            ok=False,
            external_ref=None,
            detail=f"{self.name} not configured",
            connector=self.name,
        )

    def push_finding(self, finding: Any, *, transport: Transport) -> ConnectorResult:
        """Carry a finding into the external system as a ticket / issue / event.

        The inert-by-default guard lives here: an unconfigured connector returns
        the ``"<name> not configured"`` result immediately and **never touches**
        ``transport``. Otherwise the adapter formats the request, the injected
        transport performs the single ``post``, and the adapter parses the
        response. A transport failure is caught and reported as ``ok=False`` — a
        connector never raises out of a push."""
        if not self.configured:
            return self._not_configured()

        url, headers, payload = self._format_finding(finding)
        try:
            response = transport.post(url, headers=headers, json=payload)
        except Exception as exc:  # noqa: BLE001 — any transport error is a failed push, not a crash
            return ConnectorResult(
                ok=False,
                external_ref=None,
                detail=f"{self.name} transport error: {exc}",
                connector=self.name,
            )
        return self._parse(response)

    @abstractmethod
    def _format_finding(self, finding: Any) -> tuple[str, dict, dict]:
        """Return ``(url, headers, json_payload)`` for this finding — the outbound
        request, formatted for this system, from the connector's config. Called
        only when the connector is configured."""

    @abstractmethod
    def _parse(self, response: Response) -> ConnectorResult:
        """Map an external system's response to a :class:`ConnectorResult`."""


# ---------------------------------------------------------------------------
# Shared formatting helpers — one honest view of a finding
# ---------------------------------------------------------------------------


def finding_summary(finding: Any) -> dict:
    """A stable, JSON-safe view of a finding an adapter formats from — the fields
    a ticket / control-evidence / event needs: identity, severity, the narrative,
    the control mapping, and which deployment it belongs to. Reads only attributes
    the :class:`~assurance.models.Finding` model already exposes."""
    deployment = finding.deployment
    return {
        "uuid": str(finding.uuid),
        "fingerprint": finding.fingerprint,
        "finding_type": finding.finding_type,
        "title": finding.title,
        "severity": finding.severity,
        "description": finding.impact or "",
        "business_impact": finding.business_impact or "",
        "recommendation": finding.recommendation or "",
        "control_mapping": dict(finding.control_mapping or {}),
        "location": finding.location or "",
        "deployment": {
            "name": deployment.name,
            "uuid": str(deployment.uuid),
            "environment": deployment.environment,
        },
    }


def finding_body(summary: dict) -> str:
    """A human-readable description body built from :func:`finding_summary` — the
    text most ticketing systems want in a description/comment field. Deterministic
    and free of any timestamp so the same finding formats identically."""
    dep = summary["deployment"]
    lines = [
        f"Severity: {summary['severity']}",
        f"Deployment: {dep['name']} ({dep['environment']})",
        f"Type: {summary['finding_type']}",
    ]
    if summary["location"]:
        lines.append(f"Location: {summary['location']}")
    if summary["description"]:
        lines.append("")
        lines.append(summary["description"])
    if summary["recommendation"]:
        lines.append("")
        lines.append(f"Recommendation: {summary['recommendation']}")
    if summary["control_mapping"]:
        def _fmt(values) -> str:
            # A control_mapping value is normally a list, but a scalar string must
            # not be iterated char-by-char ("A1" -> "A, 1") — normalize it first.
            if isinstance(values, (list, tuple, set)):
                items = list(values)
            else:
                items = [values]
            return ", ".join(str(v) for v in items)

        mappings = ", ".join(
            f"{framework}: {_fmt(values)}"
            for framework, values in sorted(summary["control_mapping"].items())
        )
        lines.append("")
        lines.append(f"Controls: {mappings}")
    lines.append("")
    lines.append(f"Athena finding: {summary['uuid']}")
    return "\n".join(lines)


def is_success(status_code: int) -> bool:
    """A 2xx is an accepted push."""
    return 200 <= status_code < 300


def error_detail(connector: str, response: Response) -> str:
    """A compact, safe error line from a non-2xx response — the status and a
    trimmed body, never the outbound credentials."""
    try:
        body = response.text
    except Exception:  # noqa: BLE001 — a body we cannot read must not mask the status
        body = ""
    body = (body or "")[:200]
    return f"{connector} error {response.status_code}: {body}".rstrip(": ").rstrip()
