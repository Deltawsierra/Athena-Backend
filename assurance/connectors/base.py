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
entirely against a fake transport in tests. **Live wiring is now in place**: a
per-tenant :class:`~assurance.models.ConnectorBinding` binds a real transport to
credentials encrypted at rest, and :mod:`assurance.dispatch` is the policy for when
an automated push fires. An unconfigured connector (no binding, no key) stays
inert: it reports ``not configured`` and does nothing.

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


class NotSent(Exception):
    """The request certainly never reached the provider.

    A connection that was never established, a name that never resolved: nothing
    left the client, so the provider cannot have committed anything, and retrying
    is safe. This is the ONLY case a client can be sure about.
    """


class OutcomeUnknown(Exception):
    """The request may have been received and committed before the answer was lost.

    A read timeout is the canonical case: the request went out, the provider may
    have created the ticket, and the acknowledgement never came back. Recording this
    as a failure licenses a retry that double-executes; recording it as a success
    claims a ticket that may not exist. Neither is true, so it gets its own state.
    """


def classify_transport_error(exc: BaseException) -> type[NotSent] | type[OutcomeUnknown]:
    """Which of the two an arbitrary transport error is. Defaults to UNKNOWN.

    Fail-closed by construction: an error this does not recognise is treated as
    possibly-committed, because the alternative default -- assuming nothing was
    sent -- is the one that licenses a duplicate effect on the customer's system.
    Only errors that can only happen *before any bytes reach the server* are
    classified as NotSent, and they are recognised by their cause rather than by
    their message, because a message is not a contract.
    """
    import requests.exceptions as rex

    try:
        from urllib3.exceptions import NameResolutionError, NewConnectionError
    except ImportError:  # pragma: no cover - urllib3 ships with requests
        NameResolutionError = NewConnectionError = ()  # type: ignore[assignment]

    if isinstance(exc, rex.ConnectTimeout):
        # A connect timeout is exactly "the connection was never made".
        return NotSent
    if isinstance(exc, ConnectionRefusedError):
        # Python's own builtin, and the one builtin case that is unambiguous: the
        # peer refused the connection, so nothing was ever sent. Its siblings --
        # ConnectionResetError, BrokenPipeError, ConnectionAbortedError -- all mean
        # the connection died at a point we cannot pin down, so they fall through.
        return NotSent
    if isinstance(exc, rex.ConnectionError):
        # A ConnectionError covers both "never connected" (DNS, refused) and
        # "connection died mid-request". Only the first is safe, and urllib3's own
        # exception type is what tells them apart.
        cause = exc.args[0] if exc.args else None
        wrapped = getattr(cause, "reason", cause)
        if NewConnectionError and isinstance(wrapped, (NewConnectionError, NameResolutionError)):
            return NotSent
        return OutcomeUnknown
    return OutcomeUnknown


@runtime_checkable
class Transport(Protocol):
    """The single I/O primitive every adapter is given. One ``post`` call, with
    the URL, headers and JSON body the adapter formatted. The real one wraps an
    HTTP client; the test one records the call and returns a canned
    :class:`Response`. Injecting it is what keeps the adapters free of any
    hardcoded network access.

    A transport MAY also offer ``get(url, *, headers, params)``: the read an
    adapter uses to look for an issue it may already have created
    (:meth:`Connector.find_existing`). One without it simply cannot look."""

    def post(self, url: str, *, headers: dict, json: dict) -> Response: ...


class DeadlineExceeded(Exception):
    """The request had no complete answer within the transport's total deadline.

    It may have reached the provider, so it is classified as an uncertain outcome
    (:func:`classify_transport_error` defaults to :class:`OutcomeUnknown`)."""


#: The wall-clock limit on one whole request -- name resolution, connect, sending,
#: and every read of the answer -- in seconds. ``requests``' own ``(connect, read)``
#: timeout bounds each socket operation, not the total: a server that drips one
#: byte every few seconds held a push for 40 s under ``(3.05, 10)``.
DEFAULT_DEADLINE_SECONDS = 30.0


class RequestsTransport:
    """The production :class:`Transport`: a thin wrapper over ``requests``.

    It is **never constructed at import** and **never invoked unless a caller
    both builds it and passes it to a *configured* connector** — an unconfigured
    connector short-circuits before any transport is touched. It carries a
    (connect, read) timeout so a hung external system cannot pin a worker, mirror-
    ing ``ai_engine.services.cyberengine_client``, AND a total deadline
    (``ASSURANCE_CONNECTOR_DEADLINE_SECONDS``, default 30): the request runs on a
    helper thread and the caller stops waiting when the deadline passes, raising
    :class:`DeadlineExceeded`. The helper thread is abandoned to finish or time out
    on its own; it holds no lock and no database connection. No base URL lives
    here: the URL is always the one the adapter formatted from its injected config."""

    def __init__(self, timeout: tuple[float, float] = (3.05, 10.0), deadline: float | None = None) -> None:
        self.timeout = timeout
        if deadline is None:
            from django.conf import settings

            deadline = float(getattr(settings, "ASSURANCE_CONNECTOR_DEADLINE_SECONDS", DEFAULT_DEADLINE_SECONDS))
        self.deadline = deadline

    def post(self, url: str, *, headers: dict, json: dict) -> Response:
        # Imported lazily so merely importing this package pulls in no HTTP client
        # and, more to the point, so nothing here can be mistaken for a call site.
        import requests

        return self.within_deadline(requests.post, url, headers=headers, json=json, timeout=self.timeout)

    def get(self, url: str, *, headers: dict, params: dict | None = None) -> Response:
        import requests

        return self.within_deadline(requests.get, url, headers=headers, params=params, timeout=self.timeout)

    def within_deadline(self, call, *args, **kwargs):
        """``call(*args, **kwargs)``, or :class:`DeadlineExceeded` once the deadline passes."""
        import threading

        box: dict = {}

        def run():
            try:
                box["value"] = call(*args, **kwargs)
            except BaseException as exc:  # noqa: BLE001 - handed back to the caller below
                box["error"] = exc

        helper = threading.Thread(target=run, name="assurance-transport", daemon=True)
        helper.start()
        helper.join(self.deadline)
        if helper.is_alive():
            raise DeadlineExceeded(f"no complete answer within the {self.deadline:g} s deadline")
        if "error" in box:
            raise box["error"]
        return box["value"]


@dataclass(frozen=True)
class Lookup:
    """What an adapter found when it looked for the issue a finding may already
    have: ``state`` is ``"found"`` (with ``external_ref``), ``"absent"``, or
    ``"unknown"`` -- it could not look, or the answer did not say."""

    state: str
    external_ref: str | None = None
    detail: str = ""

    FOUND = "found"
    ABSENT = "absent"
    UNKNOWN = "unknown"

    @classmethod
    def unknown(cls, detail: str) -> Lookup:
        return cls(cls.UNKNOWN, None, detail)


def finding_marker(finding: Any) -> str:
    """The label an adapter tags a created issue with, so it can find it again:
    ``athena-<finding uuid>`` (43 characters; within Jira's and GitHub's limits)."""
    return f"athena-{finding.uuid}"


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
    # Whether the outcome is KNOWN. ``ok=False, certain=True`` is "it definitely
    # did not happen"; ``ok=False, certain=False`` is "it may have happened and we
    # cannot tell". Defaults to True so every existing result -- a parsed response,
    # an inert connector -- keeps meaning exactly what it meant: those are the
    # cases where the client does know.
    certain: bool = True

    @property
    def uncertain(self) -> bool:
        """True when the provider may have committed this and the client cannot tell."""
        return not self.ok and not self.certain

    def as_dict(self) -> dict:
        """A plain, JSON-safe dict — what an API surfaces to a caller."""
        return {
            "ok": self.ok,
            "external_ref": self.external_ref,
            "detail": self.detail,
            "connector": self.connector,
            "certain": self.certain,
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

    #: The config field that carries the secret credential. A per-tenant binding
    #: stores this one field encrypted at rest and every other field in the clear.
    secret_field: str = "token"

    #: The non-secret config fields a per-tenant binding stores in the clear (the
    #: endpoint/scoping fields). The secret field is deliberately NOT listed here.
    settings_fields: tuple[str, ...] = ()

    #: The request header this system deduplicates a create on, or ``None`` when it
    #: has none. When a caller passes an ``operation_id`` -- the dispatcher passes
    #: the durable id of "this finding to this connector" -- it is sent in this
    #: header, so two pushes of one operation (a retry, or two runners in two
    #: processes) are one to a system that honours it. ``None`` for every adapter
    #: whose API has no such header: Jira's and GitHub's issue create, ServiceNow's
    #: Table API (which carries the finding's UUID as ``correlation_id`` instead)
    #: and Splunk HEC (whose event carries the finding's UUID). Sending one there
    #: would claim a deduplication nothing performs.
    idempotency_header: str | None = None

    #: Whether delivering one operation twice is harmless to this system -- true
    #: only where the receiver deduplicates on :attr:`idempotency_header`. A push
    #: whose answer was lost may then simply be sent again; anywhere else it waits
    #: until :meth:`find_existing`, or a person, settles whether it arrived.
    redelivery_is_idempotent: bool = False

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

    @classmethod
    def config_from_binding(
        cls, settings_values: dict, secret: str | None
    ) -> ConnectorConfig:
        """Build this connector's frozen config from a per-tenant binding: the
        non-secret ``settings_values`` (endpoint/scoping) plus the decrypted
        ``secret`` (or ``None`` when the binding has no usable credential — the
        resulting config then reports not-configured, so the connector stays
        inert). No secret ever appears in ``settings_values``; it arrives only
        here, in memory, at build time."""
        kwargs = {
            field: settings_values.get(field)
            for field in cls.settings_fields
            if settings_values.get(field) not in (None, "")
        }
        if secret:
            kwargs[cls.secret_field] = secret
        return cls.config_class(**kwargs)

    def _not_configured(self) -> ConnectorResult:
        return ConnectorResult(
            ok=False,
            external_ref=None,
            detail=f"{self.name} not configured",
            connector=self.name,
        )

    def push_finding(
        self, finding: Any, *, transport: Transport, operation_id: str | None = None
    ) -> ConnectorResult:
        """Carry a finding into the external system as a ticket / issue / event.

        The inert-by-default guard lives here: an unconfigured connector returns
        the ``"<name> not configured"`` result immediately and **never touches**
        ``transport``. Otherwise the adapter formats the request, the injected
        transport performs the single ``post``, and the adapter parses the
        response. A transport failure is caught and reported as ``ok=False`` — a
        connector never raises out of a push. ``operation_id`` goes out in
        :attr:`idempotency_header` when this system has one."""
        if not self.configured:
            return self._not_configured()

        url, headers, payload = self._format_finding(finding)
        if operation_id and self.idempotency_header:
            headers = {**headers, self.idempotency_header: operation_id}
        try:
            response = transport.post(url, headers=headers, json=payload)
        except Exception as exc:  # noqa: BLE001 — any transport error is a failed push, not a crash
            # A transport error is not one thing. "The connection was never made"
            # and "the request went out and the answer never came back" were both
            # reported as ok=False, which meant a read timeout after the provider
            # had already created the ticket was recorded as a failure and retried
            # -- creating it twice. They are told apart here.
            kind = classify_transport_error(exc)
            certain = kind is NotSent
            what = (
                "nothing was sent"
                if certain
                else "the request may have been received before the answer was lost"
            )
            return ConnectorResult(
                ok=False,
                external_ref=None,
                detail=f"{self.name} transport error ({what}): {exc}",
                connector=self.name,
                certain=certain,
            )
        return self._parse(response)

    def find_existing(self, finding: Any, *, transport: Any) -> Lookup:
        """Look for the issue this finding was already pushed as, so a push whose
        answer was lost, or a second runner, reuses it instead of creating another.

        The base cannot look: ``unknown``. An adapter that can overrides
        :meth:`_lookup_request` and :meth:`_parse_lookup`. A transport without
        ``get`` cannot look either, and any error while looking is ``unknown`` --
        never ``absent``, which would license a second create."""
        if not self.configured:
            return Lookup.unknown(f"{self.name} not configured")
        request = self._lookup_request(finding)
        if request is None:
            return Lookup.unknown(f"{self.name} offers no read-back of what it was sent")
        get = getattr(transport, "get", None)
        if get is None:
            return Lookup.unknown("the transport cannot read")
        url, headers, params = request
        try:
            response = get(url, headers=headers, params=params)
            if not is_success(response.status_code):
                return Lookup.unknown(error_detail(self.name, response))
            return self._parse_lookup(response.json())
        except Exception as exc:  # noqa: BLE001 - a failed or unreadable look says nothing
            return Lookup.unknown(f"{self.name} look-up failed: {type(exc).__name__}: {exc}")

    def _lookup_request(self, finding: Any) -> tuple[str, dict, dict] | None:
        """``(url, headers, params)`` of the read that finds this finding's issue,
        or ``None`` when this system offers none."""
        return None

    def _parse_lookup(self, body: Any) -> Lookup:  # pragma: no cover - only with _lookup_request
        return Lookup.unknown(f"{self.name} look-up not implemented")

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
