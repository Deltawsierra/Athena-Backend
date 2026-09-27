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
            from ..dispatch import connector_deadline

            deadline = connector_deadline()
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
    have. ``state`` is:

    - ``"found"`` -- the issue this installation created for the finding:
      ``external_ref`` names it, ``closed`` says whether the tracker has closed it,
      and ``how`` says how it is known -- ``"recorded"`` (the issue the attempt
      already records), ``"verified"`` (its marker's tag verifies; of several, the
      one created first), or ``"legacy"`` (the one issue in a format older than
      tags, created before this installation wrote them);
    - ``"absent"`` -- no issue of this installation's for it;
    - ``"ambiguous"`` -- several issues in an older format, all created before
      tags were written, none verifiable: never adopted, and never a license to
      create another;
    - ``"unknown"`` -- it could not look, or the answer did not say.

    ``ignored``: issues that matched the search and are NOT this installation's --
    a copied label, a planted body, a tag that does not verify, an older format
    created after tags were -- named so the caller can say so. They never hold a
    dispatch and are never adopted."""

    state: str
    external_ref: str | None = None
    detail: str = ""
    closed: bool = False
    how: str = ""
    ignored: tuple = ()

    FOUND = "found"
    ABSENT = "absent"
    AMBIGUOUS = "ambiguous"
    UNKNOWN = "unknown"

    @classmethod
    def unknown(cls, detail: str, ignored: tuple = ()) -> Lookup:
        return cls(cls.UNKNOWN, None, detail, ignored=ignored)


@dataclass(frozen=True)
class LookupRequest:
    """One read an adapter makes to look for a finding's issue. ``kind`` tells its
    ``_parse_lookup`` which answer shape to expect. ``missing_means_next``: the
    next request is this one's stand-in, tried only when this one answers 404 or
    410 (this system does not serve this read: Jira Cloud has retired
    ``/rest/api/2/search``; Data Center has no ``/rest/api/3/search/jql``).
    Otherwise every request is made, in order, until one finds the issue."""

    url: str
    headers: dict
    params: dict
    kind: str = ""
    missing_means_next: bool = False


@dataclass(frozen=True)
class Hit:
    """One issue a look's answer lists: its id, whether the tracker has closed it,
    when the provider says it was created, and its text (body and the fields that
    carry a marker) -- what its marker is checked against."""

    ref: str
    closed: bool = False
    created: Any = None
    text: str = ""


#: Issues asked for per page of a look.
LOOK_PAGE_SIZE = 100
#: Pages one look reads at most, over all its requests (and its time budget, one
#: transport deadline, bounds it too).
LOOK_MAX_PAGES = 50


def parse_provider_time(value: Any):
    """A provider's creation time as an aware UTC datetime, or ``None``: GitHub's
    ``2026-09-27T01:02:03Z``, Jira's ``2026-09-27T01:02:03.000+0000``, ServiceNow's
    ``2026-09-27 01:02:03`` (UTC)."""
    from datetime import datetime, timezone as dt_timezone

    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip().replace("Z", "+00:00")
    if len(text) >= 5 and text[-5] in "+-" and text[-4:].isdigit() and text[-3] != ":":
        text = f"{text[:-2]}:{text[-2:]}"
    try:
        parsed = datetime.fromisoformat(text.replace(" ", "T", 1))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt_timezone.utc)
    return parsed


def installation_id() -> str:
    """This installation's id, hashed: the persisted random id
    (:class:`~assurance.models.AssuranceInstallation`) or, when set,
    ``ASSURANCE_INSTALLATION_ID``. Never derived from ``SECRET_KEY``."""
    import hashlib

    from ..markers import identity

    return hashlib.sha256(f"athena-installation\x1f{identity().installation_id}".encode()).hexdigest()


def finding_marker(finding: Any) -> str:
    """The label an adapter tags a created issue with, so it can search for it:
    ``athena-<installation>-<finding uuid>``, 50 characters -- GitHub's limit for a
    label name. The tag that makes it verifiable is in the body
    (:func:`assurance.markers.marker_for`)."""
    from ..markers import marker_for

    return marker_for(finding).label


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

    def find_existing(
        self,
        finding: Any,
        *,
        transport: Any,
        known_ref: str | None = None,
        expected: Any = None,
        legacy: bool = True,
    ) -> Lookup:
        """Look for the issue this installation created for this finding, so a push
        whose answer was lost, or a second runner, reuses it instead of creating
        another. See :mod:`assurance.markers` for what is adopted and why.

        ``known_ref``: the issue already recorded for the finding -- read directly,
        so it is found however many copies of it exist. ``expected``: the
        :class:`~assurance.markers.Marker` whose tag an adopted issue must carry
        (the one the attempt's push carried; by default, the finding's marker now).
        ``legacy``: whether an issue in a format older than tags, created before
        this installation wrote tags, may be taken as this code's -- for a first
        push, and for an attempt whose push carried an older format; not for one
        whose push carried a tag, which only a tagged issue can be.

        The base cannot look: ``unknown``. An adapter that can overrides
        :meth:`_lookup_requests`, :meth:`_parse_lookup` and, to page,
        :meth:`_next_page`. A transport without ``get`` cannot look either, and any
        error while looking -- a raised error, an error answer, a look that runs
        out of pages or of time -- is ``unknown``, never ``absent``, which would
        license a second create. Pages are read oldest issue first, so the first
        issue whose tag verifies is the original, and the look stops there."""
        import time as _time

        if not self.configured:
            return Lookup.unknown(f"{self.name} not configured")
        get = getattr(transport, "get", None)
        requests = self._lookup_requests(finding)
        if not requests:
            return Lookup.unknown(f"{self.name} offers no read-back of what it was sent")
        if get is None:
            return Lookup.unknown("the transport cannot read")
        from ..markers import carries_a_tag, identity, marker_for

        ident = identity()
        expected = expected or marker_for(finding, ident)
        budget = float(getattr(transport, "deadline", DEFAULT_DEADLINE_SECONDS) or DEFAULT_DEADLINE_SECONDS)
        began = _time.monotonic()
        seen: set = set()
        ignored: list = []
        older: list = []
        pages = 0

        def answer(state, ref=None, detail="", closed=False, how=""):
            return Lookup(state, ref, detail, closed=closed, how=how, ignored=tuple(ignored))

        if known_ref:
            fetch = self._fetch_request(str(known_ref))
            if fetch is not None:
                try:
                    response = get(fetch.url, headers=fetch.headers, params=fetch.params)
                    pages += 1
                    if is_success(response.status_code):
                        hits = self._parse_lookup(response.json(), "one")
                        if hits:
                            closed = hits[0].closed
                            return answer(
                                Lookup.FOUND, str(known_ref),
                                f"{self.name} issue {known_ref}, recorded for this finding, exists "
                                f"({'closed' if closed else 'open'})",
                                closed, "recorded",
                            )
                    elif response.status_code not in (404, 410):
                        return Lookup.unknown(error_detail(self.name, response))
                except Exception as exc:  # noqa: BLE001 - a failed look says nothing
                    return Lookup.unknown(f"{self.name} look-up failed: {type(exc).__name__}: {exc}")

        stand_in = False
        for i, request in enumerate(requests):
            if i and requests[i - 1].missing_means_next and not stand_in:
                continue  # the request before answered: this one only stands in for it
            last = i == len(requests) - 1
            stand_in = False
            params = dict(request.params)
            while True:
                if pages >= LOOK_MAX_PAGES or _time.monotonic() - began > budget:
                    return Lookup.unknown(
                        f"{self.name} look-up stopped after {pages} page(s) without finding this "
                        f"installation's issue (it matched {len(seen)} other issue(s))",
                        tuple(ignored),
                    )
                try:
                    response = get(request.url, headers=request.headers, params=params)
                    pages += 1
                    status = response.status_code
                    if status in (404, 410) and request.missing_means_next and not last:
                        stand_in = True
                        break
                    if not is_success(status):
                        return Lookup.unknown(error_detail(self.name, response), tuple(ignored))
                    body = response.json()
                    hits = self._parse_lookup(body, request.kind)
                except Exception as exc:  # noqa: BLE001 - a failed or unreadable look says nothing
                    return Lookup.unknown(f"{self.name} look-up failed: {type(exc).__name__}: {exc}", tuple(ignored))
                if hits is None:
                    return Lookup.unknown(f"{self.name} look-up answer had no list of issues", tuple(ignored))
                for hit in hits:
                    ref = str(hit.ref)
                    if ref in seen:
                        continue
                    seen.add(ref)
                    state = "closed" if hit.closed else "open"
                    if known_ref and ref == str(known_ref):
                        return answer(
                            Lookup.FOUND, ref, f"{self.name} issue {ref}, recorded for this finding, exists ({state})",
                            hit.closed, "recorded",
                        )
                    if expected.verifies(hit.text):
                        return answer(
                            Lookup.FOUND, ref,
                            f"{self.name} issue {ref} already exists ({state}); its marker verifies",
                            hit.closed, "verified",
                        )
                    created = parse_provider_time(hit.created)
                    if (
                        legacy
                        and not carries_a_tag(hit.text)
                        and created is not None
                        and ident.since is not None
                        and created < ident.since
                    ):
                        older.append((ref, hit.closed))
                    else:
                        ignored.append(ref)
                params = self._next_page(request, body, params, len(hits))
                if params is None:
                    break
        if len(older) == 1:
            ref, closed = older[0]
            return answer(
                Lookup.FOUND, ref,
                f"{self.name} issue {ref} already exists ({'closed' if closed else 'open'}); it is in an older "
                "marker format, created before this installation wrote verifiable markers",
                closed, "legacy",
            )
        if older:
            refs = ", ".join(r for r, _ in older)
            return answer(
                Lookup.AMBIGUOUS, None,
                f"{self.name}: {len(older)} issues in an older marker format, all created before this "
                f"installation wrote verifiable markers, carry this finding ({refs}); which is its own "
                "cannot be told",
            )
        return answer(Lookup.ABSENT, None, f"{self.name} has no issue of this installation's for this finding")

    def _lookup_requests(self, finding: Any) -> list[LookupRequest]:
        """The reads that find this finding's issue, oldest first, in order; empty
        when this system offers none."""
        return []

    def _fetch_request(self, ref: str) -> LookupRequest | None:
        """The read of one issue by its id, or ``None`` when this system offers none."""
        return None

    def _parse_lookup(self, body: Any, kind: str) -> list[Hit] | None:  # pragma: no cover
        """The :class:`Hit` list of one look's answer (``kind`` ``"one"``: the answer
        to :meth:`_fetch_request`), or ``None`` when it does not have the shape
        expected."""
        return None

    def _next_page(self, request: LookupRequest, body: Any, params: dict, count: int) -> dict | None:
        """The params for the next page of ``request``'s answer, or ``None`` when
        this was the last."""
        return None

    def comment_on(self, ref: str, text: str, *, transport: Any) -> ConnectorResult | None:
        """Add ``text`` as a comment on issue ``ref``, or ``None`` when this system
        takes no comments here."""
        request = self._comment_request(ref, text) if self.configured else None
        if request is None:
            return None
        url, headers, payload = request
        try:
            response = transport.post(url, headers=headers, json=payload)
        except Exception as exc:  # noqa: BLE001 - as push_finding: never raises
            certain = classify_transport_error(exc) is NotSent
            return ConnectorResult(
                ok=False, external_ref=None, detail=f"{self.name} comment transport error: {exc}",
                connector=self.name, certain=certain,
            )
        if is_success(response.status_code):
            return ConnectorResult(ok=True, external_ref=str(ref), detail=f"commented on {ref}", connector=self.name)
        return ConnectorResult(ok=False, external_ref=None, detail=error_detail(self.name, response), connector=self.name)

    def _comment_request(self, ref: str, text: str) -> tuple[str, dict, dict] | None:
        return None

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
