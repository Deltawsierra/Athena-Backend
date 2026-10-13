"""A secret planted in any origin never leaves Athena-Backend through a sink.

The collector-hardening roadmap item, on this service (the engines' harness is
Athena-Engine #76; achilles-engine carries it as #94): one canary per ORIGIN a
secret can come from -- each connector and posture binding's token, the key they
are encrypted under, the engine's ``X-API-Key``, the closure forward's
``MINOTAUR_OUTCOMES_KEY``, the gate's approval-read token and the observed-effect
token, the closure-evidence, failsafe poll and failsafe service tokens, the
signing key behind every signature this service verifies (a test keyring), a
proxy's userinfo in the environment, a password in a sign-in body, and what a
tenant sends in a request body or an upload. The service is driven down every
PATH -- a scan that completes; one, launched at a target with a login, the engine
refuses with a page that quotes the request back; one whose launch times out and
is reconciled; a scan's Stop, and a Stop owed and delivered by ``manage.py
deliver_owed_stops``, each also through a same-host redirect; connector pushes and
posture reads that succeed, fail with a page quoting the request, and run past
their deadline; a closure recorded and forwarded, refused, and retried by
``manage.py retry_closure_forwards``; the gate's read and an observed effect; the
failsafe's poll, a stop draft and the state read; a defender text and file scan;
everything outbound with a credentialed proxy named in the environment, the
engine reached through it (a scan's Stop delivered, and owed and delivered, by
it) and nothing else; a route that raises -- and then every route that reads is
read. After each path every
SINK is serialised whole and searched for every canary, however encoded
(tests/canary_search.py, #76's search unchanged; a PDF's compressed streams are
inflated first).

The sinks: every API answer (receipts and evidence packs among them, and the
error pages), every export (PDF), e-mail, every log record of every logger at
every level with stdout and stderr, every row of every model, every file under
``MEDIA_ROOT``, every span, and every management command's stdout and stderr.

``MATRIX`` gives every (origin, sink) cell one status: declared (the code says it
never reaches there, quoted in ``DECLARATIONS`` and checked to be there) and
asserted absent on every path; or not declared, observed and printed by
``test_the_observed_matrix``. The completeness tests hold the inventory to the
code: every route and method, every model, every management command, every
module that writes a file, configures logging, or sends a request, and every
span attribute, is classified here -- so a new sink fails until this harness
covers it.

The SAFETY RULE: the scan's Stop and ``deliver_owed_stops`` are driven with every
canary planted -- directly, through a same-host redirect and through the
environment's credentialed proxy -- and timed against their existing bounds
(``test_a_stop_is_delivered_with_every_canary_planted_and_inside_its_bound``).
Nothing this harness checks sits on a stop path; the withholding added on the
outbound path never raises (``safety.outbound.quiet``) and costs microseconds.
"""

from __future__ import annotations

import base64
import collections
import contextlib
import copy
import io
import json
import logging
import re
import secrets
import socket
import string
import sys
import threading
import time
import types
import uuid
import zlib
from dataclasses import dataclass, field
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from tests.canary_search import Needles, search

ROOT = Path(__file__).resolve().parent.parent

#: pytest-django sets up the test database only for a session holding a test that
#: asks for it; the run below is one module-scoped fixture, rolled back at its end.
pytestmark = pytest.mark.django_db


def _hex(count: int) -> str:
    return secrets.token_hex(count)


@dataclass(frozen=True)
class Origin:
    canary: str
    planted: str


#: The signing key's seed: its hex is the canary, and its raw bytes are searched too.
_SIGNING_SEED = secrets.token_bytes(32)

ORIGINS: dict[str, Origin] = {
    "connector.token": Origin(
        "cnryhook" + _hex(12), "a webhook connector binding's shared secret (X-Athena-Token)"
    ),
    "posture.token": Origin(
        "cnrypost" + _hex(12), "a cloud posture binding's read token (Authorization: Bearer)"
    ),
    "credential.key": Origin(
        Fernet.generate_key().decode("ascii"), "ASSURANCE_CREDENTIAL_KEY, the key bindings are encrypted under"
    ),
    "engine.api_key": Origin(
        "cnryapikey" + _hex(14), "CYBERENGINE_OPERATOR_KEY, sent to the engine as X-API-Key"
    ),
    "minotaur.outcomes_key": Origin(
        "cnryoutcomes" + _hex(12), "MINOTAUR_OUTCOMES_KEY, in the environment only (X-Minotaur-Key)"
    ),
    "gate.token": Origin(
        "cnrygate" + _hex(16), "ASSURANCE_GATE_APPROVAL_TOKEN, the gate's approval-read credential"
    ),
    "effect.token": Origin(
        "cnryeffect" + _hex(16), "ASSURANCE_OBSERVED_EFFECT_TOKEN, the observed-effect service's credential"
    ),
    "closure.token": Origin(
        "cnryclosure" + _hex(14), "CLOSURE_EVIDENCE_SERVICE_TOKEN, the engine service's credential"
    ),
    "failsafe.poll_token": Origin(
        "cnrypoll" + _hex(16), "FAILSAFE_POLL_TOKEN, the engines' poll credential"
    ),
    "failsafe.service_token": Origin(
        "cnryservice" + _hex(16), "FAILSAFE_SERVICE_TOKEN, the dashboard's stop credential"
    ),
    "signing.key": Origin(
        _SIGNING_SEED.hex(), "the private key behind every signature this service verifies, via a test keyring"
    ),
    "proxy.userinfo": Origin(
        "cnryproxy" + _hex(12), "the password in HTTP_PROXY/HTTPS_PROXY/ALL_PROXY's userinfo"
    ),
    "economics.feed_key": Origin(
        "cnryfeedkey" + _hex(12),
        "ECONOMICS_FRED_API_KEY and ECONOMICS_BLS_API_KEY, the feed providers' keys (FRED's in the query, BLS's in "
        "the body)",
    ),
    "request.password": Origin(
        "cnrypw" + _hex(12), "the password in a sign-in body"
    ),
    "request.body": Origin(
        "cnrybody" + _hex(12), "text in a request body: a defender text scan, a CVE to classify"
    ),
    "request.target_userinfo": Origin(
        "cnrytarget" + _hex(12), "the password in a scan target URL's userinfo"
    ),
    "tenant.evidence": Origin(
        "cnryevidence" + _hex(12), "evidence a tenant sends: a closure document, an uploaded log file"
    ),
    "exception.message": Origin(
        "CNRYEXC" + "".join(secrets.choice(string.ascii_uppercase) for _ in range(14)),
        "the message of an exception a route raises",
    ),
}
CANARY = {name: origin.canary for name, origin in ORIGINS.items()}
_EXTRA = {
    "signing.key": {
        "seed.b64": base64.b64encode(_SIGNING_SEED).decode("ascii"),
        "seed.b64url": base64.urlsafe_b64encode(_SIGNING_SEED).decode("ascii").rstrip("="),
    }
}

#: The credentials: none of them belongs in any sink.
CREDENTIALS = frozenset(
    {
        "connector.token",
        "posture.token",
        "credential.key",
        "engine.api_key",
        "minotaur.outcomes_key",
        "gate.token",
        "effect.token",
        "closure.token",
        "failsafe.poll_token",
        "failsafe.service_token",
        "signing.key",
        "proxy.userinfo",
        "request.password",
        "economics.feed_key",
    }
)

SINKS: dict[str, str] = {
    "api.answers": "every answer an API route gives: JSON, text, and a stop's answer",
    "api.receipts": "the receipt, the assurance receipt and the signed assurance receipt",
    "api.packs": "evidence packs: the assurance packs, the incident pack, the vendor packet",
    "api.error_pages": "the answer to a route that raises (a 500) and to a route that does not exist",
    "exports": "every PDF a route serves, inflated: the scan report, the CVE report, the audit log",
    "mail": "every e-mail sent, whole, with its attachments (PDFs inflated)",
    "logs": "every record of every logger at every level, and stdout and stderr",
    "db": "every row of every model, serialised",
    "files": "every file under MEDIA_ROOT, read whole",
    "spans": "every span this service emits: name, attributes, events, status",
    "commands": "a management command's stdout and stderr",
}
_ALL = frozenset(SINKS)


@dataclass(frozen=True)
class Declaration:
    origins: frozenset[str]
    sinks: frozenset[str]
    #: A repository path.
    where: str
    #: Words in that file that make the cells declared: verbatim, bar line breaks
    #: and comment markers.
    says: str


DECLARATIONS: tuple[Declaration, ...] = (
    Declaration(
        frozenset({"connector.token", "posture.token"}),
        _ALL,
        "assurance/views.py",
        "The credential VALUE is never returned.",
    ),
    Declaration(
        frozenset({"connector.token", "posture.token"}),
        frozenset({"db"}),
        "assurance/views.py",
        "``secret`` is write-only and encrypted at rest",
    ),
    Declaration(
        frozenset({"engine.api_key", "connector.token", "posture.token", "minotaur.outcomes_key", "proxy.userinfo",
                   "economics.feed_key"}),
        _ALL,
        "safety/outbound.py",
        "No error quotes a credential.",
    ),
    Declaration(
        frozenset({"economics.feed_key"}),
        _ALL,
        "assurance/economics/feeds.py",
        "a key's value is never printed, logged, recorded or quoted, and a source version records the URL it was "
        "read from WITHOUT it.",
    ),
    Declaration(
        frozenset({"minotaur.outcomes_key"}),
        _ALL,
        "assurance/closure_forward.py",
        "One line for an operator; never the key.",
    ),
    Declaration(
        frozenset({"proxy.userinfo"}),
        _ALL,
        "safety/outbound.py",
        "A proxy's userinfo is withheld from every error and answer.",
    ),
    Declaration(
        frozenset({"credential.key", "gate.token", "effect.token", "closure.token", "failsafe.poll_token",
                   "failsafe.service_token", "signing.key", "request.password"}),
        _ALL,
        "README.md",
        "A credential this service holds or is sent reaches no answer, record, export, e-mail, log, file, span or command output",
    ),
    Declaration(
        frozenset({"request.target_userinfo"}),
        frozenset({"api.answers", "api.receipts", "api.packs", "exports", "mail", "files"}),
        "pentest/models.py",
        "The scan keeps the URL it was launched with (a reconcile sends that launch again, unchanged); every "
        "answer, report and e-mail shows this.",
    ),
    Declaration(
        frozenset(ORIGINS),
        frozenset({"api.error_pages"}),
        "README.md",
        "an error page says that something failed, never what it was given or what the exception said",
    ),
)

DECLARED = "declared"
NOT_DECLARED = "not declared"


def _status(origin: str, sink: str) -> str:
    if any(origin in d.origins and sink in d.sinks for d in DECLARATIONS):
        return DECLARED
    return NOT_DECLARED


MATRIX: dict[tuple[str, str], str] = {(o, s): _status(o, s) for o in ORIGINS for s in SINKS}

PATHS: dict[str, str] = {
    "boot": "health, a sign-in with a password, a token refresh",
    "scan_success": "an engagement, a scan that completes, its report downloaded and e-mailed",
    "scan_failure": "a scan of a target with a login, a CVE classification and a defender text scan the "
    "engine refuses with a page that quotes the request back, X-API-Key and the target included",
    "scan_timeout_and_retry": "a scan whose launch answer never comes, then its reconcile",
    "scan_stop": "a scan's Stop delivered; a Stop owed while the engine is down, and delivered by "
    "manage.py deliver_owed_stops; both again with the engine's stop route answering 308 to its new path",
    "connectors": "a webhook and a posture binding written; pushes and reads that succeed, fail with "
    "a page quoting the request, and run past their deadline",
    "closure_forward": "a closure recorded by the engine service and forwarded; refused; retried by "
    "manage.py retry_closure_forwards",
    "gate_and_effects": "the gate's approval read, an observed effect signed by the test keyring's key, "
    "and a signed assurance receipt",
    "failsafe": "the engines' poll, a stop draft on the service token, the state read",
    "uploads": "a defender text scan and a log file uploaded",
    "proxy": "every outbound call with a credentialed proxy in the environment: the engine reached through "
    "it (a scan launched and stopped; a Stop refused by the proxy's page quoting the request back, owed, "
    "and delivered by manage.py deliver_owed_stops), every other call not",
    "route_raises": "a route that raises with a message, and a route that does not exist",
    "records": "claims derived, a provider and its assertion written, a retest opened",
    "feeds": "manage.py fetch_financial_source reads FRED with its key in the query, and is refused by a BLS that "
    "quotes the request back, its key in the body; one with no key set; the deployment's data health read",
    "read_everything": "every route that reads, over every object the paths made",
}

# ---------------------------------------------------------------------------
# The services this backend calls, on loopback
# ---------------------------------------------------------------------------

STALL_SECONDS = 3.0


def _canonical(document) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class Fake:
    """A loopback HTTP service. ``mode`` is ``"ok"``, ``"echo"`` (500 with a page that
    quotes the request back: its headers and its body, as a debugging proxy's error
    page does) or ``"stall"`` (no answer for STALL_SECONDS). ``routes`` answers
    ``(method, path, headers, body) -> (status, json)``, or ``(status, json, headers)``."""

    def __init__(self, name, routes):
        self.name = name
        self.mode = "ok"
        self.routes = routes
        self.seen: list[tuple[str, str, dict]] = []
        self.lock = threading.Lock()
        fake = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _any(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                with fake.lock:
                    fake.seen.append((self.command, self.path, dict(self.headers)))
                    mode = fake.mode
                if mode == "stall":
                    time.sleep(STALL_SECONDS)
                headers = {}
                if mode == "echo":
                    status, answer = 500, {
                        "detail": "upstream error",
                        "request": {"headers": dict(self.headers), "body": body.decode("utf-8", "replace")},
                    }
                else:
                    status, answer, *more = fake.routes(self.command, self.path, dict(self.headers), body)
                    headers = more[0] if more else {}
                payload = json.dumps(answer).encode()
                try:
                    self.send_response(status)
                    for name, value in headers.items():
                        self.send_header(name, value)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except OSError:
                    return

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = do_CONNECT = _any

            def log_message(self, *_args):
                return None

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.server.handle_error = lambda *_args: None
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


class Engine:
    """The engine, as this backend reaches it: launches, a run's record, a stop, the
    defender, CVE classification, the failsafe's state, a receipt to sign, and the
    governance reads. A run completes when it is read unless ``hold`` is set. With
    ``moved_stop`` set, its stop route answers 308 to the same path with a trailing
    slash, where the stop is taken."""

    def __init__(self, signing_key):
        from tests.test_a_lost_launch_answer_reads_unknown import ACCEPTED, COMPLETED

        self.accepted, self.completed = ACCEPTED, COMPLETED
        self.signing_key = signing_key
        self.runs: dict[str, dict] = {}
        self.hold = False
        self.moved_stop = False
        self.fake = Fake("engine", self.answer)

    def answer(self, method, path, headers, body):
        from tests.test_a_signed_receipt_says_when_it_was_issued import _engine_bytes, _envelope

        document = json.loads(body or b"{}") if body else {}
        if path == "/defend":
            return 200, {"allow": True, "action": "allow"}
        if (method, path) == ("POST", "/api/scan"):
            run_id = str(uuid.uuid4())
            # The engine names a target with its userinfo replaced (athena-engine's
            # engine/utils/redaction.py), as this one does.
            target = re.sub(r"//[^/@]*@", "//[redacted]@", str(document.get("target") or ""))
            self.runs[run_id] = {
                "run_id": run_id, "kind": "scan", "target": target, "state": "running",
                "done": False, "reason": None, "result": None, "key_hash": "operator-key-hash",
            }
            return 202, dict(self.accepted, run_id=run_id, status_url=f"/api/scans/{run_id}")
        if method == "POST" and path.startswith("/api/scans/") and path.endswith("/abort") and self.moved_stop:
            return 308, {}, {"Location": path + "/"}
        if method == "POST" and path.startswith("/api/scans/") and path.endswith(("/abort", "/abort/")):
            run_id = path.removeprefix("/api/scans/").removesuffix("/").removesuffix("/abort")
            run = self.runs.get(run_id)
            if run is None:
                return 404, {"detail": "No such scan run"}
            run.update(state="aborted", done=True, reason=document.get("reason"), result={"stopped": True})
            return 200, {"run_id": run_id, "state": "aborting", "recorded": True}
        if method == "GET" and path.startswith("/api/scans/"):
            run = self.runs.get(path.removeprefix("/api/scans/"))
            if run is None:
                return 404, {"detail": "No such scan run"}
            if run["state"] == "running" and not self.hold:
                run.update(state="completed", done=True, result=copy.deepcopy(self.completed["result"]))
            return 200, copy.deepcopy(run)
        if path == "/api/assurance/receipt/sign":
            return 200, _envelope(_engine_bytes(document.get("receipt")), self.signing_key)
        if path == "/api/classify-cve":
            return 200, {"label": "CWE-79", "confidence": 0.9}
        if path in ("/api/defend-log/text", "/api/defend-log/file"):
            return 200, {"verdict": "benign", "findings": []}
        if path == "/api/failsafe/state":
            return 200, {"engine_id": "athena-engine", "state": "running", "since": None}
        if path == "/api/assurance/check":
            return 200, {"verdict": "unchanged"}
        return 404, {"detail": f"no {method} {path}"}


def _service(method, path, headers, body):
    """A connector's system, a posture source and Minotaur: everything is accepted."""
    if path.endswith("/remediation-outcomes"):
        return 201, {"id": 1}
    if method == "GET":
        return 200, {"items": [], "public_access_block": True, "encryption": "aws:kms"}
    return 201, {"id": "EXT-1", "key": "EXT-1"}


@contextlib.contextmanager
def _in_mode(fake, mode):
    fake.mode = mode
    try:
        yield
    finally:
        fake.mode = "ok"


def _closed_base() -> str:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# Logs, stdout and stderr
# ---------------------------------------------------------------------------


class _Lines:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._parts: list[str] = []

    def write(self, text) -> int:
        with self._lock:
            self._parts.append(str(text))
        return len(text)

    def flush(self) -> None:
        return None

    def isatty(self) -> bool:
        return False

    def drain(self) -> str:
        with self._lock:
            text, self._parts = "".join(self._parts), []
        return text


class _Tee:
    def __init__(self, sink: _Lines, through) -> None:
        self.sink = sink
        self.through = through

    def write(self, text) -> int:
        self.sink.write(text)
        with contextlib.suppress(Exception):
            self.through.write(text)
        return len(text)

    def flush(self) -> None:
        with contextlib.suppress(Exception):
            self.through.flush()

    def isatty(self) -> bool:
        return False

    def fileno(self):
        return self.through.fileno()


_FORMAT = logging.Formatter("%(asctime)s [%(levelname)s] %(name)s %(message)s")
_HARNESS_LOGGERS = ("urllib3", "asyncio", "faker")
#: The HTTP client's logger: its records are searched on the paths that set
#: ``World.client_records`` (the feeds path), as its own filters leave them for a
#: handler (safety.outbound's ``_ClientRecordFilter``). Everywhere else it is the
#: harness's, as before.
_CLIENT_LOGGER = "urllib3"


def _record_line(record: logging.LogRecord) -> str:
    try:
        return _FORMAT.format(record) + "\n"
    except Exception:  # noqa: BLE001 - a record that cannot format is kept raw
        return repr(record.__dict__) + "\n"


# ---------------------------------------------------------------------------
# PDFs: their streams are compressed, so they are inflated before the search
# ---------------------------------------------------------------------------

_STREAM = re.compile(rb"stream\r?\n(.*?)endstream", re.DOTALL)


def _pdf_texts(data: bytes) -> list[str]:
    """The PDF whole, and every stream in it decoded: Flate, and ASCII85 then Flate
    (reportlab's ``[/ASCII85Decode /FlateDecode]``)."""
    texts = [data.decode("latin-1")]
    for match in _STREAM.finditer(data):
        raw = match.group(1).strip()
        candidates = [raw]
        with contextlib.suppress(Exception):
            candidates.append(base64.a85decode(raw if raw.startswith(b"<~") else b"<~" + raw, adobe=True))
        for candidate in candidates:
            for window in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
                with contextlib.suppress(zlib.error):
                    texts.append(zlib.decompress(candidate, window).decode("latin-1"))
                    break
    return texts


# ---------------------------------------------------------------------------
# The world
# ---------------------------------------------------------------------------


@dataclass
class PathRun:
    name: str
    documents: dict[str, list[tuple[str, object]]]
    signals: dict[str, object]


@dataclass
class Timed:
    what: str
    seconds: float
    bound: float


@dataclass
class World:
    tmp: Path
    patch: pytest.MonkeyPatch = field(default_factory=pytest.MonkeyPatch)
    paths: list[PathRun] = field(default_factory=list)
    called: set[tuple[str, str]] = field(default_factory=set)
    timed: list[Timed] = field(default_factory=list)
    #: Whether urllib3's records are searched too (the feeds path).
    client_records: bool = False

    # -- set-up ----------------------------------------------------------------

    def start(self) -> None:
        from django.contrib.auth import get_user_model
        from django.core import mail
        from django.test.utils import override_settings
        from mythos_core import tracing

        from ai_engine.services import cyberengine_client as cec
        from assurance import closure_forward, gate_approval, observed_effects, observed_outcomes
        from tests import signed_chains
        from tests.test_an_exception_reaches_a_span_as_its_type_alone import _SDKLikeTrace, _Status, _StatusCode

        self.state = self.tmp / "state"
        self.media = self.state / "media"
        self.media.mkdir(parents=True)
        keys = self.tmp / "keys"
        keys.mkdir()

        self.signing_key = Ed25519PrivateKey.from_private_bytes(_SIGNING_SEED)
        self.engine = Engine(self.signing_key)
        self.service = Fake("service", _service)

        # The test keyring: Achilles' observed-effect key is the canary seed's (one
        # key has one engine, so the other engines keep their own).
        self.patch.setitem(signed_chains.ENGINE_KEYS, "achilles-effect", self.signing_key)
        keyring = keys / "outcome-keyring.json"
        signed_chains.write_keyring(keyring)
        self.patch.setenv(observed_outcomes.KEYRING_ENV, str(keyring))

        User = get_user_model()
        self.User = User
        env = {
            "MINOTAUR_OUTCOMES_KEY": CANARY["minotaur.outcomes_key"],
            gate_approval.TOKEN_ENV: CANARY["gate.token"],
            gate_approval.USER_ENV: "gate-reader",
            observed_effects.TOKEN_ENV: CANARY["effect.token"],
            observed_effects.USER_ENV: "effect-service",
        }
        for name, value in env.items():
            self.patch.setenv(name, value)
        for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
            self.patch.setenv(name, "")
        for name in ("NO_PROXY", "no_proxy"):
            self.patch.setenv(name, "127.0.0.1,localhost")

        self.overrides = override_settings(
            CYBERENGINE_URL=self.engine.fake.base,
            CYBERENGINE_OPERATOR_KEY=CANARY["engine.api_key"],
            CLOSURE_EVIDENCE_SERVICE_TOKEN=CANARY["closure.token"],
            CLOSURE_EVIDENCE_SERVICE_USER="closure-engine",
            FAILSAFE_POLL_TOKEN=CANARY["failsafe.poll_token"],
            FAILSAFE_SERVICE_TOKEN=CANARY["failsafe.service_token"],
            FAILSAFE_SERVICE_USER="failsafe-service",
            MINOTAUR_OUTCOMES_URL=self.service.base + "/",
            MINOTAUR_RUNNER_KEY=None,
            ASSURANCE_CREDENTIAL_KEY=CANARY["credential.key"],
            MEDIA_ROOT=str(self.media),
            EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
            DEFENDER_TIMEOUT_SECONDS=2,
            ECONOMICS_LIVE_FEEDS_ENABLED=True,
            ECONOMICS_FRED_API_KEY=CANARY["economics.feed_key"],
            ECONOMICS_BLS_API_KEY=CANARY["economics.feed_key"],
        )
        self.overrides.enable()
        mail.outbox = []

        self.patch.setattr(cec, "SCAN_POLL_SECONDS", 0)
        self.patch.setattr(cec, "SCAN_COLLECT_SECONDS", 2)
        self.patch.setattr(cec, "ENGINE_TIMEOUT", (2.0, 2.0))
        self.patch.setattr("pentest.views.target_is_out_of_bounds", lambda url: None)
        # The closure forward's send runs where the harness can see it, on this thread.
        self.patch.setattr(closure_forward, "_spawn", lambda work: work())

        # Spans, recorded as the SDK records them; the API's Status for their status.
        api = types.ModuleType("opentelemetry")
        trace_module = types.ModuleType("opentelemetry.trace")
        trace_module.Status = _Status
        trace_module.StatusCode = _StatusCode
        api.trace = trace_module
        self.patch.setitem(sys.modules, "opentelemetry", api)
        self.patch.setitem(sys.modules, "opentelemetry.trace", trace_module)
        self.trace = _SDKLikeTrace()
        self.patch.setattr(tracing, "_otel_trace", lambda: self.trace)

        # Every record of every logger, at every level, whatever its handlers.
        self.lines = _Lines()
        lines = self.lines
        original = logging.Logger.handle

        world = self

        def handle(logger, record):
            root = record.name.split(".", 1)[0]
            if root not in _HARNESS_LOGGERS:
                lines.write(_record_line(record))
            elif root == _CLIENT_LOGGER and world.client_records and logger.filter(record):
                # As a handler receives it: after the logger's own filters.
                lines.write(_record_line(record))
            return original(logger, record)

        self.patch.setattr(logging.Logger, "handle", handle)
        self._levels = {}
        for name, logger in [("", logging.getLogger()), *logging.root.manager.loggerDict.items()]:
            if isinstance(logger, logging.Logger):
                self._levels[name] = (logger.level, logger.disabled)
                logger.setLevel(logging.DEBUG)
                logger.disabled = False
        self.patch.setattr(sys, "stdout", _Tee(self.lines, sys.stdout))
        self.patch.setattr(sys, "stderr", _Tee(self.lines, sys.stderr))

        # The people.
        self.admin = User.objects.create_user(
            username="canary-admin", password=CANARY["request.password"], role=User.Roles.ADMIN
        )
        for name in ("gate-reader", "effect-service", "closure-engine"):
            User.objects.create_user(username=name, password=None, role=User.Roles.VIEWER)
        User.objects.create_user(username="failsafe-service", password=None, role=User.Roles.ADMIN)

    def close(self) -> None:
        with contextlib.suppress(Exception):
            self.overrides.disable()
        for name, (level, disabled) in self._levels.items():
            logger = logging.getLogger(name) if name else logging.getLogger()
            logger.setLevel(level)
            logger.disabled = disabled
        self.patch.undo()
        self.engine.fake.close()
        self.service.close()

    # -- calling the API ---------------------------------------------------------

    def client(self, user=None, **credentials):
        from rest_framework.test import APIClient

        client = APIClient(raise_request_exception=False)
        if user is not None:
            client.force_authenticate(user=user)
        if credentials:
            client.credentials(**credentials)
        return client

    def call(self, docs, sink, client, method, url, route, **kwargs):
        """One request, its on-commit work run (the closure forward's send among it),
        and its answer kept under ``sink``."""
        from django.test import TestCase

        self.called.add((route, method.upper()))
        with TestCase.captureOnCommitCallbacks(execute=True):
            response = getattr(client, method.lower())(url, **kwargs)
        content = getattr(response, "content", b"")
        if not content and hasattr(response, "streaming_content"):
            content = b"".join(response.streaming_content)
        if content[:5] == b"%PDF-":
            docs["exports"].append((f"{method} {url}", _pdf_texts(content)))
        else:
            docs[sink].append((f"{method} {url}", content.decode("utf-8", "replace")))
        docs["api.answers"].append((f"{method} {url} headers", dict(response.items())))
        return response

    def command(self, docs, name, *args, raises=False):
        from django.core.management import call_command
        from django.core.management.base import CommandError

        out, err = io.StringIO(), io.StringIO()
        began = time.monotonic()
        try:
            call_command(name, *args, stdout=out, stderr=err)
            failed = None
        except CommandError as exc:
            failed = str(exc)
            if not raises:
                raise
        elapsed = time.monotonic() - began
        docs["commands"].append((name, {"stdout": out.getvalue(), "stderr": err.getvalue(), "error": failed}))
        return failed, elapsed

    # -- collecting every sink ---------------------------------------------------

    def collect(self, name, docs, signals) -> None:
        from django.apps import apps
        from django.core import mail, serializers

        from assurance import oplog

        oplog.drain()
        rows = {}
        for model in apps.get_models():
            rows[model._meta.label] = serializers.serialize("json", model._default_manager.all())
        docs["db"].append(("rows", rows))
        files = {
            str(path.relative_to(self.state)): path.read_bytes()
            for path in sorted(self.state.rglob("*"))
            if path.is_file()
        }
        docs["files"].append(("files", files))
        for label, data in files.items():
            if data[:5] == b"%PDF-":
                docs["files"].append((label, _pdf_texts(data)))
        for message in mail.outbox:
            whole = message.message().as_bytes()
            docs["mail"].append((message.subject, whole.decode("latin-1")))
            for attachment in message.attachments:
                content = attachment[1] if isinstance(attachment, tuple) else attachment.get_payload(decode=True)
                if isinstance(content, bytes) and content[:5] == b"%PDF-":
                    docs["mail"].append((f"{message.subject} attachment", _pdf_texts(content)))
        mail.outbox = []
        spans = []
        for span in self.trace.spans:
            spans.append({"name": span.name, "attributes": dict(span.attributes), "events": span.events,
                          "status": span.status})
        self.trace.spans.clear()
        docs["spans"].append(("spans", spans))
        docs["logs"].append(("logs", self.lines.drain()))
        self.paths.append(PathRun(name, dict(docs), signals))

    def run(self, name, body) -> None:
        docs: dict[str, list[tuple[str, object]]] = collections.defaultdict(list)
        signals: dict[str, object] = {}
        self.lines.drain()
        self.trace.spans.clear()
        try:
            body(docs, signals)
        except Exception as exc:  # noqa: BLE001 - a path that broke is reported, not hidden
            import traceback

            signals["broke"] = "".join(traceback.format_exception(exc))
        self.collect(name, docs, signals)

    # -- the objects the paths share ------------------------------------------------

    def _engagement(self, docs, admin_client):
        from django.utils import timezone

        now = timezone.now()
        answer = self.call(
            docs, "api.answers", admin_client, "post", "/api/pentest/engagements/", "pentest:engagements",
            data={"name": "Client Q3", "client_name": "Acme", "status": "running",
                  "scope_hosts": ["offline.invalid"],
                  "testing_window_start": (now - timedelta(hours=1)).isoformat(),
                  "testing_window_end": (now + timedelta(hours=2)).isoformat()},
            format="json",
        )
        assert answer.status_code == 201, answer.content
        return answer.json()["id"]

    def _deployment(self):
        from assurance.models import Deployment, Finding

        if getattr(self, "deployment", None) is None:
            self.deployment = Deployment.objects.create(name="canary-deployment", owner=self.admin)
            self.finding = Finding.objects.create(
                deployment=self.deployment, fingerprint="fp-canary", finding_type="sql_injection",
                title="SQLi", severity="critical", retest_required=True,
            )
        return self.deployment, self.finding

    def _launch(self, docs, client, engagement_id, target=None, **extra):
        return self.call(
            docs, "api.answers", client, "post", "/api/pentest/scan/", "pentest:run_pentest_scan",
            data={"url": target or "https://offline.invalid/", "consent": True, "engagement_id": engagement_id,
                  **extra},
            format="json",
        )

    # -- the paths -------------------------------------------------------------------

    def boot(self, docs, signals):
        anonymous = self.client()
        signals["health"] = self.call(docs, "api.answers", anonymous, "get", "/api/health/", "health").status_code
        token = self.call(
            docs, "api.answers", anonymous, "post", "/api/token/", "token_obtain_pair",
            data={"username": "canary-admin", "password": CANARY["request.password"]}, format="json",
        )
        signals["sign_in"] = token.status_code
        wrong = self.call(
            docs, "api.answers", anonymous, "post", "/api/token/", "token_obtain_pair",
            data={"username": "canary-admin", "password": CANARY["request.password"] + "x"}, format="json",
        )
        signals["wrong_password"] = wrong.status_code
        refresh = (token.json() or {}).get("refresh") if token.status_code == 200 else None
        if refresh:
            signals["refresh"] = self.call(
                docs, "api.answers", anonymous, "post", "/api/token/refresh/", "token_refresh",
                data={"refresh": refresh}, format="json",
            ).status_code

    def scan_success(self, docs, signals):
        admin = self.client(self.admin)
        engagement = self._engagement(docs, admin)
        self.engagement_id = engagement
        target = f"https://scanner:{CANARY['request.target_userinfo']}@offline.invalid/"
        launched = self._launch(docs, admin, engagement, target, recipient_email="ciso@example.com")
        signals["launch"] = launched.status_code
        scan_id = launched.json().get("scan_id")
        self.scan_ids = [scan_id]
        signals["status"] = self.call(
            docs, "api.answers", admin, "get", f"/api/pentest/scans/{scan_id}/", "pentest:detail_pentest_scan"
        ).json().get("status")
        pdf = self.call(docs, "exports", admin, "get", f"/api/pentest/scans/{scan_id}/pdf/", "pentest:download_scan_pdf")
        signals["pdf"] = pdf.status_code
        signals["email"] = self.call(
            docs, "api.answers", admin, "post", f"/api/pentest/scans/{scan_id}/email/", "pentest:resend_scan_email",
            data={"recipient_email": "ciso@example.com"}, format="json",
        ).status_code

    def scan_failure(self, docs, signals):
        from pentest.models import PentestScan

        admin = self.client(self.admin)
        self.engine.fake.mode = "echo"
        try:
            target = f"https://scanner:{CANARY['request.target_userinfo']}@offline.invalid/"
            launched = self._launch(docs, admin, self.engagement_id, target)
            signals["launch"] = launched.status_code
            self.scan_ids.append(launched.json().get("scan_id"))
            signals["classify"] = self.call(
                docs, "api.answers", admin, "post", "/api/detection/cve/classify/", "detection:cve-classify",
                data={"text": f"CVE text {CANARY['request.body']}"}, format="json",
            ).status_code
            signals["defender_text"] = self.call(
                docs, "api.answers", admin, "post", "/api/detection/defender/text/", "detection:defender-text-scan",
                data={"content": f"log text {CANARY['request.body']}"}, format="json",
            ).status_code
        finally:
            self.engine.fake.mode = "ok"
        echoed = [h for _m, _p, h in self.engine.fake.seen if h.get("X-Api-Key") or h.get("X-API-Key")]
        signals["engine_got_key"] = bool(echoed)
        # The scan the engine refused was launched with the login, and keeps it.
        signals["failed_scan_has_a_login"] = PentestScan.objects.get(uuid=launched.json().get("scan_id")).target_url == target
        # The page quoting the request came back, and what this service kept of it
        # says the key was withheld: the leak was driven, not missed.
        failed = launched.json()
        signals["echo_answered"] = "upstream error" in json.dumps(failed) and "[withheld]" in json.dumps(failed)

    def scan_timeout_and_retry(self, docs, signals):
        admin = self.client(self.admin)
        self.engine.fake.mode = "stall"
        try:
            launched = self._launch(docs, admin, self.engagement_id)
        finally:
            self.engine.fake.mode = "ok"
        signals["launch"] = launched.status_code
        scan_id = launched.json().get("scan_id")
        self.scan_ids.append(scan_id)
        signals["status"] = launched.json().get("status")
        reconciled = self.call(
            docs, "api.answers", admin, "post", f"/api/pentest/scans/{scan_id}/reconcile/",
            "pentest:reconcile_pentest_scan", format="json",
        )
        signals["reconcile"] = reconciled.status_code

    def scan_stop(self, docs, signals):
        from django.test.utils import override_settings

        admin = self.client(self.admin)
        self.engine.hold = True
        try:
            launched = self._launch(docs, admin, self.engagement_id)
            scan_id = launched.json().get("scan_id")
            self.scan_ids.append(scan_id)
            began = time.monotonic()
            stopped = self.call(
                docs, "api.answers", admin, "post", f"/api/pentest/scans/{scan_id}/stop/",
                "pentest:stop_pentest_scan", data={}, format="json",
            )
            self.timed.append(Timed("a scan's Stop, delivered", time.monotonic() - began, STOP_BOUND_SECONDS))
            signals["stop"] = (stopped.status_code, (stopped.json().get("stop") or {}).get("state"))

            launched = self._launch(docs, admin, self.engagement_id)
            owed_id = launched.json().get("scan_id")
            self.scan_ids.append(owed_id)
            with override_settings(CYBERENGINE_URL=_closed_base()):
                began = time.monotonic()
                owed = self.call(
                    docs, "api.answers", admin, "post", f"/api/pentest/scans/{owed_id}/stop/",
                    "pentest:stop_pentest_scan", data={}, format="json",
                )
                self.timed.append(Timed("a scan's Stop, owed", time.monotonic() - began, STOP_BOUND_SECONDS))
                failed, elapsed = self.command(docs, "deliver_owed_stops", raises=True)
                self.timed.append(Timed("deliver_owed_stops, engine down", elapsed, DELIVER_BOUND_SECONDS))
            signals["owed"] = (owed.status_code, (owed.json().get("stop") or {}).get("state"), bool(failed))
            failed, elapsed = self.command(docs, "deliver_owed_stops")
            self.timed.append(Timed("deliver_owed_stops, delivered", elapsed, DELIVER_BOUND_SECONDS))
            signals["delivered"] = self.call(
                docs, "api.answers", admin, "get", f"/api/pentest/scans/{owed_id}/", "pentest:detail_pentest_scan"
            ).json().get("stop", {}).get("state")

            # The engine's stop route moved: it answers 308 to the same path with a
            # trailing slash. The Stop, and an owed one deliver_owed_stops sends, land.
            self.engine.moved_stop = True
            signals["moved"] = self._stop_twice(
                docs, admin, "through a same-host redirect", lambda: override_settings(CYBERENGINE_URL=_closed_base())
            )
            signals["moved_followed"] = any(
                p.endswith("/abort/") for _m, p, _h in self.engine.fake.seen
            )
        finally:
            self.engine.hold = False
            self.engine.moved_stop = False

    def _stop_twice(self, docs, admin, how, unanswered):
        """A scan's Stop, delivered; and one owed while ``unanswered()`` holds (the
        engine down, or refusing), then delivered by deliver_owed_stops -- each timed
        against its bound. Their states, as the scan's answer says them."""
        launched = self._launch(docs, admin, self.engagement_id)
        scan_id = launched.json().get("scan_id")
        self.scan_ids.append(scan_id)
        began = time.monotonic()
        stopped = self.call(
            docs, "api.answers", admin, "post", f"/api/pentest/scans/{scan_id}/stop/",
            "pentest:stop_pentest_scan", data={}, format="json",
        )
        self.timed.append(Timed(f"a scan's Stop, {how}", time.monotonic() - began, STOP_BOUND_SECONDS))
        launched = self._launch(docs, admin, self.engagement_id)
        owed_id = launched.json().get("scan_id")
        self.scan_ids.append(owed_id)
        with unanswered():
            owed = self.call(
                docs, "api.answers", admin, "post", f"/api/pentest/scans/{owed_id}/stop/",
                "pentest:stop_pentest_scan", data={}, format="json",
            )
        _failed, elapsed = self.command(docs, "deliver_owed_stops")
        self.timed.append(Timed(f"deliver_owed_stops, {how}", elapsed, DELIVER_BOUND_SECONDS))
        delivered = self.call(
            docs, "api.answers", admin, "get", f"/api/pentest/scans/{owed_id}/", "pentest:detail_pentest_scan"
        ).json().get("stop", {}).get("state")
        return {
            "stop": (stopped.status_code, (stopped.json().get("stop") or {}).get("state")),
            "owed": (owed.json().get("stop") or {}).get("state"),
            "delivered": delivered,
        }

    def connectors(self, docs, signals):
        from django.test.utils import override_settings

        dep, finding = self._deployment()
        admin = self.client(self.admin)
        base = f"/api/assurance/deployments/{dep.uuid}/"
        put = self.call(
            docs, "api.answers", admin, "put", base + "connectors/webhook/config/", "deployment-connector-config",
            data={"enabled": True, "endpoint": {"url": self.service.base + "/hooks/athena"},
                  "secret": CANARY["connector.token"]}, format="json",
        )
        signals["bind_webhook"] = put.status_code
        put = self.call(
            docs, "api.answers", admin, "put", base + "posture/cloud/config/", "deployment-posture-config",
            data={"enabled": True, "endpoint": {"base_url": self.service.base, "url": self.service.base,
                                               "account": "123456789012"},
                  "secret": CANARY["posture.token"]}, format="json",
        )
        signals["bind_posture"] = put.status_code
        pushes = {}
        for mode in ("ok", "echo", "stall"):
            self.service.mode = mode
            # A push that runs past its deadline: the deadline is under the stall.
            deadline = override_settings(ASSURANCE_CONNECTOR_DEADLINE_SECONDS=1 if mode == "stall" else 30)
            deadline.enable()
            try:
                answer = self.call(
                    docs, "api.answers", admin, "post", base + "connectors/webhook/push/", "deployment-connector-push",
                    data={"finding": str(finding.uuid)}, format="json", HTTP_IDEMPOTENCY_KEY=str(uuid.uuid4()),
                )
                pushes[mode] = (answer.status_code, (answer.json() or {}).get("ok"))
                read = self.call(
                    docs, "api.answers", admin, "get", base + "cloud-posture/", "deployment-cloud-posture"
                )
                pushes[f"posture-{mode}"] = read.status_code
            finally:
                deadline.disable()
                self.service.mode = "ok"
        signals["pushes"] = pushes
        signals["webhook_got_token"] = any(
            h.get("X-Athena-Token") == CANARY["connector.token"] for _m, _p, h in self.service.seen
        )

    def closure_forward(self, docs, signals):
        from tests.test_a_closure_stands_only_on_a_replay_the_engine_service_recorded import (
            _body,
            _document,
            _finding,
        )

        statuses = {}
        for mode in ("ok", "echo"):
            finding = _finding()
            document = _document(
                finding,
                remediation={"kind": "parameterised query",
                             "control_changed": f"orders search query {CANARY['tenant.evidence']}"},
            )
            self.service.mode = mode
            try:
                answer = self.call(
                    docs, "api.answers", self.client(HTTP_X_CLOSURE_EVIDENCE_TOKEN=CANARY["closure.token"]),
                    "post", f"/api/assurance/findings/{finding.uuid}/closure-evidence/", "finding-closure-evidence",
                    data=_body(document), format="json",
                )
            finally:
                self.service.mode = "ok"
            statuses[mode] = answer.status_code
        signals["recorded"] = statuses
        signals["retry_left"] = self.command(docs, "retry_closure_forwards", raises=True)[0]
        signals["minotaur_got_key"] = any(
            h.get("X-Minotaur-Key") == CANARY["minotaur.outcomes_key"] for _m, _p, h in self.service.seen
        )

    def gate_and_effects(self, docs, signals):
        from tests.test_spine_authority_chain import WF, _base, _world
        from tests.test_the_gate_attests_the_approval_it_read import _record

        dep, _client, permit, _ = _world()
        self.world_deployment = dep
        gate = self.client(HTTP_X_GATE_APPROVAL_TOKEN=CANARY["gate.token"])
        read = self.call(
            docs, "api.answers", gate, "get", _base(dep) + f"workflows/{WF}/approval-in-force/",
            "deployment-approval-in-force",
        )
        signals["gate_read"] = read.status_code
        effect = self.client(HTTP_X_OBSERVED_EFFECT_TOKEN=CANARY["effect.token"])

        class _Recording:
            def __init__(inner, client):
                inner.client = client

            def post(inner, url, data=None, **kwargs):
                return self.call(docs, "api.answers", inner.client, "post", url, "deployment-observed-effects",
                                 data=data, **kwargs)

            def __getattr__(inner, name):
                return getattr(inner.client, name)

        try:
            _record(_Recording(effect), dep, permit)
            signals["effect"] = "recorded"
        except AssertionError as exc:
            signals["effect"] = f"refused: {exc}"[:300]
        signed = self.call(
            docs, "api.receipts", self.client(self.admin), "get",
            f"/api/assurance/deployments/{dep.uuid}/signed-assurance-receipt/", "deployment-signed-assurance-receipt",
            HTTP_ACCEPT="application/json",
        )
        signals["signed_receipt"] = (signed.status_code, (signed.json() or {}).get("signed"))

    def failsafe(self, docs, signals):
        poll = self.client(HTTP_X_FAILSAFE_POLL_TOKEN=CANARY["failsafe.poll_token"])
        signals["poll"] = self.call(
            docs, "api.answers", poll, "get", "/api/failsafe/pending/?engine_id=athena-engine", "failsafe:pending"
        ).status_code
        service = self.client(HTTP_X_FAILSAFE_SERVICE_TOKEN=CANARY["failsafe.service_token"])
        began = time.monotonic()
        draft = self.call(
            docs, "api.answers", service, "post", "/api/failsafe/commands/", "failsafe:commands",
            data={"action": "pause", "engine_id": "athena-engine", "reason": "canary harness"}, format="json",
        )
        self.timed.append(Timed("a pause drafted on the service token", time.monotonic() - began, STOP_BOUND_SECONDS))
        signals["draft"] = draft.status_code
        signals["state"] = self.call(
            docs, "api.answers", service, "get", "/api/failsafe/state/?engine_id=athena-engine", "failsafe:state"
        ).status_code
        signals["audit"] = self.call(
            docs, "api.answers", self.client(self.admin), "get", "/api/failsafe/audit/", "failsafe:audit"
        ).status_code

    def uploads(self, docs, signals):
        from django.core.files.uploadedfile import SimpleUploadedFile

        admin = self.client(self.admin)
        signals["text"] = self.call(
            docs, "api.answers", admin, "post", "/api/detection/defender/text/", "detection:defender-text-scan",
            data={"content": f"GET /login user=bob {CANARY['request.body']}"}, format="json",
        ).status_code
        upload = SimpleUploadedFile("app.log", f"line one {CANARY['tenant.evidence']}\n".encode(), "text/plain")
        signals["file"] = self.call(
            docs, "api.answers", admin, "post", "/api/detection/defender/file/", "detection:defender-file-scan",
            data={"uploaded_file": upload}, format="multipart",
        ).status_code
        signals["classify"] = self.call(
            docs, "api.answers", admin, "post", "/api/detection/cve/classify/", "detection:cve-classify",
            data={"text": f"a CVE {CANARY['request.body']}"}, format="json",
        ).status_code

    def proxy(self, docs, signals):
        from django.test.utils import override_settings

        # The engine is reached only through the proxy: its own address is closed, and
        # the proxy answers for it as the engine. Anything else the proxy is asked for
        # it refuses.
        engine_base = _closed_base()

        def on_the_engine_s_lane(path):
            # The defender gateway's /defend asks the engine too, on the engine's lane.
            return path.startswith(engine_base + "/") or path.endswith("/defend")

        def through(method, path, headers, body):
            if path.startswith(engine_base + "/"):
                return self.engine.answer(method, path[len(engine_base):], headers, body)
            if path.endswith("/defend"):
                return self.engine.answer(method, "/defend", headers, body)
            return 502, {"detail": "proxy"}

        proxy = Fake("proxy", through)
        url = proxy.base.replace("http://", f"http://egress:{CANARY['proxy.userinfo']}@")
        try:
            with pytest.MonkeyPatch.context() as mp:
                for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
                    mp.setenv(name, url)
                for name in ("NO_PROXY", "no_proxy"):
                    mp.setenv(name, "")
                admin = self.client(self.admin)
                with override_settings(CYBERENGINE_URL=engine_base):
                    # The proxy's page quoting the request back, Proxy-Authorization and all.
                    with _in_mode(proxy, "echo"):
                        signals["classify"] = self.call(
                            docs, "api.answers", admin, "post", "/api/detection/cve/classify/",
                            "detection:cve-classify", data={"text": "a CVE"}, format="json",
                        ).status_code
                    self.engine.hold = True
                    try:
                        signals["engine"] = self._stop_twice(
                            docs, admin, "through the environment's proxy", lambda: _in_mode(proxy, "echo")
                        )
                    finally:
                        self.engine.hold = False
                dep, finding = self._deployment()
                base = f"/api/assurance/deployments/{dep.uuid}/"
                signals["push"] = self.call(
                    docs, "api.answers", admin, "post", base + "connectors/webhook/push/", "deployment-connector-push",
                    data={"finding": str(finding.uuid)}, format="json", HTTP_IDEMPOTENCY_KEY=str(uuid.uuid4()),
                ).status_code
                signals["posture"] = self.call(
                    docs, "api.answers", admin, "get", base + "cloud-posture/", "deployment-cloud-posture"
                ).status_code
                with override_settings(MINOTAUR_OUTCOMES_URL=_closed_base() + "/"):
                    self.closure_forward(docs, {})
                    self.command(docs, "retry_closure_forwards", "--unknown", raises=True)
        finally:
            proxy.close()
        signals["engine_through_proxy"] = sum(1 for _m, p, _h in proxy.seen if p.startswith(engine_base + "/"))
        signals["defender_through_proxy"] = sum(1 for _m, p, _h in proxy.seen if p.endswith("/defend"))
        signals["others_through_proxy"] = [p for _m, p, _h in proxy.seen if not on_the_engine_s_lane(p)]
        login = base64.b64encode(f"egress:{CANARY['proxy.userinfo']}".encode()).decode()
        signals["proxy_got_login"] = any(h.get("Proxy-Authorization") == f"Basic {login}" for _m, _p, h in proxy.seen)

    def route_raises(self, docs, signals):
        from assurance import views

        dep, _finding = self._deployment()
        admin = self.client(self.admin)

        def raising(*_args, **_kwargs):
            raise RuntimeError(f"the latency table could not be read: {CANARY['exception.message']}")

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(views.DeploymentViewSet, "latency", raising, raising=True)
            answer = self.call(
                docs, "api.error_pages", admin, "get", "/api/assurance/deployments/latency/", "deployment-latency"
            )
        signals["raised"] = answer.status_code
        missing = self.call(
            docs, "api.error_pages", admin, "get",
            f"/api/no-such-route/{CANARY['request.body']}/", "<no route>",
        )
        signals["missing"] = missing.status_code

    def records(self, docs, signals):
        from django.utils import timezone

        from assurance.models import AssuranceClaim, RetestRequirement

        admin = self.client(self.admin)
        for dep in (self.deployment, getattr(self, "world_deployment", None)):
            if dep is not None:
                signals[f"claims {dep.name}"] = self.call(
                    docs, "api.answers", admin, "post", f"/api/assurance/deployments/{dep.uuid}/recompute-claims/",
                    "deployment-recompute-claims", data={}, format="json",
                ).status_code
        provider = self.call(
            docs, "api.answers", admin, "post", "/api/assurance/providers/", "provider-list",
            data={"name": "Model Host", "kind": "other", "notes": f"from the contract {CANARY['tenant.evidence']}"},
            format="json",
        )
        signals["provider"] = provider.status_code
        if provider.status_code == 201:
            signals["assertion"] = self.call(
                docs, "api.answers", admin, "post", "/api/assurance/provider-assertions/",
                "provider-assertion-list",
                data={"provider": provider.json()["uuid"], "field": "region", "value": "eu-west-1",
                      "notes": f"per the DPA {CANARY['tenant.evidence']}"},
                format="json",
            ).status_code
        claim = AssuranceClaim.objects.filter(deployment=self.deployment).first()
        if claim is not None:
            now = timezone.now()
            RetestRequirement.objects.create(
                deployment=self.deployment, claim=claim, reason="the canary harness opened it",
                triggering_system_fingerprint="sha256:" + "0" * 64, actor=self.admin, opened_at=now,
                claim_seen_at=claim.last_seen,
            )
        signals["claims"] = AssuranceClaim.objects.count()
        # The scenario builder's two routes (#149). A build the route refuses because it
        # names no effect (400); then a REAL build that is recorded (201), carrying the
        # tenant's canaries in its title and an effect's evidence; then that scenario's
        # events read back (200). builder.describe()'s output -- answered, stored on the
        # scenario, and reread -- is searched like every other sink.
        from tests.test_economics_builder import (
            _asset,
            _attr,
            _body,
            _effect,
            _finding,
            _link,
            _pset,
            _section_30_attributes,
        )

        scenarios = f"/api/assurance/deployments/{self.deployment.uuid}/economics/scenarios/"
        signals["scenario_build_refused"] = self.call(
            docs, "api.answers", admin, "post", scenarios + "build/", "deployment-economics-scenario-build",
            data={"title": f"exposure {CANARY['request.body']}", "effects": []}, format="json",
        ).status_code

        asset = _asset(self.deployment, name=f"payments-{uuid.uuid4().hex[:8]}")
        _pset(self.deployment, self.admin)
        finding = _finding(self.deployment)
        attributes = _section_30_attributes()
        attributes["incident_response_cost"] = _attr(
            "money", "80000", "165000", "250000", why=f"incident response {CANARY['tenant.evidence']}",
        )
        build_body = _body(
            [_effect("redirect", asset, attributes=attributes)],
            [_link(finding, "redirect")],
            title=f"payment loss {CANARY['request.body']}",
        )
        built = self.call(
            docs, "api.answers", admin, "post", scenarios + "build/", "deployment-economics-scenario-build",
            data=build_body, format="json",
        )
        signals["scenario_build"] = built.status_code
        scenario_uuid = built.json()["scenario"]["uuid"] if built.status_code == 201 else uuid.uuid4()
        signals["scenario_events"] = self.call(
            docs, "api.answers", admin, "get", scenarios + f"{scenario_uuid}/events/",
            "deployment-economics-scenario-events",
        ).status_code
        # Raising a financial source's trust tier (spec, section 6.1): a tenant's source
        # raised in one step, then to authoritative by request and a second admin's
        # approval; another source's request withdrawn over the API, and one more
        # requested and withdrawn by manage.py raise_source_trust. Every reason carries
        # the tenant's canaries; every raise is read back by read_everything.
        from assurance.economics.models import FinancialSource, FinancialSourceTrustRaise

        second = self.User.objects.create_user(
            username="canary-second-admin", password=None, role=self.User.Roles.ADMIN
        )
        revenue = FinancialSource.objects.create(
            deployment=self.deployment, source_key="canary-revenue", provider=f"ledger {CANARY['tenant.evidence']}",
            dataset="revenue", license_class="customer", retrieved_at=timezone.now(),
            snapshot_hash="sha256:" + "c" * 64, schema_version="1",
        )
        sources, raises = "/api/assurance/economics/sources/", "/api/assurance/economics/trust-raises/"
        trust = {}
        one_step = self.call(
            docs, "api.answers", admin, "post", f"{sources}{revenue.uuid}/trust-raises/",
            "economics-source-trust-raises",
            data={"to_tier": "customer", "reason": f"the books {CANARY['request.body']}"}, format="json",
        )
        trust["one_step"] = one_step.status_code
        latest = one_step.json()["to_version"]["uuid"] if one_step.status_code == 201 else revenue.uuid
        asked = self.call(
            docs, "api.answers", admin, "post", f"{sources}{latest}/trust-raises/", "economics-source-trust-raises",
            data={"to_tier": "authoritative", "reason": f"the ledger {CANARY['tenant.evidence']}"}, format="json",
        )
        trust["asked"] = asked.status_code
        if asked.status_code == 201:
            trust["approved"] = self.call(
                docs, "api.answers", self.client(second), "post", f"{raises}{asked.json()['uuid']}/approve/",
                "economics-trust-raise-approve", data={}, format="json",
            ).status_code
        survey = FinancialSource.objects.create(
            source_key="canary-survey", provider="an industry survey", dataset="losses", license_class="licensed",
            retrieved_at=timezone.now(), snapshot_hash="sha256:" + "d" * 64, schema_version="1",
        )
        withdrawable = self.call(
            docs, "api.answers", admin, "post", f"{sources}{survey.uuid}/trust-raises/",
            "economics-source-trust-raises",
            data={"to_tier": "authoritative", "reason": f"the survey {CANARY['request.body']}"}, format="json",
        )
        trust["withdrawable"] = withdrawable.status_code
        if withdrawable.status_code == 201:
            trust["withdrawn"] = self.call(
                docs, "api.answers", admin, "post", f"{raises}{withdrawable.json()['uuid']}/withdraw/",
                "economics-trust-raise-withdraw", data={}, format="json",
            ).status_code
        # The command authenticates its --as account with the password typed at a
        # terminal: the canary admin's own, the sign-in canary, so every sink is
        # searched for a typed password too. It never approves (refused before any
        # password is asked); any admin withdraws.
        import getpass

        class _Terminal:
            def isatty(self):
                return True

        with pytest.MonkeyPatch.context() as typing:
            typing.setattr(sys, "stdin", _Terminal())
            typing.setattr(getpass, "getpass", lambda prompt="", stream=None: CANARY["request.password"])
            self.command(
                docs, "raise_source_trust", "request", str(survey.uuid), "--to", "authoritative",
                "--reason", f"the survey again {CANARY['tenant.evidence']}", "--as", self.admin.username,
            )
            pending = FinancialSourceTrustRaise.objects.filter(from_version=survey, state="pending").first()
            if pending is not None:
                refused, _elapsed = self.command(
                    docs, "raise_source_trust", "approve", str(pending.uuid), "--as", second.username, raises=True,
                )
                trust["command_approve_refused"] = bool(refused) and "second_person_required" in refused
                self.command(docs, "raise_source_trust", "withdraw", str(pending.uuid), "--as", self.admin.username)
        trust["command"] = list(
            FinancialSourceTrustRaise.objects.filter(from_version=survey)
            .order_by("id")
            .values_list("state", "channel", "withdrawn_via")
        )
        signals["trust_raise"] = trust
        # The scenario endpoints and the report (MVP step 6): the scenario simulated
        # (201: a result is recorded, completed or refused) and its report read back
        # (200); read_everything then reads the scenario and its report again. What
        # they answer -- the scenario's title, its parameters' provenance, the report --
        # is searched like every other sink.
        signals["scenario_simulate"] = self.call(
            docs, "api.answers", admin, "post", scenarios + f"{scenario_uuid}/simulate/",
            "deployment-economics-scenario-simulate", data={"seed": 7, "policy": "quick_10k"}, format="json",
        ).status_code
        # The same route with every one of the deployment's economics run slots held
        # (assurance.economics.capacity): answered 503 economics_capacity at once,
        # before the body is read. Its answer is searched like every other, with a
        # canary in the body it was sent.
        from assurance.economics import capacity

        slots, _why = capacity.acquire(str(self.deployment.uuid))
        try:
            signals["scenario_simulate_at_capacity"] = self.call(
                docs, "api.answers", admin, "post", scenarios + f"{scenario_uuid}/simulate/",
                "deployment-economics-scenario-simulate",
                data={"seed": 8, "policy": "quick_10k", "note": f"busy {CANARY['request.body']}"}, format="json",
            ).status_code
        finally:
            if slots is not None:
                slots.release()
        signals["scenario_results"] = self.call(
            docs, "api.answers", admin, "get", scenarios + f"{scenario_uuid}/results/",
            "deployment-economics-scenario-results",
        ).status_code
        # The remediation option and its ROI (MVP step 13): one option recorded (201),
        # its current and residual runs simulated (201: each recorded, completed or
        # refused) and its ROI read back (200); read_everything reads the ROI again.
        # What they answer -- the option's title and document, the economics -- is
        # searched like every other sink.
        from tests.test_economics_remediation import option_body

        mitigated = self.call(
            docs, "api.answers", admin, "post", scenarios + f"{scenario_uuid}/mitigations/",
            "deployment-economics-scenario-mitigations",
            data=option_body("0.5", title=f"re-approve {CANARY['request.body']}"), format="json",
        )
        signals["mitigation"] = mitigated.status_code
        option_uuid = mitigated.json()["option"]["uuid"] if mitigated.status_code == 201 else uuid.uuid4()
        signals["mitigation_simulate"] = self.call(
            docs, "api.answers", admin, "post", scenarios + f"{scenario_uuid}/mitigations/{option_uuid}/simulate/",
            "deployment-economics-mitigation-simulate", data={"seed": 7, "policy": "quick_10k"}, format="json",
        ).status_code
        signals["scenario_roi"] = self.call(
            docs, "api.answers", admin, "get", scenarios + f"{scenario_uuid}/roi/", "deployment-economics-scenario-roi",
        ).status_code
        # The portfolio (E5): the deployment's scenarios totalled (201: recorded,
        # completed or refused, every scenario not totalled named with its reason)
        # and its report read back (200); read_everything reads it again. The
        # scenarios' titles and every reason it names are searched like every sink.
        portfolio_url = f"/api/assurance/deployments/{self.deployment.uuid}/economics/portfolio/"
        signals["portfolio_simulate"] = self.call(
            docs, "api.answers", admin, "post", portfolio_url + "simulate/", "deployment-economics-portfolio-simulate",
            data={"seed": 7, "policy": "quick_10k", "reporting_currency": "USD", "valuation_date": "2026-10-06"},
            format="json",
        ).status_code
        signals["portfolio"] = self.call(
            docs, "api.answers", admin, "get", portfolio_url, "deployment-economics-portfolio",
        ).status_code
        # The read routes the dashboard needs (spec, section 30): the deployment's
        # scenario versions listed (200), each with its title, which carries the
        # tenant's canaries; and a completed exposure run receipted -- signed by the
        # test keyring's key, as the engine would sign it -- and its signed bytes read
        # back (200). The built scenario's run here is a refused one, and a refused run
        # has no figures to sign (result_not_completed), so the run receipted is step
        # 6's stored scenario's. read_everything reads both again. Each is
        # searched like every other sink, the receipt's as a receipt.
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
        from mythos_core import exposure_receipt as receipt_core

        from assurance.economics import receipt_service, simulation_service
        from tests.test_economics_report import stored as stored_scenario

        signals["scenario_list"] = self.call(
            docs, "api.answers", admin, "get", scenarios, "deployment-economics-scenarios",
        ).status_code
        receipted = stored_scenario(self.deployment, self.admin, set_key="canary_receipted")
        run = simulation_service.simulate_scenario(receipted, seed=7, draws=10_000).result
        keyring = receipt_core.receipt_keyring(
            [self.signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)], other_roles={}
        )
        issued = None if run is None else receipt_service.issue_receipt(
            run, keyring=keyring, signer=lambda document: receipt_core.sign_receipt(document, self.signing_key)
        )
        signals["receipt_issued"] = None if issued is None else (issued.receipt is not None, issued.code)
        receipt_id = issued.receipt.receipt_id if issued is not None and issued.receipt is not None else uuid.uuid4().hex
        signals["receipt_bytes"] = self.call(
            docs, "api.receipts", admin, "get",
            f"/api/assurance/deployments/{self.deployment.uuid}/economics/receipts/{uuid.UUID(receipt_id)}/",
            "deployment-economics-receipt",
        ).status_code
        # Continuous financial assurance (E6, spec section 34): a new version of the
        # receipted scenario's set stales its run; the check records it (200) and the
        # deployment's assurance and the run's freshness are read (200); a refresh of
        # the receipted version, which the builder did not build, is refused (400), with
        # a canary in the body it was sent; and the operator's command runs. What they
        # answer -- the scenarios' titles and reasons, the dependency map -- is searched
        # like every other sink; read_everything reads both reads again.
        from assurance.economics.models import CustomerParameterSet
        from tests.test_economics_scenarios import _entry as set_entry

        CustomerParameterSet.record(self.deployment, "canary_receipted", {"variables": {
            "notification_unit_cost": set_entry("money_per_unit", "3"),
            "notification_fixed_cost": set_entry("money", "40000"),
        }}, author=self.admin)
        economics = f"/api/assurance/deployments/{self.deployment.uuid}/economics/"
        signals["assurance_check"] = self.call(
            docs, "api.answers", admin, "post", economics + "assurance/", "deployment-economics-assurance",
            data={}, format="json",
        ).status_code
        signals["assurance"] = self.call(
            docs, "api.answers", admin, "get", economics + "assurance/", "deployment-economics-assurance",
        ).status_code
        signals["scenario_freshness"] = self.call(
            docs, "api.answers", admin, "get", scenarios + f"{receipted.uuid}/freshness/",
            "deployment-economics-scenario-freshness",
        ).status_code
        signals["scenario_refresh"] = self.call(
            docs, "api.answers", admin, "post", scenarios + f"{receipted.uuid}/refresh/",
            "deployment-economics-scenario-refresh",
            data={"seed": 9, "policy": "quick_10k", "as_of": "2026-10-06"}, format="json",
        ).status_code
        self.command(docs, "check_financial_assurance", "--deployment", str(self.deployment.uuid))

    def feeds(self, docs, signals):
        """MVP step 10: the operator's fetch, with the providers' key planted. FRED
        answers with its observations for the window asked (the key in the query);
        BLS answers 500 with a page quoting the request, its body and the key in it;
        then BLS again with no key set. Every sink is searched for the key."""
        from django.test.utils import override_settings

        from assurance.economics import feeds as economics_feeds

        fixtures = ROOT / "tests" / "fixtures" / "economics_feeds"
        observations = json.loads(
            (fixtures / "fred-cpiaucsl-2026-10-13.json").read_bytes().partition(b"\n")[2]
        )
        def provider(method, path, headers, body):
            if path.startswith("/fred/"):
                from urllib.parse import parse_qs, urlsplit

                window = parse_qs(urlsplit(path).query)["realtime_start"][0]
                answer = copy.deepcopy(observations)
                answer.update(realtime_start=window, realtime_end=window)
                for entry in answer["observations"]:
                    entry.update(realtime_start=window, realtime_end=window)
                return 200, answer
            return 404, {"detail": f"no {method} {path}"}

        fake = Fake("feeds", provider)
        # urllib3's own records of these requests are searched too: FRED's key is in
        # the query of the request line it records at DEBUG.
        self.client_records = True
        try:
            with pytest.MonkeyPatch.context() as mp:
                mp.setattr(economics_feeds, "base_url", lambda feed: fake.base)
                self.command(docs, "fetch_financial_source", "fred-cpiaucsl")
                signals["client_request_line"] = "/fred/series/observations?" in "".join(self.lines._parts)
                with _in_mode(fake, "echo"):
                    refused, _ = self.command(docs, "fetch_financial_source", "bls-ppi-final-demand", raises=True)
                with override_settings(ECONOMICS_BLS_API_KEY=""):
                    missing, _ = self.command(docs, "fetch_financial_source", "bls-ahe-total-private", raises=True)
        finally:
            self.client_records = False
            fake.close()
        from assurance.economics.models import FinancialSourceFetch

        signals["fetches"] = list(
            FinancialSourceFetch.objects.order_by("id").values_list("source_key", "outcome", "code")
        )
        signals["bls_refused"] = bool(refused) and "fetch_http_error" in refused
        signals["no_key_refused"] = bool(missing) and "source_key_missing" in missing
        # The key went in: FRED's in the query the provider saw; BLS's in the body of
        # the POST its echo page quoted back (tests/test_economics_feeds.py pins where
        # each key goes).
        signals["provider_got_key"] = any(CANARY["economics.feed_key"] in path for _m, path, _h in fake.seen)
        signals["bls_posted"] = any(method == "POST" for method, _p, _h in fake.seen)
        dep, _finding = self._deployment()
        signals["data_health"] = self.call(
            docs, "api.answers", self.client(self.admin), "get",
            f"/api/assurance/deployments/{dep.uuid}/economics/data-health/", "deployment-economics-data-health",
        ).status_code
        # The normalization route (MVP step 12): an amount normalized for the
        # deployment over the sources a run of it may use; what it answers is searched
        # like every other sink.
        from urllib.parse import urlencode

        normalization = urlencode({
            "amount": "400000", "currency": "EUR", "event_date": "2026-09-30", "valuation_date": "2026-09-30",
            "base_currency": "USD", "reporting_currency": "USD", "providers": "ECB,FRB-H10",
            "index_series_id": "CPIAUCSL", "index_geography": "US",
            "index_category": "consumer prices, all items", "index_base": "1982-1984=100",
        })
        signals["normalization"] = self.call(
            docs, "api.answers", self.client(self.admin), "get",
            f"/api/assurance/deployments/{dep.uuid}/economics/normalization/?{normalization}",
            "deployment-economics-normalization",
        ).status_code

    def read_everything(self, docs, signals):
        admin = self.client(self.admin)
        read, failed = 0, []
        for route, url in _readable_urls(self):
            sink = READ_SINKS.get(route, "api.answers")
            answer = self.call(docs, sink, admin, "get", url, route, HTTP_ACCEPT="application/json")
            read += 1
            if answer.status_code >= 500:
                failed.append((route, answer.status_code))
        signals["read"] = read
        signals["failed"] = failed


#: How long a scan's Stop, owed or delivered, may take here, end to end, and how long
#: deliver_owed_stops may take for one owed Stop. The engine's timeout here is 2 s
#: (connect and read), so a Stop that waits on nothing else ends inside one of them.
STOP_BOUND_SECONDS = 5.0
DELIVER_BOUND_SECONDS = 5.0


# ---------------------------------------------------------------------------
# Every route, and what it is
# ---------------------------------------------------------------------------

_DOCS = "not an export: "
_READ = "api.answers"

#: Every route this service serves, by name, and the sink its answer is -- or why it
#: is not one. A route that is an export is called by some path above.
ROUTES: dict[str, str] = {
    "health": _READ,
    "api-root": _DOCS + "the API's index of routes",
    "token_obtain_pair": _READ,
    "token_refresh": _READ,
    "accounts:api-root": _DOCS + "the accounts API's index of routes",
    "accounts:user-list": _READ,
    "accounts:user-detail": _READ,
    "accounts:user-me": _READ,
    "accounts:user-set-role": _DOCS + "a role change: answers the user it changed, as user-detail reads it",
    "audit_log_list": _READ,
    "export_pdf": "exports",
    "detection:cve-classify": _READ,
    "detection:cve-detail": _READ,
    "detection:cve-email": _DOCS + "e-mails the CVE report, searched as mail when sent",
    "detection:cve-list": _READ,
    "detection:cve-pdf": "exports",
    "detection:defender-detail": _READ,
    "detection:defender-file-scan": _READ,
    "detection:defender-list": _READ,
    "detection:defender-text-scan": _READ,
    "failsafe:audit": _READ,
    "failsafe:cancel-command": _DOCS + "withdraws a draft; answers the command, as command-detail reads it",
    "failsafe:command-detail": _READ,
    "failsafe:commands": _READ,
    "failsafe:pending": _READ,
    "failsafe:state": _READ,
    "failsafe:submit-signature": _DOCS + "a signature on a command; answers the command, as command-detail reads it",
    "pentest:allowed_pentest_checks": _READ,
    "pentest:detail_pentest_scan": _READ,
    "pentest:download_scan_pdf": "exports",
    "pentest:engagement_detail": _READ,
    "pentest:engagement_plan": _DOCS + "a plan for an engagement the caller sends; reads no scan",
    "pentest:engagements": _READ,
    "pentest:list_pentest_scans": _READ,
    "pentest:pentest_scan_status": _READ,
    "pentest:reconcile_pentest_scan": _READ,
    "pentest:resend_scan_email": _READ,
    "pentest:run_llm_pentest_scan": _DOCS + "an LLM scan's launch; answers as run_pentest_scan does, "
    "and is refused without an LLM engine here",
    "pentest:run_pentest_scan": _READ,
    "pentest:stop_pentest_scan": _READ,
    "asset-detail": _READ,
    "asset-list": _READ,
    "claim-declare-latent-condition": _DOCS + "declares a latent condition; answers it, as claim-latent-conditions reads it",
    "claim-detail": _READ,
    "claim-events": _READ,
    "claim-evidence": _READ,
    "claim-list": _READ,
    "claim-transition": _DOCS + "moves a claim; answers it, as claim-detail reads it",
    "claim-withdraw-latent-condition": _DOCS + "withdraws a latent condition; answers it, as claim-latent-conditions reads it",
    "finding-assignable": _READ,
    "finding-closure-evidence": _READ,
    "finding-detail": _READ,
    "finding-incident-pack": "api.packs",
    "finding-list": _READ,
    "finding-remediation": _READ,
    "finding-remediation-assign": _DOCS + "assigns a finding's remediation; answers it, as finding-remediation reads it",
    "finding-remediation-transition": _DOCS + "moves a remediation; answers it, as finding-remediation reads it",
    "finding-repair-contracts": _READ,
    "finding-vendor-packet": "api.packs",
    "provider-assertion-detail": _READ,
    "provider-assertion-list": _READ,
    "provider-detail": _READ,
    "provider-list": _READ,
    "retest-requirement-detail": _READ,
    "retest-requirement-list": _READ,
    "unknown-detail": _READ,
    "unknown-list": _READ,
}
_DEPLOYMENT_READS = (
    "ai-bom", "approved-workflows", "assurance-claims", "authority-chains", "bom-drift", "business-impact",
    "capabilities", "chain-birth", "chain-outcomes", "cloud-posture", "compliance", "connectors",
    "coverage-manifest-view", "data-boundary", "data-lifecycle", "decision-support", "declared-architecture",
    "detail", "dispatch-attempts", "dispatch-policy", "effective-access", "executive-summary", "latency",
    "latent-conditions", "list", "metadata-logging", "operational-assurance", "operational-risk",
    "personal-context", "posture", "repo-posture", "retest-requirements", "revalidation-plan",
    "ripple-effect", "route-map", "secrets-posture", "training-reuse", "vendor-assurance",
    "vendor-packet-candidates", "connector-config", "posture-config", "approval-in-force",
)
ROUTES.update({f"deployment-{name}": _READ for name in _DEPLOYMENT_READS})
ROUTES.update(
    {
        "deployment-assurance-pack": "api.packs",
        "deployment-assurance-packs": "api.packs",
        "deployment-assurance-receipt": "api.receipts",
        "deployment-receipt": "api.receipts",
        "deployment-signed-assurance-receipt": "api.receipts",
        "deployment-authentications": _DOCS + "records a signed sign-in; answers what it recorded, as "
        "authority-chains reads it",
        "deployment-delegations": _DOCS + "records a signed delegation; answers what it recorded, as "
        "authority-chains reads it",
        "deployment-check": _DOCS + "the deployment's check, read as deployment-detail",
        "deployment-check-invalidations": _DOCS + "re-derives the claims a change invalidates; read as "
        "assurance-claims",
        "deployment-connector-push": _READ,
        "deployment-observed-chain-outcomes": _DOCS + "records a signed outcome; read as chain-outcomes",
        "deployment-observed-effects": _READ,
        "deployment-recompute": _DOCS + "recomputes the decision; read as deployment-detail",
        "deployment-recompute-claims": _DOCS + "re-derives the claims; read as assurance-claims",
        "deployment-record-bom-drift": _DOCS + "records the BOM's drift; read as bom-drift",
        "deployment-economics-parameter-set": _READ,
        "deployment-economics-parameter-set-versions": _READ,
        # The scenario builder's two routes (#149): a build answers the scenario it
        # built, and the events route reads one scenario's causal loss events.
        "deployment-economics-scenario-build": _READ,
        "deployment-economics-scenario-events": _READ,
        # Raising a source's trust tier (spec, section 6.1): the list and a raise
        # answer the raise records; an approval and a withdrawal answer the one they
        # moved, as the list reads it.
        "economics-source-trust-raises": _READ,
        "economics-trust-raise-approve": _DOCS + "approves a pending raise; answers the raise, as "
        "economics-source-trust-raises reads it",
        "economics-trust-raise-withdraw": _DOCS + "withdraws a pending raise; answers the raise, as "
        "economics-source-trust-raises reads it",
        # The scenario endpoints (MVP step 6): a scenario version with its parameters'
        # provenance, a simulation's summary, and its report JSON.
        "deployment-economics-scenario": _READ,
        "deployment-economics-scenario-simulate": _READ,
        "deployment-economics-scenario-results": _READ,
        # The remediation option and its ROI (MVP step 13): an option recorded, its
        # current and residual runs' summaries, and its ROI document.
        "deployment-economics-scenario-mitigations": _READ,
        "deployment-economics-mitigation-simulate": _READ,
        "deployment-economics-scenario-roi": _READ,
        # The data-health route (MVP step 10): each feed source's state for a deployment.
        "deployment-economics-data-health": _READ,
        # The normalization route (MVP step 12): one amount normalized for a deployment.
        "deployment-economics-normalization": _READ,
        # The read routes the dashboard needs (spec, section 30): a deployment's
        # scenario versions, and a Financial Exposure Receipt's signed bytes.
        "deployment-economics-scenarios": _READ,
        "deployment-economics-receipt": "api.receipts",
        # Step 11's context routes: a prefill suggestion (it takes its query, and a
        # read with none is refused 400 with its code) and a scenario's precedents.
        "deployment-economics-suggestions": _READ,
        "deployment-economics-scenario-precedents": _READ,
        # The portfolio (E5): the totals and their report JSON, and the authored
        # correlation group versions a portfolio names.
        "deployment-economics-portfolio": _READ,
        "deployment-economics-portfolio-simulate": _READ,
        "deployment-economics-portfolio-groups": _READ,
        # Continuous financial assurance (E6, spec section 34): a run's freshness, the
        # deployment's assurance and its check, and a stale scenario's refresh.
        "deployment-economics-scenario-freshness": _READ,
        "deployment-economics-assurance": _READ,
        "deployment-economics-scenario-refresh": _READ,
    }
)
_ADMIN = "not an export: the admin site, staff only; every page renders rows searched whole as db"
READ_SINKS = {route: sink for route, sink in ROUTES.items() if sink in SINKS}


def _is_admin(name: str) -> bool:
    return name.startswith("admin:")


def _readable_urls(world):
    """(route, url) for every route that reads, over every object the paths made."""
    from django.urls import NoReverseMatch, reverse

    from assurance import models as am
    from detection.models import CVEClassifyResult, ThreatDetection
    from failsafe.models import FailsafeCommand
    from pentest.models import Engagement, PentestScan
    from tests.test_no_control_holds_back_a_stop import walk

    served = walk()
    kwargs_by_route: dict[str, list[dict]] = {}
    deployments = list(am.Deployment.objects.all()[:3])
    findings = list(am.Finding.objects.all()[:2])
    for name, entry in served.items():
        if _is_admin(name) or "GET" not in entry["methods"] or name not in READ_SINKS:
            continue
        options = [{}]
        if name.startswith("deployment-") and name not in ("deployment-list", "deployment-latency"):
            options = [{"uuid": str(d.uuid)} for d in deployments]
            if name == "deployment-connector-config":
                options = [{**o, "connector": "webhook"} for o in options]
            if name == "deployment-posture-config":
                options = [{**o, "domain": "cloud"} for o in options]
            if name == "deployment-approval-in-force":
                from tests.test_spine_authority_chain import WF

                options = [{**o, "workflow": WF} for o in options]
            if name in (
                "deployment-economics-scenario",
                "deployment-economics-scenario-events",
                "deployment-economics-scenario-results",
                "deployment-economics-scenario-roi",
                "deployment-economics-scenario-precedents",
                "deployment-economics-scenario-freshness",
            ):
                from assurance.economics.models import FinancialScenario

                options = [
                    {**o, "scenario": str(sc.uuid)}
                    for o in options
                    for sc in FinancialScenario.objects.filter(deployment__uuid=o["uuid"])[:2]
                ]
            if name == "deployment-economics-receipt":
                from assurance.economics.models import FinancialExposureReceipt

                options = [
                    {**o, "receipt": str(uuid.UUID(row.receipt_id))}
                    for o in options
                    for row in FinancialExposureReceipt.objects.filter(deployment__uuid=o["uuid"])[:2]
                ]
            if name.startswith("deployment-economics-parameter-set"):
                from assurance.economics.models import CustomerParameterSet

                keys = sorted(set(CustomerParameterSet.objects.values_list("set_key", flat=True))) or ["canary-set"]
                options = [{**o, "set_key": key} for o in options for key in keys[:2]]
            if name == "deployment-assurance-pack":
                from assurance.packs import _PACKS_BY_KEY

                options = [{**o, "pack": pack} for o in options for pack in sorted(_PACKS_BY_KEY)[:2]]
        elif name == "economics-source-trust-raises":
            from assurance.economics.models import FinancialSource

            options = [{"uuid": str(s.uuid)} for s in FinancialSource.objects.all()[:3]]
        elif name.startswith("finding-"):
            options = [{"uuid": str(f.uuid)} for f in findings] if name != "finding-list" else [{}]
        elif name.startswith("claim-") and name != "claim-list":
            options = [{"uuid": str(c.uuid)} for c in am.AssuranceClaim.objects.all()[:2]]
        elif name in ("asset-detail", "provider-detail", "provider-assertion-detail", "unknown-detail",
                      "retest-requirement-detail"):
            model = {"asset-detail": am.Asset, "provider-detail": am.Provider,
                     "provider-assertion-detail": am.ProviderAssertion, "unknown-detail": am.Unknown,
                     "retest-requirement-detail": am.RetestRequirement}[name]
            options = [{"uuid": str(o.uuid)} for o in model.objects.all()[:2]]
        elif name.startswith("pentest:") and name in ("pentest:detail_pentest_scan", "pentest:pentest_scan_status",
                                                       "pentest:download_scan_pdf"):
            options = [{"scan_id": str(s.uuid)} for s in PentestScan.objects.all()]
        elif name == "pentest:engagement_detail":
            options = [{"engagement_id": e.pk} for e in Engagement.objects.all()]
        elif name in ("detection:cve-detail", "detection:cve-pdf"):
            options = [{"pk": o.pk} for o in CVEClassifyResult.objects.all()]
        elif name == "detection:defender-detail":
            options = [{"pk": o.pk} for o in ThreatDetection.objects.all()]
        elif name == "failsafe:command-detail":
            options = [{"cmd_uuid": str(c.uuid)} for c in FailsafeCommand.objects.all()[:3]]
        elif name == "accounts:user-detail":
            options = [{"pk": world.admin.pk}]
        kwargs_by_route[name] = options
    for name, options in sorted(kwargs_by_route.items()):
        for kwargs in options:
            namespace_free = name
            try:
                url = reverse(namespace_free, kwargs=kwargs or None)
            except NoReverseMatch:
                continue
            yield name, url


# ---------------------------------------------------------------------------
# The run, once for the module
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Hit:
    origin: str
    sink: str
    path: str
    form: str
    digest: bool
    context: str


@dataclass
class Observation:
    paths: list[PathRun]
    hits: list[Hit]
    called: set[tuple[str, str]]
    timed: list[Timed]


NEEDLES = Needles(CANARY, _EXTRA)


@pytest.fixture(scope="module")
def observed(django_db_setup, django_db_blocker, tmp_path_factory) -> Observation:
    from django.db import transaction

    world = World(tmp_path_factory.mktemp("canary"))
    with django_db_blocker.unblock():
        with transaction.atomic():
            try:
                world.start()
                for name in PATHS:
                    world.run(name, getattr(world, name))
            finally:
                world.close()
                transaction.set_rollback(True)
    hits = []
    for run in world.paths:
        for sink, documents in run.documents.items():
            for _label, document in documents:
                for origin, form, digest, context in search(document, NEEDLES):
                    hits.append(Hit(origin, sink, run.name, form, digest, context))
    return Observation(world.paths, hits, world.called, world.timed)


# ---------------------------------------------------------------------------
# The inventory is complete
# ---------------------------------------------------------------------------


def test_every_cell_of_the_matrix_is_named():
    assert set(MATRIX) == {(o, s) for o in ORIGINS for s in SINKS}
    for declaration in DECLARATIONS:
        assert declaration.origins <= set(ORIGINS), declaration.origins - set(ORIGINS)
        assert declaration.sinks <= set(SINKS), declaration.sinks - set(SINKS)
    assert len(set(CANARY.values())) == len(CANARY), "two origins share a canary"
    assert CREDENTIALS <= set(ORIGINS)
    for origin in CREDENTIALS:
        assert all(MATRIX[(origin, sink)] == DECLARED for sink in SINKS), (
            f"{origin} is a credential: every sink must be declared to never carry it"
        )


def _words(text: str) -> str:
    return " ".join(text.replace("#", " ").split())


def test_every_declaration_is_where_it_says():
    missing = [(d.where, d.says) for d in DECLARATIONS if _words(d.says) not in _words((ROOT / d.where).read_text())]
    assert missing == [], missing


def test_every_sink_was_searched(observed):
    produced = {sink for run in observed.paths for sink, documents in run.documents.items() if documents}
    assert produced == set(SINKS), {
        "never produced": sorted(set(SINKS) - produced),
        "not in the inventory": sorted(produced - set(SINKS)),
    }


def test_every_route_is_a_sink_or_says_why_not(observed):
    from tests.test_no_control_holds_back_a_stop import walk

    served = {name for name in walk() if not _is_admin(name)}
    assert served == set(ROUTES), {
        "served, not classified": sorted(served - set(ROUTES)),
        "classified, not served": sorted(set(ROUTES) - served),
    }
    for route, what in ROUTES.items():
        assert what in SINKS or what.startswith("not an export: "), route
    exported = {route for route, what in ROUTES.items() if what in SINKS}
    called = {route for route, _method in observed.called}
    never = sorted(exported - called)
    assert never == [], f"a route that is a sink was never called: {never}"


#: Every model the admin site renders rows of: each is searched as db, whole, on
#: every path (``test_every_model_is_searched``). A model registered with the admin
#: and not named here fails ``test_every_admin_route_renders_rows_the_db_search_covers``.
ADMIN_MODELS = frozenset({
    "accounts.CustomUser", "assurance.Asset", "assurance.ConnectorBinding", "assurance.DataBoundary",
    "assurance.DecisionDispatchDue", "assurance.Deployment", "assurance.DispatchAttempt",
    "assurance.DispatchPolicy", "assurance.Finding", "assurance.PostureBinding", "assurance.Provider",
    "assurance.ProviderAssertion", "assurance.RemediationEvent", "assurance.RepairContract",
    "assurance.Unknown", "audit.AuditLog", "auth.Group", "pentest.Engagement", "pentest.PentestScan",
    "token_blacklist.BlacklistedToken", "token_blacklist.OutstandingToken",
})


def test_every_admin_route_renders_rows_the_db_search_covers():
    from django.contrib import admin

    from tests.test_no_control_holds_back_a_stop import walk

    served = {name for name in walk() if _is_admin(name)}
    assert served, "no admin route found"
    registered = {m._meta.label for m in admin.site._registry}
    assert registered == ADMIN_MODELS, {
        "registered, not named here": sorted(registered - ADMIN_MODELS),
        "named here, not registered": sorted(ADMIN_MODELS - registered),
    }


#: Every model, and what its rows hold. Every row of every one is searched as db.
MODELS_SEARCHED = "every model's rows are serialised and searched whole (World.collect)"


def test_every_model_is_searched(observed):
    from django.apps import apps

    labels = {m._meta.label for m in apps.get_models()}
    searched = set()
    for run in observed.paths:
        for _label, rows in run.documents.get("db", []):
            searched |= set(rows)
    assert searched == labels, {"not searched": sorted(labels - searched)}


def _python_files(*roots: Path):
    for root in roots:
        for path in sorted(root.rglob("*.py")):
            parts = path.relative_to(ROOT).parts
            if "migrations" in parts or "tests" in parts or "settings" in path.name:
                continue
            yield path


_APPS = ("accounts", "ai_engine", "assurance", "audit", "detection", "failsafe", "idempotency", "pentest",
         "safety", "config", "tools")

#: Every management command, and the sink its output is.
COMMANDS: dict[str, str] = {
    "approve_deployment": "commands: an operator's approval of the engine's deployment; prints the "
    "engine's measured tuple, never its key",
    "deliver_owed_stops": "commands",
    "reconcile_dispatch_attempt": "commands: settles one dispatch attempt by hand; prints its id and state",
    "recompute_chain_decisions": "commands: re-derives decisions; prints counts",
    "retry_blocking_dispatches": "commands: retries owed dispatches; prints counts and ids",
    "retry_closure_forwards": "commands",
    "raise_source_trust": "commands",
    "fetch_financial_source": "commands",
    "check_financial_assurance": "commands",
}


def test_every_management_command_is_classified(observed):
    found = {
        path.stem
        for app in _APPS
        for path in sorted((ROOT / app).glob("management/commands/*.py"))
        if path.stem != "__init__"
    }
    assert found == set(COMMANDS), {
        "a command, not classified": sorted(found - set(COMMANDS)),
        "classified, not a command": sorted(set(COMMANDS) - found),
    }
    driven = {label for run in observed.paths for label, _out in run.documents.get("commands", [])}
    for name, what in COMMANDS.items():
        assert what.startswith("commands"), name
        if what == "commands":
            assert name in driven, f"{name} is classified as searched and was never run"


_WRITES = re.compile(
    r"""open\([^)\n]*["'][rwax]*[wax][rwax+b]*["']|os\.open\(|\.write_(?:text|bytes)\(|upload_to=|default_storage"""
)

#: Every module that writes a file, and the sink it is.
FILE_WRITERS: dict[str, str] = {
    "pentest/models.py": "files: the scan's PDF report (upload_to pentest_reports/, under MEDIA_ROOT), "
    "written by pentest.utils.save_pdf_to_scan through the scan's FileField",
    # Not under MEDIA_ROOT, so not read by the files search: each slot file is created
    # empty and never written to, and is named by a slot's index or a digest of a
    # deployment's uuid (tests/test_economics_run_cap.py, test_a_slot_file_carries_nothing).
    "assurance/economics/capacity.py": "files: the economics run slots, empty lock files in "
    "ATHENA_ECONOMICS_SLOT_DIR (run-<i>.lock, tenant-<sha256 of a deployment uuid>-<i>.lock), never written to; "
    "they carry no byte of any request",
}


def test_every_module_that_writes_a_file_is_classified():
    writers = {
        str(path.relative_to(ROOT))
        for app in _APPS
        for path in _python_files(ROOT / app)
        if _WRITES.search(path.read_text())
    }
    assert writers == set(FILE_WRITERS), {
        "writes, not classified": sorted(writers - set(FILE_WRITERS)),
        "classified, writes nothing": sorted(set(FILE_WRITERS) - writers),
    }
    for module, what in FILE_WRITERS.items():
        assert what.split(":", 1)[0] in SINKS, module


_LOG_SETUP = re.compile(r"logging\.basicConfig\(|logging\.config\.|\.addHandler\(|logging\.\w*Handler\(")

#: Every module that configures where log records go. The settings module's LOGGING
#: is not read here (this harness opens no settings file): every record of every
#: logger is captured in Logger.handle, before any handler, whatever LOGGING says.
LOG_SINKS: dict[str, str] = {}


def test_every_place_the_log_is_sent_is_classified():
    configured = {
        str(path.relative_to(ROOT))
        for app in _APPS
        for path in _python_files(ROOT / app)
        if _LOG_SETUP.search(path.read_text())
    }
    assert configured == set(LOG_SINKS), {
        "configures logging, not classified": sorted(configured - set(LOG_SINKS)),
        "classified, configures nothing": sorted(set(LOG_SINKS) - configured),
    }


#: Every span attribute this service sets.
SPAN_FIELDS: dict[str, str] = {
    "mythos.engine": "the service's name",
    "gen_ai.operation.name": "the span's name in the shared vocabulary",
    "gen_ai.tool.name": "which step ran",
    "mythos.subject": "the subject a span is about: a deployment's primary key, never its name",
    "mythos.raw_findings": "a count: how many findings an engine answer carried",
    "mythos.verdict": "a verdict",
    "error.type": "the class of an exception that left the span, never its message",
}


def test_every_field_a_span_carries_is_classified(observed):
    keys, descriptions, events = set(), set(), []
    for run in observed.paths:
        for _label, spans in run.documents.get("spans", []):
            for span in spans:
                keys |= set(span["attributes"])
                events.extend(span["events"])
                if span["status"]:
                    descriptions.add(span["status"][1])
    assert sorted(keys - set(SPAN_FIELDS)) == [], keys
    assert events == [], events
    assert all(d is None or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.]*", d) for d in descriptions), descriptions


# ---------------------------------------------------------------------------
# Every path ran, and every canary went in
# ---------------------------------------------------------------------------


def test_every_path_ran(observed):
    assert [run.name for run in observed.paths] == list(PATHS)
    broke = {run.name: run.signals["broke"] for run in observed.paths if "broke" in run.signals}
    assert broke == {}, "\n\n".join(f"{name}:\n{why}" for name, why in broke.items())
    s = {run.name: run.signals for run in observed.paths}
    assert s["boot"]["health"] == 200
    assert s["boot"]["sign_in"] == 200 and s["boot"]["wrong_password"] == 401
    assert s["scan_success"]["launch"] == 200, s["scan_success"]
    assert s["scan_success"]["status"] == "completed", s["scan_success"]
    assert s["scan_success"]["pdf"] == 200
    assert s["scan_failure"]["engine_got_key"] is True
    assert s["scan_failure"]["echo_answered"] is True, s["scan_failure"]
    assert s["scan_failure"]["failed_scan_has_a_login"] is True, s["scan_failure"]
    assert s["scan_timeout_and_retry"]["status"] == "unknown", s["scan_timeout_and_retry"]
    assert s["scan_stop"]["stop"][1] == "delivered", s["scan_stop"]
    assert s["scan_stop"]["owed"][1] == "owed" and s["scan_stop"]["owed"][2], s["scan_stop"]
    assert s["scan_stop"]["delivered"] == "delivered", s["scan_stop"]
    assert s["scan_stop"]["moved"] == {"stop": (200, "delivered"), "owed": "owed", "delivered": "delivered"}, s["scan_stop"]
    assert s["scan_stop"]["moved_followed"] is True, s["scan_stop"]
    assert s["connectors"]["bind_webhook"] == 201 and s["connectors"]["bind_posture"] == 201, s["connectors"]
    assert s["connectors"]["pushes"]["ok"] == (200, True), s["connectors"]
    assert s["connectors"]["pushes"]["echo"][1] is False, s["connectors"]
    assert s["connectors"]["pushes"]["stall"][1] is False, s["connectors"]
    assert s["connectors"]["webhook_got_token"] is True
    assert s["closure_forward"]["recorded"] == {"ok": 201, "echo": 201}, s["closure_forward"]
    assert s["closure_forward"]["minotaur_got_key"] is True
    assert s["gate_and_effects"]["gate_read"] == 200, s["gate_and_effects"]
    assert s["gate_and_effects"]["effect"] == "recorded", s["gate_and_effects"]
    assert s["failsafe"]["poll"] == 200 and s["failsafe"]["draft"] in (200, 201), s["failsafe"]
    assert s["proxy"]["engine"] == {"stop": (200, "delivered"), "owed": "owed", "delivered": "delivered"}, s["proxy"]
    assert s["proxy"]["engine_through_proxy"] > 0 and s["proxy"]["proxy_got_login"] is True, s["proxy"]
    assert s["proxy"]["defender_through_proxy"] > 0, s["proxy"]
    assert s["proxy"]["others_through_proxy"] == [], "a call off the engine's lane went through the environment's proxy"
    assert s["route_raises"]["raised"] == 500 and s["route_raises"]["missing"] == 404, s["route_raises"]
    assert s["records"]["claims"] > 0 and s["records"]["provider"] == 201, s["records"]
    assert (
        s["records"]["scenario_build_refused"],
        s["records"]["scenario_build"],
        s["records"]["scenario_events"],
        s["records"]["scenario_simulate"],
        s["records"]["scenario_simulate_at_capacity"],
        s["records"]["scenario_results"],
        s["records"]["mitigation"],
        s["records"]["mitigation_simulate"],
        s["records"]["scenario_roi"],
        s["records"]["portfolio_simulate"],
        s["records"]["portfolio"],
    ) == (400, 201, 200, 201, 503, 200, 201, 201, 200, 201, 200), s["records"]
    # The read routes the dashboard needs: the list read, a receipt issued and its bytes read.
    assert (s["records"]["scenario_list"], s["records"]["receipt_issued"], s["records"]["receipt_bytes"]) == (
        200, (True, None), 200,
    ), s["records"]
    # Continuous financial assurance: the check, the reads and a refused refresh.
    assert (
        s["records"]["assurance_check"], s["records"]["assurance"], s["records"]["scenario_freshness"],
        s["records"]["scenario_refresh"],
    ) == (200, 200, 200, 400), s["records"]
    assert s["records"]["trust_raise"] == {
        "one_step": 201, "asked": 201, "approved": 200, "withdrawable": 201, "withdrawn": 200,
        "command_approve_refused": True,
        "command": [("withdrawn", "api", "api"), ("withdrawn", "command", "command")],
    }, s["records"]
    assert s["feeds"]["fetches"] == [
        ("fred-cpiaucsl", "recorded", ""), ("bls-ppi-final-demand", "refused", "fetch_http_error"),
    ], s["feeds"]
    assert s["feeds"]["bls_refused"] is True and s["feeds"]["no_key_refused"] is True, s["feeds"]
    assert s["feeds"]["provider_got_key"] is True and s["feeds"]["bls_posted"] is True, s["feeds"]
    assert s["feeds"]["data_health"] == 200, s["feeds"]
    assert s["feeds"]["normalization"] == 200, s["feeds"]
    # urllib3's request-line record was searched: the channel is live, not vacuous.
    assert s["feeds"]["client_request_line"] is True, s["feeds"]
    assert s["read_everything"]["read"] > 50, s["read_everything"]


def test_every_canary_went_in(observed):
    """Absence downstream means something only if the canary reached the service:
    each origin's canary is shown to have arrived where it was planted."""
    reached = {hit.origin for hit in observed.hits if not hit.digest}
    # Content a tenant sends is recorded: the search must find it somewhere, or it
    # cannot show where it is not.
    for origin in ("request.body", "tenant.evidence", "exception.message", "request.target_userinfo"):
        assert origin in reached, f"{origin}'s canary is found nowhere: the search cannot be trusted for it"
    # The PDFs are searched inflated: the scan's report names its target's host.
    exported = [
        text
        for run in observed.paths
        for _label, document in run.documents.get("exports", [])
        if isinstance(document, list)
        for text in document
    ]
    assert any("offline.invalid" in text for text in exported), "no PDF export was read inflated"


def test_a_stop_is_delivered_with_every_canary_planted_and_inside_its_bound(observed):
    """The SAFETY RULE: with every canary planted, a scan's Stop is delivered (and,
    with the engine down, owed and then delivered by deliver_owed_stops), and each
    inside the bound it already had."""
    assert {t.what for t in observed.timed} >= {
        "a scan's Stop, delivered", "a scan's Stop, owed", "deliver_owed_stops, engine down",
        "deliver_owed_stops, delivered", "a pause drafted on the service token",
        "a scan's Stop, through a same-host redirect", "deliver_owed_stops, through a same-host redirect",
        "a scan's Stop, through the environment's proxy", "deliver_owed_stops, through the environment's proxy",
    }
    late = [(t.what, round(t.seconds, 3), t.bound) for t in observed.timed if t.seconds > t.bound]
    assert late == [], late


# ---------------------------------------------------------------------------
# The assertions
# ---------------------------------------------------------------------------

_DECLARED_CELLS = sorted(cell for cell, status in MATRIX.items() if status == DECLARED)


@pytest.mark.parametrize(("origin", "sink"), _DECLARED_CELLS)
def test_a_declared_sink_never_carries_the_canary(observed, origin, sink):
    leaks = [hit for hit in observed.hits if hit.origin == origin and hit.sink == sink]
    assert leaks == [], "\n".join(f"{h.path}: {h.form}: ...{h.context}..." for h in leaks)


def test_the_observed_matrix(observed, capsys):
    """What every cell showed, printed for the reader. A ``not declared`` cell is
    reported and claimed absent nowhere."""
    paths: dict[tuple[str, str], set[str]] = collections.defaultdict(set)
    kinds: dict[tuple[str, str], set[str]] = collections.defaultdict(set)
    for hit in observed.hits:
        paths[(hit.origin, hit.sink)].add(hit.path)
        kinds[(hit.origin, hit.sink)].add("digest" if hit.digest else "canary")
    lines = []
    for (origin, sink), status in MATRIX.items():
        cell = (origin, sink)
        if cell in paths:
            on = [name for name in PATHS if name in paths[cell]]
            seen = f"PRESENT ({'+'.join(sorted(kinds[cell]))}) on {len(on)}/{len(PATHS)} paths: {', '.join(on)}"
        elif status == NOT_DECLARED:
            continue
        else:
            seen = f"absent on all {len(PATHS)} paths"
        lines.append(f"{status:12} {origin:24} {sink:16} {seen}")
    timings = [f"{t.what}: {t.seconds:.3f} s (bound {t.bound:g} s)" for t in observed.timed]
    with capsys.disabled():
        print("\n" + "\n".join(lines + timings))
    assert set(paths) <= set(MATRIX)
