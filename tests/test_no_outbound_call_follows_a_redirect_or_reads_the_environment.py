"""Every request this service sends with ``requests`` itself follows no redirect,
reads no ``.netrc`` or proxy from the environment, and quotes no credential when
it fails (``safety.outbound``).

The engines' requests go through mythos-core's ``safe_http``, which since
Mythos-Core#50 trusts nothing in the environment and strips credentials on a hop
to another origin. This service's do not: it calls ``requests`` itself, at the
call sites :data:`SITES` names, and on master each one followed a redirect with
its own headers (``requests`` drops ``Authorization`` on a hop to another host
and keeps ``X-API-Key``, ``X-Minotaur-Key`` and a webhook's token header), put
the ``.netrc`` login kept for the target's host on the request (in place of the
``Authorization`` a caller set), and sent the request through any proxy the
environment named, credentials and all.

Each call site is driven for real, over loopback, against servers this file
runs: the target, an "elsewhere" a redirect points at (another origin: another
port), and a proxy. Nothing leaves the machine. Every site is held to three
things:

* a redirect to another origin is not followed, so none of the request's headers
  reaches it -- nothing reaches it at all;
* a ``.netrc`` entry for the target's host is not sent;
* a credentialed proxy in the environment is not used, and its credentials appear
  in no error: the exception's text (and its causes'), a log line, or what the
  call site returns or records.

``test_every_call_site_is_driven_here`` holds :data:`SITES` to the code: a new
``requests`` (or ``httpx``/``urllib``) call fails until it goes through
``safety.outbound`` and is driven here.
"""

from __future__ import annotations

import base64
import logging
import secrets
import socket
import threading
import time
import traceback
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parent.parent


class Recorder:
    """A loopback server that records every request it is sent. ``answer`` says
    how it answers: ``"ok"`` (200, an empty JSON object) or ``("redirect", url)``
    (307 to ``url``)."""

    def __init__(self, answer="ok"):
        self.answer = answer
        self.seen: list[tuple[str, str, dict]] = []
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _any(self):
                length = int(self.headers.get("Content-Length") or 0)
                if length:
                    self.rfile.read(length)
                recorder.seen.append((self.command, self.path, dict(self.headers)))
                if isinstance(recorder.answer, tuple) and recorder.answer[0] == "redirect":
                    self.send_response(307)
                    self.send_header("Location", recorder.answer[1])
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                body = b'{"allow": true, "action": "allow"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_PUT = do_CONNECT = _any

            def log_message(self, *_args):
                return None

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


def _closed_base() -> str:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return f"http://127.0.0.1:{port}"


# ---------------------------------------------------------------------------
# The call sites, each driven the way the service drives it
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Site:
    #: Where the call is, as ``test_every_call_site_is_driven_here`` finds it.
    where: str
    #: Why it follows no redirect.
    redirects: str
    #: Drive it at ``base`` carrying ``credential``; return what the call site
    #: answers or records, or raise what it raises.
    drive: object


def _engine_get(base, credential):
    from ai_engine.services.cyberengine_client import CyberEngineClient

    return CyberEngineClient(base, credential)._get("/api/assurance/keyring")


def _engine_post(base, credential):
    from ai_engine.services.cyberengine_client import CyberEngineClient

    return CyberEngineClient(base, credential)._post("/api/classify-cve", {"text": "x"})


def _engine_file(base, credential):
    from ai_engine.services.cyberengine_client import CyberEngineClient

    return CyberEngineClient(base, credential).defend_log_file(b"log line\n", "app.log")


def _defender(base, credential):
    from django.http import HttpResponse
    from django.test import override_settings

    from audit.middleware import DefenderMiddleware

    with override_settings(CYBERENGINE_URL=base, CYBERENGINE_OPERATOR_KEY=credential, DEFENDER_TIMEOUT_SECONDS=5):
        gateway = DefenderMiddleware(lambda request: HttpResponse("ok"))
        return gateway._call_engine({"path": "/api/x", "method": "GET"}, time.monotonic() + 5)


def _transport_post(base, credential):
    from assurance.connectors.base import RequestsTransport

    return RequestsTransport(timeout=(2, 2), deadline=5).post(
        f"{base}/remediation-outcomes", headers={"X-Minotaur-Key": credential, "Authorization": f"Bearer {credential}"}, json={}
    )


def _transport_get(base, credential):
    from assurance.connectors.base import RequestsTransport

    return RequestsTransport(timeout=(2, 2), deadline=5).get(
        f"{base}/rest/api/2/search", headers={"X-Webhook-Token": credential, "Authorization": f"Bearer {credential}"}, params={"q": "x"}
    )


def _posture(base, credential):
    from assurance.posture.base import RequestsFetcher

    return RequestsFetcher(base, {"Authorization": f"Bearer {credential}"}, timeout=(2, 2)).fetch("v1/config")


_MACHINE_API = (
    "a machine API at a base URL an operator configured, which answers no request "
    "with a redirect: one that arrives is an intermediary's"
)

SITES: dict[str, Site] = {
    "engine.get": Site(
        "ai_engine/services/cyberengine_client.py::CyberEngineClient._send_get",
        f"the engine: {_MACHINE_API}; a 3xx is the refusal it is (EngineError, refused)",
        _engine_get,
    ),
    "engine.post": Site(
        "ai_engine/services/cyberengine_client.py::CyberEngineClient._send_post",
        f"the engine: {_MACHINE_API}; a 3xx is a refusal, and on a scan's launch an outcome "
        "not known (LaunchOutcomeUnknown), never a failure",
        _engine_post,
    ),
    "engine.file": Site(
        "ai_engine/services/cyberengine_client.py::CyberEngineClient.defend_log_file",
        f"the engine's defender: {_MACHINE_API}",
        _engine_file,
    ),
    "defender": Site(
        "audit/middleware.py::DefenderMiddleware._call_engine",
        f"the engine's /defend: {_MACHINE_API}; a 3xx is a failed call, and the gateway "
        "fails open as it does on every failed call",
        _defender,
    ),
    "transport.post": Site(
        "assurance/connectors/base.py::RequestsTransport.post",
        "a push to a customer's system or Minotaur: a write to the URL the binding names, "
        "which a redirect would carry, token header and all, to wherever Location points",
        _transport_post,
    ),
    "transport.get": Site(
        "assurance/connectors/base.py::RequestsTransport.get",
        "a connector's look-up of an issue it may have created: a read of the system the "
        "binding names; a 3xx is a look-up that found nothing it can trust",
        _transport_get,
    ),
    "posture": Site(
        "assurance/posture/base.py::RequestsFetcher.fetch",
        "a posture source's read: a 3xx is a check that reads unknown",
        _posture,
    ),
}


def _call(site: Site, base: str, credential: str) -> str:
    """Drive ``site``; everything it says back, as text: its answer, or the exception
    it raised with every cause and the formatted traceback."""
    try:
        result = site.drive(base, credential)
    except Exception as exc:  # noqa: BLE001 - what a failure says is what is checked
        return "".join(traceback.format_exception(exc)) + repr(exc.args)
    if isinstance(result, requests.Response):
        return f"{result.status_code} {result.headers!r} {result.text}"
    return repr(result)


def _canary(label: str) -> str:
    return f"cnry{label}{secrets.token_hex(10)}"


@pytest.fixture
def no_environment_proxy(monkeypatch):
    """Loopback is reached directly unless a test names a proxy."""
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(name, "")
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "127.0.0.1,localhost")


@pytest.mark.parametrize("name", sorted(SITES))
def test_a_redirect_to_another_origin_carries_none_of_its_headers(name, no_environment_proxy):
    credential = _canary("hdr")
    elsewhere = Recorder()
    target = Recorder(answer=("redirect", f"{elsewhere.base}/collected"))
    try:
        said = _call(SITES[name], target.base, credential)
    finally:
        target.close()
        elsewhere.close()
    assert target.seen, f"{name} never reached its target: {said}"
    carried = [(path, headers) for _m, path, headers in elsewhere.seen]
    assert carried == [], f"{name} followed a redirect to another origin with {carried}"


@pytest.mark.parametrize("name", sorted(SITES))
def test_a_netrc_entry_for_the_target_is_not_sent(name, no_environment_proxy, tmp_path, monkeypatch):
    password = _canary("netrc")
    netrc = tmp_path / ".netrc"
    netrc.write_text(f"machine 127.0.0.1\nlogin operator\npassword {password}\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    monkeypatch.setenv("HOME", str(tmp_path))
    target = Recorder()
    try:
        said = _call(SITES[name], target.base, _canary("cred"))
    finally:
        target.close()
    assert target.seen, f"{name} never reached its target: {said}"
    for _method, _path, headers in target.seen:
        for value in headers.values():
            decoded = value
            if value.startswith("Basic "):
                decoded = base64.b64decode(value[6:]).decode("utf-8", "replace")
            assert password not in decoded, f"{name} sent the .netrc login for its target: {headers}"


@pytest.mark.parametrize("name", sorted(SITES))
def test_a_credentialed_proxy_in_the_environment_is_neither_used_nor_quoted(name, monkeypatch, caplog):
    password = _canary("proxypw")
    proxy = Recorder()
    url = proxy.base.replace("http://", f"http://egress:{password}@")
    for variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(variable, url)
    for variable in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(variable, "")
    try:
        with caplog.at_level(logging.DEBUG):
            said = _call(SITES[name], _closed_base(), _canary("cred"))
    finally:
        proxy.close()
    assert proxy.seen == [], f"{name} sent its request through the environment's proxy: {proxy.seen}"
    quoted = [where for where, text in (("its answer or error", said), ("the log", caplog.text)) if password in text]
    assert quoted == [], f"{name} quoted the proxy's credentials in {quoted}"


def test_withholding_that_fails_says_less_and_never_stops_a_stop(monkeypatch, no_environment_proxy):
    """The SAFETY RULE, for what this adds to the outbound path: a withholding that
    raises says less, never more, and never stops a stop. With both halves broken --
    an error's text and an answer's body -- a failed call says the classes of its
    exceptions and nothing else, and a scan's Stop still reaches the engine, at
    once."""
    from ai_engine.services.cyberengine_client import CyberEngineClient, EngineError
    from safety import outbound

    def broken(*_args, **_kwargs):
        raise RuntimeError("withholding broke")

    monkeypatch.setattr(outbound, "withhold", broken)
    monkeypatch.setattr(outbound, "withheld_body", broken)
    credential = _canary("stopkey")

    down = _closed_base()
    try:
        CyberEngineClient(down, credential)._post("/api/classify-cve?token=QTOKEN", {"text": "x"})
    except EngineError as exc:
        # What the exception and every one it was raised from or during say (a
        # traceback's source lines would quote this test's own call).
        said, seen, current = [], set(), exc
        pending = [exc]
        while pending:
            current = pending.pop()
            if current is None or id(current) in seen:
                continue
            seen.add(id(current))
            said.append(f"{type(current).__name__}: {current} {current.args!r}")
            pending.extend([current.__cause__, current.__context__])
            pending.extend(arg for arg in current.args if isinstance(arg, BaseException))
        said = "\n".join(said)
    else:
        raise AssertionError("an engine that is down answered")
    assert "QTOKEN" not in said and "classify-cve" not in said, said

    engine = Recorder()
    began = time.monotonic()
    try:
        with pytest.raises(EngineError):
            # The answer's body is dropped (it could not be withheld from), so the
            # answer is unreadable -- after the Stop was sent and answered.
            CyberEngineClient(engine.base, credential).abort_scan("run-1", "operator stop")
        elapsed = time.monotonic() - began
    finally:
        engine.close()
    assert [path for method, path, _h in engine.seen if method == "POST"] == ["/api/scans/run-1/abort"]
    assert elapsed < 2.0, elapsed


# ---------------------------------------------------------------------------
# Every call site is one of these
# ---------------------------------------------------------------------------

_VERBS = frozenset({"get", "post", "put", "patch", "delete", "head", "options", "request", "Session"})
_CLIENT_MODULES = ("requests", "httpx", "urllib.request", "http.client", "urllib3")
_NOT_FIRST_PARTY = {"tests", "node_modules", "migrations", "__pycache__", "frontend"}


def _first_party():
    for path in sorted(ROOT.rglob("*.py")):
        parts = path.relative_to(ROOT).parts
        if set(parts) & _NOT_FIRST_PARTY or any(p.startswith(".") for p in parts):
            continue
        if (ROOT / parts[0] / "pyvenv.cfg").exists() or "settings" in path.name:
            continue
        yield path


def _calls(path: Path):
    """(scope, kind, what) for every HTTP call in ``path``: kind is ``"outbound"`` for a
    call through safety.outbound and ``"direct"`` for any other client's."""
    import ast

    tree = ast.parse(path.read_text())

    def visit(node, scope):
        for child in ast.iter_child_nodes(node):
            inner = scope
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                inner = (*scope, child.name)
            here = ".".join(inner) or "<module>"
            if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name):
                owner, attr = child.value.id, child.attr
                if owner == "outbound" and attr in _VERBS:
                    yield here, "outbound", f"outbound.{attr}"
                elif (owner == "requests" and attr in _VERBS) or owner in {"httpx", "urllib3"}:
                    if not (owner == "urllib3" and attr == "exceptions"):
                        yield here, "direct", f"{owner}.{attr}"
            elif isinstance(child, ast.Call) and getattr(child.func, "id", None) == "urlopen":
                yield here, "direct", "urlopen"
            elif isinstance(child, ast.Import):
                for alias in child.names:
                    if alias.name in _CLIENT_MODULES[1:] or alias.name == "httpx":
                        yield here, "direct", f"import {alias.name}"
            elif isinstance(child, ast.ImportFrom) and child.module in ("urllib.request", "http.client", "httpx"):
                yield here, "direct", f"from {child.module} import"
            yield from visit(child, inner)

    yield from visit(tree, ())


def test_every_call_site_is_driven_here():
    """Each place this service's own code calls an HTTP client is a site here, and
    goes through ``safety.outbound``: a direct ``requests`` (``httpx``, ``urllib``)
    call is refused."""
    sites, direct = set(), []
    for path in _first_party():
        relative = path.relative_to(ROOT).as_posix()
        if relative == "safety/outbound.py":
            continue
        for scope, kind, what in _calls(path):
            if kind == "direct":
                direct.append(f"{relative}::{scope}: {what}")
            else:
                sites.add(f"{relative}::{scope}")
    assert direct == [], f"a direct HTTP call that does not go through safety.outbound: {direct}"
    driven = {site.where for site in SITES.values()}
    assert sites == driven, {
        "calls, not driven here": sorted(sites - driven),
        "driven here, no longer calls": sorted(driven - sites),
    }
    for name, site in SITES.items():
        assert site.redirects, f"{name} does not say why it follows no redirect"
