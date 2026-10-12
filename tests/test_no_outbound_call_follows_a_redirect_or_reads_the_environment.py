"""Every request this service sends with ``requests`` itself follows no redirect to
another host, reads no ``.netrc`` from the environment, and quotes no credential
when it fails (``safety.outbound``). Off the engine's lane it follows no redirect
at all and reads no proxy; on it (``ENGINE_SITES``), a redirect that stays on the
engine's host is followed and the environment's proxy is used, so a scan's Stop
an engine answers that way, or reached only through its proxy, is delivered.

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
runs: the target, an "elsewhere" a redirect points at (another host, or off the
engine's lane another port), and a proxy. Nothing leaves the machine. Every site
is held to these things:

* a redirect to another host (off the engine's lane, to any other origin, or to
  the same one) is not followed, so none of the request's headers reaches it --
  nothing reaches it at all;
* a ``.netrc`` entry for the target's host is not sent;
* off the engine's lane, a credentialed proxy in the environment is not used; on
  it, the proxy is used and ``NO_PROXY`` is honoured; either way the proxy's
  credentials appear in no error or answer: the exception's text (and its
  causes'), a log line, or what the call site returns or records;
* a secret in a request's path or query appears in no error when the connection
  fails.

``test_every_call_site_is_driven_here`` holds :data:`SITES` to the code: a new
``requests`` (or ``httpx``/``urllib``) call fails until it goes through
``safety.outbound`` and is driven here.
"""

from __future__ import annotations

import base64
import io
import json
import logging
import secrets
import socket
import ssl
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
    how it answers: ``"ok"`` (200, an empty JSON object), ``("redirect", url)``
    (307 to ``url``; ``("redirect", url, status)`` with that status), ``"echo"`` (502
    with a page quoting the request's headers back, as a debugging proxy's does),
    or a function ``(method, path, headers, body) -> (status, headers, body)``."""

    def __init__(self, answer="ok", tls=None):
        self.answer = answer
        self.seen: list[tuple[str, str, dict]] = []
        self.bodies: list[bytes] = []
        recorder = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def _send(self, status, headers, body):
                self.send_response(status)
                for name, value in headers.items():
                    self.send_header(name, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _any(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                recorder.seen.append((self.command, self.path, dict(self.headers)))
                recorder.bodies.append(body)
                if callable(recorder.answer):
                    self._send(*recorder.answer(self.command, self.path, dict(self.headers), body))
                    return
                if recorder.answer == "echo":
                    page = json.dumps({"detail": "bad gateway", "request": dict(self.headers)}).encode()
                    self._send(502, {"Content-Type": "application/json"}, page)
                    return
                if isinstance(recorder.answer, tuple) and recorder.answer[0] == "redirect":
                    status = recorder.answer[2] if len(recorder.answer) > 2 else 307
                    self._send(status, {"Location": recorder.answer[1]}, b"")
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
        self.server.handle_error = lambda *_args: None
        scheme = "http"
        if tls is not None:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(*tls)
            self.server.socket = context.wrap_socket(self.server.socket, server_side=True)
            scheme = "https"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.port = self.server.server_address[1]
        self.base = f"{scheme}://127.0.0.1:{self.port}"

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

_ENGINE_LANE = (
    "the engine's lane: a 307 or 308 (a 301, 302 or 303 answering a GET) that stays on "
    "the engine's host, at any port, http to https or as it was, is followed, at most "
    "three times -- an engine that moved its route or onto https still hears a scan's "
    "Stop; any other 3xx is answered as it is"
)

SITES: dict[str, Site] = {
    "engine.get": Site(
        "ai_engine/services/cyberengine_client.py::CyberEngineClient._send_get",
        f"{_ENGINE_LANE}, and is the refusal it is (EngineError, refused)",
        _engine_get,
    ),
    "engine.post": Site(
        "ai_engine/services/cyberengine_client.py::CyberEngineClient._send_post",
        f"{_ENGINE_LANE}: a refusal, and on a scan's launch an outcome not known "
        "(LaunchOutcomeUnknown), never a failure",
        _engine_post,
    ),
    "engine.file": Site(
        "ai_engine/services/cyberengine_client.py::CyberEngineClient.defend_log_file",
        f"the engine's defender, {_ENGINE_LANE}",
        _engine_file,
    ),
    "defender": Site(
        "audit/middleware.py::DefenderMiddleware._call_engine",
        f"the engine's /defend, {_ENGINE_LANE}; any other 3xx is a failed call, and the "
        "gateway fails open as it does on every failed call",
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


#: The engine's lane: these follow a same-host redirect and use the environment's proxy.
ENGINE_SITES = frozenset({"engine.get", "engine.post", "engine.file", "defender"})
#: Every other site follows no redirect and reads no proxy.
CLOSED_SITES = sorted(set(SITES) - ENGINE_SITES)


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


@pytest.mark.parametrize("name", CLOSED_SITES)
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


@pytest.mark.parametrize("status", [307, 308])
@pytest.mark.parametrize("name", sorted(SITES))
def test_a_redirect_to_another_host_carries_none_of_its_headers(name, status, no_environment_proxy):
    """``localhost`` is another host than ``127.0.0.1`` (it is compared as written, after
    IDNA), though it reaches the same machine: the engine's lane refuses it too."""
    credential = _canary("hdr")
    elsewhere = Recorder()
    target = Recorder(answer=("redirect", f"http://localhost:{elsewhere.port}/collected", status))
    try:
        said = _call(SITES[name], target.base, credential)
    finally:
        target.close()
        elsewhere.close()
    assert len(target.seen) == 1, f"{name}: {target.seen} {said}"
    assert elsewhere.seen == [], f"{name} followed a redirect to another host with {elsewhere.seen}"


@pytest.mark.parametrize("name", CLOSED_SITES)
def test_off_the_engine_s_lane_a_same_origin_redirect_is_not_followed_either(name, no_environment_proxy):
    """The connector transport and the posture fetcher keep refusing every redirect,
    to their own origin too."""
    target = Recorder(answer=lambda method, path, headers, body: (
        (308, {"Location": "/moved"}, b"") if path != "/moved" else (200, {}, b"{}")
    ))
    try:
        said = _call(SITES[name], target.base, _canary("cred"))
    finally:
        target.close()
    assert [path for _m, path, _h in target.seen if path == "/moved"] == [], f"{name}: {target.seen} {said}"


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


def test_the_defender_gateway_follows_its_engine_s_same_host_redirect(no_environment_proxy):
    """The gateway asks the engine a Stop goes to, so it reaches it the same way: an
    engine that moved /defend on its own origin still answers the gateway's question,
    rather than every request failing open."""
    target = Recorder(answer=lambda method, path, headers, body: (
        (308, {"Location": "/moved/defend"}, b"")
        if path == "/defend"
        else (200, {"Content-Type": "application/json"}, b'{"allow": false, "action": "block"}')
    ))
    try:
        said = _call(SITES["defender"], target.base, _canary("cred"))
    finally:
        target.close()
    assert [path for _m, path, _h in target.seen] == ["/defend", "/moved/defend"], said
    assert said == repr(({"allow": False, "action": "block"}, None)), said


@pytest.mark.parametrize("name", CLOSED_SITES)
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
# The engine's lane: a redirect that stays on the engine's host, and its proxy
# ---------------------------------------------------------------------------

#: What the engine answers a Stop it recorded (athena-engine #71).
_STOPPED = (200, {"Content-Type": "application/json"},
            b'{"run_id": "run-1", "state": "aborted", "recorded": true, "reason": "operator stop"}')
_ABORT = "/api/scans/run-1/abort"
#: How long a Stop may take here: the engine answers at once, and the timeout is 3 s.
_STOP_SECONDS = 2.0


def _stop(base, key="cnrystopkey0123456789"):
    """A scan's Stop, sent as the Stop route sends it; (what the client said, seconds)."""
    from ai_engine.services.cyberengine_client import CyberEngineClient, EngineError

    began = time.monotonic()
    try:
        said = CyberEngineClient(base, key).abort_scan("run-1", "operator stop")
    except EngineError as exc:
        said = exc
    return said, time.monotonic() - began


def _stops_at(path):
    """An engine whose Stop route is ``path``: the old route answers 308 to it."""
    def answer(method, at, headers, body):
        if at == path:
            return _STOPPED
        if at == _ABORT:
            return 308, {"Location": path}, b""
        return 200, {"Content-Type": "application/json"}, b"{}"
    return answer


@pytest.fixture
def tls_files(tmp_path):
    """A certificate for 127.0.0.1 and its key, the certificate its own root: the
    https end of an http-to-https move, trusted through REQUESTS_CA_BUNDLE as an
    operator's own roots are."""
    import datetime
    import ipaddress

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "127.0.0.1")])
    now = datetime.datetime.now(datetime.timezone.utc)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]), False)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(key.public_key()), False)
        .add_extension(
            x509.KeyUsage(digital_signature=True, content_commitment=False, key_encipherment=False,
                          data_encipherment=False, key_agreement=False, key_cert_sign=True, crl_sign=False,
                          encipher_only=False, decipher_only=False),
            True,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path, key_path = tmp_path / "engine.pem", tmp_path / "engine.key"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    ))
    return str(cert_path), str(key_path)


def test_a_stop_answered_with_a_same_origin_308_is_delivered(no_environment_proxy):
    """The review's first case: the engine's abort route answers 308 to itself with a
    trailing slash. The Stop is sent again there, body and key, and lands."""
    engine = Recorder(answer=_stops_at(_ABORT + "/"))
    try:
        said, seconds = _stop(engine.base)
    finally:
        engine.close()
    assert isinstance(said, dict) and said["stopped"] is True, said
    assert [(m, p) for m, p, _h in engine.seen] == [("POST", _ABORT), ("POST", _ABORT + "/")]
    assert all(h.get("X-API-Key") == "cnrystopkey0123456789" for _m, _p, h in engine.seen)
    assert engine.bodies[0] == engine.bodies[1] and b"operator stop" in engine.bodies[1]
    assert seconds < _STOP_SECONDS, seconds


def test_a_stop_answered_with_a_307_to_the_same_host_on_another_port_is_delivered(no_environment_proxy):
    """The review's second case, as it drove it: 307 to the same host at another port."""
    moved = Recorder(answer=_stops_at(_ABORT))
    engine = Recorder(answer=("redirect", f"{moved.base}{_ABORT}"))
    try:
        said, seconds = _stop(engine.base)
    finally:
        engine.close()
        moved.close()
    assert isinstance(said, dict) and said["stopped"] is True, said
    assert [p for _m, p, _h in moved.seen] == [_ABORT] and moved.bodies[0] == engine.bodies[0]
    assert seconds < _STOP_SECONDS, seconds


def test_a_stop_answered_with_a_307_from_http_to_https_is_delivered(no_environment_proxy, tls_files, monkeypatch):
    """An engine moved onto https: its http port answers 307 to https on the same host."""
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", tls_files[0])
    moved = Recorder(answer=_stops_at(_ABORT), tls=tls_files)
    engine = Recorder(answer=("redirect", f"{moved.base}{_ABORT}"))
    try:
        said, seconds = _stop(engine.base)
    finally:
        engine.close()
        moved.close()
    assert moved.base.startswith("https://")
    assert isinstance(said, dict) and said["stopped"] is True, said
    assert [p for _m, p, _h in moved.seen] == [_ABORT]
    assert seconds < _STOP_SECONDS, seconds


def test_an_https_engine_redirected_to_http_is_refused(no_environment_proxy, tls_files, monkeypatch):
    """https to http is a downgrade: answered as the 3xx it is, and nothing is sent in clear."""
    from ai_engine.services.cyberengine_client import EngineError

    monkeypatch.setenv("REQUESTS_CA_BUNDLE", tls_files[0])
    clear = Recorder(answer=_stops_at(_ABORT))
    engine = Recorder(answer=("redirect", f"{clear.base}{_ABORT}"), tls=tls_files)
    try:
        said, _seconds = _stop(engine.base)
    finally:
        engine.close()
        clear.close()
    assert isinstance(said, EngineError) and said.status == 307, said
    assert len(engine.seen) == 1 and clear.seen == []


@pytest.mark.parametrize("status", [301, 302, 303])
def test_a_301_302_or_303_answering_a_stop_is_refused(status, no_environment_proxy):
    """These turn a POST into a GET without its body: the Stop would not be the Stop."""
    from ai_engine.services.cyberengine_client import EngineError

    engine = Recorder(answer=lambda method, path, headers, body: (
        (status, {"Location": _ABORT + "/"}, b"") if path == _ABORT else _STOPPED
    ))
    try:
        said, _seconds = _stop(engine.base)
    finally:
        engine.close()
    assert isinstance(said, EngineError) and said.status == status, said
    assert [p for _m, p, _h in engine.seen] == [_ABORT]


def test_a_302_answering_a_status_read_on_the_engine_s_host_is_followed(no_environment_proxy):
    """A GET is sent again as the same GET: a 301, 302 or 303 changes nothing about it."""
    from ai_engine.services.cyberengine_client import CyberEngineClient

    engine = Recorder(answer=lambda method, path, headers, body: (
        (302, {"Location": "/v2/api/assurance/keyring"}, b"") if path == "/api/assurance/keyring"
        else (200, {"Content-Type": "application/json"}, b'{"keys": []}')
    ))
    try:
        answer = CyberEngineClient(engine.base, "cnrykey")._get("/api/assurance/keyring")
    finally:
        engine.close()
    assert answer == {"keys": []}
    assert [(m, p) for m, p, _h in engine.seen] == [("GET", "/api/assurance/keyring"), ("GET", "/v2/api/assurance/keyring")]


def test_a_redirect_loop_is_refused_after_three_hops(no_environment_proxy):
    from ai_engine.services.cyberengine_client import EngineError
    from safety import outbound

    engine = Recorder(answer=lambda method, path, headers, body: (
        308, {"Location": "/b" if path != "/b" else _ABORT}, b""
    ))
    try:
        said, seconds = _stop(engine.base)
    finally:
        engine.close()
    assert isinstance(said, EngineError) and said.status == 308, said
    assert len(engine.seen) == 1 + outbound.ENGINE_REDIRECT_HOPS == 4, engine.seen
    assert seconds < _STOP_SECONDS, seconds


def test_a_launch_through_a_same_host_307_is_not_an_unknown_outcome(no_environment_proxy):
    """The review: a launch answered 307 was LaunchOutcomeUnknown, and its run never
    named, so a Stop for it could not be sent. Followed, the run is named and collected;
    the launch was sent again whole: body, key and Idempotency-Key."""
    from ai_engine.services import cyberengine_client as cec
    from tests.test_a_lost_launch_answer_reads_unknown import ACCEPTED, COMPLETED

    def answer(method, path, headers, body):
        if (method, path) == ("POST", "/api/scan"):
            return 307, {"Location": "/api/v2/scan"}, b""
        if (method, path) == ("POST", "/api/v2/scan"):
            return 202, {"Content-Type": "application/json"}, json.dumps(dict(ACCEPTED, run_id="run-7")).encode()
        if path == "/api/scans/run-7":
            return 200, {"Content-Type": "application/json"}, json.dumps(dict(COMPLETED, run_id="run-7")).encode()
        return 404, {}, b"{}"

    named = []
    engine = Recorder(answer=answer)
    try:
        findings = cec.CyberEngineClient(engine.base, "cnrylaunchkey").run_scan(
            "https://target.invalid/", idempotency_key="launch-key-1", on_run=named.append
        )
    finally:
        engine.close()
    assert named == ["run-7"] and isinstance(findings, dict), (named, findings)
    launches = [(p, h) for m, p, h in engine.seen if m == "POST"]
    assert [p for p, _h in launches] == ["/api/scan", "/api/v2/scan"]
    assert all(h.get("Idempotency-Key") == "launch-key-1" and h.get("X-API-Key") == "cnrylaunchkey" for _p, h in launches)
    assert engine.bodies[0] == engine.bodies[1] and b"target.invalid" in engine.bodies[1]


def test_a_launch_redirected_to_another_host_is_still_unknown_and_carries_its_key_nowhere(no_environment_proxy):
    from ai_engine.services.cyberengine_client import CyberEngineClient, LaunchOutcomeUnknown

    elsewhere = Recorder()
    engine = Recorder(answer=("redirect", f"http://localhost:{elsewhere.port}/api/scan"))
    try:
        with pytest.raises(LaunchOutcomeUnknown):
            CyberEngineClient(engine.base, "cnrylaunchkey").run_scan("https://target.invalid/", idempotency_key="k1")
    finally:
        engine.close()
        elsewhere.close()
    assert len(engine.seen) == 1 and elsewhere.seen == []


@pytest.mark.django_db
@pytest.mark.parametrize("move", ["308 to the same origin", "307 to the same host, http to https"])
def test_the_stop_route_and_deliver_owed_stops_deliver_through_a_same_host_redirect(
    move, no_environment_proxy, tls_files, monkeypatch
):
    """The review's two cases through the Stop route and ``deliver_owed_stops``: a Stop
    the route sends is delivered; one owed while the engine was down is delivered by
    the command, which then exits 0 -- each inside its bound."""
    from django.contrib.auth import get_user_model
    from django.core.management import call_command
    from django.test import override_settings
    from rest_framework.test import APIClient

    from pentest.models import PentestScan

    monkeypatch.setenv("REQUESTS_CA_BUNDLE", tls_files[0])
    moved = None
    if move.startswith("308"):
        engine = Recorder(answer=_stops_at(_ABORT + "/"))
    else:
        moved = Recorder(answer=_stops_at(_ABORT), tls=tls_files)
        engine = Recorder(answer=lambda method, path, headers, body: (
            (307, {"Location": f"{moved.base}{path}"}, b"") if path == _ABORT else (200, {}, b"{}")
        ))
    analyst = get_user_model().objects.create_user(username="analyst", password=None, role="analyst")
    sent, owed = (
        PentestScan.objects.create(user=analyst, target_url="https://t.invalid/", consent=True,
                                   status=PentestScan.STATUS_PENDING, engine_run_id="run-1")
        for _ in range(2)
    )
    client = APIClient()
    client.force_authenticate(user=analyst)
    try:
        with override_settings(CYBERENGINE_URL=engine.base, CYBERENGINE_OPERATOR_KEY="cnrystopkey"):
            began = time.monotonic()
            answer = client.post(f"/api/pentest/scans/{sent.uuid}/stop/", {}, format="json")
            route_seconds = time.monotonic() - began
        with override_settings(CYBERENGINE_URL=_closed_base(), CYBERENGINE_OPERATOR_KEY="cnrystopkey"):
            client.post(f"/api/pentest/scans/{owed.uuid}/stop/", {}, format="json")
        owed.refresh_from_db()
        assert owed.stop_delivered_at is None
        with override_settings(CYBERENGINE_URL=engine.base, CYBERENGINE_OPERATOR_KEY="cnrystopkey"):
            began = time.monotonic()
            call_command("deliver_owed_stops", stdout=io.StringIO())
            deliver_seconds = time.monotonic() - began
            call_command("deliver_owed_stops", stdout=io.StringIO())
    finally:
        engine.close()
        if moved is not None:
            moved.close()
    sent.refresh_from_db()
    owed.refresh_from_db()
    assert answer.status_code == 200 and sent.stop_delivered_at is not None, (answer.status_code, sent.stop_detail)
    assert owed.stop_delivered_at is not None, owed.stop_detail
    assert route_seconds < _STOP_SECONDS and deliver_seconds < _STOP_SECONDS, (route_seconds, deliver_seconds)


def _proxy_answering_as_the_engine(engine_base):
    """A forward proxy that answers, for the engine it is in front of, as the engine;
    and anything else 502."""
    def answer(method, path, headers, body):
        if path.startswith(engine_base) and path.endswith(_ABORT):
            return _STOPPED
        if path.startswith(engine_base):
            return 200, {"Content-Type": "application/json"}, b'{"allow": true, "action": "allow"}'
        return 502, {}, b"{}"
    return answer


def _proxy_environment(monkeypatch, proxy_url, no_proxy=""):
    for variable in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"):
        monkeypatch.setenv(variable, "")
    for variable in ("HTTP_PROXY", "http_proxy"):
        monkeypatch.setenv(variable, proxy_url)
    for variable in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(variable, no_proxy)


def test_an_engine_reached_through_the_environment_s_proxy_hears_a_stop(monkeypatch, tmp_path):
    """The review's case: the engine is reached only through HTTP_PROXY. The Stop goes
    through it and is delivered; a ``.netrc`` login kept for the engine's host or the
    proxy's is sent to neither."""
    engine_base = "http://engine.invalid:8000"
    proxy = Recorder(answer=_proxy_answering_as_the_engine(engine_base))
    _proxy_environment(monkeypatch, proxy.base)
    netrc_password = _canary("netrc")
    netrc = tmp_path / ".netrc"
    netrc.write_text(f"machine engine.invalid\nlogin operator\npassword {netrc_password}\n"
                     f"machine 127.0.0.1\nlogin operator\npassword {netrc_password}\n")
    netrc.chmod(0o600)
    monkeypatch.setenv("NETRC", str(netrc))
    monkeypatch.setenv("HOME", str(tmp_path))
    try:
        said, seconds = _stop(engine_base)
    finally:
        proxy.close()
    assert isinstance(said, dict) and said["stopped"] is True, said
    assert [(m, p) for m, p, _h in proxy.seen] == [("POST", engine_base + _ABORT)]
    sent = json.dumps(proxy.seen)
    assert netrc_password not in sent and base64.b64encode(f"operator:{netrc_password}".encode()).decode() not in sent
    assert seconds < _STOP_SECONDS, seconds


def test_no_proxy_is_honoured_on_the_engine_s_lane(monkeypatch):
    proxy = Recorder(answer=_proxy_answering_as_the_engine("http://"))
    engine = Recorder(answer=_stops_at(_ABORT))
    _proxy_environment(monkeypatch, proxy.base, no_proxy="127.0.0.1")
    try:
        said, _seconds = _stop(engine.base)
    finally:
        proxy.close()
        engine.close()
    assert isinstance(said, dict) and said["stopped"] is True, said
    assert proxy.seen == [] and [p for _m, p, _h in engine.seen] == [_ABORT]


@pytest.mark.parametrize("name", sorted(ENGINE_SITES))
def test_the_engine_s_lane_uses_a_credentialed_proxy_and_quotes_none_of_its_login(name, monkeypatch, caplog):
    """The proxy carries the call, and its page quoting the request back --
    ``Proxy-Authorization`` among it -- reaches no answer, error or log line with the
    proxy's password in it, plain or encoded."""
    password = _canary("proxypw")
    proxy = Recorder(answer="echo")
    _proxy_environment(monkeypatch, proxy.base.replace("http://", f"http://egress:{password}@"))
    try:
        with caplog.at_level(logging.DEBUG):
            said = _call(SITES[name], "http://engine.invalid:8000", _canary("cred"))
    finally:
        proxy.close()
    assert proxy.seen and proxy.seen[0][1].startswith("http://engine.invalid:8000/"), proxy.seen
    login = base64.b64encode(f"egress:{password}".encode()).decode()
    assert any(h.get("Proxy-Authorization") == f"Basic {login}" for _m, _p, h in proxy.seen), proxy.seen
    # The proxy's page was the answer: the engine client says it back, withheld; the
    # defender gateway says only its status, and quotes no answer at all.
    assert ("HTTP 502" in said) if name == "defender" else ("bad gateway" in said), said
    for form in (password, login):
        quoted = [where for where, text in (("its answer or error", said), ("the log", caplog.text)) if form in text]
        assert quoted == [], f"{name} quoted the proxy's login in {quoted}"


def _engine_path(base, secret):
    from ai_engine.services.cyberengine_client import CyberEngineClient

    return CyberEngineClient(base, "cnrykey")._post(f"/api/classify-cve/{secret}?token={secret}", {"text": "x"})


def _transport_path(base, secret):
    from assurance.connectors.base import RequestsTransport

    return RequestsTransport(timeout=(2, 2), deadline=5).post(
        f"{base}/services/T0/B0/{secret}?token={secret}", headers={}, json={}
    )


def _posture_path(base, secret):
    from assurance.posture.base import RequestsFetcher

    return RequestsFetcher(base, {}, timeout=(2, 2)).fetch(f"v1/{secret}?token={secret}")


_PATH_SECRET_SITES = {"engine": _engine_path, "transport": _transport_path, "posture": _posture_path}


@pytest.mark.parametrize("name", sorted(_PATH_SECRET_SITES))
def test_a_failed_connection_quotes_no_secret_from_its_path_or_query(name, no_environment_proxy, caplog):
    """urllib3 quotes the request's path and query in a failed connection's text
    ("Max retries exceeded with url: /services/T0/B0/<the webhook's secret>?token=...");
    a webhook's secret is in its path. Neither appears in what the call says."""
    secret = _canary("pathsecret")
    with caplog.at_level(logging.DEBUG):
        said = _call(Site("", "", _PATH_SECRET_SITES[name]), _closed_base(), secret)
    assert secret not in said and secret not in caplog.text, said


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
