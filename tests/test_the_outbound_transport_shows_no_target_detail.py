"""The outbound transport (``safety.outbound``) never shows a target's detail in an
error, and a call that asks for a total deadline (``total=``) gets one; no other
call does, every stop's included.

* **No error says its target.** Every error the transport raises, and every
  exception that error was raised from, during or with, says one fixed message, its
  own class and an opaque reference the chain shares -- never the target's host,
  port, path, query, login or fragment. On master a connect that timed out (what
  Windows raises for a closed loopback port, which it does not refuse at once)
  carried urllib3's connection object as an argument, whose ``repr`` is
  ``<HTTPConnection(host=..., port=...)>``: the quieting rewrote text arguments
  only, so the host and port were said in the traceback. On Linux the same port is
  refused at once, and urllib3's ``NewConnectionError`` formats the connection into
  a TEXT argument instead, so the leak never showed there. Here the Windows shape is
  built on any platform (``socket.timeout`` from the connect), and every other way a
  send fails is driven for real over loopback. The exceptions a call site classifies
  a failure by (requests' ``MaxRetryError`` and its ``reason``) are kept.
* **``total=`` is opt-in.** A status line or headers dripped a byte at a time keep a
  read alive however short its read timeout; with ``total=`` a timer shuts the
  call's sockets down at the deadline, the call raises the quiet
  ``TotalDeadlineExceeded``, and no timer thread or socket is left. A call that does
  not pass it never arms a timer: not a plain call, and not a scan's Stop, its
  owed-stop delivery or the failsafe's stop-lane read.
"""

from __future__ import annotations

import io
import logging
import re
import secrets
import socket
import threading
import time
import traceback

import pytest

from tests.test_no_outbound_call_follows_a_redirect_or_reads_the_environment import (
    Recorder,
    _closed_base,
    _proxy_environment,
    no_environment_proxy,  # noqa: F401 - a fixture
)

#: An opaque reference (its prefix is random hex, which could hold a port's digits).
_REFERENCE = re.compile(r"ob-[0-9a-f]+-[0-9a-f]+")


def _canary(label: str) -> str:
    return f"cnry{label}{secrets.token_hex(6)}"


def _members(exc: BaseException):
    from safety import outbound

    return list(outbound._chain(exc))


def _everything_said(exc: BaseException) -> str:
    """What an exception says: its traceback (every cause and context), and the
    ``str``, ``repr`` and arguments of every exception of its chain."""
    said = ["".join(traceback.format_exception(exc))]
    for member in _members(exc):
        said.append(f"{type(member).__name__}: {member!s} {member!r} {member.args!r}")
    return _REFERENCE.sub("ob-REF", "\n".join(said))


def _target(host: str, port) -> dict:
    """A target URL carrying a canary in its login, path, query and fragment."""
    parts = {
        "user": _canary("user"), "password": _canary("pw"), "path": _canary("path"),
        "query": _canary("query"), "fragment": _canary("frag"), "host": host, "port": str(port),
    }
    parts["url"] = (
        f"http://{parts['user']}:{parts['password']}@{host}:{port}/{parts['path']}"
        f"?token={parts['query']}#{parts['fragment']}"
    )
    return parts


def _assert_says_nothing_of(exc: BaseException, target: dict, *, host_is_canary: bool = True) -> None:
    from safety import outbound

    said = _everything_said(exc)
    named = ["user", "password", "path", "query", "fragment", "port"] + (["host"] if host_is_canary else [])
    shown = [name for name in named if target[name] in said]
    assert shown == [], f"the error said the target's {shown}:\n{said}"
    if not host_is_canary:
        assert "127.0.0.1" not in said, said
    # What it says instead: the fixed message, its class, and ONE reference for the chain.
    # (An OSError says its errno first: "[Errno 104] the outbound request failed ...")
    assert outbound.FAILED_SEND in str(exc), str(exc)
    references = {
        match for member in _members(exc) for match in _REFERENCE.findall(f"{member!s} {member.args!r}")
    }
    assert len(references) == 1, references
    for member in _members(exc):
        if not any(isinstance(arg, BaseException) for arg in member.args) and not isinstance(member, OSError):
            assert type(member).__name__ in str(member), (type(member).__name__, str(member))


# ---------------------------------------------------------------------------
# Every way a send fails says nothing of its target
# ---------------------------------------------------------------------------


def test_a_connect_that_times_out_says_neither_host_nor_port(monkeypatch, no_environment_proxy):  # noqa: F811
    """Windows' shape for a closed port: urllib3's ConnectTimeoutError carries the
    connection itself, whose repr names the host and port."""
    import requests
    import urllib3.connection

    from ai_engine.services.cyberengine_client import _never_reached_the_engine
    from safety import outbound

    def times_out(*_args, **_kwargs):
        raise socket.timeout("timed out")

    monkeypatch.setattr(urllib3.connection.connection, "create_connection", times_out)
    target = _target(_canary("host"), 47000 + secrets.randbelow(2000))
    with pytest.raises(requests.exceptions.ConnectTimeout) as raised:
        outbound.post(target["url"], json={}, timeout=2, engine=True)
    _assert_says_nothing_of(raised.value, target)
    assert _never_reached_the_engine(raised.value), "the cause a launch is classified by was lost"


def test_a_refused_connection_says_neither_host_nor_port(no_environment_proxy):  # noqa: F811
    """A closed port: refused at once on Linux, timed out on Windows. Either way
    nothing of the target is said, and it still reads as never having reached it."""
    import requests

    from ai_engine.services.cyberengine_client import _never_reached_the_engine
    from safety import outbound

    target = _target("127.0.0.1", _closed_base().rsplit(":", 1)[1])
    with pytest.raises(requests.RequestException) as raised:
        outbound.post(target["url"], json={}, timeout=2, engine=True)
    _assert_says_nothing_of(raised.value, target, host_is_canary=False)
    assert _never_reached_the_engine(raised.value), "the cause a launch is classified by was lost"


def test_a_name_that_does_not_resolve_is_not_said(monkeypatch, no_environment_proxy):  # noqa: F811
    import requests

    from safety import outbound

    target = _target(_canary("host") + ".invalid", 8443)
    resolve = socket.getaddrinfo

    def getaddrinfo(host, *args, **kwargs):
        if host == target["host"]:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return resolve(host, *args, **kwargs)

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    with pytest.raises(requests.ConnectionError) as raised:
        outbound.get(target["url"], timeout=2)
    _assert_says_nothing_of(raised.value, target)


def test_a_read_that_times_out_says_neither_host_nor_port(no_environment_proxy):  # noqa: F811
    import requests

    from safety import outbound

    release = threading.Event()

    def stalls(method, path, headers, body):
        release.wait(5)
        return 200, {}, b"{}"

    engine = Recorder(answer=stalls)
    target = _target("127.0.0.1", engine.port)
    try:
        with pytest.raises(requests.exceptions.ReadTimeout) as raised:
            outbound.get(target["url"], timeout=(2, 0.3), engine=True)
    finally:
        release.set()
        engine.close()
    _assert_says_nothing_of(raised.value, target, host_is_canary=False)


def test_a_connection_dropped_before_an_answer_says_nothing_of_its_target(no_environment_proxy):  # noqa: F811
    import requests

    from safety import outbound

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)

    def drop():
        conn, _ = listener.accept()
        conn.recv(65536)
        conn.close()

    threading.Thread(target=drop, daemon=True).start()
    target = _target("127.0.0.1", listener.getsockname()[1])
    try:
        with pytest.raises(requests.ConnectionError) as raised:
            outbound.post(target["url"], json={}, timeout=2)
    finally:
        listener.close()
    _assert_says_nothing_of(raised.value, target, host_is_canary=False)


def test_a_tls_failure_says_nothing_of_its_target(no_environment_proxy):  # noqa: F811
    """https to a server that answers in plain HTTP: the TLS error's own text, which
    an SSLError keeps apart from its arguments, is quieted too."""
    import requests

    from safety import outbound

    engine = Recorder()
    target = _target("127.0.0.1", engine.port)
    try:
        with pytest.raises(requests.exceptions.SSLError) as raised:
            outbound.get(target["url"].replace("http://", "https://", 1), timeout=2, engine=True)
    finally:
        engine.close()
    _assert_says_nothing_of(raised.value, target, host_is_canary=False)


def test_a_url_that_cannot_be_read_is_not_said(no_environment_proxy):  # noqa: F811
    import requests

    from safety import outbound

    target = _target(_canary("host"), "99999999")
    with pytest.raises(requests.RequestException) as raised:
        outbound.get(target["url"], timeout=2)
    _assert_says_nothing_of(raised.value, target)


def test_a_proxy_that_cannot_be_reached_says_nothing_of_the_target_or_its_login(monkeypatch):
    import requests

    from safety import outbound

    proxy_password = _canary("proxypw")
    proxy_port = _closed_base().rsplit(":", 1)[1]
    _proxy_environment(monkeypatch, f"http://egress:{proxy_password}@127.0.0.1:{proxy_port}")
    target = _target(_canary("host") + ".invalid", 8000)
    with pytest.raises(requests.RequestException) as raised:
        outbound.post(target["url"], json={}, timeout=2, engine=True)
    _assert_says_nothing_of(raised.value, target)
    said = _everything_said(raised.value)
    assert proxy_password not in said and proxy_port not in said, said


def test_a_request_that_cannot_be_prepared_says_nothing_of_its_target(monkeypatch):
    """A proxy password that will not encode raises UnicodeEncodeError, not a
    RequestException, before anything is sent: still the fixed message, and the
    character it could not encode is not said either."""
    import requests

    from safety import outbound

    _proxy_environment(monkeypatch, "http://egress:cnry%E2%82%ACpw@127.0.0.1:1")  # pragma: allowlist secret
    target = _target(_canary("host") + ".invalid", 8000)
    with pytest.raises(requests.RequestException) as raised:
        outbound.post(target["url"], json={}, timeout=2, engine=True)
    _assert_says_nothing_of(raised.value, target)
    assert "€" not in _everything_said(raised.value)


def test_a_redirect_chain_that_spends_its_deadline_says_nothing_of_its_target(no_environment_proxy):  # noqa: F811
    import requests

    from safety import outbound

    def slow_loop(method, path, headers, body):
        time.sleep(0.3)
        return 307, {"Location": path}, b""

    engine = Recorder(answer=slow_loop)
    target = _target("127.0.0.1", engine.port)
    try:
        with pytest.raises(requests.exceptions.ReadTimeout) as raised:
            outbound.post(target["url"], json={}, timeout=(0.2, 0.2), engine=True)
    finally:
        engine.close()
    _assert_says_nothing_of(raised.value, target, host_is_canary=False)


def test_quieting_that_fails_says_only_the_class(monkeypatch):
    from safety import outbound

    def broken(*_args, **_kwargs):
        raise RuntimeError("quieting broke")

    monkeypatch.setattr(outbound, "_say_only", broken)
    host = _canary("host")
    exc = OSError(5, f"refused by {host}")
    assert outbound.quiet(exc) is exc
    assert host not in _everything_said(exc) and str(exc) == "[Errno 5] OSError", str(exc)


def test_a_record_of_the_http_client_says_nothing_of_a_failed_connection(monkeypatch, caplog, no_environment_proxy):  # noqa: F811
    """urllib3 names a broken connection by the exception ('%r') and logs a
    traceback with exc_info: both quieted, whatever the record's level."""
    import requests
    import urllib3.connection

    from safety import outbound

    def times_out(*_args, **_kwargs):
        raise socket.timeout("timed out")

    monkeypatch.setattr(urllib3.connection.connection, "create_connection", times_out)
    target = _target(_canary("host"), 47000 + secrets.randbelow(2000))
    try:
        outbound.get(target["url"], timeout=2)
    except requests.RequestException as exc:
        failure = exc
    else:
        raise AssertionError("a connect that times out answered")
    # Put the raw shape back: the connection object, as urllib3 raises it.
    conn = urllib3.connection.HTTPConnection(target["host"], int(target["port"]))
    raw = urllib3.exceptions.ConnectTimeoutError(conn, f"Connection to {target['host']} timed out.")
    with caplog.at_level(logging.DEBUG, logger="urllib3.connectionpool"):
        logger = logging.getLogger("urllib3.connectionpool")
        logger.warning("Retrying (%r) after connection broken by '%r': %s", "Retry(total=0)", raw, "/")
        logger.error("a request failed", exc_info=(type(failure), failure, failure.__traceback__))
    text = caplog.text
    for name in ("host", "port", "path", "query", "fragment", "user", "password"):
        assert target[name] not in _REFERENCE.sub("ob-REF", text), (name, text)
    assert outbound.FAILED_SEND in text


# ---------------------------------------------------------------------------
# total=: a dripping far end is cut at the deadline, and only when asked
# ---------------------------------------------------------------------------


class _Dripper:
    """Accepts one connection, reads the request and drips ``what`` -- the status
    line and headers, or (``body=True``) a whole answer's body -- one byte every
    ``every`` seconds. Records when the client's end of the socket closed."""

    def __init__(self, *, every: float = 0.1, body: bool = False, tls_silent: bool = False):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.base = f"{'https' if tls_silent else 'http'}://127.0.0.1:{self.port}"
        self.closed_at: float | None = None
        self.accepted = threading.Event()
        self._every, self._body, self._silent = every, body, tls_silent
        self._stop = threading.Event()
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.listener.accept()
        except OSError:
            return
        self.accepted.set()
        conn.settimeout(0.05)
        try:
            if self._silent:
                # A TLS handshake that never finishes: nothing is ever answered.
                while not self._stop.is_set():
                    try:
                        if conn.recv(65536) == b"":
                            break
                    except socket.timeout:
                        continue
            else:
                self._read_request(conn)
                if self._body:
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 100000\r\n\r\n")
                    drip = b"x" * 100000
                else:
                    drip = b"HTTP/1.1 200 OK\r\n" + b"".join(b"X-Drip-%d: a\r\n" % n for n in range(5000))
                for i in range(len(drip)):
                    if self._stop.is_set():
                        break
                    conn.sendall(drip[i:i + 1])
                    if self._closed(conn, self._every):
                        break
        except OSError:
            pass
        finally:
            if self.closed_at is None:
                self.closed_at = time.monotonic()
            conn.close()

    @staticmethod
    def _read_request(conn):
        data = b""
        while b"\r\n\r\n" not in data:
            try:
                chunk = conn.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                return
            data += chunk

    def _closed(self, conn, wait: float) -> bool:
        """Waits ``wait`` seconds; whether the client closed its end meanwhile."""
        until = time.monotonic() + wait
        while time.monotonic() < until:
            try:
                if conn.recv(65536) == b"":
                    self.closed_at = time.monotonic()
                    return True
            except socket.timeout:
                continue
            except OSError:
                self.closed_at = time.monotonic()
                return True
        return False

    def close(self):
        self._stop.set()
        self.listener.close()
        self.thread.join(5)


def _timer_threads():
    from safety import outbound

    return [t for t in threading.enumerate() if t.name == outbound.TOTAL_TIMER_NAME and t.is_alive()]


@pytest.fixture
def armed(monkeypatch):
    """Every timer ``safety.outbound`` arms, and every deadline it holds, recorded."""
    from safety import outbound

    timers, deadlines = [], []
    arm, deadline_class = outbound._arm, outbound._Deadline

    def spy(deadline, total):
        timers.append(total)
        return arm(deadline, total)

    class Spied(deadline_class):
        def __init__(self, total):
            super().__init__(total)
            deadlines.append(self)

    monkeypatch.setattr(outbound, "_arm", spy)
    monkeypatch.setattr(outbound, "_Deadline", Spied)
    return {"timers": timers, "deadlines": deadlines}


def _cut(dripper: _Dripper, *, total: float, **kwargs):
    from safety import outbound

    began = time.monotonic()
    try:
        outbound.get(f"{dripper.base}/health", total=total, **kwargs)
    except Exception as exc:  # noqa: BLE001 - what it raised is what is checked
        return exc, time.monotonic() - began, began
    raise AssertionError("a dripping answer was handed on as whole")


@pytest.mark.parametrize("body", [False, True], ids=["status-and-headers", "body"])
def test_a_dripped_answer_is_cut_at_the_total_deadline(body, armed, no_environment_proxy):  # noqa: F811
    """The read timeout (5 s) never fires: each byte comes inside it. ``total=1``
    shuts the socket down at 1 s, the call raises the quiet timeout, and neither the
    timer's thread nor the socket outlives the call."""
    from safety import outbound

    dripper = _Dripper(every=0.1, body=body)
    try:
        exc, took, began = _cut(dripper, total=1.0, timeout=(5, 5))
        dripper.thread.join(3)
    finally:
        dripper.close()
    assert isinstance(exc, outbound.TotalDeadlineExceeded), repr(exc)
    assert 0.9 <= took < 1.8, took
    assert str(exc).startswith(outbound.FAILED_SEND) and "127.0.0.1" not in _everything_said(exc)
    assert dripper.closed_at is not None and dripper.closed_at - began < 2.0, "the socket was not closed at the deadline"
    assert _timer_threads() == [], "the deadline's timer outlived its call"
    (deadline,) = armed["deadlines"]
    assert deadline.connections and all(c.sock is None for c in deadline.connections), "a connection was left open"
    assert deadline.sockets and all(s.fileno() == -1 for s in deadline.sockets), "a socket was left open"


def test_a_tls_handshake_that_never_finishes_is_cut_at_the_total_deadline(armed, no_environment_proxy):  # noqa: F811
    from safety import outbound

    dripper = _Dripper(tls_silent=True)
    try:
        exc, took, _began = _cut(dripper, total=1.0, timeout=(5, 5), verify=False)
    finally:
        dripper.close()
    assert isinstance(exc, outbound.TotalDeadlineExceeded), repr(exc)
    assert 0.9 <= took < 1.8, took
    assert _timer_threads() == []


def test_an_answer_inside_the_total_deadline_is_read_and_its_timer_is_gone_at_once(armed, no_environment_proxy):  # noqa: F811
    """The timer is cancelled and joined before the call returns: with ``total=30``,
    nothing of it is left the moment the answer is handed on."""
    from safety import outbound

    engine = Recorder()
    try:
        began = time.monotonic()
        answer = outbound.post(f"{engine.base}/api/x", json={}, timeout=5, total=30)
        took = time.monotonic() - began
    finally:
        engine.close()
    assert answer.status_code == 200 and answer.json() == {"allow": True, "action": "allow"}
    assert took < 2.0, took
    assert armed["timers"] == [30.0]
    assert _timer_threads() == [], "the deadline's timer outlived a call that was answered"
    (deadline,) = armed["deadlines"]
    assert all(s.fileno() == -1 for s in deadline.sockets), "a socket was left open"


def test_a_redirect_chain_is_held_to_one_total_deadline(armed, no_environment_proxy):  # noqa: F811
    from safety import outbound

    dripper = _Dripper(every=0.1)

    def to_the_dripper(method, path, headers, body):
        return 307, {"Location": f"http://127.0.0.1:{dripper.port}{path}"}, b""

    engine = Recorder(answer=to_the_dripper)
    try:
        began = time.monotonic()
        with pytest.raises(outbound.TotalDeadlineExceeded):
            outbound.get(f"{engine.base}/api/failsafe/x", timeout=(5, 5), engine=True, total=1.0)
        took = time.monotonic() - began
    finally:
        engine.close()
        dripper.close()
    assert 0.9 <= took < 1.8, took
    assert _timer_threads() == []


@pytest.mark.parametrize("total", [0, -1, float("inf"), float("nan"), "1", True])
def test_a_total_that_is_not_a_positive_number_is_refused_before_anything_is_sent(total, armed, no_environment_proxy):  # noqa: F811
    from safety import outbound

    engine = Recorder()
    try:
        with pytest.raises(ValueError, match="total="):
            outbound.get(f"{engine.base}/x", timeout=2, total=total)
    finally:
        engine.close()
    assert engine.seen == [] and armed["timers"] == []


def test_a_call_that_does_not_ask_for_a_total_deadline_never_arms_one(armed, no_environment_proxy):  # noqa: F811
    """Every lane, answered and failed: no timer, no deadline, no thread."""
    import requests

    from safety import outbound

    engine = Recorder()
    down = _closed_base()
    try:
        for engine_lane in (False, True):
            assert outbound.get(f"{engine.base}/x", timeout=2, engine=engine_lane).status_code == 200
            assert outbound.post(f"{engine.base}/x", json={}, timeout=2, engine=engine_lane).status_code == 200
            assert outbound.get(f"{engine.base}/x", timeout=2, engine=engine_lane, stream=True).status_code == 200
            with pytest.raises(requests.RequestException):
                outbound.post(f"{down}/x", json={}, timeout=2, engine=engine_lane)
    finally:
        engine.close()
    assert armed == {"timers": [], "deadlines": []}
    assert _timer_threads() == []


_STOPPED = (200, {"Content-Type": "application/json"},
            b'{"run_id": "run-1", "state": "aborted", "recorded": true, "reason": "operator stop"}')


@pytest.mark.django_db
def test_no_stop_ever_arms_a_total_deadline(armed, no_environment_proxy):  # noqa: F811
    """The SAFETY RULE: a scan's Stop through its route, an owed Stop delivered by
    ``deliver_owed_stops``, the engine client's abort itself, and the failsafe's
    stop-lane read are each sent with no timer, no deadline and no thread -- answered,
    and with the engine down (owed)."""
    from django.contrib.auth import get_user_model
    from django.core.management import CommandError, call_command
    from django.test import override_settings
    from rest_framework.test import APIClient

    from ai_engine.services.cyberengine_client import CyberEngineClient, EngineError
    from pentest.models import PentestScan

    def answer(method, path, headers, body):
        if path.endswith("/abort"):
            return _STOPPED
        return 200, {"Content-Type": "application/json"}, b'{"enabled": true, "state": "running"}'

    engine = Recorder(answer=answer)
    down = _closed_base()
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
            assert client.post(f"/api/pentest/scans/{sent.uuid}/stop/", {}, format="json").status_code == 200
        with override_settings(CYBERENGINE_URL=down, CYBERENGINE_OPERATOR_KEY="cnrystopkey"):
            assert client.post(f"/api/pentest/scans/{owed.uuid}/stop/", {}, format="json").status_code == 202
            with pytest.raises(CommandError, match="still owed"):
                call_command("deliver_owed_stops", stdout=io.StringIO())
        with override_settings(CYBERENGINE_URL=engine.base, CYBERENGINE_OPERATOR_KEY="cnrystopkey"):
            call_command("deliver_owed_stops", stdout=io.StringIO())
        CyberEngineClient(engine.base, "cnrystopkey").abort_scan("run-1", "operator stop")
        assert CyberEngineClient(engine.base, "cnrystopkey").failsafe_state()["enabled"] is True
        with pytest.raises(EngineError):
            CyberEngineClient(down, "cnrystopkey").abort_scan("run-1", "operator stop")
        with pytest.raises(EngineError):
            CyberEngineClient(down, "cnrystopkey").failsafe_state()
    finally:
        engine.close()
    owed.refresh_from_db()
    assert owed.stop_delivered_at is not None, owed.stop_detail
    stops = [path for method, path, _h in engine.seen if path.endswith("/abort")]
    assert len(stops) == 3, engine.seen
    assert armed == {"timers": [], "deadlines": []}, "a stop armed a total deadline"
    assert _timer_threads() == []
