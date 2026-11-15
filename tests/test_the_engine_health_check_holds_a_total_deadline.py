"""The engine's health check holds a total deadline, so a dripping engine cannot hold it (AB-LLM-ASSET).

Readiness (config.readiness) asks the engine's ``GET /health`` under the client's
``HEALTH_TIMEOUT``: 0.5 s to connect, 1 s to read. A read timeout bounds one socket
read, not the answer: an engine that sent a byte inside every read timeout held the
check for as long as it kept sending, and with it readiness's one engine check, so
every probe read "did not answer within 2 s" from a check that was still waiting.

``CyberEngineClient.health()`` now answers by ``HEALTH_DEADLINE_SECONDS`` in all,
inside readiness's 2 s bound. Proved against a stub engine that drips its body, and
one that drips its status line and headers, a byte every 0.25 s:

* health() fails as a timeout (``unknown`` to readiness) inside the bound;
* a dripped body is cut off at the deadline and its connection closed, so the ask
  ends and nothing is left waiting;
* a dripped status line or headers hold one ask, and only one: every ask meanwhile
  answers at once, and opens no second connection;
* readiness answers inside its bound with the engine ``unknown`` because its own check
  ran out, and no check is left in flight.
"""

from __future__ import annotations

import http.server
import threading
import time

import pytest
import requests

from ai_engine.services import cyberengine_client
from config import readiness
from tests.test_readiness_names_each_dependency import _ask, _client, _reading

#: Seconds between two bytes of a drip: well inside the 1 s read timeout.
DRIP_EVERY = 0.25
#: How long a stub engine keeps dripping before it gives up on its own.
DRIP_FOR = 20.0


@pytest.fixture(autouse=True)
def _fresh():
    readiness.forget_inflight()
    yield
    readiness.forget_inflight()


def _ask_is_free(within):
    """True once no /health ask is in flight (the slot health() takes), within ``within`` s."""
    slot = getattr(cyberengine_client, "_HEALTH_ASK", None)
    if slot is None:
        return True
    if not slot.acquire(timeout=within):
        return False
    slot.release()
    return True


@pytest.fixture()
def dripping():
    """dripping(part) -> (client, connections): a real client whose engine drips its
    ``"body"`` (a 200 whose body comes a byte at a time) or its ``"headers"`` (the
    status line and headers a byte at a time), until the test ends; ``connections``
    counts the connections it was asked on, and records each one's end."""
    servers = []
    release = threading.Event()

    def start(part):
        connections = {"opened": 0, "closed_by_client": threading.Event()}

        class Engine(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - the stdlib's name
                connections["opened"] += 1
                try:
                    if part == "body":
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", "100000")
                        self.end_headers()
                        drip = b" " * 100000
                    else:
                        drip = b"HTTP/1.1 200 OK\r\nX-Drip: " + b"a" * 100000
                    ends = time.monotonic() + DRIP_FOR
                    for byte in drip:
                        if release.is_set() or time.monotonic() > ends:
                            return
                        self.wfile.write(bytes([byte]))
                        self.wfile.flush()
                        time.sleep(DRIP_EVERY)
                except OSError:
                    connections["closed_by_client"].set()

            def log_message(self, *_args):
                pass

        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Engine)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return _client(f"http://127.0.0.1:{server.server_address[1]}"), connections

    yield start
    release.set()
    for server in servers:
        server.shutdown()
        server.server_close()
    # The ask a dripped header held ends once the drip does; the next test starts free.
    assert _ask_is_free(5.0), "a /health ask was still in flight after its engine stopped"


def _health(client):
    """client.health() on a thread of the test's own: (outcome, still running after the
    readiness bound)."""
    outcome = {}

    def ask():
        started = time.monotonic()
        try:
            outcome["answer"] = client.health()
        except cyberengine_client.EngineError as exc:
            outcome["error"] = exc
        outcome["took"] = time.monotonic() - started

    thread = threading.Thread(target=ask, daemon=True)
    thread.start()
    thread.join(readiness.DEADLINE_SECONDS)
    return outcome, thread.is_alive()


def test_the_total_deadline_is_inside_the_readiness_bound():
    deadline = cyberengine_client.HEALTH_DEADLINE_SECONDS
    assert isinstance(deadline, float)
    assert 0 < deadline <= 0.75 * readiness.DEADLINE_SECONDS
    # Each socket operation still has its own, shorter, timeout inside it.
    assert max(cyberengine_client.HEALTH_TIMEOUT) < deadline


@pytest.mark.parametrize("part", ["body", "headers"])
def test_a_dripping_engines_health_check_ends_at_its_deadline(dripping, part):
    """A byte every 0.25 s never trips the 1 s read timeout. The check still ends,
    inside the readiness bound, as a timeout: nothing is established."""
    client, connections = dripping(part)
    outcome, still_running = _health(client)
    assert not still_running, f"the health check still waits after {readiness.DEADLINE_SECONDS:g} s"
    assert "answer" not in outcome, outcome
    assert outcome["error"].kind == cyberengine_client.ENGINE_UNREACHABLE
    assert isinstance(outcome["error"].__cause__, requests.Timeout), outcome
    assert outcome["took"] < readiness.DEADLINE_SECONDS
    assert connections["opened"] == 1


def test_a_dripped_body_is_cut_off_and_its_connection_closed(dripping):
    """The body is read against the same deadline, so the ask itself ends there and
    closes its connection: no thread is left reading a drip."""
    client, connections = dripping("body")
    outcome, still_running = _health(client)
    assert not still_running and "error" in outcome, outcome
    # The ask ends within one more read of the drip after the deadline.
    assert _ask_is_free(1.5), "the ask was still reading the dripped body"
    assert connections["closed_by_client"].wait(2.0), "the dripped body's connection was never closed"


def test_while_a_dripped_header_holds_an_ask_the_next_answers_at_once(dripping):
    """No read of the body bounds a status line dripped a byte at a time, so that ask
    stays on its thread until the drip ends. While it does, health() answers at once,
    as a timeout, and opens no second connection: a readiness probe each second does
    not leave a thread behind each time."""
    client, connections = dripping("headers")
    first, still_running = _health(client)
    assert not still_running and "error" in first, first

    started = time.monotonic()
    with pytest.raises(cyberengine_client.EngineError) as raised:
        client.health()
    assert time.monotonic() - started < 0.5
    assert isinstance(raised.value.__cause__, requests.Timeout)
    assert connections["opened"] == 1


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("part", ["body", "headers"])
def test_readiness_against_a_dripping_engine_answers_inside_its_bound(dripping, part):
    """At readiness's real 2 s bound: the answer comes before it, the engine reads
    ``unknown`` because its own check ran out at its deadline (not because the answer
    stopped waiting), and no check is left in flight."""
    client, _connections = dripping(part)
    response, took = _ask(client)
    assert took < readiness.DEADLINE_SECONDS, took
    assert response.status_code == 503, response.content
    engine_reading = _reading(response, "the engine")
    assert engine_reading["status"] == "unknown", engine_reading
    assert "did not answer /health within its own" in engine_reading["reason"], engine_reading
    assert _reading(response, "the database")["status"] == "ok"
    assert "the engine" not in readiness._inflight
