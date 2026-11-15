"""Readiness names each dependency, from bounded checks, and never touches a stop (G14-AB-2).

``GET /api/health/`` is liveness: ``ok`` at once, whatever is down, unchanged.
``GET /api/health/ready/`` (config.readiness) asks the database, the engine and
Mythos-Core, each on a bounded check, and names each one ``ok``, ``degraded`` or
``unknown`` with the reason. With a dependency down it never says ``ok``; with a
dependency hung it answers inside its bound; with every dependency up it says
ready. It is a read (safety.degraded), not a stop (safety.stops), and nothing but
the root URLconf imports it.
"""

from __future__ import annotations

import ast
import http.server
import socket
import threading
import time
from pathlib import Path
from unittest import mock

import pytest
from django.db import OperationalError
from django.db.backends.utils import CursorWrapper
from mythos_core import status as core_status
from rest_framework.test import APIClient

from config import readiness
from safety import degraded, stops

ROOT = Path(__file__).resolve().parent.parent
READY = "/api/health/ready/"

#: A hung dependency is held this long by the tests, far past the answer's bound
#: (patched to BOUND), and released when the test ends.
HELD_SECONDS = 5.0
BOUND = 0.3


@pytest.fixture(autouse=True)
def _fresh():
    readiness.forget_inflight()
    with mock.patch.object(readiness, "DEADLINE_SECONDS", BOUND):
        yield
    readiness.forget_inflight()


@pytest.fixture()
def release():
    """An event a hung dependency waits on, set when the test ends."""
    event = threading.Event()
    yield event
    event.set()


class _Health(http.server.BaseHTTPRequestHandler):
    status_line = 200
    body = b'{"status": "ok"}'
    content_type = "application/json"
    delay = 0.0

    def do_GET(self):  # noqa: N802 - the stdlib's name
        time.sleep(self.delay)
        try:
            self.send_response(self.status_line)
            self.send_header("Content-Type", self.content_type)
            self.end_headers()
            self.wfile.write(self.body)
        except OSError:
            pass

    def log_message(self, *_args):
        pass


@pytest.fixture()
def engine():
    """engine(**handler attributes) -> a real client whose engine answers so."""
    servers = []

    def start(**attrs):
        handler = type("Engine", (_Health,), attrs)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return _client(f"http://127.0.0.1:{server.server_address[1]}")

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _client(url):
    from ai_engine.services.cyberengine_client import CyberEngineClient

    # A key that cannot occur in an answer: the engine's lane withholds the key from
    # everything the engine says, so a one-letter key would redact the "k" of "ok".
    return CyberEngineClient(url, "readiness-test-operator-key")


def _refusing_engine():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return _client(f"http://127.0.0.1:{port}")


def _ask(engine_client):
    """GET readiness, anonymously, with ``engine_client`` as the configured engine (None:
    no engine configured). Returns (response, seconds it took)."""
    api = APIClient(raise_request_exception=False)
    with mock.patch("ai_engine.services.cyberengine_client.CyberEngineClient.from_settings") as factory:
        if engine_client is None:
            factory.side_effect = RuntimeError("CYBERENGINE_URL is not configured")
        else:
            factory.return_value = engine_client
        started = time.monotonic()
        response = api.get(READY)
        took = time.monotonic() - started
    return response, took


def _reading(response, name):
    return response.json()["dependencies"][name]


def _not_ready(response, name, state):
    """The answer says not ready, names ``name`` ``state``, and is safety.degraded's
    evidence-read answer."""
    assert response.status_code == 503, response.content
    body = response.json()
    assert body["status"] == core_status.UNKNOWN
    assert body["operation_class"] == degraded.EVIDENCE_READ
    assert name in body["detail"] and state in body["detail"]
    reading = body["dependencies"][name]
    assert reading["status"] == state, reading
    assert reading["reason"]


# --- Every dependency up --------------------------------------------------------------


@pytest.mark.django_db(transaction=True)
def test_every_dependency_up_is_ready(engine):
    response, _took = _ask(engine())
    assert response.status_code == 200, response.content
    body = response.json()
    assert body["status"] == "ok"
    assert {name: r["status"] for name, r in body["dependencies"].items()} == {
        "the database": "ok", "the engine": "ok", "Mythos-Core": "ok",
    }
    assert set(body["not_probed"]) == {"connectors", "the receipt signer"}


@pytest.mark.django_db(transaction=True)
def test_liveness_is_unchanged_whatever_readiness_says():
    api = APIClient(raise_request_exception=False)
    with mock.patch.multiple(CursorWrapper, execute=_refused, executemany=_refused):
        response = api.get("/api/health/")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "message": "Django backend is alive."}


# --- Each dependency down: degraded, named, never ok ------------------------------------


def _refused(*_args, **_kwargs):
    raise OperationalError("the database is unavailable at db.internal:5432 as user canary")


@pytest.mark.django_db(transaction=True)
def test_the_database_refusing_is_degraded(engine):
    with mock.patch.multiple(CursorWrapper, execute=_refused, executemany=_refused):
        response, _took = _ask(engine())
    _not_ready(response, "the database", "degraded")
    body = response.json()
    assert body["dependency"] == "the database"
    assert "OperationalError" in _reading(response, "the database")["reason"]
    # Named by type, never by message: the message carried a host and a user.
    assert "db.internal" not in response.content.decode() and "canary" not in response.content.decode()
    assert _reading(response, "the engine")["status"] == "ok"


@pytest.mark.django_db(transaction=True)
def test_the_database_answering_garbage_is_degraded(engine):
    real = CursorWrapper.__getattr__

    def garbage(self, attr):
        if attr == "fetchone":
            return lambda: ("not 1",)
        return real(self, attr)

    with mock.patch.object(CursorWrapper, "__getattr__", garbage):
        response, _took = _ask(engine())
    _not_ready(response, "the database", "degraded")


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("fault", ["refuses connections", "answers 503", "answers HTML", "answers not ok"])
def test_the_engine_down_is_degraded(engine, fault):
    client = {
        "refuses connections": _refusing_engine,
        "answers 503": lambda: engine(status_line=503, body=b'{"detail": "down"}'),
        "answers HTML": lambda: engine(body=b"<html>holding page</html>", content_type="text/html"),
        "answers not ok": lambda: engine(body=b'{"status": "starting"}'),
    }[fault]()
    response, _took = _ask(client)
    _not_ready(response, "the engine", "degraded")
    assert response.json()["dependency"] == "the engine"
    assert _reading(response, "the database")["status"] == "ok"


@pytest.mark.django_db(transaction=True)
def test_no_engine_configured_is_unknown():
    response, _took = _ask(None)
    _not_ready(response, "the engine", "unknown")
    assert "CYBERENGINE_URL" not in response.content.decode()


@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("fault", ["will not import", "speaks another word for unknown"])
def test_mythos_core_down_is_degraded(engine, fault):
    real = readiness.importlib.import_module

    def importing(name, *args, **kwargs):
        if fault == "will not import" and name == "mythos_core.failsafe":
            raise ImportError("No module named 'mythos_core.failsafe'")
        module = real(name, *args, **kwargs)
        if fault == "speaks another word for unknown" and name == "mythos_core.status":
            return mock.Mock(UNKNOWN="UNKNOWN")
        return module

    with mock.patch.object(readiness.importlib, "import_module", importing):
        response, _took = _ask(engine())
    _not_ready(response, "Mythos-Core", "degraded")


# --- Each dependency hung: answered inside the bound, unknown ---------------------------


def _hanging_database(release):
    def hang(*_args, **_kwargs):
        release.wait(HELD_SECONDS)
        raise OperationalError("canceling statement due to statement timeout")

    return mock.patch.multiple(CursorWrapper, execute=hang, executemany=hang)


@pytest.mark.django_db(transaction=True)
def test_a_hung_database_is_unknown_inside_the_bound(engine, release):
    client = engine()
    with _hanging_database(release):
        response, took = _ask(client)
    assert took < BOUND + 1.0, took
    _not_ready(response, "the database", "unknown")
    assert "did not answer within" in _reading(response, "the database")["reason"]
    assert _reading(response, "the engine")["status"] == "ok"


@pytest.mark.django_db(transaction=True)
def test_a_hung_engine_is_unknown_inside_the_bound(engine):
    response, took = _ask(engine(delay=HELD_SECONDS))
    assert took < BOUND + 1.0, took
    _not_ready(response, "the engine", "unknown")
    assert _reading(response, "the database")["status"] == "ok"


@pytest.mark.django_db(transaction=True)
def test_a_hung_mythos_core_is_unknown_inside_the_bound(engine, release):
    real = readiness.importlib.import_module

    def importing(name, *args, **kwargs):
        if name == "mythos_core.http":
            release.wait(HELD_SECONDS)
        return real(name, *args, **kwargs)

    with mock.patch.object(readiness.importlib, "import_module", importing):
        response, took = _ask(engine())
    assert took < BOUND + 1.0, took
    _not_ready(response, "Mythos-Core", "unknown")


@pytest.mark.django_db(transaction=True)
def test_a_hung_dependency_is_asked_once_however_often_the_probe_polls(engine, release):
    """A probe polled while a dependency hangs waits on the check already in flight: one
    thread held, not one per poll. Asked afresh once that check answers."""
    asked = []
    real = readiness.CHECKS["the database"]

    def counted():
        asked.append(1)
        release.wait(HELD_SECONDS)
        return real()

    client = engine()
    with mock.patch.dict(readiness.CHECKS, {"the database": counted}):
        for _ in range(3):
            response, took = _ask(client)
            assert took < BOUND + 1.0, took
            assert _reading(response, "the database")["status"] == "unknown"
        assert len(asked) == 1
        release.set()
        deadline = time.monotonic() + 5
        while "the database" in readiness._inflight and time.monotonic() < deadline:
            time.sleep(0.01)
        response, _took = _ask(client)
    assert len(asked) == 2
    assert response.status_code == 200, response.content


# --- Never on a stop's path ---------------------------------------------------------------


def test_readiness_is_a_read_and_not_a_stop():
    assert degraded.class_of("readiness", "GET") == degraded.EVIDENCE_READ
    assert "readiness" not in stops.EXEMPT_ROUTES
    assert "readiness" in stops.NOT_STOPS


def test_the_words_are_the_existing_ones():
    from assurance.coverage import CHECK_DEGRADED

    assert readiness.UNKNOWN == core_status.UNKNOWN
    assert readiness.DEGRADED == CHECK_DEGRADED
    assert readiness.OK == "ok"


def test_nothing_but_the_root_urlconf_imports_readiness():
    """No stop, gate or control reads what readiness answers."""
    importers = []
    for path in sorted(ROOT.rglob("*.py")):
        rel = path.relative_to(ROOT)
        if rel.parts[0] in {"tests", "frontend", "node_modules"} or "settings" in path.name.lower():
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.ImportFrom):
                names = [f"{node.module or ''}.{a.name}" for a in node.names] + [node.module or ""]
                if node.level and rel.parts[0] == "config":
                    names += [f"config.{node.module}" if node.module else "config"]
                    names += [f"config.{a.name}" for a in node.names]
            elif isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            if any(n == "config.readiness" or n.startswith("config.readiness.") for n in names):
                importers.append(rel.as_posix())
    assert sorted(set(importers)) == ["config/urls.py"]


def test_readiness_is_routed_beside_liveness_under_the_gateways_skip():
    from django.urls import resolve

    from audit.middleware import SKIP_PREFIXES

    assert resolve(READY).url_name == "readiness"
    assert resolve("/api/health/").url_name == "health"
    assert READY.startswith(SKIP_PREFIXES)
