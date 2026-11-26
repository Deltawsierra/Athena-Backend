"""Readiness never waits on a slow engine, and a probe flood costs one check a second (AB-DEADVIEW).

``GET /api/health/ready/`` (config.readiness) answers within its 2 s bound. Its engine
check asked the engine's ``/health`` under the client's ENGINE_TIMEOUT -- a scan's
timeout, 60 s to read by default -- so a hung engine held the check's thread for a
minute, and every probe in that minute read "did not answer" from a check still
waiting. The check now has its own short timeout (``HEALTH_TIMEOUT``), never the
long one: against a hung engine it ends, ``unknown``, well inside the bound, and
holds nothing.

And a finished check's reading is served again for ``CACHE_SECONDS`` (1 s), counted
from when the check was asked: a flood of probes costs at most one check per
dependency per second, and no ``ok`` is ever served older than that -- not after
the second is up, not counted from the answer instead of the ask, and not after a
probe waited on a slow check while it held a cached one.

And a probe that starts just inside a reading's second and builds its answer once
the second is up asks again, inside its bound: a dependency that answers is never
read ``unknown`` because the probe's own clock moved on (the flood test met exactly
that on Windows, once: one probe of the flood answered 503 from a ready backend).
"""

from __future__ import annotations

import http.server
import threading
import time
from unittest import mock

import pytest
import requests
from django.db import OperationalError
from django.db.backends.utils import CursorWrapper

from ai_engine.services import cyberengine_client
from config import readiness
from tests.test_readiness_names_each_dependency import _ask, _client, _Health, _reading

#: The client's long default, named here so the test does not depend on settings: a
#: scan's connect and read timeouts.
LONG = (3.05, 60.0)
#: How long a hung engine holds a request before the test releases it.
HELD_SECONDS = 30.0


@pytest.fixture(autouse=True)
def _fresh():
    readiness.forget_inflight()
    with mock.patch.object(cyberengine_client, "ENGINE_TIMEOUT", LONG):
        yield
    readiness.forget_inflight()


@pytest.fixture()
def engine():
    """engine(hung=False) -> a real client whose engine answers ``{"status": "ok"}``, or
    reads the request and never answers until the test ends."""
    servers = []
    release = threading.Event()

    def start(*, hung=False):
        attrs = {}
        if hung:
            def do_GET(self):  # noqa: N802 - the stdlib's name
                release.wait(HELD_SECONDS)

            attrs["do_GET"] = do_GET
        handler = type("Engine", (_Health,), attrs)
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return _client(f"http://127.0.0.1:{server.server_address[1]}")

    yield start
    release.set()
    for server in servers:
        server.shutdown()
        server.server_close()


def _no_ok_older_than_the_cache(response):
    for name, reading in response.json()["dependencies"].items():
        if reading["status"] == "ok":
            assert reading["age_seconds"] < readiness.CACHE_SECONDS, (name, reading)


# --- The engine's check has its own short timeout ----------------------------------------


def test_the_health_check_has_its_own_timeout_well_inside_the_bound():
    timeout = cyberengine_client.HEALTH_TIMEOUT
    assert timeout != cyberengine_client.ENGINE_TIMEOUT
    assert sum(timeout) <= 0.75 * readiness.DEADLINE_SECONDS


def test_the_health_check_never_inherits_the_engine_clients_timeout(engine):
    client = engine()
    sent = []
    real = cyberengine_client.outbound.get

    def recording(url, **kwargs):
        sent.append(kwargs.get("timeout"))
        return real(url, **kwargs)

    with mock.patch.object(cyberengine_client.outbound, "get", recording):
        assert client.health() == {"status": "ok"}
    assert sent == [cyberengine_client.HEALTH_TIMEOUT]


def test_a_hung_engines_health_check_ends_inside_the_bound(engine):
    """Against an engine that reads the request and never answers, the check fails as
    a timeout inside the readiness bound, under the client's 60 s read timeout."""
    client = engine(hung=True)
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
    assert not thread.is_alive(), f"the health check still waits after {readiness.DEADLINE_SECONDS:g} s"
    assert "answer" not in outcome
    assert isinstance(outcome["error"].__cause__, requests.Timeout), outcome
    assert outcome["took"] < readiness.DEADLINE_SECONDS


@pytest.mark.django_db(transaction=True)
def test_readiness_against_a_hung_engine_answers_well_inside_its_bound(engine):
    """At readiness's real 2 s bound: the answer comes before it, the engine reads
    ``unknown`` because its own check ran out (not because the answer stopped
    waiting), and no check is left holding a thread."""
    response, took = _ask(engine(hung=True))
    assert took < readiness.DEADLINE_SECONDS, took
    assert response.status_code == 503, response.content
    engine_reading = _reading(response, "the engine")
    assert engine_reading["status"] == "unknown", engine_reading
    assert "did not answer /health within its own" in engine_reading["reason"], engine_reading
    assert _reading(response, "the database")["status"] == "ok"
    assert "the engine" not in readiness._inflight


@pytest.mark.parametrize(
    ("cause", "state"),
    [
        (requests.ReadTimeout("read timed out"), "unknown"),
        (requests.ConnectTimeout("connect timed out"), "unknown"),
        (requests.ConnectionError("connection refused"), "degraded"),
    ],
)
def test_only_a_timeout_reads_as_no_answer(cause, state):
    """An engine that did not answer in time is ``unknown``; one that refused answered,
    and its answer was a failure: ``degraded``, as before."""
    client = mock.Mock()
    error = cyberengine_client.EngineError("Engine unreachable", kind=cyberengine_client.ENGINE_UNREACHABLE)
    error.__cause__ = cause
    client.health.side_effect = error
    with mock.patch.object(cyberengine_client.CyberEngineClient, "from_settings", return_value=client):
        future = readiness.Future()
        readiness._run("the engine", readiness._engine, future)
    assert readiness._reading(future, 0.0, 0.0, 0.0)[0] == state


# --- The answer, cached for one second from the ask ------------------------------------------


def _counted(asks):
    """CHECKS with each check counted: name -> the monotonic times it was asked."""
    wrapped = {}
    for name, check in readiness.CHECKS.items():
        def counted(name=name, check=check):
            asks.setdefault(name, []).append(time.monotonic())
            return check()

        wrapped[name] = counted
    return wrapped


@pytest.mark.django_db(transaction=True)
def test_a_probe_flood_costs_at_most_one_check_per_dependency_per_second(engine):
    client = engine()
    asks = {}
    with mock.patch.dict(readiness.CHECKS, _counted(asks)):
        probes = 0
        started = time.monotonic()
        while probes < 10 or time.monotonic() - started < 1.5:
            response, _took = _ask(client)
            assert response.status_code == 200, response.content
            _no_ok_older_than_the_cache(response)
            probes += 1
    for name, times in asks.items():
        assert len(times) < probes, (name, len(times), probes)
        gaps = [later - earlier for earlier, later in zip(times, times[1:])]
        # The check's own clock starts a moment after the ask's, on its thread.
        assert all(gap > readiness.CACHE_SECONDS - 0.1 for gap in gaps), (name, gaps)
    assert set(asks) == set(readiness.CHECKS)


def _database_refuses():
    def refused(*_args, **_kwargs):
        raise OperationalError("the database is unavailable")

    return mock.patch.multiple(CursorWrapper, execute=refused, executemany=refused)


@pytest.mark.django_db(transaction=True)
def test_no_ok_is_served_once_its_second_is_up(engine):
    """Inside its second a cached ok is served (that is the cache); once the second is
    up the dependency is asked again, and a database that has gone down says so."""
    client = engine()
    before = time.monotonic()
    first, _took = _ask(client)
    assert first.status_code == 200, first.content
    with _database_refuses():
        within, _took = _ask(client)
        if time.monotonic() - before < readiness.CACHE_SECONDS:
            assert within.status_code == 200, within.content
        _no_ok_older_than_the_cache(within)
        time.sleep(max(0.0, before + readiness.CACHE_SECONDS + 0.05 - time.monotonic()))
        after, _took = _ask(client)
    assert after.status_code == 503, after.content
    assert _reading(after, "the database")["status"] == "degraded"
    _no_ok_older_than_the_cache(after)


@pytest.mark.django_db(transaction=True)
def test_a_readings_age_is_counted_from_the_ask_not_the_answer(engine):
    """A check that took 0.6 s to answer ok: 1.05 s after it was asked -- 0.45 s after
    it answered -- its ok is not served again."""
    client = engine()
    real = readiness.CHECKS["the database"]
    asked = []

    def slow():
        asked.append(time.monotonic())
        time.sleep(0.6)
        return real()

    with mock.patch.dict(readiness.CHECKS, {"the database": slow}):
        first, _took = _ask(client)
        assert first.status_code == 200, first.content
        with _database_refuses():
            time.sleep(max(0.0, asked[0] + readiness.CACHE_SECONDS + 0.05 - time.monotonic()))
            second, _took = _ask(client)
    assert len(asked) == 2
    assert second.status_code == 503, second.content
    assert _reading(second, "the database")["status"] == "degraded"
    _no_ok_older_than_the_cache(second)


@pytest.mark.django_db(transaction=True)
def test_a_cached_ok_that_ages_while_a_probe_waits_is_asked_again_not_served_stale(engine):
    """The engine's check in flight, the database's ok cached: while the probe waits on
    the engine, the database's second runs out, and it is asked again then -- a second
    after it was last asked, not before -- and the new check's reading is served (with
    its own age), never the cached ok."""
    client = engine()
    release = threading.Event()
    asks = {}
    counted = _counted(asks)

    def hung():
        release.wait(HELD_SECONDS)
        return counted["the engine"]()

    try:
        with mock.patch.dict(readiness.CHECKS, {**counted, "the engine": hung}):
            with mock.patch.object(readiness, "DEADLINE_SECONDS", 0.2):
                first, _took = _ask(client)
            assert _reading(first, "the database")["status"] == "ok"
            second, took = _ask(client)
    finally:
        release.set()
    assert took < readiness.DEADLINE_SECONDS + 1.0, took
    answered = time.monotonic()
    database = _reading(second, "the database")
    assert database["status"] == "ok", database
    assert len(asks["the database"]) == 2, asks
    gap = asks["the database"][1] - asks["the database"][0]
    assert gap > readiness.CACHE_SECONDS - 0.1, gap
    # The reading served is the second check's, not the first's cached ok.
    assert database["age_seconds"] < answered - asks["the database"][0] - readiness.CACHE_SECONDS + 0.1, database
    assert _reading(second, "the engine")["status"] == "unknown"


# --- A reading whose second is up as the answer is built -------------------------------------


class _Clock:
    """What config.readiness reads the time from, scripted: each reading of it is the
    next instant listed, and the last one listed from then on."""

    def __init__(self, *instants):
        self.instants = list(instants)

    def monotonic(self):
        return self.instants.pop(0) if len(self.instants) > 1 else self.instants[0]


#: When, on the scripted clock, the first probe asks every dependency.
ASKED = 100.0
#: When the second probe starts: 1 ms inside the second its cached readings are served for.
INSIDE = ASKED + readiness.CACHE_SECONDS - 0.001


@pytest.mark.parametrize(
    ("later", "asked_again"),
    [
        # The second is up between the probe's start and the moment its answer is built.
        ([ASKED + readiness.CACHE_SECONDS + 0.001], True),
        # It is up only after that moment: the answer is built from readings still fresh.
        ([ASKED + readiness.CACHE_SECONDS - 0.0005, ASKED + readiness.CACHE_SECONDS + 0.001], False),
    ],
)
@pytest.mark.django_db(transaction=True)
def test_a_cached_ok_whose_second_is_up_as_the_answer_is_built_is_asked_again(engine, later, asked_again):
    """A probe starts 1 ms inside its cached readings' second, with no check to wait on,
    and builds its answer 2 ms later, once the second is up. Every dependency answers,
    so the probe asks each again inside its bound and says ready from the new readings:
    never ``unknown`` because its own clock moved on, and never the aged ``ok``. A probe
    whose answer is built before the second is up serves what it holds and asks nothing."""
    client = engine()
    asks = {}
    clock = _Clock(ASKED)
    with mock.patch.dict(readiness.CHECKS, _counted(asks)), mock.patch.object(readiness, "time", clock):
        first, _took = _ask(client)
        assert first.status_code == 200, first.content
        clock.instants = [INSIDE, *later]
        second, _took = _ask(client)
    assert second.status_code == 200, second.content
    _no_ok_older_than_the_cache(second)
    for name in readiness.CHECKS:
        assert len(asks[name]) == (2 if asked_again else 1), (name, asks)
        if asked_again:
            # The reading served is the second check's own, asked as the answer was built.
            assert _reading(second, name)["age_seconds"] == 0.0, (name, second.content)


@pytest.mark.django_db(transaction=True)
def test_a_cached_ok_whose_second_is_up_only_past_the_bound_is_not_asked_again(engine):
    """The same probe, held so long that its answer is built when its whole bound is
    spent: nothing is asked past the bound, and the readings, now older than their
    second, read ``unknown`` -- never the ``ok`` they were."""
    client = engine()
    asks = {}
    clock = _Clock(ASKED)
    with mock.patch.dict(readiness.CHECKS, _counted(asks)), mock.patch.object(readiness, "time", clock):
        first, _took = _ask(client)
        assert first.status_code == 200, first.content
        clock.instants = [INSIDE, INSIDE + readiness.DEADLINE_SECONDS]
        second, _took = _ask(client)
    assert second.status_code == 503, second.content
    for name in readiness.CHECKS:
        assert len(asks[name]) == 1, (name, asks)
        reading = _reading(second, name)
        assert reading["status"] == "unknown", (name, reading)
        assert "past the" in reading["reason"], (name, reading)


@pytest.mark.parametrize("state", ["ok", "degraded"])
def test_a_cached_reading_past_its_second_is_never_served_as_it_was(state):
    """However the answer came to be built late (a busy scheduler between the wait and
    the answer), a cached reading past its second reads ``unknown``, never ``ok``."""
    reading = {"status": state, "reason": "answered"}
    now = 100.0
    assert readiness._from_cache(reading, now - readiness.CACHE_SECONDS + 0.01, now) == reading
    for age in (readiness.CACHE_SECONDS, readiness.CACHE_SECONDS + 0.5, 60.0):
        served = readiness._from_cache(reading, now - age, now)
        assert served["status"] == "unknown", (age, served)
        assert "past the" in served["reason"]
