"""Readiness: whether what this backend depends on answers, each dependency named.

``GET /api/health/`` is liveness and stays exactly that: it answers ``ok`` at once
from this process, whatever is down, so a load balancer never restarts a backend
for an outage that is not its own. It says nothing about the database, the engine
or Mythos-Core. ``GET /api/health/ready/`` is readiness: one bounded check per
dependency, each named, each with its state and the reason for it.

The dependencies, as safety.degraded names them:

* ``the database`` -- ``SELECT 1`` on a connection of the check's own, and the
  row read back must be the row asked for.
* ``the engine`` -- the engine's own ``GET /health``, whose contract is a 200 and
  ``{"status": "ok"}`` (tests/test_engine_contract.py).
* ``Mythos-Core`` -- the modules this backend loads import, and its status
  vocabulary still spells ``unknown`` the way safety.degraded spells it.

Each reads one of three states:

* ``ok`` -- it answered, and the answer was the one asked for;
* ``degraded`` -- it answered, and the answer was a failure: it refused, raised,
  or answered something that is not the answer (``assurance.coverage``'s word for
  a check that ran and could not do its whole job);
* ``unknown`` -- nothing was established: it did not answer inside the bound, or
  there is nothing configured to ask (Mythos-Core's ``status.UNKNOWN``).

Bounded. Every check runs on a daemon thread of its own, and the answer waits at
most :data:`DEADLINE_SECONDS` for all of them together; a check still running
then reads ``unknown``, saying how long it has been asked. A check still running
from an earlier probe is waited on again, never started a second time, so a hung
dependency holds one thread however often the probe is polled.

Never on a stop's path. It is a read (safety.degraded: evidence_read; safety.stops:
not a stop). Nothing imports this module but the root URLconf, and no stop, gate or
control reads what it answers: a dependency that is down makes this answer say so,
and changes what nothing else does.

Every reason is named by the exception's type (and an engine failure's kind and
HTTP status), never by its message: a message can carry a host, a query or a
credential, and this route answers anyone.

The answer: 200 with ``status: "ok"`` when every dependency is ``ok``; otherwise
503, in safety.degraded's shape for an evidence read (``detail``, ``status:
"unknown"``, ``operation_class``, ``dependency`` -- the first dependency not ok),
because whether this backend can serve is then not established. Both carry
``dependencies`` -- each name with its ``status`` and ``reason`` -- and
``not_probed``, the dependencies no bounded check here can ask, with why.
"""

from __future__ import annotations

import importlib
import threading
import time
from concurrent.futures import Future, wait

from rest_framework.decorators import api_view, permission_classes, throttle_classes
from rest_framework.permissions import AllowAny
from rest_framework.response import Response

from safety import degraded

#: ``ok``: the dependency answered, and the answer was the one asked for. The word
#: the liveness probe and the engine's own ``/health`` answer in.
OK = "ok"
#: ``assurance.coverage.CHECK_DEGRADED``: it answered, and the answer was a failure.
DEGRADED = "degraded"
#: ``mythos_core.status.UNKNOWN``: nothing was established.
UNKNOWN = degraded.UNKNOWN

#: How long one readiness answer waits for every check together. A probe that hangs
#: on the dependency it is meant to report is how a load balancer marks a backend
#: down for its own timeout rather than for the reason.
DEADLINE_SECONDS = 2.0

DATABASE = "the database"
ENGINE = "the engine"
MYTHOS_CORE = "Mythos-Core"

#: The Mythos-Core modules this backend loads: the status vocabulary, and the two the
#: stop paths import at start (the Windows job's import smoke names the same two).
MYTHOS_CORE_MODULES = ("mythos_core.status", "mythos_core.http", "mythos_core.failsafe")

#: What this backend depends on that no bounded check here can ask, and why.
NOT_PROBED = {
    "connectors": (
        "configured per deployment, not for this backend: each deployment's connector and "
        "posture routes read them, and a push that cannot reach one is recorded failed or "
        "unknown and held"
    ),
    "the receipt signer": (
        "the engine's signing route signs what it is sent, so asking it would sign something; "
        "a receipt that could not be signed says it is unsigned"
    ),
}


class _Answer(Exception):
    """A dependency answered, and its answer was a failure: ``degraded``, with why."""


def _database():
    from django.db import connection

    with connection.cursor() as cursor:
        cursor.execute("SELECT 1")
        row = cursor.fetchone()
    if tuple(row or ()) != (1,):
        raise _Answer("answered SELECT 1 with a row that is not the row asked for")
    return "answered SELECT 1"


def _engine():
    from ai_engine.services.cyberengine_client import CyberEngineClient

    try:
        client = CyberEngineClient.from_settings()
    except RuntimeError:
        return None  # nothing configured to ask
    answer = client.health()
    if not isinstance(answer, dict) or answer.get("status") != OK:
        raise _Answer('answered /health, but not {"status": "ok"}')
    return 'answered /health {"status": "ok"}'


def _mythos_core():
    for name in MYTHOS_CORE_MODULES:
        importlib.import_module(name)
    status = importlib.import_module("mythos_core.status")
    if getattr(status, "UNKNOWN", None) != UNKNOWN:
        raise _Answer("its status vocabulary no longer spells unknown as this backend does")
    return f"imports {', '.join(MYTHOS_CORE_MODULES)}"


#: Each dependency and its check, in the order they are reported: the first that is
#: not ok is the ``dependency`` a not-ready answer names.
CHECKS = {
    DATABASE: _database,
    ENGINE: _engine,
    MYTHOS_CORE: _mythos_core,
}

_lock = threading.Lock()
#: name -> (future, monotonic time it was asked): the check in flight for each dependency.
_inflight: dict[str, tuple[Future, float]] = {}


def _run(name, check, future):
    try:
        future.set_result(check())
    except BaseException as exc:  # noqa: BLE001 - whatever a check raises is its answer, recorded, never lost
        future.set_exception(exc)
    finally:
        with _lock:
            if _inflight.get(name, (None,))[0] is future:
                del _inflight[name]
        if name == DATABASE:
            from django.db import connections

            connections.close_all()  # this thread's own connection, and only it


def _asked(name, check):
    """The check in flight for ``name``, started only if none is."""
    with _lock:
        running = _inflight.get(name)
        if running is not None:
            return running
        future = Future()
        running = _inflight[name] = (future, time.monotonic())
    threading.Thread(target=_run, args=(name, check, future), daemon=True, name=f"readiness: {name}").start()
    return running


def _reading(future, asked_at, now):
    if not future.done():
        return UNKNOWN, (
            f"did not answer within {DEADLINE_SECONDS:g} s (asked {now - asked_at:.1f} s ago); "
            "nothing is established about it"
        )
    exc = future.exception()
    if exc is None:
        said = future.result()
        if said is None:
            return UNKNOWN, "nothing is configured to ask, so nothing is established about it"
        return OK, said
    if isinstance(exc, _Answer):
        return DEGRADED, str(exc)
    kind = getattr(exc, "kind", None)
    http_status = getattr(exc, "status", None)
    if isinstance(kind, str):
        said = f"{type(exc).__name__}: {kind}" + (f", HTTP {http_status}" if isinstance(http_status, int) else "")
    else:
        said = type(exc).__name__
    return DEGRADED, f"failed ({said})"


def check_all():
    """Every dependency's reading: {name: {"status", "reason"}}, in :data:`CHECKS` order,
    within :data:`DEADLINE_SECONDS` however the dependencies answer."""
    asked = {name: _asked(name, check) for name, check in CHECKS.items()}
    wait([future for future, _at in asked.values()], timeout=DEADLINE_SECONDS)
    now = time.monotonic()
    readings = {}
    for name, (future, asked_at) in asked.items():
        state, reason = _reading(future, asked_at, now)
        readings[name] = {"status": state, "reason": reason}
    return readings


@api_view(["GET"])
@permission_classes([AllowAny])
# Polled as often as liveness is, by the same load balancer: the default anonymous
# throttle would answer 429, which reads as an outage. A flood of probes cannot fan
# out either: each dependency has at most one check in flight (`_asked`).
@throttle_classes([])
def readiness(request):
    """Whether every dependency answers; each named with its state and why."""
    readings = check_all()
    not_ok = [name for name, reading in readings.items() if reading["status"] != OK]
    if not not_ok:
        return Response(
            {
                "status": OK,
                "operation_class": degraded.EVIDENCE_READ,
                "detail": "Ready: every dependency answered as asked.",
                "dependencies": readings,
                "not_probed": NOT_PROBED,
            }
        )
    said = "; ".join(f"{name} is {readings[name]['status']}: {readings[name]['reason']}" for name in not_ok)
    return Response(
        {
            "detail": f"Not ready, so whether this backend can serve is unknown: {said}.",
            "status": degraded.POLICY[degraded.EVIDENCE_READ]["status"],
            "operation_class": degraded.EVIDENCE_READ,
            "dependency": not_ok[0],
            "dependencies": readings,
            "not_probed": NOT_PROBED,
        },
        status=503,
    )


def forget_inflight():
    """For tests: forget every check in flight, so the next probe asks afresh. A check
    still running finishes on its own thread, and its answer goes nowhere."""
    with _lock:
        _inflight.clear()
