"""Athena-Backend's binding of the shared tracing vocabulary.

`mythos_core.tracing` holds the span names and attribute keys; this holds the two
things that cannot live in a shared package:

**The engine name, spelled once.** Every span carries ``mythos.engine =
"athena-backend"``. It is named apart from the scanning engine (``athena``)
deliberately: a deployment assessment crosses both, and folding them into one
component would make "the assessment spent eight seconds in Athena" unanswerable
as to *which* Athena.

**One process-wide latency record.** :class:`mythos_core.tracing.Timings` is a
plain object, so a per-call instance would record into something discarded
immediately afterwards. Under a WSGI server this is per worker process, which is
the right granularity: a p95 mixed across workers would hide a single slow one.

Nothing here reaches the network. With the ``otel`` extra uninstalled -- the state
in CI and in every deployment today -- every span is a no-op that allocates
nothing, and the latency table is still produced.
"""

from __future__ import annotations

import os
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from typing import Any

from mythos_core import tracing
from mythos_core.tracing import (  # re-exported so call sites need one import
    EXECUTE_TOOL,
    GEN_AI_TOOL_NAME,
    INVOKE_WORKFLOW,
    MYTHOS_VERDICT,
    PLAN,
    RETRIEVAL,
)

__all__ = [
    "ENGINE",
    "EXECUTE_TOOL",
    "GEN_AI_TOOL_NAME",
    "INVOKE_WORKFLOW",
    "MYTHOS_VERDICT",
    "PLAN",
    "RETRIEVAL",
    "configure",
    "latency_table",
    "reset_timings",
    "span",
    "status",
]

#: The value of ``mythos.engine`` on every span this service emits.
ENGINE = "athena-backend"

#: The process-wide latency record. See the module docstring for why it is state.
TIMINGS = tracing.Timings()


@contextmanager
def span(
    name: str,
    *,
    subject: str = "",
    attributes: Mapping[str, Any] | None = None,
    component: str | None = None,
) -> Iterator[Any]:
    """One span, timed into :data:`TIMINGS`.

    ``name`` is the shared span name a collector groups by. ``component`` is the
    row it lands on in the latency table, prefixed with the engine name here
    rather than at the call site -- so a row can never be filed under a misspelled
    engine. Pass one wherever a single span name covers work a reader would change
    separately: claim derivation, invalidation and the ripple traversal are all
    ``plan``, and one ``plan`` row averaging them names nothing to go and fix.

    Yields the underlying span when one exists and ``None`` otherwise, so a caller
    must treat the yielded value as optional.

    An exception that leaves the block is recorded on the span by its type
    alone, then raised on unchanged and at once. Left to the OpenTelemetry SDK it
    is recorded whole -- its message and stack trace as an ``exception`` event,
    the message again as the status description, a chained cause's text in the
    trace -- and an exception raised while deriving a deployment's claims can
    quote what it was reading: a finding's location, a deployment's name, an
    engine answer's excerpt. A span leaves the assessment's trust boundary (the
    subject is the deployment's primary key for that reason), so it says what
    failed and nothing the exception says. The caller still gets the exception,
    whole.
    """
    escaped: Exception | None = None
    try:
        with tracing.span(
            name,
            engine=ENGINE,
            subject=subject,
            attributes=attributes,
            timings=TIMINGS,
            component=f"{ENGINE}.{component}" if component else None,
        ) as active:
            try:
                yield active
            except Exception as exc:  # noqa: BLE001 - raised unchanged once the span closes
                escaped = exc
                # Telemetry never replaces what it records: the exception may be a
                # stop, and a stop must reach its caller as itself.
                with suppress(Exception):
                    _failed(active, exc)
    except Exception:  # noqa: BLE001 - the block's own exception outranks the span's
        # Ending the span raised (an exporter, a processor). With the block's
        # exception in hand, that one is what the caller gets: a span that
        # cannot be ended never replaces a stop.
        if escaped is None:
            raise
    if escaped is not None:
        raise escaped


def _failed(active: Any, exc: Exception) -> None:
    """Mark ``active`` failed, naming the exception's type and nothing it says.

    ``error.type`` is the OpenTelemetry convention for exactly this, and the
    ERROR status carries the class name where the SDK would put the message.
    """
    if active is None:
        return
    kind = type(exc)
    name = kind.__qualname__
    if kind.__module__ not in (None, "builtins"):
        name = f"{kind.__module__}.{name}"
    active.set_attribute("error.type", name)
    try:
        from opentelemetry.trace import Status, StatusCode
    except ImportError:  # a span object without the API installed: no status type
        return
    active.set_status(Status(StatusCode.ERROR, kind.__name__))


def configure(endpoint: str | None = None) -> bool:
    """Wire up an exporter if one is configured. Returns whether spans export."""
    service = os.environ.get(tracing.SERVICE_NAME_VARIABLE) or ENGINE
    return tracing.configure(service, endpoint=endpoint)


def status() -> dict[str, Any]:
    """What the tracing layer can honestly say about itself."""
    return tracing.tracing_status()


def latency_table() -> list[dict[str, Any]]:
    """One row per component: count, p50, p95, min, max in milliseconds."""
    return TIMINGS.table()


def reset_timings() -> None:
    """Drop every recorded sample, in place.

    For a harness taking a fresh baseline, and for tests that must not read
    another test's samples. Never called from a request path: a request that
    silently cleared the record would make the table depend on which request
    happened to arrive last.

    In place, not by rebinding the global, and the difference is not cosmetic.
    ``span()`` reads ``TIMINGS`` when it is entered and hands *that object* to
    ``tracing.span``, which records in its ``finally``. Rebinding between entry
    and exit sends the sample into an orphan -- and it does so selectively: a
    span longer than the interval between resets can never survive, so the
    reset destroys exactly the slow work a p95 exists to find. Measured on the
    baseline harness, an outer workflow span was lost while all of its children
    survived, publishing a table with one assessment and five of its own steps.
    Clearing under the lock keeps every in-flight span pointed at a live object.
    """
    with TIMINGS._lock:  # noqa: SLF001 - the recorder's own lock, by design
        TIMINGS.samples.clear()
        # The companion total arrives with the bounded recorder in a later
        # mythos-core; clearing it here is a no-op against the current pin and
        # keeps the total honest the moment this repo is repinned, rather than
        # leaving a row that reports a lifetime count against a cleared window.
        getattr(TIMINGS, "recorded", {}).clear()
