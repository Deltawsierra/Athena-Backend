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
from contextlib import contextmanager
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
    """
    with tracing.span(
        name,
        engine=ENGINE,
        subject=subject,
        attributes=attributes,
        timings=TIMINGS,
        component=f"{ENGINE}.{component}" if component else None,
    ) as active:
        yield active


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
    """Drop every recorded sample.

    For a harness taking a fresh baseline, and for tests that must not read
    another test's samples. Never called from a request path: a request that
    silently cleared the record would make the table depend on which request
    happened to arrive last.
    """
    global TIMINGS
    TIMINGS = tracing.Timings()
