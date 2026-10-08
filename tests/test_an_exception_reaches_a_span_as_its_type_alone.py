"""An exception that leaves one of this service's spans reaches it as its type alone.

GHSA-4x9p-g9wm-8q7f (Pydantic AI, fixed in 1.107.6 and 2.44.0): with content kept
out of exported telemetry, an exception was still recorded with its message and
stack trace as an event, the SDK described the span's ERROR status with the
message again, and the error that ended a run after its retries carried every
chained cause's text. Pydantic AI is not a dependency of this service
(advisories.toml); this is the same channel on its own spans.

``assurance.observability.span`` called ``mythos_core.tracing.span`` with the
OpenTelemetry SDK's defaults, so an exception raised while deriving a deployment's
claims -- one that quotes what it was reading, a finding's location or a
deployment's name -- went to the collector whole, while the span's own attributes
carry the deployment's primary key and nothing identifying
(tests/test_assurance_tracing.py). It now records ``error.type`` and the class
name as the status, and raises the exception on unchanged.

The tracer below behaves as the SDK's does through ``use_span``: an exception that
passes out through ``start_as_current_span`` is recorded whole, and sets an ERROR
status described as ``"<type>: <message>"``. Nothing is exported.
"""

from __future__ import annotations

import secrets
import sys
import traceback
import types
from contextlib import contextmanager

import pytest

from assurance import observability as obs
from tests.test_assurance_tracing import _deployment

pytestmark = pytest.mark.django_db


class _Span:
    def __init__(self, name, attributes):
        self.name = name
        self.attributes = dict(attributes or {})
        self.events = []
        self.status = None

    def set_attribute(self, key, value):
        self.attributes[key] = value

    def set_status(self, status, description=None):
        self.status = (str(getattr(status, "status_code", status)), getattr(status, "description", description))

    def record_exception(self, exc):
        self.events.append(
            {
                "name": "exception",
                "exception.message": str(exc),
                "exception.stacktrace": "".join(traceback.format_exception(exc)),
            }
        )


class _SDKLikeTrace:
    def __init__(self):
        self.spans = []

    def get_tracer(self, *_args, **_kwargs):
        return self

    @contextmanager
    def start_as_current_span(self, name, attributes=None, **_kwargs):
        span = _Span(name, attributes)
        self.spans.append(span)
        try:
            yield span
        except Exception as exc:
            span.record_exception(exc)
            span.set_status("ERROR", f"{type(exc).__name__}: {exc}")
            raise


class _StatusCode:
    """The OpenTelemetry API's StatusCode, as far as a span here reads it."""

    UNSET = "UNSET"
    OK = "OK"
    ERROR = "ERROR"


class _Status:
    def __init__(self, status_code, description=None):
        self.status_code = status_code
        self.description = description


@pytest.fixture(autouse=True)
def opentelemetry_status(monkeypatch):
    """The API's Status and StatusCode, always: this service installs no
    OpenTelemetry, and without the API a span sets no status at all -- so a test
    that accepted that could not see a status that carried the exception's
    message (review round 1, L1)."""
    api = types.ModuleType("opentelemetry")
    trace = types.ModuleType("opentelemetry.trace")
    trace.Status = _Status
    trace.StatusCode = _StatusCode
    api.trace = trace
    monkeypatch.setitem(sys.modules, "opentelemetry", api)
    monkeypatch.setitem(sys.modules, "opentelemetry.trace", trace)


@pytest.fixture()
def recorded(monkeypatch):
    from mythos_core import tracing

    trace = _SDKLikeTrace()
    monkeypatch.setattr(tracing, "_otel_trace", lambda: trace)
    return trace


class Unassessable(Exception):
    """An exception of this service's own kind, as a derivation step might raise."""


def _value_error(location, name):
    try:
        raise KeyError(f"finding at {location} has no severity")
    except KeyError as first:
        raise ValueError(f"cannot assess {name}: {first}") from first


def _key_error(location, name):
    raise KeyError(f"cannot assess {name}: finding at {location} has no severity")


def _own_error(location, name):
    try:
        raise OSError(f"{location} could not be read")
    except OSError as first:
        raise Unassessable(f"cannot assess {name}: {first}") from first


@pytest.mark.parametrize(
    "raising, kind, error_type",
    [
        (_value_error, ValueError, "ValueError"),
        # Review round 1, L2: not only a ValueError.
        (_key_error, KeyError, "KeyError"),
        (_own_error, Unassessable, f"{__name__}.Unassessable"),
    ],
    ids=["ValueError", "KeyError", "an exception of its own"],
)
def test_a_derivation_that_fails_leaves_its_span_as_one_type(
    recorded, monkeypatch, raising, kind, error_type
):
    """Deriving a deployment's claims fails with an exception quoting what it was
    reading, chained from the failure before it: the span says which exception,
    and nothing it or its cause says."""
    import assurance.claims as claims

    location = "/internal/" + secrets.token_hex(8)
    name = "cnrydeployment" + secrets.token_hex(8)

    def unreadable(deployment, now):
        raising(location, name)

    monkeypatch.setattr(claims, "_plan_derive", unreadable)
    deployment = _deployment()
    with pytest.raises(kind) as raised:
        claims.derive_claims(deployment)
    assert name in str(raised.value), "the caller still gets the exception whole"

    spans = [s for s in recorded.spans if s.attributes.get("error.type")]
    assert spans, "no span recorded the failure"
    exported = repr([vars(s) for s in recorded.spans])
    assert name not in exported and location not in exported, exported
    for span in spans:
        assert span.events == []
        assert span.attributes["error.type"] == error_type
        assert span.status == ("ERROR", kind.__name__), span.status


def test_a_stop_leaving_a_span_reaches_its_caller_as_itself(monkeypatch):
    from mythos_core import tracing

    class Unwritable:
        def set_attribute(self, *_args):
            raise RuntimeError("the span cannot be written to")

        def set_status(self, *_args):
            raise RuntimeError("the span cannot be written to")

    class Trace:
        def get_tracer(self, *_args, **_kwargs):
            return self

        @contextmanager
        def start_as_current_span(self, name, attributes=None, **_kwargs):
            yield Unwritable()

    class Stopped(Exception):
        pass

    monkeypatch.setattr(tracing, "_otel_trace", lambda: Trace())
    stop = Stopped("stopped by an operator")
    with pytest.raises(Stopped) as raised, obs.span(obs.PLAN, component="derive_claims"):
        raise stop
    assert raised.value is stop


def test_a_stop_reaches_its_caller_as_itself_when_ending_the_span_raises(monkeypatch):
    """Ending the span raises -- an exporter or a processor that fails on end --
    while a stop is leaving the block: the caller gets the stop, not the span's
    error (review round 1, L4). With nothing leaving the block, the span's own
    failure is raised as it was."""
    from mythos_core import tracing

    class Trace:
        def get_tracer(self, *_args, **_kwargs):
            return self

        @contextmanager
        def start_as_current_span(self, name, attributes=None, **_kwargs):
            try:
                yield None
            finally:
                raise RuntimeError("the span could not be ended")

    class Stopped(Exception):
        pass

    monkeypatch.setattr(tracing, "_otel_trace", lambda: Trace())
    stop = Stopped("stopped by an operator")
    with pytest.raises(Stopped) as raised, obs.span(obs.PLAN, component="derive_claims"):
        raise stop
    assert raised.value is stop
    with pytest.raises(RuntimeError, match="could not be ended"):
        with obs.span(obs.PLAN, component="derive_claims"):
            pass
