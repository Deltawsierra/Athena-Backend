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
import traceback
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


@pytest.fixture()
def recorded(monkeypatch):
    from mythos_core import tracing

    trace = _SDKLikeTrace()
    monkeypatch.setattr(tracing, "_otel_trace", lambda: trace)
    return trace


def test_a_derivation_that_fails_leaves_its_span_as_one_type(recorded, monkeypatch):
    """Deriving a deployment's claims fails with an exception quoting what it was
    reading, chained from the failure before it: the span says which exception,
    and nothing it or its cause says."""
    import assurance.claims as claims

    location = "/internal/" + secrets.token_hex(8)
    name = "cnrydeployment" + secrets.token_hex(8)

    def unreadable(deployment, now):
        try:
            raise KeyError(f"finding at {location} has no severity")
        except KeyError as first:
            raise ValueError(f"cannot assess {name}: {first}") from first

    monkeypatch.setattr(claims, "_plan_derive", unreadable)
    deployment = _deployment()
    with pytest.raises(ValueError) as raised:
        claims.derive_claims(deployment)
    assert name in str(raised.value), "the caller still gets the exception whole"

    spans = [s for s in recorded.spans if s.attributes.get("error.type")]
    assert spans, "no span recorded the failure"
    exported = repr([vars(s) for s in recorded.spans])
    assert name not in exported and location not in exported, exported
    for span in spans:
        assert span.events == []
        assert span.attributes["error.type"] == "ValueError"
        assert span.status is None or span.status[1] == "ValueError", span.status


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
