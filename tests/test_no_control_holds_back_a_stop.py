"""No control in front of a view may refuse or delay a stop (#321).

The rule is absolute: no control, read failure, stale read, failed write, flood
or kill switch may ever block or delay a stop, pause, stand-down, terminate,
revoke, or a scan's Stop. On 7985460 three request-path controls broke it:

* The gateway (``audit.middleware.DefenderMiddleware``) put an engine round trip
  in front of every request, stops included. ``requests``' timeout bounds each
  socket operation, not the call, so an engine that sent a byte every 0.3 s
  held every stop and the engines' own command poll for 20.5 s (30 s when it
  dripped its headers). In enforce mode its block or throttle answer refused
  pause, lift, revoke, contradict, the failsafe draft, sign and cancel, and the
  poll, with 403 or 429.
* ``/api/failsafe/pending/`` is anonymous, so the default anonymous throttle
  (30/min per address) applied to it. The engines poll every 2 s -- exactly
  30/min -- so one extra poll, or a second engine behind the same address, got
  429 with Retry-After 60 and every command waited.
* The per-user throttle answered a flooded operator's stops with 429 (#310).

``safety.stops`` is now the one place a request is judged a stop, and the
gateway and the default throttles both read it. The first section is the
tripwire: it walks the URLconf and fails on any route nobody has classified.
The gateway tests run a real misbehaving engine on 127.0.0.1. The throttle
tests drive the real views through the whole middleware stack.
"""

from __future__ import annotations

import http.server
import json
import re
import threading
import time
import uuid
from unittest import mock

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from django.urls import URLPattern, URLResolver, get_resolver
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework.throttling import SimpleRateThrottle

from audit.middleware import DefenderMiddleware
from safety import stops
from safety.throttling import StopsPass

# --- The classification, declared here as well ---------------------------------

#: The stop set, stated independently of safety.stops so that a route dropped
#: from it -- or moved to NOT_STOPS with a reason -- fails here.
EXPECTED_STOPS = {
    "deployment-recompute": {"POST"},
    "claim-transition": {"POST"},
    "failsafe:commands": {"GET", "POST"},
    "failsafe:command-detail": {"GET"},
    "failsafe:submit-signature": {"POST"},
    "failsafe:cancel-command": {"POST"},
    "failsafe:pending": {"GET"},
    "deployment-dispatch-policy": {"PUT"},
    "pentest:engagement_detail": {"PATCH", "DELETE"},
    "accounts:user-set-role": {"PATCH"},
    "accounts:user-detail": {"DELETE"},
}

#: A route whose name says "stop" in any of these words is in the stop set,
#: unless it is listed below.
STOP_WORDS = re.compile(
    r"pause|lift|stop|halt|kill|terminat|stand|revok|abort|cancel|suspend|disabl|"
    r"contradict|failsafe|withdraw|dispatch|role|engagement|transition"
)
NAMED_LIKE_A_STOP_BUT_NOT = {
    "claim-withdraw-latent-condition",
    "deployment-dispatch-attempts",
    "failsafe:audit",
    "failsafe:state",
    "finding-remediation-transition",
    "pentest:engagement_plan",
    "pentest:engagements",
}

PLACEHOLDERS = re.compile(r"\b(todo|tbd|fixme|xxx|same as)\b", re.I)

U = "11111111-2222-4333-8444-555555555555"
POLL_TOKEN = "test-poll-token-321"

#: One request that is a stop for every (route, method) in the stop set:
#: (route, method, path, JSON body or None, extra headers).
STOP_REQUESTS = [
    ("deployment-recompute", "POST", f"/api/assurance/deployments/{U}/recompute/", {"paused": True}, {}),
    ("deployment-recompute", "POST", f"/api/assurance/deployments/{U}/recompute/", {"paused": False}, {}),
    ("claim-transition", "POST", f"/api/assurance/claims/{U}/transition/", {"to_status": "revoked"}, {}),
    ("claim-transition", "POST", f"/api/assurance/claims/{U}/transition/", {"to_status": "contradicted"}, {}),
    ("failsafe:commands", "GET", "/api/failsafe/commands/", None, {}),
    ("failsafe:commands", "POST", "/api/failsafe/commands/", {"action": "stand_down", "engine_id": "e"}, {}),
    ("failsafe:command-detail", "GET", f"/api/failsafe/commands/{U}/", None, {}),
    ("failsafe:submit-signature", "POST", f"/api/failsafe/commands/{U}/signatures/", {"key_id": "a", "sig": "00"}, {}),
    ("failsafe:cancel-command", "POST", f"/api/failsafe/commands/{U}/cancel/", {}, {}),
    ("failsafe:pending", "GET", "/api/failsafe/pending/", None, {"HTTP_X_FAILSAFE_POLL_TOKEN": POLL_TOKEN}),
    ("deployment-dispatch-policy", "PUT", f"/api/assurance/deployments/{U}/dispatch-policy/", {"enabled": False}, {}),
    ("pentest:engagement_detail", "PATCH", "/api/pentest/engagements/7/", {"status": "paused"}, {}),
    ("pentest:engagement_detail", "DELETE", "/api/pentest/engagements/7/", None, {}),
    ("accounts:user-set-role", "PATCH", "/api/accounts/users/7/set_role/", {"role": "viewer"}, {}),
    ("accounts:user-detail", "DELETE", "/api/accounts/users/7/", None, {}),
]

#: The same routes carrying requests that are NOT stops: the gateway still asks
#: about them and still enforces its answer, so the exemption is no wider than
#: the stop set.
NOT_STOP_REQUESTS = [
    ("POST", f"/api/assurance/deployments/{U}/recompute/", {}, {}),
    ("POST", f"/api/assurance/claims/{U}/transition/", {"to_status": "verified"}, {}),
    ("GET", "/api/failsafe/pending/", None, {}),
    ("GET", "/api/failsafe/pending/", None, {"HTTP_X_FAILSAFE_POLL_TOKEN": "a-guess"}),
    ("PUT", f"/api/assurance/deployments/{U}/dispatch-policy/", {"min_severity": "high"}, {}),
    ("PATCH", "/api/pentest/engagements/7/", {"name": "renamed"}, {}),
    ("GET", "/api/pentest/engagements/7/", None, {}),
    ("GET", "/api/failsafe/state/", None, {}),
    ("POST", "/api/pentest/scan/", {"url": "https://x.test"}, {}),
]


def walk(patterns=None, namespaces=(), prefix=""):
    """{view name: {"methods": set, "callbacks": list}} for every route served.

    Refuses a route it cannot name, as the engine's walker refuses a mount it
    cannot see into: an unnamed route is exactly where an unclassified stop
    would hide. Django's admin site is one entry, ``admin:*``."""
    found = {}

    def add(name, methods, callback):
        entry = found.setdefault(name, {"methods": set(), "callbacks": []})
        entry["methods"] |= methods
        if callback is not None:
            entry["callbacks"].append(callback)

    for pattern in get_resolver().url_patterns if patterns is None else patterns:
        if isinstance(pattern, URLResolver):
            inner = namespaces + ((pattern.namespace,) if pattern.namespace else ())
            if inner[:1] == ("admin",):
                add("admin:*", {"ANY"}, None)
                continue
            for name, entry in walk(pattern.url_patterns, inner, prefix + str(pattern.pattern)).items():
                add(name, entry["methods"], None)
                found[name]["callbacks"].extend(entry["callbacks"])
        elif isinstance(pattern, URLPattern):
            if not pattern.name:
                raise AssertionError(
                    f"the route {prefix}{pattern.pattern} has no name, so it cannot be classified"
                )
            callback = pattern.callback
            actions = getattr(callback, "actions", None)
            cls = getattr(callback, "cls", None)
            if actions:
                methods = {method.upper() for method in actions}
            elif cls is not None:
                methods = {
                    method.upper()
                    for method in cls.http_method_names
                    if method not in ("options", "head") and hasattr(cls, method)
                }
            else:
                methods = {"ANY"}
            add(":".join((*namespaces, pattern.name)), methods, callback)
        else:
            raise AssertionError(f"unrecognised URLconf entry {type(pattern).__name__}")
    return found


# --- The tripwire --------------------------------------------------------------


def test_every_route_is_classified_as_a_stop_or_not():
    served = set(walk())
    stop_set, not_stops = set(stops.STOP_ROUTES), set(stops.NOT_STOPS)

    assert not stop_set & not_stops, f"classified both ways: {sorted(stop_set & not_stops)}"
    unclassified = served - stop_set - not_stops
    assert not unclassified, (
        "these routes are neither a stop nor declared not one; classify each in "
        f"safety/stops.py: {sorted(unclassified)}"
    )
    stale = (stop_set | not_stops) - served
    assert not stale, f"classified routes that no longer exist: {sorted(stale)}"


def test_the_stop_set_is_the_one_declared_here():
    declared = {name: set(methods) for name, methods in stops.STOP_ROUTES.items()}
    assert declared == EXPECTED_STOPS


def test_every_stop_method_is_one_the_route_serves():
    """A stop declared on a method the route does not serve is never recognised:
    PUT where the view takes PATCH would leave every real request unexempt."""
    served = walk()
    for name, methods in stops.STOP_ROUTES.items():
        missing = set(methods) - served[name]["methods"]
        assert not missing, f"{name} declares stops on {sorted(missing)}, which it does not serve"


def test_a_route_named_like_a_stop_is_one_or_is_listed_as_not():
    for name in walk():
        if STOP_WORDS.search(name) and name not in stops.STOP_ROUTES:
            assert name in NAMED_LIKE_A_STOP_BUT_NOT, (
                f"{name} is named like a stop but is not in the stop set; add it to "
                "safety.stops.STOP_ROUTES, or to NAMED_LIKE_A_STOP_BUT_NOT here"
            )
    assert NAMED_LIKE_A_STOP_BUT_NOT <= set(stops.NOT_STOPS)


def test_every_route_that_is_not_a_stop_says_why():
    for name, reason in stops.NOT_STOPS.items():
        words = re.findall(r"[a-z0-9']+", reason.lower())
        assert len(words) >= 3 and not PLACEHOLDERS.search(reason), (
            f"{name} is declared not a stop with a placeholder, not a reason: {reason!r}"
        )


def test_no_stop_view_opts_out_of_the_stop_exemption():
    """A stop view's own throttle_classes would replace the defaults; every one
    must still let a stop through."""
    for name in stops.STOP_ROUTES:
        for callback in walk()[name]["callbacks"]:
            cls = callback.cls
            throttles = callback.initkwargs.get("throttle_classes", cls.throttle_classes)
            wrong = [t.__name__ for t in throttles if not issubclass(t, StopsPass)]
            assert not wrong, f"{name} throttles stops with {wrong}"


def test_the_walker_refuses_what_it_cannot_name_and_sees_into_includes():
    from django.urls import include, path

    def view(request):  # pragma: no cover - never called
        return HttpResponse()

    inner = ([path("x/", view, name="inner")], "space")
    found = walk([path("a/", include(inner)), path("b/", view, name="outer")])
    assert set(found) == {"space:inner", "outer"}
    assert found["outer"]["methods"] == {"ANY"}
    with pytest.raises(AssertionError, match="has no name"):
        walk([path("c/", view)])


def test_every_stop_route_and_method_has_a_sample_request_below():
    sampled = {(name, method) for name, method, *_ in STOP_REQUESTS}
    declared = {(name, method) for name, methods in stops.STOP_ROUTES.items() for method in methods}
    assert sampled == declared


# --- The gateway: a real engine on 127.0.0.1 that misbehaves -------------------


class _Engine(http.server.BaseHTTPRequestHandler):
    """/defend, answering block after ``mode``: at once, after a hang, with its
    body a byte at a time, or with its status line and headers a byte at a time.
    A drip is 0.15 s a byte, under any per-socket timeout used here."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.asked.append(self.path)
        raw = json.dumps({"allow": False, "action": "block", "reason": "stand-in"}).encode()
        head = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\n\r\n"
        mode = self.server.mode
        try:
            if mode == "hang":
                time.sleep(3.0)
            if mode == "headers":
                for byte in head.encode():
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.15)
                self.wfile.write(raw)
                return
            self.wfile.write(head.encode())
            if mode == "body":
                for byte in raw[:16]:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.15)
                self.wfile.write(raw[16:])
            else:
                self.wfile.write(raw)
        except OSError:
            pass  # the caller stopped waiting, which is the point


class _EngineServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def handle_error(self, request, client_address):
        pass


@pytest.fixture()
def configure():
    """Settings for one test, put back after it."""
    active = []

    def apply(**values):
        override = override_settings(**values)
        override.enable()
        active.append(override)

    yield apply
    for override in reversed(active):
        override.disable()


@pytest.fixture()
def engine():
    server = _EngineServer(("127.0.0.1", 0), _Engine)
    server.mode, server.asked = "now", []
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture()
def gateway(configure, engine):
    def build(mode="now", monitor_only=False, timeout=0.5, max_in_flight=32):
        engine.mode = mode
        configure(
            CYBERENGINE_URL=f"http://127.0.0.1:{engine.server_address[1]}",
            CYBERENGINE_OPERATOR_KEY="k",
            DEFENDER_MONITOR_ONLY=monitor_only,
            DEFENDER_TIMEOUT_SECONDS=timeout,
            DEFENDER_MAX_IN_FLIGHT=max_in_flight,
            FAILSAFE_POLL_TOKEN=POLL_TOKEN,
        )
        return DefenderMiddleware(lambda request: HttpResponse("the view ran"))

    return build


def _request(method, path, body, extra):
    factory = RequestFactory()
    data = "" if body is None else json.dumps(body)
    return factory.generic(method, path, data=data, content_type="application/json", **extra)


@pytest.mark.parametrize("mode", ["hang", "body", "headers"])
@pytest.mark.parametrize(
    "sample", STOP_REQUESTS, ids=[f"{name}-{method}-{i}" for i, (name, method, *_) in enumerate(STOP_REQUESTS)]
)
def test_a_slow_or_trickling_engine_never_delays_a_stop(gateway, engine, mode, sample):
    """Measured on 7985460: 0.5 s behind a hung engine, 20.5 s behind one that
    drips its body, 30 s behind one that drips its headers -- every stop, and
    the engines' own poll. A stop never reaches the engine now."""
    _name, method, path, body, extra = sample
    app = gateway(mode=mode, monitor_only=True)
    started = time.monotonic()
    response = app(_request(method, path, body, extra))
    took = time.monotonic() - started
    assert response.status_code == 200 and response.content == b"the view ran"
    assert took < 0.25, f"{method} {path} took {took:.3f}s behind an engine in mode {mode!r}"
    assert engine.asked == []


@pytest.mark.parametrize("answer", [
    {"allow": False, "action": "block", "reason": "x"},
    {"allow": True, "action": "throttle", "block_seconds": 30},
])
@pytest.mark.parametrize(
    "sample", STOP_REQUESTS, ids=[f"{name}-{method}-{i}" for i, (name, method, *_) in enumerate(STOP_REQUESTS)]
)
def test_enforce_mode_never_refuses_a_stop(configure, sample, answer):
    """On 7985460, with DEFENDER_MONITOR_ONLY=False, the engine's block answered
    every stop 403 and its throttle answered 429."""
    _name, method, path, body, extra = sample
    configure(DEFENDER_MONITOR_ONLY=False, FAILSAFE_POLL_TOKEN=POLL_TOKEN)
    post = mock.Mock(side_effect=AssertionError("a stop was sent to the engine"))
    with mock.patch("audit.middleware.requests.post", post):
        response = DefenderMiddleware(lambda request: HttpResponse("the view ran"))(
            _request(method, path, body, extra)
        )
    assert response.status_code == 200 and response.content == b"the view ran"
    post.assert_not_called()


def _engine_answers(payload):
    import io

    import urllib3

    def answer(*args, **kwargs):
        response = requests.Response()
        response.status_code = 200
        response.raw = urllib3.HTTPResponse(
            body=io.BytesIO(json.dumps(payload).encode()), status=200, preload_content=False
        )
        return response

    return mock.Mock(side_effect=answer)


@pytest.mark.parametrize("sample", NOT_STOP_REQUESTS, ids=[f"{m}-{p}-{i}" for i, (m, p, *_) in enumerate(NOT_STOP_REQUESTS)])
def test_the_same_routes_are_still_enforced_when_the_request_is_not_a_stop(configure, sample):
    """The exemption is the stop set and no wider: a routine recompute, a claim
    verified, a poll without the token, a policy that only changes severity."""
    method, path, body, extra = sample
    configure(DEFENDER_MONITOR_ONLY=False, FAILSAFE_POLL_TOKEN=POLL_TOKEN)
    post = _engine_answers({"allow": False, "action": "block", "reason": "x"})
    with mock.patch("audit.middleware.requests.post", post):
        response = DefenderMiddleware(lambda request: HttpResponse("the view ran"))(
            _request(method, path, body, extra)
        )
    assert response.status_code == 403
    post.assert_called_once()


@pytest.mark.parametrize(
    ("content_type", "data"),
    [
        ("multipart/form-data; boundary=zz", b'--zz\r\nContent-Disposition: form-data; name="paused"\r\n\r\ntrue\r\n--zz--\r\n'),
        ("application/json", b'{"paused": tru'),
        ("application/json; charset=utf-16", json.dumps({"paused": True}).encode("utf-16")),
        ("application/json", b'{"\\u0070aused": true}'),
        ("application/x-www-form-urlencoded", b"paused=true"),
        ("application/vnd.example+json", b'{"paused": true}'),
    ],
    ids=["multipart", "broken-json", "utf-16", "escaped-key", "form", "unknown-type"],
)
def test_a_pause_whose_body_is_read_differently_is_still_a_stop(content_type, data):
    """The body is judged as the view's parser will read it; one that cannot be
    read that way here is a stop, so a doubt about the body never refuses one."""
    request = RequestFactory().generic(
        "POST", f"/api/assurance/deployments/{U}/recompute/", data=data, content_type=content_type
    )
    assert stops.is_stop(request)


def test_a_routine_recompute_is_not_a_stop():
    for data in (b"", b"{}", b'{"paused": null}', b"[]"):
        request = RequestFactory().generic(
            "POST", f"/api/assurance/deployments/{U}/recompute/", data=data, content_type="application/json"
        )
        assert not stops.is_stop(request), data


@pytest.mark.parametrize("mode", ["hang", "body", "headers"])
def test_every_other_request_waits_no_longer_than_the_whole_deadline_and_is_allowed(gateway, engine, mode):
    """The deadline is on the whole call. requests' timeout was per socket
    operation, so a byte every 0.15 s never tripped it: the body drip held the
    request 2.4 s and the header drip 7 s. Past the deadline the request is
    allowed, as when the engine is down: the gateway fails open, even though the
    late answer here is a block in enforce mode."""
    app = gateway(mode=mode, monitor_only=False, timeout=0.3)
    started = time.monotonic()
    response = app(_request("GET", "/api/failsafe/state/", None, {}))
    took = time.monotonic() - started
    assert response.status_code == 200 and response.content == b"the view ran"
    assert took < 0.3 + 0.25, f"took {took:.3f}s against a 0.3s deadline"
    assert engine.asked == ["/defend"]


def test_calls_left_running_are_bounded_and_the_next_request_still_meets_its_deadline(gateway, monkeypatch):
    """A call the request stopped waiting for can still be running -- an engine
    dripping its headers holds it. With every slot taken, the next request waits
    for one only until its own deadline, and is allowed."""
    app = gateway(mode="headers", monitor_only=False, timeout=0.3, max_in_flight=1)
    problems = []
    monkeypatch.setattr(app, "_record_failure", problems.append)
    for _ in range(2):
        started = time.monotonic()
        response = app(_request("GET", "/api/failsafe/state/", None, {}))
        assert response.status_code == 200
        assert time.monotonic() - started < 0.3 + 0.25
    assert problems[0] == "engine gave no decision within 0.3s"
    assert problems[1] == "all 1 engine call slots are in use; not asking"


def test_the_call_stops_reading_a_trickling_answer_at_its_deadline(gateway, engine, monkeypatch):
    """The answer is read as a stream under the deadline, so a call left behind
    by its request gives its slot back within a byte of the deadline, not when
    the engine finishes dripping (2.4 s here). With one slot, a request 0.8 s
    later is asked about, not turned away as "all slots in use"."""
    app = gateway(mode="body", monitor_only=False, timeout=0.3, max_in_flight=1)
    problems = []
    monkeypatch.setattr(app, "_record_failure", problems.append)
    started = time.monotonic()
    app(_request("GET", "/api/failsafe/state/", None, {}))
    time.sleep(max(0.0, 0.8 - (time.monotonic() - started)))
    app(_request("GET", "/api/failsafe/state/", None, {}))
    assert len(engine.asked) == 2, problems
    assert "all 1 engine call slots are in use; not asking" not in problems


def test_a_stop_route_request_that_cannot_be_judged_is_a_stop(monkeypatch):
    def broken(request, read):
        raise RuntimeError("the judge failed")

    monkeypatch.setitem(stops.STOP_ROUTES, "deployment-recompute", {"POST": broken})
    request = RequestFactory().post(f"/api/assurance/deployments/{U}/recompute/", data={}, content_type="application/json")
    assert stops.is_stop(request)
    # Off the stop set, nothing is a stop by accident.
    assert not stops.is_stop(RequestFactory().get("/api/failsafe/state/"))
    assert not stops.is_stop(RequestFactory().get("/no/such/route/"))


def test_a_prompt_answer_is_still_enforced(gateway):
    app = gateway(mode="now", monitor_only=False)
    response = app(_request("GET", "/api/failsafe/state/", None, {}))
    assert response.status_code == 403


# --- The throttles, through the whole stack -------------------------------------

User = get_user_model()

#: The shipped anonymous rate (config.settings). The engines poll every 2 s.
ANON_RATE = "30/min"


@pytest.fixture()
def rates(monkeypatch, configure):
    """Real rates for these tests. The test settings switch throttling off, and
    the throttle classes read their rates once, at import."""

    def apply(anon=ANON_RATE, user="300/min"):
        monkeypatch.setattr(SimpleRateThrottle, "THROTTLE_RATES", {"anon": anon, "user": user})

    cache.clear()
    configure(DEFENDER_MONITOR_ONLY=True, FAILSAFE_POLL_TOKEN=POLL_TOKEN)
    # The gateway answers allow at once: these tests are about the throttles.
    monkeypatch.setattr("audit.middleware.requests.post", _engine_answers({"allow": True, "action": "allow"}))
    apply()
    yield apply
    cache.clear()


def _poll(client=None, token=POLL_TOKEN, engine_id="athena-1", **extra):
    headers = {} if token is None else {"HTTP_X_FAILSAFE_POLL_TOKEN": token}
    return (client or APIClient()).get(f"/api/failsafe/pending/?engine_id={engine_id}", **headers, **extra)


@pytest.mark.django_db
def test_more_than_thirty_polls_a_minute_from_one_address_are_all_served(rates):
    """On 7985460 the 31st poll in a minute was 429 with Retry-After 60."""
    codes = [_poll().status_code for _ in range(45)]
    assert codes == [200] * 45


@pytest.mark.django_db
def test_two_engines_behind_one_address_are_never_throttled(rates):
    codes = {"athena-1": [], "athena-2": []}
    for _ in range(30):
        for engine_id in codes:
            codes[engine_id].append(_poll(engine_id=engine_id).status_code)
    assert codes == {"athena-1": [200] * 30, "athena-2": [200] * 30}


@pytest.mark.django_db
def test_a_flood_of_guesses_at_the_poll_token_is_still_limited(rates):
    """A poll without the token is not a stop: it is throttled like any other
    anonymous request, so the token cannot be guessed at speed."""
    codes = [_poll(token="a-guess").status_code for _ in range(31)]
    assert codes == [401] * 30 + [429]
    assert _poll(token=None).status_code == 429


@pytest.mark.django_db
def test_the_engine_is_served_from_an_address_whose_guesses_are_throttled(rates):
    for _ in range(31):
        _poll(token="a-guess")
    assert _poll(token="a-guess").status_code == 429
    assert _poll().status_code == 200


@pytest.mark.django_db
def test_a_poll_carrying_a_stale_bearer_header_is_served(rates):
    """The engine is not an operator and the poll reads no JWT; on 7985460 a
    stale bearer header on the engine's request was answered 401."""
    assert _poll(HTTP_AUTHORIZATION="Bearer stale").status_code == 200


_n = [0]


def _admin():
    _n[0] += 1
    return User.objects.create_user(username=f"stop321-{_n[0]}", password="x", role=User.Roles.ADMIN)


def _deployment():
    from assurance.claims import derive_claims
    from assurance.decision import recompute_decision
    from assurance.models import Asset, DataBoundary, Deployment

    dep = Deployment.objects.create(name=f"stop321-{uuid.uuid4()}", owner=_admin())
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    DataBoundary.objects.create(
        deployment=dep, allowed_regions=["eu-west-1"], training_allowed=False, third_party_sharing_allowed=False
    )
    Asset.objects.bulk_create(
        [
            Asset(deployment=dep, kind=Asset.Kind.TOOL, name=f"tool-{i}", identifier=f"tool-{i}",
                  classification=Asset.Classification.KNOWN)
            for i in range(3)
        ]
    )
    derive_claims(Deployment.objects.get(pk=dep.pk))
    recompute_decision(Deployment.objects.get(pk=dep.pk))
    return Deployment.objects.get(pk=dep.pk)


def _claim(dep):
    from assurance.models import AssuranceClaim

    Status = AssuranceClaim.ClaimStatus
    return (
        AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True)
        .exclude(status__in=[Status.REVOKED, Status.STALE, Status.SUPERSEDED])
        .order_by("pk")
        .first()
    )


@pytest.fixture()
def operator_key(configure):
    key = Ed25519PrivateKey.generate()
    configure(FAILSAFE_OPERATOR_KEYS={"alice": key.public_key().public_bytes_raw().hex()})
    return key


def _every_stop(client, operator, operator_key):
    """Every kind of stop an operator makes, each on its own row, and the
    engine's poll. Returns {stop: status code}."""
    from assurance.decision import recompute_decision
    from pentest.models import Engagement

    to_pause, to_lift, to_revoke, to_contradict, to_switch_off = (_deployment() for _ in range(5))
    recompute_decision(to_lift, paused=True)
    # Two drafts, one to sign and one to cancel. A draft is a stop too.
    drafts = [
        client.post("/api/failsafe/commands/", {"action": "pause", "engine_id": "athena-1"}, format="json").data
        for _ in range(2)
    ]
    sig = operator_key.sign(bytes.fromhex(drafts[0]["signing_bytes"])).hex()
    engagement = Engagement.objects.create(name="stop321", created_by=operator, status="running")
    colleague = _admin()

    base = "/api/assurance"
    return {
        "pause": client.post(f"{base}/deployments/{to_pause.uuid}/recompute/", {"paused": True}, format="json").status_code,
        "lift": client.post(f"{base}/deployments/{to_lift.uuid}/recompute/", {"paused": False}, format="json").status_code,
        "revoke": client.post(f"{base}/claims/{_claim(to_revoke).uuid}/transition/", {"to_status": "revoked"}, format="json").status_code,
        "contradict": client.post(f"{base}/claims/{_claim(to_contradict).uuid}/transition/", {"to_status": "contradicted"}, format="json").status_code,
        "stand down": client.post("/api/failsafe/commands/", {"action": "stand_down", "engine_id": "athena-1"}, format="json").status_code,
        "terminate": client.post("/api/failsafe/commands/", {"action": "terminate", "engine_id": "athena-1"}, format="json").status_code,
        "sign": client.post(f"/api/failsafe/commands/{drafts[0]['uuid']}/signatures/", {"key_id": "alice", "sig": sig}, format="json").status_code,
        "cancel": client.post(f"/api/failsafe/commands/{drafts[1]['uuid']}/cancel/", {}, format="json").status_code,
        "dispatch off": client.put(f"{base}/deployments/{to_switch_off.uuid}/dispatch-policy/", {"enabled": False}, format="json").status_code,
        "engagement paused": client.patch(f"/api/pentest/engagements/{engagement.pk}/", {"status": "paused"}, format="json").status_code,
        "operator demoted": client.patch(f"/api/accounts/users/{colleague.pk}/set_role/", {"role": "viewer"}, format="json").status_code,
        "poll": _poll().status_code,
    }


SERVED = {
    "pause": 200, "lift": 200, "revoke": 200, "contradict": 200, "stand down": 201, "terminate": 201,
    "sign": 200, "cancel": 200, "dispatch off": 200, "engagement paused": 200, "operator demoted": 200, "poll": 200,
}


def _client_for(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


@pytest.mark.django_db
def test_a_flooded_operator_can_still_pause_stand_down_revoke_and_lift(rates, operator_key):
    """#310: past the per-user rate every stop was 429. The rate is 20/min here
    so the flood is short; the mechanism is the same at 300/min."""
    rates(user="20/min")
    operator = _admin()
    client = _client_for(operator)
    flood = [client.get("/api/failsafe/audit/").status_code for _ in range(25)]
    assert flood == [200] * 20 + [429] * 5, "the flood did not reach the rate"
    assert _every_stop(client, operator, operator_key) == SERVED


@pytest.mark.django_db
def test_stops_do_not_spend_the_operators_budget(rates, operator_key):
    """A stop is never counted: an operator who has just made every kind of stop
    still has the whole of their rate for everything else."""
    rates(user="5/min")
    operator = _admin()
    client = _client_for(operator)
    assert _every_stop(client, operator, operator_key) == SERVED
    reads = [client.get("/api/failsafe/audit/").status_code for _ in range(6)]
    assert reads == [200] * 5 + [429]


@pytest.mark.django_db
def test_enforce_mode_never_refuses_a_stop_through_the_whole_stack(rates, configure, operator_key, monkeypatch):
    """The gateway as settings.MIDDLEWARE installs it, answering block to
    everything in enforce mode: every stop is served, and a read is refused."""
    configure(DEFENDER_MONITOR_ONLY=False)
    monkeypatch.setattr(
        "audit.middleware.requests.post", _engine_answers({"allow": False, "action": "block", "reason": "x"})
    )
    operator = _admin()
    client = _client_for(operator)
    assert _every_stop(client, operator, operator_key) == SERVED
    assert client.get("/api/failsafe/audit/").status_code == 403
