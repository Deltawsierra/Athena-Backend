"""The Defender gateway is never sent a credential from a scan's target.

``audit.middleware.DefenderMiddleware`` asks the engine's ``/defend`` about every
request that is not a stop, with its path, method, user agent, query string and
body. The body was redacted by key (``password``, ``api_key``, ...), so a scan
launch's ``url`` -- with the login (``user:password@``), the ``;jsessionid=``, the
``?api_key=`` and the fragment a target can carry -- went to another service as it
was typed: ``url`` names no secret. #219 withholds
those parts everywhere a target is shown; this is the one place it was sent.

A scan launch's target now reaches the Defender as ``pentest.models.target_shown``
shows it (login ``[withheld]``; every query, ``;param`` and fragment value
``•••``), and a launch whose target the gateway cannot read is not sent at all.
The scheme, host, port and path are as given, so what the engine scores --
path, method, query and body, for attack structure -- is unchanged for every
target that carries no credential.

These run against a real engine stub on loopback and read what it was sent off
the wire: request line, headers and body.
"""

import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

import pytest
from django.http import HttpResponse
from django.test import RequestFactory, override_settings

from audit.middleware import DefenderMiddleware, redact
from safety.stops import is_stop
from tests.test_no_control_holds_back_a_stop import POLL_TOKEN, STOP_REQUESTS

#: A target carrying a credential in every place a URL can carry one.
TARGET = (
    "https://planted-user:PLANTED-PASS-7f3a@scan.example.test:8443/app;jsessionid=PLANTED-SESS-9c1d"  # pragma: allowlist secret
    "/x?api_key=PLANTED-KEY-4e8b&page=2#PLANTED-FRAG-6d0e"
)
#: The same target as #219 shows it, which is what the Defender may be sent.
SHOWN = "https://[withheld]@scan.example.test:8443/app;jsessionid=•••/x?api_key=•••&page=•••#•••"
#: Every planted value carries this; none of it may reach the engine.
PLANTED = b"PLANTED"
#: A request's own credentials, planted beside the target.
AUTHORIZATION = "Bearer PLANTED-AUTH-8a6f"
COOKIE = "sessionid=PLANTED-COOKIE-3d9e; csrftoken=PLANTED-CSRF-1c7b"

LAUNCH = "/api/pentest/scan/"
LLM_LAUNCH = "/api/pentest/llm-scan/"


class _Engine(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - http.server's name
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        self.server.asked.append({
            "line": self.requestline.encode("latin-1"),
            "headers": bytes(self.headers),
            "body": body,
        })
        answer = json.dumps(self.server.answer).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)

    def log_message(self, *args):
        pass


@pytest.fixture()
def engine():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Engine)
    server.asked, server.answer = [], {"allow": True, "action": "allow", "reason": "ok"}
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True)
    thread.start()
    yield server
    server.shutdown()
    server.server_close()
    thread.join(5)


@pytest.fixture()
def gateway(engine):
    overrides = []

    def build(**more):
        values = {
            "CYBERENGINE_URL": f"http://127.0.0.1:{engine.server_address[1]}",
            "CYBERENGINE_OPERATOR_KEY": "operator-key-for-the-stub",
            "DEFENDER_MONITOR_ONLY": True,
            "DEFENDER_TIMEOUT_SECONDS": 5,
            **more,
        }
        override = override_settings(**values)
        override.enable()
        overrides.append(override)
        return DefenderMiddleware(lambda request: HttpResponse("the view ran"))

    yield build
    for override in reversed(overrides):
        override.disable()


def _wire(engine):
    """Everything the engine was sent, as one byte string."""
    return b"\n".join(part for asked in engine.asked for part in asked.values())


def _sent(engine):
    """The one context the engine was asked about."""
    assert len(engine.asked) == 1, f"the engine was asked {len(engine.asked)} times"
    return json.loads(engine.asked[0]["body"])


def _launch(path, data, content_type, **extra):
    extra.setdefault("HTTP_AUTHORIZATION", AUTHORIZATION)
    extra.setdefault("HTTP_COOKIE", COOKIE)
    return RequestFactory().post(path, data=data, content_type=content_type, **extra)


def _multipart(**fields):
    parts = [
        f'--zz\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n'
        for name, value in fields.items()
    ]
    return ("".join(parts) + "--zz--\r\n").encode()


# (label, path, body, content type, the field the body names its target in)
LAUNCHES = [
    ("json", LAUNCH, json.dumps({"url": TARGET, "consent": True, "engagement_id": 7}), "application/json"),
    ("json, slashes escaped", LAUNCH,
     '{"url": "%s", "consent": true}' % TARGET.replace("/", "\\/"), "application/json"),
    ("json, url twice", LAUNCH,
     '{"url": "%s", "consent": true, "url": "%s"}' % (TARGET, TARGET), "application/json"),
    ("json, charset utf-16", LAUNCH,
     json.dumps({"url": TARGET, "consent": True}), "application/json; charset=utf-16"),
    ("form", LAUNCH,
     "url=" + TARGET.replace("&", "%26").replace("#", "%23") + "&consent=true", "application/x-www-form-urlencoded"),
    ("json labelled as a form", LAUNCH,
     json.dumps({"url": TARGET, "consent": True}), "application/x-www-form-urlencoded"),
    ("multipart", LAUNCH, _multipart(url=TARGET, consent="true"), "multipart/form-data; boundary=zz"),
    ("llm scan", LLM_LAUNCH,
     json.dumps({"target_name": "t", "adapter": "openai", "base_url": TARGET, "model": "m",
                 "attacks": ["prompt_injection"], "max_turns": 3}), "application/json"),
]


@pytest.mark.django_db
@pytest.mark.parametrize(("label", "path", "body", "content_type"), LAUNCHES, ids=[row[0] for row in LAUNCHES])
def test_no_credential_a_scan_launch_carries_reaches_the_defender(gateway, engine, label, path, body, content_type):
    """The login, every query, ``;param`` and fragment value of the target, and the
    request's own Authorization and Cookie headers: none of it is on the wire to the
    engine, whatever shape the launch is in."""
    response = gateway()(_launch(path, body, content_type))

    assert response.status_code == 200 and response.content == b"the view ran"
    wire = _wire(engine)
    assert engine.asked, "the launch was not put to the engine at all"
    assert PLANTED not in wire, f"{label}: a planted credential reached the engine: {wire!r}"
    # What it is sent instead is the target as it is shown: host and path intact.
    forwarded = _sent(engine)
    assert forwarded["path"] == path and forwarded["method"] == "POST"
    assert "scan.example.test" in forwarded["body"]


@pytest.mark.django_db
def test_the_target_reaches_the_defender_exactly_as_it_is_shown(gateway, engine):
    gateway()(_launch(LAUNCH, json.dumps({"url": TARGET, "consent": True}), "application/json"))

    body = json.loads(_sent(engine)["body"])
    assert body == {"url": SHOWN, "consent": True}


@pytest.mark.django_db
def test_a_form_launch_s_target_reaches_the_defender_as_shown_and_its_other_fields_as_sent(gateway, engine):
    raw = "consent=true&url=" + TARGET.replace("&", "%26").replace("#", "%23") + "&note=%27+OR+1%3D1--"
    gateway()(_launch(LAUNCH, raw, "application/x-www-form-urlencoded"))

    body = _sent(engine)["body"]
    assert parse_qs(body)["url"] == [SHOWN]
    assert body.startswith("consent=true&") and body.endswith("&note=%27+OR+1%3D1--"), body


@pytest.mark.django_db
def test_a_target_in_a_launch_s_query_string_is_withheld_too(gateway, engine):
    query = "url=" + TARGET.replace("&", "%26").replace("#", "%23")
    gateway()(_launch(f"{LAUNCH}?{query}", json.dumps({"url": "https://scan.example.test/"}), "application/json"))

    assert PLANTED not in _wire(engine)
    assert parse_qs(_sent(engine)["query"])["url"] == [SHOWN]


@pytest.mark.django_db
def test_the_target_said_again_elsewhere_in_the_launch_is_withheld_too(gateway, engine):
    body = {"url": TARGET, "consent": True, "note": f"rescan of {TARGET}, key PLANTED-KEY-4e8b"}
    gateway()(_launch(LAUNCH, json.dumps(body), "application/json"))

    assert PLANTED not in _wire(engine)


@pytest.mark.django_db
@pytest.mark.parametrize(("label", "body", "content_type"), [
    ("text", f"url: {TARGET} consent: true", "text/plain"),
    ("json that does not parse", '{"url": "%s", ' % TARGET, "application/json"),
    ("json that does not parse, slashes escaped", '{"url": "%s", ' % TARGET.replace("/", "\\/"), "application/json"),
    ("url not a string", json.dumps({"url": {"href": TARGET}}), "application/json"),
    ("longer than the gateway parses", json.dumps({"url": TARGET, "note": "A" * 9000}), "application/json"),
])
def test_a_launch_whose_target_cannot_be_read_has_every_url_in_it_withheld(gateway, engine, label, body, content_type):
    """A launch body the gateway cannot read its target from -- not a form, not
    JSON, or longer than it parses -- is still inspected, with every URL in it
    shown as a target is: whichever one the target is, its credential stays here."""
    gateway(DEFENDER_MAX_BODY_BYTES=2048)(_launch(LAUNCH, body, content_type))

    assert PLANTED not in _wire(engine), f"{label}: {_wire(engine)!r}"
    if label != "url not a string":
        assert "scan.example.test" in _sent(engine)["body"], "the body was not inspected"


@pytest.mark.django_db
def test_a_target_the_read_prefix_cuts_inside_its_login_is_withheld_whole(gateway, engine):
    """The gateway reads four times what it keeps (redaction can shrink a body), so
    a target can be cut inside its login -- where no `@` is left to end the login
    at -- and still be kept once a long secret before it is redacted."""
    head = '{"password":"'
    padding = 4096 - len(head) - len('","url":"') - len("https://planted-user:PLANT")
    body = head + "x" * padding + '","url":"' + TARGET + '"}'
    assert body[:4096].endswith("https://planted-user:PLANT")

    gateway(DEFENDER_MAX_BODY_BYTES=1024)(_launch(LAUNCH, body, "application/json"))

    wire = _wire(engine)
    assert b"planted-user" not in wire and b"PLANT" not in wire, wire
    assert '"url":"•••' in _sent(engine)["body"]


_TEXT, _JSON, _FORM = "text/plain", "application/json", "application/x-www-form-urlencoded"


def _many(pair, size=256 * 1024):
    """A JSON object of ``pair`` again and again, just under ``size``."""
    return "{" + ",".join([pair] * (size // (len(pair) + 1) - 1)) + "}"


@pytest.mark.django_db
@pytest.mark.parametrize(("body", "content_type"), [
    pytest.param(("a://" * 20_000)[: 64 * 1024], _TEXT, id="schemes"),
    pytest.param(("a:" * 40_000)[: 64 * 1024], _TEXT, id="no-slashes"),
    pytest.param("https://" + "@" * (64 * 1024), _TEXT, id="logins"),
    pytest.param("https://h/" + ";=" * (32 * 1024), _TEXT, id="params"),
    pytest.param("https://h/" + "x/" * (32 * 1024), _TEXT, id="segments"),
    pytest.param(("token" * 20_000)[: 64 * 1024], _TEXT, id="one-run"),
    pytest.param(_many('"url":"https://u:p@h/?a=b#c"'), _JSON, id="one-target-many-times"),
    pytest.param("{" + ",".join(f'"url":"https://u:p{i}@h/?a={i}"' for i in range(8_000)) + "}", _JSON,  # pragma: allowlist secret
                 id="many-targets"),
    pytest.param(_many('"q":{"url":"https://u:p@h/"}'), _JSON, id="nested-targets"),
    pytest.param("&".join(f"url=https%3A%2F%2Fu%3Ap{i}%40h%2F" for i in range(8_000)), _FORM, id="form-targets"),
])
def test_withholding_a_launch_s_target_is_linear_in_the_body(gateway, engine, body, content_type):
    """It runs before authentication, on every launch, so the shapes that would make
    it quadratic -- a URL scan from inside a run, a target withheld from the body
    once per duplicate -- are held to the text fallback's bound
    (test_defender_middleware.test_the_text_fallback_is_linear_in_the_body)."""
    app = gateway(DEFENDER_MAX_BODY_BYTES=64 * 1024)
    started = time.perf_counter()
    app(_launch(LAUNCH, body, content_type))
    assert time.perf_counter() - started < 2.0
    assert engine.asked and b"https://u:p" not in _wire(engine)


@pytest.mark.django_db
def test_neither_authorization_nor_cookie_is_ever_sent_to_the_defender(gateway, engine):
    """A tripwire: the gateway sends the engine its own X-API-Key and the
    request's path, method, user agent, query and body -- never the caller's
    Authorization or Cookie header, on any route."""
    for path in (LAUNCH, "/api/pentest/scans/", "/api/thing"):
        gateway()(_launch(path, json.dumps({"q": 1}), "application/json"))

    wire = _wire(engine)
    assert len(engine.asked) == 3
    assert PLANTED not in wire
    for asked in engine.asked:
        assert set(json.loads(asked["body"])) == {"ip", "path", "method", "user_agent", "query", "body"}


# ---------------------------------------------------------------------------
# What the engine scores is unchanged
# ---------------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("target", [
    "https://scan.example.test",
    "https://scan.example.test:8443/app/login",
    "http://10.0.0.5/",
])
def test_a_launch_whose_target_carries_no_credential_is_sent_as_before(gateway, engine, target):
    """Withholding is the identity on a target with nothing to withhold, so the
    engine sees what it always saw."""
    raw = json.dumps({"url": target, "consent": True, "note": "1' OR '1'='1"})
    gateway()(_launch(LAUNCH, raw, "application/json"))

    assert _sent(engine)["body"] == redact(raw)


@pytest.mark.django_db
@pytest.mark.parametrize("raw", [
    "url=https://scan.example.test/app&consent=true&note=%27+OR+1%3D1--",
    "url=https%3A%2F%2Fscan.example.test%2Fapp&consent=true",
])
def test_a_form_launch_whose_target_carries_no_credential_is_sent_as_it_was_written(gateway, engine, raw):
    gateway()(_launch(LAUNCH, raw, "application/x-www-form-urlencoded"))

    assert _sent(engine)["body"] == raw


@pytest.mark.django_db
def test_an_attack_in_the_target_s_path_or_in_another_field_still_reaches_the_defender(gateway, engine):
    target = "https://planted-user:PLANTED-PASS-7f3a@scan.example.test/../../etc/passwd?k=PLANTED-KEY-4e8b"  # pragma: allowlist secret
    raw = json.dumps({"url": target, "consent": True, "note": "<script>alert(1)</script>"})
    gateway()(_launch(LAUNCH, raw, "application/json"))

    body = _sent(engine)["body"]
    assert PLANTED not in _wire(engine)
    assert "/../../etc/passwd" in body and "<script>alert(1)</script>" in body


@pytest.mark.django_db
def test_a_url_with_an_attack_in_its_query_on_another_route_still_reaches_the_defender(gateway, engine):
    """Only a scan launch's target is withheld; a URL in any other body is scored as
    it was, so an attack in its query still reaches the engine."""
    raw = json.dumps({"callback": "https://cb.example.test/?q=1' OR '1'='1"})
    gateway()(_launch("/api/thing", raw, "application/json"))

    assert _sent(engine)["body"] == redact(raw)


@pytest.mark.django_db
def test_the_engine_s_refusal_of_a_launch_is_still_enforced(gateway, engine):
    engine.answer = {"allow": False, "action": "block", "reason": "malicious_signal"}
    response = gateway(DEFENDER_MONITOR_ONLY=False)(
        _launch(LAUNCH, json.dumps({"url": TARGET, "consent": True}), "application/json")
    )

    assert response.status_code == 403
    assert PLANTED not in _wire(engine)


# ---------------------------------------------------------------------------
# Stops never go through the gateway
# ---------------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.parametrize(
    "sample", STOP_REQUESTS, ids=[f"{name}-{method}-{i}" for i, (name, method, *_) in enumerate(STOP_REQUESTS)]
)
def test_no_stop_is_sent_to_the_defender(gateway, engine, sample):
    """A tripwire beside the stop files' own: every stop in canonical form,
    carrying a planted Authorization and Cookie, is served by its view and
    the engine is asked nothing -- withholding adds nothing on a stop's path."""
    _name, method, path, body, extra = sample
    app = gateway(DEFENDER_MONITOR_ONLY=False, FAILSAFE_POLL_TOKEN=POLL_TOKEN)
    path = path() if callable(path) else path
    body = body() if callable(body) else body
    request = RequestFactory().generic(
        method, path, data="" if body is None else json.dumps(body), content_type="application/json",
        HTTP_AUTHORIZATION=AUTHORIZATION, HTTP_COOKIE=COOKIE, **extra,
    )
    assert is_stop(request), f"{method} {path} is no longer a stop"

    response = app(request)

    assert response.status_code == 200 and response.content == b"the view ran"
    assert engine.asked == []
