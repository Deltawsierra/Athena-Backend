"""
The defender middleware is a gateway: it asks the engine for a decision on
every request and allows the request when it gets none. That default is
correct, but it used to be silent, so a wrong header or a stopped engine
switched the defensive layer off with nothing in the logs.

These tests need no engine. They use Django's RequestFactory rather than a
hand-rolled fake, because the body handling is where the defects were and a
stub carrying `body = b""` cannot reach it.
"""

import logging
from unittest import mock

from django.core.files.uploadedfile import SimpleUploadedFile

import django
import pytest
import requests
from django.conf import settings
from django.http import HttpResponse

if not settings.configured:
    settings.configure(
        DEBUG=True,
        SECRET_KEY="test-secret-key-for-middleware-tests",
        ALLOWED_HOSTS=["*"],
        DATABASES={},
        INSTALLED_APPS=[],
        CYBERENGINE_URL="http://127.0.0.1:8001",
        CYBERENGINE_OPERATOR_KEY="test-operator-key",
        DEFENDER_MONITOR_ONLY=True,
        DATA_UPLOAD_MAX_MEMORY_SIZE=2 * 1024 * 1024,
    )
    django.setup()

from django.test import RequestFactory  # noqa: E402

from audit.middleware import DefenderMiddleware, client_ip  # noqa: E402

ENGINE_URL = "http://127.0.0.1:8001/defend"
_MISSING = object()


@pytest.fixture()
def factory():
    return RequestFactory()


@pytest.fixture()
def settings_override():
    """
    Set settings for one test and put them back.

    The previous version of this file mutated global settings and never
    restored them, so a threshold set in one test leaked into the next and the
    suite passed only in the order it happened to be written in.
    """
    saved = {}

    def apply(**overrides):
        for key, value in overrides.items():
            if key not in saved:
                saved[key] = getattr(settings, key, _MISSING)
            setattr(settings, key, value)

    yield apply

    for key, value in saved.items():
        if value is _MISSING:
            delattr(settings, key)
        else:
            setattr(settings, key, value)


@pytest.fixture()
def middleware(settings_override):
    def build(**overrides):
        settings_override(**overrides)
        return DefenderMiddleware(lambda request: HttpResponse("ok"))

    return build


def engine_says(payload=None, status=200, raises=None):
    """A stand-in for requests.post."""
    if raises is not None:
        return mock.Mock(side_effect=raises)
    response = mock.Mock()
    response.status_code = status
    if isinstance(payload, Exception):
        response.json.side_effect = payload
    else:
        response.json.return_value = {"action": "allow"} if payload is None else payload
    return mock.Mock(return_value=response)


def logged(caplog):
    return " | ".join(record.getMessage() for record in caplog.records)


# ---------------------------------------------------------------------------
# What is sent to the engine
# ---------------------------------------------------------------------------


def test_the_engine_is_asked_at_the_right_url_on_the_standard_header(factory, middleware):
    """
    The engine authenticates every privileged route on X-API-Key. This
    middleware sent X-Operator-Key, so once the engine moved to the standard
    dependency every call here would have failed. The URL is asserted too: the
    call went to /defend/ against a route defined without the trailing slash,
    spending a redirect inside a 500ms budget.
    """
    post = engine_says()
    with mock.patch("audit.middleware.requests.post", post):
        middleware()(factory.get("/api/thing"))

    args, kwargs = post.call_args
    assert args[0] == ENGINE_URL
    assert kwargs["headers"]["X-API-Key"] == "test-operator-key"
    assert "X-OPERATOR-KEY" not in kwargs["headers"]
    assert kwargs["timeout"] == 0.5


def test_credentials_are_never_forwarded_to_the_engine(factory, middleware):
    """The body of every request was forwarded, including sign-in bodies."""
    post = engine_says()
    with mock.patch("audit.middleware.requests.post", post):
        middleware()(
            factory.post(
                "/api/token/",
                data='{"username":"alice","password":"hunter2"}',
                content_type="application/json",
            )
        )

    forwarded = post.call_args.kwargs["json"]
    assert forwarded["body"] == ""
    assert "hunter2" not in str(forwarded)


def test_a_sensitive_field_elsewhere_is_redacted(factory, middleware):
    post = engine_says()
    with mock.patch("audit.middleware.requests.post", post):
        middleware()(
            factory.post(
                "/api/pentest/scan/",
                data='{"url":"https://x.test","api_key":"sk-live-123","note":"hi"}',
                content_type="application/json",
            )
        )

    body = post.call_args.kwargs["json"]["body"]
    assert "sk-live-123" not in body
    assert "[redacted]" in body
    assert "https://x.test" in body, "the rest of the body is still inspectable"


def test_an_uploaded_file_is_not_copied_into_the_engine(factory, middleware):
    """
    The file itself is never forwarded, but the ordinary fields beside it are.

    Skipping multipart wholesale was a complete bypass of inspection: the same
    payload that was read as JSON went unread as a form.
    """
    upload = SimpleUploadedFile("evidence.bin", b"x" * 100, content_type="application/octet-stream")
    post = engine_says()
    with mock.patch("audit.middleware.requests.post", post):
        middleware()(
            factory.post(
                "/api/pentest/scan/",
                data={"note": "1 OR 1=1", "password": "hunter2", "f": upload},
            )
        )

    body = post.call_args.kwargs["json"]["body"]
    assert "xxxxxxxx" not in body, "the uploaded file was copied into the engine"
    assert "1+OR+1%3D1" in body or "1 OR 1=1" in body, "the form fields were not inspected"
    assert "hunter2" not in body
    assert "[redacted]" in body


def test_the_log_analysis_endpoint_is_not_scored_as_the_callers_own_behaviour(
    factory, middleware
):
    """
    Its body is attack text an analyst deliberately submitted for inspection.
    Feeding it to the gateway meant pasting one hostile log line got the
    analyst's own address blocked from every endpoint for five minutes.
    """
    post = engine_says()
    with mock.patch("audit.middleware.requests.post", post):
        middleware()(
            factory.post(
                "/api/detection/defender/text/",
                data={"text": "GET /shell?x=1; cat /etc/passwd"},
            )
        )

    assert post.call_args is None, "the analysis endpoint was sent to the gateway"


def test_a_body_too_large_to_inspect_is_reported_not_silently_emptied(
    factory, middleware, settings_override, caplog
):
    """
    A payload padded past DATA_UPLOAD_MAX_MEMORY_SIZE made request.body raise.
    A bare except swallowed it and the engine saw an empty body, so the same
    injection that was blocked at 43 bytes went through at 3 MB, in silence.
    """
    # The bound is set here rather than inherited, so the test states the
    # condition it is about.
    settings_override(DATA_UPLOAD_MAX_MEMORY_SIZE=2048)
    oversized = factory.post(
        "/api/thing",
        data='{"q":"' + "A" * 8192 + '"}',
        content_type="application/json",
    )

    post = engine_says()
    with caplog.at_level(logging.WARNING, logger="audit.middleware"):
        with mock.patch("audit.middleware.requests.post", post):
            middleware()(oversized)

    assert post.call_args.kwargs["json"]["body"] == ""
    assert "could not be inspected" in logged(caplog)


def test_static_paths_are_not_sent_to_the_engine(factory, middleware):
    post = engine_says()
    with mock.patch("audit.middleware.requests.post", post):
        middleware()(factory.get("/static/app.css"))

    post.assert_not_called()


# ---------------------------------------------------------------------------
# How a decision is enforced
# ---------------------------------------------------------------------------


def test_a_block_decision_is_enforced_when_not_monitoring_only(factory, middleware):
    with mock.patch(
        "audit.middleware.requests.post",
        engine_says({"action": "block", "allow": False, "reason": "sqli"}),
    ):
        result = middleware(DEFENDER_MONITOR_ONLY=False)(factory.get("/api/thing"))

    assert result.status_code == 403


@pytest.mark.parametrize("action", ["deny", "BLOCK", "reject", "drop", ""])
def test_a_refusal_is_honoured_whatever_the_engine_calls_it(factory, middleware, action):
    """
    Only the exact string "block" was enforced, so "deny", "BLOCK" or any new
    spelling on the engine side silently disabled enforcement. The engine also
    sends an explicit allow boolean, and it was being thrown away.
    """
    with mock.patch(
        "audit.middleware.requests.post",
        engine_says({"action": action, "allow": False, "reason": "x"}),
    ):
        result = middleware(DEFENDER_MONITOR_ONLY=False)(factory.get("/api/thing"))

    assert result.status_code == 403, f"action {action!r} was let through"


def test_a_block_is_recorded_rather_than_discarded_in_monitor_mode(
    factory, middleware, caplog
):
    """
    Monitor mode is the shipped default. It made a round trip on every request,
    received block decisions, and discarded them: a monitor that monitored
    nothing.
    """
    with caplog.at_level(logging.WARNING, logger="audit.middleware"):
        with mock.patch(
            "audit.middleware.requests.post",
            engine_says({"action": "block", "allow": False, "reason": "sqli"}),
        ):
            result = middleware(DEFENDER_MONITOR_ONLY=True)(factory.get("/api/thing"))

    assert result.status_code == 200
    assert "would have blocked" in logged(caplog)


def test_a_throttle_answers_429_rather_than_sleeping(factory, middleware):
    """Sleeping spent one of our own workers on the caller's behalf."""
    with mock.patch(
        "audit.middleware.requests.post",
        engine_says({"action": "throttle", "allow": True, "block_seconds": 30}),
    ):
        result = middleware(DEFENDER_MONITOR_ONLY=False)(factory.get("/api/thing"))

    assert result.status_code == 429
    assert result["Retry-After"] == "30"


def test_a_decision_that_is_not_an_object_does_not_500_every_request(
    factory, middleware, caplog
):
    """Valid JSON of the wrong shape reached .get() and raised AttributeError."""
    with caplog.at_level(logging.WARNING, logger="audit.middleware"):
        with mock.patch("audit.middleware.requests.post", engine_says(["allow"])):
            result = middleware(DEFENDER_MONITOR_ONLY=False)(factory.get("/api/thing"))

    assert result.status_code == 200
    assert "not an object" in logged(caplog)


def test_a_body_that_is_not_json_is_reported(factory, middleware, caplog):
    with caplog.at_level(logging.WARNING, logger="audit.middleware"):
        with mock.patch(
            "audit.middleware.requests.post", engine_says(ValueError("no json"))
        ):
            result = middleware()(factory.get("/api/thing"))

    assert result.status_code == 200
    assert "not JSON" in logged(caplog)


# ---------------------------------------------------------------------------
# Failure visibility
# ---------------------------------------------------------------------------


def test_a_refused_key_is_logged_rather_than_passing_in_silence(
    factory, middleware, caplog
):
    with caplog.at_level(logging.WARNING, logger="audit.middleware"):
        with mock.patch("audit.middleware.requests.post", engine_says(status=403)):
            result = middleware()(factory.get("/api/thing"))

    assert result.status_code == 200, "the request is still allowed"
    assert "refused the operator key" in logged(caplog)


def test_an_unreachable_engine_is_logged(factory, middleware, caplog):
    with caplog.at_level(logging.WARNING, logger="audit.middleware"):
        with mock.patch(
            "audit.middleware.requests.post",
            engine_says(raises=requests.ConnectionError("refused")),
        ):
            result = middleware()(factory.get("/api/thing"))

    assert result.status_code == 200
    assert "unreachable" in logged(caplog)


def test_a_half_dead_engine_still_escalates(factory, middleware, caplog):
    """
    The counter was consecutive and reset on every success, so an engine
    failing half the time never produced a single error line even though half
    the traffic was going uninspected.
    """
    failing = engine_says(raises=requests.ConnectionError("refused"))
    working = engine_says()
    app = middleware(DEFENDER_FAILURE_ALERT_AFTER=3)

    with caplog.at_level(logging.WARNING, logger="audit.middleware"):
        for _ in range(8):
            with mock.patch("audit.middleware.requests.post", failing):
                app(factory.get("/api/thing"))
            with mock.patch("audit.middleware.requests.post", working):
                app(factory.get("/api/thing"))

    assert any(record.levelno == logging.ERROR for record in caplog.records)


def test_the_first_alert_is_not_suppressed_on_a_freshly_booted_machine(
    factory, middleware, caplog
):
    """
    time.monotonic() counts from an arbitrary point, and on a machine that has
    just booted, such as a CI runner, that point is near zero. The "have I
    alerted recently" sentinel started at 0.0, so the first alert read as
    having just happened and was suppressed. Every failure after the threshold
    then logged nothing at all.
    """
    failing = engine_says(raises=requests.ConnectionError("refused"))
    app = middleware(DEFENDER_FAILURE_ALERT_AFTER=3)

    with caplog.at_level(logging.WARNING, logger="audit.middleware"):
        with mock.patch(
            "audit.middleware.time.monotonic", side_effect=[0.1 * i for i in range(1, 40)]
        ):
            with mock.patch("audit.middleware.requests.post", failing):
                for _ in range(6):
                    app(factory.get("/api/thing"))

    assert any(record.levelno == logging.ERROR for record in caplog.records)


def test_neither_the_operator_key_nor_a_password_reaches_a_log(
    factory, middleware, caplog
):
    with caplog.at_level(logging.DEBUG, logger="audit.middleware"):
        with mock.patch(
            "audit.middleware.requests.post",
            engine_says(raises=requests.ConnectionError("http://127.0.0.1:8001 failed")),
        ):
            middleware()(
                factory.post(
                    "/api/thing",
                    data='{"password":"hunter2"}',
                    content_type="application/json",
                )
            )

    assert "test-operator-key" not in logged(caplog)
    assert "hunter2" not in logged(caplog)


# ---------------------------------------------------------------------------
# Whose address is it
# ---------------------------------------------------------------------------


def test_a_forwarded_for_header_is_ignored_without_a_trusted_proxy(factory):
    """
    This address is the only key the engine's rate limiter and block table use.
    Trusting the header let a caller rotate it to evade rate limiting, or forge
    one request to get someone else's address blocked.
    """
    request = factory.get("/api/thing", HTTP_X_FORWARDED_FOR="1.2.3.4")
    request.META["REMOTE_ADDR"] = "10.0.0.9"

    assert client_ip(request) == "10.0.0.9"


def test_a_forwarded_for_header_is_used_behind_a_declared_proxy(
    factory, settings_override
):
    settings_override(DEFENDER_TRUSTED_PROXY_COUNT=1)
    request = factory.get("/api/thing", HTTP_X_FORWARDED_FOR="9.9.9.9, 203.0.113.7")
    request.META["REMOTE_ADDR"] = "10.0.0.9"

    # One proxy in front of us appended the address it saw, which is the
    # rightmost entry a client could not have written.
    assert client_ip(request) == "203.0.113.7"


# ---------------------------------------------------------------------------
# Redaction, from an adversarial run that leaked the secret in 14 of 30 bodies
# ---------------------------------------------------------------------------

SECRET = "SUPERSECRETVALUE12345"


@pytest.mark.parametrize(
    ("content_type", "body"),
    [
        ("application/json", '{"password": "%s"}' % SECRET),
        ("application/json", '{"pwd": "a\\"%s"}' % SECRET),
        ("application/json", '{"password": {"v": "%s"}}' % SECRET),
        ("application/json", '{"token": ["%s"]}' % SECRET),
        ("application/json", '{"outer": {"api_key": "%s"}}' % SECRET),
        ("application/json", '{"private_key": "%s"}' % SECRET),
        ("application/json", '{"otp": "%s"}' % SECRET),
        ("application/x-www-form-urlencoded", "username=bob&password=%s" % SECRET),
        ("application/x-www-form-urlencoded", "X-Api-Key=%s" % SECRET),
        ("text/plain", "Authorization: Bearer %s" % SECRET),
    ],
)
def test_a_credential_never_reaches_the_engine(factory, middleware, content_type, body):
    """
    The redactor was one regex over a JSON string value, so a form body, a
    bearer token in text, a non-string JSON value and an escaped quote in the
    value all forwarded the secret to another service's logs.
    """
    post = engine_says()
    request = factory.post("/api/pentest/scan/", data=body, content_type=content_type)
    with mock.patch("audit.middleware.requests.post", post):
        middleware()(request)

    forwarded = post.call_args.kwargs["json"]["body"]
    assert SECRET not in forwarded
    assert "[redacted]" in forwarded


def test_a_credential_in_the_query_string_is_redacted_too(factory, middleware):
    """QUERY_STRING was copied through with no redaction path at all."""
    post = engine_says()
    with mock.patch("audit.middleware.requests.post", post):
        middleware()(factory.get("/api/pentest/scans/?token=%s&page=2" % SECRET))

    query = post.call_args.kwargs["json"]["query"]
    assert SECRET not in query
    assert "page=2" in query, "the rest of the query is still inspectable"


def test_an_attack_payload_in_an_ordinary_field_reaches_the_engine_intact(factory, middleware):
    """Redaction must not mangle what the engine is being asked to look at."""
    post = engine_says()
    request = factory.post(
        "/api/pentest/scan/",
        data="q=%27+OR+1%3D1--&password=" + SECRET,
        content_type="application/x-www-form-urlencoded",
    )
    with mock.patch("audit.middleware.requests.post", post):
        middleware()(request)

    forwarded = post.call_args.kwargs["json"]["body"]
    assert "%27+OR+1%3D1--" in forwarded
    assert SECRET not in forwarded


def test_a_secret_at_the_truncation_boundary_is_redacted_and_the_cut_is_reported(
    factory, middleware, settings_override, caplog
):
    """
    Truncation ran before redaction, so a secret straddling the limit lost its
    closing quote, missed the pattern, and was forwarded in clear. The cut
    itself was silent, which is the walk-past-inspection bug at a lower
    threshold.
    """
    limit = 2048
    padding = "A" * (limit + 100)
    body = '{"note":"%s","password":"%s"}' % (padding, SECRET)
    assert len(body) > limit

    post = engine_says()
    request = factory.post("/api/pentest/scan/", data=body, content_type="application/json")
    with caplog.at_level(logging.WARNING), mock.patch("audit.middleware.requests.post", post):
        middleware(DEFENDER_MAX_BODY_BYTES=limit)(request)

    forwarded = post.call_args.kwargs["json"]["body"]
    assert SECRET not in forwarded
    assert len(forwarded) <= limit
    assert any("truncated" in record.getMessage() for record in caplog.records)


@pytest.mark.parametrize("action", ["deny", "DENIED", "reject", "Refused", "BLOCK"])
def test_every_spelling_of_no_is_a_refusal(factory, middleware, action):
    """
    The comment claimed "deny" was covered. It was not: only the literal
    "block" was, so a decision of {"action": "deny"} was permission.
    """
    post = engine_says({"allow": True, "action": action, "reason": "x"})
    with mock.patch("audit.middleware.requests.post", post):
        response = middleware(DEFENDER_MONITOR_ONLY=False)(factory.get("/api/pentest/scans/"))

    assert response.status_code == 403


@pytest.mark.parametrize(
    "forwarded",
    ["not-an-address", "1.2.3.4:8080", "999.999.999.999", "for=1.2.3.4", "a" * 300, ""],
)
def test_a_forwarded_value_that_is_not_an_address_falls_back_to_the_socket(
    factory, settings_override, forwarded
):
    """
    Whatever the header held became the key in the engine's rate limiter and
    block table, so `1.2.3.4:8080` and `1.2.3.4` were different callers.
    """
    settings_override(DEFENDER_TRUSTED_PROXY_COUNT=1)
    request = factory.get("/api/pentest/scans/", HTTP_X_FORWARDED_FOR=forwarded)
    request.META["REMOTE_ADDR"] = "10.0.0.9"

    assert client_ip(request) == "10.0.0.9"


def test_a_trusted_forwarded_address_is_still_used(factory, settings_override):
    settings_override(DEFENDER_TRUSTED_PROXY_COUNT=1)
    request = factory.get("/api/pentest/scans/", HTTP_X_FORWARDED_FOR="203.0.113.5, 10.0.0.1")
    request.META["REMOTE_ADDR"] = "10.0.0.9"

    assert client_ip(request) == "10.0.0.1"


def test_a_proxy_count_that_is_not_a_number_does_not_break_every_request(
    factory, settings_override
):
    settings_override(DEFENDER_TRUSTED_PROXY_COUNT="abc")
    request = factory.get("/api/pentest/scans/", HTTP_X_FORWARDED_FOR="203.0.113.5")
    request.META["REMOTE_ADDR"] = "10.0.0.9"

    assert client_ip(request) == "10.0.0.9"


def test_the_failure_window_does_not_lose_failures_under_concurrency(middleware):
    """
    One instance serves every worker thread, and the window was a
    read-modify-write across two statements: 32 threads lost 40% of the
    failures, so the alert fired late exactly when load was high.
    """
    import threading

    instance = middleware(DEFENDER_FAILURE_WINDOW_SECONDS=300, DEFENDER_FAILURE_ALERT_AFTER=10**9)
    threads = [
        threading.Thread(target=lambda: [instance._record_failure("x") for _ in range(200)])
        for _ in range(16)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(instance._recent_failures) == 16 * 200


# ---------------------------------------------------------------------------
# The text fallback, which runs before authentication on every route
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "body",
    [
        pytest.param("[" * (64 * 1024), id="brackets"),
        pytest.param("[" * (32 * 1024) + "]" * (32 * 1024), id="nested-past-the-parser"),
        pytest.param(("token" * 20_000)[: 64 * 1024], id="sensitive-parts-in-one-run"),
        pytest.param(("a:" * 40_000)[: 64 * 1024], id="separators"),
        pytest.param(("apikey:x]" * 10_000)[: 64 * 1024], id="value-stops-on-a-key-char"),
        pytest.param("password:" + "\n" * (64 * 1024 - 9), id="whitespace-to-backtrack"),
    ],
)
def test_the_text_fallback_is_linear_in_the_body(factory, middleware, body):
    """A body the JSON path cannot parse fell to one regex with a sensitive-part
    alternation between two unbounded runs of key characters, a class that
    includes brackets. Eight kilobytes of `[` held a worker for seven seconds,
    before authentication. The forwarding cap is 64 KiB; every shape here used to
    take minutes at that size and must now take well under a second."""
    import time

    post = engine_says()
    request = factory.post("/api/pentest/scan/", data=body, content_type="text/plain")
    started = time.perf_counter()
    with mock.patch("audit.middleware.requests.post", post):
        middleware(DEFENDER_MAX_BODY_BYTES=64 * 1024)(request)
    assert time.perf_counter() - started < 2.0


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # A key may begin where a redacted value stopped cleanly, just after a `]`
        # that is itself a key character ...
        ("apikey:Token] api-keyv=%s" % SECRET, "apikey: [redacted]] api-keyv: [redacted]"),
        # ... but a value that stops at `]` with more of itself after it has no
        # certain end, and is redacted to the end of the line, key and all.
        ("apikey:Token]api-keyv=%s" % SECRET, "apikey: [redacted]"),
        # A quoted key right after other key characters.
        ('ab"password": %s' % SECRET, 'ab"password": [redacted]'),
        # A key after a non-sensitive pair.
        ("name: bob password: %s" % SECRET, "name: bob password: [redacted]"),
        # The value runs to the end of the line for a colon.
        ("Authorization: Bearer %s\nnext" % SECRET, "Authorization: [redacted]\nnext"),
        # ... and to the next separator for an equals sign.
        ("api-key=%s&page=2" % SECRET, "api-key: [redacted]&page=2"),
        # A value that is whitespace before a separator is still what follows the key.
        ("auth: ,rest", "auth: [redacted],rest"),
        ("Token=\t", "Token: [redacted]"),
        # Nothing after the key at all: kept, and nothing invented.
        ("password:", "password:"),
        ("password:\n", "password:\n"),
        # Not a secret.
        ("name: bob", "name: bob"),
    ],
)
def test_the_text_fallback_redacts_what_the_single_pattern_did(text, expected):
    """Pinned against the pattern this scan replaced; a differential run of 1.2
    million generated inputs found no case where the two disagree."""
    from audit.middleware import _redact_text

    assert _redact_text(text) == expected


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Letters whose case folds into ASCII: under the pattern this scan replaced
        # (compiled re.I) they were part of the key token, and the value redacted.
        ("paſſword=hunter2", "paſſword: [redacted]"),
        ("ſession=abc123", "ſession: [redacted]"),
        ("client_secret=x&paſſ=y", "client_secret: [redacted]&paſſ: [redacted]"),
        ("apiKey: v", "apiKey: [redacted]"),
        # Where the scan resumes after a value that stopped at `]`: the key that
        # starts there folds case too ...
        ("token: x] paſſword=hunter2", "token: [redacted]] paſſword: [redacted]"),
        # ... and with no delimiter after the `]`, the rest of the line is the value.
        ("token: x]paſſword=hunter2", "token: [redacted]"),
    ],
)
def test_the_text_fallback_folds_case_as_the_pattern_it_replaced_did(text, expected):
    from audit.middleware import _redact_text

    assert _redact_text(text) == expected


@pytest.mark.parametrize("key", ["paſſword", "ſession", "api_Key"])
def test_the_structured_paths_fold_case_too(key):
    """``.lower()`` keeps the long s, so the JSON and form paths forwarded the value
    the text path redacted."""
    from audit.middleware import _is_sensitive_key

    assert _is_sensitive_key(key)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # A key in any script is one token: the ö split "Passwörter" in two.
        ("Passwörter=hunter2", "Passwörter: [redacted]"),
        ("contraseña_token: abc", "contraseña_token: [redacted]"),
        # A quoted key the token scan cannot read -- a space in it -- in a body
        # that is not JSON (the trailing comma), which the structured path would
        # have redacted.
        ('{"client secret": "hunter2",}', '{"client secret": [redacted],}'),
        ('{"my \\"secret\\" key": v,}', '{"my \\"secret\\" key": [redacted],}'),
        # ...and only those: a readable key is judged once, and a harmless one kept.
        ('{"password": "x", "display name": "bob",}', '{"password": [redacted], "display name": "bob",}'),
    ],
)
def test_the_text_fallback_redacts_what_the_structured_path_would(text, expected):
    from audit.middleware import _redact_text

    assert _redact_text(text) == expected


def test_the_quoted_key_pass_stays_linear():
    import time

    from audit.middleware import _redact_text

    for unit in ('"a', '"\\"', '"x' + "a" * 127):
        small, large = unit * 2000, unit * 8000
        start = time.perf_counter()
        _redact_text(small)
        t_small = time.perf_counter() - start
        start = time.perf_counter()
        _redact_text(large)
        t_large = time.perf_counter() - start
        assert t_large < max(t_small, 0.002) * 12, (unit[:4], t_small, t_large)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # JSON escapes in a quoted key: judged as the structured path would read it.
        ('{"p\\u0061ssword": "HUNTER2Z",}', '{"p\\u0061ssword": [redacted],}'),
        # ß folds to ss only under casefold -- on every path.
        ("paßword=abc", "paßword: [redacted]"),
        ('{"seßion": "x",}', '{"seßion": [redacted],}'),
        # No length bound on a quoted key any more.
        ('{"' + "billing " * 16 + 'secret": "v",}', '{"' + "billing " * 16 + 'secret": [redacted],}'),
        # A key written once is redacted once -- and a value followed by a colon
        # rather than a delimiter has no certain end, so the line goes with it.
        ('{"a secret": "a secret": "x"', '{"a secret": [redacted]'),
    ],
)
def test_the_text_fallback_judges_keys_as_the_structured_path_does(text, expected):
    from audit.middleware import _redact_text

    assert _redact_text(text) == expected


@pytest.mark.parametrize("key", ["private-key", "SESSİON", "paßword", "Api-Key"])
def test_one_judgement_for_every_path(key):
    """The structured path forwarded `private-key` and `SESSİON`, which the text
    path redacted; the text path forwarded `paßword`, which the structured path
    redacted. One predicate now answers for all three."""
    from audit.middleware import _is_sensitive_key, _redact_structure, _redact_text

    assert _is_sensitive_key(key)
    assert _redact_structure({key: "S3CR3T"}) == {key: "[redacted]"}
    assert "S3CR3T" not in _redact_text(f'{{"{key}": "S3CR3T",}}')


@pytest.mark.parametrize("unit", ['"\\', '"a', '\\"', '"x' + "a" * 127])
def test_the_quoted_key_pass_visits_each_character_once(unit):
    """A body of `"\\` repeated made the per-position pattern backtrack 128
    characters at every quote: 10 MB took 34 s, before authentication. Bounded in
    absolute terms, generously, as well as in growth. The quoted keys are read in
    the same pass as the token keys now, so the whole pass is what is timed."""
    import time

    from audit.middleware import _redact_text

    body = unit * (1_048_576 // len(unit))
    start = time.perf_counter()
    _redact_text(body)
    assert time.perf_counter() - start < 1.0


# ---- Round 6: memory, a bounded text pass, and keys after a stray quote. ----


@pytest.mark.parametrize(
    "body",
    [
        '"' + "a" * 2_000_000,  # one unterminated string
        'password: "' + "a" * 2_000_000 + '"',  # one enormous quoted secret
        '{"k": "' + "a" * 2_000_000 + '", "x": [',  # a string inside text that is not JSON
    ],
)
def test_a_long_string_costs_no_memory_beyond_itself(body):
    """`"(?:[^"\\\\]|\\\\.)*"` kept backtracking state for every character it matched
    -- about 120 bytes each -- so one 10 MB string took 1.3 GB before
    authentication. The possessive pattern keeps none."""
    import tracemalloc

    from audit.middleware import redact

    tracemalloc.start()
    try:
        redact(body)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 12 * len(body), f"{peak / len(body):.1f} bytes per character"


def test_the_text_pass_is_bounded_and_says_the_body_was_cut():
    """The text fallback ran over the whole body before the caller kept 64 KiB of
    it: ten seconds for 10 MB of `"":`. It now redacts a prefix, and reports the cut
    even when what redaction left would have fit."""
    from audit.middleware import redact_within

    body = "password=" + "x" * 50 + "&" + '"":' * 100_000
    text, cut, _doubtful = redact_within(body, limit=1_000)
    assert cut is True
    assert len(text) <= 1_000 and "xxxx" not in text
    assert redact_within(body[:900], limit=1_000)[1] is False
    # A JSON body within the limit is read whole by the structured path, and is
    # not cut; one past it is not parsed whole either -- see the test below.
    assert redact_within('{"a": "yy", "password": "x"}', limit=1_000) == (
        '{"a":"yy","password":"[redacted]"}',
        False,
        False,
    )
    assert redact_within('{"a": "' + "y" * 5_000 + '"}', limit=1_000)[1] is True


def test_a_body_redaction_shrinks_under_the_limit_is_still_reported_as_truncated(middleware, factory):
    """A long secret collapses to the marker, so what is left fits -- but the text
    pass only read the prefix, and a clean-looking body that was cut is the
    walk-past-inspection this middleware exists to prevent.

    Here the WHOLE body redacts to 28 characters, under the 100 kept, so only the
    bounded pass can say it was cut; and the size it names is the prefix it read,
    four times what is kept."""
    mw = middleware(DEFENDER_MAX_BODY_BYTES=100)
    body = "password=" + "s" * 10_000 + "\nnote: n"
    request = factory.post("/api/x/", data=body, content_type="text/plain")
    text, problem = mw._get_body(request)
    assert text == "password: [redacted]"
    assert problem == "request body was truncated at 400 bytes for inspection"


@pytest.mark.parametrize(
    "text",
    [
        '{"size": 5", "client secret": "S3CR3T",}',
        '{"description": "set password: x", "client secret": "S3CR3T",}',
        '{"size": 5", "p\\u0061ssword": "S3CR3T",}',
        '{"size": 5", "$password": "S3CR3T",}',
        '{"note": "a password=hunter2 b",\n"client secret": "S3CR3T",}',
    ],
)
def test_a_stray_quote_costs_nothing_after_it(text):
    """The quoted-key pass paired quotes from the start of the text, and text on
    this path is not JSON: one stray quote, or a value the token scan cut short,
    flipped the pairing and every later key it could not read went through."""
    from audit.middleware import redact

    assert "S3CR3T" not in redact(text)


@pytest.mark.parametrize(
    "text",
    [
        '{"Password:": "S3CR3T",}',  # a key that ends in the separator
        '{"Password=": "a,S3CR3T",}',
        '{"tokens": ["t1", "S3CR3T"],}',  # a list of secrets
        '{"credentials": {"user": "bob", "key": "S3CR3T"},}',
        "{'password': 'S3CR3T', 'otp': '12,S3CR3T'}",  # single quotes
        '{"password\t": "S3CR3T",}',  # a literal tab in the key
        '{"p\\u0061ssword\\x": "S3CR3T",}',  # a key JSON cannot decode at all
        '{"client secret": [redacted]S3CR3T,}',  # the marker only begins the value
        '{"client secret" : "S3CR3T",}',  # whitespace before the colon
        '{"client secret": "abc\\\nS3CR3T",}',  # an escaped newline inside the value
        '{"note": "a\\\nb", "client secret": "S3CR3T",}',  # ... and before the key
    ],
)
def test_the_text_path_redacts_what_the_structured_path_would(text):
    from audit.middleware import redact

    assert "S3CR3T" not in redact(text)


def test_a_form_key_is_judged_decoded():
    from audit.middleware import redact

    assert "S3CR3T" not in redact("p%61ssword=S3CR3T&x=1", form=True)


# ---- Round 7: a value whose end is not certain is redacted to the end of its line. ----


def _outcome(text):
    """What the redactor forwards for ``text``, and whether it said a value had no
    certain end."""
    from audit.middleware import redact_within

    redacted, _cut, doubtful = redact_within(text)
    return redacted, doubtful


@pytest.mark.parametrize(
    "text",
    [
        # A bracketed or quoted value with more of the value after it.
        "password=[Summer]2024-S3CR3T",
        "user=bob&password={x}S3CR3T&page=2",
        "password: [redacted]S3CR3T",
        '{"password": [a][b]S3CR3T,}',
        "password: [x] S3CR3T",
        '{"password": "abc" "S3CR3T",}',
        # SQL's and YAML's doubled quote, which is an escape, not an end.
        "UPDATE users SET password = 'o''S3CR3T' WHERE id=1",
        "password: 'it''s S3CR3T'",
        # An unquoted value that stopped where it may have opened something.
        "password: abc]S3CR3T",
        "password: a[b,S3CR3T]",
        'password: x"y,S3CR3T"',
        # A quote or a bracket that never closes.
        '{"password": "abc,S3CR3T',
        '{"tokens": ["x", "], S3CR3T}',
        '{"tokens": ["a", "S3CR3T"',
    ],
)
def test_a_value_without_a_certain_end_is_redacted_to_the_end_of_its_line(text):
    """Each of these ended the value wherever the scanner could pair a quote or a
    bracket, and forwarded the rest of the secret after it. Where the end is not
    certain the value now runs to the end of the line, and that is said."""
    redacted, doubtful = _outcome(text)
    assert "S3CR3T" not in redacted
    assert doubtful is True


def test_redacting_to_the_end_of_the_line_leaves_the_next_line_alone():
    assert _outcome("password: [x] S3CR3T\nq: UNION SELECT") == (
        "password: [redacted]\nq: UNION SELECT",
        True,
    )


@pytest.mark.parametrize(
    "text",
    [
        # Keys that end in their separator: the pair they look like is the key.
        '{"New Password:": "S3CR3T", "q": "UNION SELECT",}',
        '{"Confirm password:": "S3CR3T", "q": "UNION SELECT",}',
        '{"$token:": "S3CR3T", "q": "UNION SELECT",}',
        '{"api token=": "S3CR3T", "q": "UNION SELECT",}',
        "{'Password:': 'S3CR3T', 'q': 'UNION SELECT'}",
        "{'api_key=': 'S3CR3T', 'q': 'UNION SELECT'}",
        # Single-quoted keys and strings, as Python writes them.
        "{'client secret': 'S3CR3T', 'q': 'UNION SELECT'}",
        "{'new password': 'S3CR3T', 'q': 'UNION SELECT'}",
        "{'tokens': ['a]b', 'S3CR3T'], 'q': 'UNION SELECT'}",
        "{'credentials': {'note': '}', 'key': 'S3CR3T'}, 'q': 'UNION SELECT'}",
        # A string that begins with a colon, after an unquoted key: read back from
        # that colon, the text before it looked like a quoted key.
        '{name: "bob", user_token: "abc", sep: ":", "client secret": "S3CR3T", q: "UNION SELECT"}',
        # A key that lost its opening quote.
        '{password": "S3CR3T", "q": "UNION SELECT",}',
        'x password": S3CR3T, q: UNION SELECT',
        '{"a": 1, client_secret": "S3CR3T", "q": "UNION SELECT",}',
        # A quoted key whose last word names nothing: only the quoted reading
        # sees the secret in it -- after an equals sign, where no key is
        # expected, or after a separator of its own with no value.
        '"client secret key" = "S3CR3T"\nq = "UNION SELECT"',
        '{"a": 1 "client secret key": "S3CR3T", "q": "UNION SELECT",}',
        '{"token:,client secret key": "S3CR3T", "q": "UNION SELECT",}',
        # A harmless pair written inside a quoted key casts no doubt on it.
        '{"note: x, client secret": "S3CR3T", "q": "UNION SELECT",}',
        # A key that ends in its separator, whose value begins with a delimiter --
        # wherever in the body a key can open.
        '{"New Password:": ",S3CR3T", "q": "UNION SELECT",}',
        '{"a": 1, "New Password:": ",S3CR3T", "q": "UNION SELECT",}',
        '{\n  "New Password:": ",S3CR3T",\n  "q": "UNION SELECT",\n}',
        # ... and where no key can open, when what follows the closing quote is
        # not a string that ends cleanly.
        'x"New Password:": "S3CR3T", "q": "UNION SELECT",',
    ],
)
def test_a_key_is_read_whatever_its_quotes_and_the_field_after_it_is_kept(text):
    redacted, doubtful = _outcome(text)
    assert "S3CR3T" not in redacted
    assert "UNION SELECT" in redacted
    assert doubtful is False


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        # Whitespace and the next key end a value, as in logfmt.
        ('level=info password="x y" q="UNION SELECT"', 'level=info password: [redacted] q="UNION SELECT"'),
        # So does a closing bracket before a delimiter, of any kind.
        (
            'login(user="bob", password="S3CR3T", q="UNION SELECT")',
            'login(user="bob", password: [redacted], q="UNION SELECT")',
        ),
        (
            '{"a": {"password": "S3CR3T"} , "q": "UNION SELECT",}',
            '{"a": {"password": [redacted]} , "q": "UNION SELECT",}',
        ),
        # A quote that is the last thing in an unquoted value closes a string
        # around the whole pair; it is not the start of one inside the value.
        ('{"msg": "token: abc", "q": "UNION SELECT",}', '{"msg": "token: [redacted], "q": "UNION SELECT",}'),
        ("password: S3CR3T\nq: UNION SELECT", "password: [redacted]\nq: UNION SELECT"),
        ("user=bob&password=S3CR3T&q=UNION SELECT", "user=bob&password: [redacted]&q=UNION SELECT"),
        # A quoted value and then any of the delimiters.
        ('password="S3CR3T"&q=UNION SELECT', "password: [redacted]&q=UNION SELECT"),
        ('a=1; session="S3CR3T"; q=UNION SELECT', "a=1; session: [redacted]; q=UNION SELECT"),
        ('login(password="S3CR3T"); q="UNION SELECT"', 'login(password: [redacted]); q="UNION SELECT"'),
        # A value that runs to the end of its line leaves nothing on it to lose,
        # whatever it holds.
        ("password: a[b\nq: UNION SELECT", "password: [redacted]\nq: UNION SELECT"),
        # The next line at the key's own depth is the next key, not more value.
        ("db:\n  password: S3CR3T\n  host: UNION SELECT", "db:\n  password: [redacted]\n  host: UNION SELECT"),
        # A "=" in a list reads back, over three lines, to the string before it:
        # a quoted key that parses as nothing, inside the list's own value. The
        # list goes and no more -- its lines are not indented under the q8 line
        # the read-back began on, but under the line of its separator.
        (
            '{\nq8: "UNION SELECT",\ns: {\n  signature: [\n    "=",\n    "S3CR3T"\n  ],\n  q9: "UNION SELECT"\n}\n}',
            '{\nq8: "UNION SELECT",\ns: {\n  signature: [redacted],\n  q9: "UNION SELECT"\n}\n}',
        ),
    ],
)
def test_a_value_that_ends_cleanly_keeps_what_follows_it(text, expected):
    assert _outcome(text) == (expected, False)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("{'a, token: S3CR3T, b': 'S3CR3T', 'q': 'UNION SELECT'}", "{'a, token: [redacted], 'q': 'UNION SELECT'}"),
        # The pair's value ends inside the key; the key's runs on past it.
        ("x'a, token: y, b': 'S3CR3T', 'q': 'UNION SELECT'", "x'a, token: [redacted], 'q': 'UNION SELECT'"),
        # The pair's value holds the key's closing quote; the key's own value is
        # after that quote. Either reading alone forwarded the other's secret.
        ('{"a token: \'b": \', S3CR3T\', "q": "UNION SELECT",}', '{"a token: [redacted], "q": "UNION SELECT",}'),
        # The pair's value ends on its line; the key's runs on to the next.
        ('x"a token: \'a\'b": [\n"S3CR3T"\n], "q": "UNION SELECT"', 'x"a token: [redacted], "q": "UNION SELECT"'),
        # Every pair inside, not only the first: the second one's value is the
        # one that runs furthest.
        ('{"a token: x, secret: [": 1,\n"S3CR3T"], "q": "UNION SELECT"}', '{"a token: [redacted]'),
        # A string value that begins with a colon, after a sensitive unquoted key,
        # reads back as a quoted key; and a missing comma puts a real key in the
        # same place. Which is which cannot be told, so both values go.
        ('{a: "b", user_token: ":", "client secret": "S3CR3T", q: "UNION SELECT"}', '{a: "b", user_token: [redacted]'),
        # Only one reading parses at all here -- but that one has no certain end
        # either, so the line it took is still said to be lost.
        ('{a: "b", user_token: [":", "S3CR3T"] y, "q": "UNION SELECT"}', '{a: "b", user_token: [redacted]'),
        ('{"a": 1 "New Password:": ",S3CR3T", "q": 2,}', '{"a": 1 "New Password: [redacted], "q": 2,}'),
        ('{"a": 1 "x token: \'b": \', S3CR3T\', "q": 2}', '{"a": 1 "x token: [redacted], "q": 2}'),
        # An apostrophe in prose reads back as a quote too.
        ("Here's my token: S3CR3T and the users': list\nq: UNION SELECT", "Here's my token: [redacted]\nq: UNION SELECT"),
    ],
)
def test_a_pair_written_inside_a_quoted_key_is_redacted_with_the_keys_value(text, expected):
    """The quoted key is copied out as it was written, so a pair inside it would
    be copied with it. Every value goes -- through the latest end -- and the line
    is reported, since the readings disagree about where the key was."""
    assert _outcome(text) == (expected, True)


def test_a_key_is_not_read_back_past_the_quote_that_closed_the_last_one():
    # `"a b "` ends in a space, so no token key closes it and the scan does not
    # move past it. Read back from `c"` into it, `": token, c"` was a key.
    text = '{"a b ": token, c": "keep",}'
    assert _outcome(text) == (text, False)


@pytest.mark.parametrize(
    "unit",
    [
        'a: "b", user_token: ":", ',  # a key read back from a string's own quote
        '"New Password:": "x", ',  # a key that ends in its separator
        'x"New Password:": 12, ',  # ... opening where no key can
        'x"a token: 1, b": 2, ',  # a pair inside a quoted key
    ],
)
def test_the_text_pass_stays_linear_when_a_key_is_doubted(unit):
    """Each of these read a value to the end of the line and then threw it away,
    and the next key on the line did the same: 128 KB of them took two seconds,
    before authentication."""
    import time

    from audit.middleware import _redact_text

    timings = []
    for size in (16_000, 128_000):
        body = "{" + unit * (size // len(unit))
        start = time.perf_counter()
        _redact_text(body)
        timings.append(time.perf_counter() - start)
    assert timings[1] < max(timings[0], 0.005) * 24, timings


def test_a_value_carried_onto_indented_lines_is_redacted_with_them():
    """Under `private_key: |` the key itself is on the indented lines after it,
    and those went through in clear."""
    text = "user: bob\nprivate_key: |\n  -----BEGIN KEY-----\n  S3CR3T\n\n  MORE\nq: UNION SELECT"
    assert _outcome(text) == ("user: bob\nprivate_key: [redacted]\nq: UNION SELECT", True)


@pytest.mark.parametrize(
    "body",
    [
        '{"password": "' + "A" * 900 + ",S3CR3T" * 40 + '",}',
        '{"client secret": "' + "A" * 900 + "\nS3CR3T" * 40 + '",}',
        'password="' + "A" * 900 + "&S3CR3T" * 40 + '"',
    ],
)
def test_a_cut_inside_a_quoted_value_takes_the_rest_of_the_prefix(body):
    """The cut left the quote open, the value then stopped at the first comma,
    line break or `&` inside the secret, and the rest of it was forwarded."""
    from audit.middleware import redact_within

    text, cut, _doubtful = redact_within(body, limit=1_000)
    assert cut is True
    assert "S3CR3T" not in text


def test_a_secret_the_prefix_cuts_through_is_not_forwarded(middleware, factory):
    mw = middleware(DEFENDER_MAX_BODY_BYTES=100)
    body = '{"note": "hi", "password": "correct horse,' + "S3CR3T-battery" * 50 + '",}'
    request = factory.post("/api/x/", data=body, content_type="application/json")
    text, problem = mw._get_body(request)
    assert text == '{"note": "hi", "password": [redacted]'
    assert problem.startswith("request body was truncated at 400 bytes for inspection")


def test_a_sensitive_key_planted_before_an_attack_is_reported(middleware, factory):
    """Redacting to the end of the line takes the attack with the secret. That
    must not look like a clean inspection."""
    body = "note: hi\npassword: [x] ' UNION SELECT username, pw FROM users --"
    request = factory.post("/api/x/", data=body, content_type="text/plain")
    text, problem = middleware()._get_body(request)
    assert text == "note: hi\npassword: [redacted]"
    assert problem == (
        "request body could not be fully inspected: a value after a sensitive key had "
        "no certain end and was redacted to the end of its line"
    )


def test_a_body_whose_values_all_end_cleanly_is_not_reported(middleware, factory):
    body = '{"password": "S3CR3T", "q": "UNION SELECT",}'
    request = factory.post("/api/x/", data=body, content_type="application/json")
    text, problem = middleware()._get_body(request)
    assert text == '{"password": [redacted], "q": "UNION SELECT",}'
    assert problem is None


def test_a_json_body_past_the_prefix_is_never_parsed_whole(middleware, factory):
    """It was parsed, rebuilt and serialised whole before the cut: 9 MB of tiny
    keys took four seconds and 180 MB, before authentication, to keep 64 KiB."""
    import json

    from audit import middleware as module

    mw = middleware(DEFENDER_MAX_BODY_BYTES=1_000)
    body = "{" + ",".join('"k%d":0' % i for i in range(5_000)) + "}"
    assert len(body) > 10 * 4 * 1_000
    parsed = []
    real_loads = json.loads

    def loads(text, *args, **kwargs):
        parsed.append(len(text))
        return real_loads(text, *args, **kwargs)

    request = factory.post("/api/x/", data=body, content_type="application/json")
    with mock.patch.object(module.json, "loads", loads):
        text, problem = mw._get_body(request)
    assert max(parsed, default=0) <= 4 * 1_000
    assert text.startswith('{"k0":0,"k1":0,')
    assert problem == "request body was truncated at 1000 bytes for inspection"


@pytest.mark.parametrize(
    ("body", "forwarded"),
    [
        ({"username": "bob", "password": "S3CR3T"}, '{"username":"bob","password":"[redacted]"}'),
        # Every `&` chunk has its `=` -- there is only one -- but it opens like JSON.
        ({"q": "a=b", "password": "S3CR3T"}, '{"q":"a=b","password":"[redacted]"}'),
    ],
)
def test_a_json_body_labelled_as_a_form_is_still_redacted(middleware, factory, body, forwarded):
    """jQuery posts `JSON.stringify(...)` with the form content type by default. A
    chunk with no `=` was kept verbatim, and in a JSON body that was all of it."""
    import json

    request = factory.post(
        "/api/x/", data=json.dumps(body), content_type="application/x-www-form-urlencoded; charset=UTF-8"
    )
    assert middleware()._get_body(request) == (forwarded, None)


def test_a_body_is_read_in_the_charset_it_declares(middleware, factory):
    """Read as UTF-8, a UTF-16 body had a NUL between every character: no key
    matched, and the password went through one strip away from clear."""
    import json

    body = json.dumps({"username": "bob", "password": "S3CR3T"}).encode("utf-16")
    request = factory.generic(
        "POST", "/api/x/", data=body, content_type="application/json; charset=utf-16"
    )
    text, problem = middleware()._get_body(request)
    assert "S3CR3T" not in text.replace(chr(0), "")
    assert text == '{"username":"bob","password":"[redacted]"}'
    assert problem is None


def test_a_byte_its_charset_cannot_decode_does_not_stop_the_body_being_read(middleware, factory):
    request = factory.generic(
        "POST", "/api/x/", data=b'{"password": "S3CR3T\xff", "q": "UNION SELECT"}', content_type="application/json"
    )
    assert middleware()._get_body(request) == ('{"password":"[redacted]","q":"UNION SELECT"}', None)


def test_an_unknown_charset_is_read_as_the_default(middleware, factory):
    request = factory.generic(
        "POST", "/api/x/", data=b'{"password": "S3CR3T"}', content_type="application/json; charset=no-such"
    )
    assert middleware()._get_body(request) == ('{"password":"[redacted]"}', None)


@pytest.mark.parametrize("charset", ["base64", "zlib", "punycode"])
def test_a_charset_that_is_not_read_here_is_reported(middleware, factory, charset):
    """base64 and zlib are codecs the parser would transform the body with --
    undone before authentication, a decompression bomb -- and punycode's decoder
    is slower than linear: a second for 80 KB."""
    request = factory.generic(
        "POST", "/api/x/", data=b"eyJwYXNzd29yZCI6ICJ4In0=", content_type=f"application/json; charset={charset}"
    )
    _text, problem = middleware()._get_body(request)
    assert problem == "request body could not be fully inspected: its charset is not one read here"


@pytest.mark.parametrize(
    ("query", "forwarded"),
    [
        ("debug&token=S3CR3T", "debug&token: [redacted]"),
        ('{"password":"S3CR3T"}', '{"password":"[redacted]"}'),
    ],
)
def test_a_query_string_that_is_not_a_form_is_read_as_text_too(factory, middleware, query, forwarded):
    post = engine_says()
    with mock.patch("audit.middleware.requests.post", post):
        middleware()(factory.get("/api/x/", QUERY_STRING=query))
    assert post.call_args.kwargs["json"]["query"] == forwarded


def test_a_query_string_value_with_no_certain_end_is_reported(factory, middleware, caplog):
    post = engine_says()
    with caplog.at_level(logging.WARNING, logger="audit.middleware"):
        with mock.patch("audit.middleware.requests.post", post):
            middleware()(factory.get("/api/x/", QUERY_STRING='debug&note=token:"x&q=UNION+SELECT'))
    assert post.call_args.kwargs["json"]["query"] == "debug&note=token: [redacted]"
    assert "query string could not be fully inspected" in logged(caplog)


# Shapes that a one-line mutant of the scanner forwarded while every test above
# passed. Each asserts what the mutant broke: no secret leaks, the field after a
# value survives, or the cut is reported as the size it really was.


@pytest.mark.parametrize(
    "text",
    [
        '{"tokens": ["a]", "S3CR3T"],}',  # a closing bracket inside a string in the list
        '{"tokens": ["x", "], S3CR3T}',  # a string inside the list that never closes
        '&]:"password"=[}{"S3CR3T"',  # the closing bracket is followed by more value
        '{"a\\": b password": "S3CR3T",}',  # an escaped quote and a colon inside a key
        '{"password:"S3CR3T", "a": 1,}',  # a token whose quoted value follows the colon
        '"Password:": "S3CR3T",',  # a quoted key ending in its separator, at offset 0
    ],
)
def test_no_secret_survives_the_shapes_that_escaped_the_suite(text):
    from audit.middleware import redact

    assert "S3CR3T" not in redact(text)


@pytest.mark.parametrize(
    "text",
    [
        '{"tokens": ["a\\\nb"], "q": "UNION SELECT",}',  # an escaped line break in a listed string
        '{"credentials": {"k": "v"}, "q": "UNION SELECT",}',  # an object closes at its brace
    ],
)
def test_a_bracketed_value_does_not_swallow_the_field_after_it(text):
    redacted, doubtful = _outcome(text)
    assert '"q": "UNION SELECT"' in redacted
    assert doubtful is False


def test_a_bracketed_value_is_replaced_whole_and_nothing_more():
    assert _outcome('{"tokens": ["a"], "q": 1,}') == ('{"tokens": [redacted], "q": 1,}', False)


def test_the_quote_that_closed_one_key_never_opens_the_next():
    # The walk back stops short of the previous candidate's closing quote: taken
    # as an opening quote, it made `": token, b"` a key, and "token" is in it.
    text = '{"a": token, b": "keep",}'
    assert _outcome(text) == (text, False)


def test_a_key_is_judged_by_how_json_reads_its_escapes():
    # `"o\tp<TAB>"` is o, tab, p, tab, which names nothing. Dropping the backslash
    # read "otp", and the value under a harmless key was lost.
    text = '{"o\\tp\t": "keep",}'
    assert _outcome(text) == (text, False)


def test_a_backslash_at_the_floor_still_escapes_the_quote_after_it():
    # The quote after the backslash at offset 0 is escaped, so it opens no key and
    # the 1 is not the value of a "password x".
    text = '\\"password x": 1, "q": 2'
    assert _outcome(text) == (text, False)


def test_a_body_exactly_at_the_limit_is_not_cut():
    from audit.middleware import redact_within

    body = "note: " + "x" * 994
    assert len(body) == 1000
    assert redact_within(body, limit=1000) == (body, False, False)
    assert redact_within(body + "x", limit=1000)[1] is True


def test_the_text_pass_reads_four_times_what_is_kept(middleware, factory):
    # 220 raw characters, 31 after redaction: inside the 4x prefix, so read whole.
    request = factory.post("/api/x/", data="password=" + "s" * 200 + "\nnote: tail", content_type="text/plain")
    assert middleware(DEFENDER_MAX_BODY_BYTES=100)._get_body(request) == (
        "password: [redacted]\nnote: tail",
        None,
    )


def test_the_truncation_reported_is_the_one_applied(middleware, factory):
    request = factory.post("/api/x/", data="note: " + "n" * 1000, content_type="text/plain")
    text, problem = middleware(DEFENDER_MAX_BODY_BYTES=100)._get_body(request)
    assert len(text) == 100
    assert problem == "request body was truncated at 100 bytes for inspection"


# ---- Round 8: a text pass linear for any body, and no value ends inside the next field. ----

_PREFIX = 4 * 64 * 1024  # what the middleware reads of a body, at the default limit


def _fit(unit, size, head="", tail=""):
    """``head``, ``unit`` repeated, ``tail``: ``size`` characters. A ``tail`` of
    None closes every unit, a bracket: `[[[...]]]`."""
    if tail is None:
        count = (size - len(head)) // 2
        return head + unit * count + "]" * count
    return head + unit * ((size - len(head) - len(tail)) // len(unit)) + tail


@pytest.mark.parametrize(
    ("unit", "head", "tail"),
    [
        pytest.param("token: a ", "'", "': x", id="pairs-inside-one-quoted-key"),
        pytest.param("token=a ", "'", "'=x", id="equals-pairs-inside-one-quoted-key"),
        pytest.param("token: [", "'", "': x", id="lists-inside-one-quoted-key"),
        pytest.param("x token:", "'", "': x", id="keys-ending-in-their-separator"),
        pytest.param(' x" token: y', "password=a", ', "z"', id="keys-before-one-string"),
        pytest.param('"', "", "", id="quotes"),
        pytest.param("\"'", "", "", id="alternating-quotes"),
        pytest.param("'a': ", "", "", id="quoted-keys"),
        pytest.param("password: x ", "", "", id="keys-on-one-line"),
        pytest.param("[{", "", "", id="deep-brackets"),
        pytest.param("\\" * 15 + '"', "", "", id="backslash-runs"),
        pytest.param(', password: "a;b"', "api_key=a", "", id="strings-inside-an-equals-value"),
        pytest.param("[", "password=a, ", None, id="groups-nested-inside-a-value"),
        pytest.param("\n", "password:", "", id="a-separator-then-line-breaks"),
    ],
)
def test_the_text_pass_is_linear_in_the_prefix_for_any_shape(unit, head, tail):
    """One quoted key holding `token: a ` 29,000 times took 27 seconds at the
    256 KiB the middleware reads, before authentication, on every content type
    inspected: each pair inside it was read to the end of the line, and the line
    was the whole body. A list in each pair took minutes.

    Timed at the prefix and at an eighth of it: linear time grows eightfold,
    quadratic sixty-four-fold. The bound on the ratio is loose for a slow or busy
    machine, the absolute one generous; both fail by a wide margin on the
    quadratic pass. A pass already slow at an eighth fails there, rather than
    spend minutes on the prefix."""
    import time

    from audit.middleware import redact_within

    def timed(size, runs):
        body = _fit(unit, size, head, tail)
        best = None
        for _ in range(runs):
            start = time.perf_counter()
            redact_within(body, limit=_PREFIX)
            elapsed = time.perf_counter() - start
            best = elapsed if best is None else min(best, elapsed)
            if elapsed > 1.0:
                break
        return best

    small = timed(_PREFIX // 8, 3)
    assert small < 1.0, small
    large = timed(_PREFIX, 1)
    assert large < 2.0, (small, large)
    assert large < 20 * max(small, 0.02), (small, large)


@pytest.mark.parametrize(
    "text",
    [
        # The reported shapes: an unquoted value runs over the next field and
        # stops at a delimiter inside that field's string.
        'api_key=abc123, password: ";SECRETTAIL"',
        'token=abc password=";SECRETTAIL"',
        'token=abc, password: "&SECRETTAIL"',
        # ... at a line break inside it,
        'api_key=abc123, password: ";SECRET\nSECRETTAIL"',
        'api_key=a, tokens: ["b;\nSECRETTAIL"]',
        # ... or, with no quote at all, at a delimiter of its own separator where
        # the key it swallowed would not stop: after a colon, a value runs on.
        "api_key=abc, password: x;SECRETTAIL",
        "token=abc my password: x&SECRETTAIL",
        # A value with no certain end redacted to the end of its line -- which is
        # inside the next field's string.
        "pwd= a, 'name' = \"b\"; \"password\":'\r\nSECRETTAIL'",
        # A line carried over under a value, likewise.
        "token: a\n  otp = 'x\rSECRETTAIL'",
        # ... and so the end of the line after any value with no certain end: one
        # that swallowed a pair, and one with more after its string.
        'api_key=a, password: ";SECRETTAIL"; token: \'x\nSECRETTAIL\'',
        "password: \"a\" b, token: 'x\nSECRETTAIL'",
        # A read that begins inside a string: the value of the quoted key read
        # back from the quote that opens session_id's value.
        "'a'; session_id= ': b[x]c,', \"new password\": 'd\r\nSECRETTAIL'",
        # A bracket inside a string, read as a group, closed in the next field's
        # string and hid the quote that opened the secret.
        "client_secret=x, \"new password\"=\t'y= {= '\n\"otp\": z & 'session_id'='}: w\n\rSECRETTAIL'",
    ],
)
def test_a_value_never_ends_inside_the_next_fields_string(text):
    """Each of these forwarded SECRETTAIL and called the body cleanly inspected."""
    redacted, doubtful = _outcome(text)
    assert "SECRETTAIL" not in redacted
    assert doubtful is True


def test_the_reported_body_is_redacted_and_reported(middleware, factory):
    request = factory.post(
        "/api/x/", data='api_key=abc123, password: ";SECRETTAIL"', content_type="text/plain"
    )
    text, problem = middleware()._get_body(request)
    assert text == "api_key: [redacted]"
    assert problem == (
        "request body could not be fully inspected: a value after a sensitive key had "
        "no certain end and was redacted to the end of its line"
    )


def test_a_quote_after_the_value_still_closes_the_string_around_the_pair():
    # A quote after a character of the value, before the delimiter, is the end of
    # a string around the whole pair, as before: the field after it is kept.
    assert _outcome('{"msg": "token: abc", "q": "UNION SELECT",}') == (
        '{"msg": "token: [redacted], "q": "UNION SELECT",}',
        False,
    )
    # And a key inside an unquoted value that stops no later than the value does
    # changes nothing: `password: x` ends at the same comma.
    assert _outcome("api_key: a password: x, q: UNION SELECT") == (
        "api_key: [redacted], q: UNION SELECT",
        False,
    )


def test_no_secret_survives_and_no_separate_field_is_dropped_unsaid():
    """Differential property check (the full run was 56,000 bodies; cf5ec50
    leaked in 3,246 of them). Pairs under sensitive keys -- bare, quoted with any
    content, lists -- among cleanly quoted `UNION SELECT` fields, every key
    spelling, both separators, every joiner, and the reported shape on purpose: a
    bare value followed by a quoted secret that starts with one of the bare
    value's own delimiters. No marker under a sensitive key may be forwarded,
    and a field no bare value swallowed may not be dropped while the body is
    called cleanly inspected."""
    import json
    import random
    import re

    from audit.middleware import redact_within

    rng = random.Random(8)
    counter = [0]

    def tag(prefix):
        counter[0] += 1
        return f"{prefix}{counter[0]:06d}"

    stops = {":": ",}]\r\n", "=": "&;\r\n"}
    tricky = [",", ";", "&", "\n", "\r", "]", "}", "[", "{", "(", '"', "'", "\\", ":", "=", " ", "ab", ": ", "= "]

    def content(first=""):
        parts = [first or (rng.choice(";&,\n]}'\"") if rng.random() < 0.35 else ""), tag("VAL")]
        for _ in range(rng.randint(0, 2)):
            parts += ["".join(rng.choice(tricky) for _ in range(rng.randint(0, 3))), tag("VAL")]
        return "".join(parts)

    def dq(s):
        return json.dumps(s)

    def sq(s):
        return "'" + s.replace("\\", "\\\\").replace("'", "\\'") + "'"

    def key(name):
        r = rng.random()
        if re.fullmatch(r"[\w.-]+", name) and r < 0.4:
            return name
        return dq(name) if r < 0.75 else sq(name)

    sensitive = ["password", "token", "api_key", "secret", "Authorization", "otp", "client-secret", "new password"]
    leaks, silent = [], []
    for _ in range(1500):
        fields = []
        for i in range(rng.randint(1, 6)):
            sep = rng.choice([": ", ":", "=", " = ", "=\t"])
            if fields and fields[-1][1] == "bare" and rng.random() < 0.5:
                bare = fields[-1][2]
                quote = rng.choice([dq, sq])
                joiner = rng.choice([" ", ", "] if bare == "=" else [" ", "; ", "&"])
                fields.append(("sens", "quoted", sep.strip(), key(rng.choice(sensitive[:7])) + sep
                               + quote(content(rng.choice(stops[bare]))), joiner))
            elif rng.random() < 0.55:
                r = rng.random()
                if r < 0.3:
                    kind, value = "bare", tag("VAL") + rng.choice(["", "-a.b", "/z"])
                elif r < 0.85:
                    kind, value = "quoted", rng.choice([dq, sq])(content())
                else:
                    items = [rng.choice([dq, sq])(content()) for _ in range(rng.randint(1, 2))]
                    kind, value = "list", "[" + rng.choice([", ", ",\n  "]).join(items) + "]"
                fields.append(("sens", kind, sep.strip(), key(rng.choice(sensitive)) + sep + value, None))
            else:
                atk = tag("ATK")
                fields.append(("atk", atk, None, key(rng.choice(["q", "name", "note"])) + sep
                               + rng.choice([dq, sq])(atk + " UNION SELECT"), None))
        text, active, separate = "", set(), []
        for i, (role, kind, sep, rendered, joiner) in enumerate(fields):
            if i:
                joiner = joiner or rng.choice([", ", ",", "\n", "\r\n", "&", "; ", " ", "\n  "])
                if joiner == " " and rendered[0] in "\"'" and " " in rendered.split(sep or ":", 1)[0]:
                    joiner = ", "  # a space and then a key with a space in it ends nothing
                active = {s for s in active if not any(c in stops[s] for c in joiner)}
                text += joiner
            if role == "atk" and not active:
                separate.append(kind)
            text += rendered
            if kind == "bare":
                active.add(sep)
        if rng.random() < 0.3:
            text = "{" + text + rng.choice(["}", ",}", ""])
        out, _cut, doubtful = redact_within(text, limit=_PREFIX)
        if any(marker in out for marker in re.findall(r"VAL\d{6}", text)):
            leaks.append((text, out))
        if not doubtful and any(atk not in out for atk in separate):
            silent.append((text, out))
    assert leaks == []
    assert silent == []
