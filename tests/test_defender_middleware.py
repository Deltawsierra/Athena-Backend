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
        # A key may begin where a redacted value stopped, on a key character: the
        # value class stops at `]`, and `]` is a key character.
        ("apikey:Token]api-keyv=%s" % SECRET, "apikey: [redacted]]api-keyv: [redacted]"),
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
        # Where the scan resumes mid-run, after a value that stopped at `]`: the
        # key that starts there folds case too.
        ("token: x]paſſword=hunter2", "token: [redacted]]paſſword: [redacted]"),
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
        # A key written once is redacted once.
        ('{"a secret": "a secret": "x"', '{"a secret": [redacted]: "x"'),
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
    absolute terms, generously, as well as in growth."""
    import time

    from audit.middleware import _redact_quoted_keys

    body = unit * (1_048_576 // len(unit))
    start = time.perf_counter()
    _redact_quoted_keys(body)
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
    text, cut = redact_within(body, limit=1_000)
    assert cut is True
    assert len(text) <= 1_000 and "xxxx" not in text
    assert redact_within(body[:900], limit=1_000)[1] is False
    # A JSON body is read whole by the structured path, and is not cut.
    assert redact_within('{"a": "' + "y" * 5_000 + '"}', limit=1_000)[1] is False


def test_a_body_redaction_shrinks_under_the_limit_is_still_reported_as_truncated(middleware, factory):
    """A long secret collapses to the marker, so what is left fits -- but the text
    pass only read the prefix, and a clean-looking body that was cut is the
    walk-past-inspection this middleware exists to prevent."""
    mw = middleware(DEFENDER_MAX_BODY_BYTES=100)
    body = "password=" + "s" * 10_000 + "\nnote: " + "n" * 10_000
    request = factory.post("/api/x/", data=body, content_type="text/plain")
    text, problem = mw._get_body(request)
    assert "sss" not in text
    assert problem is not None and "truncated" in problem


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
