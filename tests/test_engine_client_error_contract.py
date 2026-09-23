"""
EngineError is this client's whole contract with its callers.

Nine places handle an engine that cannot answer -- pentest/views.py,
detection/views.py, ai_engine/services/preflight.py and the
approve_deployment command -- and every one of them catches EngineError and
nothing else. Anything the client raises that is not an EngineError does not
reach those handlers: it reads as a bug in this process, returns a 500, and
tells an operator nothing about the engine.

resp.json() used to be called outside the try blocks that produce
EngineError, so two answers a real engine can give escaped the contract: a
2xx whose body is not JSON, and a 2xx whose body is JSON but not an object.

The responses here are real requests.Response objects rather than mocks, so
.json() and .text behave exactly as they do against a live engine -- a mock
would only prove the test agrees with itself about which exception decoding
raises.
"""

from unittest import mock

import pytest
import requests

from ai_engine.services.cyberengine_client import (
    MAX_BODY_EXCERPT,
    CyberEngineClient,
    EngineError,
)


def _response(status: int, body: str) -> requests.Response:
    resp = requests.Response()
    resp.status_code = status
    resp._content = body.encode("utf-8")
    resp.headers["Content-Type"] = "application/json"
    resp.url = "http://127.0.0.1:8001/api/scan"
    return resp


@pytest.fixture
def client():
    return CyberEngineClient(base_url="http://127.0.0.1:8001", api_key="k")


# The bodies a 2xx can carry that are not a result.
NOT_A_RESULT = [
    # A proxy in front of the engine answering with its own page.
    ("<html><body>502 Bad Gateway</body></html>", "not JSON"),
    # A response truncated mid-object.
    ('{"findings": [', "not JSON"),
    # An empty 200.
    ("", "not JSON"),
    # Valid JSON that is not the object every caller and annotation expects.
    ("null", "NoneType"),
    ("[]", "list"),
    ('"ok"', "str"),
    ("42", "int"),
]


@pytest.mark.parametrize(("body", "expected"), NOT_A_RESULT)
def test_a_get_that_is_not_a_result_is_an_engine_error(client, body, expected):
    with mock.patch(
        "ai_engine.services.cyberengine_client.requests.get",
        return_value=_response(200, body),
    ), pytest.raises(EngineError) as raised:
        client._get("/api/scans/abc")

    assert expected in str(raised.value)
    assert "/api/scans/abc" in str(raised.value)


@pytest.mark.parametrize(("body", "expected"), NOT_A_RESULT)
def test_a_post_that_is_not_a_result_is_an_engine_error(client, body, expected):
    with mock.patch(
        "ai_engine.services.cyberengine_client.requests.post",
        return_value=_response(200, body),
    ), pytest.raises(EngineError) as raised:
        client.classify_cve("CVE-2024-0001")

    assert expected in str(raised.value)
    assert "/api/classify-cve" in str(raised.value)


@pytest.mark.parametrize(("body", "expected"), NOT_A_RESULT)
def test_a_log_file_upload_that_is_not_a_result_is_an_engine_error(client, body, expected):
    """
    The third body read. It builds its own request rather than going through
    _post, which is exactly how a reader loses track of one.
    """
    with mock.patch(
        "ai_engine.services.cyberengine_client.requests.post",
        return_value=_response(200, body),
    ), pytest.raises(EngineError) as raised:
        client.defend_log_file(b"an auth log", "auth.log")

    assert expected in str(raised.value)
    assert "/api/defend-log/file" in str(raised.value)


def test_a_scan_the_engine_answered_badly_is_an_engine_error_not_an_attribute_error(client):
    """
    The failure as a caller meets it.

    run_scan calls .get() on whatever _post returned. A JSON null answered the
    annotation's dict with None, and the first .get() raised AttributeError --
    past every handler, naming nothing about the engine.
    """
    with mock.patch(
        "ai_engine.services.cyberengine_client.requests.post",
        return_value=_response(200, "null"),
    ), pytest.raises(EngineError):
        client.run_scan("https://customer.example")


def test_an_engine_that_answers_properly_is_still_read(client):
    """
    The negative control. A guard that refuses everything passes every test
    above and breaks the product.
    """
    with mock.patch(
        "ai_engine.services.cyberengine_client.requests.post",
        return_value=_response(200, '{"done": true, "result": {"findings": []}}'),
    ):
        assert client.run_scan("https://customer.example") == {"findings": []}


def test_a_long_bad_body_is_quoted_in_full_size_but_not_in_full(client):
    """
    The engine's body is not bounded by anything this process controls, and an
    exception message becomes a log line and an API error field.
    """
    body = "x" * 40000
    with mock.patch(
        "ai_engine.services.cyberengine_client.requests.get",
        return_value=_response(200, body),
    ), pytest.raises(EngineError) as raised:
        client._get("/api/scans/abc")

    message = str(raised.value)
    assert len(message) < MAX_BODY_EXCERPT * 2
    assert "40000 characters total" in message


def test_a_long_error_body_is_quoted_in_full_size_but_not_in_full(client):
    """The same bound on the non-2xx path, which quotes the body as well."""
    with mock.patch(
        "ai_engine.services.cyberengine_client.requests.get",
        return_value=_response(500, "y" * 40000),
    ), pytest.raises(EngineError) as raised:
        client._get("/api/scans/abc")

    message = str(raised.value)
    assert len(message) < MAX_BODY_EXCERPT * 2
    assert "40000 characters total" in message
    assert "500" in message


@pytest.mark.parametrize("method", ["get", "post"])
def test_an_unreachable_engine_keeps_its_cause(client, method):
    """
    The transport failure is re-raised as EngineError. Without `from`, the
    original is reported as an error that happened while handling this one,
    which reads as a fault in the error handling rather than the fault itself.
    """
    boom = requests.ConnectionError("connection refused")
    with mock.patch(
        f"ai_engine.services.cyberengine_client.requests.{method}", side_effect=boom
    ), pytest.raises(EngineError) as raised:
        if method == "get":
            client._get("/api/scans/abc")
        else:
            client.classify_cve("CVE-2024-0001")

    assert raised.value.__cause__ is boom


def test_an_unreachable_engine_keeps_its_cause_on_the_file_upload(client):
    boom = requests.ConnectionError("connection refused")
    with mock.patch(
        "ai_engine.services.cyberengine_client.requests.post", side_effect=boom
    ), pytest.raises(EngineError) as raised:
        client.defend_log_file(b"an auth log", "auth.log")

    assert raised.value.__cause__ is boom
