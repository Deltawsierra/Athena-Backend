"""
Log text posted to POST /api/detection/defender/text/ is bounded.

The view took ``serializers.CharField()`` with no ``max_length`` and sent whatever it was given
to the engine; only Django's request-body limit applied. It now refuses a body that declares
itself over the bound before parsing it (413), a text over the cap in characters (413, from the
serializer's ``max_length``), and a text over the cap in UTF-8 bytes (413, which is the
engine's measure and the only one that holds for text that is not ASCII).

Nothing refused is sent to the engine or recorded, and nothing refused is quoted back or logged.
The engine is replaced by a stub that records what it is asked.

Every credential-shaped value here is a synthetic canary.
"""

import json
import logging
import uuid

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from detection import log_upload
from detection.models import ThreatDetection
from detection.serializers import ThreatDetectionScanSerializer
from detection.views import DefenderTextScanAPIView

pytestmark = pytest.mark.django_db

User = get_user_model()

# The figures are written out, not read from the module: a cap that is raised, or removed,
# must fail these tests, not move them with it.
CAP = 1024 * 1024
ENVELOPE = 16 * 1024
EXPANSION = 6
BOUND = EXPANSION * CAP + ENVELOPE
URL = "/api/detection/defender/text/"
CANARY = "cnry-log-secret-4e7c2a"
SENTENCE = "A log file is at most 1048576 bytes."

ATTACK = '203.0.113.9 - - [05/Sep/2026:02:00:00 +0000] "GET /?id=1\' OR 1=1-- HTTP/1.1" 200 512'
ORDINARY = '198.51.100.7 - - [05/Sep/2026:02:00:01 +0000] "GET /index.html HTTP/1.1" 200 512'


class _Engine:
    """Stands for the engine client: records the text it is asked to analyse."""

    asked = []

    @classmethod
    def from_settings(cls):
        return cls()

    def defend_log_text(self, text):
        _Engine.asked.append(text)
        return {"alerts": [{"type": "sql_injection"}] if "OR 1=1" in text else []}


@pytest.fixture()
def engine(monkeypatch):
    _Engine.asked = []
    monkeypatch.setattr("detection.views.CyberEngineClient", _Engine)
    return _Engine


def _user():
    return User.objects.create_user(
        username=f"u-{uuid.uuid4().hex[:10]}", password=None, role=User.Roles.ANALYST
    )


def _client():
    client = APIClient()
    client.force_authenticate(user=_user())
    return client


def _json(text, **more):
    """A JSON body as Python's ``json.dumps`` writes it, which is what ``requests``' ``json=``
    sends: every non-ASCII and control character escaped."""
    return json.dumps({"content": text, **more}).encode()


def _post(client, body, *, content_type="application/json"):
    """POST ``body`` as it is, with the length a client declares for it."""
    return client.generic("POST", URL, data=body, content_type=content_type)


class _Tripwire:
    """A request body that must not be read: any read is recorded, then fails."""

    def __init__(self):
        self.reads = 0

    def read(self, *args):
        self.reads += 1
        raise AssertionError("the body was read")

    readline = read


def _declaring(length, body, *, user=None):
    """A request that declares ``length`` bytes and whose body is ``body``."""
    request = APIRequestFactory().generic(
        "POST",
        URL,
        data=b"",
        content_type="application/json",
        CONTENT_LENGTH=str(length),
        **{"wsgi.input": body},
    )
    if user is not None:
        force_authenticate(request, user=user)
    return request


def _nothing_was_asked_or_kept(engine):
    assert engine.asked == []
    assert ThreatDetection.objects.count() == 0


# ---------------------------------------------------------------------------
# An oversized body is refused, and is not read
# ---------------------------------------------------------------------------


def test_the_cap_is_the_file_views_and_the_bound_holds_the_worst_json_spelling():
    """The text is held to the file view's figure, not a second one; the engine's is the
    same. The body bound is the worst JSON spelling of a text at the cap (six bytes for
    one) and the envelope. Raising the cap is a decision with a measurement behind it, so
    it is also an edit to this test."""
    assert log_upload.LOG_UPLOAD_MAX_BYTES == CAP
    assert log_upload.LOG_UPLOAD_ENVELOPE_BYTES == ENVELOPE
    assert log_upload.LOG_TEXT_JSON_EXPANSION == EXPANSION
    assert log_upload.LOG_TEXT_MAX_REQUEST_BYTES == BOUND
    assert log_upload.LogUploadTooLarge.default_detail == SENTENCE


def test_a_declared_length_over_the_bound_is_refused_before_the_body_is_read(engine):
    body = _Tripwire()
    request = _declaring(8 * CAP, body, user=_user())

    response = DefenderTextScanAPIView.as_view()(request)

    assert response.status_code == 413, response.data
    assert response.data["detail"] == SENTENCE
    assert body.reads == 0, "the body of a request declared too large was read"
    _nothing_was_asked_or_kept(engine)


def test_a_length_that_is_not_a_number_is_a_400(engine):
    body = _Tripwire()
    request = _declaring("12e3", body, user=_user())

    response = DefenderTextScanAPIView.as_view()(request)

    assert response.status_code == 400, response.data
    assert body.reads == 0
    _nothing_was_asked_or_kept(engine)


def test_a_caller_with_no_credentials_is_refused_and_nothing_is_read(engine):
    body = _Tripwire()
    request = _declaring(8 * CAP, body)

    response = DefenderTextScanAPIView.as_view()(request)

    assert response.status_code in (401, 403), response.data
    assert body.reads == 0
    _nothing_was_asked_or_kept(engine)


# ---------------------------------------------------------------------------
# The text is held to the cap, in characters and in the bytes it is
# ---------------------------------------------------------------------------


def test_a_text_one_character_over_the_cap_is_refused_413_though_it_fits_the_bound(engine):
    body = _json("x" * (CAP + 1))
    assert len(body) <= BOUND, "this body is meant to pass the bound"

    response = _post(_client(), body)

    assert response.status_code == 413, response.content
    assert response.json()["detail"] == SENTENCE
    _nothing_was_asked_or_kept(engine)


def test_the_cap_is_in_utf8_bytes_not_characters(engine):
    """Half the cap in characters, one byte over it encoded: two bytes each."""
    text = "é" * (CAP // 2 + 1)
    assert len(text) < CAP and len(text.encode("utf-8")) == CAP + 2

    response = _post(_client(), _json(text))

    assert response.status_code == 413, response.content
    assert response.json()["detail"] == SENTENCE
    _nothing_was_asked_or_kept(engine)


@pytest.mark.parametrize(
    ("name", "text"),
    [
        pytest.param("ASCII", "a" * CAP, id="ascii"),
        pytest.param("newlines", "a" + "\n" * (CAP - 2) + "b", id="newlines"),
        pytest.param("control characters, the worst spelling", "\x01" * CAP, id="control"),
        pytest.param("two-byte characters", "é" * (CAP // 2), id="two-byte"),
        pytest.param("three-byte characters", "€" * (CAP // 3), id="three-byte"),
        pytest.param("four-byte characters", "\U0001f600" * (CAP // 4), id="four-byte"),
    ],
)
def test_a_text_at_the_cap_is_sent_to_the_engine_however_its_json_is_spelled(engine, name, text):
    """A text of exactly the cap (or the last whole character under it) is accepted in its
    worst JSON spelling: the body for control characters is six times the cap."""
    assert len(text.encode("utf-8")) <= CAP and CAP - len(text.encode("utf-8")) < 4
    body = _json(text)
    assert len(body) <= BOUND, name

    response = _post(_client(), body)

    assert response.status_code == 201, (name, response.content)
    assert engine.asked == [text]
    assert ThreatDetection.objects.count() == 1


def test_a_text_one_byte_over_the_cap_in_its_worst_spelling_is_refused(engine):
    """Six times the cap and a few bytes: still inside the bound, so it is parsed, and
    then refused for the text it carries."""
    body = _json("\x01" * (CAP + 1))
    assert CAP * EXPANSION < len(body) <= BOUND

    response = _post(_client(), body)

    assert response.status_code == 413, response.content
    assert response.json()["detail"] == SENTENCE
    _nothing_was_asked_or_kept(engine)


def test_a_log_that_ends_in_a_newline_at_the_cap_is_analysed_as_the_serializer_trims_it(engine):
    """The serializer trims a text's outer whitespace, as it always did, and the cap holds
    for what is sent on: a log of exactly the cap that ends in a newline is not over it."""
    text = ATTACK + "\n" + "x" * (CAP - len(ATTACK) - 1)
    assert len(text) == CAP
    sent = text + "\n"

    response = _post(_client(), _json(sent))

    assert response.status_code == 201, response.content
    assert engine.asked == [text]
    assert response.json()["detected"] is True


def test_a_lone_surrogate_is_still_the_serializers_400(engine):
    """JSON can spell one (``\\ud800``); Django REST framework's CharField refuses it, as it
    always did, so it never reaches the byte check."""
    body = _json("\ud800 " + ORDINARY)
    assert b"\\ud800" in body

    response = _post(_client(), body)

    assert response.status_code == 400, response.content
    _nothing_was_asked_or_kept(engine)


def test_the_byte_check_counts_a_lone_surrogate_and_does_not_raise_on_one():
    """The check is also the one place the cap is measured in bytes, so it does not depend
    on what a serializer let through: a surrogate cannot be encoded as UTF-8, and counts as
    the three bytes it would take."""
    assert log_upload.check_log_text("\ud800 " + ORDINARY) == "\ud800 " + ORDINARY
    with pytest.raises(log_upload.LogUploadTooLarge):
        log_upload.check_log_text("\ud800" * (CAP // 3 + 1))


def test_the_byte_check_holds_the_cap_exactly():
    assert log_upload.check_log_text("a" * CAP) == "a" * CAP
    with pytest.raises(log_upload.LogUploadTooLarge):
        log_upload.check_log_text("a" * (CAP + 1))
    with pytest.raises(log_upload.LogUploadTooLarge):
        log_upload.check_log_text("\u00e9" * (CAP // 2 + 1))


# ---------------------------------------------------------------------------
# The serializer holds the cap itself
# ---------------------------------------------------------------------------


def test_the_serializer_field_holds_the_cap_in_characters():
    assert ThreatDetectionScanSerializer().fields["content"].max_length == CAP


def test_the_serializer_refuses_a_text_over_the_cap_by_its_length_and_accepts_one_at_it():
    at_cap = ThreatDetectionScanSerializer(data={"content": "x" * CAP})
    over = ThreatDetectionScanSerializer(data={"content": "x" * (CAP + 1)})

    assert at_cap.is_valid(), at_cap.errors
    assert not over.is_valid()
    assert [error.code for error in over.errors["content"]] == ["max_length"]


# ---------------------------------------------------------------------------
# What the view answered before, it answers still
# ---------------------------------------------------------------------------


def test_an_ordinary_text_is_sent_to_the_engine_as_it_always_was(engine):
    text = "\n".join([ORDINARY, ATTACK, ORDINARY])

    response = _client().post(URL, {"content": text}, format="json")

    assert response.status_code == 201, response.content
    assert engine.asked == [text]
    body = response.json()
    assert set(body) == {"id", "detected", "engine_response"}
    assert body["detected"] is True and body["engine_response"] == {"alerts": [{"type": "sql_injection"}]}
    assert ThreatDetection.objects.get().file_name == "text_input"


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param({}, id="no content"),
        pytest.param({"content": ""}, id="empty"),
        pytest.param({"content": "   \n  "}, id="blank"),
        pytest.param({"content": None}, id="null"),
        pytest.param({"content": ["a"]}, id="a list"),
    ],
)
def test_a_body_that_is_not_text_is_still_a_400(engine, payload):
    response = _client().post(URL, payload, format="json")

    assert response.status_code == 400, response.content
    _nothing_was_asked_or_kept(engine)


def test_a_caller_with_no_credentials_is_refused_through_the_client_too(engine):
    response = APIClient().post(URL, {"content": ORDINARY}, format="json")

    assert response.status_code in (401, 403), response.content
    _nothing_was_asked_or_kept(engine)


# ---------------------------------------------------------------------------
# A refusal does not quote the text or log it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "refusal",
    ["too many characters", "too many bytes", "worst spelling", "not a string"],
)
def test_a_refusal_says_nothing_of_the_text_and_logs_nothing_of_it(engine, caplog, refusal):
    if refusal == "too many characters":
        body = _json(CANARY + "x" * CAP)
    elif refusal == "too many bytes":
        body = _json(CANARY + "é" * (CAP // 2))
    elif refusal == "worst spelling":
        body = _json(CANARY + "\x01" * CAP)
    else:
        body = json.dumps({"content": {"note": CANARY}}).encode()

    with caplog.at_level(logging.DEBUG):
        response = _post(_client(), body)

    assert response.status_code in (400, 413), (refusal, response.status_code, response.content)
    assert CANARY not in response.content.decode()
    assert CANARY not in str(dict(response.items()))
    assert CANARY not in caplog.text, caplog.text
    _nothing_was_asked_or_kept(engine)
