"""
A log file uploaded to POST /api/detection/defender/file/ is bounded, and is read within the bound.

The view read ``uploaded_file.read().decode()`` on whatever it was sent, with no limit on size
or kind, and sent the text on to the engine. It now refuses a body that declares itself over the
cap before parsing it (413), a type that is not a log's (415), a file over the cap by its size
(413), reads the rest in chunks and never past one byte over the cap, and refuses what does not
start as text (415).

Nothing refused is sent to the engine or recorded, and nothing refused is quoted back or logged.
The engine is replaced by a stub that records what it is asked.

Every credential-shaped value here is a synthetic canary.
"""

import logging
import uuid

import pytest
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from detection import log_upload
from detection.models import ThreatDetection
from detection.views import DefenderFileScanAPIView

pytestmark = pytest.mark.django_db

User = get_user_model()

# The figures are written out, not read from the module: a cap that is raised, or removed,
# must fail these tests, not move them with it.
CAP = 1024 * 1024
ENVELOPE = 16 * 1024
BOUND = CAP + ENVELOPE
URL = "/api/detection/defender/file/"
CANARY = "cnry-log-secret-8d21b7"
MULTIPART = "multipart/form-data; boundary=upload-test-boundary"

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


def _upload(client, content, *, name="app.log", content_type="text/plain"):
    return client.post(
        URL, {"uploaded_file": SimpleUploadedFile(name, content, content_type)}, format="multipart"
    )


def _exactly(size, lines):
    """``size`` bytes of log: ``lines`` first, then blank lines to the length."""
    head = ("\n".join(lines) + "\n").encode()
    return head + b"\n" * (size - len(head))


class _Tripwire:
    """A request body that must not be read: any read is recorded, then fails."""

    def __init__(self):
        self.reads = 0

    def read(self, *args):
        self.reads += 1
        raise AssertionError("the body was read")

    readline = read


class _Liar:
    """A file that says it is small and is not, and counts what is read of it."""

    name = "app.log"
    content_type = "text/plain"

    def __init__(self, total, *, size=10):
        self.total, self.size, self.served = total, size, 0

    def read(self, n=-1):
        left = self.total - self.served
        take = left if n is None or n < 0 else min(n, left)
        self.served += take
        return b"a" * take


# ---------------------------------------------------------------------------
# An oversized upload is refused, and is not read
# ---------------------------------------------------------------------------


def test_the_cap_is_one_mebibyte_and_the_bound_adds_only_the_envelope():
    """Raising the cap is a decision with a measurement behind it (see the constant's
    comment), so it is also an edit to this test. The engine's cap is the same figure."""
    assert log_upload.LOG_UPLOAD_MAX_BYTES == CAP
    assert log_upload.LOG_UPLOAD_ENVELOPE_BYTES == ENVELOPE
    assert log_upload.LOG_UPLOAD_MAX_REQUEST_BYTES == BOUND


def test_a_declared_length_over_the_bound_is_refused_before_the_body_is_read(engine):
    body = _Tripwire()
    request = APIRequestFactory().generic(
        "POST",
        URL,
        data=b"",
        content_type=MULTIPART,
        CONTENT_LENGTH=str(8 * CAP),
        **{"wsgi.input": body},
    )
    force_authenticate(request, user=_user())

    response = DefenderFileScanAPIView.as_view()(request)

    assert response.status_code == 413, response.data
    assert body.reads == 0, "the body of a request declared too large was read"
    assert engine.asked == []
    assert ThreatDetection.objects.count() == 0


def test_a_length_that_is_not_a_number_is_a_400(engine):
    request = APIRequestFactory().generic(
        "POST",
        URL,
        data=b"",
        content_type=MULTIPART,
        CONTENT_LENGTH="12e3",
        **{"wsgi.input": _Tripwire()},
    )
    force_authenticate(request, user=_user())

    response = DefenderFileScanAPIView.as_view()(request)

    assert response.status_code == 400, response.data
    assert engine.asked == []


def test_a_file_one_byte_over_the_cap_is_refused_though_it_fits_the_bound(engine):
    content = _exactly(CAP + 1, [ORDINARY])

    response = _upload(_client(), content)

    assert response.status_code == 413, response.content
    assert response.json()["detail"] == log_upload.LogUploadTooLarge.default_detail
    assert engine.asked == []
    assert ThreatDetection.objects.count() == 0


def test_a_file_that_says_it_is_over_the_cap_is_refused_before_any_read():
    liar = _Liar(total=8 * CAP, size=CAP + 1)

    with pytest.raises(log_upload.LogUploadTooLarge):
        log_upload.read_log_text(liar)

    assert liar.served == 0


def test_a_read_stops_one_byte_past_the_cap_whatever_size_the_file_says():
    """The size a parser reports can be wrong or missing; the read does not rely on it."""
    liar = _Liar(total=8 * CAP, size=10)

    with pytest.raises(log_upload.LogUploadTooLarge):
        log_upload.read_log_text(liar)

    assert liar.served == CAP + 1, f"{liar.served} of {liar.total} bytes read"


def test_a_file_with_no_size_is_read_within_the_cap():
    liar = _Liar(total=8 * CAP)
    liar.size = None

    with pytest.raises(log_upload.LogUploadTooLarge):
        log_upload.read_log_text(liar)

    assert liar.served == CAP + 1


# ---------------------------------------------------------------------------
# A file at the cap, and an ordinary log, are analysed as before
# ---------------------------------------------------------------------------


def test_a_file_exactly_at_the_cap_is_analysed(engine):
    content = _exactly(CAP, [ATTACK, ORDINARY])
    assert len(content) == CAP

    response = _upload(_client(), content)

    assert response.status_code == 201, response.content
    assert engine.asked == [content.decode()]
    assert response.json()["detected"] is True
    assert ThreatDetection.objects.get().file_name == "app.log"


def test_an_ordinary_log_is_sent_to_the_engine_as_it_always_was(engine):
    text = "\n".join([ORDINARY, ATTACK, ORDINARY]) + "\n"

    response = _upload(_client(), text.encode())

    assert response.status_code == 201, response.content
    assert engine.asked == [text]
    body = response.json()
    assert set(body) == {"id", "detected", "engine_response"}
    assert body["detected"] is True and body["engine_response"] == {"alerts": [{"type": "sql_injection"}]}


def test_what_is_not_utf_8_is_dropped_as_it_always_was(engine):
    content = b"GET /ok\n\xff\xfe broken \xc3\n" + ORDINARY.encode()

    response = _upload(_client(), content)

    assert response.status_code == 201, response.content
    assert engine.asked == [content.decode("utf-8", errors="ignore")]


# ---------------------------------------------------------------------------
# A file that is not text is refused
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "declared",
    [
        "text/plain",
        "text/plain; charset=utf-8",
        "text/csv",
        "text/x-log",
        "TEXT/PLAIN",
        "application/octet-stream",
        "application/json",
        "application/x-ndjson",
        "",
    ],
)
def test_the_types_a_log_is_sent_as_are_accepted(engine, declared):
    """A browser sends a .log file as application/octet-stream; an unnamed type too."""
    response = _upload(_client(), ATTACK.encode(), content_type=declared)

    assert response.status_code == 201, (declared, response.content)
    assert engine.asked == [ATTACK]


@pytest.mark.parametrize(
    "declared",
    [
        "image/png",
        "application/pdf",
        "application/zip",
        "application/gzip",
        "application/x-msdownload",
        "audio/mpeg",
        "video/mp4",
    ],
)
def test_a_type_that_is_not_a_log_is_refused_415(engine, declared):
    response = _upload(_client(), ATTACK.encode(), content_type=declared)

    assert response.status_code == 415, (declared, response.content)
    assert response.json()["detail"] == log_upload.LogUploadNotText.default_detail
    assert engine.asked == []
    assert ThreatDetection.objects.count() == 0


@pytest.mark.parametrize(
    "content",
    [
        pytest.param(ATTACK.encode("utf-16"), id="utf-16"),
        pytest.param(b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR", id="a png"),
        pytest.param(b"PK\x03\x04\x00\x00\x00\x00", id="a zip"),
    ],
)
def test_a_binary_sent_as_text_is_refused_415(engine, content):
    response = _upload(_client(), content, content_type="text/plain")

    assert response.status_code == 415, response.content
    assert response.json()["detail"] == log_upload.LogUploadNotText.default_detail
    assert engine.asked == []
    assert ThreatDetection.objects.count() == 0


def test_an_empty_file_is_still_a_400(engine):
    response = _upload(_client(), b"")

    assert response.status_code == 400, response.content
    assert engine.asked == []


def test_a_request_with_no_file_is_still_a_400(engine):
    response = _client().post(URL, {}, format="multipart")

    assert response.status_code == 400, response.content
    assert engine.asked == []


def test_a_caller_with_no_credentials_is_refused_and_nothing_is_asked(engine):
    response = APIClient().post(
        URL, {"uploaded_file": SimpleUploadedFile("a.log", b"x", "text/plain")}, format="multipart"
    )

    assert response.status_code in (401, 403), response.content
    assert engine.asked == []


# ---------------------------------------------------------------------------
# A refusal does not quote the file or log it
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "content, declared",
    [
        pytest.param(CANARY.encode() + b"x" * CAP, "text/plain", id="too large"),
        pytest.param(CANARY.encode() + b"\x00\x01", "text/plain", id="binary"),
        pytest.param(CANARY.encode(), f"image/{CANARY}", id="type"),
    ],
)
def test_a_refusal_says_nothing_of_the_file_and_logs_nothing_of_it(engine, caplog, content, declared):
    with caplog.at_level(logging.DEBUG):
        response = _upload(_client(), content, name=f"{CANARY}.log", content_type=declared)

    assert response.status_code in (413, 415), (response.status_code, response.content)
    assert CANARY not in response.content.decode()
    assert CANARY not in str(dict(response.items()))
    assert CANARY not in caplog.text, caplog.text
    assert engine.asked == []
