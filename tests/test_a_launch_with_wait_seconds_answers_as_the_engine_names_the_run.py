"""A launch asked to wait ``wait_seconds`` answers as soon as the engine names the run.

``POST /api/pentest/scan/`` waited for the run in full: the engine was asked to hold
the launch inline for ``SCAN_INLINE_WAIT_SECONDS`` and the run was then collected for
``SCAN_COLLECT_SECONDS`` (ten minutes), so a client that cannot hold a call that long
-- the dashboard, which polls the engine live by the run's id -- never got the run's
id back in time. The body may now carry ``wait_seconds``: how long the launch waits in
all, 0 to ``SCAN_COLLECT_SECONDS``. The engine's inline wait is the smaller of it and
``SCAN_INLINE_WAIT_SECONDS``; the run is collected for the rest; ``0`` is one read of
the run and then the 202 that always said the run was still going, now naming where
the scan is read (``status_url``) and where its record is collected once the run ends
(``collect_url``). Absent, the launch is what it was. A value that is not a number of
seconds in range is refused, 400, before anything is sent. The recipient a launch names
is kept on the row from the start, so a scan collected later is still mailed its report.

The engine here is the real HTTP stub of tests/test_a_lost_launch_answer_reads_unknown
(athena-engine at 79ba4af as this backend reaches it); the deadline arithmetic is
proved against a clock the test owns, so nothing here depends on wall time.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from django.utils import timezone
from rest_framework.test import APIClient

from ai_engine.services import cyberengine_client as cec
from pentest.models import Engagement, PentestScan
from tests.test_a_lost_launch_answer_reads_unknown import COMPLETED, SCAN_URL, TARGET, Engine

pytestmark = pytest.mark.django_db

User = get_user_model()
KEY = "HTTP_IDEMPOTENCY_KEY"
RECIPIENT = "ops@client.example"


@pytest.fixture()
def engine(settings, monkeypatch):
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "127.0.0.1,localhost,.invalid")
    served = Engine()
    settings.CYBERENGINE_URL = served.base
    settings.CYBERENGINE_OPERATOR_KEY = "operator-key-for-this-test"
    # A short default budget, polled often: a launch that ignores wait_seconds still
    # answers inside the test rather than hanging, and its reads can be counted.
    monkeypatch.setattr(cec, "SCAN_POLL_SECONDS", 0.05)
    monkeypatch.setattr(cec, "SCAN_COLLECT_SECONDS", 0.5)
    monkeypatch.setattr(cec, "ENGINE_TIMEOUT", (2.0, 3.0))
    monkeypatch.setattr("pentest.views.target_is_out_of_bounds", lambda url: None)
    monkeypatch.setattr("pentest.views.preflight.check", lambda client, tenant_id=None: {"verdict": "unchanged"})
    monkeypatch.setattr("pentest.views.render_scan_pdf_bytes", lambda scan: b"%PDF-1.4 report")
    monkeypatch.setattr("pentest.views.save_pdf_to_scan", lambda scan, pdf: None)
    yield served
    served.close()


def _analyst():
    return User.objects.create_user(username=f"a-{uuid.uuid4().hex[:10]}", password=None, role=User.Roles.ANALYST)


def _client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _engagement(user):
    now = timezone.now()
    return Engagement.objects.create(
        created_by=user, name="Client Q3", status="running", scope_hosts=["offline.invalid"],
        testing_window_start=now - timedelta(hours=1), testing_window_end=now + timedelta(hours=1),
    )


def _launch(client, engagement, **extra):
    body = {"url": TARGET, "consent": True, "engagement_id": engagement.pk, **extra}
    return client.post(SCAN_URL, body, format="json")


def _reads(engine, run_id):
    return [path for method, path, _h in engine.requests if method == "GET" and path == f"/api/scans/{run_id}"]


def _sent_wait(engine):
    return [body.get("wait_seconds") for _key, body in engine.launches]


# ===========================================================================
# 1. wait_seconds: 0 -- one read, then the 202 naming the run and where to collect it
# ===========================================================================


def test_wait_seconds_zero_answers_202_with_the_run_after_one_read_and_says_where_to_collect_it(engine):
    engine.finish_on_read = False
    analyst = _analyst()

    response = _launch(_client(analyst), _engagement(analyst), wait_seconds=0, recipient_email=RECIPIENT)

    assert response.status_code == 202, response.content
    (run_id,) = engine.runs
    body = response.json()
    scan = PentestScan.objects.get(uuid=body["scan_id"])
    assert body["status"] == PentestScan.STATUS_PENDING
    assert body["engine_run_id"] == run_id
    assert body["status_url"] == f"/api/pentest/scans/{scan.uuid}/"
    assert body["collect_url"] == f"/api/pentest/scans/{scan.uuid}/collect/"
    assert "collected later" in body["detail"]
    # The engine was asked for no inline wait, and read about the run exactly once.
    assert _sent_wait(engine) == [0]
    assert len(_reads(engine, run_id)) == 1, _reads(engine, run_id)
    # The scan stays pending under its run, with the recipient kept for the collect.
    assert (scan.status, scan.engine_run_id) == (PentestScan.STATUS_PENDING, run_id)
    assert scan.recipient_email == RECIPIENT
    assert scan.email_sent is False and mail.outbox == []


def test_wait_seconds_may_be_sent_as_text_by_a_form_client(engine):
    engine.finish_on_read = False
    analyst = _analyst()

    response = _launch(_client(analyst), _engagement(analyst), wait_seconds="0")

    assert response.status_code == 202, response.content
    assert _sent_wait(engine) == [0]
    assert "collect_url" in response.json()


# ===========================================================================
# 2. The budget: the engine's inline wait is the smaller half, the collect the rest
# ===========================================================================


def test_the_inline_wait_is_the_smaller_of_wait_seconds_and_the_inline_limit(engine, monkeypatch):
    monkeypatch.setattr(cec, "SCAN_COLLECT_SECONDS", 600)
    analyst = _analyst()
    client = _client(analyst)
    engagement = _engagement(analyst)

    short = _launch(client, engagement, wait_seconds=5)
    long = _launch(client, engagement, wait_seconds=30)

    assert (short.status_code, long.status_code) == (200, 200), (short.content, long.content)
    assert _sent_wait(engine) == [5.0, cec.SCAN_INLINE_WAIT_SECONDS]
    assert short.json()["result"] == COMPLETED["result"]


class _Clock:
    """A monotonic clock the test owns: sleeping advances it, nothing else does."""

    def __init__(self):
        self.now = 1000.0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def _client_reading(reads: list):
    """A client whose every read of the run says it is still running, counted."""
    import requests

    client = cec.CyberEngineClient("http://engine.invalid", "k")

    def send_get(path):
        reads.append(path)
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b'{"run_id": "r-1", "state": "running", "done": false}'
        resp.headers["Content-Type"] = "application/json"
        return resp

    client._send_get = send_get
    return client


@pytest.mark.parametrize("collect_seconds, reads_expected", [(0, 1), (0.3, 2), (1.0, 5), (None, 3)])
def test_the_collect_deadline_is_wait_seconds_and_zero_is_exactly_one_read(monkeypatch, collect_seconds, reads_expected):
    """Polled every 0.3 s of the test's clock: a budget of 0 reads once and gives up;
    1.0 reads at 0, 0.3, 0.6, 0.9 and 1.2; None is the module's default (0.5 here)."""
    clock = _Clock()
    monkeypatch.setattr(cec, "time", clock)
    monkeypatch.setattr(cec, "SCAN_POLL_SECONDS", 0.3)
    monkeypatch.setattr(cec, "SCAN_COLLECT_SECONDS", 0.5)
    reads: list = []

    with pytest.raises(cec.ScanStillRunning) as raised:
        _client_reading(reads).collect_scan("r-1", collect_seconds=collect_seconds)

    assert len(reads) == reads_expected, reads
    assert raised.value.run_id == "r-1"
    assert "collected later" in str(raised.value)


# ===========================================================================
# 3. Without wait_seconds the launch is what it was
# ===========================================================================


def test_without_wait_seconds_the_launch_waits_and_answers_as_it_always_has(engine):
    analyst = _analyst()

    response = _launch(_client(analyst), _engagement(analyst), recipient_email=RECIPIENT)

    assert response.status_code == 200, response.content
    assert set(response.json()) == {"scan_id", "result"}
    assert response.json()["result"] == COMPLETED["result"]
    assert _sent_wait(engine) == [cec.SCAN_INLINE_WAIT_SECONDS]
    scan = PentestScan.objects.get(uuid=response.json()["scan_id"])
    assert scan.status == PentestScan.STATUS_COMPLETED
    assert (scan.recipient_email, scan.email_sent) == (RECIPIENT, True)
    assert [m.to for m in mail.outbox] == [[RECIPIENT]]


def test_without_wait_seconds_a_run_that_outlasts_the_wait_is_still_202_and_now_says_where_to_collect_it(engine):
    engine.finish_on_read = False
    analyst = _analyst()

    response = _launch(_client(analyst), _engagement(analyst))

    assert response.status_code == 202, response.content
    body = response.json()
    (run_id,) = engine.runs
    assert _sent_wait(engine) == [cec.SCAN_INLINE_WAIT_SECONDS]
    assert len(_reads(engine, run_id)) > 1, "the default budget was not polled"
    assert body["status"] == PentestScan.STATUS_PENDING and body["engine_run_id"] == run_id
    assert body["status_url"] == f"/api/pentest/scans/{body['scan_id']}/"
    assert body["collect_url"] == f"/api/pentest/scans/{body['scan_id']}/collect/"


# ===========================================================================
# 4. A wait_seconds that cannot be read is refused before anything is sent
# ===========================================================================


@pytest.mark.parametrize("value", [-1, 1, "soon", True, [0], {"seconds": 0}, "", "nan", "inf"])
def test_a_wait_seconds_that_is_not_a_number_of_seconds_in_range_is_refused_before_anything_is_sent(engine, value):
    """The range is 0 to SCAN_COLLECT_SECONDS (0.5 in this test), so 1 is out of it."""
    analyst = _analyst()

    response = _launch(_client(analyst), _engagement(analyst), wait_seconds=value)

    assert response.status_code == 400, response.content
    assert "wait_seconds" in response.json()["error"]
    assert engine.launches == [], "a launch was sent on a wait_seconds that could not be read"
    assert PentestScan.objects.count() == 0


# ===========================================================================
# 5. The same press again: the recorded 202, and no second launch
# ===========================================================================


def test_a_launch_replayed_with_its_key_is_answered_the_recorded_202_and_launches_nothing_again(engine):
    engine.finish_on_read = False
    analyst = _analyst()
    client = _client(analyst)
    body = {"url": TARGET, "consent": True, "engagement_id": _engagement(analyst).pk, "wait_seconds": 0}

    first = client.post(SCAN_URL, body, format="json", **{KEY: "press-1"})
    replay = client.post(SCAN_URL, body, format="json", **{KEY: "press-1"})

    assert first.status_code == 202, first.content
    assert replay.status_code == 202, replay.content
    assert replay["Idempotent-Replayed"] == "true"
    assert replay.json() == first.json()
    assert replay.json()["collect_url"] == f"/api/pentest/scans/{first.json()['scan_id']}/collect/"
    assert len(engine.launches) == 1, "the replay launched the scan again"
    (run_id,) = engine.runs
    assert len(_reads(engine, run_id)) == 1, "the replay read the engine"
    assert PentestScan.objects.count() == 1
