"""A pending scan's run is collected once it has ended, and a stopped run is never a result.

A scan whose run outlasts its launch stays pending under the engine's run id, and
nothing collected it: ``collect_scan`` was called only from the launch, and a reconcile
is for a launch whose answer was lost. Such a scan never got its verdict, its ingest,
its report or its mail -- and a run an operator stopped was, at launch, FAILED with
the engine's words and its partial result thrown away.

``POST /api/pentest/scans/<uuid>/collect/`` (an admin or analyst who can see the scan;
``manage.py collect_pending_scans`` runs the same code for every pending scan) reads
the run from the engine once, bounded, and records how it ended:

* completed: the launch's own completion path -- the refusal check, the engagement
  re-authorised under its lock, ``mark_completed`` (the assurance ingest fires on
  commit), the report rendered, and mailed if the launch named a recipient;
* aborted: a new status, STOPPED, with the engine's reason and whatever the run had
  when it stopped kept; no verdict, nothing ingested, no report, no mail;
* failed, and a run the engine does not have: FAILED, saying why;
* not done: 202 "still running"; the engine unreadable: 503, the row untouched.

A collect never sends a launch, and never a Stop. Two collects of one scan record its
end once: the second answers 409. The route is declared not a stop (safety.stops) for
the reason it is not one: a read of the engine and a write of this record.

The engine here is the real HTTP stub of tests/test_a_lost_launch_answer_reads_unknown.
"""

from __future__ import annotations

import copy
import threading
import uuid
from datetime import timedelta
from io import StringIO

import pytest
from django.contrib.auth import get_user_model
from django.core import mail
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.utils import timezone
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from ai_engine.services import cyberengine_client as cec
from assurance.models import Deployment, Evidence, Finding
from pentest.models import Engagement, PentestScan
from safety import stops
from tests.test_a_lost_launch_answer_reads_unknown import COMPLETED, SCAN_URL, TARGET, Engine, _closed_port_url

pytestmark = pytest.mark.django_db

User = get_user_model()
RECIPIENT = "ops@client.example"
#: PentestScan.STATUS_STOPPED, spelled out so this module imports on a backend without it.
STOPPED = "stopped"
#: What a run the engine stopped early had when it stopped: the finding it had found,
#: and the engine's own marker that the rest did not run (PentestScan.INCOMPLETE_MARKER).
PARTIAL = {
    "scan_id": 703,
    "results": [
        {"type": "xss", "severity": "high", "message": "Reflected input on /search",
         "endpoint": "https://offline.invalid/search"},
        {"type": "scan_incomplete", "internal": True,
         "message": "the remaining scanners did not run, so this is not a clean result"},
    ],
    "coverage": {"checks": [{"check": "xss", "ran": True}]},
}


@pytest.fixture()
def engine(settings, monkeypatch):
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "127.0.0.1,localhost,.invalid")
    served = Engine()
    served.rendered = []
    settings.CYBERENGINE_URL = served.base
    settings.CYBERENGINE_OPERATOR_KEY = "operator-key-for-this-test"
    monkeypatch.setattr(cec, "SCAN_POLL_SECONDS", 0.05)
    monkeypatch.setattr(cec, "SCAN_COLLECT_SECONDS", 0.5)
    monkeypatch.setattr(cec, "ENGINE_TIMEOUT", (2.0, 3.0))
    monkeypatch.setattr("pentest.views.target_is_out_of_bounds", lambda url: None)
    monkeypatch.setattr("pentest.views.preflight.check", lambda client, tenant_id=None: {"verdict": "unchanged"})
    # The report is recorded as rendered, per scan, rather than built.
    monkeypatch.setattr(
        "pentest.views.render_scan_pdf_bytes", lambda scan: served.rendered.append(scan.uuid) or b"%PDF-1.4 report"
    )
    monkeypatch.setattr("pentest.views.save_pdf_to_scan", lambda scan, pdf: None)
    yield served
    served.close()


def _user(role=None):
    return User.objects.create_user(
        username=f"u-{uuid.uuid4().hex[:10]}", password=None, role=role or User.Roles.ANALYST
    )


def _client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _engagement(user):
    now = timezone.now()
    return Engagement.objects.create(
        created_by=user, name="Client Q3", client_name="Client", status="running", scope_hosts=["offline.invalid"],
        testing_window_start=now - timedelta(hours=1), testing_window_end=now + timedelta(hours=1),
    )


def _pending_scan(engine, recipient=None, user=None):
    """A scan launched with ``wait_seconds: 0`` against an engine that holds its run:
    pending, naming the run. Returns (client, scan, run id, the launch's answer)."""
    engine.finish_on_read = False
    analyst = user or _user()
    client = _client(analyst)
    body = {"url": TARGET, "consent": True, "engagement_id": _engagement(analyst).pk, "wait_seconds": 0}
    if recipient:
        body["recipient_email"] = recipient
    response = client.post(SCAN_URL, body, format="json")
    assert response.status_code == 202, response.content
    launched = response.json()
    scan = PentestScan.objects.get(uuid=launched["scan_id"])
    assert scan.status == PentestScan.STATUS_PENDING and scan.engine_run_id == launched["engine_run_id"]
    return client, scan, launched["engine_run_id"], launched


def _end(engine, run_id, state, **fields):
    """The run ends on the engine: ``state``, with whatever the engine records beside it."""
    with engine.lock:
        engine.runs[run_id].update(state=state, done=True, finished_at=timezone.now().isoformat(), **fields)


def _collect(client, scan):
    return client.post(f"/api/pentest/scans/{scan.uuid}/collect/", {}, format="json")


def _launches(engine):
    return [path for method, path, _h in engine.requests if (method, path) == ("POST", "/api/scan")]


def _reads(engine, run_id):
    return [path for method, path, _h in engine.requests if method == "GET" and path == f"/api/scans/{run_id}"]


def _completed_result():
    return copy.deepcopy(COMPLETED["result"])


# ===========================================================================
# 1. A completed run: the launch's own completion, later
# ===========================================================================


def test_a_collect_completes_a_pending_scan_derives_its_verdict_ingests_it_renders_and_mails_the_report(
        engine, django_capture_on_commit_callbacks):
    client, scan, run_id, _launched = _pending_scan(engine, recipient=RECIPIENT)
    _end(engine, run_id, "completed", result=_completed_result())
    launches = len(_launches(engine))

    with django_capture_on_commit_callbacks(execute=True):
        response = _collect(client, scan)

    assert response.status_code == 200, response.content
    body = response.json()
    scan.refresh_from_db()
    assert body["status"] == scan.status == PentestScan.STATUS_COMPLETED
    assert scan.verdict is not None
    assert body["verdict"] == scan.verdict == PentestScan.derive_verdict(COMPLETED["result"])
    assert scan.collected_at is not None and body["collected_at"]
    assert body["engine_response"] == COMPLETED["result"] == scan.engine_response
    assert (body["uuid"], body["engine_run_id"]) == (str(scan.uuid), run_id)
    # The ingest fired on commit: the system of record has the deployment and its findings.
    assert Deployment.objects.count() == 1
    assert Finding.objects.filter(scan=scan).exists()
    # The report was rendered once and mailed once, to the recipient the launch named.
    assert engine.rendered == [scan.uuid]
    assert [m.to for m in mail.outbox] == [[RECIPIENT]]
    assert scan.email_sent is True
    # One read of the run by the collect (the launch's one before it), and no launch.
    assert len(_reads(engine, run_id)) == 2, _reads(engine, run_id)
    assert len(_launches(engine)) == launches, "the collect sent a launch"


def test_a_collect_mails_nothing_when_the_launch_named_no_recipient(engine, django_capture_on_commit_callbacks):
    client, scan, run_id, _launched = _pending_scan(engine)
    _end(engine, run_id, "completed", result=_completed_result())

    with django_capture_on_commit_callbacks(execute=True):
        response = _collect(client, scan)

    assert response.status_code == 200, response.content
    scan.refresh_from_db()
    assert scan.status == PentestScan.STATUS_COMPLETED and engine.rendered == [scan.uuid]
    assert mail.outbox == [] and scan.email_sent is False


# ===========================================================================
# 2. A stopped run: STOPPED, no verdict, nothing ingested, what it had kept
# ===========================================================================


def test_a_collect_of_a_run_stopped_on_the_engine_records_stopped_with_no_verdict_and_ingests_nothing(
        engine, django_capture_on_commit_callbacks):
    client, scan, run_id, _launched = _pending_scan(engine, recipient=RECIPIENT)
    _end(engine, run_id, "aborted", reason="stopped by an operator", result=copy.deepcopy(PARTIAL))

    with django_capture_on_commit_callbacks(execute=True):
        response = _collect(client, scan)

    assert response.status_code == 200, response.content
    body = response.json()
    scan.refresh_from_db()
    assert body["status"] == scan.status == STOPPED, "a stopped run was not recorded as stopped"
    assert body["verdict"] is None and scan.verdict is None, "a stopped run was given a verdict"
    assert scan.error_message == "Stopped on the engine: stopped by an operator"
    assert body["error_message"] == scan.error_message
    assert scan.engine_response == PARTIAL, "what the run had when it stopped was not kept"
    assert scan.collected_at is not None
    # Never a result: nothing reached the system of record (no deployment, so no
    # finding, no evidence and no check coverage), no report, no mail.
    assert Deployment.objects.count() == 0
    assert Finding.objects.count() == 0 and Evidence.objects.count() == 0
    assert engine.rendered == []
    assert mail.outbox == [] and scan.email_sent is False
    # And every reader of the scan says so.
    assert client.get(f"/api/pentest/scans/{scan.uuid}/").json()["status"] == STOPPED
    assert client.get(f"/api/pentest/scans/{scan.uuid}/pdf/").status_code == 409
    assert client.post(f"/api/pentest/scans/{scan.uuid}/email/", {}, format="json").status_code == 409


def test_mark_stopped_keeps_no_verdict_and_says_the_reason_with_the_target_s_login_withheld():
    # A login a tenant put in the target, made up here so that no credential-shaped
    # text is written into this file.
    password = uuid.uuid4().hex[:12]
    target = f"https://scanner:{password}@offline.invalid/"
    scan = PentestScan.objects.create(
        user=_user(), target_url=target, consent=True,
        status=PentestScan.STATUS_PENDING, engine_response={"results": [{"type": "xss", "severity": "high"}]},
    )

    scan.mark_stopped(f"Stopped on the engine: {target} was stopped")

    scan.refresh_from_db()
    assert (scan.status, scan.verdict) == (STOPPED, None)
    assert scan.error_message.startswith("Stopped on the engine: ")
    assert password not in scan.error_message
    assert dict(PentestScan.STATUS_CHOICES)[STOPPED].startswith("Stopped")


# ===========================================================================
# 3. A failed run, and a run the engine does not have
# ===========================================================================


def test_a_collect_of_a_run_that_failed_on_the_engine_records_failed_with_its_error(
        engine, django_capture_on_commit_callbacks):
    client, scan, run_id, _launched = _pending_scan(engine, recipient=RECIPIENT)
    _end(engine, run_id, "failed", error="OperationalError: database is locked", result=copy.deepcopy(PARTIAL))

    with django_capture_on_commit_callbacks(execute=True):
        response = _collect(client, scan)

    assert response.status_code == 200, response.content
    scan.refresh_from_db()
    assert response.json()["status"] == scan.status == PentestScan.STATUS_FAILED
    assert scan.error_message == "Failed on the engine: OperationalError: database is locked"
    assert scan.verdict is None and scan.engine_response == PARTIAL
    assert Deployment.objects.count() == 0 and Finding.objects.count() == 0
    assert mail.outbox == [] and engine.rendered == []


def test_a_collect_of_a_run_the_engine_does_not_have_records_failed_saying_so(engine):
    client, scan, run_id, _launched = _pending_scan(engine)
    with engine.lock:
        del engine.runs[run_id]

    response = _collect(client, scan)

    assert response.status_code == 200, response.content
    scan.refresh_from_db()
    assert scan.status == PentestScan.STATUS_FAILED
    assert scan.error_message == f"the engine has no run {run_id}"
    assert response.json()["error_message"] == scan.error_message
    assert scan.collected_at is not None


# ===========================================================================
# 4. The engine cannot be read: 503, the row untouched; still going: 202
# ===========================================================================


def test_a_collect_while_the_engine_cannot_be_read_answers_503_and_leaves_the_scan_pending(engine, settings):
    client, scan, run_id, _launched = _pending_scan(engine)

    settings.CYBERENGINE_URL = _closed_port_url()
    unreachable = _collect(client, scan)
    settings.CYBERENGINE_URL = engine.base
    # A 404 the engine did not write -- a gateway's page -- says nothing about the run.
    engine.read_run = lambda h: h.answer(404, text="<html><h1>Not Found</h1></html>", content_type="text/html")
    gateway = _collect(client, scan)
    del engine.read_run
    settings.CYBERENGINE_OPERATOR_KEY = ""
    unconfigured = _collect(client, scan)
    settings.CYBERENGINE_OPERATOR_KEY = "operator-key-for-this-test"

    for response in (unreachable, gateway, unconfigured):
        assert response.status_code == 503, response.content
        assert "stays pending" in response.json()["detail"]
        assert response.json()["status"] == PentestScan.STATUS_PENDING
    scan.refresh_from_db()
    assert (scan.status, scan.collected_at, scan.engine_response) == (PentestScan.STATUS_PENDING, None, None)
    # Readable again, the run is collected.
    _end(engine, run_id, "completed", result=_completed_result())
    assert _collect(client, scan).status_code == 200


def test_a_collect_of_a_run_still_going_answers_202_still_running_after_one_read_and_writes_nothing(engine):
    client, scan, run_id, launched = _pending_scan(engine)
    assert launched["collect_url"] == f"/api/pentest/scans/{scan.uuid}/collect/"
    reads = len(_reads(engine, run_id))

    response = client.post(launched["collect_url"], {}, format="json")

    assert response.status_code == 202, response.content
    assert response.json() == {
        "scan_id": str(scan.uuid), "status": PentestScan.STATUS_PENDING, "engine_run_id": run_id, "detail": "still running",
    }
    assert len(_reads(engine, run_id)) == reads + 1, "the collect read the run more than once"
    scan.refresh_from_db()
    assert (scan.status, scan.collected_at, scan.engine_response) == (PentestScan.STATUS_PENDING, None, None)
    # Done, in a state this backend does not read: nothing is read from it either.
    _end(engine, run_id, "finishing")
    odd = _collect(client, scan)
    assert odd.status_code == 202, odd.content
    assert "does not read" in odd.json()["detail"]
    scan.refresh_from_db()
    assert (scan.status, scan.collected_at) == (PentestScan.STATUS_PENDING, None)


# ===========================================================================
# 5. A collect never sends a launch, whatever the run says
# ===========================================================================


def test_a_collect_never_sends_a_launch_whatever_the_run_says(engine, settings, django_capture_on_commit_callbacks):
    client, scan, run_id, _launched = _pending_scan(engine)
    assert _launches(engine) == ["/api/scan"]

    _collect(client, scan)  # still running
    settings.CYBERENGINE_URL = _closed_port_url()
    _collect(client, scan)  # the engine cannot be reached
    settings.CYBERENGINE_URL = engine.base
    _end(engine, run_id, "aborted", reason="stopped by an operator", result={})
    _collect(client, scan)  # stopped
    _collect(client, scan)  # already collected
    assert _launches(engine) == ["/api/scan"], "a collect of this scan sent a launch"

    client2, scan2, run2, _launched2 = _pending_scan(engine)
    _end(engine, run2, "completed", result=_completed_result())
    with django_capture_on_commit_callbacks(execute=True):
        _collect(client2, scan2)  # completed
    client3, scan3, run3, _launched3 = _pending_scan(engine)
    with engine.lock:
        del engine.runs[run3]
    _collect(client3, scan3)  # the engine has no such run
    client4, scan4, run4, _launched4 = _pending_scan(engine)
    _end(engine, run4, "failed", error="boom")
    _collect(client4, scan4)  # failed

    assert _launches(engine) == ["/api/scan"] * 4, "a collect sent a launch"
    assert {s.status for s in PentestScan.objects.all()} == {STOPPED, "completed", "failed"}


# ===========================================================================
# 6. Two collects of one scan record its end once
# ===========================================================================


def test_a_second_collect_answers_409_with_the_scan_s_status_and_records_nothing_again(
        engine, django_capture_on_commit_callbacks):
    client, scan, run_id, _launched = _pending_scan(engine, recipient=RECIPIENT)
    _end(engine, run_id, "completed", result=_completed_result())

    with django_capture_on_commit_callbacks(execute=True):
        first = _collect(client, scan)
    findings = Finding.objects.count()
    with django_capture_on_commit_callbacks(execute=True):
        second = _collect(client, scan)

    assert (first.status_code, second.status_code) == (200, 409), (first.content, second.content)
    assert second.json()["status"] == PentestScan.STATUS_COMPLETED
    assert "only a pending scan is collected" in second.json()["detail"]
    assert findings >= 1 and Finding.objects.count() == findings
    assert Deployment.objects.count() == 1
    assert engine.rendered == [scan.uuid], "the report was rendered again"
    assert len(mail.outbox) == 1, "the report was mailed again"


@pytest.mark.django_db(transaction=True)
def test_two_collects_at_once_record_the_end_once_and_mail_the_report_once(engine):
    analyst = _user()
    _client_, scan, run_id, _launched = _pending_scan(engine, recipient=RECIPIENT, user=analyst)
    _end(engine, run_id, "completed", result=_completed_result())
    answers = []
    together = threading.Barrier(2)

    def collect():
        try:
            together.wait(10)
            request = APIRequestFactory().post(f"/api/pentest/scans/{scan.uuid}/collect/", {}, format="json")
            force_authenticate(request, user=analyst)
            from pentest import views

            answers.append(views.collect_pentest_scan(request, scan_id=scan.uuid).status_code)
        finally:
            connection.close()

    collectors = [threading.Thread(target=collect, name=f"collector-{n}") for n in range(2)]
    for thread in collectors:
        thread.start()
    for thread in collectors:
        thread.join(60)

    assert sorted(answers) == [200, 409], answers
    scan.refresh_from_db()
    assert scan.status == PentestScan.STATUS_COMPLETED and scan.verdict is not None
    assert engine.rendered == [scan.uuid], "both collectors rendered the report"
    assert len(mail.outbox) == 1, "both collectors mailed the report"
    assert Deployment.objects.count() == 1
    assert Finding.objects.filter(scan=scan).exists()


# ===========================================================================
# 7. Who may collect, and what may be collected
# ===========================================================================


def test_a_collect_is_scoped_as_scan_detail_is(engine):
    client, scan, run_id, _launched = _pending_scan(engine)
    stranger = _client(_user())
    viewer = _client(_user(User.Roles.VIEWER))
    admin = _client(_user(User.Roles.ADMIN))

    assert _collect(stranger, scan).status_code == 404
    assert _collect(viewer, scan).status_code == 403
    assert APIClient().post(f"/api/pentest/scans/{scan.uuid}/collect/", {}, format="json").status_code == 401
    assert _collect(admin, scan).status_code == 202  # an admin sees every scan; this run is still going
    assert _collect(client, scan).status_code == 202
    scan.refresh_from_db()
    assert scan.status == PentestScan.STATUS_PENDING


def test_only_a_pending_scan_that_names_its_run_is_collected(engine):
    analyst = _user()
    client = _client(analyst)
    rows = {
        "This scan is completed": PentestScan.objects.create(
            user=analyst, target_url=TARGET, consent=True, status=PentestScan.STATUS_COMPLETED,
            engine_run_id="run-done", engine_response={"results": []},
        ),
        "names no run": PentestScan.objects.create(
            user=analyst, target_url=TARGET, consent=True, status=PentestScan.STATUS_PENDING,
        ),
        "This scan is unknown": PentestScan.objects.create(
            user=analyst, target_url=TARGET, consent=True, status=PentestScan.STATUS_UNKNOWN, error_message="lost",
        ),
    }

    for said, scan in rows.items():
        response = _collect(client, scan)
        assert response.status_code == 409, (scan.status, response.content)
        assert said in response.json()["detail"]
        assert response.json()["status"] == scan.status
    # (The gateway's /defend probes aside, which ask the engine about every request.)
    assert [p for _m, p, _h in engine.requests if p.startswith("/api/")] == [], (
        "a scan with nothing to collect reached the engine"
    )


# ===========================================================================
# 8. The command: every pending run once; non-zero while one stays pending
# ===========================================================================


def test_the_command_collects_every_pending_run_once_and_fails_while_one_stays_pending(
        engine, settings, django_capture_on_commit_callbacks):
    analyst = _user()
    _a, done, done_run, _la = _pending_scan(engine, recipient=RECIPIENT, user=analyst)
    _b, going, going_run, _lb = _pending_scan(engine, user=analyst)
    _end(engine, done_run, "completed", result=_completed_result())
    launches = len(_launches(engine))
    out = StringIO()

    with django_capture_on_commit_callbacks(execute=True):
        with pytest.raises(CommandError, match=f"still pending: scan {going.uuid}"):
            call_command("collect_pending_scans", stdout=out)

    done.refresh_from_db()
    going.refresh_from_db()
    assert (done.status, going.status) == (PentestScan.STATUS_COMPLETED, PentestScan.STATUS_PENDING)
    assert done.collected_at is not None and going.collected_at is None
    lines = out.getvalue().splitlines()
    assert any(str(done.uuid) in line and "200 completed" in line for line in lines), lines
    assert any(str(going.uuid) in line and "still running" in line for line in lines), lines
    assert [m.to for m in mail.outbox] == [[RECIPIENT]] and Deployment.objects.count() == 1
    assert len(_launches(engine)) == launches, "the command sent a launch"

    # A scan pending for less than the threshold does not fail the run.
    call_command("collect_pending_scans", "--older-than-seconds", "3600", stdout=StringIO())
    # Nor is one past --limit collected in this run: it is left for the next.
    with pytest.raises(CommandError, match="still pending"):
        call_command("collect_pending_scans", "--limit", "0", stdout=StringIO())

    # Once its run ends, it is collected and the command exits clean.
    _end(engine, going_run, "aborted", reason="stopped by an operator", result={})
    out = StringIO()
    call_command("collect_pending_scans", stdout=out)
    going.refresh_from_db()
    assert going.status == STOPPED and going.verdict is None
    assert "0 scan(s) still pending" in out.getvalue()
    assert len(mail.outbox) == 1 and Deployment.objects.count() == 1

    # With no engine configured nothing can be read, and the command says so.
    settings.CYBERENGINE_OPERATOR_KEY = ""
    with pytest.raises(CommandError, match="no engine is configured"):
        call_command("collect_pending_scans", stdout=StringIO())


# ===========================================================================
# 9. The route is declared not a stop, for the reason it is not one
# ===========================================================================


def test_the_collect_route_is_declared_not_a_stop_for_the_reason_it_is_not_one():
    assert stops.NOT_STOPS["pentest:collect_pentest_scan"] == {
        "POST": (
            "collects a finished run's record from the engine: a read of the engine and a write of "
            "this record; it starts and stops nothing"
        )
    }
    assert "pentest:collect_pentest_scan" not in stops.EXEMPT_ROUTES
    # The scan's Stop is what it was.
    assert set(stops.STOP_ROUTES["pentest:stop_pentest_scan"]) == {"POST"}
