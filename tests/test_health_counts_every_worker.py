"""``/api/health/`` reads what EVERY worker lost or refused, not only the one that answers.

#217 made each count of what a process lost or refused (a line meant for stderr, a log
record, an unrecorded dispatch refused past its bound) read "degraded" in health. The
counts are per process, and a probe is answered by one worker: a loss in another
worker read "ok". Now each worker publishes its counts as a small file in one
directory (``assurance.worker_reports``), and health sums them all.

The workers here are real processes: each test starts worker B as a child Python
process that publishes from the same directory, and asks health of this one, worker
A. B is the publisher a serving worker runs (``ensure_publisher``), with its counts
read from ``assurance.oplog`` as ``dispatch.degraded_counts`` reads them -- the child
does not load Django, so the dispatch module's third count is zero there.

What is proved:

- a loss in worker B reads "degraded", with B's count, in worker A's health;
- a report that cannot be read, a report directory that cannot be read, and a live
  worker's report not rewritten within its bound (a worker killed outright) read
  "unknown", never "ok";
- a worker that exits keeps its counts in health until an operator acknowledges
  them, and the acknowledgement records who and when; a live worker's report cannot
  be acknowledged;
- publishing is never on a stop's path: a stop is answered within its bound while
  every publish hangs and fails, and the failed publish is counted and shown.
"""

from __future__ import annotations

import datetime
import io
import json
import logging
import os
import pathlib
import subprocess
import sys
import threading
import time
import types

import pytest
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import override_settings
from rest_framework.test import APIClient

from assurance import dispatch, oplog, worker_reports

ROOT = pathlib.Path(__file__).resolve().parent.parent

#: Worker B: a process that publishes its report as a serving worker does, loses
#: ``argv[1]`` lines meant for stderr (the count ``oplog`` keeps of them), prints its
#: report id, and exits normally when its stdin closes.
WORKER_B = r"""
import sys

from assurance import oplog, worker_reports


def counts():
    # assurance.dispatch.degraded_counts, read without Django.
    return {
        "stderr_lines_lost": oplog.STDERR_LOST[0],
        "log_records_dropped": oplog.LOG_DROPPED[0],
        "unrecorded_dispatches_refused": 0,
    }


worker_reports.ensure_publisher(counts)
oplog.STDERR_LOST[0] += int(sys.argv[1])
print(worker_reports.worker_id(), flush=True)
sys.stdin.read()
"""


def _wait_for(predicate, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.05)
    return predicate()


class WorkerB:
    """Worker B, a child process publishing to ``directory``."""

    def __init__(self, directory: pathlib.Path, output: pathlib.Path, lost: int):
        self.directory = directory
        self.lost = lost
        env = dict(os.environ)
        env["ATHENA_WORKER_REPORT_DIR"] = str(directory)
        env["PYTHONPATH"] = os.pathsep.join([str(ROOT), env.get("PYTHONPATH", "")]).rstrip(os.pathsep)
        self.output_path = output
        self.output = open(output, "wb")  # noqa: SIM115 - closed in end()
        self.process = subprocess.Popen(
            [sys.executable, "-c", WORKER_B, str(lost)],
            cwd=str(ROOT),
            env=env,
            stdin=subprocess.PIPE,
            stdout=self.output,
            stderr=subprocess.STDOUT,
        )
        self.id = None

    def report_path(self) -> pathlib.Path:
        return self.directory / f"{self.id}.json"

    def report(self):
        try:
            return json.loads(self.report_path().read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None

    def published(self) -> str:
        """Wait until B has published its loss; returns its id."""

        def ready():
            text = self.output_path.read_bytes().decode("utf-8", "replace").strip()
            if not self.id and text and len(text.splitlines()[0]) == 16:
                self.id = text.splitlines()[0]
            report = self.report() if self.id else None
            return bool(report and report["counts"] and report["counts"]["stderr_lines_lost"] == self.lost)

        assert _wait_for(ready), f"worker B never published: {self.output_path.read_bytes()!r}"
        return self.id

    def exit(self) -> None:
        """A normal exit: its stdin closes, the interpreter ends, ``atexit`` runs."""
        self.process.communicate(input=b"", timeout=30)
        assert self.process.returncode == 0, self.output_path.read_bytes()

    def kill(self) -> None:
        """Killed outright (SIGKILL; TerminateProcess on Windows): nothing more is written."""
        self.process.kill()
        self.process.wait(30)

    def end(self) -> None:
        if self.process.poll() is None:
            self.kill()
        if self.process.stdin is not None:
            self.process.stdin.close()
        self.output.close()


@pytest.fixture
def reports(tmp_path, monkeypatch):
    """One directory every worker of the test publishes to, and this process's
    publisher state and counts fresh. Any publisher the test starts is stopped."""
    directory = tmp_path / "reports"
    monkeypatch.setenv("ATHENA_WORKER_REPORT_DIR", str(directory))
    stop = threading.Event()
    monkeypatch.setattr(worker_reports, "_PUBLISHER", [])
    monkeypatch.setattr(worker_reports, "_RETRY", {})
    monkeypatch.setattr(worker_reports, "_STOP", stop)
    monkeypatch.setattr(worker_reports, "PUBLISH_FAILED", [0])
    monkeypatch.setattr(worker_reports, "_FAILING", [False])
    for module, name in ((oplog, "STDERR_LOST"), (oplog, "LOG_DROPPED"), (dispatch, "_UNRECORDED_REFUSED")):
        monkeypatch.setattr(module, name, [0])
    monkeypatch.setattr(dispatch, "_DEGRADED_REPORTED", [{}])
    workers = []

    def worker_b(lost):
        worker = WorkerB(directory, tmp_path / f"worker-b-{len(workers)}.out", lost)
        workers.append(worker)
        return worker

    yield types.SimpleNamespace(directory=directory, worker_b=worker_b, stop=stop)
    stop.set()
    for _pid, thread, *_rest in worker_reports._PUBLISHER:
        thread.join(10)
    for worker in workers:
        worker.end()


def _health():
    answer = APIClient().get("/api/health/")
    assert answer.status_code == 200, answer.content
    return answer.json()


# ---------------------------------------------------------- the loss in another worker


@pytest.mark.django_db
def test_a_loss_in_another_worker_reads_degraded_in_this_workers_health(reports):
    """The fail-first case: worker B loses two lines; health is asked of worker A,
    which lost nothing. On #217's head this read "ok"."""
    b = reports.worker_b(lost=2)
    b_id = b.published()
    body = _health()
    assert body["status"] == "degraded", body
    assert body["degraded"] == {"stderr_lines_lost": 2}, body
    assert body["workers"] == {b_id: {"state": worker_reports.LIVE, "stderr_lines_lost": 2}}, body
    assert "stderr_lines_lost=2" in body["message"], body
    assert "unknown" not in body, body
    b.exit()


@pytest.mark.django_db
def test_both_workers_counts_are_summed(reports):
    b = reports.worker_b(lost=2)
    b_id = b.published()
    oplog.STDERR_LOST[0] = 1
    dispatch._UNRECORDED_REFUSED[0] = 4
    body = _health()
    assert body["status"] == "degraded", body
    assert body["degraded"] == {"stderr_lines_lost": 3, "unrecorded_dispatches_refused": 4}, body
    assert body["workers"][b_id] == {"state": worker_reports.LIVE, "stderr_lines_lost": 2}, body
    assert body["workers"][worker_reports.worker_id()] == {
        "state": worker_reports.THIS, "stderr_lines_lost": 1, "unrecorded_dispatches_refused": 4,
    }, body
    b.exit()


@pytest.mark.django_db
def test_a_live_worker_that_lost_nothing_leaves_health_ok(reports):
    b = reports.worker_b(lost=0)
    b.published()
    assert _health() == {"status": "ok", "message": "Django backend is alive."}
    b.exit()


# ------------------------------------------------------------ unknown, never ok


@pytest.mark.django_db
@pytest.mark.parametrize("lost", [0, 3])
def test_a_worker_killed_outright_reads_unknown_once_its_report_is_stale_never_ok(reports, monkeypatch, lost):
    """Killed outright, a worker writes nothing more. Within the bound its last report
    stands; past it, health reads unknown for it -- and still counts what it had
    counted (degraded, with the worker named unknown)."""
    b = reports.worker_b(lost=lost)
    b_id = b.published()
    b.kill()
    assert b.report()["exited"] is False
    within = _health()
    assert within["status"] == ("degraded" if lost else "ok"), within
    bound = 0.5
    monkeypatch.setattr(worker_reports, "STALE_AFTER_SECONDS", bound)
    assert _wait_for(lambda: time.time() - b.report()["published"] > bound + 0.1)
    body = _health()
    assert body["status"] == ("degraded" if lost else "unknown"), body
    assert body["status"] != "ok"
    assert list(body["unknown"]) == [b_id], body
    assert body["unknown"][b_id].startswith("stale: last published"), body
    assert "0.5 s bound" in body["unknown"][b_id], body
    if lost:
        assert body["degraded"] == {"stderr_lines_lost": lost}, body
        assert body["workers"][b_id] == {"state": worker_reports.STALE, "stderr_lines_lost": lost}, body
        assert f"1 worker report(s) read unknown: {b_id} stale" in body["message"], body


@pytest.mark.django_db
@pytest.mark.parametrize(
    "content",
    [
        b"not json",
        b'{"counts": {"stderr_lines_lost": 0}, "exited": false',
        b'{"counts": {"stderr_lines_lost": -1}, "exited": false, "published": 1}',
        b'{"counts": null, "exited": false, "published": 1}',
        b'{"counts": {"stderr_lines_lost": 0}, "exited": false}',
        b"[]",
    ],
    ids=["not-json", "truncated", "negative", "counts-unread", "no-time", "not-an-object"],
)
def test_a_report_that_cannot_be_read_reads_unknown_never_ok(reports, content):
    reports.directory.mkdir()
    (reports.directory / "0123456789abcdef.json").write_bytes(content)
    body = _health()
    assert body["status"] == "unknown", body
    assert list(body["unknown"]) == ["0123456789abcdef"], body
    assert body["unknown"]["0123456789abcdef"].startswith("unreadable: "), body


@pytest.mark.django_db
def test_a_report_directory_that_cannot_be_read_reads_unknown_never_ok(reports, monkeypatch, tmp_path):
    not_a_directory = tmp_path / "a-file"
    not_a_directory.write_text("x")
    monkeypatch.setenv("ATHENA_WORKER_REPORT_DIR", str(not_a_directory))
    body = _health()
    assert body["status"] == "unknown", body
    assert body["unknown"]["directory"].startswith("the report directory could not be read"), body


@pytest.mark.django_db
def test_a_reports_read_that_raises_reads_unknown_never_ok(reports, monkeypatch):
    def unreadable(*args, **kwargs):
        raise RuntimeError("no reports")

    monkeypatch.setattr(worker_reports, "summarize", unreadable)
    body = _health()
    assert body["status"] == "unknown", body
    assert "the other workers' reports could not be read" in body["message"], body


# ------------------------------------------------- an exited worker, acknowledged


@pytest.mark.django_db
def test_an_exited_workers_counts_stay_until_acknowledged_and_the_acknowledgement_is_recorded(reports, monkeypatch):
    b = reports.worker_b(lost=2)
    b_id = b.published()
    b.exit()
    report = b.report()
    assert report is not None, "the exited worker's report went with it: its counts vanished"
    assert report["exited"] is True and report["counts"]["stderr_lines_lost"] == 2, report
    # An exited worker's report is final: no bound makes it stale, or makes it vanish.
    monkeypatch.setattr(worker_reports, "STALE_AFTER_SECONDS", 0.0)
    for _ in range(2):
        body = _health()
        assert body["status"] == "degraded", body
        assert body["degraded"] == {"stderr_lines_lost": 2}, body
        assert body["workers"][b_id] == {"state": worker_reports.EXITED, "stderr_lines_lost": 2}, body
        assert "unknown" not in body, body

    # Who acknowledges it must be said.
    with pytest.raises(CommandError, match="--by"):
        call_command("acknowledge_worker_reports", b_id, stdout=io.StringIO())
    assert _health()["status"] == "degraded"

    listed = io.StringIO()
    call_command("acknowledge_worker_reports", stdout=listed)
    assert f"{b_id}: exited, host " in listed.getvalue() and "stderr_lines_lost=2" in listed.getvalue()

    before = datetime.datetime.now(datetime.UTC)
    out = io.StringIO()
    call_command("acknowledge_worker_reports", b_id, by="operator-ann", stdout=out)
    after = datetime.datetime.now(datetime.UTC)
    assert f"worker report {b_id} (exited) acknowledged by operator-ann" in out.getvalue()
    assert _health() == {"status": "ok", "message": "Django backend is alive."}
    assert not b.report_path().exists()

    kept = list((reports.directory / worker_reports.ACKNOWLEDGED).glob(f"{b_id}-*.json"))
    assert len(kept) == 1, kept
    record = json.loads(kept[0].read_text(encoding="utf-8"))
    assert record["acknowledged_by"] == "operator-ann"
    assert before <= datetime.datetime.fromisoformat(record["acknowledged_at"]) <= after
    assert record["state"] == worker_reports.EXITED
    assert record["report"]["counts"]["stderr_lines_lost"] == 2
    assert record["report"]["id"] == b_id


@pytest.mark.django_db
def test_a_stale_report_is_acknowledged_as_stale(reports, monkeypatch):
    b = reports.worker_b(lost=1)
    b_id = b.published()
    b.kill()
    monkeypatch.setattr(worker_reports, "STALE_AFTER_SECONDS", 0.0)
    out = io.StringIO()
    call_command("acknowledge_worker_reports", "--all", by="operator-ann", stdout=out)
    assert f"worker report {b_id} (stale) acknowledged by operator-ann" in out.getvalue()
    assert _health() == {"status": "ok", "message": "Django backend is alive."}


@pytest.mark.django_db
def test_a_live_workers_report_cannot_be_acknowledged(reports):
    b = reports.worker_b(lost=2)
    b_id = b.published()
    with pytest.raises(CommandError, match="live worker"):
        call_command("acknowledge_worker_reports", b_id, by="operator-ann", stdout=io.StringIO())
    out = io.StringIO()
    call_command("acknowledge_worker_reports", "--all", by="operator-ann", stdout=out)
    assert "nothing to acknowledge" in out.getvalue()
    assert _health()["degraded"] == {"stderr_lines_lost": 2}
    assert not (reports.directory / worker_reports.ACKNOWLEDGED).exists()
    b.exit()


@pytest.mark.django_db
def test_a_worker_that_exits_with_nothing_counted_leaves_nothing_to_acknowledge(reports):
    b = reports.worker_b(lost=0)
    b.published()
    b.exit()
    assert not b.report_path().exists()
    assert _health() == {"status": "ok", "message": "Django backend is alive."}


# --------------------------------------------------- never on a stop's path


def test_a_publish_is_never_made_in_the_requests_thread(reports, monkeypatch):
    """A request starts the publisher; the publisher thread writes, the request never."""
    writers = []
    real = worker_reports.publish

    def publish(*args, **kwargs):
        writers.append(threading.current_thread().name)
        return real(*args, **kwargs)

    monkeypatch.setattr(worker_reports, "publish", publish)
    monkeypatch.setattr(dispatch, "start_owed_sweeper", lambda: False)
    dispatch.ensure_owed_sweeper()
    assert _wait_for(lambda: writers), "the publisher never published"
    assert set(writers) == {worker_reports.PUBLISHER_THREAD}, writers
    assert _wait_for((reports.directory / f"{worker_reports.worker_id()}.json").exists)


def test_a_report_carries_its_workers_identity_and_whole_number_counts_only(reports):
    """A report is a sink (tests/test_no_planted_secret_leaves_through_a_sink.py): it
    holds a fixed set of fields and whole-number counts, never a byte of a request."""
    assert worker_reports.publish({"stderr_lines_lost": 2, worker_reports.UNPUBLISHED: 0}) is True
    report = json.loads((reports.directory / f"{worker_reports.worker_id()}.json").read_text(encoding="utf-8"))
    assert set(report) == {"id", "host", "pid", "published", "published_at", "exited", "counts"}, report
    assert report["counts"] == {"stderr_lines_lost": 2, worker_reports.UNPUBLISHED: 0}
    assert report["id"] == worker_reports.worker_id() and len(report["id"]) == 16
    assert report["pid"] == os.getpid() and report["exited"] is False
    assert worker_reports._parse(json.dumps(report).encode()) == report
    for bad in ({"x": "a secret"}, {"x": 1.5}, {"x": True}, {"x": -1}):
        with pytest.raises(ValueError):
            worker_reports._parse(json.dumps({**report, "counts": bad}).encode())


def test_a_failed_publish_is_counted_and_shown(reports, monkeypatch):
    def refused(directory, report_id, data):
        raise OSError("no space left on device")

    monkeypatch.setattr(worker_reports, "_write", refused)
    assert worker_reports.publish({"stderr_lines_lost": 0}) is False
    assert worker_reports.PUBLISH_FAILED[0] == 1
    assert worker_reports.local_counts(dispatch.degraded_counts)[worker_reports.UNPUBLISHED] == 1


@pytest.mark.django_db
def test_a_failed_publish_reads_degraded_in_health(reports, monkeypatch):
    worker_reports.PUBLISH_FAILED[0] = 2
    body = _health()
    assert body["status"] == "degraded", body
    assert body["degraded"] == {worker_reports.UNPUBLISHED: 2}, body


def test_a_publisher_that_cannot_start_is_started_again_after_a_backoff(reports, monkeypatch, caplog):
    real_start = threading.Thread.start
    refused = []

    def start(self):
        if self.name == worker_reports.PUBLISHER_THREAD and not refused:
            refused.append(1)
            raise RuntimeError("can't start new thread")
        return real_start(self)

    monkeypatch.setattr(threading.Thread, "start", start)
    with caplog.at_level(logging.ERROR, logger="assurance.worker_reports"):
        for _ in range(100):
            worker_reports.ensure_publisher(dispatch.degraded_counts)
        oplog.drain()
        assert caplog.text.count("could not start this worker's report publisher") == 1, caplog.text
    worker_reports._RETRY["next"] = 0.0
    worker_reports.ensure_publisher(dispatch.degraded_counts)
    pid, thread, *_rest = worker_reports._PUBLISHER[0]
    assert pid == os.getpid() and thread.is_alive() and thread.name == worker_reports.PUBLISHER_THREAD


@pytest.mark.django_db(transaction=True)
def test_a_stop_is_answered_within_its_bound_while_every_publish_hangs_and_fails(reports, monkeypatch):
    """Every publish hangs for HOLD seconds and then fails. A pause sent through the
    WSGI entry point -- the process's first, which starts the publisher -- and a
    second one, while the publisher is stuck in its write, each answer within the
    bound a stop is held to (``PROMPT``); the failed publishes are counted and read
    degraded in health."""
    from django.contrib.auth import get_user_model
    from django.utils import timezone

    from assurance.decision import recompute_decision
    from assurance.models import Deployment
    from tests.test_no_control_holds_back_a_stop import _wsgi_bearer_client
    from tests.test_no_dispatch_holds_back_a_stop import HOLD, PROMPT

    User = get_user_model()
    writing = threading.Event()

    def hangs_then_fails(directory, report_id, data):
        writing.set()
        time.sleep(HOLD)
        raise OSError("the report directory hangs, then refuses")

    monkeypatch.setattr(worker_reports, "_write", hangs_then_fails)
    admin = User.objects.create_user(username="admin-health", password="x", role=User.Roles.ADMIN)
    deployments = []
    for n in range(2):
        dep = Deployment.objects.create(name=f"health-{n}", owner=admin)
        Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
        recompute_decision(Deployment.objects.get(pk=dep.pk))
        deployments.append(Deployment.objects.get(pk=dep.pk))
    warm = APIClient()
    warm.force_authenticate(user=admin)
    # The first request of a process imports the URLconf: paid outside the entry point,
    # so the first request through it is still the one that starts the publisher.
    warm.get(f"/api/assurance/deployments/{deployments[0].uuid}/dispatch-attempts/")
    assert worker_reports._PUBLISHER == []
    client = _wsgi_bearer_client(admin)
    with override_settings(ASSURANCE_DISPATCH_SWEEP_SECONDS=0):
        took = []
        for n, dep in enumerate(deployments):
            began = time.monotonic()
            answer = client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json")
            took.append(time.monotonic() - began)
            assert answer.status_code == 200, answer.content
            assert answer.json()["decision"] == Deployment.Decision.PAUSED
            if n == 0:
                assert worker_reports._PUBLISHER, "the first request did not start the publisher"
                assert writing.wait(10), "the publisher never began its write"
    assert all(t < PROMPT for t in took), f"a pause waited on a publish: {took}"
    assert _wait_for(lambda: worker_reports.PUBLISH_FAILED[0] >= 1, timeout=HOLD + 10)
    body = _health()
    assert body["status"] == "degraded", body
    assert body["degraded"][worker_reports.UNPUBLISHED] >= 1, body
