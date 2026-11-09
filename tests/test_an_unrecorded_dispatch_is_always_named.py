"""A dispatch past its bound is always named on stderr, or counted -- never dropped.

A dispatch that its stop could not record, and that is not started because this
process already runs its hard bound of dispatch threads, is known to nothing else:
no sweep will ever find it. The one line that names it (``dispatch.
_unrecorded_not_started`` through ``oplog.emit_now``) must reach stderr. It used not
to when stderr was slow:

- where ``select`` cannot be asked (Windows), a line emitted while the writer thread
  was still writing the line before it was skipped, and never written;
- where it can (POSIX), a line emitted while the stderr pipe was full was skipped,
  and never written, even once the pipe drained.

Both were counted in ``oplog.STDERR_SKIPPED``, which nothing reads, so a dispatch past
its bound could go unnamed on stderr with no trace there. Now such a line waits,
queued, for the one stderr writer and is written once stderr takes it; a line past
that queue's bound, or one stderr fails to take, is counted in ``oplog.STDERR_LOST``
and the count is logged. The stop that emits the line never waits for any of it.

Each test here runs on any host: the Windows case is given a ``select`` that fails
as Windows' does (WSAENOTSOCK), and the POSIX case, where the real ``select`` cannot
answer about a pipe, is given one that answers for the test's pipe.
"""

from __future__ import annotations

import logging
import os
import re
import select
import sys
import threading
import time
import types

import pytest
from django.test import override_settings

from assurance import dispatch, oplog

#: What Windows raises for select() on a descriptor that is not a socket.
WSAENOTSOCK = 10038
LINE = "run `manage.py retry_blocking_dispatches --deployment %s`"
#: The longest a stop's call may take here: it waits on nothing, so it takes
#: milliseconds; the bound only has to tell that from waiting on stderr.
PROMPT = 0.5
#: How long a stalled stderr stays stalled before the test lets it go.
STALL = 2.0


def _select_takes_sockets_only(*_args):
    raise OSError(WSAENOTSOCK, "An operation was attempted on something that is not a socket")


class _Os:
    """``oplog``'s ``os``, with a ``write`` that is a slow stderr (each write takes
    ``seconds``), a stalled one (it blocks until ``go`` is set) or a failing one.
    Everything else is the real ``os``."""

    def __init__(self, seconds=0.0, stalled=False, fails=False):
        self._os = os
        self.seconds = seconds
        self.fails = fails
        self.go = threading.Event()
        if not stalled:
            self.go.set()
        self.entered = threading.Event()
        self.written: list[bytes] = []

    def write(self, descriptor, data):
        self.entered.set()
        assert self.go.wait(10), "the test never let the stalled write go"
        time.sleep(self.seconds)
        if self.fails:
            raise BrokenPipeError(32, "Broken pipe")
        self.written.append(bytes(data))
        return len(data)

    def __getattr__(self, name):
        return getattr(self._os, name)


def _named(chunks) -> list[int]:
    """The deployments named, in the order their lines were written."""
    text = b"".join(chunks).decode("utf-8", "replace")
    return [int(n) for n in re.findall(r"--deployment (\d+)`", text)]


def _stderr_writers():
    return [t for t in threading.enumerate() if t.name == "assurance-stderr" and t.is_alive()]


def _settle(timeout=10.0):
    """Wait until no thread is writing a line to stderr."""
    deadline = time.monotonic() + timeout
    while _stderr_writers() and time.monotonic() < deadline:
        for writer in _stderr_writers():
            writer.join(max(0.0, deadline - time.monotonic()))
    assert not _stderr_writers(), "the stderr writer did not finish"


def _dispatches_settle(timeout=10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        running = [t for t in threading.enumerate() if t.name.startswith(dispatch.THREAD_PREFIX)]
        if not running:
            return
        time.sleep(0.02)
    raise AssertionError("a background dispatch was still running")


@pytest.fixture
def windows_stderr(monkeypatch, tmp_path):
    """stderr as on Windows: ``select`` takes sockets only. stderr itself is a file
    (the tests that need it read what the stand-in ``os`` was given instead)."""
    path = tmp_path / "stderr.txt"
    with path.open("wb") as sink:
        monkeypatch.setattr(sys, "__stderr__", sink)
        monkeypatch.setattr(oplog, "select", types.SimpleNamespace(select=_select_takes_sockets_only))
        yield path
        monkeypatch.undo()
        _settle()


class _FullPipe:
    """stderr as a pipe nobody has read yet: full. ``drain`` starts a reader."""

    def __init__(self, monkeypatch):
        self.read_fd, self.write_fd = os.pipe()
        os.set_blocking(self.write_fd, False)
        try:
            while True:
                os.write(self.write_fd, b"x" * 65536)
        except BlockingIOError:
            pass
        os.set_blocking(self.write_fd, True)
        self.full = True
        self.read: list[bytes] = []
        self._reader = None
        try:
            select.select([], [self.write_fd], [], 0)
        except OSError:
            # Windows: select cannot answer about a pipe. The POSIX case is what is
            # tested, so it is given a select that answers as POSIX's would.
            def answer(_readers, writers, _errors, _timeout):
                return [], ([] if self.full else list(writers)), []

            monkeypatch.setattr(oplog, "select", types.SimpleNamespace(select=answer))

    def fileno(self):
        return self.write_fd

    def drain(self):
        def read():
            while True:
                try:
                    chunk = os.read(self.read_fd, 65536)
                except OSError:
                    return
                if not chunk:
                    return
                self.read.append(chunk)

        self.full = False
        self._reader = threading.Thread(target=read, daemon=True)
        self._reader.start()

    def wait_for(self, deployments, timeout=10.0) -> list[int]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline and _named(self.read) != deployments:
            time.sleep(0.01)
        return _named(self.read)

    def close(self):
        if self._reader is None:
            os.close(self.read_fd)
            os.close(self.write_fd)
            return
        # The write end first: the reader then reads to the end and returns. On
        # Windows, closing a pipe's read end while another thread is blocked reading
        # it waits for that read -- which, with the write end still open, never ends.
        os.close(self.write_fd)
        self._reader.join(5)
        if not self._reader.is_alive():
            os.close(self.read_fd)


def _logged(caplog, text, timeout=5.0):
    oplog.drain(timeout)
    return text in caplog.text


# ------------------------------------------------------------------- the writer


def test_a_slow_stderr_where_select_cannot_be_asked_gets_every_line(windows_stderr, monkeypatch):
    """Windows: each line takes 50 ms to write. Six lines are emitted at once: the
    first is handed to the writer, the five behind it wait for it -- none is
    dropped -- and the caller never waits."""
    slow = _Os(seconds=0.05)
    monkeypatch.setattr(oplog, "os", slow)
    skipped = oplog.STDERR_SKIPPED[0]
    took = []
    for deployment in range(1, 7):
        began = time.monotonic()
        oplog.emit_now(logging.ERROR, LINE, deployment)
        took.append(time.monotonic() - began)
    assert max(took) < PROMPT, took
    assert oplog.STDERR_SKIPPED[0] > skipped, "no line had to wait: the stderr was not slow"
    _settle()
    assert _named(slow.written) == [1, 2, 3, 4, 5, 6], slow.written
    oplog.drain()


def test_a_full_stderr_pipe_gets_its_line_once_it_drains(monkeypatch):
    """POSIX: stderr is a pipe nobody is reading, full. The line is not written in
    the caller's thread -- a write would block -- and the call returns at once; once
    the pipe is read, the line is there."""
    err = _FullPipe(monkeypatch)
    monkeypatch.setattr(sys, "__stderr__", err)
    skipped = oplog.STDERR_SKIPPED[0]
    try:
        began = time.monotonic()
        oplog.emit_now(logging.ERROR, LINE, 7)
        took = time.monotonic() - began
        assert took < PROMPT, took
        assert oplog.STDERR_SKIPPED[0] == skipped + 1
        err.drain()
        assert err.wait_for([7]) == [7], "the line never reached stderr once it drained"
        _settle()
    finally:
        monkeypatch.undo()
        err.close()
        _settle()
    oplog.drain()


def test_past_the_bound_a_line_is_counted_lost_and_the_count_is_logged(windows_stderr, monkeypatch, caplog):
    """stderr has stalled. One line is being written, three wait (the bound here),
    and the two past them are counted lost -- never dropped silently -- and the count
    is logged once stderr is taking lines again. Each line is in the log too."""
    stalled = _Os(stalled=True)
    monkeypatch.setattr(oplog, "os", stalled)
    monkeypatch.setattr(oplog, "MAX_STDERR_PENDING", 3, raising=False)
    lost = oplog.__dict__.get("STDERR_LOST", [0])[0]
    with caplog.at_level(logging.WARNING, logger="assurance.dispatch"):
        try:
            oplog.emit_now(logging.ERROR, LINE, 1)
            assert stalled.entered.wait(5), "the first line was never handed to a writer"
            began = time.monotonic()
            for deployment in range(2, 7):
                oplog.emit_now(logging.ERROR, LINE, deployment)
            assert time.monotonic() - began < PROMPT
            assert oplog.STDERR_LOST[0] == lost + 2, "the two lines past the bound were not counted"
        finally:
            stalled.go.set()
            _settle()
        assert _named(stalled.written) == [1, 2, 3, 4], stalled.written
        assert _logged(caplog, "2 line(s) meant for stderr were not written to it"), caplog.text
        for deployment in range(1, 7):
            assert _logged(caplog, f"--deployment {deployment}`"), deployment


def test_a_line_stderr_fails_to_take_is_counted_lost_and_the_count_is_logged(windows_stderr, monkeypatch, caplog):
    broken = _Os(fails=True)
    monkeypatch.setattr(oplog, "os", broken)
    lost = oplog.__dict__.get("STDERR_LOST", [0])[0]
    with caplog.at_level(logging.WARNING, logger="assurance.dispatch"):
        oplog.emit_now(logging.ERROR, LINE, 8)
        _settle()
        assert oplog.STDERR_LOST[0] == lost + 1
        assert _logged(caplog, "1 line(s) meant for stderr were not written to it"), caplog.text


# ---------------------------------------------- dispatches past the hard bound


def _past_the_bound(first: int, count: int):
    """Unrecorded dispatches: the hard bound is 4 threads (twice 1 run + 1 waiting).
    The first four start; the ``count`` after them are refused, each named. Returns
    the outcomes and how long each stop's call took."""
    outcomes, took = [], []
    with override_settings(ASSURANCE_DISPATCH_MAX_CONCURRENT_RUNS=1, ASSURANCE_DISPATCH_MAX_WAITING_RUNS=1):
        for n in range(4 + count):
            began = time.monotonic()
            outcomes.append(dispatch.start_blocking_decision_dispatch(first + n, unrecorded=True))
            took.append(time.monotonic() - began)
    return outcomes, took


@pytest.fixture
def held_dispatches(monkeypatch):
    released = threading.Event()
    monkeypatch.setattr(dispatch, "_blocking_dispatch_job", lambda pk, **kw: released.wait(10))
    monkeypatch.setattr(dispatch, "_JOBS", {})
    yield
    released.set()
    _dispatches_settle()


def test_every_dispatch_past_its_bound_is_named_on_a_stalled_stderr_and_no_stop_waits(
    windows_stderr, monkeypatch, held_dispatches
):
    """Windows: stderr stalls for 2 s. Six dispatches past the hard bound: each stop's
    call returns at once, and once stderr takes lines again all six are named."""
    stalled = _Os(stalled=True)
    monkeypatch.setattr(oplog, "os", stalled)
    release = threading.Timer(STALL, stalled.go.set)
    release.start()
    try:
        outcomes, took = _past_the_bound(7000, 6)
        assert outcomes == [dispatch.STARTED] * 4 + [dispatch.FULL] * 6
        assert max(took) < PROMPT, took
    finally:
        release.join()
        _settle()
    assert _named(stalled.written) == list(range(7004, 7010)), stalled.written


def test_every_dispatch_past_its_bound_is_named_once_a_full_stderr_pipe_drains(monkeypatch, held_dispatches):
    """POSIX: stderr is a full pipe. Six dispatches past the hard bound: each stop's
    call returns at once, and once the pipe is read all six are named on it."""
    err = _FullPipe(monkeypatch)
    real = sys.__stderr__
    monkeypatch.setattr(sys, "__stderr__", err)
    try:
        outcomes, took = _past_the_bound(7100, 6)
        assert outcomes == [dispatch.STARTED] * 4 + [dispatch.FULL] * 6
        assert max(took) < PROMPT, took
        err.drain()
        assert err.wait_for(list(range(7104, 7110))) == list(range(7104, 7110))
        _settle()
    finally:
        monkeypatch.setattr(sys, "__stderr__", real)
        err.close()
        _settle()
    oplog.drain()


# ------------------------------------------------- every count where it is seen

#: Each count, and the counter that holds it.
COUNTERS = {
    "stderr_lines_lost": (oplog, "STDERR_LOST"),
    "log_records_dropped": (oplog, "LOG_DROPPED"),
    "unrecorded_dispatches_refused": (dispatch, "_UNRECORDED_REFUSED"),
}


@pytest.fixture
def counts_at_zero(monkeypatch):
    for module, name in COUNTERS.values():
        monkeypatch.setattr(module, name, [0], raising=False)
    monkeypatch.setattr(dispatch, "_DEGRADED_REPORTED", [{}], raising=False)


def _health():
    from rest_framework.test import APIClient

    answer = APIClient().get("/api/health/")
    assert answer.status_code == 200, answer.content
    return answer.json()


@pytest.mark.django_db
def test_health_is_ok_only_while_every_count_is_zero(counts_at_zero):
    # "ok" names every count it read, each 0 (#226 adds the fourth, a worker's
    # report it could not publish), and no worker with a count.
    assert _health() == {
        "status": "ok",
        "message": "Django backend is alive.",
        "counts": {
            "stderr_lines_lost": 0,
            "log_records_dropped": 0,
            "unrecorded_dispatches_refused": 0,
            "worker_reports_unpublished": 0,
        },
        "workers": {},
    }


@pytest.mark.django_db
@pytest.mark.parametrize("count", sorted(COUNTERS))
def test_each_non_zero_count_reads_degraded_in_health_never_ok(count, counts_at_zero, monkeypatch):
    module, name = COUNTERS[count]
    monkeypatch.setattr(module, name, [3])
    body = _health()
    assert body["status"] == "degraded", body
    assert body["degraded"] == {count: 3}, body
    assert f"{count}=3" in body["message"], body


@pytest.mark.django_db
def test_health_reads_unknown_never_ok_when_the_counts_cannot_be_read(counts_at_zero, monkeypatch):
    def unreadable():
        raise RuntimeError("no counts")

    monkeypatch.setattr(dispatch, "degraded_counts", unreadable)
    assert _health()["status"] == "unknown"


@pytest.mark.django_db
@pytest.mark.parametrize("count", sorted(COUNTERS))
def test_each_non_zero_count_is_in_the_sweeps_warning(count, counts_at_zero, monkeypatch, caplog):
    module, name = COUNTERS[count]
    monkeypatch.setattr(module, name, [3])
    with caplog.at_level(logging.WARNING, logger="assurance.dispatch"):
        caplog.clear()
        dispatch.sweep_owed_blocking_dispatches()
        assert f"this process is degraded since it started: {count}=3" in caplog.text, caplog.text
        # Once per change, not on every sweep; again when the count moves.
        caplog.clear()
        dispatch.sweep_owed_blocking_dispatches()
        assert "degraded" not in caplog.text, caplog.text
        getattr(module, name)[0] += 1
        dispatch.sweep_owed_blocking_dispatches()
        assert f"{count}=4" in caplog.text, caplog.text


@pytest.mark.django_db
def test_the_sweep_says_nothing_while_every_count_is_zero(counts_at_zero, caplog):
    with caplog.at_level(logging.WARNING, logger="assurance.dispatch"):
        dispatch.sweep_owed_blocking_dispatches()
    assert "degraded" not in caplog.text, caplog.text


def test_a_record_dropped_from_the_full_log_queue_is_counted_for_good(monkeypatch):
    """The log queue's own drop count is reset once the drop is logged; the count
    health and the sweep read is not."""
    oplog.drain()
    monkeypatch.setattr(oplog, "start_pump", lambda: False)
    monkeypatch.setattr(oplog, "_BUF", type(oplog._BUF)())
    monkeypatch.setattr(oplog, "_COND", threading.Condition(threading.Lock()))
    monkeypatch.setattr(oplog, "_DROPPED", [0])
    monkeypatch.setattr(oplog, "LOG_DROPPED", [0], raising=False)
    monkeypatch.setattr(oplog, "MAX_QUEUED", 2)
    for n in range(5):
        oplog.log_later(logging.WARNING, "record %d", n)
    assert oplog.queued() == 2
    assert oplog.LOG_DROPPED[0] == 3
    assert dispatch.degraded_counts()["log_records_dropped"] == 3


def test_reading_the_counts_takes_no_lock_a_stop_takes(counts_at_zero):
    """Health and the sweep read the counts while a stop may hold the dispatch and
    log locks: the read must not wait for any of them."""
    held = [dispatch._JOBS_LOCK, oplog._STDERR_LOCK, oplog._PUMP_LOCK]
    for lock in held:
        assert lock.acquire(timeout=5)
    cond = oplog._COND
    assert cond.acquire(timeout=5)
    try:
        answer = []
        reader = threading.Thread(target=lambda: answer.append(dispatch.degraded_counts()), daemon=True)
        reader.start()
        reader.join(2)
        assert answer, "reading the counts waited on a lock a stop takes"
    finally:
        cond.release()
        for lock in held:
            lock.release()
