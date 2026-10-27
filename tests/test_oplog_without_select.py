"""The line an operator must see now, where ``select`` cannot be asked (Windows).

``oplog._write_stderr_now`` asks ``select.select`` whether stderr would take a line
without waiting, and writes only if so (the SAFETY RULE: the caller is a stop's
thread and must never wait on a stalled stderr). Windows' ``select`` takes sockets
only: on stderr, a console or a pipe, it fails with WSAENOTSOCK (WinError 10038),
which the old code counted as "stderr cannot take it" -- so the line never reached
stderr, on any Windows run.

These tests run that case on any host: ``oplog`` is given a ``select`` that fails as
Windows' does. The line must reach stderr; the caller must still never wait, even on
a stderr that has stalled; and a stalled stderr must strand one thread, not one per
line. The POSIX behaviour (``select`` answers; a full pipe is skipped and counted)
stays covered by ``test_no_dispatch_holds_back_a_stop.py``.
"""

from __future__ import annotations

import errno
import logging
import os
import sys
import threading
import time
import types

import pytest

from assurance import oplog

#: What Windows raises for select() on a descriptor that is not a socket.
WSAENOTSOCK = 10038
LINE = "run `manage.py retry_blocking_dispatches --deployment %s`"


def _select_takes_sockets_only(*_args):
    raise OSError(WSAENOTSOCK, "An operation was attempted on something that is not a socket")


class _Os:
    """``oplog``'s ``os``, with a ``write`` that is a stderr which has stalled: it
    blocks until the test lets it go. Everything else is the real ``os``."""

    def __init__(self):
        self._os = os
        self.go = threading.Event()
        self.entered = threading.Event()
        self.written: list[bytes] = []

    def write(self, descriptor, data):
        self.entered.set()
        assert self.go.wait(10), "the test never let the stalled write go"
        self.written.append(bytes(data))
        return len(data)

    def __getattr__(self, name):
        return getattr(self._os, name)


@pytest.fixture
def windows_stderr(monkeypatch, tmp_path):
    """stderr as on Windows: ``select`` takes sockets only. stderr itself is a file
    the test reads back."""
    path = tmp_path / "stderr.txt"
    with path.open("wb") as sink:
        monkeypatch.setattr(sys, "__stderr__", sink)
        monkeypatch.setattr(oplog, "select", types.SimpleNamespace(select=_select_takes_sockets_only))
        yield path
        _settle()


def _settle():
    """Wait for the thread that is writing a line to stderr, if there is one."""
    for writer in list(getattr(oplog, "_STDERR_WRITER", [])):
        writer.join(10)
        assert not writer.is_alive(), "the stderr writer did not finish"


def _stderr_threads():
    return [t for t in threading.enumerate() if t.name == "assurance-stderr" and t.is_alive()]


def test_the_line_an_operator_must_see_reaches_stderr_where_select_takes_sockets_only(windows_stderr):
    skipped = oplog.STDERR_SKIPPED[0]
    began = time.monotonic()
    oplog.emit_now(logging.ERROR, LINE, 9)
    took = time.monotonic() - began
    _settle()
    text = windows_stderr.read_text(encoding="utf-8")
    assert took < 0.5, took
    assert text.count("\n") == 1 and "retry_blocking_dispatches --deployment 9" in text and "ERROR" in text, text
    assert oplog.STDERR_SKIPPED[0] == skipped, "a line that reached stderr was counted as lost"
    oplog.drain()


def test_a_stalled_stderr_never_holds_the_caller_and_strands_one_thread_not_one_per_line(windows_stderr, monkeypatch):
    stalled = _Os()
    monkeypatch.setattr(oplog, "os", stalled)
    skipped = oplog.STDERR_SKIPPED[0]
    try:
        began = time.monotonic()
        for deployment in (1, 2, 3):
            oplog.emit_now(logging.ERROR, LINE, deployment)
        took = time.monotonic() - began
        assert stalled.entered.wait(5), "the first line was never handed to a writer"
        assert took < 0.5, took
        assert len(_stderr_threads()) == 1, _stderr_threads()
        assert oplog.STDERR_SKIPPED[0] == skipped + 2, "the two lines stderr could not take were not counted"
    finally:
        stalled.go.set()
        _settle()
    assert len(stalled.written) == 1 and b"--deployment 1" in stalled.written[0], stalled.written
    # stderr is taking lines again: the next one is written
    monkeypatch.setattr(oplog, "os", os)
    oplog.emit_now(logging.ERROR, LINE, 4)
    _settle()
    assert "--deployment 4" in windows_stderr.read_text(encoding="utf-8")
    oplog.drain()


def test_no_thread_to_write_it_is_counted_and_never_waited_for(windows_stderr, monkeypatch):
    """The process is out of threads: the line cannot be written without waiting, so it
    is counted (the record still waits for the log thread), and the lock that keeps
    one writer at a time is not left held."""
    skipped = oplog.STDERR_SKIPPED[0]
    real_start = threading.Thread.start

    def refuse(self):
        if self.name == "assurance-stderr":
            raise RuntimeError("can't start new thread")
        return real_start(self)

    monkeypatch.setattr(threading.Thread, "start", refuse)
    began = time.monotonic()
    oplog.emit_now(logging.ERROR, LINE, 5)
    took = time.monotonic() - began
    monkeypatch.setattr(threading.Thread, "start", real_start)
    assert took < 0.5, took
    assert oplog.STDERR_SKIPPED[0] == skipped + 1
    assert windows_stderr.read_bytes() == b""
    oplog.emit_now(logging.ERROR, LINE, 6)  # threads can start again
    _settle()
    text = windows_stderr.read_text(encoding="utf-8")
    assert "--deployment 6" in text and "--deployment 5" not in text, text
    oplog.drain()


def test_select_failing_for_another_reason_is_not_taken_for_windows(monkeypatch, tmp_path):
    """Only WSAENOTSOCK means "select cannot be asked here". A closed descriptor is
    still a skipped line, as on POSIX: no thread, no write."""

    def bad_descriptor(*_args):
        raise OSError(errno.EBADF, "Bad file descriptor")

    with (tmp_path / "stderr.txt").open("wb") as sink:
        monkeypatch.setattr(sys, "__stderr__", sink)
        monkeypatch.setattr(oplog, "select", types.SimpleNamespace(select=bad_descriptor))
        skipped = oplog.STDERR_SKIPPED[0]
        assert oplog._write_stderr_now("one line") is False
    assert oplog.STDERR_SKIPPED[0] == skipped + 1
    assert _stderr_threads() == []
    assert (tmp_path / "stderr.txt").read_bytes() == b""


def test_the_exit_waits_a_moment_for_a_line_handed_to_the_writer(windows_stderr, monkeypatch):
    stalled = _Os()
    monkeypatch.setattr(oplog, "os", stalled)
    monkeypatch.setattr(oplog, "STDERR_AT_EXIT_SECONDS", 5.0)
    oplog.emit_now(logging.ERROR, LINE, 6)
    assert stalled.entered.wait(5)
    threading.Timer(0.2, stalled.go.set).start()
    oplog._flush_at_exit()
    assert len(stalled.written) == 1, "the exit left before the line was written"
    assert _stderr_threads() == []
    oplog.drain()
