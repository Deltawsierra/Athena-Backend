"""``oplog.drain`` does not report a record written while another thread is writing it.

A log pump left running by an earlier test pops a record and sets ``_BUSY`` while
``drain`` -- in a test that replaced ``_PUMP`` with ``[]`` -- sees no pump of its
own and an empty queue. It used to return 0 at once, before that record was
handled, so a test reading what was logged raced the write. It waits for the
write now, bounded by ``limit``, and returns the honest count at the deadline.

Deterministic: ``_BUSY`` is set by hand, and cleared by a thread that is let go by
an Event once ``drain`` is known to be waiting -- no sleep decides the outcome.
"""

from __future__ import annotations

import threading
import time

from assurance import oplog


def _own_pump_absent(monkeypatch):
    monkeypatch.setattr(oplog, "_PUMP", [])
    monkeypatch.setattr(oplog, "_BUSY", [False])
    monkeypatch.setattr(oplog, "_BUF", type(oplog._BUF)())


def test_drain_waits_for_a_write_another_thread_has_in_flight(monkeypatch):
    _own_pump_absent(monkeypatch)
    oplog._BUSY[0] = True  # a stray pump popped the last record and is writing it
    polled = threading.Event()
    handled = []
    real_sleep = time.sleep

    def finish_the_write():
        polled.wait(5)  # drain has looked, seen the write in flight, and gone to wait
        handled.append("record 2")
        with oplog._COND:
            oplog._BUSY[0] = False

    def sleep(seconds):
        polled.set()  # drain only sleeps once it has seen the write in flight
        real_sleep(seconds)

    monkeypatch.setattr(oplog.time, "sleep", sleep)
    writer = threading.Thread(target=finish_the_write)
    writer.start()
    try:
        left = oplog.drain(5.0)
        assert handled == ["record 2"], "drain returned before the in-flight write finished"
        assert left == 0
    finally:
        writer.join(5)


def test_drain_returns_at_the_deadline_with_the_leftover_if_the_write_never_ends(monkeypatch):
    _own_pump_absent(monkeypatch)
    oplog._BUSY[0] = True  # never cleared
    started = time.monotonic()
    left = oplog.drain(0.2)
    elapsed = time.monotonic() - started
    assert left == 1
    assert 0.2 <= elapsed < 2.0, "drain must be bounded by its limit"
