"""Two ways to log from a path that must not wait, chosen by what the line is for.

- :func:`emit_now` -- for what an operator must see to recover work that would
  otherwise be lost: a dispatch that is neither recorded nor started. In the
  calling thread (a stop's), at once, it writes ONE line to stderr, and only if
  stderr can take it without waiting (``select``); it never writes to a log
  handler, whose sink may be slow or stalled. The record for the handlers goes
  through :func:`log_later`. When no thread can start, it waits in the queue --
  bounded, and counted in :data:`KEPT_FOR_WRITER` -- until a later request, the
  sweeper or the exit starts or runs the writer.
- :func:`log_later` -- for everything else (noise, as far as recovery goes): the
  record is made here, with its time, thread and message, and written by a
  background thread, so a slow or stalled log sink never holds a stop or a lock a
  stop needs. The queue is bounded (:data:`MAX_QUEUED`): past it the oldest
  records are dropped and counted, and the count is logged. What is still queued
  when the process exits is written then, for at most :data:`FLUSH_AT_EXIT_SECONDS`.

Fork-safe: a forked child starts with its own empty queue, lock and pump.
"""

from __future__ import annotations

import atexit
import collections
import logging
import os
import select
import sys
import threading
import time
import traceback

logger = logging.getLogger("assurance.dispatch")

#: Records :func:`log_later` holds at most; past it the oldest are dropped.
MAX_QUEUED = 1000
#: How long the process's exit waits for what is still queued.
FLUSH_AT_EXIT_SECONDS = 2.0
#: The longest line :func:`emit_now` writes.
MAX_LINE = 600
PUMP_THREAD = "assurance-log"

_BUF: collections.deque = collections.deque()
_COND = threading.Condition(threading.Lock())
_DROPPED = [0]
#: This process's pump, as ``[(pid, thread)]``.
_PUMP: list = []
_PUMP_LOCK = threading.Lock()
#: Lines :func:`emit_now` could not write to stderr without waiting.
STDERR_SKIPPED = [0]


#: Whether the pump is writing a record now.
_BUSY = [False]


def _pump() -> None:
    while True:
        with _COND:
            _BUSY[0] = False
            while not _BUF:
                _COND.wait()
            record = _BUF.popleft()
            _BUSY[0] = True
            dropped, _DROPPED[0] = _DROPPED[0], 0
        if dropped:
            _handle(
                logger.makeRecord(
                    logger.name, logging.WARNING, "", 0,
                    "%d deferred log record(s) were dropped: the log sink fell %d records behind",
                    (dropped, MAX_QUEUED), None,
                )
            )
        _handle(record)


def _handle(record) -> None:
    try:
        logging.getLogger(record.name).handle(record)
    except Exception:  # noqa: BLE001, S110 - a log that cannot be written is dropped
        pass


def start_pump() -> bool:
    """Start this process's pump if it has none running. Never raises."""
    pid = os.getpid()
    current = _PUMP[0] if _PUMP else None
    if current is not None and current[0] == pid and current[1].is_alive():
        return True
    try:
        with _PUMP_LOCK:
            current = _PUMP[0] if _PUMP else None
            if current is not None and current[0] == pid and current[1].is_alive():
                return True
            thread = threading.Thread(target=_pump, name=PUMP_THREAD, daemon=True)
            thread.start()
            _PUMP[:] = [(pid, thread)]
            return True
    except Exception:  # noqa: BLE001 - e.g. no thread can start; the records wait, bounded
        return False


def log_later(level, msg, *args, exc=False, logger_name=None) -> bool:
    """Log from the background pump, never here. ``exc``: include the traceback of
    the exception being handled (as text: no frame is kept alive). Never raises.
    Returns whether the pump is running to write it (``False``: it waits, queued)."""
    try:
        target = logging.getLogger(logger_name) if logger_name else logger
        if not target.isEnabledFor(level):
            return True
        record = target.makeRecord(target.name, level, "", 0, msg, args, None)
        record.msg, record.args = record.getMessage(), None
        if exc and sys.exc_info()[0] is not None:
            record.exc_text = "".join(traceback.format_exception(*sys.exc_info())).rstrip()
        with _COND:
            if len(_BUF) >= MAX_QUEUED:
                _BUF.popleft()
                _DROPPED[0] += 1
            _BUF.append(record)
            _COND.notify()
    except Exception:  # noqa: BLE001, S110 - never raised into a stop
        return False
    return start_pump()


def queued() -> int:
    return len(_BUF)


def dropped() -> int:
    return _DROPPED[0]


def _write_stderr_now(line: str) -> bool:
    """One line to stderr if it can take it without waiting; ``False`` if not."""
    data = (line.replace("\n", " ")[:MAX_LINE] + "\n").encode("utf-8", "replace")
    try:
        try:
            fd = sys.__stderr__.fileno() if sys.__stderr__ is not None else 2
        except (AttributeError, ValueError, OSError):
            fd = 2
        _, writable, _ = select.select([], [fd], [], 0)
        if not writable:
            STDERR_SKIPPED[0] += 1
            return False
        # Under PIPE_BUF bytes: one write, and a pipe that is writable has room for it.
        os.write(fd, data)
        return True
    except (OSError, ValueError):
        STDERR_SKIPPED[0] += 1
        return False


#: Records :func:`emit_now` queued while no writer thread could start: they wait,
#: bounded, for the next request, sweep or exit to start or run the writer.
KEPT_FOR_WRITER = [0]


def emit_now(level, msg, *args, logger_name=None) -> None:
    """Write one line an operator must see, now, in this thread, depending on no
    other thread and waiting on nothing: to stderr, only if it can take the line
    without waiting. This thread never writes to a log handler -- a slow or
    stalled sink would hold it (a stop's answer) -- so the record for the handlers
    is queued for the log thread (:func:`log_later`); when no thread can start, it
    waits there, bounded and counted (:data:`KEPT_FOR_WRITER`). Never raises. Keep
    ``msg`` to one short line."""
    target = logging.getLogger(logger_name) if logger_name else logger
    try:
        text = msg % args if args else str(msg)
    except Exception:  # noqa: BLE001 - a malformed message is still written
        text = f"{msg} {args!r}"
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    _write_stderr_now(f"{stamp} {logging.getLevelName(level)} {target.name} {text}")
    if not log_later(level, "%s", text, logger_name=logger_name):
        KEPT_FOR_WRITER[0] += 1


def drain(limit: float = 5.0) -> int:
    """Wait, for at most ``limit`` seconds, until everything queued is written:
    through the pump while it runs, here if it does not. Returns how many records
    are left. For the process's exit, and for a test that reads what was logged."""
    deadline = time.monotonic() + limit
    pid = os.getpid()
    while time.monotonic() < deadline:
        with _COND:
            if not _BUF and not _BUSY[0]:
                return 0
            pump = _PUMP[0] if _PUMP else None
            record = None
            if pump is None or pump[0] != pid or not pump[1].is_alive():
                if not _BUF:
                    return 0
                record = _BUF.popleft()
        if record is None:
            time.sleep(0.01)
        else:
            _handle(record)
    return len(_BUF) + int(_BUSY[0])


def _flush_at_exit() -> None:
    left = drain(FLUSH_AT_EXIT_SECONDS)
    if left:
        _write_stderr_now(f"assurance: {left} deferred log record(s) were not written before exit")


atexit.register(_flush_at_exit)


def _after_fork_in_child() -> None:
    global _BUF, _COND, _PUMP_LOCK
    _BUF = collections.deque()
    _COND = threading.Condition(threading.Lock())
    _DROPPED[0] = 0
    _BUSY[0] = False
    _PUMP.clear()
    _PUMP_LOCK = threading.Lock()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
