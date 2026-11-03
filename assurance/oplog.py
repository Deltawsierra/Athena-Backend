"""Two ways to log from a path that must not wait, chosen by what the line is for.

- :func:`emit_now` -- for what an operator must see to recover work that would
  otherwise be lost: a dispatch that is neither recorded nor started. In the
  calling thread (a stop's), at once, it writes ONE line to stderr, and only if
  stderr can take it without waiting (``select``); it never writes to a log
  handler, whose sink may be slow or stalled. The record for the handlers goes
  through :func:`log_later`. Where ``select`` cannot be asked (Windows takes
  sockets only, and stderr is a console or a pipe), the line is handed to one
  small thread that writes it; this thread still waits on nothing (see
  :func:`_write_stderr_now`). A line stderr cannot take at once -- a full pipe, or
  the writer still busy with the line before it -- is never dropped silently: it
  waits, queued, for that writer, which writes it as soon as stderr takes it. The
  queue is bounded (:data:`MAX_STDERR_PENDING`); a line past it, or one stderr
  fails to take, is counted in :data:`STDERR_LOST`, and the count is written to
  stderr and the log. When no thread can start, the line waits in the queue and
  its record in the log queue -- bounded, and counted in :data:`KEPT_FOR_WRITER`
  -- until a later request, the sweeper or the exit starts or runs the writers.
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
#: Lines :func:`emit_now` could not write to stderr at once, without waiting: each
#: waits, queued, for the stderr writer (:data:`STDERR_LOST` counts any that never
#: reach stderr).
STDERR_SKIPPED = [0]
#: Lines meant for stderr that never reached it: past :data:`MAX_STDERR_PENDING`, or
#: stderr failed to take them. Written to stderr and the log as a count.
STDERR_LOST = [0]
#: How much of :data:`STDERR_LOST` has been written out as a count.
_STDERR_LOST_REPORTED = [0]
#: The most lines that wait for the stderr writer; past it a line is counted lost.
MAX_STDERR_PENDING = 100
#: What Windows' ``select`` fails with on a descriptor that is not a socket
#: (WSAENOTSOCK, "WinError 10038"): it cannot say whether stderr would take a line.
_WSAENOTSOCK = 10038
#: Lines waiting for the stderr writer, oldest first, as ``(descriptor, bytes)``. The
#: descriptor is a duplicate of stderr's, made when the line was emitted: the line
#: goes where stderr was then, and never to a descriptor number reused since.
_STDERR_PENDING: collections.deque = collections.deque()
#: Guards :data:`_STDERR_PENDING` and :data:`_STDERR_WRITING`; held only to add or
#: take a line, never across a write.
_STDERR_LOCK = threading.Lock()
#: Whether the one stderr writer is running: it runs until the queue is empty.
_STDERR_WRITING = [False]
#: That thread, for the exit (and a test) to wait for.
_STDERR_WRITER: list = []
#: The longest the exit waits for it.
STDERR_AT_EXIT_SECONDS = 0.5
STDERR_THREAD = "assurance-stderr"


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


def _select_takes_sockets_only(exc: OSError) -> bool:
    """Is ``exc`` Windows' answer to ``select`` on a descriptor that is not a socket?"""
    return _WSAENOTSOCK in (exc.errno, getattr(exc, "winerror", None))


def _close(fd: int) -> None:
    try:
        os.close(fd)
    except OSError:
        pass


def _stderr_fd() -> int:
    try:
        return sys.__stderr__.fileno() if sys.__stderr__ is not None else 2
    except (AttributeError, ValueError, OSError):
        return 2


def _write_all(fd: int, data: bytes) -> bool:
    try:
        while data:
            data = data[os.write(fd, data):]
    except (OSError, ValueError):
        return False
    return True


def _lost_unreported() -> int:
    return STDERR_LOST[0] - _STDERR_LOST_REPORTED[0]


def _report_lost() -> None:
    """Log the count of lines lost since the last count, from the log thread. Not to
    stderr: it is what failed to take them, and each line is in the log already."""
    lost = _lost_unreported()
    if lost <= 0:
        return
    _STDERR_LOST_REPORTED[0] += lost
    log_later(
        logging.WARNING,
        "%d line(s) meant for stderr were not written to it (more than %d waited for the "
        "stderr writer, or stderr failed to take them); each is in this log",
        lost,
        MAX_STDERR_PENDING,
    )


def _drain_stderr() -> None:
    """The stderr writer: write every queued line, oldest first, then log the count
    of any lost. It may wait on a stalled stderr -- it is the one thread that does, so
    a stalled stderr strands one thread, never one per line, and never a stop's."""
    done = False
    try:
        while True:
            with _STDERR_LOCK:
                line = _STDERR_PENDING.popleft() if _STDERR_PENDING else None
                if line is None and not _lost_unreported():
                    _STDERR_WRITING[0] = False
                    done = True
                    return
            if line is None:
                _report_lost()
                continue
            fd, data = line
            try:
                if not _write_all(fd, data):
                    STDERR_LOST[0] += 1
            finally:
                _close(fd)
    finally:
        if not done:  # it ended on an error: the next line starts a writer again
            with _STDERR_LOCK:
                _STDERR_WRITING[0] = False


def start_stderr_writer() -> bool:
    """Start the stderr writer if lines wait for it and none runs. Never raises;
    ``False`` when it is needed and could not start (the lines keep waiting, for the
    next line, the sweeper or the exit to start it)."""
    with _STDERR_LOCK:
        if _STDERR_WRITING[0] or (not _STDERR_PENDING and not _lost_unreported()):
            return True
        _STDERR_WRITING[0] = True
    try:
        thread = threading.Thread(target=_drain_stderr, name=STDERR_THREAD, daemon=True)
        thread.start()
    except Exception:  # noqa: BLE001 - e.g. no thread can start: the lines wait, bounded
        with _STDERR_LOCK:
            _STDERR_WRITING[0] = False
        return False
    _STDERR_WRITER[:] = [thread]
    return True


def _hand_to_the_writer(fd: int, data: bytes) -> bool:
    """Queue ``data`` for the stderr writer, and start it if none runs. Never waits
    for the write. ``True`` when the line was next in line and a writer now runs for
    it; ``False`` when it waits behind another line or for a writer to start, or is
    lost -- past :data:`MAX_STDERR_PENDING`, or no copy of the descriptor could be
    made -- which is counted in :data:`STDERR_LOST`."""
    try:
        copy = os.dup(fd)
    except OSError:
        STDERR_LOST[0] += 1
        return False
    next_in_line = kept = False
    with _STDERR_LOCK:
        if len(_STDERR_PENDING) < MAX_STDERR_PENDING:
            next_in_line = not _STDERR_PENDING and not _STDERR_WRITING[0]
            _STDERR_PENDING.append((copy, data))
            kept = True
    if not kept:
        STDERR_LOST[0] += 1
        _close(copy)
        return False
    return start_stderr_writer() and next_in_line


def _write_stderr_in_a_thread(fd: int, data: bytes) -> bool:
    """For where ``select`` cannot say whether stderr would take the line (Windows).

    A write to a full pipe, or to a console whose window is paused, blocks, and the
    caller is a stop's thread: it must not wait. So the line is written by the stderr
    writer and this returns at once -- ``True`` when the line was handed over to a
    writer free for it, ``False`` (counted in :data:`STDERR_SKIPPED`) when it waits
    behind the line before it, which is how a slow stderr shows itself here, or for
    a writer to start. Either way it is written once stderr takes it, unless it is
    lost, which is counted."""
    handed = _hand_to_the_writer(fd, data)
    if not handed:
        STDERR_SKIPPED[0] += 1
    return handed


def wait_for_stderr(limit: float = 5.0) -> int:
    """Wait, for at most ``limit`` seconds, until the stderr writer has written every
    line queued for it. Returns how many are left (a write in flight counts as one).
    For the exit, and for a test that reads stderr where a thread writes it."""
    deadline = time.monotonic() + limit
    while True:
        with _STDERR_LOCK:
            left = len(_STDERR_PENDING) + int(_STDERR_WRITING[0])
        if not left or time.monotonic() >= deadline:
            return left
        time.sleep(0.005)


def _write_stderr_now(line: str) -> bool:
    """One line to stderr if it can take it without waiting; ``False`` if not.

    Where ``select`` can be asked, the line is written here, in the calling thread,
    once stderr is writable; when it is not, the line waits for the stderr writer.
    Where ``select`` cannot be asked (Windows), the writer writes it and this does
    not wait for it: ``True`` then means the line was handed over (see
    :func:`_write_stderr_in_a_thread`)."""
    data = (line.replace("\n", " ")[:MAX_LINE] + "\n").encode("utf-8", "replace")
    try:
        fd = _stderr_fd()
        try:
            _, writable, _ = select.select([], [fd], [], 0)
        except OSError as exc:
            if not _select_takes_sockets_only(exc):
                raise
            return _write_stderr_in_a_thread(fd, data)
        if not writable:
            STDERR_SKIPPED[0] += 1
            _hand_to_the_writer(fd, data)
            return False
        # Under PIPE_BUF bytes: one write, and a pipe that is writable has room for it.
        os.write(fd, data)
        return True
    except (OSError, ValueError):
        STDERR_SKIPPED[0] += 1
        STDERR_LOST[0] += 1
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
    through the pump while it runs, here if it does not, and for a record another
    thread has popped and is still writing. Returns how many records are left (a
    write still in flight counts as one). For the process's exit, and for a test that reads what was logged."""
    deadline = time.monotonic() + limit
    pid = os.getpid()
    while time.monotonic() < deadline:
        with _COND:
            if not _BUF and not _BUSY[0]:
                return 0
            pump = _PUMP[0] if _PUMP else None
            record = None
            if pump is None or pump[0] != pid or not pump[1].is_alive():
                # Nothing queued here but ``_BUSY`` set (the check above): a pump
                # that is not this process's own -- one a test left running -- has
                # popped a record and is still writing it. Wait for it, within
                # ``limit``, rather than report it written.
                if _BUF:
                    record = _BUF.popleft()
        if record is None:
            time.sleep(0.01)
        else:
            _handle(record)
    return len(_BUF) + int(_BUSY[0])


def _flush_at_exit() -> None:
    # A line waiting for the stderr writer is lost if the process ends first: the
    # writer is started if it is not running (or a count of lost lines is owed to the
    # log, which is drained after it).
    start_stderr_writer()
    writer = _STDERR_WRITER[0] if _STDERR_WRITER else None
    if writer is not None:
        writer.join(STDERR_AT_EXIT_SECONDS)
    left = drain(FLUSH_AT_EXIT_SECONDS)
    if left:
        _write_stderr_now(f"assurance: {left} deferred log record(s) were not written before exit")
        start_stderr_writer()
        writer = _STDERR_WRITER[0] if _STDERR_WRITER else None
        if writer is not None:
            writer.join(STDERR_AT_EXIT_SECONDS)


atexit.register(_flush_at_exit)


def _after_fork_in_child() -> None:
    global _BUF, _COND, _PUMP_LOCK, _STDERR_LOCK, _STDERR_PENDING
    _BUF = collections.deque()
    _COND = threading.Condition(threading.Lock())
    _DROPPED[0] = 0
    _BUSY[0] = False
    _PUMP.clear()
    _PUMP_LOCK = threading.Lock()
    # The parent's writer writes the parent's queued lines; the child closes its
    # inherited copies of their descriptors, so a pipe's reader still sees its end.
    for fd, _data in list(_STDERR_PENDING):
        _close(fd)
    _STDERR_PENDING = collections.deque()
    _STDERR_LOCK = threading.Lock()
    _STDERR_WRITING[0] = False
    _STDERR_WRITER.clear()


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)
