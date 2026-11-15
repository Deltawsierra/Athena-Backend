"""Every worker's lost and refused counts, where every worker and ``/api/health/`` read
them.

:func:`assurance.dispatch.degraded_counts` counts, per process, what an operator must
act on: lines meant for stderr that never reached it, log records dropped, and
unrecorded dispatches refused. A health probe is answered by ONE worker, so a loss in
another worker used to read "ok". Now each serving worker publishes its counts as a
small file in one directory, and health sums them all.

- **Where.** One JSON file per worker process, ``<id>.json``, in
  :func:`report_directory`: ``ATHENA_WORKER_REPORT_DIR`` where it is set, else a
  directory in the system's temporary directory named for this checkout. Every
  worker of one host names the same one. The id is random, made when the process
  first needs it (a forked child makes its own); the host and the pid are inside.
  A file, not a database row: a row would be written through the database's one
  writer, which a stop's own write waits for on SQLite, and the economics run slots
  (:mod:`assurance.economics.capacity`) already keep their per-host state in a
  directory the same way. Several hosts: each host's health sums the workers of
  that host -- the ones its load balancer's probe of that host is about -- unless
  ``ATHENA_WORKER_REPORT_DIR`` names a directory every host shares (each file is
  its own worker's, so they never collide). Staleness is judged by each file's own
  publication time, so hosts that share a directory must keep their clocks within
  a few seconds of each other.
- **Off every stop.** A request costs a comparison and a liveness check
  (:func:`ensure_publisher`, through ``dispatch.ensure_owed_sweeper``); only the
  process's first request starts the publisher thread, and a start that fails is
  tried again after a backoff. The thread reads the counts (plain reads, no lock)
  every :data:`CHECK_SECONDS`, and writes when one moved or every
  :data:`HEARTBEAT_SECONDS`. Nothing a stop takes is taken, and nothing waits for a
  write: a slow or failing directory delays only the publisher thread.
- **A failed publish is counted** (:data:`PUBLISH_FAILED`, shown as
  :data:`UNPUBLISHED`), is part of this worker's counts, and makes health read
  degraded wherever the count can be read. Windows refuses to replace a file another
  process has open; the replace is tried :data:`REPLACE_TRIES` times first.
- **Read by health** (:func:`summarize`): this worker's counts live, every other
  worker's from its file. A file that cannot be read, or that a live worker has not
  rewritten within :data:`STALE_AFTER_SECONDS`, reads ``unknown`` -- never "ok".
- **Exit.** A worker that exits normally writes its last counts marked ``exited``.
  Its file stays, and its counts stay in every sum, until an operator acknowledges
  it (``manage.py acknowledge_worker_reports``, :func:`acknowledge`), which records
  who and when. A worker that exits with nothing counted removes its file: there is
  nothing to keep. A worker killed outright (SIGKILL, TerminateProcess, the OOM
  killer) writes nothing more; its file goes stale and reads ``unknown`` until it is
  acknowledged. Counts never silently vanish.

The module imports nothing from Django, so a worker without Django -- or a probe --
can load it on its own.
"""

from __future__ import annotations

import atexit
import contextlib
import datetime
import hashlib
import json
import os
import socket
import sys
import tempfile
import threading
import time
import uuid

#: The directory every worker of a host writes its report to.
DIRECTORY_VARIABLE = "ATHENA_WORKER_REPORT_DIR"
_CHECKOUT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
#: The directory when ``ATHENA_WORKER_REPORT_DIR`` is not set: one per checkout, so two
#: checkouts on one host never read each other's workers.
DEFAULT_DIRECTORY = os.path.join(
    tempfile.gettempdir(), "athena-worker-reports-" + hashlib.sha256(_CHECKOUT.encode()).hexdigest()[:12]
)
#: Where acknowledged reports are kept, inside the report directory.
ACKNOWLEDGED = "acknowledged"
SUFFIX = ".json"

#: Seconds between two reads of the counts by the publisher thread.
CHECK_SECONDS = 1.0
#: The longest a live worker goes without rewriting its report.
HEARTBEAT_SECONDS = 10.0
#: The bound past which a live worker's report is stale: it reads ``unknown``.
STALE_AFTER_SECONDS = 60.0
#: The most reports one read takes; past it the rest read ``unknown``.
MAX_REPORTS = 512
#: The largest report read; a larger file is not a report.
MAX_REPORT_BYTES = 64 * 1024
#: Tries of a replace (or a read) that Windows refuses because the file is open; the
#: pause before each retry doubles from :data:`RETRY_PAUSE` (0.01 s, then 0.02, 0.04,
#: 0.08), so a reader polling at a steady interval cannot meet every one.
REPLACE_TRIES = 5
RETRY_PAUSE = 0.01
#: The publisher's start, after a failure, waits at most this long before it is tried
#: again.
RETRY_MAX_SECONDS = 300.0
PUBLISHER_THREAD = "assurance-worker-report"

#: The name this worker's failed publishes are shown under, beside its other counts.
UNPUBLISHED = "worker_reports_unpublished"
#: This process's publishes that failed, since it started.
PUBLISH_FAILED = [0]

#: What a report is, as health and the command read it.
LIVE, EXITED, STALE, THIS = "live", "exited", "stale", "this worker"

#: This process's id, as ``[(pid, id)]``.
_ID: list = []
#: This process's publisher, as ``[(pid, thread, directory, source)]``.
_PUBLISHER: list = []
#: The publisher's start, retried after a failure: ``{"pid", "failures", "next"}``.
_RETRY: dict = {}
#: Held while a thread of this process starts the publisher (never waited on).
_STARTING = threading.Lock()
#: Held by the publisher thread and the exit across one write: never by a request.
_WRITING = threading.Lock()
_STOP = threading.Event()
#: Whether the publisher's last write failed (the failure is logged once, as is the
#: recovery).
_FAILING = [False]


def report_directory() -> str:
    """``ATHENA_WORKER_REPORT_DIR``, else :data:`DEFAULT_DIRECTORY`."""
    return os.environ.get(DIRECTORY_VARIABLE) or DEFAULT_DIRECTORY


def worker_id() -> str:
    """This process's report id: random, made once per process (a forked child makes
    its own, since its pid differs)."""
    pid = os.getpid()
    current = _ID[0] if _ID else None
    if current is None or current[0] != pid:
        current = (pid, uuid.uuid4().hex[:16])
        _ID[:] = [current]
    return current[1]


def local_counts(source) -> dict:
    """This worker's counts: ``source()`` (``dispatch.degraded_counts``) and its own
    failed publishes."""
    counts = dict(source())
    counts[UNPUBLISHED] = PUBLISH_FAILED[0]
    return counts


def _log(level: int, msg: str, *args) -> None:
    try:
        from .oplog import log_later

        log_later(level, msg, *args, logger_name="assurance.worker_reports")
    except Exception:  # noqa: BLE001, S110 - a report's log line never fails the report
        pass


# ------------------------------------------------------------------------ writing


def _write(directory: str, report_id: str, data: bytes) -> None:
    """``data`` as ``<directory>/<report_id>.json``, whole or not at all: written to a
    temporary file, flushed to disk, then put in place with one replace."""
    os.makedirs(directory, exist_ok=True)
    final = os.path.join(directory, report_id + SUFFIX)
    temporary = os.path.join(directory, f".{report_id}.{os.getpid()}.tmp")
    try:
        with open(temporary, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        for attempt in range(REPLACE_TRIES):
            try:
                os.replace(temporary, final)
                return
            except PermissionError:
                # Windows: a reader has the report open. It closes it in moments.
                if attempt == REPLACE_TRIES - 1:
                    raise
                time.sleep(RETRY_PAUSE * 2**attempt)
    finally:
        with contextlib.suppress(OSError):
            os.remove(temporary)


def publish(counts, *, exited: bool = False, directory: str | None = None) -> bool:
    """Write this worker's report: ``counts`` (``None`` when they could not be read,
    which every reader takes as unknown). Never raises; a failure is counted in
    :data:`PUBLISH_FAILED` and logged once. Called by the publisher thread and at
    exit -- never by a request."""
    directory = directory or report_directory()
    try:
        now = time.time()
        data = json.dumps(
            {
                "id": worker_id(),
                "host": socket.gethostname(),
                "pid": os.getpid(),
                "published": now,
                "published_at": datetime.datetime.fromtimestamp(now, datetime.UTC).isoformat(),
                "exited": bool(exited),
                "counts": counts,
            },
            sort_keys=True,
        ).encode()
        _write(directory, worker_id(), data)
    except Exception as exc:  # noqa: BLE001 - every failure is counted, whatever it is
        PUBLISH_FAILED[0] += 1
        if not _FAILING[0]:
            _FAILING[0] = True
            _log(30, "this worker could not publish its report to %s (%s: %s); counted, and tried again",
                 directory, type(exc).__name__, exc)
        return False
    if _FAILING[0]:
        _FAILING[0] = False
        _log(30, "this worker's report is published to %s again, after %d failed publish(es)",
             directory, PUBLISH_FAILED[0])
    return True


def _counts_or_none(source):
    try:
        return local_counts(source)
    except Exception:  # noqa: BLE001 - published as unreadable, which reads unknown
        return None


def _publisher(source, directory: str, stop) -> None:
    published, due = object(), 0.0
    while True:
        counts = _counts_or_none(source)
        now = time.monotonic()
        if counts != published or now >= due:
            with _WRITING:
                publish(counts, directory=directory)
            # Counted, if it failed: the count moved, so the next check tries again.
            published, due = counts, now + HEARTBEAT_SECONDS
        if stop.wait(CHECK_SECONDS):
            return


def ensure_publisher(source) -> None:
    """Start this process's publisher thread if it has none running: called on every
    request (``dispatch.ensure_owed_sweeper``), so it starts in the process that serves.
    Costs a comparison and a liveness check once it runs. Never blocks, never writes,
    never raises: a start that fails is tried again after a backoff that doubles up
    to :data:`RETRY_MAX_SECONDS`."""
    pid = os.getpid()
    current = _PUBLISHER[0] if _PUBLISHER else None
    if current is not None and current[0] == pid and current[1].is_alive():
        return
    if _RETRY.get("pid") == pid and time.monotonic() < _RETRY.get("next", 0):
        return
    if not _STARTING.acquire(blocking=False):
        return  # another thread of this process is starting it now
    try:
        current = _PUBLISHER[0] if _PUBLISHER else None
        if current is not None and current[0] == pid and current[1].is_alive():
            return
        if _STOP.is_set():
            return
        directory = report_directory()
        thread = threading.Thread(
            target=_publisher, args=(source, directory, _STOP), name=PUBLISHER_THREAD, daemon=True
        )
        _PUBLISHER[:] = [(pid, thread, directory, source)]
        thread.start()
        _RETRY.clear()
    except Exception:  # noqa: BLE001 - serving never waits on the publisher
        failures = (_RETRY.get("failures", 0) if _RETRY.get("pid") == pid else 0) + 1
        wait = min(RETRY_MAX_SECONDS, 2.0 ** (failures - 1))
        _RETRY.update(pid=pid, failures=failures, next=time.monotonic() + wait)
        _log(40, "could not start this worker's report publisher (failure %d); tried again in %g s", failures, wait)
    finally:
        _STARTING.release()


def stop_publisher(limit: float = 2.0) -> None:
    """Stop this process's publisher thread, waiting for it at most ``limit`` seconds."""
    _STOP.set()
    current = _PUBLISHER[0] if _PUBLISHER else None
    if current is not None and current[0] == os.getpid() and current[1].is_alive():
        current[1].join(limit)


def _at_exit() -> None:
    """A worker that started a publisher writes its last counts as it exits: marked
    exited, kept until acknowledged; or, with nothing counted, its file removed."""
    current = _PUBLISHER[0] if _PUBLISHER else None
    if current is None or current[0] != os.getpid():
        return  # this process never published (a forked child, the master)
    _pid, _thread, directory, source = current
    stop_publisher()
    oplog = sys.modules.get("assurance.oplog")
    if oplog is not None:
        # What the log's own exit loses is counted there: count it before the last report.
        with contextlib.suppress(Exception):
            oplog._flush_at_exit()
    counts = _counts_or_none(source)
    locked = _WRITING.acquire(timeout=2.0)
    try:
        if counts is not None and not any(counts.values()):
            with contextlib.suppress(OSError):
                os.remove(os.path.join(directory, worker_id() + SUFFIX))
            return
        publish(counts, exited=True, directory=directory)
    finally:
        if locked:
            _WRITING.release()


atexit.register(_at_exit)


def _after_fork_in_child() -> None:
    global _STARTING, _WRITING, _STOP
    _ID.clear()
    _PUBLISHER.clear()
    _RETRY.clear()
    _STARTING = threading.Lock()
    _WRITING = threading.Lock()
    _STOP = threading.Event()
    PUBLISH_FAILED[0] = 0
    _FAILING[0] = False


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


# ------------------------------------------------------------------------ reading


def _read(path: str) -> bytes:
    for attempt in range(REPLACE_TRIES):
        try:
            with open(path, "rb") as handle:
                return handle.read(MAX_REPORT_BYTES + 1)
        except PermissionError:
            # Windows: the file is being replaced at this moment.
            if attempt == REPLACE_TRIES - 1:
                raise
            time.sleep(RETRY_PAUSE * 2**attempt)
    raise AssertionError("unreachable")  # pragma: no cover


def _parse(data: bytes) -> dict:
    """A report's content, checked: raises ``ValueError`` for anything that is not one."""
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError(f"larger than {MAX_REPORT_BYTES} bytes")
    report = json.loads(data.decode("utf-8"))
    if not isinstance(report, dict):
        raise ValueError("not an object")
    published = report.get("published")
    if isinstance(published, bool) or not isinstance(published, (int, float)):
        raise ValueError("no publication time")
    if not isinstance(report.get("exited"), bool):
        raise ValueError("no exited flag")
    counts = report.get("counts")
    if counts is None:
        raise ValueError("its worker could not read its own counts")
    if not isinstance(counts, dict) or not all(
        isinstance(name, str) and isinstance(n, int) and not isinstance(n, bool) and n >= 0
        for name, n in counts.items()
    ):
        raise ValueError("counts that are not whole numbers")
    return report


def reports(directory: str | None = None, *, now: float | None = None) -> tuple[list, dict]:
    """Every report in the directory, read: ``(readable, unknown)``. ``readable`` is a
    list of ``(id, state, report)`` with state :data:`LIVE`, :data:`EXITED` or
    :data:`STALE`; ``unknown`` maps an id (or ``"directory"``) to why it reads
    unknown. A stale report is in both: its last counts are still counts."""
    directory = directory or report_directory()
    now = time.time() if now is None else now
    readable, unknown = [], {}
    try:
        names = sorted(name for name in os.listdir(directory) if name.endswith(SUFFIX) and not name.startswith("."))
    except FileNotFoundError:
        return readable, unknown  # no worker has published here
    except OSError as exc:
        unknown["directory"] = f"the report directory could not be read: {type(exc).__name__}"
        return readable, unknown
    if len(names) > MAX_REPORTS:
        unknown["directory"] = f"{len(names)} reports, more than the {MAX_REPORTS} one read takes"
        names = names[:MAX_REPORTS]
    for name in names:
        report_id = name[: -len(SUFFIX)]
        try:
            report = _parse(_read(os.path.join(directory, name)))
        except FileNotFoundError:
            continue  # acknowledged, or removed by its worker's exit, since the listing
        except (OSError, ValueError) as exc:
            unknown[report_id] = f"unreadable: {exc}" if isinstance(exc, ValueError) else (
                f"unreadable: {type(exc).__name__}"
            )
            continue
        if report["exited"]:
            state = EXITED
        elif now - report["published"] > STALE_AFTER_SECONDS:
            state = STALE
            unknown[report_id] = (
                f"stale: last published {now - report['published']:.0f} s ago, past the "
                f"{STALE_AFTER_SECONDS:g} s bound"
            )
        else:
            state = LIVE
        readable.append((report_id, state, report))
    return readable, unknown


def summarize(local: dict, *, directory: str | None = None, now: float | None = None) -> dict:
    """This worker's counts (``local``, read live) and every other worker's report,
    summed: ``{"counts": {name: total}, "workers": {id: {"state", "counts"}},
    "unknown": {id: reason}}``. This worker's own file is never read: its live counts
    are newer."""
    own = worker_id()
    totals = dict(local)
    workers = {own: {"state": THIS, "counts": dict(local)}}
    readable, unknown = reports(directory, now=now)
    unknown.pop(own, None)
    for report_id, state, report in readable:
        if report_id == own:
            continue
        workers[report_id] = {"state": state, "counts": report["counts"]}
        for name, count in report["counts"].items():
            totals[name] = totals.get(name, 0) + count
    return {"counts": totals, "workers": workers, "unknown": unknown}


# ------------------------------------------------------------------ acknowledging


class NotAcknowledged(Exception):
    """A report that may not be acknowledged: a live worker's, or one not found."""


def acknowledge(report_id: str, *, by: str, directory: str | None = None, now: float | None = None) -> dict:
    """Acknowledge an exited, stale or unreadable worker's report: the report is kept,
    with who acknowledged it and when, under ``acknowledged/``, and leaves the sums.
    A live worker's report cannot be acknowledged (its counts are still moving). A
    report rewritten while it is acknowledged is left in place. Returns the record."""
    directory = directory or report_directory()
    by = (by or "").strip()
    if not by:
        raise NotAcknowledged("say who acknowledges it (--by)")
    if not report_id or os.path.basename(report_id) != report_id or report_id.startswith("."):
        raise NotAcknowledged(f"{report_id!r} is not a report id")
    path = os.path.join(directory, report_id + SUFFIX)
    now = time.time() if now is None else now
    try:
        data = _read(path)
    except FileNotFoundError:
        raise NotAcknowledged(f"no report {report_id} in {directory}") from None
    try:
        report = _parse(data)
        state = EXITED if report["exited"] else (STALE if now - report["published"] > STALE_AFTER_SECONDS else LIVE)
    except ValueError:
        report, state = None, "unreadable"
    if state == LIVE:
        raise NotAcknowledged(
            f"{report_id} is a live worker's report (published {now - report['published']:.0f} s ago): "
            "its counts are still moving; acknowledge it once it has exited or gone stale"
        )
    try:
        import getpass

        user = getpass.getuser()
    except Exception:  # noqa: BLE001 - the name given is the record; the account is extra
        user = None
    record = {
        "id": report_id,
        "state": state,
        "report": report if report is not None else data.decode("utf-8", "replace"),
        "acknowledged_by": by,
        "acknowledged_by_account": user,
        "acknowledged": now,
        "acknowledged_at": datetime.datetime.fromtimestamp(now, datetime.UTC).isoformat(),
    }
    kept = os.path.join(directory, ACKNOWLEDGED)
    os.makedirs(kept, exist_ok=True)
    stamp = datetime.datetime.fromtimestamp(now, datetime.UTC).strftime("%Y%m%dT%H%M%S%fZ")
    kept = os.path.join(kept, f"{report_id}-{stamp}{SUFFIX}")
    with open(kept, "x", encoding="utf-8") as handle:
        json.dump(record, handle, sort_keys=True, indent=2)
    if _read(path) != data:
        # Its worker wrote it again: alive after all. The report stays, unacknowledged.
        os.remove(kept)
        raise NotAcknowledged(f"{report_id} was rewritten while it was acknowledged: its worker is alive")
    os.remove(path)
    return record
