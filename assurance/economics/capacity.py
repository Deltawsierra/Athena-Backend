"""How many economics runs are made at once: a cap that never waits, so no stop ever
waits behind a run (``docs/economics/spec-v1.md``, section 32; the SAFETY RULE).

A simulate request runs its Monte Carlo synchronously, in the worker that serves it,
for up to its one deadline (``report_api.REQUEST_BUDGET_SECONDS``, 120 s). Nothing
bounded how many ran at once, so one analyst, or a stolen analyst token, could fill
every worker with long runs, and a scan's Stop then waited for a free worker (the
section 28 threat-model audit, S1).

Every route that runs a Monte Carlo now takes a SLOT before it runs, and registers
with ONE line: ``@capacity.capped`` on its handler (:func:`capped`).

- **Across worker processes.** A slot is an exclusive ``flock`` on one small file in
  :func:`slot_directory`, which every worker on the host shares. The kernel releases
  a flock when the last descriptor of its open file closes, so a worker that dies by
  any means (SIGKILL, the OOM killer, gunicorn's timeout) gives its slots back at
  once: a slot cannot leak, and no lease, expiry or sweeper is needed. A database
  lease was the alternative; it leaks a dead worker's slot until it expires, and it
  would put a database read in front of the cap. The cap is per host, which is what
  it protects: the host's pool of workers. Where there is no ``fcntl`` (Windows)
  nothing can be locked and no slot is ever granted: every run is refused with the
  same 503 (``unreadable``), never run uncapped, and that refusal cannot itself
  raise (a second ``import fcntl`` inside its handler used to turn it into a 500).
- **It never waits.** Every lock is taken with ``LOCK_NB``. When no slot is free the
  request is answered AT ONCE: 503, ``Retry-After``, code ``economics_capacity``
  (:func:`at_capacity`); nothing runs and nothing is recorded. Nothing queues.
- **Two caps.** The global cap (:func:`global_cap`): ``ATHENA_ECONOMICS_RUN_CAP``
  where it is set, else ``max(1, WEB_CONCURRENCY - 2)`` -- ``WEB_CONCURRENCY`` is
  gunicorn's own variable for its worker count -- so at least two workers stay free
  for everything else, every stop included. The per-tenant cap (:func:`tenant_cap`):
  ``ATHENA_ECONOMICS_RUN_CAP_PER_TENANT``, default 1, so one tenant cannot hold every
  slot. The tenant is the deployment ("the deployment IS the tenant",
  :mod:`assurance.models`).
- **Given back on every exit.** The slots are released in a ``finally`` around the
  handler: its answer, a refusal, an exception, and a ``SystemExit`` (gunicorn's abort
  of a timed-out worker); the process's death releases them in the kernel. A client
  that disconnects is the same: the handler runs to its end (bounded by its deadline),
  and its ``finally`` releases.
- **Off every stop.** Only a handler decorated :func:`capped` takes a slot, and no
  stop route's handler is one (``tests/test_economics_run_cap.py`` walks the URLconf
  and drives every stop with every slot held). The cap reads no database and no
  Django setting: the environment only, each variable by its literal name.

The module imports nothing from Django at load, so a probe can load it on its own.
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import os
import tempfile

try:
    import fcntl
except ImportError:  # Windows has no fcntl: no slot can be locked, so none is ever granted (below)
    fcntl = None

#: The code a request is answered with when no slot is free.
CODE = "economics_capacity"
#: Seconds a refused request is told to wait (``Retry-After``). A run is bounded by
#: its 120 s deadline; most finish well inside it.
RETRY_AFTER_SECONDS = 30
#: Workers the default global cap always leaves free for everything else.
FREE_WORKERS = 2
#: gunicorn's own default worker count, when ``WEB_CONCURRENCY`` is not set.
DEFAULT_WORKERS = 1
DEFAULT_TENANT_CAP = 1
#: The directory the slot files are in, when ``ATHENA_ECONOMICS_SLOT_DIR`` is not set.
DEFAULT_SLOT_DIRECTORY = os.path.join(tempfile.gettempdir(), "athena-economics-slots")

#: Every handler :func:`capped` registered, by ``module.qualname``.
CAPPED: set[str] = set()


def _whole(text: str | None) -> int | None:
    """``text`` as a whole number of at least 0, or None for anything else."""
    if text is None:
        return None
    text = text.strip()
    if not (text.isascii() and text.isdigit()) or len(text) > 6:
        return None
    return int(text)


def workers() -> int:
    """The host's worker count: ``WEB_CONCURRENCY`` (gunicorn's own), else 1."""
    found = _whole(os.environ.get("WEB_CONCURRENCY"))
    return found if found else DEFAULT_WORKERS


def global_cap() -> int:
    """How many runs the host makes at once: ``ATHENA_ECONOMICS_RUN_CAP`` where it is
    a whole number (0 refuses every run), else ``max(1, workers - 2)``."""
    explicit = _whole(os.environ.get("ATHENA_ECONOMICS_RUN_CAP"))
    if explicit is not None:
        return explicit
    return max(1, workers() - FREE_WORKERS)


def tenant_cap() -> int:
    """How many runs one tenant makes at once: ``ATHENA_ECONOMICS_RUN_CAP_PER_TENANT``
    where it is a whole number, else 1."""
    explicit = _whole(os.environ.get("ATHENA_ECONOMICS_RUN_CAP_PER_TENANT"))
    return DEFAULT_TENANT_CAP if explicit is None else explicit


def slot_directory() -> str:
    """Where the slot files are: ``ATHENA_ECONOMICS_SLOT_DIR``, else a directory in the
    system's temporary directory. Every worker of one host must name the same one."""
    return os.environ.get("ATHENA_ECONOMICS_SLOT_DIR") or DEFAULT_SLOT_DIRECTORY


class Slots:
    """The slots one run holds: released together, once."""

    def __init__(self, descriptors: list[int]):
        self._descriptors = descriptors

    def release(self) -> None:
        descriptors, self._descriptors = self._descriptors, []
        for descriptor in reversed(descriptors):
            # LOCK_UN first: a child forked meanwhile shares the open file, and must not
            # keep the slot. Closing the last descriptor releases it in any case. Without
            # fcntl no slot was ever taken, so there is nothing to unlock: only to close.
            if fcntl is not None:
                with contextlib.suppress(OSError):
                    fcntl.flock(descriptor, fcntl.LOCK_UN)
            with contextlib.suppress(OSError):
                os.close(descriptor)


def _take_one(directory: str, prefix: str, count: int) -> int | None:
    """An exclusive lock on the first free one of ``count`` slot files, WITHOUT
    WAITING, or None when every one is held. Raises ``ImportError`` where there is no
    ``fcntl`` (Windows): :func:`acquire` answers that as ``"unreadable"``."""
    if fcntl is None:
        raise ImportError("fcntl is not available on this platform: no run slot can be locked")
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    for index in range(count):
        descriptor = os.open(os.path.join(directory, f"{prefix}-{index}.lock"), flags, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(descriptor)
            continue
        except BaseException:
            os.close(descriptor)
            raise
        return descriptor
    return None


def _tenant_prefix(tenant: str) -> str:
    return "tenant-" + hashlib.sha256(str(tenant).encode("utf-8")).hexdigest()[:32]


def acquire(tenant: str) -> tuple[Slots | None, str]:
    """``(slots, "")`` when one of the tenant's slots and one of the host's are free,
    both taken without waiting; else ``(None, why)``. ``why`` is ``"tenant"`` (the
    tenant's every slot is held), ``"host"`` (the host's every slot is held) or
    ``"unreadable"`` (the slot files cannot be opened: refused, never run uncapped).
    Where there is no ``fcntl`` (Windows) nothing can be locked, so every run is
    ``"unreadable"``: the honest answer is the 503, never a run no cap counts."""
    if fcntl is None:
        return None, "unreadable"
    held: list[int] = []
    try:
        directory = slot_directory()
        os.makedirs(directory, mode=0o700, exist_ok=True)
        mine = _take_one(directory, _tenant_prefix(tenant), tenant_cap())
        if mine is None:
            return None, "tenant"
        held.append(mine)
        host = _take_one(directory, "run", global_cap())
        if host is None:
            Slots(held).release()
            return None, "host"
        held.append(host)
        return Slots(held), ""
    except (OSError, ImportError):
        Slots(held).release()
        return None, "unreadable"
    except BaseException:
        Slots(held).release()
        raise


_WHY = {
    "tenant": "this deployment already has as many economics runs in progress as it may",
    "host": "every economics run slot on this server is in use",
    "unreadable": "the economics run slots cannot be read on this server",
}


def at_capacity(why: str):
    """The answer when no slot is free: 503 at once, with ``Retry-After``. It carries
    nothing from the request."""
    from rest_framework import status
    from rest_framework.response import Response

    return Response(
        {
            "code": CODE,
            "detail": f"{_WHY.get(why, _WHY['host'])}: nothing was run or recorded; send the same request again "
            f"after {RETRY_AFTER_SECONDS} s",
            "recorded": False,
        },
        status=status.HTTP_503_SERVICE_UNAVAILABLE,
        headers={"Retry-After": str(RETRY_AFTER_SECONDS)},
    )


def capped(handler):
    """Register a route that runs a Monte Carlo: ``@capacity.capped`` on its APIView
    handler, whose URL names the deployment as ``uuid``. One line.

    Before any slot is touched: the deployment is looked up as the handler looks it up
    (404 for one the caller cannot see, so a tenant's runs are never disclosed to
    anyone who cannot see it), and a caller who may not write is passed straight to the
    handler, which refuses them (403) and runs nothing. Then a slot is taken without
    waiting, or the request is answered at once (:func:`at_capacity`); and the slots
    are released in a ``finally``, whatever the handler does."""

    @functools.wraps(handler)
    def run(view, request, *args, **kwargs):
        from .api import _deployment, _may_write

        deployment = _deployment(request, kwargs["uuid"])
        if not _may_write(request.user):
            return handler(view, request, *args, **kwargs)
        slots, why = acquire(str(deployment.uuid))
        if slots is None:
            return at_capacity(why)
        try:
            return handler(view, request, *args, **kwargs)
        finally:
            slots.release()

    run.economics_capped = True
    CAPPED.add(f"{handler.__module__}.{handler.__qualname__}")
    return run


__all__ = [
    "CAPPED",
    "CODE",
    "RETRY_AFTER_SECONDS",
    "Slots",
    "acquire",
    "at_capacity",
    "capped",
    "global_cap",
    "slot_directory",
    "tenant_cap",
    "workers",
]
