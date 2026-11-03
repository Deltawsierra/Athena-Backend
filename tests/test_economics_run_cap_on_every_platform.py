"""The economics run cap on every platform (``assurance.economics.capacity``; spec,
section 32.2). POSIX takes a slot with ``fcntl.flock``; Windows takes it with
``msvcrt.locking`` on byte 0 of the slot file. Both run these tests, and CI runs them on
Linux and on windows-latest:

- this host has its platform's own lock, never none;
- the cap holds across processes: slots held by another process (another worker)
  refuse a run at once, by host and by tenant, and the per-tenant cap of one tenant
  never refuses another;
- a holder that dies gives its slots back: killed by ``Popen.kill``, which is SIGKILL on
  POSIX and ``TerminateProcess`` on Windows, so no ``finally`` of its own runs;
- with every slot held by another process, a simulate is the 503 at once, and every
  stop the tripwire drives is answered within its bound (THE SAFETY RULE);
- a simulate runs through the route under the cap (201) and gives its slot back, and a
  receipt is made through the simulate route (``test_economics_read_routes._receipted``,
  the fixture a Windows run used to have to route around);
- the Windows lock itself, on any host: one attempt at byte 0 (``LK_NBLCK``), never the
  waiting ``LK_LOCK``; given back with ``LK_UNLCK`` and the handle closed; and any lock
  error but "held elsewhere" refuses the run, never runs it uncapped. On Windows these
  drive the real ``msvcrt``; elsewhere a stand-in with the same answers, built on flock.
"""

from __future__ import annotations

import contextlib
import errno
import inspect
import os
import subprocess
import sys
import textwrap
import time
import types

import pytest
from django.contrib.auth import get_user_model

from assurance.economics import capacity, simulation_service
from assurance.economics.models import FinancialExposureReceipt, SimulationResult
from assurance.models import Deployment
from tests import test_economics_run_cap as run_cap
from tests import test_no_control_holds_back_a_stop as tripwire
from tests.test_economics_read_routes import _receipted
from tests.test_economics_report import QUICK, stored

User = get_user_model()

# The fixtures of the run-cap tests, used here as they are there.
caps = run_cap.caps
operator_key = run_cap.operator_key
stop_lane = run_cap.stop_lane

WINDOWS = sys.platform == "win32"
#: The longest a dead holder's slots may take to come back. On POSIX the kernel releases
#: a flock as the process dies; Windows releases a dead process's byte locks as it closes
#: its handles, before the process is reported ended. Probed without waiting, again and
#: again, until free or this long.
FREED_WITHIN = 5.0

_HOLDER = textwrap.dedent(
    """
    import importlib.util, sys
    spec = importlib.util.spec_from_file_location("economics_capacity_holder", sys.argv[1])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    held = []
    for tenant in sys.argv[2:]:
        slots, why = module.acquire(tenant)
        if slots is None:
            print("refused:" + why, flush=True)
            break
        held.append(slots)
    else:
        print("held", flush=True)
    sys.stdin.read()
    """
)


@contextlib.contextmanager
def _holder(*tenants):
    """Another process -- another worker -- holding one slot for each of ``tenants``,
    with this test's caps and slot directory, until it is ended. It loads
    ``capacity.py`` on its own (it imports nothing from Django) and never releases."""
    env = {
        "ATHENA_ECONOMICS_SLOT_DIR": os.environ["ATHENA_ECONOMICS_SLOT_DIR"],
        "ATHENA_ECONOMICS_RUN_CAP": os.environ["ATHENA_ECONOMICS_RUN_CAP"],
        "ATHENA_ECONOMICS_RUN_CAP_PER_TENANT": os.environ["ATHENA_ECONOMICS_RUN_CAP_PER_TENANT"],
        "PATH": os.environ.get("PATH", ""),
    }
    if WINDOWS and os.environ.get("SYSTEMROOT"):
        env["SYSTEMROOT"] = os.environ["SYSTEMROOT"]
    holder = subprocess.Popen(
        [sys.executable, "-I", "-c", _HOLDER, inspect.getsourcefile(capacity), *tenants],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, text=True,
    )
    try:
        said, _took = run_cap._within(30, "the holder's acquire", holder.stdout.readline)
        assert said.strip() == "held", (said, holder.poll())
        yield holder
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.wait(timeout=30)
        for stream in (holder.stdin, holder.stdout, holder.stderr):
            stream.close()


def _freed(tenant):
    """``(answer, seconds)``: probes ``tenant`` without waiting until a slot is free or
    :data:`FREED_WITHIN` has passed."""
    began = time.perf_counter()
    while True:
        answer = run_cap._probe(tenant)
        took = time.perf_counter() - began
        if answer == "free" or took > FREED_WITHIN:
            return answer, took
        time.sleep(0.02)


# ================================================================ the lock


def test_this_host_locks_its_slots_with_its_own_lock_never_none():
    assert capacity.lock_kind() == ("msvcrt" if WINDOWS else "flock")


def test_the_cap_holds_across_processes(caps):
    """Another worker holds both of the host's slots: a run here is refused at once, by
    host and, for a tenant it holds, by tenant. When it ends, without releasing, its
    slots come back."""
    caps(host=2, tenant=1)
    with _holder("tenant-a", "tenant-b") as holder:
        answers = {tenant: run_cap._probe_within(tenant) for tenant in ("tenant-c", "tenant-a", "tenant-b")}
        assert {tenant: answer for tenant, (answer, _) in answers.items()} == {
            "tenant-c": "host", "tenant-a": "tenant", "tenant-b": "tenant"}
        assert max(took for _, took in answers.values()) < run_cap.REFUSED_WITHIN, answers
        holder.stdin.close()  # it exits on its own, its slots still locked
        holder.wait(timeout=30)
    assert _freed("tenant-c")[0] == "free"
    assert _freed("tenant-a")[0] == "free"


def test_a_killed_holders_slots_come_back(caps):
    """A worker killed outright (SIGKILL on POSIX, TerminateProcess on Windows: the OOM
    killer, gunicorn after its graceful timeout) runs no ``finally``. The operating
    system releases its locks as it dies, so its slots come back."""
    caps(host=1, tenant=1)
    with _holder("killed-tenant") as holder:
        assert run_cap._probe("killed-tenant") == "tenant"
        assert run_cap._probe("another-tenant") == "host"
        holder.kill()
        code = holder.wait(timeout=30)
        # Popen.kill: SIGKILL on POSIX; TerminateProcess(handle, 1) on Windows.
        assert code == (1 if WINDOWS else -9), code
        answer, took = _freed("killed-tenant")
        assert answer == "free", (answer, took)
        assert run_cap._probe("another-tenant") == "free"


def test_one_tenants_cap_never_refuses_another_tenant(caps):
    """Per tenant, across processes: a tenant at its cap is refused; another tenant is
    not, and has a cap of its own."""
    caps(host=3, tenant=1)
    with _holder("tenant-a"):
        assert run_cap._probe("tenant-a") == "tenant"
        held = run_cap._hold("tenant-b")
        try:
            assert run_cap._probe("tenant-b") == "tenant"
            assert run_cap._probe("tenant-a") == "tenant"
            assert run_cap._probe("tenant-c") == "free"
        finally:
            held.release()
    caps(host=3, tenant=2)
    with _holder("tenant-a"):
        held = run_cap._hold("tenant-a")  # its second slot, beside the other worker's
        try:
            assert run_cap._probe("tenant-a") == "tenant"
            assert run_cap._probe("tenant-b") == "free"
        finally:
            held.release()


# ===================================== every slot held, by another worker


@pytest.mark.django_db(transaction=True)
def test_with_every_slot_held_by_another_worker_a_run_is_refused_and_every_stop_is_answered_in_its_bound(
    caps, operator_key, stop_lane, monkeypatch, capsys
):
    """THE SAFETY RULE, on this platform. Another process holds every slot. A simulate
    is 503 ``economics_capacity`` with ``Retry-After`` within ``REFUSED_WITHIN`` and
    records nothing; every stop the tripwire drives (a scan's Stop and every operator
    stop) is served, each within ``STOP_LATENCY_BOUND``, through
    ``config.wsgi.application``. No stop handler is capped at all
    (``test_economics_run_cap.test_no_stop_route_takes_a_slot``, which walks the URLconf,
    runs on both platforms)."""
    caps(host=2, tenant=1)
    analyst = User.objects.create_user(username="ann-every", password="x", role="analyst")
    deployment = Deployment.objects.create(name="every-held")
    scenario = stored(deployment, analyst)
    with _holder("worker-x", "worker-y"):
        assert run_cap._probe("any-other-tenant") == "host"
        before = SimulationResult.objects.count()
        response, took = run_cap._post_within(analyst, run_cap._simulate_url(deployment, scenario),
                                              {"seed": 61, "policy": QUICK})
        run_cap._refused_at_capacity(response)
        assert took < run_cap.REFUSED_WITHIN, took
        assert SimulationResult.objects.count() == before

        timings = []
        real = tripwire._WsgiHandler.__call__

        def timed(self, environ):
            began = time.perf_counter()
            try:
                return real(self, environ)
            finally:
                timings.append((time.perf_counter() - began, environ["REQUEST_METHOD"], environ["PATH_INFO"]))

        monkeypatch.setattr(tripwire._WsgiHandler, "__call__", timed)
        operator = tripwire._admin()
        bearer = tripwire._wsgi_bearer_client(operator)
        bearer.get("/api/failsafe/audit/")  # the first request through the entry point imports what it needs
        timings.clear()
        served = tripwire._every_stop(bearer, operator, operator_key, anonymous=tripwire._WsgiClient)
        assert run_cap._probe("any-other-tenant") == "host", "a slot came free while the stops were made"
    assert served == tripwire.SERVED
    assert len(timings) >= len(tripwire.EVERY_STOP)
    slow = [(round(t, 3), method, path) for t, method, path in timings if t > tripwire.STOP_LATENCY_BOUND]
    assert slow == [], slow
    with capsys.disabled():
        print(
            f"\n[economics run cap, {sys.platform}] every slot held by another process: refusal "
            f"{took * 1000:.1f} ms; {len(timings)} stop requests, slowest {max(t for t, _, _ in timings) * 1000:.1f} ms "
            f"(bound {tripwire.STOP_LATENCY_BOUND * 1000:.0f} ms)"
        )


# ============================================ a run, through the route


@pytest.mark.django_db
def test_a_simulate_runs_through_the_route_under_the_cap_and_gives_its_slot_back(caps, monkeypatch):
    """The run takes the deployment's slot and the host's (seen from inside it), is
    made (201), and gives both back."""
    caps(host=1, tenant=1)
    analyst = User.objects.create_user(username="ann-runs", password="x", role="analyst")
    deployment = Deployment.objects.create(name="runs-here")
    scenario = stored(deployment, analyst)
    seen = {}
    real = simulation_service.simulate_scenario

    def inside(*args, **kwargs):
        seen["tenant"] = run_cap._probe(str(deployment.uuid))
        seen["host"] = run_cap._probe("any-other-tenant")
        return real(*args, **kwargs)

    monkeypatch.setattr(simulation_service, "simulate_scenario", inside)
    response = run_cap._client(analyst).post(run_cap._simulate_url(deployment, scenario),
                                             {"seed": 71, "policy": QUICK}, format="json")
    assert response.status_code == 201, (response.status_code, response.content[:300])
    assert seen == {"tenant": "tenant", "host": "host"}, seen
    assert run_cap._probe(str(deployment.uuid)) == "free"


@pytest.mark.django_db
def test_a_receipt_is_made_through_the_simulate_route(caps, monkeypatch):
    """``test_economics_read_routes._receipted``: a receipt asked for through the
    simulate route, under the cap (201, issued), the slot given back."""
    caps(host=1, tenant=1)
    analyst = User.objects.create_user(username="ann-receipt", password="x", role="analyst")
    User.objects.create_user(username="ada-receipt", password="x", role="admin")  # the reviewer
    deployment = Deployment.objects.create(name="receipted-here")
    scenario, row, _ring, envelope = _receipted(deployment, analyst, monkeypatch)
    assert FinancialExposureReceipt.objects.filter(scenario=scenario).count() == 1
    assert row.envelope == envelope
    assert run_cap._probe(str(deployment.uuid)) == "free"


# ===================================== the Windows lock, on any host


class _Recorder:
    """What ``capacity`` sees as ``msvcrt``: on Windows the real one, elsewhere a stand-in
    that answers as Windows does (``LK_NBLCK`` held elsewhere raises ``EACCES``;
    ``LK_LOCK`` waits), built on flock. Every call is recorded with the file position it
    was made at; ``fail`` makes the next lock raise that errno instead."""

    def __init__(self, real):
        self._real = real
        self.LK_UNLCK, self.LK_LOCK, self.LK_NBLCK = real.LK_UNLCK, real.LK_LOCK, real.LK_NBLCK
        self.LK_RLCK, self.LK_NBRLCK = real.LK_RLCK, real.LK_NBRLCK
        self.calls: list[tuple[int, int, int]] = []
        self.fail: int | None = None

    def locking(self, descriptor, mode, nbytes):
        self.calls.append((mode, nbytes, os.lseek(descriptor, 0, os.SEEK_CUR)))
        if self.fail is not None and mode != self.LK_UNLCK:
            raise OSError(self.fail, os.strerror(self.fail))
        return self._real.locking(descriptor, mode, nbytes)


def _flock_as_msvcrt():
    import fcntl

    def locking(descriptor, mode, nbytes):
        if mode in (2, 4):  # LK_NBLCK, LK_NBRLCK: one attempt
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise OSError(errno.EACCES, "Permission denied") from None
        elif mode in (1, 3):  # LK_LOCK, LK_RLCK: Windows retries for 10 s; this waits
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        elif mode == 0:  # LK_UNLCK
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        else:
            raise OSError(errno.EINVAL, "Invalid argument")

    return types.SimpleNamespace(LK_UNLCK=0, LK_LOCK=1, LK_NBLCK=2, LK_RLCK=3, LK_NBRLCK=4, locking=locking)


@pytest.fixture
def windows_lock(monkeypatch):
    """``capacity`` as it is on Windows: no ``fcntl``, and ``msvcrt`` (recorded)."""
    if WINDOWS:
        import msvcrt as real
    else:
        real = _flock_as_msvcrt()
    recorder = _Recorder(real)
    monkeypatch.setattr(capacity, "fcntl", None, raising=False)
    monkeypatch.setattr(capacity, "msvcrt", recorder, raising=False)
    assert capacity.lock_kind() == "msvcrt"
    return recorder


def test_the_windows_lock_is_one_attempt_on_byte_zero_and_never_waits(windows_lock, caps):
    caps(host=2, tenant=1)
    held = [run_cap._hold("tenant-a"), run_cap._hold("tenant-b")]
    try:
        answers = {tenant: run_cap._probe_within(tenant) for tenant in ("tenant-c", "tenant-a")}
        assert {tenant: answer for tenant, (answer, _) in answers.items()} == {"tenant-c": "host",
                                                                              "tenant-a": "tenant"}
        assert max(took for _, took in answers.values()) < run_cap.REFUSED_WITHIN, answers
    finally:
        for slots in held:
            slots.release()
    locks = [(mode, nbytes, at) for mode, nbytes, at in windows_lock.calls if mode != windows_lock.LK_UNLCK]
    assert locks, "no slot was locked through msvcrt"
    assert {(mode, nbytes, at) for mode, nbytes, at in locks} == {(windows_lock.LK_NBLCK, 1, 0)}, locks


def test_the_windows_lock_is_given_back_and_its_handle_closed(windows_lock, caps, tmp_path, monkeypatch):
    caps(host=1, tenant=1)
    monkeypatch.setenv("ATHENA_ECONOMICS_SLOT_DIR", str(tmp_path / "slots"))
    slots = run_cap._hold("tenant-a")
    descriptors = list(slots._descriptors)
    assert len(descriptors) == 2
    assert run_cap._probe("tenant-z") == "host"
    windows_lock.calls.clear()
    slots.release()
    assert windows_lock.calls == [(windows_lock.LK_UNLCK, 1, 0)] * 2, windows_lock.calls
    for descriptor in descriptors:
        with pytest.raises(OSError):
            os.fstat(descriptor)
    assert run_cap._probe("tenant-a") == "free"
    assert all(path.stat().st_size == 0 for path in (tmp_path / "slots").iterdir())


@pytest.mark.parametrize("code", [errno.EBADF, errno.EINVAL, errno.EIO], ids=["EBADF", "EINVAL", "EIO"])
def test_a_windows_lock_that_fails_refuses_the_run_never_runs_it_uncapped(windows_lock, caps, code):
    """Only "held elsewhere" (``EACCES``) means a slot is busy. Any other lock error
    refuses the run as ``unreadable``: it is never taken for a free slot."""
    caps(host=1, tenant=1)
    windows_lock.fail = code
    assert run_cap._probe("tenant-a") == "unreadable"
    windows_lock.fail = None
    assert run_cap._probe("tenant-a") == "free", "a refused acquire kept a slot"


def test_a_windows_lock_failing_on_the_hosts_slot_gives_the_tenants_back(windows_lock, caps):
    caps(host=1, tenant=1)
    real = windows_lock.locking
    count = {"locks": 0}

    def second_fails(descriptor, mode, nbytes):
        if mode != windows_lock.LK_UNLCK:
            count["locks"] += 1
            if count["locks"] == 2:
                raise OSError(errno.EIO, os.strerror(errno.EIO))
        return real(descriptor, mode, nbytes)

    windows_lock.locking = second_fails
    slots, why = capacity.acquire("tenant-a")
    assert (slots, why) == (None, "unreadable")
    windows_lock.locking = real
    assert run_cap._probe("tenant-a") == "free"


@pytest.mark.django_db
def test_a_simulate_with_the_windows_lock_runs_and_at_capacity_is_the_503(windows_lock, caps):
    caps(host=1, tenant=1)
    analyst = User.objects.create_user(username="ann-winlock", password="x", role="analyst")
    deployment = Deployment.objects.create(name="win-lock")
    scenario = stored(deployment, analyst)
    url = run_cap._simulate_url(deployment, scenario)
    response = run_cap._client(analyst).post(url, {"seed": 81, "policy": QUICK}, format="json")
    assert response.status_code == 201, (response.status_code, response.content[:300])
    held = run_cap._hold("someone-else")
    try:
        refused = run_cap._client(analyst).post(url, {"seed": 82, "policy": QUICK}, format="json")
        assert "every economics run slot" in run_cap._refused_at_capacity(refused)["detail"]
    finally:
        held.release()
