"""The cap on economics runs at once (``assurance.economics.capacity``;
``docs/economics/spec-v1.md``, section 32): the SAFETY RULE says nothing may block,
delay or drop a stop, and a simulate request holds its worker for up to 120 s.

- With every slot held by a slow run (a test seam holds each run open), a further
  simulate is 503 ``economics_capacity`` with ``Retry-After`` in well under a second,
  on both Monte Carlo routes, and records nothing; and every stop -- a scan's Stop,
  a pause, a stand-down, a terminate, a revoke, a demotion, a removal, the stop lane's
  reads and the engine's poll -- is answered, through the whole WSGI stack, within the
  bound the stop tripwire already holds it to.
- Per tenant: a second run of the same deployment is 503 while another deployment's
  run proceeds.
- A slot comes back on every exit: an exception, gunicorn's abort (``SystemExit``), and
  a holder killed with SIGKILL (the kernel releases its flock).
- No stop route's handler takes a slot; every handler that runs a Monte Carlo does.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.db import connections
from django.test.utils import override_settings
from rest_framework.test import APIClient

from assurance.economics import capacity, remediation_service, simulation_service
from assurance.economics.models import SimulationResult
from assurance.models import Deployment
from safety import stops
from tests import test_no_control_holds_back_a_stop as tripwire
from tests.test_economics_remediation import option_body
from tests.test_economics_report import QUICK, stored

User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
#: The longest a held run waits for the test to let it go: a run is never held
#: forever, so a defect makes a test fail, not hang.
HOLD_SECONDS = 20.0
#: "Well under a second": the longest a refusal at capacity may take.
REFUSED_WITHIN = 0.5
#: Every name a handler calls to make a Monte Carlo run, or the sensitivity analysis
#: a Validity Card is (#162's portfolio route's is ``simulate_portfolio``).
RUN_ENTRY_POINTS = frozenset(
    {"simulate_scenario", "simulate_option", "simulate_portfolio", "issue_card", "issue_charts", "issue_receipt"}
)
#: The handlers that run a Monte Carlo today, each registered with ``@capacity.capped``.
CAPPED_HANDLERS = {
    "assurance.economics.report_api.ScenarioSimulateView.post",
    "assurance.economics.remediation_api.MitigationSimulateView.post",
    # E6's refresh (spec, section 34.4): it rebuilds, runs, cards and receipts a stale
    # scenario version.
    "assurance.economics.report_api.ScenarioRefreshView.post",
}


def _client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _simulate_url(deployment, scenario):
    return f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario.uuid}/simulate/"


def _mitigation_url(deployment, scenario, option):
    return (f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario.uuid}/mitigations/"
            f"{option.uuid}/simulate/")


def _refused_at_capacity(response):
    assert response.status_code == 503, (response.status_code, getattr(response, "data", None))
    assert response["Retry-After"] == str(capacity.RETRY_AFTER_SECONDS)
    body = response.json()
    assert body["code"] == "economics_capacity" and body["recorded"] is False, body
    return body


@pytest.fixture
def caps(monkeypatch):
    """The caps for one test: a global cap and a per-tenant cap."""

    def apply(host, tenant=1):
        monkeypatch.setenv("ATHENA_ECONOMICS_RUN_CAP", str(host))
        monkeypatch.setenv("ATHENA_ECONOMICS_RUN_CAP_PER_TENANT", str(tenant))

    return apply


class HeldOpen:
    """The test seam: a simulate request made by :meth:`start` takes its slot, then its
    run is held open inside ``simulation_service.simulate_scenario`` until
    :meth:`let_go` (or :data:`HOLD_SECONDS`). Any other request's run is the real one."""

    def __init__(self, monkeypatch):
        self.go = threading.Event()
        self.entered = threading.Semaphore(0)
        self.holders: set[int] = set()
        self.threads: list[threading.Thread] = []
        self.answers: dict[str, int] = {}
        real = simulation_service.simulate_scenario

        def held(*args, **kwargs):
            if threading.get_ident() in self.holders:
                self.entered.release()
                self.go.wait(timeout=HOLD_SECONDS)
            return real(*args, **kwargs)

        monkeypatch.setattr(simulation_service, "simulate_scenario", held)

    def start(self, name, user, url, body):
        def run():
            self.holders.add(threading.get_ident())
            try:
                self.answers[name] = _client(user).post(url, body, format="json").status_code
            finally:
                connections.close_all()

        thread = threading.Thread(target=run, name=f"held-{name}", daemon=True)
        self.threads.append(thread)
        thread.start()

    def wait_entered(self, count):
        for _ in range(count):
            assert self.entered.acquire(timeout=HOLD_SECONDS / 2), "a held run never took its slot and started"

    def let_go(self):
        self.go.set()
        for thread in self.threads:
            thread.join(timeout=120)
            assert not thread.is_alive(), f"{thread.name} did not finish"


@pytest.fixture
def held_open(monkeypatch):
    seam = HeldOpen(monkeypatch)
    yield seam
    seam.go.set()
    for thread in seam.threads:
        thread.join(timeout=120)


@pytest.fixture
def operator_key():
    key = Ed25519PrivateKey.generate()
    with override_settings(FAILSAFE_OPERATOR_KEYS={"alice": key.public_key().public_bytes_raw().hex()}):
        yield key


@pytest.fixture
def stop_lane(monkeypatch):
    """What the tripwire's every-stop drive needs, as its ``rates`` fixture sets it:
    the poll token, a gateway that allows at once, and an engine state read that
    answers at once."""
    from django.core.cache import cache
    from rest_framework.throttling import SimpleRateThrottle

    cache.clear()
    monkeypatch.setattr(
        SimpleRateThrottle, "THROTTLE_RATES",
        {"anon": tripwire.ANON_RATE, "user": "300/min", "sign_in": "10/min", "sign_in_address": "60/min"},
    )
    monkeypatch.setattr("audit.middleware.outbound.post", tripwire._engine_answers({"allow": True, "action": "allow"}))
    monkeypatch.setattr(
        "ai_engine.services.cyberengine_client.CyberEngineClient.from_settings",
        classmethod(lambda cls: tripwire._LiveState()),
    )
    with override_settings(DEFENDER_MONITOR_ONLY=True, FAILSAFE_POLL_TOKEN=tripwire.POLL_TOKEN):
        yield
    cache.clear()


def _within(seconds, what, work):
    """``(work(), seconds it took)``, run in a thread of its own so that a call that
    WAITS fails the test instead of hanging it. A late call finishes on its own."""
    out = {}

    def run():
        began = time.perf_counter()
        try:
            out["answer"] = work()
        finally:
            out["took"] = time.perf_counter() - began
            connections.close_all()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout=seconds)
    if thread.is_alive():
        pytest.fail(f"{what} WAITED: no answer within {seconds} s")
    if "answer" not in out:
        pytest.fail(f"{what} raised instead of answering")
    return out["answer"], out["took"]


def _probe_within(tenant, seconds=5.0):
    """What ``capacity.acquire`` answers for ``tenant`` now, ``"free"`` or why it is
    refused, and how long it took. A slot it took is given straight back, so a failing
    check holds nothing; an acquire that waits fails the test."""

    def probe():
        slots, why = capacity.acquire(tenant)
        if slots is None:
            return why
        slots.release()
        return "free"

    return _within(seconds, f"acquiring a slot for {tenant}", probe)


def _probe(tenant):
    return _probe_within(tenant)[0]


def _hold(tenant, seconds=5.0):
    """Slots for ``tenant``, KEPT for the test to release, taken in a thread of its own
    so an acquire that waits fails the test instead of hanging it."""
    (slots, why), _took = _within(seconds, f"holding a slot for {tenant}", lambda: capacity.acquire(tenant))
    assert slots is not None, f"no slot for {tenant}: {why}"
    return slots


def _post_within(user, url, body, seconds=REFUSED_WITHIN * 10):
    """A simulate request and how long it took, made in a thread of its own (a test
    that makes one must commit its rows: ``transaction=True``)."""
    return _within(seconds, f"POST {url}", lambda: _client(user).post(url, body, format="json"))


# ===================================================================== the caps


@pytest.mark.parametrize(
    ("workers", "explicit", "expected"),
    [
        (None, None, 1), ("1", None, 1), ("2", None, 1), ("3", None, 1), ("4", None, 2), ("9", None, 7),
        ("lots", None, 1), ("0", None, 1), ("4", "3", 3), ("4", "0", 0), ("4", "-1", 2), (None, "5", 5),
    ],
)
def test_the_default_cap_leaves_two_workers_free(monkeypatch, workers, explicit, expected):
    """cap = max(1, WEB_CONCURRENCY - 2), where WEB_CONCURRENCY is gunicorn's own worker
    count (1 when unset, gunicorn's default); ATHENA_ECONOMICS_RUN_CAP overrides it
    where it is a whole number (0 refuses every run)."""
    for name, value in (("WEB_CONCURRENCY", workers), ("ATHENA_ECONOMICS_RUN_CAP", explicit)):
        if value is None:
            monkeypatch.delenv(name, raising=False)
        else:
            monkeypatch.setenv(name, value)
    assert capacity.global_cap() == expected


def test_the_per_tenant_cap_is_one_by_default(monkeypatch):
    monkeypatch.delenv("ATHENA_ECONOMICS_RUN_CAP_PER_TENANT", raising=False)
    assert capacity.tenant_cap() == 1
    monkeypatch.setenv("ATHENA_ECONOMICS_RUN_CAP_PER_TENANT", "2")
    assert capacity.tenant_cap() == 2
    monkeypatch.setenv("ATHENA_ECONOMICS_RUN_CAP_PER_TENANT", "two")
    assert capacity.tenant_cap() == 1


def test_a_slot_is_taken_without_waiting(caps):
    """Every slot held: the next acquire answers at once, refused; one given back, it
    is taken."""
    caps(host=2, tenant=1)
    held = []
    try:
        held.append(_hold("tenant-a"))
        held.append(_hold("tenant-b"))
        assert _probe_within("tenant-c", seconds=5)[0] == "host"
        assert _probe_within("tenant-a", seconds=5)[0] == "tenant"
        took = [_probe_within(tenant, seconds=5)[1] for tenant in ("tenant-c", "tenant-a")]
        assert max(took) < 0.05, took
        held[0].release()
        assert _probe_within("tenant-c", seconds=5)[0] == "free"
    finally:
        for slots in held:
            slots.release()


def test_one_tenant_never_takes_every_slot(caps):
    caps(host=3, tenant=1)
    held = _hold("tenant-a")
    try:
        assert _probe("tenant-a") == "tenant"
        assert _probe("tenant-b") == "free"
    finally:
        held.release()


def test_slot_files_that_cannot_be_opened_refuse_the_run_never_run_it_uncapped(monkeypatch, tmp_path):
    blocked = tmp_path / "not-a-directory"
    blocked.write_text("a file where the slot directory should be")
    monkeypatch.setenv("ATHENA_ECONOMICS_SLOT_DIR", str(blocked))
    assert _probe("tenant-a") == "unreadable"


# ============================================ every slot held by a slow run


@pytest.mark.django_db(transaction=True)
def test_with_every_slot_held_a_run_is_refused_at_once_and_every_stop_is_answered_in_its_bound(
    caps, held_open, operator_key, stop_lane, monkeypatch, capsys
):
    """THE SAFETY RULE. Two slow runs (the seam holds each open) take the host's two
    slots. Then:

    - a further simulate, and a remediation option's simulate, are each 503
      ``economics_capacity`` with ``Retry-After`` within :data:`REFUSED_WITHIN`, and
      record nothing;
    - every stop the tripwire drives -- the scan's Stop and every operator stop -- is
      served (its usual status), each within ``STOP_LATENCY_BOUND`` through
      ``config.wsgi.application``;
    - the held runs, let go, finish (201) and give their slots back."""
    caps(host=2, tenant=1)
    analyst = User.objects.create_user(username="ann-cap", password="x", role="analyst")
    deployments = [Deployment.objects.create(name=f"cap-{i}") for i in range(3)]
    scenarios = [stored(d, analyst) for d in deployments]
    option, _ = remediation_service.record_option(scenarios[2], option_body("0.5"), author=analyst)
    for i in range(2):
        held_open.start(f"run-{i}", analyst, _simulate_url(deployments[i], scenarios[i]), {"seed": 11 + i,
                                                                                          "policy": QUICK})
    held_open.wait_entered(2)
    assert _probe("any-other-tenant") == "host", "the two held runs do not hold every slot"

    before = SimulationResult.objects.count()
    refusals = {}
    for name, url, body in (
        ("simulate", _simulate_url(deployments[2], scenarios[2]), {"seed": 13, "policy": QUICK}),
        ("mitigation simulate", _mitigation_url(deployments[2], scenarios[2], option), {"seed": 13, "policy": QUICK}),
    ):
        response, refusals[name] = _post_within(analyst, url, body)
        _refused_at_capacity(response)
    assert max(refusals.values()) < REFUSED_WITHIN, refusals
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
    assert _probe("any-other-tenant") == "host", "a slot came free while the stops were made"
    assert served == tripwire.SERVED
    assert len(timings) >= len(tripwire.EVERY_STOP)
    slow = [(round(t, 3), method, path) for t, method, path in timings if t > tripwire.STOP_LATENCY_BOUND]
    assert slow == [], slow
    scan_stop = [t for t, method, path in timings if method == "POST" and path.endswith("/stop/")]
    with capsys.disabled():
        print(
            f"\n[economics run cap] every slot held: refusals {', '.join(f'{k} {v * 1000:.1f} ms' for k, v in refusals.items())}; "
            f"{len(timings)} stop requests, slowest {max(t for t, _, _ in timings) * 1000:.1f} ms, "
            f"scan Stop {scan_stop[0] * 1000:.1f} ms (bound {tripwire.STOP_LATENCY_BOUND * 1000:.0f} ms)"
        )

    held_open.let_go()
    assert held_open.answers == {"run-0": 201, "run-1": 201}
    assert _probe("any-other-tenant") == "free", "a held run did not give its slot back"


@pytest.mark.django_db(transaction=True)
def test_a_second_run_of_one_tenant_is_refused_while_another_tenants_run_proceeds(caps, held_open):
    caps(host=2, tenant=1)
    analyst = User.objects.create_user(username="ann-tenant", password="x", role="analyst")
    busy, other = Deployment.objects.create(name="busy"), Deployment.objects.create(name="other")
    busy_scenario, other_scenario = stored(busy, analyst), stored(other, analyst)
    held_open.start("busy", analyst, _simulate_url(busy, busy_scenario), {"seed": 21, "policy": QUICK})
    held_open.wait_entered(1)
    refused, took = _post_within(analyst, _simulate_url(busy, busy_scenario), {"seed": 22, "policy": QUICK})
    body = _refused_at_capacity(refused)
    assert "this deployment" in body["detail"] and took < REFUSED_WITHIN, (body, took)
    proceeds, _ = _post_within(analyst, _simulate_url(other, other_scenario), {"seed": 23, "policy": QUICK}, 120)
    assert proceeds.status_code == 201, proceeds.data
    held_open.let_go()
    assert held_open.answers == {"busy": 201}
    again, _ = _post_within(analyst, _simulate_url(busy, busy_scenario), {"seed": 22, "policy": QUICK}, 120)
    assert again.status_code == 201, again.data


@pytest.mark.django_db(transaction=True)
def test_no_slot_is_disclosed_to_one_who_cannot_see_the_deployment_or_may_not_run(caps):
    """With every slot held, one who cannot see the deployment is 404 and a viewer 403,
    as ever: the cap is reached only after access, so a tenant's runs are never told
    to another tenant, and a refused caller never takes a slot."""
    caps(host=1, tenant=1)
    owner = User.objects.create_user(username="vic-cap", password="x", role="viewer")
    outsider = User.objects.create_user(username="oto-cap", password="x", role="viewer")
    analyst = User.objects.create_user(username="ann-access", password="x", role="analyst")
    deployment = Deployment.objects.create(name="seen", owner=owner)
    scenario = stored(deployment, analyst)
    held = _hold(str(deployment.uuid))
    try:
        url, body = _simulate_url(deployment, scenario), {"seed": 31, "policy": QUICK}
        assert _post_within(outsider, url, body)[0].status_code == 404
        assert _post_within(owner, url, body)[0].status_code == 403
        refused, _ = _post_within(analyst, url, body)
        assert _refused_at_capacity(refused) == {
            "code": "economics_capacity",
            "detail": "this deployment already has as many economics runs in progress as it may: nothing was run or "
            f"recorded; send the same request again after {capacity.RETRY_AFTER_SECONDS} s",
            "recorded": False,
        }
    finally:
        held.release()


# ===================================================== a slot comes back on every exit


@pytest.mark.django_db
@pytest.mark.parametrize("fault", [RuntimeError("the run broke"), SystemExit(1)], ids=["exception", "worker abort"])
def test_a_slot_is_given_back_when_the_run_raises(caps, monkeypatch, fault):
    """An exception, and gunicorn's abort of a timed-out worker (``SystemExit`` raised
    in the handler), each give the slot back."""
    caps(host=1, tenant=1)
    analyst = User.objects.create_user(username="ann-fault", password="x", role="analyst")
    deployment = Deployment.objects.create(name="faulty")
    scenario = stored(deployment, analyst)

    def broken(*args, **kwargs):
        raise fault

    monkeypatch.setattr(simulation_service, "simulate_scenario", broken)
    with pytest.raises(type(fault)):
        _client(analyst).post(_simulate_url(deployment, scenario), {"seed": 41, "policy": QUICK}, format="json")
    assert _probe(str(deployment.uuid)) == "free", f"the slot was kept after {type(fault).__name__}"


_HOLDER = textwrap.dedent(
    """
    import importlib.util, sys
    spec = importlib.util.spec_from_file_location("economics_capacity_probe", sys.argv[1])
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    slots, why = module.acquire("killed-tenant")
    print("held" if slots is not None else "refused:" + why, flush=True)
    sys.stdin.read()
    """
)


def test_a_killed_holders_slots_come_back(caps, tmp_path):
    """A worker killed by SIGKILL (the OOM killer; gunicorn after its graceful timeout)
    runs no ``finally``: the kernel releases its flock when the process dies, so its
    slots come back at once. No lease, expiry or sweeper is involved."""
    caps(host=1, tenant=1)
    env = {
        "ATHENA_ECONOMICS_SLOT_DIR": os.environ["ATHENA_ECONOMICS_SLOT_DIR"],
        "ATHENA_ECONOMICS_RUN_CAP": "1",
        "ATHENA_ECONOMICS_RUN_CAP_PER_TENANT": "1",
        "PATH": os.environ.get("PATH", ""),
    }
    holder = subprocess.Popen(
        [sys.executable, "-I", "-c", _HOLDER, inspect.getsourcefile(capacity)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env, cwd=tmp_path, text=True,
    )
    try:
        said, _took = _within(30, "the holder's acquire", holder.stdout.readline)
        assert said.strip() == "held", said
        assert _probe("killed-tenant") == "tenant"
        assert _probe("another-tenant") == "host"
        holder.send_signal(signal.SIGKILL)
        holder.wait(timeout=30)
        answer, took = _probe_within("killed-tenant", seconds=5)
        assert answer == "free" and took < 1.0, (answer, took)
    finally:
        if holder.poll() is None:
            holder.kill()
            holder.wait(timeout=30)
        for stream in (holder.stdin, holder.stdout, holder.stderr):
            stream.close()


def test_a_slot_file_carries_nothing(caps, monkeypatch, tmp_path):
    """The canary harness classifies the slot files (``FILE_WRITERS``): each is created
    empty, never written to, and named by a slot's index or a digest of the tenant,
    never the tenant itself."""
    caps(host=2, tenant=1)
    monkeypatch.setenv("ATHENA_ECONOMICS_SLOT_DIR", str(tmp_path / "slots"))
    tenant = "deployment-0b9f3a52-canary-tenant"
    held = _hold(tenant)
    held.release()
    names = sorted(path.name for path in (tmp_path / "slots").iterdir())
    assert names == ["run-0.lock", f"tenant-{hashlib.sha256(tenant.encode()).hexdigest()[:32]}-0.lock"], names
    assert all((tmp_path / "slots" / name).stat().st_size == 0 for name in names)
    assert not any(tenant in name for name in names)


# =============================================== which handlers take a slot


def _member(cls, name):
    """``name`` as ``cls`` defines or inherits it, read from the classes' own
    namespaces (never a getattr by a runtime name), or None."""
    for klass in cls.__mro__:
        if name in vars(klass):
            return vars(klass)[name]
    return None


def _handlers(callback):
    """Every handler ``callback`` (a URL pattern's) dispatches to, by HTTP method."""
    cls = getattr(callback, "cls", None) or getattr(callback, "view_class", None)
    if cls is None:
        return {"ANY": callback}
    actions = getattr(callback, "actions", None)
    wanted = actions.items() if actions else ((m, m) for m in cls.http_method_names if m not in ("options", "head"))
    found = {method.upper(): _member(cls, name) for method, name in wanted}
    return {method: handler for method, handler in found.items() if callable(handler)}


def _calls(handler) -> set[str]:
    try:
        tree = ast.parse(textwrap.dedent(inspect.getsource(inspect.unwrap(handler))))
    except (OSError, TypeError, SyntaxError):
        return set()
    names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            names.add(func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", ""))
    return names


def _served():
    """{route name: {method: handler}} for every route the URLconf serves."""
    served = {}
    for name, entry in tripwire.walk().items():
        handlers = served.setdefault(name, {})
        for callback in entry["callbacks"]:
            handlers.update(_handlers(callback))
    return served


def test_no_stop_route_takes_a_slot():
    """A stop never touches the cap: no handler of a stop route, or of what an
    operator needs to make one, is capped."""
    served = _served()
    assert set(stops.EXEMPT_ROUTES) <= set(served)
    capped = sorted(
        f"{name} {method}"
        for name in stops.EXEMPT_ROUTES
        for method, handler in served[name].items()
        if getattr(handler, "economics_capped", False)
    )
    assert capped == []


def test_every_handler_that_runs_a_monte_carlo_takes_a_slot():
    """Walking the whole URLconf: a handler that calls a run (``RUN_ENTRY_POINTS``) is
    capped, and only those are. #162's portfolio POST, which calls
    ``simulate_portfolio``, fails this until it registers with ``@capacity.capped``."""
    runs, capped = set(), set()
    for name, handlers in _served().items():
        for method, handler in handlers.items():
            label = f"{getattr(handler, '__module__', '?')}.{getattr(handler, '__qualname__', repr(handler))}"
            if _calls(handler) & RUN_ENTRY_POINTS:
                runs.add(label)
            if getattr(handler, "economics_capped", False):
                capped.add(label)
                assert name in stops.NOT_STOPS and name not in stops.EXEMPT_ROUTES, name
                assert method in stops.NOT_STOPS[name], (name, method)
    assert runs == CAPPED_HANDLERS
    assert capped == runs == capacity.CAPPED


def test_no_management_command_runs_a_monte_carlo_uncapped():
    """A command that ran a Monte Carlo would take a slot too. None runs one today."""
    commands = [
        path for path in REPO.glob("*/management/commands/*.py")
        if "settings" not in path.name and path.name != "__init__.py"
    ]
    assert commands, "no management command was found to read"
    uncapped = []
    for path in commands:
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names = {
            node.func.attr if isinstance(node.func, ast.Attribute) else getattr(node.func, "id", "")
            for node in ast.walk(tree) if isinstance(node, ast.Call)
        }
        if names & RUN_ENTRY_POINTS and "acquire" not in names:
            uncapped.append(path.relative_to(REPO).as_posix())
    assert uncapped == []


def test_the_spec_and_the_readme_state_the_cap():
    spec = (REPO / "docs" / "economics" / "spec-v1.md").read_text(encoding="utf-8")
    readme = (REPO / "README.md").read_text(encoding="utf-8")
    for text in (spec, readme):
        for needle in ("economics_capacity", "ATHENA_ECONOMICS_RUN_CAP", "ATHENA_ECONOMICS_RUN_CAP_PER_TENANT",
                       "WEB_CONCURRENCY", "ATHENA_ECONOMICS_SLOT_DIR", "Retry-After"):
            assert needle in text, needle
    assert "**No cap on simulations at once**" not in spec
