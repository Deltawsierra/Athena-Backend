"""Every operation says how it degrades, and degrades that way (G14, the owner's decision 13).

When something this backend depends on is down, slow or answering garbage:

* a STOP always works -- nothing here gates one or changes its answer;
* an EVIDENCE READ is an honest ``unknown`` with its reason -- never a bare 5xx;
* an EFFECT is HELD -- it never proceeds;
* an ASSESSMENT is ``AUDIT_INCOMPLETE`` -- never a pass.

The first section is the tripwire: it walks the URLconf, the admin site included,
and fails on a route or method with no operation class, on a stop declared
anywhere but safety.stops, and on a class for a route nobody serves. The second
drives every route with the database raising, hanging until its statement times
out, and answering rows that do not decode. The third is the Athena-Backend
preflight: a launch whose engine is down, hangs or answers garbage is held in
every mode. The fourth is the defender, whose garbage answer read as "nothing
detected".
"""

from __future__ import annotations

import http.server
import json
import threading
import time
import uuid
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from django.db import OperationalError
from django.db.backends.utils import CursorWrapper
from django.test import RequestFactory
from django.urls import NoReverseMatch, get_resolver, reverse
from django.views import defaults
from mythos_core import status as core_status
from mythos_core.action_assurance.decision import HOLD
from rest_framework.test import APIClient

from safety import degraded, stops
from tests.test_no_control_holds_back_a_stop import walk

# --- The tripwire ----------------------------------------------------------------


def class_problems(served, routes):
    """Every way the served routes and the declared classes disagree."""
    problems = []
    for name, entry in sorted(served.items()):
        for method in sorted(entry["methods"]):
            if degraded.class_of(name, method) is None:
                problems.append(f"{name} {method}: no operation class; declare one in safety/degraded.py")
    for name, methods in sorted(routes.items()):
        if name not in served:
            problems.append(f"{name}: declared, but no such route is served")
            continue
        for method, klass in sorted(methods.items()):
            if klass not in degraded.POLICY or klass == degraded.STOP:
                problems.append(f"{name} {method}: declares {klass!r}, which is not a non-stop operation class")
            if method in stops.EXEMPT_ROUTES.get(name, {}):
                problems.append(f"{name} {method}: is a stop, which safety.stops alone declares")
            if method not in served[name]["methods"]:
                problems.append(f"{name} {method}: declared, but the route does not serve it")
    return problems


def test_every_route_and_method_declares_how_it_degrades():
    assert class_problems(walk(), degraded.ROUTES) == []


def test_a_route_with_no_class_fails_the_tripwire():
    served = walk()
    routes = {name: dict(methods) for name, methods in degraded.ROUTES.items()}
    del routes["deployment-decision-support"]
    with mock.patch.object(degraded, "ROUTES", routes):
        assert class_problems(served, routes) == [
            "deployment-decision-support GET: no operation class; declare one in safety/degraded.py"
        ]


def test_the_stop_class_is_exactly_the_stop_set():
    served = walk()
    stop_class = {
        (name, method)
        for name, entry in served.items()
        for method in entry["methods"]
        if degraded.class_of(name, method) == degraded.STOP
    }
    declared = {(name, method) for name, methods in stops.EXEMPT_ROUTES.items() for method in methods}
    assert stop_class == declared


def test_a_stop_declared_as_anything_else_fails_the_tripwire():
    routes = {name: dict(methods) for name, methods in degraded.ROUTES.items()}
    routes["pentest:stop_pentest_scan"] = {"POST": degraded.EFFECT}
    assert class_problems(walk(), routes) == [
        "pentest:stop_pentest_scan POST: is a stop, which safety.stops alone declares"
    ]


def test_every_class_names_mythos_cores_word_for_it():
    assert (degraded.UNKNOWN, degraded.HOLD, degraded.AUDIT_INCOMPLETE) == (
        core_status.UNKNOWN, HOLD, core_status.AUDIT_INCOMPLETE
    )
    assert degraded.POLICY[degraded.EVIDENCE_READ]["status"] == core_status.UNKNOWN
    assert degraded.POLICY[degraded.EFFECT]["status"] == HOLD
    assert degraded.POLICY[degraded.ASSESSMENT]["status"] == core_status.AUDIT_INCOMPLETE
    assert degraded.POLICY[degraded.STOP]["status"] is None


def test_the_handler_imports_nothing_that_can_take_the_urlconf_down():
    """The root URLconf's handler500 is imported by ``manage.py check`` and by
    ``deliver_owed_stops`` before either runs: it imports Django and safety.stops,
    never Mythos-Core or an engine client at load."""
    import ast
    import pathlib

    tree = ast.parse(pathlib.Path(degraded.__file__).read_text(encoding="utf-8"))
    loaded = [
        (node.module if isinstance(node, ast.ImportFrom) else alias.name) or ""
        for node in tree.body
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for alias in node.names
    ]
    assert all(name.split(".")[0] in {"__future__", "logging", "sys", "django", ""} for name in loaded), loaded


def test_the_degraded_answer_is_the_root_urlconfs_handler500():
    assert get_resolver().resolve_error_handler(500) is degraded.server_error


# --- Every route, with the database down, hanging, or answering garbage ------------


def _path(name):
    """A URL for ``name`` with made-up arguments, never its format-suffix form."""
    resolver = get_resolver()
    *namespaces, short = name.split(":")
    for namespace in namespaces:
        resolver = resolver.namespace_dict[namespace][1]
    for possibility, _pattern, _defaults, converters in resolver.reverse_dict.getlist(short):
        for _result, params in possibility:
            if "format" in params:
                continue
            for style in ("uuid", "int"):
                kwargs = {
                    p: str(uuid.uuid4())
                    if "UUID" in type(converters.get(p)).__name__
                    or (style == "uuid" and "Int" not in type(converters.get(p)).__name__)
                    else "1"
                    for p in params
                }
                try:
                    return reverse(name, kwargs=kwargs)
                except NoReverseMatch:
                    continue
    raise AssertionError(f"no URL could be built for {name}")


def _api_routes():
    """(name, method, path) for every route but the admin site's, which is Django's."""
    out = []
    for name, entry in sorted(walk().items()):
        if name.startswith("admin:"):
            continue
        path = _path(name)
        for method in sorted(entry["methods"]):
            out.append((name, "GET" if method == "ANY" else method, path))
    return out


def _database(fault, calls):
    """Patches that make every statement fail as ``fault`` says, counting each in
    ``calls``: ``raises`` (refused at once), ``hangs`` (held until the database's own
    statement timeout ends it, bounded here at 20 ms a statement) or ``garbage``
    (it runs, and every row read back is not the row asked for)."""

    def failing(*_args, **_kwargs):
        calls.append(fault)
        if fault == "hangs":
            time.sleep(0.02)
            raise OperationalError("canceling statement due to statement timeout")
        raise OperationalError("the database is unavailable")

    if fault != "garbage":
        return mock.patch.multiple(CursorWrapper, execute=failing, executemany=failing)

    real = CursorWrapper.__getattr__
    answered = set()

    def answering_garbage(self, attr):
        # One garbage row per statement, then the end of its rows: a reader that
        # reads to the end must reach one.
        def rows(*_args, **_kwargs):
            calls.append(fault)
            if id(self) in answered:
                return []
            answered.add(id(self))
            return [(object(),)]

        def row(*_args, **_kwargs):
            calls.append(fault)
            return (object(),)

        if attr in ("fetchmany", "fetchall"):
            return rows
        if attr == "fetchone":
            return row
        return real(self, attr)

    return mock.patch.object(CursorWrapper, "__getattr__", answering_garbage)


DATABASE_FAULTS = ("raises", "hangs", "garbage")


@pytest.fixture()
def admin(db):
    return get_user_model().objects.create_user(
        username="g14-admin", password="x", role="admin", is_staff=True, is_superuser=True
    )


def _drive(admin, method, path, fault):
    """The answer to ``method`` ``path`` with the database failing as ``fault``, and
    how many statements reached it."""
    client = APIClient(raise_request_exception=False)
    client.force_authenticate(user=admin)
    calls = []
    with _database(fault, calls):
        response = getattr(client, method.lower())(path, data={}, format="json")
    return response, len(calls)


#: The word each class answers in, stated here apart from safety.degraded so a
#: policy that drifts to another word fails.
WORDS = {
    degraded.EVIDENCE_READ: core_status.UNKNOWN,
    degraded.EFFECT: HOLD,
    degraded.ASSESSMENT: core_status.AUDIT_INCOMPLETE,
}


def _degraded_problem(name, method, response):
    """Why ``response`` is not what the policy says a failed ``name`` ``method`` answers."""
    klass = degraded.class_of(name, method)
    if 200 <= response.status_code < 300:
        return f"{name} {method} [{klass}]: answered {response.status_code} on a failed dependency"
    if response.status_code < 500:
        return None  # refused before anything was read or done: a 4xx proceeds with nothing
    try:
        body = json.loads(response.content)
    except ValueError:
        return f"{name} {method} [{klass}]: answered {response.status_code} with no reason"
    want = WORDS[klass]
    if body.get("status") != want or body.get("operation_class") != klass or not body.get("detail"):
        return f"{name} {method} [{klass}]: answered {response.status_code} {body!r}, not {want}"
    return None


@pytest.mark.django_db
@pytest.mark.parametrize("fault", DATABASE_FAULTS)
def test_every_route_degrades_by_its_class_when_the_database_fails(admin, fault):
    """A route that reached the database while it failed answers by its class. One
    that never reached it (an API root, the liveness probe, a static registry, a
    route not built yet) depended on nothing that failed, and is not judged here."""
    problems = []
    judged = 0
    for name, method, path in _api_routes():
        if degraded.class_of(name, method) == degraded.STOP:
            continue
        response, reached = _drive(admin, method, path, fault)
        if not reached:
            continue
        judged += 1
        problem = _degraded_problem(name, method, response)
        if problem:
            problems.append(problem)
        elif response.status_code >= 500 and fault != "garbage":
            body = json.loads(response.content)
            if body["dependency"] != "the database" or "OperationalError" not in body["detail"]:
                problems.append(f"{name} {method}: did not name the database: {body!r}")
    assert problems == [], "\n".join(problems)
    assert judged > 150


@pytest.mark.django_db
@pytest.mark.parametrize("fault", DATABASE_FAULTS)
def test_a_stop_keeps_its_own_answer_when_the_database_fails(admin, fault):
    """Nothing on a stop's path changes: a stop that fails answers what it answered
    before this policy -- Django's own 500, or the stop's own refusal -- never the
    policy's degraded answer."""
    expected_500 = defaults.server_error(RequestFactory().get("/")).content
    seen = 0
    for name, method, path in _api_routes():
        if degraded.class_of(name, method) != degraded.STOP:
            continue
        seen += 1
        response, _reached = _drive(admin, method, path, fault)
        assert b"operation_class" not in response.content, (name, method)
        if response.status_code == 500:
            assert response.content == expected_500, (name, method)
    assert seen == len({(n, m) for n, ms in stops.EXEMPT_ROUTES.items() for m in ms})


def test_the_degraded_answer_never_fails_a_request():
    """A fault in building the answer answers Django's own 500, never raises."""
    request = RequestFactory().get("/api/assurance/deployments/")
    request.resolver_match = mock.Mock(view_name="deployment-list")
    with mock.patch.object(degraded, "degraded_body", side_effect=RuntimeError("defect")):
        try:
            raise OperationalError("down")
        except OperationalError:
            response = degraded.server_error(request)
    assert response.status_code == 500


@pytest.mark.parametrize(
    ("exc", "dependency"),
    [
        (OperationalError("x"), "the database"),
        (ValueError("x"), "an internal fault"),
    ],
)
def test_the_dependency_is_named_by_type_never_by_message(exc, dependency):
    body = degraded.degraded_body(degraded.EVIDENCE_READ, exc)
    assert body["dependency"] == dependency
    assert "x)" not in body["detail"] and type(exc).__name__ in body["detail"]


def test_an_engine_error_is_named_as_the_engine_even_as_a_cause():
    from ai_engine.services.cyberengine_client import ENGINE_UNREACHABLE, EngineError

    try:
        try:
            raise EngineError("refused", kind=ENGINE_UNREACHABLE)
        except EngineError as inner:
            raise KeyError("verdict") from inner
    except KeyError as outer:
        assert degraded.dependency_of(outer) == ("the engine", "EngineError")


# --- The preflight: a launch whose engine failed is held in every mode ---------------


class _Slow(http.server.BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 - the stdlib's name
        time.sleep(1.0)
        self._answer()

    do_GET = do_POST  # noqa: N815 - the stdlib's name

    def _answer(self):
        try:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b"{}")
        except OSError:
            pass

    def log_message(self, *_args):
        pass


class _Garbage(_Slow):
    def do_POST(self):  # noqa: N802 - the stdlib's name
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(b"<html>holding page</html>")

    do_GET = do_POST  # noqa: N815 - the stdlib's name


@pytest.fixture()
def engine_at():
    servers = []

    def start(handler):
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
        server.daemon_threads = True
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
        return f"http://127.0.0.1:{server.server_address[1]}"

    yield start
    for server in servers:
        server.shutdown()
        server.server_close()


def _engine(fault, engine_at):
    """A real client whose engine raises (nothing listening), hangs past its read
    timeout, or answers a page that is not JSON."""
    from ai_engine.services.cyberengine_client import CyberEngineClient

    if fault == "raises":
        import socket

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        sock.close()
        return CyberEngineClient(f"http://127.0.0.1:{port}", "k")
    return CyberEngineClient(engine_at(_Slow if fault == "hangs" else _Garbage), "k")


@pytest.mark.django_db
@pytest.mark.parametrize("gate_mode", ["observe", "enforce"])
@pytest.mark.parametrize("fault", ["raises", "hangs", "malformed"])
def test_a_launch_whose_engine_failed_is_held_in_every_mode(admin, engine_at, fault, gate_mode):
    from datetime import timedelta

    from django.utils import timezone

    from ai_engine.services import cyberengine_client, preflight
    from pentest.models import Engagement, PentestScan

    now = timezone.now()
    engagement = Engagement.objects.create(
        created_by=admin, name="G14", status="running", scope_hosts=["client.example"],
        testing_window_start=now - timedelta(hours=1), testing_window_end=now + timedelta(hours=1),
    )
    client = _engine(fault, engine_at)
    preflight.clear_cache()
    api = APIClient(raise_request_exception=False)
    api.force_authenticate(user=admin)
    started = time.monotonic()
    with mock.patch("pentest.views.target_is_out_of_bounds", return_value=None), \
            mock.patch("pentest.views.CyberEngineClient") as factory, \
            mock.patch.object(cyberengine_client, "ENGINE_TIMEOUT", (0.3, 0.3)), \
            mock.patch.object(preflight, "mode", return_value=gate_mode), \
            mock.patch.object(type(client), "run_scan", side_effect=AssertionError("launched")) as run:
        factory.from_settings.return_value = client
        response = api.post(
            "/api/pentest/scan/",
            {"url": "https://client.example/", "consent": True, "engagement_id": engagement.pk},
            format="json",
        )
    preflight.clear_cache()
    assert time.monotonic() - started < 10
    assert response.status_code == 409, response.content
    body = response.json()
    assert body["error"].startswith("This engine is not the deployment that was approved: held, not launched")
    assert body["assurance"]["verdict"] == "unknown"
    assert not run.called
    assert not PentestScan.objects.exists()


@pytest.mark.django_db
def test_a_resend_whose_engine_failed_is_held_in_observe(admin):
    from ai_engine.services import preflight
    from ai_engine.services.cyberengine_client import ENGINE_UNREACHABLE, EngineError
    from pentest.models import PentestScan

    scan = PentestScan.objects.create(
        uuid=uuid.uuid4(), user=admin, target_url="https://client.example/", consent=True,
        status=PentestScan.STATUS_UNKNOWN,
    )
    engine = mock.Mock()
    engine.assurance_check.side_effect = EngineError("connection refused", kind=ENGINE_UNREACHABLE)
    preflight.clear_cache()
    api = APIClient(raise_request_exception=False)
    api.force_authenticate(user=admin)
    with mock.patch("pentest.views.still_authorised", return_value=True), \
            mock.patch("pentest.views.target_is_out_of_bounds", return_value=None), \
            mock.patch("pentest.views.CyberEngineClient") as factory, \
            mock.patch.object(preflight, "mode", return_value="observe"):
        factory.from_settings.return_value = engine
        response = api.post(f"/api/pentest/scans/{scan.uuid}/reconcile/", {}, format="json")
    preflight.clear_cache()
    assert response.status_code == 409, response.content
    assert not engine.run_scan.called
    scan.refresh_from_db()
    assert scan.status == PentestScan.STATUS_UNKNOWN


def test_a_cached_unknown_still_holds():
    from ai_engine.services import preflight

    preflight.clear_cache()
    preflight._store("default", {"verdict": "unknown", "detail": "the engine could not be asked", "mode": "observe"},
                     time.monotonic())
    try:
        with pytest.raises(preflight.DeploymentNotApproved, match="held, not launched"):
            preflight.check(mock.Mock())
    finally:
        preflight.clear_cache()


def test_a_blocked_verdict_under_observe_still_proceeds():
    """Observe keeps its meaning for an answer the gate could read: this lane changes
    what a FAILED dependency does, not the observe mode (a later lane's)."""
    from ai_engine.services import preflight

    preflight._raise_if_enforcing({"verdict": "blocked", "detail": "x", "mode": "observe"})


# --- The defender: a garbage answer is not "nothing detected" -------------------------


@pytest.mark.django_db
@pytest.mark.parametrize("answer", [{}, {"alerts": None}, {"alerts": "none"}, {"error": "upstream"}])
def test_a_defender_answer_with_no_alerts_list_is_not_a_clean_verdict(admin, answer):
    from detection.models import ThreatDetection

    api = APIClient(raise_request_exception=False)
    api.force_authenticate(user=admin)
    with mock.patch("detection.views.CyberEngineClient") as factory:
        factory.from_settings.return_value.defend_log_text.return_value = answer
        response = api.post("/api/detection/defender/text/", {"content": "GET /"}, format="json")
    assert response.status_code == 502, response.content
    assert response.json()["status"] == core_status.AUDIT_INCOMPLETE
    assert not ThreatDetection.objects.exists()


@pytest.mark.django_db
def test_a_defender_answer_in_its_contract_is_recorded(admin):
    from detection.models import ThreatDetection

    api = APIClient(raise_request_exception=False)
    api.force_authenticate(user=admin)
    with mock.patch("detection.views.CyberEngineClient") as factory:
        factory.from_settings.return_value.defend_log_text.return_value = {"alerts": []}
        response = api.post("/api/detection/defender/text/", {"content": "GET /"}, format="json")
    assert response.status_code == 201
    assert response.json()["detected"] is False
    assert ThreatDetection.objects.count() == 1
