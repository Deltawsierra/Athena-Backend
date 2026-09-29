"""A scan launch whose engine answer was lost reads UNKNOWN, never FAILED (#363).

P3.8: a timeout after the commit never resolves to FAILED -- which licenses a second
launch of a scan that may be running -- nor to started. athena-backend #113 found
that a scan launch whose engine answer was lost was recorded FAILED, and tests pinned
it. athena-engine #77 (main 79ba4af) honours an Idempotency-Key on POST /api/scan:
the same key and request again is answered with the FIRST launch's answer, marked
``Idempotent-Replayed: true``, naming its run, and starts nothing; the key held with
no answer recorded is 409; the key held for another request is 422; and admission
(the failsafe, the scope, the operator key) runs BEFORE the key is read, so a stopped
engine refuses a resend as it refuses a launch, and records nothing under the key.

The engine here is a real HTTP server on 127.0.0.1 (:class:`Engine`) that answers
this backend as athena-engine at 79ba4af does: POST /api/scan with #77's key
semantics (engine/utils/idempotency.py ``_claim``/``_given_instead``), the run's
record at GET /api/scans/{run_id}, and a stop by the run's id at
POST /api/scans/{run_id}/abort -- in the shapes athena-engine itself answers
(tests/fixtures/engine_launch/pr71-f4610ae, generated from the real app). The
backend's own client talks to it over real sockets, so every transport failure below
is the exception ``requests`` really raises. The error map this file holds:

    what happened to the launch                          the scan reads
    ---------------------------------------------------  -----------------------------
    connection refused; the name did not resolve         FAILED: certainly not sent
    the connection closed after the request was written  UNKNOWN
    the read timed out after the request was written     UNKNOWN
    a 502 or 504 (a gateway's), a 5xx the engine did     UNKNOWN
      not write (a bare "Internal Server Error")
    a 503 the engine wrote (not admitted)                FAILED: refused, nothing started

and the reconcile's (``POST /api/pentest/scans/<uuid>/reconcile/``): the replayed
answer's run adopted; 409 still UNKNOWN; a new launch's answer the first and only
run; a refusal before the key (the engine paused) still UNKNOWN, naming it; the
engine unreachable still UNKNOWN. And a scan's Stop
(``POST /api/pentest/scans/<uuid>/stop/``): never dropped, owed while the run cannot
be named or the engine reached, and sent to exactly that run once it is named.
"""

from __future__ import annotations

import ast
import copy
import json
import socket
import threading
import time
import uuid
from datetime import timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection
from django.utils import timezone
from rest_framework.test import APIClient, APIRequestFactory, force_authenticate

from ai_engine.services import cyberengine_client as cec
from pentest.models import Engagement, PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
RECORDING = REPO / "tests" / "fixtures" / "engine_launch" / "pr71-f4610ae" / "scan-running-then-completed.json"

TARGET = "https://offline.invalid/"
SCAN_URL = "/api/pentest/scan/"
UNKNOWN = "unknown"
#: How long the engine holds an answer it will never send, against the client's read
#: timeout below.
STALL_SECONDS = 5.0


def _recorded():
    """athena-engine's own answers (#71, f4610ae): its 202 to a scan launch, and the
    run's record once it completed."""
    exchanges = json.loads(RECORDING.read_text())["exchanges"]
    launch = next(e for e in exchanges if e["request"]["method"] == "POST" and e["request"]["path"] == "/api/scan")
    reads = [e for e in exchanges if e["request"]["method"] == "GET" and e["request"]["path"].startswith("/api/scans/")
             and e["request"]["path"] != "/api/scans/active"]
    return launch["body"], reads[-1]["body"]


ACCEPTED, COMPLETED = _recorded()


def _now():
    return timezone.now().isoformat()


class Engine:
    """athena-engine at 79ba4af as this backend reaches it, over real HTTP.

    ``modes`` says how the next launches are answered, first first:

    * ``"running"`` (the default): admitted, a run registered, 202 naming it;
    * ``"lost-reset"``: the same -- the run registered and the answer recorded under
      the key -- and then the connection closes before a byte of the answer is sent;
    * ``"lost-stall"``: the same, and the answer is held past the client's read
      timeout, then never sent;
    * ``"gateway-504"``: the same, and a gateway answers 504 in the engine's place;
    * ``"raise-after-register"``: the run registered, and the route raised before it
      recorded an answer: #77 records the key ``unknown`` and FastAPI answers a bare
      500;
    * ``"gateway-502-before-engine"``: a gateway answers 502 and the engine never saw
      the request: nothing registered, nothing recorded under the key.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.runs = {}
        self.keys = {}
        self.launches = []
        self.requests = []
        self.modes = []
        self.paused = False
        self.finish_on_read = True
        self.before_answer = None
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self.server.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()

    # -- what the engine was sent ---------------------------------------------------

    def aborts(self):
        return [path for method, path, _ in self.requests if method == "POST" and "abort" in path]

    def launch_keys(self):
        return [key for key, _ in self.launches]

    # -- the routes -------------------------------------------------------------------

    def _handler(engine):  # noqa: N805 - the handler class closes over the engine
        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def read_body(self):
                length = int(self.headers.get("Content-Length") or 0)
                raw = self.rfile.read(length) if length else b""
                return json.loads(raw) if raw else None

            def answer(self, status, body=None, *, headers=None, text=None, content_type="application/json"):
                payload = (text if text is not None else json.dumps(body)).encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(payload)))
                for name, value in (headers or {}).items():
                    self.send_header(name, value)
                self.end_headers()
                self.wfile.write(payload)

            def do_GET(self):
                with engine.lock:
                    engine.requests.append(("GET", self.path, dict(self.headers)))
                engine.read_run(self)

            def do_POST(self):
                body = self.read_body()
                with engine.lock:
                    engine.requests.append(("POST", self.path, dict(self.headers)))
                if self.path == "/defend":
                    return self.answer(200, {"allow": True, "action": "allow"})
                if self.path.startswith("/api/scans/") and self.path.endswith("/abort"):
                    return engine.abort(self, body)
                if self.path == "/api/scan":
                    return engine.launch(self, body)
                return self.answer(404, {"detail": "Not Found"})

        return Handler

    def launch(self, h, body):
        key = h.headers.get("Idempotency-Key")
        with self.lock:
            self.launches.append((key, body))
            mode = self.modes.pop(0) if self.modes else "running"
        if mode == "gateway-502-before-engine":
            return h.answer(502, text="<html><body><h1>502 Bad Gateway</h1></body></html>", content_type="text/html")
        # Admission first, a repeat included: a paused engine refuses before it reads
        # the key, and nothing is recorded under it (#77; api/server.py _failsafe_gate).
        if self.paused:
            return h.answer(409, {"detail": "the engine is paused; not accepting new work"})
        digest = json.dumps(body, sort_keys=True)
        with self.lock:
            held = self.keys.get(key) if key is not None else None
            if held is None and key is not None:
                self.keys[key] = {"digest": digest, "state": "in_flight", "since": _now()}
        if held is not None:
            record = {"state": held["state"], "since": held["since"]}
            if held["digest"] != digest:
                return h.answer(422, {
                    "detail": "This Idempotency-Key was already used on this route by this operator key for a "
                              "different request. Nothing was done: send a new request with a new key.",
                    "idempotency": record})
            if held["state"] == "done":
                return h.answer(held["status"], held["body"], headers={"Idempotent-Replayed": "true"})
            return h.answer(409, {
                "detail": "The first request with this Idempotency-Key has no answer recorded: it is still "
                          "running, or it stopped before it could record one, so its outcome is unknown. "
                          "Nothing was started by this one.",
                "idempotency": record})

        run_id = str(uuid.uuid4())
        with self.lock:
            self.runs[run_id] = {
                "run_id": run_id, "kind": "scan", "target": (body or {}).get("target"), "state": "running",
                "done": False, "reason": None, "result": None, "started_at": _now(), "finished_at": None,
                "updated_at": _now(), "key_hash": "operator-key-hash",
            }
        if self.before_answer is not None:
            self.before_answer(run_id)
        if mode == "raise-after-register":
            with self.lock:
                if key is not None:
                    self.keys[key]["state"] = "unknown"
            return h.answer(500, text="Internal Server Error", content_type="text/plain")
        accepted = dict(ACCEPTED, run_id=run_id, status_url=f"/api/scans/{run_id}")
        with self.lock:
            if key is not None:
                self.keys[key].update(state="done", status=202, body=accepted)
        if mode == "lost-reset":
            return None  # the answer is never written: the connection closes
        if mode == "lost-stall":
            time.sleep(STALL_SECONDS)
            return None
        if mode == "gateway-504":
            return h.answer(504, text="upstream request timeout", content_type="text/plain")
        return h.answer(202, accepted)

    def read_run(self, h):
        run_id = h.path.removeprefix("/api/scans/")
        with self.lock:
            run = self.runs.get(run_id)
            if run is not None and run["state"] == "running" and self.finish_on_read:
                run.update(state="completed", done=True, result=copy.deepcopy(COMPLETED["result"]),
                           finished_at=_now(), updated_at=_now())
            record = copy.deepcopy(run)
        if record is None:
            return h.answer(404, {"detail": "No such scan run"})
        return h.answer(200, record)

    def abort(self, h, body):
        run_id = h.path.removeprefix("/api/scans/").removesuffix("/abort")
        reason = (body or {}).get("reason") or "stopped by an operator"
        with self.lock:
            run = self.runs.get(run_id)
            if run is None:
                answer = (404, {"detail": "No such scan run"})
            elif run["done"]:
                answer = (200, {"run_id": run_id, "state": run["state"], "detail": "not running"})
            else:
                # The work notices the stop at once here.
                run.update(state="aborted", done=True, reason=reason,
                           result={"stopped": True, "scan_incomplete": True}, finished_at=_now())
                answer = (200, {"run_id": run_id, "state": "aborting", "reason": reason, "recorded": True})
        return h.answer(*answer)


def _closed_port_url():
    """A URL on 127.0.0.1 where nothing listens: a connection to it is refused."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    return f"http://127.0.0.1:{port}"


@pytest.fixture()
def engine(settings, monkeypatch):
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "127.0.0.1,localhost,.invalid")
    served = Engine()
    settings.CYBERENGINE_URL = served.base
    settings.CYBERENGINE_OPERATOR_KEY = "operator-key-for-this-test"
    monkeypatch.setattr(cec, "SCAN_POLL_SECONDS", 0)
    monkeypatch.setattr(cec, "SCAN_COLLECT_SECONDS", 5)
    monkeypatch.setattr(cec, "ENGINE_TIMEOUT", (2.0, 3.0))
    monkeypatch.setattr("pentest.views.target_is_out_of_bounds", lambda url: None)
    monkeypatch.setattr("pentest.views.preflight.check", lambda client, tenant_id=None: {"verdict": "unchanged"})
    monkeypatch.setattr("pentest.views.render_scan_pdf_bytes", lambda scan: b"%PDF-1.4 report")
    monkeypatch.setattr("pentest.views.save_pdf_to_scan", lambda scan, pdf: None)
    yield served
    served.close()


def _analyst():
    return User.objects.create_user(username=f"a-{uuid.uuid4().hex[:10]}", password=None, role=User.Roles.ANALYST)


def _client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _engagement(user, **over):
    now = timezone.now()
    values = {
        "created_by": user, "name": "Client Q3", "status": "running", "scope_hosts": ["offline.invalid"],
        "testing_window_start": now - timedelta(hours=1), "testing_window_end": now + timedelta(hours=1),
    }
    values.update(over)
    return Engagement.objects.create(**values)


def _launch(client, engagement):
    response = client.post(SCAN_URL, {"url": TARGET, "consent": True, "engagement_id": engagement.pk}, format="json")
    return response, PentestScan.objects.get(uuid=response.json()["scan_id"])


def _reconcile(client, scan):
    return client.post(f"/api/pentest/scans/{scan.uuid}/reconcile/", format="json")


def _stop(client, scan):
    return client.post(f"/api/pentest/scans/{scan.uuid}/stop/", {}, format="json")


def _lost_launch(engine, mode="lost-reset"):
    """A scan launched against an engine that registered its run and lost the answer."""
    analyst = _analyst()
    client = _client(analyst)
    engine.modes.append(mode)
    response, scan = _launch(client, _engagement(analyst))
    return client, response, scan


# ===========================================================================
# 1. A lost answer is UNKNOWN; certainly not sent is FAILED
# ===========================================================================


@pytest.mark.parametrize("mode, raised", [
    ("lost-reset", "ConnectionError"),
    ("lost-stall", "ReadTimeout"),
])
def test_a_launch_whose_answer_was_lost_after_the_engine_committed_it_reads_unknown_not_failed(engine, mode, raised):
    """The engine registered the run -- it is scanning the customer -- and its answer
    never arrived. It was recorded FAILED: a scan read as over while it ran, and a
    second launch licensed. It is UNKNOWN, with the reason, and the launch carried the
    scan's own key."""
    _client_, response, scan = _lost_launch(engine, mode)

    assert len(engine.runs) == 1, "the engine did not commit the run this test is about"
    assert response.status_code == 202, response.content
    assert response.json()["status"] == UNKNOWN
    assert scan.status == UNKNOWN
    assert raised in scan.error_message
    assert "may have started a run" in scan.error_message
    assert scan.engine_run_id is None
    (key,) = engine.launch_keys()
    assert key and str(scan.uuid) in key


@pytest.mark.parametrize("mode", ["gateway-504", "raise-after-register"])
def test_a_5xx_carrying_nothing_the_engine_wrote_reads_unknown(engine, mode):
    """A gateway's 504 after the engine committed the run, and the bare 500 FastAPI
    answers when the route raised after registering it: neither is an answer the
    engine wrote, and the run may be scanning. They were recorded FAILED ("refused")."""
    _client_, response, scan = _lost_launch(engine, mode)

    assert len(engine.runs) == 1
    assert response.status_code == 202, response.content
    assert scan.status == UNKNOWN
    assert "nothing the engine wrote" in scan.error_message


@pytest.mark.parametrize("where", ["refused", "unresolvable"])
def test_a_launch_that_certainly_never_reached_the_engine_stays_failed(engine, settings, where):
    """The connection was never made -- refused, or the engine's name did not resolve:
    nothing was sent, nothing can be running. FAILED, as it always was."""
    settings.CYBERENGINE_URL = _closed_port_url() if where == "refused" else "http://engine.invalid:9"
    analyst = _analyst()

    response, scan = _launch(_client(analyst), _engagement(analyst))

    assert response.status_code == 502, response.content
    assert scan.status == PentestScan.STATUS_FAILED
    assert "Engine unreachable" in scan.error_message
    assert engine.launches == []


def test_a_503_the_engine_wrote_is_a_refusal_that_started_nothing(engine, monkeypatch):
    """The control for the 5xx rule: #71's own 503 -- not admitted, said in its JSON --
    started nothing, and stays the refusal it was."""
    fx = json.loads((RECORDING.parent / "scan-not-admitted.json").read_text())
    (refusal,) = [e for e in fx["exchanges"] if e["request"]["path"] == "/api/scan"]

    def not_admitted(h, body):
        with engine.lock:
            engine.launches.append((h.headers.get("Idempotency-Key"), body))
        return h.answer(refusal["status"], refusal["body"], headers={"Retry-After": "5"})

    monkeypatch.setattr(engine, "launch", not_admitted)
    analyst = _analyst()
    response, scan = _launch(_client(analyst), _engagement(analyst))

    assert response.status_code == 502, response.content
    assert scan.status == PentestScan.STATUS_FAILED
    assert engine.runs == {}


# ===========================================================================
# 2. The reconcile: the same launch, the same key -- never a second scan
# ===========================================================================


def test_the_reconcile_adopts_the_run_the_engine_started_and_scans_nothing_more(engine):
    """The engine replays the first launch's answer: its run is adopted, collected,
    and the scan completes with its findings. Two sends of the launch, one key, one
    run -- the customer was scanned once."""
    client, _response, scan = _lost_launch(engine)
    (run_id,) = engine.runs

    reconciled = _reconcile(client, scan)

    assert reconciled.status_code == 200, reconciled.content
    scan.refresh_from_db()
    assert scan.status == PentestScan.STATUS_COMPLETED
    assert scan.engine_run_id == run_id
    assert reconciled.json()["result"] == COMPLETED["result"]
    assert len(engine.runs) == 1, "the reconcile started a second scan of the customer"
    first, resent = engine.launch_keys()
    assert first == resent
    assert engine.launches[0][1] == engine.launches[1][1], "the resend was not the same request"


def test_a_reconcile_while_the_key_is_held_with_no_answer_stays_unknown(engine):
    """The route raised after registering the run, before it recorded an answer: #77
    answers the key 409, naming no run. Still UNKNOWN, and the 409 is said -- never
    FAILED on the strength of not knowing, and never a second scan."""
    client, _response, scan = _lost_launch(engine, "raise-after-register")

    reconciled = _reconcile(client, scan)

    assert reconciled.status_code == 202, reconciled.content
    scan.refresh_from_db()
    assert scan.status == UNKNOWN
    assert "holds this launch's Idempotency-Key with no answer recorded" in scan.error_message
    assert len(engine.runs) == 1


def test_a_reconcile_the_engine_never_saw_the_first_send_of_is_the_first_and_only_run(engine):
    """A gateway answered 502 and the engine never saw the launch: nothing registered.
    The resend is a new launch to the engine, and its run is the scan's first and only."""
    client, _response, scan = _lost_launch(engine, "gateway-502-before-engine")
    assert scan.status == UNKNOWN and engine.runs == {}

    reconciled = _reconcile(client, scan)

    assert reconciled.status_code == 200, reconciled.content
    (run_id,) = engine.runs
    scan.refresh_from_db()
    assert (scan.status, scan.engine_run_id) == (PentestScan.STATUS_COMPLETED, run_id)


def test_a_reconcile_refused_before_the_key_was_read_stays_unknown_and_names_the_refusal(engine):
    """The engine was paused since: it refuses the resend before it reads the key,
    which says nothing about the first send. Still UNKNOWN, naming the refusal."""
    client, _response, scan = _lost_launch(engine)
    engine.paused = True

    reconciled = _reconcile(client, scan)

    assert reconciled.status_code == 202, reconciled.content
    scan.refresh_from_db()
    assert scan.status == UNKNOWN
    assert "409: the engine is paused; not accepting new work" in scan.error_message
    assert len(engine.runs) == 1


def test_a_reconcile_while_the_engine_cannot_be_reached_stays_unknown(engine, settings):
    client, _response, scan = _lost_launch(engine)
    settings.CYBERENGINE_URL = _closed_port_url()

    reconciled = _reconcile(client, scan)

    assert reconciled.status_code == 202, reconciled.content
    scan.refresh_from_db()
    assert scan.status == UNKNOWN
    assert "still unknown" in scan.error_message


def test_a_reconcile_under_a_withdrawn_engagement_is_not_sent(engine):
    """A resend starts the scan when the engine never saw the first: it is judged as a
    launch is, and an engagement that no longer authorises the target sends nothing."""
    client, _response, scan = _lost_launch(engine)
    Engagement.objects.filter(pk=scan.engagement_id).update(status="paused")

    reconciled = _reconcile(client, scan)

    assert reconciled.status_code == 409, reconciled.content
    assert len(engine.launches) == 1
    scan.refresh_from_db()
    assert scan.status == UNKNOWN


def test_only_a_launch_whose_answer_was_lost_is_reconciled(engine):
    analyst = _analyst()
    client = _client(analyst)
    response, scan = _launch(client, _engagement(analyst))
    assert response.status_code == 200 and scan.status == PentestScan.STATUS_COMPLETED

    assert _reconcile(client, scan).status_code == 409
    assert len(engine.launches) == 1


# ===========================================================================
# 3. The key: one per scan, on every launch of it, never on a stop
# ===========================================================================


def test_every_launch_of_a_scan_carries_its_own_key_and_no_two_scans_share_one(engine):
    analyst = _analyst()
    client = _client(analyst)
    engagement = _engagement(analyst)

    _first, one = _launch(client, engagement)
    _second, two = _launch(client, engagement)

    keys = engine.launch_keys()
    assert all(keys) and len(set(keys)) == 2
    assert str(one.uuid) in keys[0] and str(two.uuid) in keys[1]


def test_every_call_that_launches_a_scan_passes_the_scans_key():
    """Structural: no first-party call of ``run_scan`` sends a launch without a key."""
    calls = []
    skip = {"tests", "node_modules", "migrations", "__pycache__"}
    for path in REPO.rglob("*.py"):
        parts = set(path.relative_to(REPO).parts)
        if parts & skip or any(part.startswith(".") for part in parts) or "site-packages" in parts:
            continue
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Call) and getattr(node.func, "attr", None) == "run_scan":
                calls.append((path.name, node.lineno, {kw.arg for kw in node.keywords}))
    assert calls, "no launch found"
    assert [c for c in calls if "idempotency_key" not in c[2]] == []


# ===========================================================================
# 4. A scan's Stop: never dropped, never refused, sent to exactly its run
# ===========================================================================


def test_a_stop_on_an_unknown_launch_is_owed_and_sent_to_exactly_the_run_the_reconcile_names(engine):
    """The SAFETY RULE end to end. The Stop is recorded at once and owed: the run
    cannot be named, and a stop never sends a launch to learn it. The reconcile names
    the run, and the engine receives the abort for exactly that run -- never
    abort-all -- with no key. The scan ends as the stopped run it is."""
    client, _response, scan = _lost_launch(engine)
    (run_id,) = engine.runs

    stopped = _stop(client, scan)
    read = client.get(f"/api/pentest/scans/{scan.uuid}/")

    assert stopped.status_code == 202, stopped.content
    assert stopped.json()["stop"]["state"] == "owed"
    assert read.json()["stop"]["state"] == "owed"
    assert engine.aborts() == []
    assert len(engine.launches) == 1, "the stop sent a launch"

    reconciled = _reconcile(client, scan)

    assert engine.aborts() == [f"/api/scans/{run_id}/abort"]
    abort_headers = [h for m, p, h in engine.requests if p.endswith("/abort")]
    assert not any("Idempotency-Key" in h for h in abort_headers)
    assert all("abort-all" not in p for _m, p, _h in engine.requests)
    scan.refresh_from_db()
    assert scan.stop_delivered_at is not None and not scan.stop_owed
    assert scan.engine_run_id == run_id
    assert scan.status == PentestScan.STATUS_FAILED and "aborted" in scan.error_message
    assert reconciled.status_code == 502, reconciled.content
    assert len(engine.runs) == 1


def test_a_stop_while_the_engine_cannot_be_reached_is_owed_not_lost(engine, settings, monkeypatch):
    """The scan names its run, and the engine cannot be reached: the stop is recorded,
    the scan reads "stop owed", and it is delivered to that run once the engine can
    be reached -- here by manage.py deliver_owed_stops, which fails while it is owed."""
    analyst = _analyst()
    client = _client(analyst)
    engine.finish_on_read = False
    monkeypatch.setattr(cec, "SCAN_COLLECT_SECONDS", 0)
    launched, scan = _launch(client, _engagement(analyst))
    (run_id,) = engine.runs
    assert launched.status_code == 202 and scan.engine_run_id == run_id
    settings.CYBERENGINE_URL = _closed_port_url()

    stopped = _stop(client, scan)

    assert stopped.status_code == 202, stopped.content
    assert stopped.json()["stop"]["state"] == "owed"
    assert client.get(f"/api/pentest/scans/{scan.uuid}/").json()["stop"]["state"] == "owed"
    with pytest.raises(CommandError, match="still owed"):
        call_command("deliver_owed_stops")
    assert engine.aborts() == []

    settings.CYBERENGINE_URL = engine.base
    call_command("deliver_owed_stops")

    assert engine.aborts() == [f"/api/scans/{run_id}/abort"]
    assert client.get(f"/api/pentest/scans/{scan.uuid}/").json()["stop"]["state"] == "delivered"


def test_a_stop_owed_through_a_reconcile_that_could_not_reach_the_engine_is_delivered_by_the_next(engine, settings):
    client, _response, scan = _lost_launch(engine)
    (run_id,) = engine.runs
    assert _stop(client, scan).status_code == 202
    settings.CYBERENGINE_URL = _closed_port_url()

    assert _reconcile(client, scan).status_code == 202
    scan.refresh_from_db()
    assert scan.status == UNKNOWN and scan.stop_owed

    settings.CYBERENGINE_URL = engine.base
    _reconcile(client, scan)

    assert engine.aborts() == [f"/api/scans/{run_id}/abort"]
    scan.refresh_from_db()
    assert not scan.stop_owed


def test_a_stop_on_a_scan_that_ended_naming_no_run_has_nothing_to_stop(engine, settings):
    settings.CYBERENGINE_URL = _closed_port_url()
    analyst = _analyst()
    client = _client(analyst)
    _response, scan = _launch(client, _engagement(analyst))
    assert scan.status == PentestScan.STATUS_FAILED

    stopped = _stop(client, scan)

    assert stopped.status_code == 200, stopped.content
    assert stopped.json()["stop"]["state"] == "delivered"
    assert "Nothing to stop" in stopped.json()["stop"]["detail"]


@pytest.mark.django_db(transaction=True)
def test_a_stop_asked_while_the_launch_waits_is_sent_the_moment_the_engine_names_the_run(engine):
    """The Stop arrives while the launch is still waiting for the engine's answer: no
    run is named yet, so it is owed. The engine answers, naming the run, and the
    launch sends the stop to it at once -- before it collects anything."""
    analyst = _analyst()
    engagement = _engagement(analyst)
    stops = []

    def stop_arrives(run_id):
        # On the engine's own thread, while the launch waits: the operator's Stop.
        try:
            scan = PentestScan.objects.get(user=analyst)
            request = APIRequestFactory().post(f"/api/pentest/scans/{scan.uuid}/stop/", {}, format="json")
            force_authenticate(request, user=analyst)
            from pentest import views

            stops.append(views.stop_pentest_scan(request, scan_id=scan.uuid))
        finally:
            connection.close()

    engine.before_answer = stop_arrives
    engine.finish_on_read = False

    response, scan = _launch(_client(analyst), engagement)

    (run_id,) = engine.runs
    assert [s.status_code for s in stops] == [202], "the stop was not owed while the run was unnamed"
    assert engine.aborts() == [f"/api/scans/{run_id}/abort"]
    first_read = next(i for i, (m, p, _h) in enumerate(engine.requests) if m == "GET")
    first_abort = next(i for i, (m, p, _h) in enumerate(engine.requests) if p.endswith("/abort"))
    assert first_abort < first_read, "the run was collected before the owed stop was sent"
    scan.refresh_from_db()
    assert not scan.stop_owed
    assert scan.status == PentestScan.STATUS_FAILED and "aborted" in scan.error_message
    assert response.status_code == 502


# ===========================================================================
# 5. The client's error map, over real sockets
# ===========================================================================


def _client_for(url):
    return cec.CyberEngineClient(base_url=url, api_key="k")


def test_the_error_map_at_the_client(engine):
    """Each transport failure as ``requests`` raises it, read by run_scan."""
    outcomes = {}
    for label, url, mode in [
        ("connection refused", _closed_port_url(), None),
        ("name not resolved", "http://engine.invalid:9", None),
        ("closed after the request was written", engine.base, "lost-reset"),
        ("read timed out after the request was written", engine.base, "lost-stall"),
        ("a gateway's 504", engine.base, "gateway-504"),
        ("a bare 500", engine.base, "raise-after-register"),
        ("a gateway's 502, the engine never saw it", engine.base, "gateway-502-before-engine"),
    ]:
        if mode:
            engine.modes.append(mode)
        with pytest.raises(cec.EngineError) as raised:
            _client_for(url).run_scan(TARGET, engagement_ref="42", idempotency_key=f"key-{label}")
        outcomes[label] = raised.value.kind

    assert outcomes == {
        "connection refused": "unreachable",
        "name not resolved": "unreachable",
        "closed after the request was written": "outcome_unknown",
        "read timed out after the request was written": "outcome_unknown",
        "a gateway's 504": "outcome_unknown",
        "a bare 500": "outcome_unknown",
        "a gateway's 502, the engine never saw it": "outcome_unknown",
    }


def test_only_the_engines_own_404_says_a_stop_has_no_run_to_stop(engine):
    """A 404 the engine wrote ("No such scan run") closes a stop: nothing runs under
    that id. A 404 anything else wrote -- a gateway in front of the wrong path -- says
    nothing about the run, and the stop stays owed rather than claiming a containment."""
    said = _client_for(engine.base).abort_scan("no-such-run")
    assert said["stopped"] is False and "has no run" in said["detail"]

    with pytest.raises(cec.EngineError):
        _client_for(engine.base + "/not-the-engine").abort_scan("run-1")


def test_a_connect_that_timed_out_or_a_proxy_never_reached_is_not_sent_and_a_tls_failure_may_have_been():
    """The shapes a live network is needed for, as requests builds them."""
    import requests
    from urllib3.exceptions import ConnectTimeoutError, MaxRetryError, NewConnectionError, ProxyError, SSLError

    def wrapped(reason, cls=requests.exceptions.ConnectionError):
        return cls(MaxRetryError(None, "/api/scan", reason))

    never = getattr(cec, "_never_reached_the_engine", None)
    assert never is not None, "the client cannot tell a launch that was never sent from one that may have been"
    assert never(wrapped(ConnectTimeoutError(None, "connect timed out"), requests.exceptions.ConnectTimeout))
    assert never(wrapped(ProxyError("Unable to connect to proxy", NewConnectionError(None, "refused")),
                         requests.exceptions.ProxyError))
    assert not never(wrapped(SSLError("EOF occurred in violation of protocol"), requests.exceptions.SSLError))
    assert not never(requests.exceptions.ReadTimeout("read timed out"))
    assert not never(requests.exceptions.ChunkedEncodingError("the body broke off"))
