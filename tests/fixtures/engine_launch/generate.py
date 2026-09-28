"""Regenerate the engine launch fixtures by driving the real engine app.

Every JSON file beside this script is an exchange the athena-engine FastAPI app
itself answered, through FastAPI's TestClient, at a named commit, to the request
THIS backend sends. Nothing in them is written by hand: the backend's engine
client (ai_engine/services/cyberengine_client.py) and its preflight gate
(ai_engine/services/preflight.py) are tested against what the engine sends, not
against what somebody expected it to send.

Two engine commits are recorded, one directory each:

  pr71-f4610ae/  athena-engine PR #71 head f4610ae03b6abacf4108990c953462fbf1880950
                 (every launch answers with `answer`; a 202 is a status, never
                 a result; a failure after registration is a 500 status that
                 still names the run; a retest's `run_id` is the abort-registry
                 id and `scan_record_id` the record; a stop that lands while a
                 retest's check is filed is answered with that verdict, `state:
                 "aborted"` and `stopped_after_recording`; an attestation answers
                 2xx only with a measured verdict)
  main-5779e99/  athena-engine main 5779e99eae1085f96e6c27ce28dbd950d8200aba
                 (no `answer` field anywhere; the retest answers its verdict
                 synchronously and its `run_id` is the scan record id)

The requests are the backend's own, field for field:

  POST /api/scan               {"target", "wait_seconds": 20.0, "engagement_ref"}
                               (CyberEngineClient.run_scan; SCAN_INLINE_WAIT_SECONDS)
  POST /api/remediation/retest {"twin_id", "engagement_ref", "scope"}
                               (CyberEngineClient.retest_finding; no wait_seconds,
                               which engine main refuses)
  POST /api/attestation/check  {"name", "url"}
                               (CyberEngineClient.attestation_check, from preflight)

and the collection reads are `GET /api/scans/{run_id}`, as collect_scan and
retest_status make them.

They were generated, at both commits, with the mythos-core installed on the
machine that ran this script ("unpinned local core"), not the one the engine's
requirements.txt pins: see `mythos_core` in each file.

Usage, from a checkout (or worktree) of athena-engine at one of those commits,
with its dependencies and mythos-core importable:

    python -B <this script> <engine checkout> <output directory>

The script refuses any other commit and a checkout with uncommitted changes, so
a fixture directory always says which engine produced it. Each file carries the
engine sha it was generated from.

What is real and what is a stand-in
-----------------------------------
Real: the engine's routes, request validation, job pool, abort registry,
decision-twin capture, retest runner and remediation record, the attestation
store's comparison and recording, and every response body and status code.

Stand-ins, so that nothing leaves the machine:

  * `engine.run_scan` is replaced by a function that sends nothing and returns
    a scan result for the offline target `https://offline.invalid/`. It holds
    until released or stopped where a scenario needs a run in flight, and
    raises where a scenario needs a scan that failed.
  * `engine.extension_review` is a review with nothing unapproved, which is what
    lets the retest runner reach `closed`.
  * `engine.attestation.route.observe` -- the TLS measurement -- returns the
    facts of an offline endpoint instead of resolving or connecting, holding
    (and honouring a stop) where a scenario needs an attestation in flight. The
    unobservable attestation needs no stand-in: its URL is one no reader can
    parse, which the engine refuses before it resolves anything.
  * Where a scenario needs a failure the engine's own contract test arranges
    the same way (tests/test_every_launch_answers_with_a_run_id_it_can_stop.py
    at f4610ae): a registry read that answers "database is locked", a pool
    hand-over that raises, or a run that ends just before the route reads its
    state (`finished-before-the-answer`: the route's own inline wait is made to
    return "not yet" once the run has ended, which is the race at the end of
    the 20 s wait the backend asks for).

Run ids, timestamps, key hashes and digests differ on every run; the tests
read them from the files rather than assuming them.
"""

from __future__ import annotations

import importlib
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

KNOWN = {
    "f4610ae03b6abacf4108990c953462fbf1880950": "pr71-f4610ae",
    "5779e99eae1085f96e6c27ce28dbd950d8200aba": "main-5779e99",
}

TARGET = "https://offline.invalid/"
ENDPOINT = "https://offline.invalid/search"
ENGAGEMENT = "42"
SCOPE = ["offline.invalid"]
RAW_KEY = "operator-key-fixture"

# CyberEngineClient.run_scan's payload, as it sends it.
SCAN_WAIT = 20.0

ROUTE_NAME = "gateway"
ROUTE_URL = "https://offline.invalid/v1/chat"
UNPARSEABLE_URL = "http://[abc/v1/chat"


def wait_until(pred, seconds=15.0):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if pred():
            return True
        time.sleep(0.02)
    return False


class Engine:
    """A fresh engine app on its own temporary database."""

    def __init__(self, workers=4, queued=16):
        tmp = tempfile.mkdtemp(prefix="engine-launch-fixture-")
        os.environ["ENGINE_DB_PATH"] = os.path.join(tmp, "engine.db")
        import mythos_core.db as db
        importlib.reload(db)
        db.init_db()
        import engine.utils.runs as runs
        import engine.utils.jobs as jobs
        import engine.utils.auth as auth
        importlib.reload(runs)
        importlib.reload(jobs)
        importlib.reload(auth)
        db.add_api_key(auth._hash_key(RAW_KEY), "operator", client_name="fixture")
        import api.server as server
        importlib.reload(server)
        jobs.reset_pool(max_workers=workers, max_queued=queued)
        from fastapi.testclient import TestClient
        self.server, self.runs, self.jobs, self.auth = server, runs, jobs, auth
        self.http = TestClient(server.app)
        self.headers = {"X-API-Key": RAW_KEY}
        self.key_hash = auth._hash_key(RAW_KEY)
        server.engine.extension_review = {"counts": {"ok": 1}, "extensions": []}
        import engine.attestation.route as route
        self.route = route
        self.real_observe = route.observe
        self.exchanges: list[dict] = []

    def call(self, method, path, body=None, keep_headers=()):
        response = self.http.request(method, path, json=body, headers=self.headers)
        try:
            payload = response.json()
        except ValueError:
            payload = response.text
        exchange = {
            "request": {"method": method, "path": path, **({"body": body} if body is not None else {})},
            "status": response.status_code,
            "body": payload,
        }
        kept = {name: response.headers[name] for name in keep_headers if name in response.headers}
        if kept:
            exchange["headers"] = kept
        return exchange

    def record(self, exchange, note):
        self.exchanges.append({"note": note, **exchange})
        return exchange

    def twin(self, scan_run_id):
        """A real decision twin, captured as a scan captures one."""
        from engine import scan_auth
        from engine.replay import twin
        tenant = self.server.resolve_tenant(self.key_hash, None)
        return twin.capture(
            {"endpoint": ENDPOINT, "details": "Reflected input on /search"},
            {"type": "xss", "severity": "high", "tier": "confirmed", "confidence": 0.9},
            run_id=scan_run_id, target=TARGET, tenant=tenant,
            scan_auth=scan_auth.context(False, []),
        )

    def live(self, kind):
        return [one for one in self.runs.active() if one["kind"] == kind]

    def close(self):
        self.route.observe = self.real_observe
        self.jobs.drain(15)


def scan_result(kind, scan_id):
    """What the stand-in run_scan returns: a scan of the offline target."""
    from engine import scan_auth
    coverage = {
        "checks": [{"check": "xss", "state": "performed", "probes_attempted": 4, "probes_failed": 0}],
        "not_performed": [], "degraded": [], "unmeasured": [],
    }
    if kind == "closed":
        return {"scan_id": scan_id, "results": [], "coverage": coverage, "auth": scan_auth.context(False, [])}
    if kind == "still_open":
        return {
            "scan_id": scan_id,
            "results": [{"type": "xss", "severity": "high", "message": "Reflected input on /search", "endpoint": ENDPOINT}],
            "coverage": coverage, "auth": scan_auth.context(False, []),
        }
    raise ValueError(kind)


def stand_in(E, kind, scan_id, release=None, started=None, raises=None):
    """A run_scan that sends nothing, holds until released or stopped, then returns."""
    def run_scan(target, **kw):
        run_id = kw.get("run_id")
        if started is not None:
            started.set()
        if release is not None:
            while not release.is_set():
                if run_id and E.runs.abort_reason(run_id):
                    # A scan that was stopped returns what it had: nothing.
                    return {"scan_id": scan_id, "results": []}
                time.sleep(0.02)
        if raises:
            raise RuntimeError(raises)
        return scan_result(kind, scan_id)
    return run_scan


def offline_facts(url):
    """The facts route.observe records for an HTTPS endpoint, for the offline target."""
    return {
        "host": "offline.invalid", "port": 443, "scheme": "https",
        "addresses": ["192.0.2.10"], "address": "192.0.2.10",
        "encrypted": True,
        "certificate": "sha256:" + "ab" * 32,
        "issuer": [["commonName", "Offline Test CA"], ["organizationName", "Offline"]],
        "subject_names": ["offline.invalid"],
        "not_before": "Jan  1 00:00:00 2026 GMT",
        "not_after": "Jan  1 00:00:00 2036 GMT",
        "tls_version": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "alpn": None,
    }


def observe_stand_in(release=None, started=None):
    """route.observe without a socket: the offline endpoint's facts."""
    from mythos_core.http import safe_http

    def observe(url, timeout=None):
        if started is not None:
            started.set()
        if release is not None:
            while not release.is_set():
                stopped = safe_http.stop_requested()
                if stopped:
                    raise safe_http.ScanStopped(stopped)
                time.sleep(0.02)
        return offline_facts(url)
    return observe


def scan_body():
    body = {"target": TARGET, "wait_seconds": SCAN_WAIT, "engagement_ref": ENGAGEMENT}
    return body


def retest_body(twin_id):
    return {"twin_id": twin_id, "engagement_ref": ENGAGEMENT, "scope": SCOPE}


def attest_body(url=ROUTE_URL):
    return {"name": ROUTE_NAME, "url": url}


def setup_twin(E):
    """The scan whose finding a retest retests, and its decision twin."""
    E.server.engine.run_scan = stand_in(E, "still_open", 400)
    scan = E.record(E.call("POST", "/api/scan", scan_body()),
                    "setup: the scan that found the finding (answered finished inside the 20 s wait)")
    return E.twin(scan["body"]["run_id"])


def locked(*args, **kwargs):
    raise sqlite3.OperationalError("database is locked")


def mythos_core_provenance(checkout):
    """The mythos-core imported, by commit when it is a git checkout, and the engine's pin."""
    import mythos_core
    where = Path(mythos_core.__file__).resolve().parent
    found = subprocess.run(["git", "-C", str(where), "rev-parse", "HEAD"], capture_output=True, text=True)
    pinned = None
    for line in (checkout / "requirements.txt").read_text().splitlines():
        if line.startswith("mythos-core @"):
            pinned = line.rsplit("@", 1)[-1].strip()
    imported = found.stdout.strip() if found.returncode == 0 else None
    return {
        "imported_commit": imported,
        "pinned_by_requirements": pinned,
        # Said in words, so nobody reads these as a pinned-core run.
        "label": "pinned core" if imported is not None and imported == pinned else "unpinned local core",
    }


MYTHOS_CORE: dict = {}


def scenario(name, contract, engine_sha, fn, out, **pool):
    E = Engine(**pool)
    try:
        fn(E)
    finally:
        E.close()
    path = out / f"{name}.json"
    path.write_text(json.dumps({
        "engine": {"repository": "athena-engine", "sha": engine_sha, "contract": contract},
        "mythos_core": MYTHOS_CORE,
        "generated_by": "tests/fixtures/engine_launch/generate.py",
        "scenario": name,
        "exchanges": E.exchanges,
    }, indent=2, sort_keys=False) + "\n")
    print("wrote", path)


# -------------------------------------------------------------- scans -----

def scan_finished_inline(E):
    E.server.engine.run_scan = stand_in(E, "still_open", 700)
    E.record(E.call("POST", "/api/scan", scan_body()),
             "the scan, finished inside the 20 s wait the backend asks for: 200 with the finished run")


def scan_running_then_completed(E):
    release, started = threading.Event(), threading.Event()
    E.server.engine.run_scan = stand_in(E, "still_open", 701, release=release, started=started)
    answer = E.record(E.call("POST", "/api/scan", scan_body()),
                      "the scan, still running when the 20 s wait ended: 202")
    run_id = answer["body"]["run_id"]
    E.record(E.call("GET", f"/api/scans/{run_id}"), "its status read while it runs")
    release.set()
    wait_until(lambda: E.runs.get(run_id)["state"] == E.runs.COMPLETED)
    E.record(E.call("GET", f"/api/scans/{run_id}"), "its status read once it finished: the findings are under result")


def scan_finished_before_the_answer(E):
    """The run ends after the route's inline wait gave up and before it read the state."""
    E.server.engine.run_scan = stand_in(E, "still_open", 702)
    real = E.server._await_run
    ended = (E.runs.COMPLETED, E.runs.FAILED, E.runs.ABORTED)

    def await_run(run_id, seconds):
        wait_until(lambda: E.runs.get(run_id)["state"] in ended)
        return None

    E.server._await_run = await_run
    try:
        answer = E.record(E.call("POST", "/api/scan", scan_body()),
                          "the scan, which ended between the end of the route's inline wait and its state read: "
                          "202 whose state already reads completed, and no result in it")
    finally:
        E.server._await_run = real
    E.record(E.call("GET", f"/api/scans/{answer['body']['run_id']}"),
             "its status read: the findings the 202 did not carry")


def scan_stopped_while_waiting(E):
    release, started = threading.Event(), threading.Event()
    E.server.engine.run_scan = stand_in(E, "still_open", 703, release=release, started=started)
    holder = {}

    def launch():
        holder["answer"] = E.call("POST", "/api/scan", scan_body())

    thread = threading.Thread(target=launch)
    thread.start()
    started.wait(10)
    run_id = E.live("scan")[0]["run_id"]
    stop = E.call("POST", f"/api/scans/{run_id}/abort", {})
    thread.join(40)
    E.record(holder["answer"], "the scan's answer: stopped during the 20 s wait (200, the finished run, aborted)")
    E.record(stop, "the Stop, sent by the id on the engine's live list while the backend waited")


def scan_failed_inline(E):
    E.server.engine.run_scan = stand_in(E, "still_open", 704, raises="scanner exploded")
    E.record(E.call("POST", "/api/scan", scan_body()),
             "the scan, whose scanner raised inside the 20 s wait (200, the finished run, failed)")


def scan_failed_after_registration(E):
    release, started = threading.Event(), threading.Event()
    E.server.engine.run_scan = stand_in(E, "still_open", 705, release=release, started=started)
    real = E.jobs.status
    E.jobs.status = locked
    try:
        answer = E.record(E.call("POST", "/api/scan", scan_body(), keep_headers=("x-run-id",)),
                          "the scan, whose route failed after its work was handed over: 500 status, state null, "
                          "naming the run (its work is running)")
    finally:
        E.jobs.status = real
    run_id = answer["body"]["run_id"]
    started.wait(10)
    E.record(E.call("GET", f"/api/scans/{run_id}"), "its status read: the run is going")
    release.set()
    wait_until(lambda: E.runs.get(run_id)["state"] == E.runs.COMPLETED)
    E.record(E.call("GET", f"/api/scans/{run_id}"), "its status read once it finished: the findings are under result")


def scan_failed_before_start(E):
    E.server.engine.run_scan = stand_in(E, "still_open", 706)
    real = E.jobs.submit_scan

    def broken(*args, **kwargs):
        raise ValueError("the pool is misconfigured")

    E.jobs.submit_scan = broken
    try:
        answer = E.record(E.call("POST", "/api/scan", scan_body(), keep_headers=("x-run-id",)),
                          "the scan, whose hand-over to the pool failed: 500 status, state failed, nothing started")
    finally:
        E.jobs.submit_scan = real
    E.record(E.call("GET", f"/api/scans/{answer['body']['run_id']}"), "its status read: failed")


def scan_queue_full(E):
    hold = threading.Event()
    blocker = E.runs.start("https://blocker.invalid/", state=E.runs.QUEUED)
    E.jobs.submit_scan(blocker, lambda: hold.wait(30) or {"results": []})
    wait_until(lambda: E.runs.get(blocker)["state"] == E.runs.RUNNING)
    E.server.engine.run_scan = stand_in(E, "still_open", 707)
    E.record(E.call("POST", "/api/scan", scan_body(), keep_headers=("retry-after", "x-run-id")),
             "the scan, refused by a full worker queue (429): nothing started")
    hold.set()


def not_admitted(path, body_of):
    def fn(E):
        E.server.engine.run_scan = stand_in(E, "still_open", 708)
        body = body_of(E)
        real = E.runs.admit
        E.runs.admit = locked
        try:
            E.record(E.call("POST", path, body, keep_headers=("retry-after", "x-run-id")),
                     "the launch, whose admission could not be read from the abort registry: 503, nothing registered")
        finally:
            E.runs.admit = real
        E.record(E.call("GET", "/api/scans/active"), "the engine's live list: nothing was registered")
    return fn


# ------------------------------------------------------------ retests -----

def retest_verdict(kind, scan_id):
    def fn(E):
        twin = setup_twin(E)
        E.server.engine.run_scan = stand_in(E, kind, scan_id)
        answer = E.record(E.call("POST", "/api/remediation/retest", retest_body(twin["id"])),
                          f"the retest, answered inside the engine's inline wait with a {kind} verdict (201)")
        run_id = answer["body"]["run_id"]
        if E.KNOWN_CONTRACT == "pr71":
            E.record(E.call("GET", f"/api/scans/{run_id}"), "the same run read from its status_url")
    return fn


def retest_running(outcome, scan_id):
    def fn(E):
        twin = setup_twin(E)
        release, started = threading.Event(), threading.Event()
        E.server.engine.run_scan = stand_in(E, "closed", scan_id, release=release, started=started)
        answer = E.record(E.call("POST", "/api/remediation/retest", retest_body(twin["id"])),
                          "the retest, still running when the engine's 30 s inline wait ended (202 status)")
        run_id = answer["body"]["run_id"]
        E.record(E.call("GET", f"/api/scans/{run_id}"), "its status read while it runs")
        if outcome == "stopped":
            E.record(E.call("POST", f"/api/scans/{run_id}/abort", {}), "Stop, by the run_id the 202 answered")
            wait_until(lambda: E.runs.get(run_id)["state"] == E.runs.ABORTED)
        else:
            release.set()
            wait_until(lambda: E.runs.get(run_id)["state"] == E.runs.COMPLETED)
        E.record(E.call("GET", f"/api/scans/{run_id}"), f"its status read once it ended ({outcome})")
        release.set()
    return fn


def retest_stopped_while_waiting(E):
    twin = setup_twin(E)
    release, started = threading.Event(), threading.Event()
    E.server.engine.run_scan = stand_in(E, "closed", 720, release=release, started=started)
    holder = {}

    def launch():
        holder["answer"] = E.call("POST", "/api/remediation/retest", retest_body(twin["id"]))

    thread = threading.Thread(target=launch)
    thread.start()
    started.wait(10)
    run_id = E.live("retest")[0]["run_id"]
    stop = E.call("POST", f"/api/scans/{run_id}/abort", {})
    thread.join(40)
    E.record(holder["answer"], "the retest's answer: stopped during the engine's inline wait")
    E.record(stop, "the Stop, sent by the id on the engine's live list")
    if E.KNOWN_CONTRACT == "pr71":
        E.record(E.call("GET", f"/api/scans/{holder['answer']['body']['run_id']}"),
                 "its status read: aborted, with the stored {stopped, scan_incomplete} and no verdict")
    release.set()


def retest_failed(E):
    twin = setup_twin(E)
    E.server.engine.run_scan = stand_in(E, "closed", 721, raises="scanner exploded")
    E.record(E.call("POST", "/api/remediation/retest", retest_body(twin["id"])),
             "the retest, whose scan raised inside the engine's inline wait")


def retest_failed_after_registration(E):
    twin = setup_twin(E)
    release, started = threading.Event(), threading.Event()
    E.server.engine.run_scan = stand_in(E, "closed", 722, release=release, started=started)
    real = E.jobs.status
    E.jobs.status = locked
    try:
        answer = E.record(E.call("POST", "/api/remediation/retest", retest_body(twin["id"]),
                                 keep_headers=("x-run-id",)),
                          "the retest, whose route failed after its work was handed over: 500 status, state null, "
                          "naming the run (its work is running)")
    finally:
        E.jobs.status = real
    run_id = answer["body"]["run_id"]
    started.wait(10)
    E.record(E.call("GET", f"/api/scans/{run_id}"), "its status read: the run is going")
    release.set()
    wait_until(lambda: E.runs.get(run_id)["state"] == E.runs.COMPLETED)
    E.record(E.call("GET", f"/api/scans/{run_id}"), "its status read once it finished: the verdict is the result")


def retest_failed_before_start(E):
    twin = setup_twin(E)
    E.server.engine.run_scan = stand_in(E, "closed", 723)
    real = E.jobs.submit_scan

    def broken(*args, **kwargs):
        raise ValueError("the pool is misconfigured")

    E.jobs.submit_scan = broken
    try:
        E.record(E.call("POST", "/api/remediation/retest", retest_body(twin["id"]), keep_headers=("x-run-id",)),
                 "the retest, whose hand-over to the pool failed: 500 status, state failed, nothing started")
    finally:
        E.jobs.submit_scan = real


def retest_queue_full(E):
    twin = setup_twin(E)
    hold = threading.Event()
    blocker = E.runs.start("https://blocker.invalid/", state=E.runs.QUEUED)
    E.jobs.submit_scan(blocker, lambda: hold.wait(30) or {"results": []})
    wait_until(lambda: E.runs.get(blocker)["state"] == E.runs.RUNNING)
    E.server.engine.run_scan = stand_in(E, "closed", 724)
    E.record(E.call("POST", "/api/remediation/retest", retest_body(twin["id"]), keep_headers=("retry-after", "x-run-id")),
             "the retest, refused by a full worker queue (429): nothing started")
    hold.set()


def retest_stopped_after_recording(E):
    from engine.replay import remediation
    twin = setup_twin(E)
    E.server.engine.run_scan = stand_in(E, "closed", 725)
    real = remediation.record

    def record_then_stop(*args, **kwargs):
        filed = real(*args, **kwargs)
        E.runs.request_abort(E.live("retest")[0]["run_id"], "customer called")
        return filed

    remediation.record = record_then_stop
    try:
        answer = E.record(E.call("POST", "/api/remediation/retest", retest_body(twin["id"])),
                          "the retest, stopped while its check was being filed: answered with that verdict, "
                          "state aborted, stopped_after_recording (201)")
        run_id = answer["body"]["run_id"]
        wait_until(lambda: E.runs.get(run_id)["state"] == E.runs.ABORTED)
    finally:
        remediation.record = real
    E.record(E.call("GET", f"/api/scans/{run_id}"),
             "its status read: state aborted, and the verdict and the check it filed as the result")


# -------------------------------------------------------- attestations -----

def attest_no_baseline(E):
    E.route.observe = observe_stand_in()
    E.record(E.call("POST", "/api/attestation/check", attest_body()),
             "a route with no baseline yet: measured, verdict review")


def attest_unchanged(E):
    E.route.observe = observe_stand_in()
    E.record(E.call("POST", "/api/attestation/baseline", attest_body()),
             "setup: the route's baseline, taken from the same offline facts")
    E.record(E.call("POST", "/api/attestation/check", attest_body()),
             "the route measured against its baseline: verdict unchanged")


def attest_unobservable(E):
    E.record(E.call("POST", "/api/attestation/check", attest_body(UNPARSEABLE_URL)),
             "a route whose URL no reader can parse: recorded unobservable, nothing resolved")


def attest_pending(E):
    release, started = threading.Event(), threading.Event()
    E.route.observe = observe_stand_in(release=release, started=started)
    answer = E.record(E.call("POST", "/api/attestation/check", attest_body(), keep_headers=("retry-after", "x-run-id")),
                      "a route still being measured when the engine's 30 s inline wait ended: 503 status")
    run_id = answer["body"]["run_id"]
    E.record(E.call("POST", f"/api/scans/{run_id}/abort", {}), "Stop, by the run_id the 503 named")
    wait_until(lambda: E.runs.get(run_id)["state"] == E.runs.ABORTED)
    E.record(E.call("GET", f"/api/attestation/runs/{run_id}"), "its status_url once stopped: 409, nothing measured")
    release.set()


def main():
    checkout = Path(sys.argv[1]).resolve()
    out_root = Path(sys.argv[2]).resolve()
    sha = subprocess.run(["git", "-C", str(checkout), "rev-parse", "HEAD"],
                         capture_output=True, text=True, check=True).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(checkout), "status", "--porcelain"],
                           capture_output=True, text=True, check=True).stdout.strip()
    if sha not in KNOWN:
        sys.exit(f"{checkout} is at {sha}, which is not one of the recorded engine commits: {sorted(KNOWN)}")
    if dirty:
        sys.exit(f"{checkout} has uncommitted changes; the fixtures must come from the commit itself")
    os.chdir(checkout)
    sys.path.insert(0, str(checkout))
    os.environ.setdefault("MYTHOS_FLOORS_PATH", str(checkout / "benchmark" / "floors.json"))
    MYTHOS_CORE.update(mythos_core_provenance(checkout))
    out = out_root / KNOWN[sha]
    out.mkdir(parents=True, exist_ok=True)
    contract = "pr71" if KNOWN[sha].startswith("pr71") else "main"
    Engine.KNOWN_CONTRACT = contract

    both = [
        ("scan-finished-inline", scan_finished_inline, {}),
        ("scan-running-then-completed", scan_running_then_completed, {}),
        ("scan-finished-before-the-answer", scan_finished_before_the_answer, {}),
        ("scan-stopped-while-waiting", scan_stopped_while_waiting, {}),
        ("scan-failed-inline", scan_failed_inline, {}),
        ("scan-queue-full", scan_queue_full, {"workers": 1, "queued": 0}),
        ("retest-verdict-closed", retest_verdict("closed", 730), {}),
        ("retest-verdict-still-open", retest_verdict("still_open", 731), {}),
        ("retest-stopped-while-waiting", retest_stopped_while_waiting, {}),
        ("retest-failed", retest_failed, {}),
        ("attest-no-baseline", attest_no_baseline, {}),
        ("attest-unchanged", attest_unchanged, {}),
        ("attest-unobservable", attest_unobservable, {}),
    ]
    pr71_only = [
        ("scan-failed-after-registration", scan_failed_after_registration, {}),
        ("scan-failed-before-start", scan_failed_before_start, {}),
        ("scan-not-admitted", not_admitted("/api/scan", lambda E: scan_body()), {}),
        ("retest-running-then-verdict", retest_running("verdict", 732), {}),
        ("retest-running-then-stopped", retest_running("stopped", 733), {}),
        ("retest-failed-after-registration", retest_failed_after_registration, {}),
        ("retest-failed-before-start", retest_failed_before_start, {}),
        ("retest-queue-full", retest_queue_full, {"workers": 1, "queued": 0}),
        ("retest-stopped-after-recording", retest_stopped_after_recording, {}),
        ("retest-not-admitted",
         not_admitted("/api/remediation/retest", lambda E: retest_body(setup_twin(E)["id"])), {}),
        ("attest-pending", attest_pending, {}),
    ]
    for name, fn, pool in both + (pr71_only if contract == "pr71" else []):
        scenario(name, contract, sha, fn, out, **pool)


if __name__ == "__main__":
    main()
