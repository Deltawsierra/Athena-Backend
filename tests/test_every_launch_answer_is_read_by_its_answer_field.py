"""Every engine launch answer is read by its `answer` field, and a 202 is never done (#315).

athena-engine #71 (head f4610ae) changes what the engine's launching routes
answer. This backend calls three of them -- `POST /api/scan` (CyberEngineClient
.run_scan, from the pentest scan view), `POST /api/remediation/retest`
(.retest_finding) and `POST /api/attestation/check` (.attestation_check, from the
preflight gate) -- and must read both #71 and engine main, which sends no
`answer` at all, for as long as either can be deployed:

  - which contract answered is read from `answer` alone. A value that is
    neither absent (main) nor the shape the route answers under #71 is a shape
    this backend does not read: nothing is read from it, and the run it names is
    kept on the error, so a run that may be going is never one nobody can stop;
  - a 202 is never "done", whatever `state` it names: the engine reads the state
    after handing the run to its pool, so a run that ended in between is
    answered 202 `state: "completed"` with no result in it (at main too);
  - a finished run is read by its state. A scan stopped while the backend waited
    inline is answered 200 with `state: "aborted"`; read as it was, its result
    (nothing) became a COMPLETED scan with no findings -- a Stop recorded as a
    clean bill, at both commits;
  - a 500 `answer: "status"` naming a run whose work started (`state: null`) is
    a run that may be scanning: it is collected, and if it cannot be it stays
    pending WITH its run id. It was recorded failed, with the id thrown away.
    One whose work never started (`state: "failed"`), a 429 and a 503 record
    nothing and name nothing to stop;
  - a retest stopped while its check was filed (201 `state: "aborted"`,
    `stopped_after_recording`) is that verdict, marked stopped after it was
    recorded; a stopped retest's stored `{stopped, scan_incomplete}` is a stop,
    with no verdict and no check.

Every engine answer here is one the real engine app sent, to the request this
backend sends: tests/fixtures/engine_launch/generate.py drove athena-engine at
f4610ae and at 5779e99 (main) in process, through FastAPI's TestClient, with the
mythos-core installed locally ("unpinned local core": see each file's
`mythos_core`). The exceptions are marked "derived": a recorded answer with one
field changed, for the shapes no engine sends.
"""

from __future__ import annotations

import copy
import json
from datetime import timedelta
from pathlib import Path
from unittest import mock

import pytest
import requests
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from ai_engine.services import cyberengine_client as cec
from ai_engine.services.cyberengine_client import (
    ENGINE_REFUSED,
    ENGINE_RUN_FAILED,
    ENGINE_STILL_RUNNING,
    ENGINE_UNREADABLE,
    CyberEngineClient,
    EngineError,
    ScanStillRunning,
    ScanUncollected,
)

pytestmark = pytest.mark.django_db

User = get_user_model()

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "engine_launch"
PR71 = "pr71-f4610ae"
MAIN = "main-5779e99"
SHAS = {
    PR71: ("f4610ae03b6abacf4108990c953462fbf1880950", "pr71"),
    MAIN: ("5779e99eae1085f96e6c27ce28dbd950d8200aba", "main"),
}
BASE = "http://engine.test"
# What CyberEngineClient.run_scan is asked in these recordings.
TARGET = "https://offline.invalid/"
ENGAGEMENT = "42"


def load(where: str, name: str) -> dict:
    return json.loads((FIXTURES / where / f"{name}.json").read_text())


def answered(fx: dict) -> list[dict]:
    return [one for one in fx["exchanges"] if not one["note"].startswith("setup")]


def launch_of(fx: dict, path: str) -> dict:
    return next(one for one in answered(fx) if one["request"]["method"] == "POST"
                and one["request"]["path"] == path)


def reads_of(fx: dict) -> list[dict]:
    return [one for one in answered(fx) if one["request"]["method"] == "GET"
            and one["request"]["path"].startswith("/api/scans/")
            and one["request"]["path"] != "/api/scans/active"]


def _response(exchange: dict) -> requests.Response:
    resp = requests.Response()
    resp.status_code = exchange["status"]
    body = exchange["body"]
    resp._content = (body if isinstance(body, str) else json.dumps(body)).encode("utf-8")
    resp.headers["Content-Type"] = "application/json"
    for name, value in (exchange.get("headers") or {}).items():
        resp.headers[name] = value
    return resp


class Replay:
    """The engine, answering from a recording: each request gets the next recorded
    answer to that method and path, and a request the engine never answered is a
    failure, not an empty 200."""

    def __init__(self, exchanges: list[dict]):
        self.pending = list(exchanges)
        self.sent: list[tuple[str, str, dict | None]] = []

    def _answer(self, method: str, url: str, body=None):
        assert url.startswith(BASE), url
        path = url[len(BASE):]
        self.sent.append((method, path, body))
        for index, one in enumerate(self.pending):
            if one["request"]["method"] == method and one["request"]["path"] == path:
                del self.pending[index]
                return _response(one)
        raise AssertionError(f"the recorded engine never answered {method} {path}")

    def post(self, url, json=None, headers=None, timeout=None, **_):  # noqa: A002
        return self._answer("POST", url, json)

    def get(self, url, headers=None, timeout=None, **_):
        return self._answer("GET", url)


@pytest.fixture()
def engine(monkeypatch):
    """Install a replay of a recording as the engine this client talks to."""
    monkeypatch.setattr(cec, "SCAN_POLL_SECONDS", 0)

    def install(exchanges):
        replay = Replay(exchanges)
        monkeypatch.setattr(cec.requests, "post", replay.post)
        monkeypatch.setattr(cec.requests, "get", replay.get)
        return replay
    return install


def client() -> CyberEngineClient:
    return CyberEngineClient(base_url=BASE, api_key="k")


# ---------------------------------------------------------------------------
# The recordings: provenance and the shape of every answer
# ---------------------------------------------------------------------------

KEY_SETS = {
    'main-5779e99/attest-no-baseline': [
        ('POST', '/api/attestation/check', 201, ('advisory', 'baseline_id', 'behaviour', 'blocking', 'current_digest', 'declared_changes', 'detail', 'name', 'observed', 'recorded', 'url', 'verdict')),
    ],
    'main-5779e99/attest-unchanged': [
        ('POST', '/api/attestation/check', 201, ('advisory', 'baseline_digest', 'baseline_id', 'behaviour', 'blocking', 'current_digest', 'declared_changes', 'detail', 'name', 'observed', 'recorded', 'url', 'verdict')),
    ],
    'main-5779e99/attest-unobservable': [
        ('POST', '/api/attestation/check', 201, ('advisory', 'baseline_id', 'blocking', 'declared_changes', 'detail', 'name', 'observed', 'recorded', 'url', 'verdict')),
    ],
    'main-5779e99/retest-failed': [
        ('POST', '/api/remediation/retest', 201, ('check', 'detail', 'finding_type', 'inventory_digest', 'run_id', 'target', 'twin_id', 'verdict')),
    ],
    'main-5779e99/retest-stopped-while-waiting': [
        ('POST', '/api/remediation/retest', 201, ('check', 'detail', 'finding_type', 'inventory_digest', 'run_id', 'target', 'twin_id', 'verdict')),
        ('POST', '/api/scans/{run_id}/abort', 200, ('reason', 'run_id', 'state')),
    ],
    'main-5779e99/retest-verdict-closed': [
        ('POST', '/api/remediation/retest', 201, ('check', 'detail', 'finding_type', 'inventory_digest', 'run_id', 'target', 'twin_id', 'verdict')),
    ],
    'main-5779e99/retest-verdict-still-open': [
        ('POST', '/api/remediation/retest', 201, ('check', 'detail', 'finding_type', 'inventory_digest', 'run_id', 'target', 'twin_id', 'verdict')),
    ],
    'main-5779e99/scan-failed-inline': [
        ('POST', '/api/scan', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
    ],
    'main-5779e99/scan-finished-before-the-answer': [
        ('POST', '/api/scan', 202, ('detail', 'run_id', 'state', 'status_url')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
    ],
    'main-5779e99/scan-finished-inline': [
        ('POST', '/api/scan', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
    ],
    'main-5779e99/scan-queue-full': [
        ('POST', '/api/scan', 429, ('error', 'run_id', 'state')),
    ],
    'main-5779e99/scan-running-then-completed': [
        ('POST', '/api/scan', 202, ('detail', 'run_id', 'state', 'status_url')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
    ],
    'main-5779e99/scan-stopped-while-waiting': [
        ('POST', '/api/scan', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
        ('POST', '/api/scans/{run_id}/abort', 200, ('reason', 'run_id', 'state')),
    ],
    'pr71-f4610ae/attest-no-baseline': [
        ('POST', '/api/attestation/check', 201, ('advisory', 'answer', 'baseline_id', 'behaviour', 'blocking', 'current_digest', 'declared_changes', 'detail', 'name', 'observed', 'recorded', 'run_id', 'state', 'status_url', 'url', 'verdict')),
    ],
    'pr71-f4610ae/attest-pending': [
        ('POST', '/api/attestation/check', 503, ('answer', 'detail', 'error', 'reason', 'run_id', 'state', 'status_url')),
        ('POST', '/api/scans/{run_id}/abort', 200, ('reason', 'recorded', 'run_id', 'state')),
        ('GET', '/api/attestation/runs/{run_id}', 409, ('answer', 'detail', 'error', 'reason', 'run_id', 'state', 'status_url')),
    ],
    'pr71-f4610ae/attest-unchanged': [
        ('POST', '/api/attestation/check', 201, ('advisory', 'answer', 'baseline_digest', 'baseline_id', 'behaviour', 'blocking', 'current_digest', 'declared_changes', 'detail', 'name', 'observed', 'recorded', 'run_id', 'state', 'status_url', 'url', 'verdict')),
    ],
    'pr71-f4610ae/attest-unobservable': [
        ('POST', '/api/attestation/check', 201, ('advisory', 'answer', 'baseline_id', 'blocking', 'declared_changes', 'detail', 'name', 'observed', 'recorded', 'run_id', 'state', 'status_url', 'url', 'verdict')),
    ],
    'pr71-f4610ae/retest-failed-after-registration': [
        ('POST', '/api/remediation/retest', 500, ('answer', 'error', 'reason', 'run_id', 'state', 'status_url')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
    ],
    'pr71-f4610ae/retest-failed-before-start': [
        ('POST', '/api/remediation/retest', 500, ('answer', 'error', 'reason', 'run_id', 'state', 'status_url')),
    ],
    'pr71-f4610ae/retest-failed': [
        ('POST', '/api/remediation/retest', 200, ('answer', 'error', 'reason', 'run_id', 'state', 'status_url')),
    ],
    'pr71-f4610ae/retest-not-admitted': [
        ('POST', '/api/remediation/retest', 503, ('detail',)),
        ('GET', '/api/scans/active', 200, ('active',)),
    ],
    'pr71-f4610ae/retest-queue-full': [
        ('POST', '/api/remediation/retest', 429, ('answer', 'error', 'reason', 'run_id', 'state', 'status_url')),
    ],
    'pr71-f4610ae/retest-running-then-stopped': [
        ('POST', '/api/remediation/retest', 202, ('answer', 'detail', 'error', 'reason', 'run_id', 'state', 'status_url')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
        ('POST', '/api/scans/{run_id}/abort', 200, ('reason', 'recorded', 'run_id', 'state')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
    ],
    'pr71-f4610ae/retest-running-then-verdict': [
        ('POST', '/api/remediation/retest', 202, ('answer', 'detail', 'error', 'reason', 'run_id', 'state', 'status_url')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
    ],
    'pr71-f4610ae/retest-stopped-after-recording': [
        ('POST', '/api/remediation/retest', 201, ('answer', 'check', 'detail', 'finding_type', 'inventory_digest', 'run_id', 'scan_record_id', 'state', 'status_url', 'stopped_after_recording', 'target', 'twin_id', 'verdict')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
    ],
    'pr71-f4610ae/retest-stopped-while-waiting': [
        ('POST', '/api/remediation/retest', 200, ('answer', 'error', 'reason', 'run_id', 'state', 'status_url')),
        ('POST', '/api/scans/{run_id}/abort', 200, ('reason', 'recorded', 'run_id', 'state')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
    ],
    'pr71-f4610ae/retest-verdict-closed': [
        ('POST', '/api/remediation/retest', 201, ('answer', 'check', 'detail', 'finding_type', 'inventory_digest', 'run_id', 'scan_record_id', 'state', 'status_url', 'target', 'twin_id', 'verdict')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
    ],
    'pr71-f4610ae/retest-verdict-still-open': [
        ('POST', '/api/remediation/retest', 201, ('answer', 'check', 'detail', 'finding_type', 'inventory_digest', 'run_id', 'scan_record_id', 'state', 'status_url', 'target', 'twin_id', 'verdict')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
    ],
    'pr71-f4610ae/scan-failed-after-registration': [
        ('POST', '/api/scan', 500, ('answer', 'error', 'reason', 'run_id', 'state', 'status_url')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
    ],
    'pr71-f4610ae/scan-failed-before-start': [
        ('POST', '/api/scan', 500, ('answer', 'error', 'reason', 'run_id', 'state', 'status_url')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
    ],
    'pr71-f4610ae/scan-failed-inline': [
        ('POST', '/api/scan', 200, ('answer', 'done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'status_url', 'target', 'updated_at')),
    ],
    'pr71-f4610ae/scan-finished-before-the-answer': [
        ('POST', '/api/scan', 202, ('answer', 'detail', 'error', 'reason', 'run_id', 'state', 'status_url')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
    ],
    'pr71-f4610ae/scan-finished-inline': [
        ('POST', '/api/scan', 200, ('answer', 'done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'status_url', 'target', 'updated_at')),
    ],
    'pr71-f4610ae/scan-not-admitted': [
        ('POST', '/api/scan', 503, ('detail',)),
        ('GET', '/api/scans/active', 200, ('active',)),
    ],
    'pr71-f4610ae/scan-queue-full': [
        ('POST', '/api/scan', 429, ('answer', 'error', 'reason', 'run_id', 'state', 'status_url')),
    ],
    'pr71-f4610ae/scan-running-then-completed': [
        ('POST', '/api/scan', 202, ('answer', 'detail', 'error', 'reason', 'run_id', 'state', 'status_url')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
        ('GET', '/api/scans/{run_id}', 200, ('done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'target', 'updated_at')),
    ],
    'pr71-f4610ae/scan-stopped-while-waiting': [
        ('POST', '/api/scan', 200, ('answer', 'done', 'finished_at', 'key_hash', 'kind', 'reason', 'result', 'run_id', 'started_at', 'state', 'status_url', 'target', 'updated_at')),
        ('POST', '/api/scans/{run_id}/abort', 200, ('reason', 'recorded', 'run_id', 'state')),
    ],
}


ALL_FIXTURES = sorted(KEY_SETS)


def test_every_recording_has_its_key_sets_asserted_and_nothing_else_is_on_disk():
    on_disk = sorted(f"{p.parent.name}/{p.stem}" for p in FIXTURES.glob("*/*.json"))
    assert on_disk == ALL_FIXTURES


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_every_recording_came_from_the_engine_it_names(name):
    where, scenario = name.split("/")
    fx = load(where, scenario)
    sha, contract = SHAS[where]
    assert fx["engine"] == {"repository": "athena-engine", "sha": sha, "contract": contract}
    assert fx["scenario"] == scenario
    assert fx["generated_by"] == "tests/fixtures/engine_launch/generate.py"
    # Said in words, so nobody reads these as a run on the pinned core.
    assert fx["mythos_core"]["label"] == "unpinned local core"
    assert fx["mythos_core"]["imported_commit"] != fx["mythos_core"]["pinned_by_requirements"]


@pytest.mark.parametrize("name", ALL_FIXTURES)
def test_every_answer_has_the_keys_it_was_recorded_with(name):
    """The key set of every answer, per recording. A regenerated recording whose
    shape moved fails here, by name, before any reader is tested against it."""
    import re

    where, scenario = name.split("/")
    rows = []
    for one in answered(load(where, scenario)):
        path = re.sub(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                      "{run_id}", one["request"]["path"])
        body = one["body"]
        rows.append((one["request"]["method"], path, one["status"],
                     tuple(sorted(body)) if isinstance(body, dict) else None))
    assert rows == KEY_SETS[name]


def test_main_sends_no_answer_field_and_pr71_marks_every_launch():
    for name in ALL_FIXTURES:
        where, scenario = name.split("/")
        for one in answered(load(where, scenario)):
            if one["request"]["method"] != "POST" or "/abort" in one["request"]["path"]:
                continue
            body = one["body"]
            if where == MAIN:
                assert "answer" not in body, name
            elif isinstance(body, dict) and one["status"] != 503:
                assert body.get("answer") in ("status", "verdict"), name


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------


def _scan(engine, where, scenario, *, exchanges=None):
    fx = load(where, scenario)
    replay = engine(exchanges if exchanges is not None else answered(fx))
    return fx, replay


@pytest.mark.parametrize("where", [PR71, MAIN])
def test_a_scan_finished_inside_the_wait_is_its_findings(engine, where):
    fx, replay = _scan(engine, where, "scan-finished-inline")
    launch = launch_of(fx, "/api/scan")

    result = client().run_scan(TARGET, engagement_ref=ENGAGEMENT)

    # The request is the one the recording was made with.
    assert replay.sent[0] == ("POST", "/api/scan", launch["request"]["body"])
    assert result == launch["body"]["result"]
    assert result["results"][0]["type"] == "xss"


@pytest.mark.parametrize("where", [PR71, MAIN])
def test_a_202_is_collected_from_the_status_route(engine, where):
    fx, replay = _scan(engine, where, "scan-running-then-completed")
    reads = reads_of(fx)

    result = client().run_scan(TARGET, engagement_ref=ENGAGEMENT)

    assert result == reads[-1]["body"]["result"]
    assert [p for m, p, _ in replay.sent if m == "GET"] == [r["request"]["path"] for r in reads]


@pytest.mark.parametrize("where", [PR71, MAIN])
def test_a_202_that_names_a_finished_run_is_still_not_done(engine, where):
    """The engine read the state after the run had already ended: 202, state
    completed, and no result in it. The findings are on the status route."""
    fx, replay = _scan(engine, where, "scan-finished-before-the-answer")
    launch = launch_of(fx, "/api/scan")
    assert launch["status"] == 202 and launch["body"]["state"] == "completed"
    assert "result" not in launch["body"]

    result = client().run_scan(TARGET, engagement_ref=ENGAGEMENT)

    assert result == reads_of(fx)[-1]["body"]["result"]
    assert result["results"], "the findings the 202 did not carry were dropped"


@pytest.mark.parametrize("where", [PR71, MAIN])
def test_a_scan_stopped_while_the_backend_waited_is_a_stop_not_a_clean_result(engine, where):
    """200, the finished run, `state: "aborted"`, and a result holding whatever
    the scan had when it stopped -- here nothing. Read as findings, a scan an
    operator stopped was recorded as one that completed and found nothing."""
    fx, _ = _scan(engine, where, "scan-stopped-while-waiting")
    launch = launch_of(fx, "/api/scan")
    assert launch["status"] == 200 and launch["body"]["state"] == "aborted"

    with pytest.raises(EngineError) as raised:
        client().run_scan(TARGET, engagement_ref=ENGAGEMENT)

    assert raised.value.kind == ENGINE_RUN_FAILED
    assert "aborted" in str(raised.value)
    assert "stopped by an operator" in str(raised.value)
    assert raised.value.run_id == launch["body"]["run_id"]


@pytest.mark.parametrize("where", [PR71, MAIN])
def test_a_scan_that_failed_inside_the_wait_is_a_failure(engine, where):
    fx, _ = _scan(engine, where, "scan-failed-inline")
    launch = launch_of(fx, "/api/scan")

    with pytest.raises(EngineError) as raised:
        client().run_scan(TARGET, engagement_ref=ENGAGEMENT)

    assert raised.value.kind == ENGINE_RUN_FAILED
    assert "scanner exploded" in str(raised.value)
    assert raised.value.run_id == launch["body"]["run_id"]


def test_a_500_naming_a_run_whose_work_started_is_collected(engine):
    """#71: the route failed after it handed the work over. The run is scanning,
    stoppable by this id, and records its own end."""
    fx, replay = _scan(engine, PR71, "scan-failed-after-registration")
    launch = launch_of(fx, "/api/scan")
    assert launch["status"] == 500 and launch["body"]["state"] is None
    assert launch["headers"]["x-run-id"] == launch["body"]["run_id"]

    result = client().run_scan(TARGET, engagement_ref=ENGAGEMENT)

    assert result == reads_of(fx)[-1]["body"]["result"]
    assert ("GET", f"/api/scans/{launch['body']['run_id']}", None) in replay.sent


def test_a_500_naming_a_run_that_cannot_be_collected_is_still_running_with_its_id(engine, monkeypatch):
    """The engine that answered 500 because its registry was locked may not answer
    the status read either. The run is still going; its id is the only handle on
    it, and it is kept."""
    fx = load(PR71, "scan-failed-after-registration")
    launch = launch_of(fx, "/api/scan")
    replay = engine([launch])

    def unreachable(url, **_):
        replay.sent.append(("GET", url[len(BASE):], None))
        raise requests.ConnectionError("connection refused")

    monkeypatch.setattr(cec.requests, "get", unreachable)

    with pytest.raises(ScanStillRunning) as raised:
        client().run_scan(TARGET, engagement_ref=ENGAGEMENT)

    assert raised.value.run_id == launch["body"]["run_id"]


def test_a_500_naming_a_run_whose_work_never_started_names_nothing_to_stop(engine):
    fx, replay = _scan(engine, PR71, "scan-failed-before-start")
    launch = launch_of(fx, "/api/scan")
    assert launch["body"]["state"] == "failed"

    with pytest.raises(EngineError) as raised:
        client().run_scan(TARGET, engagement_ref=ENGAGEMENT)

    assert raised.value.kind == ENGINE_REFUSED
    assert raised.value.status == 500
    assert raised.value.run_id is None
    assert "before the scan's work started" in str(raised.value)
    assert "Nothing was sent to the target" in str(raised.value)
    # Nothing is collected: there is no run to collect.
    assert [m for m, _, _ in replay.sent] == ["POST"]


@pytest.mark.parametrize("where, scenario, code", [
    (PR71, "scan-queue-full", 429),
    (MAIN, "scan-queue-full", 429),
    (PR71, "scan-not-admitted", 503),
])
def test_a_launch_that_started_nothing_is_a_refusal_naming_nothing(engine, where, scenario, code):
    _scan(engine, where, scenario)

    with pytest.raises(EngineError) as raised:
        client().run_scan(TARGET, engagement_ref=ENGAGEMENT)

    assert raised.value.kind == ENGINE_REFUSED
    assert raised.value.status == code
    assert raised.value.run_id is None


@pytest.mark.parametrize("answer", ["verdict", "done", None, 7])
def test_a_scan_answer_in_a_shape_this_backend_does_not_read_is_not_read(engine, answer):
    """Derived: #71's 202 with `answer` changed to a value no engine sends on this
    route. Nothing is read from it -- no state, no result, no collection -- and
    the run it names is carried, so it can still be stopped. Round 4: the run may
    still be scanning, so it is the scan still running (ScanUncollected), never a
    failed one."""
    fx = load(PR71, "scan-running-then-completed")
    launch = copy.deepcopy(launch_of(fx, "/api/scan"))
    launch["body"]["answer"] = answer
    replay = engine([launch] + reads_of(fx))

    with pytest.raises(ScanUncollected) as raised:
        client().run_scan(TARGET, engagement_ref=ENGAGEMENT)

    assert raised.value.kind == ENGINE_STILL_RUNNING
    assert "a shape this backend does not read" in str(raised.value)
    assert "may still be running" in str(raised.value)
    assert raised.value.run_id == launch["body"]["run_id"]
    assert [m for m, _, _ in replay.sent] == ["POST"]


# ---------------------------------------------------------------------------
# What the pentest scan view records
# ---------------------------------------------------------------------------


VIEW_TARGET = "https://app.client.example/login"


@pytest.fixture()
def analyst():
    return User.objects.create_user(username="launch-reader", password="x", role=User.Roles.ANALYST)


@pytest.fixture()
def engagement(analyst):
    from pentest.models import Engagement

    now = timezone.now()
    return Engagement.objects.create(
        created_by=analyst,
        name="Client Q3",
        status="running",
        scope_hosts=["client.example"],
        testing_window_start=now - timedelta(hours=1),
        testing_window_end=now + timedelta(hours=1),
    )


def scan_through_view(analyst, engagement):
    from pentest import views

    request = APIRequestFactory().post(
        "/api/pentest/scan/",
        {"url": VIEW_TARGET, "consent": True, "engagement_id": engagement.pk},
        format="json",
    )
    force_authenticate(request, user=analyst)
    with mock.patch("pentest.views.target_is_out_of_bounds", return_value=None), \
            mock.patch("pentest.views.CyberEngineClient") as cls, \
            mock.patch("pentest.views.preflight.check", return_value={"verdict": "ok"}), \
            mock.patch("pentest.views.render_scan_pdf_bytes", return_value=b"%PDF-"), \
            mock.patch("pentest.views.save_pdf_to_scan"):
        cls.from_settings.return_value = client()
        return views.run_pentest_scan(request)


def test_the_view_keeps_a_run_the_engine_started_and_failed_after_as_pending_with_its_id(
        engine, analyst, engagement, monkeypatch):
    """The 500 `state: null` case end to end: the run is scanning the customer.
    It was recorded FAILED with no engine run id -- work nobody could find or stop."""
    from pentest.models import PentestScan

    fx = load(PR71, "scan-failed-after-registration")
    launch = launch_of(fx, "/api/scan")
    engine([launch, reads_of(fx)[0]])
    # Give up collecting after the first read, which says it is running.
    monkeypatch.setattr(cec, "SCAN_COLLECT_SECONDS", 0)

    response = scan_through_view(analyst, engagement)

    assert response.status_code == 202
    scan = PentestScan.objects.get(uuid=response.data["scan_id"])
    assert scan.status == PentestScan.STATUS_PENDING
    assert scan.engine_run_id == launch["body"]["run_id"]
    assert response.data["engine_run_id"] == launch["body"]["run_id"]


@pytest.mark.parametrize("where", [PR71, MAIN])
def test_the_view_records_a_stopped_scan_as_failed_with_its_run_not_as_completed(
        engine, analyst, engagement, where):
    from pentest.models import PentestScan

    fx = load(where, "scan-stopped-while-waiting")
    launch = launch_of(fx, "/api/scan")
    engine([launch])

    response = scan_through_view(analyst, engagement)

    assert response.status_code == 502
    scan = PentestScan.objects.get(uuid=response.data["scan_id"])
    assert scan.status == PentestScan.STATUS_FAILED
    assert "aborted" in scan.error_message
    assert scan.engine_run_id == launch["body"]["run_id"]
    assert not scan.pdf_file


def test_the_view_keeps_the_run_an_unreadable_answer_names(engine, analyst, engagement):
    """Derived, as above. The answer is not read; the run it names may be going,
    and its id is kept on the scan so it can be found and stopped. Round 4: the
    scan stays PENDING, as one the engine could not be read about -- recorded
    FAILED, it read as over while the engine may still be running it."""
    from pentest.models import PentestScan

    fx = load(PR71, "scan-running-then-completed")
    launch = copy.deepcopy(launch_of(fx, "/api/scan"))
    launch["body"]["answer"] = "verdict"
    engine([launch])

    response = scan_through_view(analyst, engagement)

    assert response.status_code == 202
    scan = PentestScan.objects.get(uuid=response.data["scan_id"])
    assert scan.status == PentestScan.STATUS_PENDING
    assert scan.engine_run_id == launch["body"]["run_id"]
    assert response.data["engine_run_id"] == launch["body"]["run_id"]
    assert "does not read" in response.data["detail"]
    assert "may still be running" in response.data["detail"]


def test_the_view_records_nothing_for_a_run_whose_work_never_started(engine, analyst, engagement):
    from pentest.models import PentestScan

    fx = load(PR71, "scan-failed-before-start")
    engine([launch_of(fx, "/api/scan")])

    response = scan_through_view(analyst, engagement)

    assert response.status_code == 502
    scan = PentestScan.objects.get(uuid=response.data["scan_id"])
    assert scan.status == PentestScan.STATUS_FAILED
    assert scan.engine_run_id is None
    assert "Nothing was sent to the target" in scan.error_message


# ---------------------------------------------------------------------------
# Retests
# ---------------------------------------------------------------------------


def _retest(engine, where, scenario, exchanges=None):
    fx = load(where, scenario)
    replay = engine(exchanges if exchanges is not None else answered(fx))
    launch = launch_of(fx, "/api/remediation/retest")
    reading = client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])
    return fx, replay, launch, reading


@pytest.mark.parametrize("scenario, verdict", [
    ("retest-verdict-closed", "closed"), ("retest-verdict-still-open", "still_open"),
])
def test_a_pr71_verdict_names_its_record_by_scan_record_id_and_its_run_by_run_id(engine, scenario, verdict):
    fx, replay, launch, reading = _retest(engine, PR71, scenario)

    assert replay.sent[0] == ("POST", "/api/remediation/retest", launch["request"]["body"])
    assert reading["answer"] == "verdict"
    assert reading["verdict"] == verdict
    assert reading["scan_record_id"] == str(launch["body"]["scan_record_id"])
    assert reading["run_id"] == launch["body"]["run_id"]
    assert reading["run_id"] != reading["scan_record_id"]
    assert reading["stop_id"] is None, "a finished retest has nothing left to stop"
    assert reading["stopped_after_recording"] is None
    assert reading["check"]["verdict"] == verdict

    again = client().retest_status(reading["run_id"])
    assert again["answer"] == "verdict" and again["verdict"] == verdict
    assert again["scan_record_id"] == reading["scan_record_id"]


@pytest.mark.parametrize("scenario, verdict", [
    ("retest-verdict-closed", "closed"), ("retest-verdict-still-open", "still_open"),
    # Main answers a stopped or failed retest with the runner's verdict.
    ("retest-stopped-while-waiting", "inconclusive"), ("retest-failed", "inconclusive"),
])
def test_a_main_verdict_is_read_with_its_record_under_run_id_and_nothing_to_stop(engine, scenario, verdict):
    fx, replay, launch, reading = _retest(engine, MAIN, scenario)

    assert reading["answer"] == "verdict"
    assert reading["verdict"] == verdict
    # Main's run_id is the scan record id -- not a registry run, not stoppable --
    # and None when no scan record was made (the retest's scan raised).
    record = launch["body"]["run_id"]
    assert reading["scan_record_id"] == (None if record is None else str(record))
    assert (record is None) == (scenario == "retest-failed")
    assert reading["run_id"] is None
    assert reading["stop_id"] is None


def test_a_retest_stopped_while_its_check_was_filed_is_that_verdict_marked_stopped(engine):
    fx, replay, launch, reading = _retest(engine, PR71, "retest-stopped-after-recording")
    assert launch["status"] == 201 and launch["body"]["state"] == "aborted"

    assert reading["answer"] == "verdict"
    assert reading["verdict"] == "closed"
    assert reading["check"] is not None, "the check the engine filed was read as nothing filed"
    assert reading["stopped_after_recording"] == "customer called"
    assert reading["state"] == "aborted"

    later = client().retest_status(reading["run_id"])
    assert later["answer"] == "verdict"
    assert later["stopped_after_recording"] == "customer called"
    assert later["check"] == reading["check"]


def test_a_202_retest_is_running_and_stoppable_and_its_stop_is_read_as_a_stop(engine):
    fx, replay, launch, reading = _retest(engine, PR71, "retest-running-then-stopped")

    assert reading["answer"] == "status"
    assert reading["phase"] == "running"
    assert reading["stop_id"] == launch["body"]["run_id"]

    while_running = client().retest_status(reading["stop_id"])
    assert while_running["phase"] == "running"
    assert while_running["stop_id"] == reading["stop_id"]

    stopped = client().retest_status(reading["stop_id"])
    stored = reads_of(fx)[-1]["body"]["result"]
    assert stored["stopped"] and stored["scan_incomplete"] is True and "verdict" not in stored
    assert stopped["answer"] == "status"
    assert stopped["phase"] == "stopped"
    assert stopped["stop_id"] is None
    assert "verdict" not in stopped and "check" not in stopped


def test_a_202_retest_collected_to_its_verdict(engine):
    fx, replay, launch, reading = _retest(engine, PR71, "retest-running-then-verdict")
    assert reading["phase"] == "running"

    assert client().retest_status(reading["stop_id"])["phase"] == "running"
    final = client().retest_status(reading["stop_id"])
    assert final["answer"] == "verdict" and final["verdict"] == "closed"
    assert final["scan_record_id"] == str(reads_of(fx)[-1]["body"]["result"]["scan_record_id"])


@pytest.mark.parametrize("scenario, phase", [
    ("retest-stopped-while-waiting", "stopped"),
    ("retest-failed", "failed"),
])
def test_a_retest_that_ended_without_a_verdict_is_a_status(engine, scenario, phase):
    fx, replay, launch, reading = _retest(engine, PR71, scenario)
    assert launch["status"] == 200

    assert reading["answer"] == "status"
    assert reading["phase"] == phase
    assert reading["stop_id"] is None


def test_a_retest_500_whose_work_started_is_running_with_its_stop(engine):
    fx, replay, launch, reading = _retest(engine, PR71, "retest-failed-after-registration")

    assert reading["phase"] == "running"
    assert reading["stop_id"] == launch["body"]["run_id"] == launch["headers"]["x-run-id"]
    assert client().retest_status(reading["stop_id"])["phase"] == "running"
    assert client().retest_status(reading["stop_id"])["answer"] == "verdict"


@pytest.mark.parametrize("scenario, phase", [
    ("retest-failed-before-start", "failed"),
    ("retest-queue-full", "refused"),
])
def test_a_retest_that_never_started_names_nothing_to_stop(engine, scenario, phase):
    fx, replay, launch, reading = _retest(engine, PR71, scenario)

    assert reading["phase"] == phase
    assert reading["started"] is False
    assert reading["run_id"] is None
    assert reading["stop_id"] is None


def test_a_retest_not_admitted_is_a_refusal(engine):
    fx = load(PR71, "retest-not-admitted")
    engine(answered(fx))

    with pytest.raises(EngineError) as raised:
        client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])

    assert raised.value.status == 503
    assert raised.value.run_id is None


@pytest.mark.parametrize("change", [
    {"answer": "result"},            # a value neither contract sends
    {"answer": None},
])
def test_a_retest_answer_in_a_shape_this_backend_does_not_read_is_not_read(engine, change):
    """Derived from #71's recorded verdict: one field changed."""
    fx = load(PR71, "retest-verdict-closed")
    launch = copy.deepcopy(launch_of(fx, "/api/remediation/retest"))
    launch["body"].update(change)
    engine([launch])

    with pytest.raises(EngineError) as raised:
        client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])

    assert raised.value.kind == ENGINE_UNREADABLE
    assert raised.value.run_id == launch["body"]["run_id"]


def test_a_retest_verdict_without_answer_but_with_a_scan_record_id_is_not_read(engine):
    """Derived: #71's verdict with `answer` removed. Read as main's verdict, it
    would name its record by a registry run id."""
    fx = load(PR71, "retest-verdict-closed")
    launch = copy.deepcopy(launch_of(fx, "/api/remediation/retest"))
    del launch["body"]["answer"]
    engine([launch])

    with pytest.raises(EngineError) as raised:
        client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])

    assert raised.value.kind == ENGINE_UNREADABLE


# ---------------------------------------------------------------------------
# Route attestation, as the preflight gate asks it
# ---------------------------------------------------------------------------


def _attest(engine, where, scenario):
    from ai_engine.services import preflight

    fx = load(where, scenario)
    engine(answered(fx))
    launch = launch_of(fx, "/api/attestation/check")
    dep = mock.Mock()
    asset = mock.Mock(identifier=launch["request"]["body"]["url"])
    asset.name = launch["request"]["body"]["name"]
    dep.assets.all.return_value = [asset]
    with mock.patch("assurance.served_route.serves_inference", return_value=True):
        return launch, preflight._attest_routes(client(), dep)


@pytest.mark.parametrize("where", [PR71, MAIN])
@pytest.mark.parametrize("scenario, verdict", [
    ("attest-unchanged", "unchanged"),
    ("attest-no-baseline", "review"),
    ("attest-unobservable", "unobservable"),
])
def test_an_attestation_verdict_is_read_at_both_commits(engine, where, scenario, verdict):
    launch, report = _attest(engine, where, scenario)

    assert report["verdict"] == verdict
    assert not report.get("verdict_missing")
    if where == PR71:
        assert launch["body"]["answer"] == "verdict"


def test_an_attestation_still_measuring_is_unobserved_not_unchanged(engine):
    """#71 answers 503 `answer: "status"` when its inline wait ends before the
    measurement: nothing was measured, so the route is unobservable."""
    launch, report = _attest(engine, PR71, "attest-pending")
    assert launch["status"] == 503

    assert report["verdict"] == "unobservable"
    assert report["routes"][0]["verdict"] == "unobservable"
    assert "503" in report["routes"][0]["detail"]


# ---------------------------------------------------------------------------
# Round 4: an answer that says nothing about a run's end is not its end
# ---------------------------------------------------------------------------


def _derived(where, scenario, path, **change):
    fx = load(where, scenario)
    launch = copy.deepcopy(launch_of(fx, path))
    for key, value in change.items():
        if value is _DROP:
            launch["body"].pop(key, None)
        else:
            launch["body"][key] = value
    return fx, launch


_DROP = object()


@pytest.mark.parametrize("state", [_DROP, None, "running", "stopping"])
def test_a_finished_pr71_status_with_no_end_state_is_not_an_old_engines_result(engine, state):
    """Derived: #71's 200 "stopped while waiting" with `state` dropped (or null, or
    not an end). The contract is read from `answer` alone: it is #71's status, and
    it says nothing about how the run ended. Read as an engine older than the run
    registry, its result became a COMPLETED scan with nothing found -- a stopped
    scan recorded clean."""
    _, launch = _derived(PR71, "scan-stopped-while-waiting", "/api/scan", state=state)
    assert launch["body"]["answer"] == "status" and launch["body"].get("result") is not None
    replay = engine([launch])

    with pytest.raises(ScanUncollected) as raised:
        client().run_scan(TARGET, engagement_ref=ENGAGEMENT)

    assert raised.value.run_id == launch["body"]["run_id"]
    assert "may still be running" in str(raised.value)
    assert [m for m, _, _ in replay.sent] == ["POST"]


def test_the_view_keeps_a_finished_status_with_no_end_state_pending_never_completed(engine, analyst, engagement):
    from pentest.models import PentestScan

    _, launch = _derived(PR71, "scan-stopped-while-waiting", "/api/scan", state=_DROP)
    engine([launch])

    response = scan_through_view(analyst, engagement)

    assert response.status_code == 202
    scan = PentestScan.objects.get(uuid=response.data["scan_id"])
    assert scan.status == PentestScan.STATUS_PENDING
    assert scan.engine_run_id == launch["body"]["run_id"]
    assert not scan.pdf_file


def test_an_engine_older_than_the_run_registry_is_still_read_as_its_result(engine):
    """The negative control: no `answer`, no `state`, done, a result -- the engine
    before the run registry. Its result is the findings, as it always was."""
    _, launch = _derived(MAIN, "scan-finished-inline", "/api/scan", state=_DROP, run_id=_DROP)
    engine([launch])

    assert client().run_scan(TARGET, engagement_ref=ENGAGEMENT) == launch["body"]["result"]


def test_a_pr71_status_on_a_200_that_names_no_run_is_not_a_synchronous_result(engine):
    """B4. #71's 200 status, not done, naming no run: nothing to collect, and never
    the synchronous answer of an older engine."""
    _, launch = _derived(PR71, "scan-running-then-completed", "/api/scan", run_id=_DROP)
    launch["status"] = 200
    launch["body"]["done"] = False
    engine([launch])

    with pytest.raises(EngineError) as raised:
        client().run_scan(TARGET, engagement_ref=ENGAGEMENT)

    assert raised.value.kind == ENGINE_UNREADABLE
    assert "names no" in str(raised.value)


@pytest.mark.parametrize("code", [502, 503, 500])
def test_a_status_read_that_answers_5xx_is_a_scan_still_running_with_its_id(engine, code, analyst, engagement):
    """B1. The status read failing says nothing about the run: it is still running,
    with its id -- pending on the scan, never FAILED."""
    from pentest.models import PentestScan

    fx = load(PR71, "scan-running-then-completed")
    launch = launch_of(fx, "/api/scan")
    engine([launch, {"request": {"method": "GET", "path": f"/api/scans/{launch['body']['run_id']}"},
                     "status": code, "body": {"detail": "database is locked"}, "note": "derived"}])

    with pytest.raises(ScanUncollected) as raised:
        client().run_scan(TARGET, engagement_ref=ENGAGEMENT)
    assert raised.value.run_id == launch["body"]["run_id"]

    engine([launch, {"request": {"method": "GET", "path": f"/api/scans/{launch['body']['run_id']}"},
                     "status": code, "body": {"detail": "database is locked"}, "note": "derived"}])
    response = scan_through_view(analyst, engagement)
    assert response.status_code == 202
    assert PentestScan.objects.get(uuid=response.data["scan_id"]).status == PentestScan.STATUS_PENDING


_DEEP = "[" * 200_000 + "]" * 200_000


@pytest.mark.parametrize("status", [200, 202, 500])
def test_a_body_nested_past_any_answer_is_unreadable_never_a_recursion_error(engine, status):
    """Derived: a body nested 200,000 deep. It raised RecursionError -- not a
    ValueError -- past every reader, out of the view as a 500, the scan left
    pending with no run id."""
    fx = load(PR71, "scan-running-then-completed")
    launch = copy.deepcopy(launch_of(fx, "/api/scan"))
    launch["status"] = status
    launch["body"] = _DEEP
    engine([launch])

    with pytest.raises(EngineError) as raised:
        client().run_scan(TARGET, engagement_ref=ENGAGEMENT)

    assert not isinstance(raised.value.__cause__, RecursionError)
    if status != 500:
        assert raised.value.kind == ENGINE_UNREADABLE


def test_a_status_naming_its_run_with_one_field_nested_too_deep_keeps_the_run_by_its_header(engine, analyst, engagement):
    """Derived: #71's 202 naming its run, one field nested 200,000 deep, and the
    run in X-Run-Id. The body is unreadable; the header still names the run, which
    may be scanning: pending with that id."""
    from pentest.models import PentestScan

    fx = load(PR71, "scan-running-then-completed")
    launch = copy.deepcopy(launch_of(fx, "/api/scan"))
    run_id = launch["body"]["run_id"]
    launch["body"] = json.dumps({**launch["body"], "x": 0})[:-1] + ', "deep": ' + _DEEP + "}"
    launch["headers"] = {"X-Run-Id": run_id}
    engine([launch])

    response = scan_through_view(analyst, engagement)

    assert response.status_code == 202
    scan = PentestScan.objects.get(uuid=response.data["scan_id"])
    assert scan.status == PentestScan.STATUS_PENDING
    assert scan.engine_run_id == run_id


def test_a_500_whose_body_a_proxy_replaced_is_collected_by_its_x_run_id(engine, analyst, engagement, monkeypatch):
    """Derived: #71's 500 `state: null` with its body replaced by a proxy's HTML
    page, the engine's X-Run-Id kept. It was recorded FAILED with no run id; the run
    may be scanning -- collected by the header's id, and pending with it when it
    cannot be read."""
    from pentest.models import PentestScan

    fx = load(PR71, "scan-failed-after-registration")
    launch = copy.deepcopy(launch_of(fx, "/api/scan"))
    run_id = launch["body"]["run_id"]
    launch["body"] = "<html>502 Bad Gateway</html>"
    assert launch["headers"]["x-run-id"] == run_id
    engine([launch, reads_of(fx)[0]])
    monkeypatch.setattr(cec, "SCAN_COLLECT_SECONDS", 0)

    response = scan_through_view(analyst, engagement)

    assert response.status_code == 202
    scan = PentestScan.objects.get(uuid=response.data["scan_id"])
    assert scan.status == PentestScan.STATUS_PENDING
    assert scan.engine_run_id == run_id


def test_a_retest_500_whose_body_a_proxy_replaced_is_running_by_its_x_run_id(engine):
    fx = load(PR71, "retest-failed-after-registration")
    launch = copy.deepcopy(launch_of(fx, "/api/remediation/retest"))
    launch["body"] = "<html>502 Bad Gateway</html>"
    engine([launch])

    reading = client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])

    assert reading["phase"] == "running"
    assert reading["stop_id"] == launch["headers"]["x-run-id"]


def test_a_retest_verdict_whose_run_still_reads_running_is_not_marked_stopped(engine):
    """Derived: #71's verdict with `state: "running"` and no stop named. It was
    marked stopped_after_recording "running" -- a stop nobody made. Its run may
    still be going: read on, stoppable by its id."""
    fx = load(PR71, "retest-stopped-after-recording")
    launch = copy.deepcopy(launch_of(fx, "/api/remediation/retest"))
    launch["body"]["state"] = "running"
    launch["body"].pop("stopped_after_recording", None)
    engine([launch])

    reading = client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])

    assert reading["answer"] == "verdict"
    assert reading["stopped_after_recording"] is None
    assert reading["stop_id"] == launch["body"]["run_id"]


def test_a_retest_verdict_on_a_run_that_did_not_complete_is_marked_stopped_even_unnamed(engine):
    """B5. #71's verdict on a run that ended aborted, with no stop named: it is a
    verdict filed before a stop landed, and says so."""
    fx = load(PR71, "retest-stopped-after-recording")
    launch = copy.deepcopy(launch_of(fx, "/api/remediation/retest"))
    launch["body"].pop("stopped_after_recording", None)
    assert launch["body"]["state"] == "aborted"
    engine([launch])

    reading = client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])

    assert reading["stopped_after_recording"] == "aborted"
    assert reading["stop_id"] is None


@pytest.mark.parametrize("run_id", [_DROP, "   ", None])
def test_a_202_retest_status_naming_no_run_is_refused_and_says_there_is_no_stop_handle(engine, run_id):
    fx = load(PR71, "retest-running-then-verdict")
    launch = copy.deepcopy(launch_of(fx, "/api/remediation/retest"))
    if run_id is _DROP:
        launch["body"].pop("run_id")
    else:
        launch["body"]["run_id"] = run_id
    engine([launch])

    with pytest.raises(EngineError) as raised:
        client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])

    assert raised.value.kind == ENGINE_UNREADABLE
    assert "no stop handle" in str(raised.value)


def test_a_retest_status_whose_run_is_aborting_is_still_running_and_stoppable(engine):
    """B3. `aborting` is a run whose stop has not landed yet: still going, and
    stoppable by its id -- never read as ended."""
    fx = load(PR71, "retest-stopped-while-waiting")
    launch = copy.deepcopy(launch_of(fx, "/api/remediation/retest"))
    launch["body"]["state"] = "aborting"
    engine([launch])

    reading = client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])

    assert reading["phase"] == "running"
    assert reading["stop_id"] == launch["body"]["run_id"]


@pytest.mark.parametrize("state", [_DROP, None, "running"])
def test_a_status_read_that_says_done_with_no_end_state_is_still_running_with_its_id(engine, state):
    """Derived: #71's 202 collected, the status read answering `done: true` with its
    end state dropped (or null, or not an end). It says nothing about how the run
    ended: still running, with its id -- never a failed scan ("Scan None")."""
    fx = load(PR71, "scan-running-then-completed")
    launch = launch_of(fx, "/api/scan")
    read = copy.deepcopy(reads_of(fx)[-1])
    if state is _DROP:
        read["body"].pop("state")
    else:
        read["body"]["state"] = state
    assert read["body"]["done"] is True
    engine([launch, read])

    with pytest.raises(ScanUncollected) as raised:
        client().run_scan(TARGET, engagement_ref=ENGAGEMENT)

    assert raised.value.run_id == launch["body"]["run_id"]



# ---------------------------------------------------------------------------
# Round 5 (E3): the round-4 rules on every launch path. A run not known to have
# ended is running WITH its stop id; X-Run-Id is honoured whenever the body names
# no run. All derived from the recordings, one thing changed.
# ---------------------------------------------------------------------------


def _retest_launch(scenario, **change):
    launch = copy.deepcopy(launch_of(load(PR71, scenario), "/api/remediation/retest"))
    launch["body"].update(change)
    return launch


@pytest.mark.parametrize("state", [None, _DROP, "starting", "Running"])
def test_a_retest_status_with_no_or_an_unknown_end_state_is_running_with_its_stop(engine, state):
    """A 200 `answer: "status"` whose `state` was lost, or is one this backend does
    not know, says nothing about whether the run ended. It was read
    `ended_without_verdict` with `stop_id` None: the only stop handle dropped."""
    launch = _retest_launch("retest-stopped-while-waiting")
    assert launch["status"] == 200 and launch["body"]["answer"] == "status"
    if state is _DROP:
        launch["body"].pop("state")
    else:
        launch["body"]["state"] = state
    engine([launch])

    reading = client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])

    assert reading["phase"] == "running"
    assert reading["stop_id"] == launch["body"]["run_id"]


def test_a_retest_status_that_completed_without_a_verdict_is_still_ended_with_nothing_to_stop(engine):
    launch = _retest_launch("retest-stopped-while-waiting", state="completed")
    engine([launch])

    reading = client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])

    assert reading["phase"] == "ended_without_verdict"
    assert reading["stop_id"] is None


@pytest.mark.parametrize("state", ["starting", "Running", "aborting", "queued"])
def test_a_retest_verdict_whose_run_state_is_not_an_end_keeps_its_stop_and_is_not_marked_stopped(engine, state):
    """E3, and the killer for C12 (`aborting` read as an end): a verdict whose run
    reads a state that is not an end -- going, a stop not landed yet, or one this
    backend does not know -- was marked stopped_after_recording that state, a stop
    nobody made, and lost its stop handle."""
    launch = _retest_launch("retest-stopped-after-recording", state=state)
    launch["body"].pop("stopped_after_recording", None)
    engine([launch])

    reading = client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])

    assert reading["answer"] == "verdict"
    assert reading["stopped_after_recording"] is None
    assert reading["stop_id"] == launch["body"]["run_id"]


@pytest.mark.parametrize("state", [None, _DROP, "starting"])
def test_a_retest_run_record_done_with_no_or_an_unknown_end_state_is_running_with_its_stop(engine, state):
    fx = load(PR71, "retest-running-then-verdict")
    launch = launch_of(fx, "/api/remediation/retest")
    read = copy.deepcopy(reads_of(fx)[-1])
    read["body"]["done"] = True
    if state is _DROP:
        read["body"].pop("state")
    else:
        read["body"]["state"] = state
    engine([launch, read])

    first = client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])
    reading = client().retest_status(first["stop_id"])

    assert reading["phase"] == "running"
    assert reading["stop_id"] == launch["body"]["run_id"]


@pytest.mark.parametrize("status, body", [
    (202, "<html>gateway page</html>"),
    (200, "{\"truncated"),
])
def test_a_retest_2xx_whose_body_cannot_be_read_is_running_by_its_x_run_id(engine, status, body):
    """Killer for C15 (an unreadable 2xx with X-Run-Id raises): the engine took the
    retest and named its run in the header."""
    launch = {**_retest_launch("retest-running-then-verdict"), "status": status, "body": body,
              "headers": {"x-run-id": "rt-9"}}
    engine([launch])

    reading = client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])

    assert reading["phase"] == "running"
    assert reading["stop_id"] == "rt-9"


@pytest.mark.parametrize("status", [202, 200])
def test_a_retest_status_naming_no_run_is_running_by_its_x_run_id(engine, status):
    """The body lost its `run_id`; the header names the run: never refused, and
    never a run with no stop handle."""
    launch = _retest_launch("retest-running-then-verdict")
    launch["status"] = status
    launch["body"].pop("run_id")
    launch["headers"] = {"x-run-id": "rt-9"}
    engine([launch])

    reading = client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])

    assert reading["phase"] == "running"
    assert reading["stop_id"] == "rt-9"


@pytest.mark.parametrize("status, body", [
    (502, "<html>502 Bad Gateway</html>"),
    (500, {"answer": "status", "state": None, "error": "database is locked"}),
    (200, {"error": "upstream reset"}),
])
def test_a_retest_answer_whose_body_names_no_run_is_running_by_its_x_run_id(engine, status, body):
    launch = {**_retest_launch("retest-running-then-verdict"), "status": status, "body": body,
              "headers": {"x-run-id": "rt-9"}}
    engine([launch])

    reading = client().retest_finding(1, ENGAGEMENT, scope=["offline.invalid"])

    assert reading["phase"] == "running"
    assert reading["stop_id"] == "rt-9"


def test_a_retest_refusal_whose_body_names_its_run_is_still_read_by_the_body(engine):
    """#71's 429 names its run in the body and the header: the body says it never
    started, and nothing is left to stop."""
    fx, replay, launch, reading = _retest(engine, PR71, "retest-queue-full")
    assert launch["headers"]["x-run-id"] == launch["body"]["run_id"]
    assert reading["phase"] == "refused"
    assert reading["stop_id"] is None


def _scan_with_header(status, body, *, where=PR71, scenario="scan-running-then-completed"):
    fx = load(where, scenario)
    launch = copy.deepcopy(launch_of(fx, "/api/scan"))
    run_id = launch["body"]["run_id"]
    launch["status"] = status
    launch["body"] = body(copy.deepcopy(launch["body"])) if callable(body) else body
    launch["headers"] = {"x-run-id": run_id}
    return fx, launch, run_id


def _without_run(body):
    body.pop("run_id")
    return body


@pytest.mark.parametrize("status, body", [
    (500, lambda b: {"answer": "status", "state": None, "error": "database is locked"}),
    (202, _without_run),
    (200, lambda b: {"error": "upstream reset"}),
    (502, "<html>502 Bad Gateway</html>"),
    (504, "gateway timeout"),
], ids=["500-status-no-run", "202-status-no-run", "200-proxy-json", "502-proxy-page", "504-proxy-text"])
def test_a_scan_answer_whose_body_names_no_run_is_collected_by_its_x_run_id(engine, status, body):
    """E3: each was a refusal, a failure, or -- the 200 with no `answer` -- an old
    engine's synchronous result: "upstream reset" recorded as a completed scan, while
    the run the header names may be scanning the customer."""
    fx, launch, run_id = _scan_with_header(status, body)
    replay = engine([launch, *reads_of(fx)])

    result = client().run_scan(TARGET, engagement_ref=ENGAGEMENT)

    assert result == reads_of(fx)[-1]["body"]["result"]
    assert ("GET", f"/api/scans/{run_id}", None) in replay.sent


def test_a_scan_answer_naming_no_run_whose_x_run_id_cannot_be_collected_stays_pending_with_it(
        engine, analyst, engagement, monkeypatch):
    """End to end through the scan view: a 502 proxy page with the engine's X-Run-Id.
    It was recorded FAILED with no run id."""
    from pentest.models import PentestScan

    fx, launch, run_id = _scan_with_header(502, "<html>502 Bad Gateway</html>")
    engine([launch, reads_of(fx)[0]])
    monkeypatch.setattr(cec, "SCAN_COLLECT_SECONDS", 0)

    response = scan_through_view(analyst, engagement)

    assert response.status_code == 202
    scan = PentestScan.objects.get(uuid=response.data["scan_id"])
    assert scan.status == PentestScan.STATUS_PENDING
    assert scan.engine_run_id == run_id


def test_a_scan_refusal_whose_body_names_its_run_is_still_read_by_the_body(engine):
    """#71's 429 and its 500 `state: "failed"` name their run in the body and in the
    header: they never started, and are the refusals they were."""
    for scenario in ("scan-queue-full", "scan-failed-before-start"):
        fx = load(PR71, scenario)
        launch = launch_of(fx, "/api/scan")
        assert launch["headers"]["x-run-id"] == launch["body"]["run_id"]
        replay = engine([launch])
        with pytest.raises(EngineError) as raised:
            client().run_scan(TARGET, engagement_ref=ENGAGEMENT)
        assert raised.value.run_id is None
        assert [m for m, _, _ in replay.sent] == ["POST"]
