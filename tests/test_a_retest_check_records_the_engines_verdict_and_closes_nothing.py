"""A retest check records the engine's verdict and closes nothing (owner decision 8).

The engine's retest answers ``closed``, ``still_open`` or ``inconclusive``: "an absence
on a retest that looked, not proof of a fix". It carries none of what the closure gate
reads, so it enters this record as a RETEST CHECK -- ``RetestCheck``, pulled by this
backend with its own operator key through ``POST /api/assurance/findings/<uuid>/
retest-checks/collect/`` (``assurance.retest_checks``) -- and never as closure evidence:
``finding-closure-evidence`` stays Minotaur's replay record.

What this module holds:

* a completed run's verdict is one row, and the finding is what it was: status,
  ``last_seen``, the retest flag, the remediation state and the closure standing are
  equal before and after; no ``RetestClosureEvidence`` and no ``Evidence`` row appears,
  and nothing is forwarded to Minotaur;
* a run aborted after its check was filed is recorded, ``stopped_after_recording``; a
  run stopped before a verdict, failed or still going records nothing and is answered
  with its honest phase;
* identity: a scan not in this record is 404; another type, another deployment or
  another target host is 422; several findings of the type 409 naming them; a twin the
  engine does not list under the scan run 422; nothing is written for any of them;
* the engine's own 404 is a 404, an unreachable engine a 503, nothing written;
* a collect never launches: no ``POST /api/scan``, no ``POST /api/remediation/retest``;
* the same run collected twice is one row, the second answering the existing row;
* scoping: a finding the caller cannot see is 404 as detail is; anonymous is 401; a
  viewer is 403;
* a ``closed`` check leaves the closure standing ``not_closable`` with "no closure
  evidence recorded", and the gate still refuses the close; a ``still_open`` check does
  not refresh ``last_seen``;
* the finding serves its latest checks, and nothing it or the list route serves carries
  the login the scan's target was launched with; the list is paginated and scoped;
* the engine is read before and outside any transaction, and the write touches no
  PentestScan, Engagement, Finding, Evidence or closure-evidence row -- one insert into
  the check's own table;
* the routes are classified not stops (``safety.stops``) for what they do.

The engine here is the real HTTP stub of tests/test_a_lost_launch_answer_reads_unknown,
serving two more reads: a retest run's record and the twins listed under a scan run.
"""

from __future__ import annotations

import copy
import json
import uuid
from datetime import timedelta
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, connection, transaction
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from ai_engine.services import cyberengine_client as cec
from assurance.ingest import deployment_for_scan
from assurance.models import Deployment, Evidence, Finding, RetestClosureEvidence
from assurance.retest_closure import NOT_CLOSABLE, closure_standing
from pentest.models import Engagement, PentestScan
from safety import stops
from tests.test_a_lost_launch_answer_reads_unknown import TARGET, Engine, _closed_port_url

pytestmark = pytest.mark.django_db

User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
#: athena-engine's own record of a retest run that completed with a verdict (#71,
#: f4610ae): the last GET /api/scans/{run_id} of the recorded exchange.
RECORDING = REPO / "tests" / "fixtures" / "engine_launch" / "pr71-f4610ae" / "retest-running-then-verdict.json"
#: The login a tenant may put in a target: it must come out of nothing this record serves.
LOGIN = "scanner:s3cret-login-for-this-test"
LOGIN_TARGET = f"https://{LOGIN}@offline.invalid/"


def _checks():
    """The model, imported where it is used: on a backend without it every test here
    fails on its own assertion rather than at collection."""
    from assurance.models import RetestCheck

    return RetestCheck


def _recorded_retest_run() -> dict:
    exchanges = json.loads(RECORDING.read_text())["exchanges"]
    reads = [
        e for e in exchanges
        if e["request"]["method"] == "GET" and e["request"]["path"].startswith("/api/scans/")
    ]
    return reads[-1]["body"]


RECORDED = _recorded_retest_run()


class RetestEngine(Engine):
    """The engine of tests/test_a_lost_launch_answer_reads_unknown, serving two more reads:
    a retest run's record (``GET /api/scans/{run_id}``, from ``runs`` as every run is) and
    the decision twins listed under a scan run (``GET /api/decisions?run_id=``, from
    ``twins``, filtered by ``finding_type`` as the engine filters)."""

    def __init__(self):
        super().__init__()
        self.twins: dict[str, list[dict]] = {}

    def read_run(self, h):
        if h.path.startswith("/api/decisions"):
            query = parse_qs(urlparse(h.path).query)
            run_id = (query.get("run_id") or [None])[0]
            wanted = (query.get("finding_type") or [None])[0]
            with self.lock:
                twins = [
                    copy.deepcopy(t) for t in self.twins.get(run_id, [])
                    if wanted is None or t.get("finding_type") == wanted
                ]
            return h.answer(200, {"tenant": "default", "decisions": twins})
        return super().read_run(h)

    def reads_of(self, path):
        return sum(1 for method, seen, _ in self.requests if method == "GET" and seen == path)

    def posts(self):
        return [path for method, path, _ in self.requests if method == "POST" and path != "/defend"]

    def exchanges(self):
        """Every request but the defender gateway's ``/defend``, which the middleware asks
        about every API request before the view runs (audit.middleware)."""
        return [(method, path) for method, path, _ in self.requests if path != "/defend"]


@pytest.fixture()
def engine(settings, monkeypatch):
    for name in ("NO_PROXY", "no_proxy"):
        monkeypatch.setenv(name, "127.0.0.1,localhost,.invalid")
    served = RetestEngine()
    settings.CYBERENGINE_URL = served.base
    settings.CYBERENGINE_OPERATOR_KEY = "operator-key-for-this-test"
    monkeypatch.setattr(cec, "ENGINE_TIMEOUT", (2.0, 3.0))
    yield served
    served.close()


# ---------------------------------------------------------------------------
# The scene: a scan of this record, its deployment, one finding, and the engine's words
# ---------------------------------------------------------------------------


def _user(role=None):
    return User.objects.create_user(
        username=f"u-{uuid.uuid4().hex[:10]}", password=None, role=role or User.Roles.ANALYST
    )


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


def _engagement(user):
    now = timezone.now()
    return Engagement.objects.create(
        created_by=user, name="Client Q3", client_name="Client", status="running", scope_hosts=["offline.invalid"],
        testing_window_start=now - timedelta(hours=1), testing_window_end=now + timedelta(hours=1),
    )


def _twin(twin_id, run_id, finding_type, target):
    return {"id": twin_id, "tenant": "default", "run_id": run_id, "target": target, "finding_type": finding_type,
            "inventory_digest": None, "captured_at": "2026-10-22T12:00:00+00:00"}


def _scene(engine, *, user=None, finding_type="xss", target=TARGET, with_engagement=True):
    """A scan of this record that ran under the engine's scan run (the twin's run), its
    deployment as ingest keys it, ONE finding of ``finding_type`` in it owing a retest,
    and the engine listing twin 1 of that type under the run. Returns (user, scan, finding)."""
    person = user or _user()
    scan = PentestScan.objects.create(
        user=person, engagement=_engagement(person) if with_engagement else None, target_url=target, consent=True,
        status=PentestScan.STATUS_COMPLETED, engine_run_id=str(uuid.uuid4()),
    )
    deployment = deployment_for_scan(scan)
    finding = Finding.objects.create(
        deployment=deployment, scan=scan, fingerprint=f"fp-{uuid.uuid4().hex[:8]}", finding_type=finding_type,
        title=finding_type, severity="high", retest_required=True,
    )
    with engine.lock:
        engine.twins[scan.engine_run_id] = [_twin(1, scan.engine_run_id, finding_type, target)]
    return person, scan, finding


def _retest_run(run_id, *, verdict="closed", state="completed", finding_type="xss", target=TARGET, twin_id=1,
                detail=None, reason=None):
    """The engine's record of retest run ``run_id``, as athena-engine recorded one: the
    recorded completed run, with the verdict, type, target and twin a test names."""
    run = copy.deepcopy(RECORDED)
    run.update(run_id=run_id, state=state, done=True, reason=reason)
    result = run["result"]
    result.update(twin_id=twin_id, verdict=verdict, finding_type=finding_type, target=target, run_id=run_id)
    result["check"].update(twin_id=twin_id, verdict=verdict, finding_type=finding_type, target=target)
    if detail is not None:
        result["detail"] = detail
        result["check"]["detail"] = detail
    return run


def _stopped_before_a_verdict(run_id):
    return {"run_id": run_id, "kind": "retest", "target": TARGET, "state": "aborted", "done": True,
            "reason": "stopped by an operator", "result": {"stopped": True, "scan_incomplete": True},
            "key_hash": "operator-key-hash"}


def _failed(run_id):
    return {"run_id": run_id, "kind": "retest", "target": TARGET, "state": "failed", "done": True, "reason": None,
            "result": {"twin_id": 1, "verdict": "inconclusive", "detail": "the scanner raised", "finding_type": "xss",
                       "target": TARGET, "error": "the scanner raised"},
            "key_hash": "operator-key-hash"}


def _running(run_id):
    return {"run_id": run_id, "kind": "retest", "target": TARGET, "state": "running", "done": False, "reason": None,
            "result": None, "key_hash": "operator-key-hash"}


def _serve(engine, run):
    with engine.lock:
        engine.runs[run["run_id"]] = run
    return run["run_id"]


def _url(finding):
    return f"/api/assurance/findings/{finding.uuid}/retest-checks/"


def _collect(client, finding, run_id, twin_run_id):
    return client.post(_url(finding) + "collect/", {"run_id": run_id, "twin_run_id": twin_run_id}, format="json")


def _disposition(finding) -> dict:
    """Every field of the finding a check must leave alone, read from the row, and the
    closure standing as a reader is served it."""
    row = Finding.objects.get(pk=finding.pk)
    return {
        "status": row.status,
        "last_seen": row.last_seen,
        "retest_required": row.retest_required,
        "remediation_state": row.remediation_state,
        "closure": closure_standing(row),
    }


def _rows(finding=None):
    qs = _checks().objects.all()
    return qs.filter(finding=finding) if finding is not None else qs


# ---------------------------------------------------------------------------
# A verdict is one row, and the finding is what it was
# ---------------------------------------------------------------------------


def test_a_completed_runs_verdict_is_one_row_and_changes_no_field_of_the_finding(engine, monkeypatch):
    person, scan, finding = _scene(engine)
    run_id = _serve(engine, _retest_run(str(uuid.uuid4())))
    forwarded, recorded_evidence = [], []
    monkeypatch.setattr("assurance.closure_forward.queue", lambda record: forwarded.append(record))
    monkeypatch.setattr("assurance.views.record_closure_evidence", lambda *a, **k: recorded_evidence.append(a))
    monkeypatch.setattr("assurance.retest_closure.record_closure_evidence", lambda *a, **k: recorded_evidence.append(a))
    before = _disposition(finding)
    closure_rows, evidence_rows = RetestClosureEvidence.objects.count(), Evidence.objects.count()

    answer = _collect(_client(person), finding, run_id, scan.engine_run_id)

    assert answer.status_code == 201, answer.content
    body = answer.json()
    assert body["recorded"] is True
    check = body["check"]
    assert check["engine_run_id"] == run_id
    assert check["verdict"] == "closed" and check["verdict_known"] is True
    assert check["state"] == "completed" and check["stopped_after_recording"] is False
    assert check["twin_id"] == 1 and check["twin_run_id"] == scan.engine_run_id
    assert check["scan_record_id"] == str(RECORDED["result"]["scan_record_id"])
    assert check["engine_checked_at"] is not None and check["collected_at"] is not None
    assert check["collected_by"] == person.username
    assert "An absence on retest, not proof of a fix" in check["detail"]
    (row,) = _rows(finding)
    assert row.engine_run_id == run_id and row.collected_by == person and row.raw["verdict"] == "closed"
    # The finding is what it was, in every field a check must leave alone.
    assert _disposition(finding) == before
    assert body["closure"] == before["closure"]
    assert RetestClosureEvidence.objects.count() == closure_rows, "a check became closure evidence"
    assert Evidence.objects.count() == evidence_rows, "a check added an Evidence row"
    assert forwarded == [], "a check was forwarded to Minotaur's dataset"
    assert recorded_evidence == [], "a check was recorded as closure evidence"
    assert engine.posts() == [], "a collect sent something to the engine"


def test_a_run_aborted_after_its_check_was_filed_is_recorded_as_stopped_after_recording(engine):
    person, scan, finding = _scene(engine)
    run_id = _serve(engine, _retest_run(str(uuid.uuid4()), state="aborted", reason="stopped by an operator"))
    before = _disposition(finding)

    answer = _collect(_client(person), finding, run_id, scan.engine_run_id)

    assert answer.status_code == 201, answer.content
    check = answer.json()["check"]
    assert check["state"] == "aborted" and check["stopped_after_recording"] is True
    assert check["verdict"] == "closed"
    (row,) = _rows(finding)
    assert row.state == "aborted" and row.stopped_after_recording is True
    assert _disposition(finding) == before


@pytest.mark.parametrize(
    "record, status, phase",
    [
        (_stopped_before_a_verdict, 200, "stopped"),
        (_failed, 200, "failed"),
        (_running, 202, "running"),
    ],
    ids=["stopped-before-a-verdict", "failed", "running"],
)
def test_a_run_without_a_verdict_records_nothing_and_is_answered_with_its_phase(engine, record, status, phase):
    engine.finish_on_read = False
    person, scan, finding = _scene(engine)
    run_id = _serve(engine, record(str(uuid.uuid4())))
    before = _disposition(finding)

    answer = _collect(_client(person), finding, run_id, scan.engine_run_id)

    assert answer.status_code == status, answer.content
    body = answer.json()
    assert body["phase"] == phase and body["recorded"] is False and body["run_id"] == run_id
    assert "nothing was recorded" in body["detail"]
    assert not _rows().exists(), "a run without a verdict was recorded"
    assert _disposition(finding) == before
    assert engine.posts() == []


# ---------------------------------------------------------------------------
# Identity: every check holds, or nothing is written
# ---------------------------------------------------------------------------


def test_a_scan_that_is_not_in_this_record_is_404_and_nothing_is_written(engine):
    person, scan, finding = _scene(engine)
    run_id = _serve(engine, _retest_run(str(uuid.uuid4())))
    legacy_run = str(uuid.uuid4())  # a dashboard-direct scan: no PentestScan ran under it

    answer = _collect(_client(person), finding, run_id, legacy_run)

    assert answer.status_code == 404, answer.content
    assert "not in this record" in answer.json()["detail"]
    assert answer.json()["recorded"] is False
    assert not _rows().exists()


def test_a_scan_whose_deployment_was_never_made_is_422_and_nothing_is_written(engine):
    person, scan, finding = _scene(engine)
    run_id = _serve(engine, _retest_run(str(uuid.uuid4())))
    # A scan of this record whose run was never ingested: no deployment of its own.
    other = PentestScan.objects.create(
        user=person, target_url="https://other.invalid/", consent=True, status=PentestScan.STATUS_PENDING,
        engine_run_id=str(uuid.uuid4()),
    )
    deployments = Deployment.objects.count()

    answer = _collect(_client(person), finding, run_id, other.engine_run_id)

    assert answer.status_code == 422, answer.content
    assert "never ingested" in answer.json()["detail"]
    assert Deployment.objects.count() == deployments, "the collect created a deployment"
    assert not _rows().exists()


def test_a_verdict_of_another_type_is_422_and_nothing_is_written(engine):
    person, scan, finding = _scene(engine, finding_type="xss")
    run_id = _serve(engine, _retest_run(str(uuid.uuid4()), finding_type="sql_injection"))

    answer = _collect(_client(person), finding, run_id, scan.engine_run_id)

    assert answer.status_code == 422, answer.content
    assert "'sql_injection'" in answer.json()["detail"] and "'xss'" in answer.json()["detail"]
    assert not _rows().exists()


def test_a_twins_scan_of_another_deployment_is_422_and_nothing_is_written(engine):
    person, scan, finding = _scene(engine)
    _other_person, other_scan, _other_finding = _scene(engine, target="https://elsewhere.invalid/")
    run_id = _serve(engine, _retest_run(str(uuid.uuid4()), target="https://elsewhere.invalid/"))

    answer = _collect(_client(person), finding, run_id, other_scan.engine_run_id)

    assert answer.status_code == 422, answer.content
    assert "another deployment" in answer.json()["detail"]
    assert not _rows().exists()


def test_a_verdict_on_another_target_host_is_422_and_nothing_is_written(engine):
    person, scan, finding = _scene(engine)
    run_id = _serve(engine, _retest_run(str(uuid.uuid4()), target="https://admin.offline.invalid/"))

    answer = _collect(_client(person), finding, run_id, scan.engine_run_id)

    assert answer.status_code == 422, answer.content
    detail = answer.json()["detail"]
    assert "'admin.offline.invalid'" in detail and "'offline.invalid'" in detail
    assert not _rows().exists()


def test_several_findings_of_the_type_are_409_naming_the_candidates(engine):
    person, scan, finding = _scene(engine)
    twin_of_a_second_signature = Finding.objects.create(
        deployment=finding.deployment, scan=scan, fingerprint="fp-second-signature", finding_type="xss",
        title="xss", severity="high", retest_required=True,
    )
    run_id = _serve(engine, _retest_run(str(uuid.uuid4())))

    answer = _collect(_client(person), finding, run_id, scan.engine_run_id)

    assert answer.status_code == 409, answer.content
    body = answer.json()
    assert sorted(body["candidates"]) == sorted([str(finding.uuid), str(twin_of_a_second_signature.uuid)])
    assert "2 findings of type 'xss'" in body["detail"]
    assert not _rows().exists()


def test_a_twin_the_engine_does_not_list_under_the_scan_run_is_422_and_nothing_is_written(engine):
    person, scan, finding = _scene(engine)
    run_id = _serve(engine, _retest_run(str(uuid.uuid4()), twin_id=99))

    answer = _collect(_client(person), finding, run_id, scan.engine_run_id)

    assert answer.status_code == 422, answer.content
    assert "lists no twin 99" in answer.json()["detail"]
    assert engine.reads_of(f"/api/scans/{run_id}") == 1
    assert not _rows().exists()


# ---------------------------------------------------------------------------
# The engine: its own 404 is a 404, unreachable is a 503; never a launch
# ---------------------------------------------------------------------------


def test_a_run_the_engine_does_not_have_is_404_and_nothing_is_written(engine):
    person, scan, finding = _scene(engine)
    run_id = str(uuid.uuid4())  # another tenant's, or none: the engine answers no such run

    answer = _collect(_client(person), finding, run_id, scan.engine_run_id)

    assert answer.status_code == 404, answer.content
    assert answer.json()["detail"] == f"the engine has no run {run_id} this backend can read"
    assert not _rows().exists()


def test_an_engine_that_cannot_be_read_is_503_and_nothing_is_written(engine, settings):
    person, scan, finding = _scene(engine)
    run_id = str(uuid.uuid4())
    settings.CYBERENGINE_URL = _closed_port_url()

    answer = _collect(_client(person), finding, run_id, scan.engine_run_id)

    assert answer.status_code == 503, answer.content
    body = answer.json()
    assert body["recorded"] is False and body["engine"] == "unreachable"
    assert "Nothing was written" in body["detail"]
    assert "127.0.0.1" not in json.dumps(body), "the answer quoted the engine's address"
    assert not _rows().exists()


def test_no_engine_configured_is_503_and_nothing_is_written(engine, settings):
    person, scan, finding = _scene(engine)
    settings.CYBERENGINE_OPERATOR_KEY = ""

    answer = _collect(_client(person), finding, str(uuid.uuid4()), scan.engine_run_id)

    assert answer.status_code == 503, answer.content
    assert answer.json()["recorded"] is False
    assert engine.exchanges() == []
    assert not _rows().exists()


def test_a_collect_never_launches(engine):
    person, scan, finding = _scene(engine)
    completed = _serve(engine, _retest_run(str(uuid.uuid4())))
    stopped = _serve(engine, _stopped_before_a_verdict(str(uuid.uuid4())))
    failed = _serve(engine, _failed(str(uuid.uuid4())))
    client = _client(person)

    answers = [
        _collect(client, finding, completed, scan.engine_run_id).status_code,
        _collect(client, finding, stopped, scan.engine_run_id).status_code,
        _collect(client, finding, failed, scan.engine_run_id).status_code,
        _collect(client, finding, str(uuid.uuid4()), scan.engine_run_id).status_code,
    ]

    assert answers == [201, 200, 200, 404], "the collects did not do their work, so this proved nothing"
    assert engine.posts() == [], "a collect sent a POST to the engine"
    assert engine.launches == [] and engine.aborts() == []
    reads = [path for method, path, _ in engine.requests if method == "GET"]
    assert reads, "no collect read the engine"
    assert all(path.startswith("/api/scans/") or path.startswith("/api/decisions?") for path in reads), reads


# ---------------------------------------------------------------------------
# Twice is once
# ---------------------------------------------------------------------------


def test_the_same_run_collected_twice_is_one_row_and_the_second_answers_the_existing_row(engine):
    person, scan, finding = _scene(engine)
    run_id = _serve(engine, _retest_run(str(uuid.uuid4())))
    client = _client(person)

    first = _collect(client, finding, run_id, scan.engine_run_id)
    second = _collect(client, finding, run_id, scan.engine_run_id)

    assert first.status_code == 201, first.content
    assert second.status_code == 200, second.content
    assert second.json()["recorded"] is False
    assert second.json()["check"] == first.json()["check"]
    assert _rows().count() == 1
    assert engine.reads_of(f"/api/scans/{run_id}") == 1, "the second collect read the engine again"


def test_a_second_row_for_the_same_run_cannot_be_inserted(engine):
    """The run id is unique in the table itself, so two collects that raced past the
    lookup land on the constraint and the run is one row whatever the order (the fire-twice
    matrix drives that race; this holds the constraint it lands on)."""
    person, scan, finding = _scene(engine)
    run_id = _serve(engine, _retest_run(str(uuid.uuid4())))
    assert _collect(_client(person), finding, run_id, scan.engine_run_id).status_code == 201
    (row,) = _rows(finding)

    with pytest.raises(IntegrityError), transaction.atomic():
        _checks().objects.create(
            finding=finding, engine_run_id=run_id, twin_id=row.twin_id, twin_run_id=row.twin_run_id,
            verdict="closed", verdict_known=True, state="completed", stopped_after_recording=False,
        )

    assert _rows().count() == 1


def test_a_run_already_recorded_against_another_finding_is_409_and_nothing_is_written(engine):
    person, scan, finding = _scene(engine)
    run_id = _serve(engine, _retest_run(str(uuid.uuid4())))
    assert _collect(_client(person), finding, run_id, scan.engine_run_id).status_code == 201
    _other_person, other_scan, other_finding = _scene(engine, user=person, target="https://elsewhere.invalid/")

    answer = _collect(_client(person), other_finding, run_id, other_scan.engine_run_id)

    assert answer.status_code == 409, answer.content
    assert "already recorded" in answer.json()["detail"]
    assert _rows().count() == 1 and _rows(other_finding).count() == 0


# ---------------------------------------------------------------------------
# Who may
# ---------------------------------------------------------------------------


def test_a_finding_the_caller_cannot_see_is_404_as_detail_is_and_anonymous_is_401(engine):
    person, scan, finding = _scene(engine)
    run_id = _serve(engine, _retest_run(str(uuid.uuid4())))
    stranger = _client(_user(User.Roles.VIEWER))
    other_viewer_owns_nothing = _user(User.Roles.VIEWER)

    assert stranger.get(f"/api/assurance/findings/{finding.uuid}/").status_code == 404
    assert stranger.get(_url(finding)).status_code == 404
    # A viewer who could see the finding may not collect: the role refuses before the lookup.
    Deployment.objects.filter(pk=finding.deployment_id).update(owner=other_viewer_owns_nothing)
    viewer = _client(other_viewer_owns_nothing)
    assert viewer.get(_url(finding)).status_code == 200
    assert _collect(viewer, finding, run_id, scan.engine_run_id).status_code == 403
    anonymous = _client()
    assert _collect(anonymous, finding, run_id, scan.engine_run_id).status_code == 401
    assert anonymous.get(_url(finding)).status_code == 401
    assert not _rows().exists()
    assert engine.exchanges() == [], "a refused caller reached the engine"


@pytest.mark.parametrize(
    "body, field",
    [
        ({"twin_run_id": "r"}, "run_id"),
        ({"run_id": "r"}, "twin_run_id"),
        ({"run_id": 7, "twin_run_id": "r"}, "run_id"),
        ({"run_id": "r", "twin_run_id": "  "}, "twin_run_id"),
        ({"run_id": "../failsafe/state", "twin_run_id": "r"}, "run_id"),
        ({"run_id": "active?x=1", "twin_run_id": "r"}, "run_id"),
    ],
)
def test_a_body_that_does_not_name_both_run_ids_is_400_naming_the_field_and_reaches_no_engine(engine, body, field):
    person, _scan, finding = _scene(engine)

    answer = _client(person).post(_url(finding) + "collect/", body, format="json")

    assert answer.status_code == 400, answer.content
    assert list(answer.json()) == [field]
    assert engine.exchanges() == []
    assert not _rows().exists()


# ---------------------------------------------------------------------------
# Not closure evidence: the gate still refuses, and last_seen stays
# ---------------------------------------------------------------------------


def test_a_closed_check_leaves_the_closure_not_closable_and_the_gate_still_refuses_the_close(engine):
    admin = _user(User.Roles.ADMIN)
    person, scan, finding = _scene(engine, user=admin)
    run_id = _serve(engine, _retest_run(str(uuid.uuid4()), verdict="closed"))

    answer = _collect(_client(admin), finding, run_id, scan.engine_run_id)

    assert answer.status_code == 201, answer.content
    standing = answer.json()["closure"]
    assert standing["standing"] == NOT_CLOSABLE
    assert any(reason.startswith("no closure evidence recorded") for reason in standing["reasons"]), standing
    assert closure_standing(Finding.objects.get(pk=finding.pk)) == standing
    patched = _client(admin).patch(f"/api/assurance/findings/{finding.uuid}/", {"status": "closed"}, format="json")
    assert patched.status_code == 400, patched.content
    assert Finding.objects.get(pk=finding.pk).status == Finding.Status.OPEN


def test_a_still_open_check_does_not_refresh_last_seen(engine):
    person, scan, finding = _scene(engine)
    seen_a_week_ago = timezone.now() - timedelta(days=7)
    Finding.objects.filter(pk=finding.pk).update(last_seen=seen_a_week_ago, first_seen=seen_a_week_ago)
    run_id = _serve(engine, _retest_run(str(uuid.uuid4()), verdict="still_open"))

    answer = _collect(_client(person), finding, run_id, scan.engine_run_id)

    assert answer.status_code == 201, answer.content
    assert answer.json()["check"]["verdict"] == "still_open"
    row = Finding.objects.get(pk=finding.pk)
    assert row.last_seen == seen_a_week_ago, "a still_open check refreshed last_seen"
    assert row.status == Finding.Status.OPEN and row.retest_required is True


# ---------------------------------------------------------------------------
# Served: the latest checks on the finding, the whole list on its route, nothing sensitive
# ---------------------------------------------------------------------------


def test_the_finding_serves_its_latest_checks_and_nothing_it_serves_carries_the_targets_login(engine):
    person, scan, finding = _scene(engine, target=LOGIN_TARGET)
    quoted = f"xss was reported against {LOGIN_TARGET} on the retest, as it was on the scan: still there"
    runs = [
        _serve(engine, _retest_run(str(uuid.uuid4()), verdict="still_open", target=LOGIN_TARGET, detail=quoted))
        for _ in range(12)
    ]
    client = _client(person)
    for run_id in runs:
        assert _collect(client, finding, run_id, scan.engine_run_id).status_code == 201

    detail = client.get(f"/api/assurance/findings/{finding.uuid}/")
    listed = client.get(_url(finding))

    assert detail.status_code == 200 and listed.status_code == 200
    served = detail.json()["retest_checks"]
    assert len(served) == 10, "the finding serves its latest ten checks"
    assert [c["engine_run_id"] for c in served] == list(reversed(runs))[:10], "newest first"
    page = listed.json()
    assert page["count"] == 12 and len(page["results"]) == 12, page.keys()
    assert [c["engine_run_id"] for c in page["results"]] == list(reversed(runs))
    assert set(served[0]) == {
        "engine_run_id", "scan_record_id", "twin_id", "twin_run_id", "verdict", "verdict_known", "detail",
        "state", "stopped_after_recording", "engine_checked_at", "collected_at", "collected_by",
    }
    for answer in (detail, listed):
        assert LOGIN not in answer.content.decode(), "an answer carried the target's login"
    for row in _rows(finding):
        assert LOGIN not in row.detail and LOGIN not in json.dumps(row.raw), "a row kept the target's login"
        assert "offline.invalid" in row.detail, "the scrub took more than the login"
    # The list is scoped as the finding is.
    assert _client(_user(User.Roles.VIEWER)).get(_url(finding)).status_code == 404


def test_a_verdict_this_backend_does_not_know_is_kept_as_the_engine_sent_it_and_said_so(engine):
    person, scan, finding = _scene(engine)
    run_id = _serve(engine, _retest_run(str(uuid.uuid4()), verdict="partially_mitigated"))

    answer = _collect(_client(person), finding, run_id, scan.engine_run_id)

    assert answer.status_code == 201, answer.content
    check = answer.json()["check"]
    assert check["verdict"] == "partially_mitigated" and check["verdict_known"] is False


# ---------------------------------------------------------------------------
# Safety: the engine read is outside any transaction; the write is one row of one table
# ---------------------------------------------------------------------------


_ROWS_A_CHECK_NEVER_TOUCHES = (
    "pentest_pentestscan", "pentest_engagement", "assurance_finding", "assurance_evidence",
    "assurance_retestclosureevidence", "assurance_closureevidenceforward", "assurance_deployment",
)


@pytest.mark.django_db(transaction=True)
def test_the_engine_is_read_before_and_outside_any_transaction_and_the_write_touches_only_the_new_table(
    engine, monkeypatch,
):
    person, scan, finding = _scene(engine)
    run_id = _serve(engine, _retest_run(str(uuid.uuid4())))
    seen = []
    real = cec.CyberEngineClient.retest_status

    def spying(self, named):
        seen.append({"in_atomic_block": connection.in_atomic_block, "rows": _rows().count()})
        return real(self, named)

    monkeypatch.setattr(cec.CyberEngineClient, "retest_status", spying)
    with CaptureQueriesContext(connection) as queries:
        answer = _collect(_client(person), finding, run_id, scan.engine_run_id)

    assert answer.status_code == 201, answer.content
    assert seen == [{"in_atomic_block": False, "rows": 0}], "the engine was read inside a transaction, or after a write"
    writes = [
        q["sql"] for q in queries.captured_queries
        if q["sql"].lstrip().upper().startswith(("INSERT", "UPDATE", "DELETE"))
    ]
    inserts = [sql for sql in writes if "assurance_retestcheck" in sql.lower()]
    assert len(inserts) == 1 and inserts[0].lstrip().upper().startswith("INSERT"), writes
    touched = [sql for sql in writes if any(table in sql.lower() for table in _ROWS_A_CHECK_NEVER_TOUCHES)]
    assert touched == [], touched


def test_the_routes_are_classified_as_not_stops_for_what_they_do():
    assert stops.NOT_STOPS["finding-retest-checks-collect"] == {
        "POST": (
            "collects a finished retest run's verdict from the engine and records it: a read of the engine "
            "and a write of this record; it starts and stops nothing"
        )
    }
    assert stops.NOT_STOPS["finding-retest-checks"] == {"GET": stops._READ}
    for name in ("finding-retest-checks", "finding-retest-checks-collect"):
        assert name not in stops.STOP_ROUTES and name not in stops.EXEMPT_ROUTES
