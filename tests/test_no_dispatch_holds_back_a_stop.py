"""No connector dispatch holds back a stop (#303).

A deployment whose dispatch policy opts into the decision trigger has its
qualifying findings pushed to its connectors when its decision becomes blocking --
and a pause is a blocking decision. The recompute route, which pauses and lifts,
scheduled that dispatch "on commit"; the route runs in autocommit, where a commit
hook runs at once, so the pause answered only after every finding had been pushed
to every connector. Measured on the release before: three findings and a
connector that takes five seconds to answer held a pause for 15.04 s, and a lift
or a plain recompute landing on a blocking decision for 15.05 s. The transport's
timeout is (3.05, 10) seconds a push, so a hung ticketing system held a pause for
thirteen seconds per finding.

Now the stop records the dispatch as owed in its own transaction, commits and
answers, and the dispatch runs after it, in the background. A run claims what it
runs, so two runners never push one deployment at once; it checks before every
push that the decision which asked for it still holds; and what it does not
finish -- or never starts, its process gone -- stays recorded until a run does.

The timing tests MEASURE it: the connector here holds every push until the test
lets it go, or three seconds pass, and the stop must answer in under a second with
no push finished. They do not assert the structure that should make it fast; they
assert that it is.
"""

from __future__ import annotations

import io
import logging
import threading
import time
from datetime import timedelta

import pytest
from cryptography.fernet import Fernet
from django.contrib import admin as django_admin
from django.contrib.auth import get_user_model
from django.core.management import CommandError, call_command
from django.db import DatabaseError, OperationalError, connections, transaction
from django.test import RequestFactory, override_settings
from django.utils import timezone
from rest_framework.test import APIClient

from assurance import dispatch
from assurance.claims import derive_claims
from assurance.decision import recompute_decision
from assurance.models import (
    Asset,
    AssuranceClaim,
    ConnectorBinding,
    DataBoundary,
    DecisionDispatchDue,
    Deployment,
    DispatchAttempt,
    DispatchPolicy,
    Finding,
)

pytestmark = pytest.mark.django_db

User = get_user_model()

#: A stop alone takes milliseconds; the first request of a process pays for the
#: URLconf, which every test here pays before it measures.
PROMPT = 1.0
#: How long the connector holds a push the test has not let go of.
HOLD = 3.0

with_key = override_settings(ASSURANCE_CREDENTIAL_KEY=Fernet.generate_key().decode())


class _Answer:
    def __init__(self, status_code):
        self.status_code = status_code
        self.text = ""

    def json(self):
        return {"key": "SEC-1"} if self.status_code < 300 else {}


class HeldConnector:
    """A connector that holds every push until released (or ``HOLD`` passes), then
    answers ``status``. Counts the pushes it has finished."""

    def __init__(self, status=201):
        self.status = status
        self.release = threading.Event()
        self.started = 0
        self.finished = 0
        self.bodies = []
        self.headers = []
        self._lock = threading.Lock()

    def factory(self):
        return self

    def post(self, url, *, headers, json):
        with self._lock:
            self.started += 1
            self.bodies.append(repr(json))
            self.headers.append(dict(headers))
        self.release.wait(HOLD)
        with self._lock:
            self.finished += 1
        return _Answer(self.status)


def _background():
    return [t for t in threading.enumerate() if t.name.startswith("assurance-dispatch-")]


def _settle(timeout=30.0):
    """Wait until no background dispatch is running in this process."""
    deadline = time.monotonic() + timeout
    while _background() and time.monotonic() < deadline:
        time.sleep(0.02)
    assert not _background(), "a background dispatch was still running"


@pytest.fixture(autouse=True)
def _no_background_dispatch_outlives_its_test():
    yield
    _settle()


def _admin():
    return User.objects.create_user(username=f"a{User.objects.count()}", password="x", role=User.Roles.ADMIN)


def _client(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _findings(dep, count=2, severity="high"):
    """Open findings on ``dep``. Made BEFORE any policy exists, so the severity
    trigger has nothing to dispatch when they are saved."""
    for i in range(count):
        Finding.objects.create(
            deployment=dep, fingerprint=f"fp303-{dep.pk}-{i}", finding_type="prompt_injection",
            title=f"finding {i}", severity=severity, impact="i", recommendation="r", location="/x",
        )


def _opted_in(dep, connector="jira", min_severity="high"):
    """A binding with a credential and a policy opting into the decision trigger."""
    endpoint = (
        {"url": "https://hooks.example/athena"}
        if connector == "webhook"
        else {"base_url": "https://jira.example", "project_key": "SEC"}
    )
    binding = ConnectorBinding(deployment=dep, connector=connector, enabled=True, endpoint=endpoint)
    binding.set_secret("jira-tok")
    binding.save()
    DispatchPolicy.objects.create(
        deployment=dep, enabled=True, min_severity=min_severity, on_blocking_decision=True
    )


def _scanned(owner):
    dep = Deployment.objects.create(name=f"d{Deployment.objects.count()}", owner=owner)
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    recompute_decision(Deployment.objects.get(pk=dep.pk))
    return Deployment.objects.get(pk=dep.pk)


def _warm(client, dep):
    """The first request of a process imports the URLconf: pay it before timing."""
    client.get(f"/api/assurance/deployments/{dep.uuid}/dispatch-attempts/")


def _timed(call, connector):
    began = time.monotonic()
    response = call()
    return response, time.monotonic() - began, connector.finished


def _wait_for(predicate, timeout=20.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.02)
    return predicate()


def _sent(dep):
    return DispatchAttempt.objects.filter(
        deployment=dep, outcome=DispatchAttempt.Outcome.SENT, trigger=DispatchAttempt.Trigger.BLOCKING_DECISION
    ).count()


# --------------------------------------------------------------------- measured


@with_key
@pytest.mark.django_db(transaction=True)
def test_a_pause_answers_before_a_slow_dispatch_and_the_dispatch_still_happens(monkeypatch):
    connector = HeldConnector()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep)
    _opted_in(dep)
    client = _client(admin)
    _warm(client, dep)

    response, took, finished = _timed(
        lambda: client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json"),
        connector,
    )
    connector.release.set()

    assert response.status_code == 200, response.content
    assert response.json()["decision"] == Deployment.Decision.PAUSED
    assert took < PROMPT, f"the pause answered after {took:.3f}s: it waited on the dispatch"
    assert finished == 0, "a push finished before the pause answered"
    # Committed before it answered: a reader sees the pause at once -- and the
    # dispatch it owes, committed with it, before any push has finished.
    assert Deployment.objects.get(pk=dep.pk).decision == Deployment.Decision.PAUSED
    assert DecisionDispatchDue.objects.filter(deployment=dep).exists()
    # And the dispatch still happens, after.
    assert _wait_for(lambda: _sent(dep) == 2), list(DispatchAttempt.objects.values_list("outcome", "detail"))
    _settle()
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()


@with_key
@pytest.mark.django_db(transaction=True)
def test_a_lift_that_lands_on_a_blocking_decision_answers_before_a_slow_dispatch(monkeypatch):
    """The policy opts in while the deployment is paused; the lift lands on
    NEEDS_REMEDIATION, which is blocking, so it is the lift that dispatches."""
    connector = HeldConnector()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep)
    client = _client(admin)
    _warm(client, dep)
    assert client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json").status_code == 200
    _settle()
    _opted_in(dep)

    response, took, finished = _timed(
        lambda: client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": False}, format="json"),
        connector,
    )
    connector.release.set()

    assert response.status_code == 200, response.content
    assert response.json()["decision"] == Deployment.Decision.NEEDS_REMEDIATION
    assert took < PROMPT, f"the lift answered after {took:.3f}s: it waited on the dispatch"
    assert finished == 0
    assert _wait_for(lambda: _sent(dep) == 2)


@with_key
@pytest.mark.django_db(transaction=True)
def test_a_recompute_that_keeps_a_pause_answers_before_a_slow_dispatch(monkeypatch):
    """A recompute with no ``paused`` keeps the pause the row holds, and the
    decision it keeps is blocking."""
    connector = HeldConnector()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep)
    client = _client(admin)
    _warm(client, dep)
    client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json")
    _settle()
    _opted_in(dep)

    response, took, finished = _timed(
        lambda: client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {}, format="json"), connector
    )
    connector.release.set()

    assert response.json()["decision"] == Deployment.Decision.PAUSED
    assert took < PROMPT, f"the recompute answered after {took:.3f}s"
    assert finished == 0
    assert _wait_for(lambda: _sent(dep) == 2)


def _with_claims(owner):
    dep = Deployment.objects.create(name=f"c{Deployment.objects.count()}", owner=owner)
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    DataBoundary.objects.create(
        deployment=dep, allowed_regions=["eu-west-1"], training_allowed=False, third_party_sharing_allowed=False
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.TOOL, name="reader", identifier="reader",
        classification=Asset.Classification.KNOWN,
    )
    derive_claims(Deployment.objects.get(pk=dep.pk))
    recompute_decision(Deployment.objects.get(pk=dep.pk))
    return Deployment.objects.get(pk=dep.pk)


@with_key
@pytest.mark.django_db(transaction=True)
@pytest.mark.parametrize("to_status", [AssuranceClaim.ClaimStatus.REVOKED, AssuranceClaim.ClaimStatus.CONTRADICTED])
def test_a_revoke_or_a_contradiction_answers_promptly_beside_a_slow_connector(monkeypatch, to_status):
    """Neither schedules the dispatch; this holds that, with a connector that
    would hold the answer for seconds if either ever did."""
    connector = HeldConnector()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    admin = _admin()
    dep = _with_claims(admin)
    _findings(dep)
    _opted_in(dep)
    claim = AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).order_by("pk").first()
    client = _client(admin)
    _warm(client, dep)

    response, took, finished = _timed(
        lambda: client.post(f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": to_status}, format="json"),
        connector,
    )
    connector.release.set()

    assert response.status_code == 200, response.content
    assert took < PROMPT, f"the {to_status} answered after {took:.3f}s"
    assert finished == 0 and connector.started == 0


# ------------------------------------------------ after the answer: never lost


@with_key
@pytest.mark.django_db(transaction=True)
def test_a_pause_whose_dispatch_fails_answers_and_the_failure_stays_owed(monkeypatch, caplog):
    connector = HeldConnector(status=503)
    connector.release.set()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    monkeypatch.setattr(dispatch, "RETRY_DELAYS", (0.05,))
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    client = _client(admin)
    _warm(client, dep)

    with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
        response = client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json")
        assert response.status_code == 200
        _settle()

    owed = DecisionDispatchDue.objects.get(deployment=dep)
    # The first run and its one retry, each pushing and failing.
    assert owed.runs == 2 and connector.finished == 2
    assert "jira" in owed.last_error and "503" in owed.last_error
    assert DispatchAttempt.objects.get(deployment=dep).outcome == DispatchAttempt.Outcome.FAILED
    assert "still owed after 2 run(s)" in caplog.text
    # And it is shown to anyone who reads the deployment's dispatch record.
    shown = client.get(f"/api/assurance/deployments/{dep.uuid}/dispatch-attempts/").json()
    assert shown["blocking_decision_dispatch_owed"]["runs"] == 2
    assert "503" in shown["blocking_decision_dispatch_owed"]["last_error"]


@with_key
def test_a_run_records_what_it_owes_before_it_pushes_and_settles_only_when_nothing_failed(monkeypatch):
    """Paused without the route, so no stop recorded it: the run writes the row
    itself before its first push."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True)
    seen_at_push = []

    class Recording(HeldConnector):
        def post(self, url, *, headers, json):
            # A process killed here must leave the dispatch recorded as owed.
            seen_at_push.append(DecisionDispatchDue.objects.filter(deployment=dep).exists())
            return _Answer(self.status)

    failing = Recording(status=500)
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=failing.factory) == dispatch.OWED
    assert seen_at_push == [True]
    owed = DecisionDispatchDue.objects.get(deployment=dep)
    assert owed.runs == 1 and "500" in owed.last_error

    def raising(deployment, *, transport_factory=None, before_push=None):
        raise RuntimeError("the connector table is locked")

    monkeypatch.setattr(dispatch, "dispatch_for_blocking_decision", raising)
    assert dispatch.run_blocking_decision_dispatch(dep.pk) == dispatch.OWED
    owed.refresh_from_db()
    assert owed.runs == 2 and "RuntimeError: the connector table is locked" in owed.last_error
    monkeypatch.undo()

    working = Recording(status=201)
    assert dispatch.retry_owed_blocking_dispatches(transport_factory=working.factory) == {dep.pk: dispatch.SETTLED}
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()
    assert DispatchAttempt.objects.get(deployment=dep).outcome == DispatchAttempt.Outcome.SENT


@with_key
def test_nothing_is_owed_once_the_decision_that_asked_for_it_no_longer_holds():
    """An owed dispatch retried after the pause was lifted to a decision that is
    not blocking pushes nothing -- it would be executing a withdrawn decision --
    and is no longer owed."""
    admin = _admin()
    dep = _scanned(admin)
    _opted_in(dep)
    recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True)
    DecisionDispatchDue.objects.create(deployment=dep, owed_since=timezone.now(), runs=3, last_error="503")
    recompute_decision(Deployment.objects.get(pk=dep.pk), paused=False)
    assert Deployment.objects.get(pk=dep.pk).decision not in dispatch._BLOCKING_DECISIONS
    connector = HeldConnector()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
    assert connector.started == 0
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()


@with_key
def test_the_retry_command_runs_what_is_owed_and_fails_while_anything_still_is(monkeypatch):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True)
    DecisionDispatchDue.objects.create(deployment=dep, owed_since=timezone.now())
    failing = HeldConnector(status=503)
    failing.release.set()
    monkeypatch.setattr(dispatch, "_default_transport_factory", failing.factory)
    try:
        call_command("retry_blocking_dispatches")
    except CommandError as exc:
        assert str(dep.pk) in str(exc), exc
    else:
        raise AssertionError("the command reported nothing owed while a dispatch still was")
    assert DecisionDispatchDue.objects.get(deployment=dep).runs == 1

    working = HeldConnector()
    working.release.set()
    monkeypatch.setattr(dispatch, "_default_transport_factory", working.factory)
    call_command("retry_blocking_dispatches")
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()
    assert working.finished == 1


# ----------------------------------------------------------- how it is started


def test_the_route_only_schedules_the_dispatch_for_after_its_commit(django_capture_on_commit_callbacks, monkeypatch):
    """Inside a transaction nothing starts: one hook, for this deployment, and no
    thread until the transaction commits."""
    started = []
    monkeypatch.setattr(dispatch, "start_blocking_decision_dispatch", started.append)
    admin = _admin()
    dep = _scanned(admin)
    with django_capture_on_commit_callbacks(execute=False) as callbacks:
        response = _client(admin).post(
            f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json"
        )
    assert response.status_code == 200
    hooks = [c for c in callbacks if isinstance(c, dispatch._BlockingDispatchAfterCommit)]
    assert [h.deployment_id for h in hooks] == [dep.pk]
    assert started == []
    hooks[0]()
    assert started == [dep.pk]


def test_a_flood_of_stops_runs_one_background_dispatch_per_deployment(monkeypatch):
    """While one run is held, twenty more stops of the same deployment start no
    thread: the one running runs once more for all of them, and then is done."""
    held, runs = threading.Event(), []

    def run(deployment_id, *, transport_factory=None, token=None):
        runs.append(deployment_id)
        held.wait(HOLD)
        return dispatch.SETTLED

    monkeypatch.setattr(dispatch, "run_blocking_decision_dispatch", run)
    dispatch.start_blocking_decision_dispatch(4242)
    assert _wait_for(lambda: runs == [4242], timeout=5)
    for _ in range(20):
        dispatch.start_blocking_decision_dispatch(4242)
    assert [t.name for t in _background()] == ["assurance-dispatch-4242"]
    held.set()
    _settle()
    assert runs == [4242, 4242]
    assert 4242 not in dispatch._JOBS


def test_a_run_that_raises_is_retried_in_the_background(monkeypatch):
    runs = []

    def run(deployment_id, *, transport_factory=None, token=None):
        runs.append(deployment_id)
        if len(runs) == 1:
            raise RuntimeError("database is locked")
        return dispatch.SETTLED

    monkeypatch.setattr(dispatch, "run_blocking_decision_dispatch", run)
    monkeypatch.setattr(dispatch, "RETRY_DELAYS", (0.01, 0.01))
    dispatch.start_blocking_decision_dispatch(4343)
    _settle()
    assert runs == [4343, 4343]
    assert 4343 not in dispatch._JOBS


def test_a_background_dispatch_that_cannot_start_does_not_fail_the_stop(
    django_capture_on_commit_callbacks, monkeypatch, caplog
):
    def refuse(self):
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", refuse)
    admin = _admin()
    dep = _scanned(admin)
    with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
        with django_capture_on_commit_callbacks(execute=True):
            response = _client(admin).post(
                f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json"
            )
    assert response.status_code == 200
    assert Deployment.objects.get(pk=dep.pk).decision == Deployment.Decision.PAUSED
    assert f"retry_blocking_dispatches --deployment {dep.pk}" in caplog.text
    # Nothing is left claiming a run is in progress.
    assert dep.pk not in dispatch._JOBS


# ------------------------------------------- owed from the moment the stop commits


def _paused_via_route(client, dep):
    return client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json")


@with_key
@pytest.mark.django_db(transaction=True)
def test_a_process_that_exits_right_after_the_stop_leaves_the_dispatch_owed(monkeypatch):
    """The worker answers the pause and exits before its background thread has
    written anything -- a graceful restart, a recycled worker. The dispatch was
    recorded in the pause's own transaction, so the next process finds it owed
    and the retry command runs it."""
    connector = HeldConnector()
    connector.release.set()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    exited_with = []
    # The process is gone before the thread runs: it never starts.
    monkeypatch.setattr(dispatch, "start_blocking_decision_dispatch", exited_with.append)
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep)
    _opted_in(dep)
    client = _client(admin)
    _warm(client, dep)

    response = _paused_via_route(client, dep)

    assert response.status_code == 200 and response.json()["decision"] == Deployment.Decision.PAUSED
    assert exited_with == [dep.pk] and connector.started == 0
    owed = DecisionDispatchDue.objects.get(deployment=dep)
    assert owed.requests == 1 and owed.runs == 0 and owed.run_token == ""
    monkeypatch.undo()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    call_command("retry_blocking_dispatches")
    assert _sent(dep) == 2
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()


@with_key
def test_the_owed_record_commits_with_the_stop_or_not_at_all():
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep)
    _opted_in(dep)
    with pytest.raises(RuntimeError), transaction.atomic():
        recompute_decision(
            Deployment.objects.get(pk=dep.pk), paused=True,
            also_in_transaction=dispatch.record_blocking_dispatch_owed,
        )
        assert DecisionDispatchDue.objects.filter(deployment=dep).exists()
        raise RuntimeError("the stop's transaction rolls back")
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()
    assert Deployment.objects.get(pk=dep.pk).decision != Deployment.Decision.PAUSED
    # Each stop that asks counts; a decision that owes nothing records nothing.
    for _ in range(2):
        recompute_decision(
            Deployment.objects.get(pk=dep.pk), paused=True,
            also_in_transaction=dispatch.record_blocking_dispatch_owed,
        )
    assert DecisionDispatchDue.objects.get(deployment=dep).requests == 2
    DispatchPolicy.objects.filter(deployment=dep).update(on_blocking_decision=False)
    other = _scanned(admin)
    recompute_decision(other, paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed)
    assert not DecisionDispatchDue.objects.filter(deployment=other).exists()


@with_key
def test_a_stop_whose_owed_record_cannot_be_written_still_stops_and_the_run_writes_it(
    django_capture_on_commit_callbacks, monkeypatch, caplog
):
    """The savepoint fails; the stop neither fails nor waits, and the pause stands.
    The background run then records the dispatch itself before its first push."""
    def broken(**kwargs):
        raise DatabaseError("disk I/O error")

    monkeypatch.setattr(DecisionDispatchDue.objects, "create", broken)
    started = []
    monkeypatch.setattr(dispatch, "start_blocking_decision_dispatch", started.append)
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    client = _client(admin)
    _warm(client, dep)
    with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
        with django_capture_on_commit_callbacks(execute=True):
            began = time.monotonic()
            response = _paused_via_route(client, dep)
            took = time.monotonic() - began
    assert response.status_code == 200 and response.json()["decision"] == Deployment.Decision.PAUSED
    assert took < PROMPT
    assert Deployment.objects.get(pk=dep.pk).decision == Deployment.Decision.PAUSED
    assert "could not record the blocking-decision dispatch" in caplog.text
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()
    assert started == [dep.pk]
    monkeypatch.undo()

    seen_at_push = []

    class Recording(HeldConnector):
        def post(self, url, *, headers, json):
            seen_at_push.append(DecisionDispatchDue.objects.filter(deployment=dep).exists())
            return _Answer(503)

    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=Recording().factory) == dispatch.OWED
    assert seen_at_push == [True]
    assert DecisionDispatchDue.objects.get(deployment=dep).runs == 1


# --------------------------------------------------- the last word is a true one


@with_key
def test_the_last_log_says_it_stays_recorded_only_when_it_does(monkeypatch, caplog):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    monkeypatch.setattr(dispatch, "RETRY_DELAYS", (0.0, 0.0))

    def locked(deployment, token):
        raise OperationalError("database is locked")

    # 1. Recorded by the stop; every run then fails before it can claim it.
    monkeypatch.setattr(dispatch, "_claim", locked)
    with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
        dispatch._run_until_settled(dep.pk, "t1")
    assert "is still owed after 3 run(s); it stays recorded" in caplog.text
    assert DecisionDispatchDue.objects.filter(deployment=dep).exists()
    caplog.clear()

    # 2. Not recorded, and the run cannot write it either: the log says so, and
    #    names the command that runs it -- it never claims a record that is not there.
    DecisionDispatchDue.objects.filter(deployment=dep).delete()

    def cannot(*args, **kwargs):
        raise OperationalError("database is locked")

    monkeypatch.setattr(DecisionDispatchDue.objects, "get_or_create", cannot)
    with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
        dispatch._run_until_settled(dep.pk, "t2")
    assert "stays recorded" not in caplog.text
    assert (
        f"is still owed after 3 run(s), and no record of it could be written: run "
        f"`manage.py retry_blocking_dispatches --deployment {dep.pk}`"
    ) in caplog.text
    caplog.clear()

    # 3. Whether it is recorded cannot even be read.
    def unreadable(deployment_id):
        raise OperationalError("database is locked")

    monkeypatch.setattr(dispatch, "_owed_row", unreadable)
    with caplog.at_level(logging.ERROR, logger="assurance.dispatch"):
        dispatch._run_until_settled(dep.pk, "t3")
    assert "stays recorded" not in caplog.text
    assert "whether it is recorded could not be read" in caplog.text
    assert f"--deployment {dep.pk}" in caplog.text


# ------------------------------------------------- one runner at a time, anywhere


@with_key
@pytest.mark.django_db(transaction=True)
def test_a_scheduled_retry_during_a_background_run_pushes_nothing_twice(monkeypatch):
    """The cron fires while the background thread is mid-push -- the hung-
    connector case this exists for. It finds the dispatch claimed, pushes nothing,
    and says so; a second process's thread for a second pause does the same. Each
    finding is pushed exactly once."""
    connector = HeldConnector()
    monkeypatch.setattr(dispatch, "_default_transport_factory", connector.factory)
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=3)
    _opted_in(dep)
    client = _client(admin)
    _warm(client, dep)

    assert _paused_via_route(client, dep).status_code == 200
    assert _wait_for(lambda: connector.started == 1, timeout=5)
    # The scheduled command, here and now.
    assert dispatch.retry_owed_blocking_dispatches() == {dep.pk: dispatch.ELSEWHERE}
    with pytest.raises(CommandError):
        call_command("retry_blocking_dispatches")
    # Another worker process pauses it again: its own thread, knowing nothing of this one's.
    dispatch._JOBS.clear()
    assert _paused_via_route(client, dep).status_code == 200
    assert connector.started == 1
    connector.release.set()
    _settle()

    assert sorted(connector.bodies.count(b) for b in set(connector.bodies)) == [1, 1, 1]
    assert connector.started == 3
    assert list(DispatchAttempt.objects.filter(deployment=dep).values_list("outcome", "attempts")) == [
        (DispatchAttempt.Outcome.SENT, 1)
    ] * 3
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()


@with_key
def test_a_claim_is_skipped_while_live_and_taken_back_once_it_lapses():
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    connector = HeldConnector()
    connector.release.set()
    live = timezone.now() + timedelta(seconds=60)
    DecisionDispatchDue.objects.filter(deployment=dep).update(running_until=live, run_token="other-runner")

    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.ELSEWHERE
    assert connector.started == 0
    # The runner holding it may run again under its own claim.
    assert (
        dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory, token="other-runner")
        == dispatch.SETTLED
    )
    assert connector.started == 1

    # A runner that died leaves a claim that lapses; the next one takes it back.
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    DispatchAttempt.objects.filter(deployment=dep).delete()
    lapsed = timezone.now() - timedelta(seconds=1)
    DecisionDispatchDue.objects.filter(deployment=dep).update(running_until=lapsed, run_token="dead-runner")
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
    assert connector.started == 2


@with_key
def test_a_run_that_loses_its_claim_pushes_nothing_more(monkeypatch):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=3)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )

    class TakenOver(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            # Another runner takes the row after this runner's claim was judged dead.
            DecisionDispatchDue.objects.filter(deployment=dep).update(run_token="someone-else")
            return _Answer(201)

    connector = TakenOver()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.ELSEWHERE
    assert connector.started == 1
    assert DecisionDispatchDue.objects.get(deployment=dep).run_token == "someone-else"


@with_key
def test_a_webhook_push_carries_the_operation_id_as_its_idempotency_key():
    """A second push of one operation -- across processes, say -- is one to a
    receiver that deduplicates on it. Jira has no such header, so none is sent."""
    admin = _admin()
    for connector_name in ("webhook", "jira"):
        dep = _scanned(admin)
        _findings(dep, count=1)
        _opted_in(dep, connector=connector_name)
        recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True)
        connector = HeldConnector()
        connector.release.set()
        assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
        attempt = DispatchAttempt.objects.get(deployment=dep)
        finding = Finding.objects.get(deployment=dep)
        assert attempt.operation_id == dispatch.operation_id(finding, connector_name)
        if connector_name == "webhook":
            assert connector.headers[0]["Idempotency-Key"] == attempt.operation_id
        else:
            assert "Idempotency-Key" not in connector.headers[0]


# ------------------------------------------------------- the global kill switch


@with_key
def test_the_kill_switch_never_drops_what_is_owed(monkeypatch, django_capture_on_commit_callbacks):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=2)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    failing = HeldConnector(status=503)
    failing.release.set()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=failing.factory) == dispatch.OWED
    working = HeldConnector()
    working.release.set()

    with override_settings(ASSURANCE_AUTO_DISPATCH_ENABLED=False):
        # Switched off: the scheduled retry pushes nothing and drops nothing.
        assert dispatch.retry_owed_blocking_dispatches(transport_factory=working.factory) == {
            dep.pk: dispatch.DISABLED
        }
        with pytest.raises(CommandError, match=str(dep.pk)):
            call_command("retry_blocking_dispatches")
        assert DecisionDispatchDue.objects.get(deployment=dep).runs == 1
        # And a stop records nothing new and schedules nothing.
        other = _scanned(admin)
        _findings(other, count=1)
        _opted_in(other)
        with django_capture_on_commit_callbacks(execute=False) as callbacks:
            assert _paused_via_route(_client(admin), other).status_code == 200
        assert not [c for c in callbacks if isinstance(c, dispatch._BlockingDispatchAfterCommit)]
        assert not DecisionDispatchDue.objects.filter(deployment=other).exists()
    assert working.started == 0

    # Switched back on, the retry runs what was kept.
    assert dispatch.retry_owed_blocking_dispatches(transport_factory=working.factory) == {dep.pk: dispatch.SETTLED}
    assert working.started == 2 and _sent(dep) == 2


@with_key
def test_a_run_halts_and_keeps_the_row_when_the_switch_goes_off_mid_run():
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=3)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    switched_off = override_settings(ASSURANCE_AUTO_DISPATCH_ENABLED=False)

    class SwitchedOff(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            if self.started == 1:
                switched_off.enable()
            return _Answer(201)

    connector = SwitchedOff()
    try:
        outcome = dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory)
    finally:
        switched_off.disable()
    assert outcome == dispatch.DISABLED
    assert connector.started == 1
    owed = DecisionDispatchDue.objects.get(deployment=dep)
    assert owed.run_token == "" and owed.running_until is None


# ------------------------------------------- the decision is checked every push


@with_key
def test_a_run_stops_pushing_once_the_pause_that_asked_for_it_is_lifted():
    """The lift lands on a decision that does not block. The run checks before
    every push, so the pushes after the lift are never made -- not one of them
    under the withdrawn pause -- and nothing is owed any more."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=3, severity="low")
    _opted_in(dep, min_severity="low")
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    lifted = []

    class LiftedMidRun(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            if not lifted:
                lifted.append(recompute_decision(Deployment.objects.get(pk=dep.pk), paused=False))
            return _Answer(201)

    connector = LiftedMidRun()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
    assert lifted and lifted[0] not in dispatch._BLOCKING_DECISIONS, lifted
    assert connector.started == 1
    assert list(DispatchAttempt.objects.filter(deployment=dep).values_list("outcome", "policy_epoch")) == [
        (DispatchAttempt.Outcome.SENT, Deployment.Decision.PAUSED)
    ]
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()


@with_key
def test_a_stop_that_asks_again_mid_run_is_run_for_before_the_row_is_settled(monkeypatch):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=2)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    passes = []
    real = dispatch._run_claimed

    def counted(claim, asked, transport_factory):
        passes.append(asked)
        return real(claim, asked, transport_factory)

    monkeypatch.setattr(dispatch, "_run_claimed", counted)

    class AskedAgain(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            if self.started == 1:
                recompute_decision(
                    Deployment.objects.get(pk=dep.pk), paused=True,
                    also_in_transaction=dispatch.record_blocking_dispatch_owed,
                )
            return _Answer(201)

    connector = AskedAgain()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
    assert passes == [1, 2]
    assert connector.started == 2 and _sent(dep) == 2
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()


@with_key
def test_a_check_that_cannot_be_made_halts_the_run_and_keeps_it_owed(monkeypatch):
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=2)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    real = dispatch._owed_row
    calls = []

    def flaky(deployment_id):
        calls.append(1)
        # The run's read of what is asked, its claim, the check before the first
        # push -- and then the check before the second push fails.
        if len(calls) == 4:
            raise OperationalError("database is locked")
        return real(deployment_id)

    monkeypatch.setattr(dispatch, "_owed_row", flaky)
    connector = HeldConnector()
    connector.release.set()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.OWED
    assert connector.started == 1
    owed = DecisionDispatchDue.objects.get(deployment=dep)
    assert "the check before a push raised OperationalError" in owed.last_error and owed.run_token == ""


# ------------------------------------------------------------ what is not retried


@with_key
def test_an_unknown_push_settles_the_run_and_is_not_pushed_again():
    """A push whose answer was lost may have created the ticket: it waits for
    reconciliation, never a retry, and it leaves nothing owed."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=1)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )

    class AnswerLost(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            raise TimeoutError("read timed out")

    connector = AnswerLost()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
    assert DispatchAttempt.objects.get(deployment=dep).outcome == DispatchAttempt.Outcome.UNKNOWN
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()
    DecisionDispatchDue.objects.create(deployment=dep, owed_since=timezone.now())
    assert dispatch.retry_owed_blocking_dispatches(transport_factory=connector.factory) == {dep.pk: dispatch.SETTLED}
    assert connector.started == 1


# ------------------------------------------------------------- the retry command


@with_key
def test_the_retry_command_with_deployment_runs_and_reports_only_those(monkeypatch):
    admin = _admin()
    a, b = _scanned(admin), _scanned(admin)
    for dep in (a, b):
        _findings(dep, count=1)
        _opted_in(dep)
        recompute_decision(
            Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
        )
    down = HeldConnector(status=503)
    down.release.set()
    monkeypatch.setattr(dispatch, "_default_transport_factory", down.factory)
    assert dispatch.run_blocking_decision_dispatch(a.pk) == dispatch.OWED
    working = HeldConnector()
    working.release.set()
    monkeypatch.setattr(dispatch, "_default_transport_factory", working.factory)

    out = io.StringIO()
    call_command("retry_blocking_dispatches", "--deployment", str(b.pk), stdout=out)
    assert f"deployment(s) [{b.pk}] only" in out.getvalue() and "no other deployment was checked" in out.getvalue()
    assert working.started == 1  # B's, and not A's
    assert not DecisionDispatchDue.objects.filter(deployment=b).exists()
    assert DecisionDispatchDue.objects.get(deployment=a).runs == 1

    monkeypatch.setattr(dispatch, "_default_transport_factory", down.factory)
    with pytest.raises(CommandError, match=rf"\[{a.pk}\]"):
        call_command("retry_blocking_dispatches", "--deployment", str(a.pk), stdout=io.StringIO())
    # Without it: non-zero while anything at all is owed.
    with pytest.raises(CommandError, match=rf"\[{a.pk}\]"):
        call_command("retry_blocking_dispatches", stdout=io.StringIO())


@with_key
def test_one_deployment_whose_retry_raises_does_not_stop_the_rest(monkeypatch):
    admin = _admin()
    a, b = _scanned(admin), _scanned(admin)
    now = timezone.now()
    DecisionDispatchDue.objects.create(deployment=a, owed_since=now - timedelta(seconds=5))
    DecisionDispatchDue.objects.create(deployment=b, owed_since=now)
    real = dispatch.run_blocking_decision_dispatch

    def run(deployment_id, **kwargs):
        if deployment_id == a.pk:
            raise OperationalError("database is locked")
        return real(deployment_id, **kwargs)

    monkeypatch.setattr(dispatch, "run_blocking_decision_dispatch", run)
    assert dispatch.retry_owed_blocking_dispatches() == {a.pk: dispatch.OWED, b.pk: dispatch.SETTLED}


# ---------------------------------------------------------------- the thread itself


def test_the_background_thread_is_a_daemon_and_the_stop_has_recorded_what_it_owes(monkeypatch):
    """A daemon never holds a worker's exit -- and need not, because the row was
    committed with the stop before any thread exists."""
    made = []

    class Recorded:
        def __init__(self, *args, **kwargs):
            made.append(kwargs)

        def start(self):
            pass

    monkeypatch.setattr(dispatch.threading, "Thread", Recorded)
    dispatch.start_blocking_decision_dispatch(4545)
    dispatch._JOBS.pop(4545, None)
    assert made and made[0]["daemon"] is True
    assert made[0]["name"] == "assurance-dispatch-4545"


def test_the_background_thread_closes_its_own_connections(monkeypatch):
    used = []

    def run(deployment_id, *, transport_factory=None, token=None):
        Deployment.objects.exists()
        used.append(connections["default"])
        return dispatch.SETTLED

    monkeypatch.setattr(dispatch, "run_blocking_decision_dispatch", run)
    dispatch.start_blocking_decision_dispatch(4646)
    _settle()
    assert used and used[0].connection is None, "the thread left its connection open"


def test_the_owed_dispatch_is_read_only_in_the_admin():
    model_admin = django_admin.site._registry[DecisionDispatchDue]
    request = RequestFactory().get("/admin/")
    request.user = User.objects.create_superuser(username="su", password="x", email="su@example.com")
    assert model_admin.has_add_permission(request) is False
    assert model_admin.has_change_permission(request) is False
    assert {"requests", "running_until", "run_token"} <= set(model_admin.readonly_fields)


@with_key
def test_a_long_run_renews_its_claim_before_it_can_lapse(monkeypatch):
    """Four pushes of forty seconds each outlast one claim. Renewed before each push
    that needs it, the claim never lapses under a live run -- a lapsed one would let
    a second runner push the same findings."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=4)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    real_now = timezone.now
    skew = [timedelta(0)]

    class Clock:
        @staticmethod
        def now():
            return real_now() + skew[0]

    monkeypatch.setattr(dispatch, "timezone", Clock)
    left = []

    class Slow(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            until = DecisionDispatchDue.objects.get(deployment=dep).running_until
            left.append((until - Clock.now()).total_seconds())
            skew[0] += timedelta(seconds=40)
            return _Answer(201)

    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=Slow().factory) == dispatch.SETTLED
    assert len(left) == 4
    assert min(left) > dispatch.CLAIM_SECONDS - dispatch.CLAIM_RENEW_AFTER - 1, left


def test_a_flood_across_deployments_runs_a_bounded_number_at_once(monkeypatch):
    """Stops of many deployments start a thread each, but only a few push at once:
    the rest wait asleep, so a flood does not crowd out the process's requests."""
    held, lock, running, peak = threading.Event(), threading.Lock(), [0], [0]

    def run(deployment_id, *, transport_factory=None, token=None):
        with lock:
            running[0] += 1
            peak[0] = max(peak[0], running[0])
        held.wait(0.3)
        with lock:
            running[0] -= 1
        return dispatch.SETTLED

    monkeypatch.setattr(dispatch, "run_blocking_decision_dispatch", run)
    for pk in range(5000, 5012):
        dispatch.start_blocking_decision_dispatch(pk)
    assert len(_background()) == 12
    _settle()
    assert peak[0] == dispatch.MAX_CONCURRENT_RUNS


@with_key
def test_a_run_whose_decision_moves_to_another_blocking_one_records_the_one_in_force():
    """Lifted mid-run onto NEEDS_REMEDIATION -- still blocking, so the run goes on
    -- and every push after the lift records the authority it was made under."""
    admin = _admin()
    dep = _scanned(admin)
    _findings(dep, count=3)
    _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=dep.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )
    lifted = []

    class LiftedMidRun(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            if not lifted:
                lifted.append(recompute_decision(Deployment.objects.get(pk=dep.pk), paused=False))
            return _Answer(201)

    connector = LiftedMidRun()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) == dispatch.SETTLED
    assert lifted == [Deployment.Decision.NEEDS_REMEDIATION]
    assert connector.started == 3
    assert list(
        DispatchAttempt.objects.filter(deployment=dep).order_by("finding_id").values_list("policy_epoch", flat=True)
    ) == [Deployment.Decision.PAUSED, Deployment.Decision.NEEDS_REMEDIATION, Deployment.Decision.NEEDS_REMEDIATION]


@with_key
def test_the_retry_command_fails_for_a_dispatch_a_stop_owes_while_it_runs(monkeypatch):
    """A stop lands while the scheduled command is running; what it owes was not in
    the command's list, and the command still does not report nothing owed."""
    admin = _admin()
    a, b = _scanned(admin), _scanned(admin)
    for dep in (a, b):
        _findings(dep, count=1)
        _opted_in(dep)
    recompute_decision(
        Deployment.objects.get(pk=a.pk), paused=True, also_in_transaction=dispatch.record_blocking_dispatch_owed
    )

    class PausedMeanwhile(HeldConnector):
        def post(self, url, *, headers, json):
            self.started += 1
            recompute_decision(
                Deployment.objects.get(pk=b.pk), paused=True,
                also_in_transaction=dispatch.record_blocking_dispatch_owed,
            )
            return _Answer(201)

    monkeypatch.setattr(dispatch, "_default_transport_factory", PausedMeanwhile().factory)
    with pytest.raises(CommandError, match=rf"\[{b.pk}\]"):
        call_command("retry_blocking_dispatches", stdout=io.StringIO())
    assert not DecisionDispatchDue.objects.filter(deployment=a).exists()


def test_a_deployment_that_is_gone_owes_nothing():
    out = io.StringIO()
    call_command("retry_blocking_dispatches", "--deployment", "987654", stdout=out)
    assert "deployment 987654: settled" in out.getvalue()
