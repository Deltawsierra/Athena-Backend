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

Now the stop commits and answers, and the dispatch runs after it, in the
background. A run that does not finish cleanly stays recorded until one does.

The timing tests MEASURE it: the connector here holds every push until the test
lets it go, or three seconds pass, and the stop must answer in under a second with
no push finished. They do not assert the structure that should make it fast; they
assert that it is.
"""

from __future__ import annotations

import logging
import threading
import time

import pytest
from cryptography.fernet import Fernet
from django.contrib.auth import get_user_model
from django.test import override_settings
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
        self._lock = threading.Lock()

    def factory(self):
        return self

    def post(self, url, *, headers, json):
        with self._lock:
            self.started += 1
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


def _findings(dep, count=2):
    """Open high findings on ``dep``. Made BEFORE any policy exists, so the
    severity trigger has nothing to dispatch when they are saved."""
    for i in range(count):
        Finding.objects.create(
            deployment=dep, fingerprint=f"fp303-{dep.pk}-{i}", finding_type="prompt_injection",
            title=f"finding {i}", severity="high", impact="i", recommendation="r", location="/x",
        )


def _opted_in(dep):
    """A Jira binding with a credential and a policy opting into the decision trigger."""
    binding = ConnectorBinding(
        deployment=dep, connector="jira", enabled=True,
        endpoint={"base_url": "https://jira.example", "project_key": "SEC"},
    )
    binding.set_secret("jira-tok")
    binding.save()
    DispatchPolicy.objects.create(deployment=dep, enabled=True, min_severity="high", on_blocking_decision=True)


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
    # Committed before it answered: a reader sees the pause at once.
    assert Deployment.objects.get(pk=dep.pk).decision == Deployment.Decision.PAUSED
    # And the dispatch still happens, after.
    assert _wait_for(lambda: _sent(dep) == 2), list(DispatchAttempt.objects.values_list("outcome", "detail"))
    _settle()
    from assurance.models import DecisionDispatchDue

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

    from assurance.models import DecisionDispatchDue

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
    from assurance.models import DecisionDispatchDue

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
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=failing.factory) is False
    assert seen_at_push == [True]
    owed = DecisionDispatchDue.objects.get(deployment=dep)
    assert owed.runs == 1 and "500" in owed.last_error

    def raising(deployment, *, transport_factory=None):
        raise RuntimeError("the connector table is locked")

    monkeypatch.setattr(dispatch, "dispatch_for_blocking_decision", raising)
    assert dispatch.run_blocking_decision_dispatch(dep.pk) is False
    owed.refresh_from_db()
    assert owed.runs == 2 and "RuntimeError: the connector table is locked" in owed.last_error
    monkeypatch.undo()

    working = Recording(status=201)
    assert dispatch.retry_owed_blocking_dispatches(transport_factory=working.factory) == {dep.pk: True}
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()
    assert DispatchAttempt.objects.get(deployment=dep).outcome == DispatchAttempt.Outcome.SENT


@with_key
def test_nothing_is_owed_once_the_decision_that_asked_for_it_no_longer_holds():
    """An owed dispatch retried after the pause was lifted to a decision that is
    not blocking pushes nothing -- it would be executing a withdrawn decision --
    and is no longer owed."""
    from assurance.models import DecisionDispatchDue

    admin = _admin()
    dep = _scanned(admin)
    _opted_in(dep)
    recompute_decision(Deployment.objects.get(pk=dep.pk), paused=True)
    DecisionDispatchDue.objects.create(deployment=dep, owed_since=timezone.now(), runs=3, last_error="503")
    recompute_decision(Deployment.objects.get(pk=dep.pk), paused=False)
    assert Deployment.objects.get(pk=dep.pk).decision not in dispatch._BLOCKING_DECISIONS
    connector = HeldConnector()
    assert dispatch.run_blocking_decision_dispatch(dep.pk, transport_factory=connector.factory) is True
    assert connector.started == 0
    assert not DecisionDispatchDue.objects.filter(deployment=dep).exists()


@with_key
def test_the_retry_command_runs_what_is_owed_and_fails_while_anything_still_is(monkeypatch):
    from django.core.management import CommandError, call_command

    from assurance.models import DecisionDispatchDue

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

    def run(deployment_id, *, transport_factory=None):
        runs.append(deployment_id)
        held.wait(HOLD)
        return True

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

    def run(deployment_id, *, transport_factory=None):
        runs.append(deployment_id)
        if len(runs) == 1:
            raise RuntimeError("database is locked")
        return True

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
