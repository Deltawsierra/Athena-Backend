"""A recorded closure document becomes one row of Minotaur's dataset (Phase 6 item 3).

Each closure document the engine service records (assurance.closure_evidence) is sent
on, unchanged, to Minotaur-Backend's ``POST /remediation-outcomes`` as its runner
(assurance.closure_forward): only once the record has committed, off the request, so
no answer from Minotaur -- slow, refused, down -- delays or undoes it; off unless
configured; and recorded, so a send that did not land is retried and one that did is
never sent twice. Every call here is answered by :class:`FakeMinotaur`, in process:
nothing reaches the network.
"""

from __future__ import annotations

import threading
from datetime import timedelta

import pytest
import requests.exceptions as rex
from django.core.management import call_command
from django.core.management.base import CommandError
from django.utils import timezone
from rest_framework.test import APIClient

from assurance import closure_forward
from assurance.models import ClosureEvidenceForward, RetestClosureEvidence
from tests.test_a_closure_stands_only_on_a_replay_the_engine_service_recorded import (
    SERVICE_ACCOUNT,
    SERVICE_CREDENTIAL,
    _body,
    _document,
    _finding,
    _url,
)

pytestmark = pytest.mark.django_db

MINOTAUR = "https://minotaur.invalid"
RUNNER_KEY = "minotaur-runner-key-for-tests"

#: What Minotaur-Backend's remediation_outcomes.normalize takes, exactly: anything
#: else it refuses by name. The fake refuses the same, so a forward that adds or
#: drops a field fails here. ``contract`` -- the repair contract the replay was held
#: to -- is optional there, and so here.
ROW_FIELDS = {"finding_type", "finding_ref", "engine", "origin", "remediation", "replay", "fixtures"}
OPTIONAL_ROW_FIELDS = {"contract"}


class _Answer:
    def __init__(self, status_code, body):
        self.status_code = status_code
        self._body = body

    def json(self):
        return self._body

    @property
    def text(self):
        return str(self._body)


class FakeMinotaur:
    """Minotaur-Backend's ``POST /remediation-outcomes``, in process.

    ``mode``: ``up`` records the row (201 with its id); ``down`` refuses the
    connection (nothing sent); ``lost`` records the row and loses the answer (a read
    timeout); ``error`` answers 500; ``refuse`` answers 400."""

    def __init__(self):
        self.mode = "up"
        self.calls = []
        self.rows = []

    def post(self, url, *, headers, json):
        self.calls.append((url, dict(headers), json))
        if self.mode == "down":
            raise ConnectionRefusedError("connection refused")
        if url != MINOTAUR + "/remediation-outcomes":
            return _Answer(404, {"error": "no such route"})
        if headers.get("X-Minotaur-Key") != RUNNER_KEY:
            return _Answer(401, {"error": "a valid X-Minotaur-Key is required"})
        if self.mode == "error":
            return _Answer(500, {"error": "internal"})
        if self.mode == "refuse" or not isinstance(json, dict) or (set(json) - OPTIONAL_ROW_FIELDS) != ROW_FIELDS:
            return _Answer(400, {"error": "the row cannot be read"})
        self.rows.append(json)
        if self.mode == "lost":
            raise rex.ReadTimeout("read timed out")
        return _Answer(201, {"id": len(self.rows), **json})


@pytest.fixture(autouse=True)
def service(settings):
    from django.contrib.auth import get_user_model

    User = get_user_model()
    settings.CLOSURE_EVIDENCE_SERVICE_TOKEN = SERVICE_CREDENTIAL
    settings.CLOSURE_EVIDENCE_SERVICE_USER = SERVICE_ACCOUNT
    return User.objects.create_user(username=SERVICE_ACCOUNT, role=User.Roles.VIEWER)


@pytest.fixture
def minotaur(settings, monkeypatch):
    """Forwarding configured against the fake, and the send run where the test can
    see it: queued sends are collected, and run when the test says so."""
    settings.MINOTAUR_OUTCOMES_URL = MINOTAUR + "/"
    settings.MINOTAUR_RUNNER_KEY = RUNNER_KEY
    fake = FakeMinotaur()
    fake.spawned = []
    monkeypatch.setattr(closure_forward, "_transport", lambda: fake)
    monkeypatch.setattr(closure_forward, "_spawn", fake.spawned.append)
    return fake


def _record_and_commit(finding, document, capture):
    """POST the document as the engine service, then commit: what the request
    answered, before any send ran."""
    client = APIClient()
    client.credentials(HTTP_X_CLOSURE_EVIDENCE_TOKEN=SERVICE_CREDENTIAL)
    with capture(execute=True):
        answer = client.post(_url(finding), _body(document), format="json")
    return answer


def _run_sends(fake):
    while fake.spawned:
        fake.spawned.pop(0)()


def test_a_recorded_document_is_sent_on_unchanged_once_its_record_commits(
    minotaur, django_capture_on_commit_callbacks
):
    finding = _finding()
    document = _document(finding)

    answer = _record_and_commit(finding, document, django_capture_on_commit_callbacks)

    assert answer.status_code == 201, answer.content
    assert answer.json()["dataset_forward"] == "queued"
    assert minotaur.calls == [], "nothing is sent on the request"
    (forward,) = ClosureEvidenceForward.objects.all()
    assert forward.status == ClosureEvidenceForward.Status.PENDING

    _run_sends(minotaur)

    (record,) = RetestClosureEvidence.objects.filter(finding=finding)
    assert minotaur.calls == [(MINOTAUR + "/remediation-outcomes", {"X-Minotaur-Key": RUNNER_KEY}, record.document)]
    assert minotaur.rows == [document], "the document as recorded, unchanged"
    forward.refresh_from_db()
    assert forward.record_id == record.pk
    assert (forward.status, forward.attempts, forward.dataset_row_id) == ("sent", 1, 1)


def test_a_document_that_closes_nothing_is_a_row_too(minotaur, django_capture_on_commit_callbacks):
    finding = _finding()
    unreached = {"reached": False, "original_effect": "unknown", "variants": {}, "utility": "unknown"}

    answer = _record_and_commit(finding, _document(finding, replay=unreached), django_capture_on_commit_callbacks)
    _run_sends(minotaur)

    assert answer.json()["result"] == "inconclusive"
    assert [row["replay"] for row in minotaur.rows] == [unreached]
    assert ClosureEvidenceForward.objects.get().status == "sent"


def test_forwarding_is_off_unless_configured(settings, monkeypatch, django_capture_on_commit_callbacks):
    fake = FakeMinotaur()
    monkeypatch.setattr(closure_forward, "_transport", lambda: fake)
    monkeypatch.setattr(closure_forward, "_spawn", lambda work: work())
    for url, key in [(None, RUNNER_KEY), (MINOTAUR, None), ("  ", RUNNER_KEY), (MINOTAUR, "")]:
        settings.MINOTAUR_OUTCOMES_URL = url
        settings.MINOTAUR_RUNNER_KEY = key
        finding = _finding()

        answer = _record_and_commit(finding, _document(finding), django_capture_on_commit_callbacks)

        assert answer.status_code == 201, answer.content
        assert answer.json()["dataset_forward"] == "off"
    assert RetestClosureEvidence.objects.count() == 4
    assert ClosureEvidenceForward.objects.count() == 0
    assert fake.calls == []


def test_a_minotaur_that_is_down_never_fails_the_store_and_the_send_is_retried(
    minotaur, django_capture_on_commit_callbacks
):
    minotaur.mode = "down"
    finding = _finding()

    answer = _record_and_commit(finding, _document(finding), django_capture_on_commit_callbacks)
    _run_sends(minotaur)

    assert answer.status_code == 201
    assert RetestClosureEvidence.objects.filter(finding=finding).count() == 1
    forward = ClosureEvidenceForward.objects.get()
    assert (forward.status, forward.attempts) == ("failed", 1)
    assert "not sent" in forward.last_error

    with pytest.raises(CommandError, match="1 closure forward"):
        call_command("retry_closure_forwards")
    assert ClosureEvidenceForward.objects.get().attempts == 2

    minotaur.mode = "up"
    call_command("retry_closure_forwards")
    forward.refresh_from_db()
    assert (forward.status, forward.attempts) == ("sent", 3)
    assert len(minotaur.rows) == 1


def test_an_error_answer_is_retried_and_a_refused_row_never_is(minotaur, django_capture_on_commit_callbacks):
    minotaur.mode = "error"
    first = _finding()
    _record_and_commit(first, _document(first), django_capture_on_commit_callbacks)
    _run_sends(minotaur)
    minotaur.mode = "refuse"
    second = _finding()
    _record_and_commit(second, _document(second), django_capture_on_commit_callbacks)
    _run_sends(minotaur)
    assert dict(ClosureEvidenceForward.objects.values_list("record__finding", "status")) == {
        first.pk: "failed", second.pk: "refused",
    }

    minotaur.mode = "up"
    with pytest.raises(CommandError, match="1 closure forward"):
        call_command("retry_closure_forwards")

    assert dict(ClosureEvidenceForward.objects.values_list("record__finding", "status")) == {
        first.pk: "sent", second.pk: "refused",
    }
    assert len(minotaur.calls) == 3, "the refused row was not sent again"


def test_a_lost_answer_is_unknown_and_sent_again_only_when_asked(minotaur, django_capture_on_commit_callbacks):
    minotaur.mode = "lost"
    finding = _finding()
    _record_and_commit(finding, _document(finding), django_capture_on_commit_callbacks)
    _run_sends(minotaur)
    assert ClosureEvidenceForward.objects.get().status == "unknown"
    assert len(minotaur.rows) == 1, "it was recorded; only the answer was lost"

    minotaur.mode = "up"
    with pytest.raises(CommandError):
        call_command("retry_closure_forwards")
    assert len(minotaur.calls) == 1, "an unknown outcome is not sent again unasked"

    call_command("retry_closure_forwards", "--unknown")
    assert ClosureEvidenceForward.objects.get().status == "sent"
    assert len(minotaur.rows) == 2


def test_a_forward_left_behind_by_a_dead_process_is_sent_once_it_is_stale(
    minotaur, django_capture_on_commit_callbacks
):
    finding = _finding()
    _record_and_commit(finding, _document(finding), django_capture_on_commit_callbacks)
    minotaur.spawned.clear()  # the process died before its send ran
    forward = ClosureEvidenceForward.objects.get()

    assert closure_forward.retry_due() == {}, "not yet stale: it may still be on its way"
    ClosureEvidenceForward.objects.filter(pk=forward.pk).update(
        status="sending", updated_at=timezone.now() - closure_forward.STALE_AFTER - timedelta(seconds=1)
    )
    assert closure_forward.retry_due() == {"sent": 1}
    assert len(minotaur.rows) == 1


def test_a_forward_fired_twice_adds_one_dataset_row(minotaur, django_capture_on_commit_callbacks):
    finding = _finding()
    _record_and_commit(finding, _document(finding), django_capture_on_commit_callbacks)
    pk = ClosureEvidenceForward.objects.get().pk

    assert closure_forward.deliver(pk) == "sent"
    assert closure_forward.deliver(pk) is None
    _run_sends(minotaur)  # the queued send, after the first already landed
    assert closure_forward.retry_due(unknown=True) == {}
    call_command("retry_closure_forwards", "--unknown")

    assert len(minotaur.calls) == 1
    assert ClosureEvidenceForward.objects.get().attempts == 1


def test_the_send_has_a_timeout_and_a_deadline_and_runs_off_the_request_thread():
    transport = closure_forward._transport()
    assert transport.timeout == closure_forward.TIMEOUT
    assert 0 < transport.deadline < float("inf")

    ran = {}
    done = threading.Event()

    def work():
        ran["thread"] = threading.current_thread()
        done.set()

    closure_forward._spawn(work)
    assert done.wait(5)
    assert ran["thread"] is not threading.current_thread()
    assert ran["thread"].daemon
