"""The closure forward sends Blue's own Minotaur credential, never a shared runner key.

Roadmap: "Blue cannot touch production without approval ... bound with separate
credentials and read/write permissions. A shared administrator credential across
roles is not separation." Minotaur-Backend's ``runner`` key drove campaigns, recorded
Blue's remediation outcomes, posted release decisions, imported runs and aborted --
and this backend's closure producer held it (``MINOTAUR_RUNNER_KEY``) to record one
thing: a replay row on ``POST /remediation-outcomes``. Minotaur-Backend now issues a
key of the ``outcome-recorder`` role, which reaches that route and nothing else, and
this producer sends it (``MINOTAUR_OUTCOMES_KEY``).

- Blue's key, when set, is the one sent -- from the settings or the environment --
  and the runner key is never sent beside it.
- The legacy runner key still forwards when it is the only one set, with a loud
  warning, and the credential is reported as not separated.
- One secret set as both is one credential for two roles: never sent, logged as an
  error at start, and only ever a WARNING in ``manage.py check`` (``assurance.W305``):
  a check error would refuse every command that runs the checks, the scheduled scan
  Stop delivery (``deliver_owed_stops``) among them.
- No credential setting -- shared, holding non-ASCII text, or unreadable -- fails a
  record, a command or the start.

Every call is answered in process by :class:`RoleSplitMinotaur`, which holds each key
to its route as Minotaur-Backend does. Nothing reaches the network, and nothing here
is a stop or stands in front of one.
"""

from __future__ import annotations

import io
import logging

import pytest
from django.apps import apps
from django.core import checks as django_checks
from django.core.management import call_command

from assurance import closure_forward
from assurance.models import ClosureEvidenceForward
from tests.test_a_closure_stands_only_on_a_replay_the_engine_service_recorded import _document, _finding
from tests.test_a_recorded_closure_becomes_one_dataset_row import (
    MINOTAUR,
    ROW_FIELDS,
    _Answer,
    _record_and_commit,
    _run_sends,
    service,  # noqa: F401 - the engine service's identity, autouse
)

pytestmark = pytest.mark.django_db

#: Blue's outcome-recorder key and the legacy runner key, as the tests configure them.
OUTCOMES_KEY = "minotaur-outcome-recorder-key-for-tests"  # pragma: allowlist secret
RUNNER_KEY = "minotaur-runner-key-for-tests"  # pragma: allowlist secret


class RoleSplitMinotaur:
    """Minotaur-Backend after the split, in process: ``POST /remediation-outcomes``
    takes Blue's outcome-recorder key and the legacy runner key; any other key is a
    401. Every other route this test could reach would refuse the outcome recorder."""

    def __init__(self):
        self.calls = []
        self.rows = []

    def post(self, url, *, headers, json):
        self.calls.append((url, dict(headers), json))
        if url != MINOTAUR + "/remediation-outcomes":
            return _Answer(403, {"error": "the outcome recorder reaches no other route"})
        if headers.get("X-Minotaur-Key") not in (OUTCOMES_KEY, RUNNER_KEY):
            return _Answer(401, {"error": "a valid X-Minotaur-Key is required"})
        if not isinstance(json, dict) or not ROW_FIELDS <= set(json):
            return _Answer(400, {"error": "the row cannot be read"})
        self.rows.append(json)
        return _Answer(201, {"id": len(self.rows), **json})


@pytest.fixture
def minotaur(settings, monkeypatch):
    settings.MINOTAUR_OUTCOMES_URL = MINOTAUR
    settings.MINOTAUR_RUNNER_KEY = None
    settings.MINOTAUR_OUTCOMES_KEY = None
    monkeypatch.delenv("MINOTAUR_OUTCOMES_KEY", raising=False)
    fake = RoleSplitMinotaur()
    fake.spawned = []
    monkeypatch.setattr(closure_forward, "_transport", lambda: fake)
    monkeypatch.setattr(closure_forward, "_spawn", fake.spawned.append)
    return fake


def _forward_one(minotaur, capture):
    finding = _finding()
    answer = _record_and_commit(finding, _document(finding), capture)
    assert answer.status_code == 201, answer.content
    _run_sends(minotaur)
    return answer


def _sent_keys(minotaur):
    return [headers.get("X-Minotaur-Key") for _url, headers, _json in minotaur.calls]


def _problems():
    return [(problem.level, problem.id, problem.msg) for problem in closure_forward_check()]


def closure_forward_check():
    from assurance.checks import closure_forward_credentials

    return closure_forward_credentials()


def test_blue_s_outcome_recorder_key_is_the_one_sent(minotaur, settings, django_capture_on_commit_callbacks):
    """Blue's own key is sent, and the runner key is never sent beside it: set too, it
    is unused, and a warning says to unset it."""
    settings.MINOTAUR_OUTCOMES_KEY = OUTCOMES_KEY
    settings.MINOTAUR_RUNNER_KEY = RUNNER_KEY

    answer = _forward_one(minotaur, django_capture_on_commit_callbacks)

    assert answer.json()["dataset_forward"] == "queued"
    assert _sent_keys(minotaur) == [OUTCOMES_KEY]
    assert ClosureEvidenceForward.objects.get().status == "sent"
    found = closure_forward.credential()
    assert (found.setting, found.separation, found.problem) == ("MINOTAUR_OUTCOMES_KEY", "in force", "")
    assert OUTCOMES_KEY not in found.report() and "in force" in found.report()
    assert OUTCOMES_KEY not in repr(found)
    [(level, ident, message)] = _problems()
    assert level == django_checks.WARNING and ident == "assurance.W304"
    assert "MINOTAUR_RUNNER_KEY is set beside MINOTAUR_OUTCOMES_KEY and is not sent" in message


def test_blue_s_key_is_read_from_the_environment_when_the_settings_name_none(
    minotaur, settings, monkeypatch, django_capture_on_commit_callbacks
):
    del settings.MINOTAUR_OUTCOMES_KEY
    monkeypatch.setenv("MINOTAUR_OUTCOMES_KEY", OUTCOMES_KEY)

    _forward_one(minotaur, django_capture_on_commit_callbacks)

    assert _sent_keys(minotaur) == [OUTCOMES_KEY]
    assert _problems() == []


def test_the_legacy_runner_key_still_forwards_and_says_separation_is_not_in_force(
    minotaur, settings, caplog, django_capture_on_commit_callbacks
):
    """An unmoved deployment keeps forwarding: the one runner key is sent. It is said
    loudly -- a warning from `manage.py check`, a log line at start, the retry
    command's report -- and reported as not separated."""
    settings.MINOTAUR_RUNNER_KEY = RUNNER_KEY

    answer = _forward_one(minotaur, django_capture_on_commit_callbacks)

    assert answer.json()["dataset_forward"] == "queued"
    assert _sent_keys(minotaur) == [RUNNER_KEY]
    assert ClosureEvidenceForward.objects.get().status == "sent"
    found = closure_forward.credential()
    assert (found.setting, found.separation) == ("MINOTAUR_RUNNER_KEY", "not in force")
    assert "not in force" in found.report() and RUNNER_KEY not in found.report()
    [(level, ident, message)] = _problems()
    assert level == django_checks.WARNING and ident == "assurance.W304"
    assert "shared runner key" in message and "role separation is not in force" in message
    with caplog.at_level(logging.WARNING, logger="assurance.closure_forward"):
        closure_forward.say_credential()
    assert any("ROLE SEPARATION" in r.getMessage() and "not in force" in r.getMessage() for r in caplog.records)
    assert all(RUNNER_KEY not in r.getMessage() for r in caplog.records)


def test_one_secret_as_both_credentials_is_never_sent(minotaur, settings, caplog, django_capture_on_commit_callbacks):
    """The same secret set as Blue's key and the runner key is one credential for two
    roles: nothing queued, nothing sent, an error line at start and a WARNING in the
    checks -- and the store still records."""
    settings.MINOTAUR_OUTCOMES_KEY = RUNNER_KEY
    settings.MINOTAUR_RUNNER_KEY = RUNNER_KEY

    answer = _forward_one(minotaur, django_capture_on_commit_callbacks)

    assert answer.status_code == 201
    assert answer.json()["dataset_forward"] == "off"
    assert minotaur.calls == [] and ClosureEvidenceForward.objects.count() == 0
    assert closure_forward.configured() is None
    [(level, ident, message)] = _problems()
    assert level == django_checks.WARNING and ident == "assurance.W305"
    assert "one credential for two roles" in message and RUNNER_KEY not in message
    with caplog.at_level(logging.ERROR, logger="assurance.closure_forward"):
        closure_forward.say_credential()
    assert any("one credential for two roles" in r.getMessage() for r in caplog.records)


def test_a_forward_queued_before_the_keys_were_made_one_is_not_sent_under_them(
    minotaur, settings, django_capture_on_commit_callbacks
):
    """A forward already queued is held to the credential at the moment of sending:
    one secret as both is refused then too, recorded `failed` with why, and retried
    once the keys differ."""
    settings.MINOTAUR_OUTCOMES_KEY = OUTCOMES_KEY
    finding = _finding()
    _record_and_commit(finding, _document(finding), django_capture_on_commit_callbacks)
    settings.MINOTAUR_OUTCOMES_KEY = RUNNER_KEY
    settings.MINOTAUR_RUNNER_KEY = RUNNER_KEY

    _run_sends(minotaur)

    assert minotaur.calls == []
    forward = ClosureEvidenceForward.objects.get()
    assert forward.status == "failed" and "one credential for two roles" in forward.last_error

    settings.MINOTAUR_OUTCOMES_KEY = OUTCOMES_KEY
    call_command("retry_closure_forwards")
    assert _sent_keys(minotaur) == [OUTCOMES_KEY]
    assert ClosureEvidenceForward.objects.get().status == "sent"


def test_no_credential_is_off(minotaur, django_capture_on_commit_callbacks):
    answer = _forward_one(minotaur, django_capture_on_commit_callbacks)

    assert answer.json()["dataset_forward"] == "off"
    assert minotaur.calls == []
    assert _problems() == []


def test_the_check_is_registered():
    from assurance.checks import closure_forward_credentials

    assert closure_forward_credentials in django_checks.registry.registry.get_checks()


# --- nothing here refuses a command, a Stop's delivery, a record or the start ---------

SHARED = "one-secret-0001"  # pragma: allowlist secret


@pytest.fixture
def owed_stops(monkeypatch):
    """``deliver_owed_stops``'s handle, observed: the calls its ``_owed`` received."""
    from pentest.management.commands import deliver_owed_stops
    from pentest.models import PentestScan

    calls = []

    def owed():
        calls.append("owed")
        return PentestScan.objects.none()

    monkeypatch.setattr(deliver_owed_stops, "_owed", owed)
    return calls


def test_one_secret_as_both_never_refuses_the_stop_delivery_or_any_command(minotaur, settings, owed_stops):
    """SAFETY: the shared secret is a WARNING in the checks, so the scheduled scan-Stop
    delivery runs its handle with the checks on, and so do migrate and check."""
    settings.MINOTAUR_OUTCOMES_KEY = SHARED
    settings.MINOTAUR_RUNNER_KEY = SHARED

    call_command("deliver_owed_stops", skip_checks=False, stdout=io.StringIO(), stderr=io.StringIO())
    assert owed_stops, "deliver_owed_stops never reached its handle"
    call_command("migrate", plan=True, skip_checks=False, stdout=io.StringIO(), stderr=io.StringIO())
    call_command("check", stdout=io.StringIO(), stderr=io.StringIO())
    [(level, ident, _message)] = _problems()
    assert (level, ident) == (django_checks.WARNING, "assurance.W305")


@pytest.mark.parametrize(
    "outcomes, legacy",
    [
        ("outcomes-\u2019-0001", "runner-0002"),
        ("outcomes-0001", "runner-\u2019-0002"),
        ("outcomes-\u00e9-0001", "outcomes-\u00e9-0001"),
        ("outcomes-\udcff-0001", "runner-0002"),
    ],
    ids=["non-ascii-blue", "non-ascii-runner", "non-ascii-shared", "lone-surrogate"],
)
def test_a_secret_holding_non_ascii_text_fails_nothing(
    minotaur, settings, owed_stops, caplog, django_capture_on_commit_callbacks, outcomes, legacy
):
    """A key holding text ``compare_digest`` cannot compare as text: the check, the
    Stop delivery, the start line and a record all go ahead, and the two keys are still
    told apart -- or told to be one -- on their bytes."""
    settings.MINOTAUR_OUTCOMES_KEY = outcomes
    settings.MINOTAUR_RUNNER_KEY = legacy

    found = closure_forward.credential()
    assert (found.problem != "") == (outcomes == legacy)
    call_command("check", stdout=io.StringIO(), stderr=io.StringIO())
    call_command("deliver_owed_stops", skip_checks=False, stdout=io.StringIO(), stderr=io.StringIO())
    assert owed_stops
    with caplog.at_level(logging.WARNING, logger="assurance.closure_forward"):
        closure_forward.say_credential()
    assert not [r for r in caplog.records if "could not be read" in r.getMessage()]
    finding = _finding()
    answer = _record_and_commit(finding, _document(finding), django_capture_on_commit_callbacks)
    assert answer.status_code == 201, answer.content
    assert answer.json()["dataset_forward"] == ("off" if outcomes == legacy else "queued")


def test_a_setting_that_cannot_be_read_never_fails_the_record(
    minotaur, settings, monkeypatch, caplog, django_capture_on_commit_callbacks
):
    """Whatever reading the credential raises, the record is kept (201) and forwarding
    is off: nothing about the forward can roll back the store's transaction."""
    settings.MINOTAUR_OUTCOMES_KEY = OUTCOMES_KEY

    def unreadable():
        raise RuntimeError("the settings could not be read")

    monkeypatch.setattr(closure_forward, "credential", unreadable)
    finding = _finding()
    with caplog.at_level(logging.ERROR, logger="assurance.closure_forward"):
        answer = _record_and_commit(finding, _document(finding), django_capture_on_commit_callbacks)
    assert answer.status_code == 201, answer.content
    assert answer.json()["dataset_forward"] == "off"
    assert ClosureEvidenceForward.objects.count() == 0
    assert any("forwarding is off" in r.getMessage() for r in caplog.records)
    [(level, ident, message)] = _problems()
    assert (level, ident) == (django_checks.WARNING, "assurance.W305") and "could not be read" in message


def test_each_process_says_its_credential_at_start(minotaur, settings, monkeypatch, caplog):
    """`AssuranceConfig.ready` says the credential: with the legacy runner key alone,
    the start logs that role separation is not in force -- never the key."""
    from assurance import observability

    settings.MINOTAUR_RUNNER_KEY = RUNNER_KEY
    monkeypatch.setattr(observability, "configure", lambda *a, **k: False)
    with caplog.at_level(logging.WARNING, logger="assurance.closure_forward"):
        apps.get_app_config("assurance").ready()
    said = [r.getMessage() for r in caplog.records if "ROLE SEPARATION" in r.getMessage()]
    assert said and "not in force" in said[0]
    assert all(RUNNER_KEY not in line for line in said)


@pytest.mark.parametrize("setting, key", [("MINOTAUR_OUTCOMES_KEY", OUTCOMES_KEY), ("MINOTAUR_RUNNER_KEY", RUNNER_KEY)])
def test_the_retry_command_never_prints_the_key(minotaur, settings, django_capture_on_commit_callbacks, setting, key):
    setattr(settings, setting, key)
    finding = _finding()
    _record_and_commit(finding, _document(finding), django_capture_on_commit_callbacks)
    minotaur.spawned.clear()
    ClosureEvidenceForward.objects.update(status=ClosureEvidenceForward.Status.FAILED)
    out, err = io.StringIO(), io.StringIO()
    call_command("retry_closure_forwards", stdout=out, stderr=err)
    printed = out.getvalue() + err.getvalue()
    assert "closure forward credential:" in printed and key not in printed
    assert _sent_keys(minotaur) == [key]
