"""A stop in force keeps being served to its engine (AB-STOP-STAYS-SERVED).

``/api/failsafe/pending/`` re-served a signed command only while it was ready
and inside its window (FAILSAFE_COMMAND_TTL_SECONDS, 600 s). Eleven minutes
after a pause, a stand-down or a terminate was signed into force the poll
answered ``[]``: an engine that restarted then, or a second engine with the
same id, was told nothing. The plane kept no posture at all: commands with
windows, and one mark per engine that no resume or release ever touched.

Now a stop made ready is IN FORCE until a later signed start lifts it: a
resume lifts a pause, a release lifts a stand-down, nothing lifts a terminate.
While it is in force it stays ready and the poll answers it, whatever its
window, as the bytes the operators signed. No window, cancel or supersede
ends it.

Three more things this file holds, each found on the way and each failing on
master:

* one row the poll could not turn into a command answered the whole poll 500,
  and a readable ready stand-down of the same engine was lost with it;
* a stand-down drafted first and signed LAST, beside a release drafted after
  it and signed before it, was answered stand-down then release, and the
  engine ended running;
* an audit row that could not be written rolled a stop's signature back.

And what must not change: nothing on the path that drafts, signs or serves a
stop gains a write or a read (MASTER, below, is what master made).
"""

import importlib
import io
from collections import Counter
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.db import OperationalError, connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from tests.test_no_control_holds_back_a_stop import POLL_TOKEN, SERVICE_TOKEN, _admin, _client_for, _service_client
from tests.test_no_control_holds_back_a_stop import configure, rates, service  # noqa: F401 - fixtures, used by name
from tests.test_the_engine_poll_does_bounded_work import _measured

ENGINE = "athena-1"
IN_FORCE = "X-Failsafe-In-Force"
UNREADABLE = "X-Failsafe-Unreadable"
AUDIT_MISSED = "X-Failsafe-Audit-Missed"
BACK_IN_FORCE = "X-Failsafe-Back-In-Force"
PAST = "2000-01-01T00:00:00+00:00"
ELEVEN_MINUTES = 11 * 60

#: The data statements each stop path made on master (7413b0e), measured by
#: _statements below under this same harness: the first stop of an engine, and
#: every later one. Savepoints are not data statements and are not counted.
MASTER = {
    "draft": {"insert": 2, "select": 3},
    "sign first": {"insert": 3, "select": 4, "update": 3},
    "sign later": {"insert": 2, "select": 3, "update": 3},
    "poll": {"select": 7, "pragma": 3},
}

#: The data statements cancelling a resume that had lifted one pause made
#: before its audit event was attached to the pause, and before its answer said
#: more (025a3cd), measured the same way. Neither adds a statement.
CANCEL_OF_A_START_MADE_READY = {"select": 3, "update": 2, "insert": 2}


@pytest.fixture()
def keys(settings):
    made = {f"op{n}": Ed25519PrivateKey.generate() for n in range(2)}
    settings.FAILSAFE_OPERATOR_KEYS = {name: key.public_key().public_bytes_raw().hex() for name, key in made.items()}
    settings.FAILSAFE_COMMAND_TTL_SECONDS = 600
    return made


#: How far the plane's clock is ahead of the real one, in seconds (clock).
_AHEAD = [0.0]


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    """The plane's clock, moved on by ``clock(seconds)`` -- and by one second
    at every draft (_draft), so no two commands of a test are drafted in one
    tick of a clock that ties (Windows): which was drafted first is then never
    a matter of luck."""
    real = timezone.now
    _AHEAD[0] = 0.0
    monkeypatch.setattr(timezone, "now", lambda: real() + timedelta(seconds=_AHEAD[0]))

    def advance(seconds):
        _AHEAD[0] += seconds

    return advance


@pytest.fixture()
def operator():
    return _client_for(_admin())


def _ring(keys):
    return {name: key.public_key() for name, key in keys.items()}


def _draft(operator, action, engine_id=ENGINE, reason=""):
    _AHEAD[0] += 1.0
    answer = operator.post("/api/failsafe/commands/", {"action": action, "engine_id": engine_id, "reason": reason},
                           format="json")
    assert answer.status_code in (200, 201), answer.content
    return answer.data


def _sign(operator, drafted, keys, name):
    body = {"key_id": name, "sig": keys[name].sign(bytes.fromhex(drafted["signing_bytes"])).hex()}
    return operator.post(f"/api/failsafe/commands/{drafted['uuid']}/signatures/", body, format="json")


def _signed(operator, action, keys, engine_id=ENGINE, reason=""):
    """Draft ``action`` and sign it into force through the API, as operators do."""
    drafted = _draft(operator, action, engine_id, reason)
    for name in keys:
        answer = _sign(operator, drafted, keys, name)
        assert answer.status_code == 200, answer.content
        if answer.data["status"] == "ready":
            return drafted
    raise AssertionError(f"{action} was not made ready: {answer.data}")


def _poll(engine_id=ENGINE, **client):
    path = "/api/failsafe/pending/" + (f"?engine_id={engine_id}" if engine_id else "")
    return APIClient(**client).get(path, HTTP_X_FAILSAFE_POLL_TOKEN=POLL_TOKEN)


def _nonces(engine_id=ENGINE):
    answer = _poll(engine_id)
    assert answer.status_code == 200, answer.content[:300]
    return [command["nonce"] for command in answer.json()]


def _row(drafted):
    from failsafe.models import FailsafeCommand

    return FailsafeCommand.objects.get(uuid=drafted["uuid"])


def _statements(call):
    """(the answer, its data statements by kind, how many savepoint statements)."""
    with CaptureQueriesContext(connection) as queries:
        answer = call()
    kinds = Counter(query["sql"].split(None, 1)[0].lower() for query in queries.captured_queries)
    savepoints = sum(kinds.pop(word, 0) for word in ("savepoint", "release", "rollback"))
    return answer, dict(kinds), savepoints


# --- 1. A stop in force is answered, whatever its window ------------------------------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_pause_in_force_is_answered_after_its_window(keys, clock, operator):
    pause = _signed(operator, "pause", keys)
    assert _nonces() == [pause["nonce"]]
    clock(ELEVEN_MINUTES)
    assert _nonces() == [pause["nonce"]], "eleven minutes on, the poll answers nothing for an engine that is paused"
    clock(30 * 24 * 3600)
    answer = _poll()
    assert [c["nonce"] for c in answer.json()] == [pause["nonce"]], "a month on"
    assert answer[IN_FORCE] == "pause"


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_stand_down_in_force_is_answered_after_its_window(keys, clock, operator):
    stand_down = _signed(operator, "stand_down", keys)
    assert _nonces() == [stand_down["nonce"]]
    clock(ELEVEN_MINUTES)
    assert _nonces() == [stand_down["nonce"]], "eleven minutes on, the poll answers nothing for an engine stood down"
    assert _poll()[IN_FORCE] == "stand_down"


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_terminate_in_force_is_answered_and_named_after_its_window(keys, clock, operator):
    """The core applies a terminate only inside its window, so past it the
    answer still carries the terminate the operators signed, and the header
    names it for the engine to hold on. With a pause in force beside it, the
    header names both, the strongest first."""
    terminate = _signed(operator, "terminate", keys)
    assert _nonces() == [terminate["nonce"]]
    clock(ELEVEN_MINUTES)
    answer = _poll()
    assert [c["nonce"] for c in answer.json()] == [terminate["nonce"]], "eleven minutes on: nothing for a terminated engine"
    assert answer[IN_FORCE] == "terminate"
    pause = _signed(operator, "pause", keys)
    answer = _poll()
    assert [c["nonce"] for c in answer.json()] == [terminate["nonce"], pause["nonce"]]
    assert answer[IN_FORCE] == "terminate, pause"
    assert IN_FORCE not in _poll("another-engine")


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
@pytest.mark.parametrize("action", ["pause", "stand_down", "terminate"])
def test_what_is_served_again_is_the_bytes_the_operators_signed(action, keys, clock, operator):
    """Past its window the plane serves the document it served inside it,
    field for field. The pinned core, on a restarted engine (an empty nonce
    ledger) eleven minutes late, applies a pause and a stand-down and rejects a
    terminate as expired; on an engine that already applied it, the stop is a
    replay."""
    import time

    from mythos_core.failsafe import Command, NonceLedger, verify_command
    from mythos_core.failsafe.commands import CommandRejected

    _signed(operator, action, keys)
    inside = _poll().json()
    clock(ELEVEN_MINUTES)
    late = _poll().json()
    assert late == inside and len(late) == 1, "what is served again is not what the operators signed"
    document, engine_clock = Command.from_dict(late[0]), time.time() + ELEVEN_MINUTES + 60
    ledger = NonceLedger()
    if action == "terminate":
        with pytest.raises(CommandRejected, match="expired"):
            verify_command(document, keyring=_ring(keys), engine_id=ENGINE, nonces=ledger, now=engine_clock)
        return
    assert verify_command(document, keyring=_ring(keys), engine_id=ENGINE, nonces=ledger, now=engine_clock)
    with pytest.raises(CommandRejected, match="replay"):
        verify_command(document, keyring=_ring(keys), engine_id=ENGINE, nonces=ledger, now=engine_clock)


# --- 2. What lifts a stop, and what never does --------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
@pytest.mark.parametrize("stop,start", [("pause", "resume"), ("stand_down", "release")])
def test_a_later_resume_lifts_a_pause_and_a_later_release_a_stand_down(stop, start, keys, clock, operator):
    stopped = _signed(operator, stop, keys)
    clock(ELEVEN_MINUTES)
    assert _nonces() == [stopped["nonce"]], f"the {stop} in force is not answered"
    started = _signed(operator, start, keys)
    assert _nonces() == [started["nonce"]], f"the {stop} is still answered after the {start} that lifts it"
    row = _row(stopped)
    assert (row.in_force, str(row.lifted_by)) == (False, started["uuid"]) and row.lifted_at == _row(started).ready_at
    assert IN_FORCE not in _poll()
    clock(ELEVEN_MINUTES)
    assert _nonces() == [], "nothing is in force, and the start's window has passed"


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_resume_never_lifts_a_stand_down_and_a_release_never_a_pause(keys, clock, operator):
    """Strict matching, which never under-holds. Its cost, said in the state
    read: after a pause, a stand-down and a release, the pause is still
    answered until a resume is signed."""
    pause = _signed(operator, "pause", keys)
    stand_down = _signed(operator, "stand_down", keys)
    resume = _signed(operator, "resume", keys)
    assert _nonces() == [stand_down["nonce"], resume["nonce"]], "a resume lifts the pause, and only the pause"
    assert _row(stand_down).in_force and not _row(pause).in_force

    again = _signed(operator, "pause", keys)
    release = _signed(operator, "release", keys)
    assert _row(again).in_force, "a release lifted a pause"
    assert not _row(stand_down).in_force and str(_row(stand_down).lifted_by) == release["uuid"]
    clock(ELEVEN_MINUTES)
    assert _nonces() == [again["nonce"]], "after pause, stand-down, release: the pause is answered until a resume"
    state = operator.get(f"/api/failsafe/state/?engine_id={ENGINE}").data
    (listed,) = [row for row in state["ready"] if row["uuid"] == again["uuid"]]
    assert listed["lifted_only_by"] == "resume" and "stand-down and a release" in listed["in_force_note"]


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_start_made_ready_before_a_stop_neither_lifts_it_nor_follows_it(keys, operator):
    """A stand-down drafted first and signed LAST, beside a release drafted
    after it and signed before it. Master answered stand-down, pause, release,
    and a fresh governor ended running. The release is never delivered, it
    lifted nothing, and the state read marks it superseded, saying why. A
    release drafted and signed after the stand-down lifts it and is answered."""
    from mythos_core.failsafe import Command, Governor

    from failsafe.models import FailsafeAuditEvent

    pause = _signed(operator, "pause", keys)  # the engine's mark
    stand_down = _draft(operator, "stand_down")
    assert _sign(operator, stand_down, keys, "op0").data["status"] == "awaiting_signatures"
    release = _signed(operator, "release", keys)  # drafted after the stand-down, ready before it
    assert _sign(operator, stand_down, keys, "op1").data["status"] == "ready"  # signed into force LAST
    served = _poll().json()
    governor = Governor(engine_id=ENGINE, keyring=_ring(keys))
    for document in served:
        governor.apply(Command.from_dict(document))
    assert [c["nonce"] for c in served] == [stand_down["nonce"], pause["nonce"]], [c["action"] for c in served]
    assert governor.state.value == "stood_down"
    assert _row(stand_down).in_force and _row(stand_down).lifted_by is None

    operator.get(f"/api/failsafe/state/?engine_id={ENGINE}")
    assert _row(release).status == "superseded"
    event = FailsafeAuditEvent.objects.get(command=_row(release), event="superseded")
    assert event.detail["reason"].startswith("made ready at or before a stop was made ready for its engine")

    later = _signed(operator, "release", keys)
    assert _nonces() == [pause["nonce"], later["nonce"]]
    assert str(_row(stand_down).lifted_by) == later["uuid"]


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_start_drafted_before_a_stop_lifts_nothing(keys, clock, operator):
    """A resume drafted, then a pause signed into force, then the resume
    signed: the poll never delivers a start drafted at or before a stop of its
    engine, so it lifts nothing -- the pause stays in force and answered."""
    _signed(operator, "pause", keys, reason="the engine's mark")
    first = _signed(operator, "resume", keys)
    resume = _draft(operator, "resume", reason="drafted before the pause")
    pause = _signed(operator, "pause", keys, reason="signed after that draft")
    assert _sign(operator, resume, keys, "op0").data["status"] == "ready"
    assert _row(pause).in_force and _row(pause).lifted_by is None
    # Neither resume is answered: each was drafted before the pause now in force.
    assert _nonces() == [pause["nonce"]], (first["nonce"], resume["nonce"])
    clock(ELEVEN_MINUTES)
    assert _nonces() == [pause["nonce"]]
    # Nor does it lift an OLDER stop of its own kind when a stop of another
    # kind was signed into force after it was drafted: it is never delivered.
    late = _draft(operator, "resume", reason="drafted before the stand-down")
    stand_down = _signed(operator, "stand_down", keys)
    assert _sign(operator, late, keys, "op0").data["status"] == "ready"
    assert _row(pause).in_force, "a resume the poll never delivers lifted a pause"
    assert _nonces() == [stand_down["nonce"], pause["nonce"]]


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_start_signed_in_the_same_clock_tick_as_a_stop_is_still_after_it(keys, operator, monkeypatch):
    """A clock that ties (Windows ticks 15 ms apart): a pause and, after it, a
    resume, both made ready in one tick. The resume's ``ready_at`` is set
    strictly after the engine's last stop made ready, so it is delivered and
    lifts the pause. Read as signed WITH the pause it would be held back for
    good, and the operators' resume would do nothing."""
    pause = _draft(operator, "pause")
    resume = _draft(operator, "resume")
    tick = timezone.now() + timedelta(seconds=1)
    monkeypatch.setattr(timezone, "now", lambda: tick)
    assert _sign(operator, pause, keys, "op0").data["status"] == "ready"
    assert _sign(operator, resume, keys, "op0").data["status"] == "ready"
    assert _row(pause).ready_at == tick and _row(resume).ready_at == tick + timedelta(microseconds=1)
    assert _nonces() == [resume["nonce"]] and not _row(pause).in_force


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_cancel_a_passed_window_or_a_supersede_never_ends_a_stop_in_force(keys, clock, operator, settings):
    """A cancel needs no operator's key: on master one account's cancel ended
    a two-person stand-down for any engine that restarted. It is refused 409,
    saying what does end the stop. Reads that mark commands expired, and a
    flood of drafts past the account's limit, leave it ready and in force."""
    from failsafe.models import FailsafeCommand

    settings.FAILSAFE_UNSIGNED_STOP_DRAFTS_PER_ACCOUNT = 1
    said = {"pause": "Sign a resume drafted after it", "stand_down": "Sign a release drafted after it",
            "terminate": "Nothing ends a terminate"}
    stops = {action: _signed(operator, action, keys) for action in said}
    for action, stop in stops.items():
        cancel = operator.post(f"/api/failsafe/commands/{stop['uuid']}/cancel/", {}, format="json")
        assert cancel.status_code == 409, (action, cancel.status_code, cancel.content)
        assert "a cancel never ends a stop in force" in cancel.data["detail"] and said[action] in cancel.data["detail"]
    clock(ELEVEN_MINUTES)
    for n in range(3):  # a flood of drafts: each supersedes the account's older unsigned ones
        _draft(operator, "pause", reason=f"flood {n}")
    for _ in range(2):  # the reads that mark what is past its window expired
        assert operator.get(f"/api/failsafe/state/?engine_id={ENGINE}").status_code == 200
        assert operator.get("/api/failsafe/commands/").status_code == 200
    assert _nonces() == [stops[action]["nonce"] for action in ("terminate", "stand_down", "pause")]
    rows = FailsafeCommand.objects.filter(uuid__in=[stop["uuid"] for stop in stops.values()])
    assert {(row.status, row.in_force) for row in rows} == {("ready", True)}
    assert not any(row.mark_expired() or row.mark_canceled() or row.mark_consumed() for row in rows)
    assert {row.status for row in FailsafeCommand.objects.filter(uuid__in=[s["uuid"] for s in stops.values()])} == {"ready"}
    # A stop that was never made ready is cancelled as ever.
    unsigned = _draft(operator, "pause", reason="never signed")
    assert operator.post(f"/api/failsafe/commands/{unsigned['uuid']}/cancel/", {}, format="json").status_code == 200


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_lift_that_cannot_be_written_leaves_the_start_unsigned_and_the_stop_served(keys, clock, operator, monkeypatch):
    """The lift is written on the start's path only, in the transaction that
    signs the start into force. When it cannot be written the start is not
    made ready -- its signature is rolled back with it -- and the stop is
    answered as before. A start fails closed; no stop waits on any of it."""
    from django.db.models import QuerySet

    pause = _signed(operator, "pause", keys)
    clock(ELEVEN_MINUTES)
    real = QuerySet.update

    def no_lift(self, **fields):
        if "lifted_by" in fields:
            raise OperationalError("disk I/O error")
        return real(self, **fields)

    monkeypatch.setattr(QuerySet, "update", no_lift)
    resume = _draft(operator, "resume")
    refused = _sign(operator, resume, keys, "op0")
    assert refused.status_code == 503, (refused.status_code, refused.content)
    assert "was not made ready" in refused.data["detail"] and "stays in force" in refused.data["detail"]
    row = _row(resume)
    assert (row.status, row.signatures, row.ready_at) == ("awaiting_signatures", [], None)
    assert _row(pause).in_force and _nonces() == [pause["nonce"]]
    monkeypatch.setattr(QuerySet, "update", real)
    assert _sign(operator, resume, keys, "op0").data["status"] == "ready"
    assert _nonces() == [resume["nonce"]]


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_cancelling_a_start_puts_back_in_force_the_stop_it_lifted(keys, clock, operator):
    """A resume made ready lifts its pause. Cancelled before its engine heard
    it, it is no longer delivered, so the engine stays paused: the plane goes
    on answering the pause."""
    pause = _signed(operator, "pause", keys)
    clock(ELEVEN_MINUTES)
    resume = _signed(operator, "resume", keys)
    assert _nonces() == [resume["nonce"]] and not _row(pause).in_force
    cancel = operator.post(f"/api/failsafe/commands/{resume['uuid']}/cancel/", {}, format="json")
    assert cancel.status_code == 200 and cancel[BACK_IN_FORCE] == "1"
    row = _row(pause)
    assert (row.in_force, row.status, row.lifted_by, row.lifted_at) == (True, "ready", None, None)
    assert _nonces() == [pause["nonce"]]
    # The pause's own audit trail says it was put back, by the cancel of which start.
    from failsafe.models import FailsafeAuditEvent

    put_back = list(FailsafeAuditEvent.objects.filter(event="in_force"))
    assert [event.command_id for event in put_back] == [row.pk], "the event is not attached to the stop put back"
    assert put_back[0].detail["stop"] == pause["uuid"] and resume["uuid"] in put_back[0].detail["why"]
    assert "was cancelled" in put_back[0].detail["why"]
    assert "in_force" in [event.event for event in row.audit_events.all()]
    # The answer says which stops are back, and what that does not do.
    assert cancel.data["back_in_force"] == [pause["uuid"]], cancel.data.get("back_in_force", "(no such key)")
    # A start never made ready lifted nothing: its cancel reads nothing more and says nothing more.
    unsigned = _draft(operator, "resume")
    plain = operator.post(f"/api/failsafe/commands/{unsigned['uuid']}/cancel/", {}, format="json")
    assert plain.status_code == 200 and BACK_IN_FORCE not in plain
    assert "back_in_force" not in plain.data and "back_in_force_note" not in plain.data


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
@pytest.mark.parametrize(
    ("stop", "start", "to_stop_it_now"),
    [("pause", "resume", "sign a new pause."), ("stand_down", "release", "sign a new stand-down.")],
)
def test_the_cancel_of_a_start_made_ready_tells_the_operator_what_stops_the_engine_now(
    stop, start, to_stop_it_now, keys, clock, operator
):
    """The stop is back in force on the plane, and answered. But an engine
    that had already applied the start is running, and while it keeps running
    it rejects the old stop as a replay (the core's nonce ledger): the old stop
    stops it again only when it restarts. The cancel's answer says so, and
    what does stop it now. Saying it costs no statement."""
    stopped = _signed(operator, stop, keys)
    clock(ELEVEN_MINUTES)
    started = _signed(operator, start, keys)
    cancel, statements, _ = _statements(
        lambda: operator.post(f"/api/failsafe/commands/{started['uuid']}/cancel/", {}, format="json"))
    assert cancel.status_code == 200 and cancel[BACK_IN_FORCE] == "1"
    assert cancel.data["back_in_force"] == [stopped["uuid"]], cancel.data.get("back_in_force", "(no such key)")
    note = cancel.data["back_in_force_note"]
    assert "already applied" in note and "is running" in note and "replay" in note and "only when it restarts" in note
    assert note.endswith("To stop it now, " + to_stop_it_now), note
    assert _nonces() == [stopped["nonce"]]
    for kind in set(statements) | set(CANCEL_OF_A_START_MADE_READY):
        assert statements.get(kind, 0) <= CANCEL_OF_A_START_MADE_READY.get(kind, 0), statements


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_stops_that_could_not_be_put_back_are_said_as_null_and_the_cancel_stands(keys, clock, operator, monkeypatch):
    """When the stops a cancelled start had lifted cannot be put back in
    force, the cancel stands (it was written first), the header says
    ``unknown``, and the body says ``null``, never an empty list: nothing was
    put back, and the answer does not read as though nothing needed to be."""
    from django.db.models import QuerySet

    pause = _signed(operator, "pause", keys)
    resume = _signed(operator, "resume", keys)
    real = QuerySet.update

    def no_putting_back(self, **fields):
        if fields.get("in_force") is True:
            raise OperationalError("disk I/O error")
        return real(self, **fields)

    monkeypatch.setattr(QuerySet, "update", no_putting_back)
    cancel = operator.post(f"/api/failsafe/commands/{resume['uuid']}/cancel/", {}, format="json")
    monkeypatch.setattr(QuerySet, "update", real)
    assert cancel.status_code == 200 and cancel.data["status"] == "canceled" and cancel[BACK_IN_FORCE] == "unknown"
    assert "back_in_force" in cancel.data and cancel.data["back_in_force"] is None, cancel.data
    note = cancel.data["back_in_force_note"]
    assert "could not be put back in force" in note and note.endswith("To stop it now, sign a new pause."), note
    assert not _row(pause).in_force and _row(resume).status == "canceled"


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_cancelling_a_stop_a_start_already_lifted_says_it_was_lifted_and_by_which_start(keys, operator):
    """A pause a resume has lifted is still ``ready`` inside its window, and
    not in force. Its cancel is refused 409 as before, but not by telling the
    operator to sign the resume that was already signed: it says the pause was
    lifted, by which start and when, and that nothing is left to cancel."""
    pause = _signed(operator, "pause", keys)
    resume = _signed(operator, "resume", keys)
    lifted = _row(pause)
    assert (lifted.status, lifted.in_force, str(lifted.lifted_by)) == ("ready", False, resume["uuid"])
    cancel = operator.post(f"/api/failsafe/commands/{pause['uuid']}/cancel/", {}, format="json")
    assert cancel.status_code == 409, (cancel.status_code, cancel.content)
    said = cancel.data["detail"]
    assert "was lifted" in said and f"resume {resume['uuid']}" in said and lifted.lifted_at.isoformat() in said, said
    assert "nothing is left to cancel" in said, said
    assert "Sign a resume drafted after it" not in said and "a cancel never ends a stop in force" not in said, said
    after = _row(pause)
    assert (after.status, after.in_force, after.lifted_by, after.lifted_at) == (
        "ready", False, lifted.lifted_by, lifted.lifted_at)
    assert _nonces() == [resume["nonce"]]


# --- 3. Nothing on a stop's path gains a write or a read -------------------------------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_signing_a_stop_makes_no_more_statements_than_before_and_survives_every_other_write_failing(
    keys, operator, monkeypatch
):
    """Drafting and signing a stop make no more reads and no more writes than
    master did (MASTER): the stop's readiness is the one UPDATE it was, now
    carrying ``ready_at`` and ``in_force``; its mark is one UPDATE; its audit
    rows are the inserts they were. And the signature lands whatever else fails: with
    the mark's write and the audit insert both failing, the pause is ready, in
    force and answered, and the answer says two audit rows are missing."""
    from failsafe.models import FailsafeAuditEvent, FailsafeStopMark

    measured = {}
    for when in ("first", "later"):
        answer, measured["draft"], _ = _statements(
            lambda: operator.post("/api/failsafe/commands/", {"action": "pause", "engine_id": ENGINE}, format="json"))
        assert answer.status_code == 201
        signed, measured[f"sign {when}"], _ = _statements(lambda: _sign(operator, answer.data, keys, "op0"))  # noqa: B023
        assert signed.data["status"] == "ready"
        for path in ("draft", f"sign {when}"):
            for kind in set(measured[path]) | set(MASTER[path]):
                assert measured[path].get(kind, 0) <= MASTER[path].get(kind, 0), (path, measured[path], MASTER[path])
    print(f"\nSTATEMENTS master {MASTER}\nSTATEMENTS branch {measured}")

    def failing(*args, **kwargs):
        raise OperationalError("disk I/O error")

    drafted = _draft(operator, "pause", engine_id="athena-7")
    monkeypatch.setattr(FailsafeStopMark.objects, "filter", failing)
    monkeypatch.setattr(FailsafeAuditEvent.objects, "bulk_create", failing)
    monkeypatch.setattr(FailsafeAuditEvent.objects, "create", failing)
    monkeypatch.setattr(FailsafeAuditEvent, "save", failing)
    try:
        signed = _sign(operator, drafted, keys, "op0")
        outcome = (signed.status_code, signed.data.get("status"), signed.headers.get(AUDIT_MISSED))
    except OperationalError as exc:
        outcome = f"the signature raised {exc}"
    assert outcome == (200, "ready", "2"), outcome
    assert _row(drafted).in_force and _nonces("athena-7") == [drafted["nonce"]]


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_an_audit_row_that_cannot_be_written_never_holds_back_a_stop(keys, operator, monkeypatch, caplog):
    """The ``signed`` and ``ready`` audit rows were inserted inside the signing
    transaction with nothing around them: an insert that failed rolled the
    signature back and answered 500 -- a failed write holding back a stop. A
    stop's draft, its signature, its readiness and the cancel of a start all
    land now, whatever becomes of their audit rows; what is missing is logged
    as an error, counted and said on the answer and on the state read."""
    from failsafe import views
    from failsafe.models import FailsafeAuditEvent

    resume = _draft(operator, "resume")
    stand_down = _draft(operator, "stand_down")
    before = views.AUDIT_ROWS_MISSED.value if hasattr(views, "AUDIT_ROWS_MISSED") else 0

    def failing(*args, **kwargs):
        raise OperationalError("database or disk is full")

    monkeypatch.setattr(FailsafeAuditEvent.objects, "bulk_create", failing)
    monkeypatch.setattr(FailsafeAuditEvent.objects, "create", failing)
    monkeypatch.setattr(FailsafeAuditEvent, "save", failing)

    def code(call):
        try:
            answer = call()
            return answer.status_code, answer.headers.get(AUDIT_MISSED)
        except OperationalError as exc:
            return f"raised {exc}", None

    outcomes = {
        "first signature": code(lambda: _sign(operator, stand_down, keys, "op0")),
        "second signature": code(lambda: _sign(operator, stand_down, keys, "op1")),
        "a stop drafted": code(lambda: operator.post("/api/failsafe/commands/",
                                                     {"action": "pause", "engine_id": ENGINE}, format="json")),
        "a start cancelled": code(lambda: operator.post(f"/api/failsafe/commands/{resume['uuid']}/cancel/", {},
                                                        format="json")),
    }
    assert outcomes == {"first signature": (200, "1"), "second signature": (200, "2"), "a stop drafted": (201, "1"),
                        "a start cancelled": (200, "1")}, outcomes
    row = _row(stand_down)
    assert (row.status, row.in_force, len(row.signatures)) == ("ready", True, 2)
    assert _nonces() == [stand_down["nonce"]]
    assert _row(resume).status == "canceled"
    assert views.AUDIT_ROWS_MISSED.value - before == 5
    assert sum("AUDIT ROWS MISSING" in record.getMessage() for record in caplog.records) == 4
    state = operator.get(f"/api/failsafe/state/?engine_id={ENGINE}")
    assert int(state[AUDIT_MISSED]) >= 5
    # A START's audit rows still decide it: a resume whose audit row cannot be written is not signed.
    other = _draft(operator, "pause", engine_id="athena-8")
    assert code(lambda: _sign(operator, other, keys, "op0")) == (200, "2")
    start = None
    monkeypatch.undo()
    start = _draft(operator, "resume", engine_id="athena-8")
    monkeypatch.setattr(FailsafeAuditEvent, "save", failing)
    monkeypatch.setattr(FailsafeAuditEvent.objects, "bulk_create", failing)
    assert code(lambda: _sign(operator, start, keys, "op0"))[0] != 200
    assert _row(start).status == "awaiting_signatures" and _row(other).in_force


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_the_poll_writes_nothing_for_a_stop_in_force_and_never_waits_for_the_write_lock(keys, clock, operator):
    """The poll that answers a stop in force makes the statements the poll
    made on master and not one write: with no write it never asks for the
    database's write lock, which a stop being signed at that moment holds.
    The stop's row is as it was."""
    stand_down = _signed(operator, "stand_down", keys)
    inside, statements, _ = _statements(_poll)
    assert statements == MASTER["poll"], statements
    clock(ELEVEN_MINUTES)
    before = _row(stand_down)
    for _ in range(3):
        late, statements, _ = _statements(_poll)
        assert statements == MASTER["poll"], statements
        assert late.json() == inside.json()
    after = _row(stand_down)
    assert (after.status, after.in_force, after.updated_at) == ("ready", True, before.updated_at)
    print(f"\nSTATEMENTS poll: master {MASTER['poll']}, branch with a stop in force past its window {statements}")


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_thousand_lifted_stops_leave_the_poll_bounded_and_on_its_index(keys, clock, operator, monkeypatch):
    """A thousand pauses that were in force and were lifted, and one that is in
    force a month on: the poll loads that one row, in the statements it always
    made, by the index it always read (fsc_eng_st_act_ct) -- its work is not
    the history of stops."""
    from failsafe.models import FailsafeCommand

    pause = _signed(operator, "pause", keys)
    clock(30 * 24 * 3600)
    at = timezone.now() - timedelta(days=60)
    FailsafeCommand.objects.bulk_create(
        [
            FailsafeCommand(engine_id=ENGINE, action="pause", nonce=f"lifted-{n}", issued_at=PAST, expires_at=PAST,
                            status="expired", signed=True, signatures=[{"key_id": "op0", "sig": "00" * 64}],
                            ready_at=at, in_force=False, lifted_by=pause["uuid"], lifted_at=at)
            for n in range(1000)
        ],
        batch_size=500,
    )
    answer, loaded, statements, steps = _measured(f"/api/failsafe/pending/?engine_id={ENGINE}", monkeypatch)
    assert [c["nonce"] for c in answer.json()] == [pause["nonce"]]
    assert loaded == 1 and statements == sum(MASTER["poll"].values()), (loaded, statements)
    assert steps < 40, f"{steps * 100} SQLite steps: the poll walked the history of stops"
    with connection.cursor() as cursor:
        cursor.execute(
            "EXPLAIN QUERY PLAN "
            + str(FailsafeCommand.objects.filter(status="ready", engine_id=ENGINE, action="pause")
                  .order_by("-created_at", "-pk").values_list("pk", "created_at").query).replace("ready", "'ready'")
            .replace(f"= {ENGINE}", f"= '{ENGINE}'").replace("= pause", "= 'pause'")
        )
        plan = " ".join(str(row[-1]) for row in cursor.fetchall())
    assert "fsc_eng_st_act_ct" in plan, plan


# --- 4. A row that cannot be read, and a read that fails -----------------------------------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_one_unreadable_row_is_counted_and_every_other_stop_is_still_answered(keys, clock, operator, monkeypatch):
    """One ready row whose stored signatures are not signatures, beside a
    readable ready stand-down of the same engine: master answered 500, and the
    engine reads that as nothing pending. The stand-down is answered, the
    broken row is left out and counted, and the state read names it. The same
    when the row cannot even be loaded."""
    from failsafe.models import FailsafeCommand

    pause = _signed(operator, "pause", keys)
    stand_down = _signed(operator, "stand_down", keys)
    FailsafeCommand.objects.filter(uuid=pause["uuid"]).update(signatures=[1])
    for when in ("inside its window", "eleven minutes on"):
        answer = _poll(raise_request_exception=False)
        assert answer.status_code == 200, f"{when}: one broken row answered the whole poll {answer.status_code}"
        assert [c["nonce"] for c in answer.json()] == [stand_down["nonce"]], when
        # The pause is in force and not in the answer: the header still names it, for the engine to hold on.
        assert answer[UNREADABLE] == "1" and answer[IN_FORCE] == "stand_down, pause"
        clock(ELEVEN_MINUTES)

    state = operator.get(f"/api/failsafe/state/?engine_id={ENGINE}")
    assert state.status_code == 200 and state[UNREADABLE] == "1"
    (named,) = [row for row in state.data["ready"] if row.get("unreadable")]
    assert (named["uuid"], named["engine_id"], named["action"], named["status"]) == (
        pause["uuid"], ENGINE, "pause", "ready")
    assert "not served to its engine" in named["why"]
    assert [row["uuid"] for row in state.data["ready"] if not row.get("unreadable")] == [stand_down["uuid"]]
    listed = operator.get("/api/failsafe/commands/")
    assert listed.status_code == 200 and listed[UNREADABLE] == "1"

    # The row cannot be loaded at all: the read of all the rows fails, each is read by itself.
    broken = _row(pause).pk
    real = FailsafeCommand.from_db.__func__

    def from_db(cls, db, names, values):
        if values[list(names).index("id")] == broken:
            raise ValueError("the stored row does not decode")
        return real(cls, db, names, values)

    monkeypatch.setattr(FailsafeCommand, "from_db", classmethod(from_db))
    answer = _poll(raise_request_exception=False)
    assert answer.status_code == 200 and [c["nonce"] for c in answer.json()] == [stand_down["nonce"]]
    assert answer[UNREADABLE] == "1"
    state = operator.get(f"/api/failsafe/state/?engine_id={ENGINE}")
    (named,) = [row for row in state.data["ready"] if row.get("unreadable")]
    assert (named["uuid"], named["action"]) == (pause["uuid"], "pause")
    # A read that came across no such row says so: "0", never a missing header.
    assert _poll("another-engine")[UNREADABLE] == "0"


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_lane_that_cannot_be_read_is_never_answered_200(keys, operator, monkeypatch):
    """A guard, not a gap: when the plane's own record cannot be read at all
    the poll is not answered 200 with nothing in it. (It answers 500, which an
    engine holding at start-up reads as not heard.)"""
    from failsafe import views

    _signed(operator, "pause", keys)

    def unreadable(*args, **kwargs):
        raise OperationalError("disk I/O error")

    monkeypatch.setattr(views, "_lane_keys", unreadable)
    answer = _poll(raise_request_exception=False)
    assert answer.status_code == 500, answer.status_code


# --- 5. Order, and every engine --------------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_new_stand_down_comes_before_five_hundred_pauses_in_force(keys, operator):
    """The stops in force share the poll's stop lane and its order: terminate,
    then stand-down, then pause. A stand-down OLDER than five hundred pauses in
    force is still the first command of the first page, which is the only page
    the engine's client reads."""
    from failsafe.models import FailsafeCommand
    from failsafe.views import POLL_STOP_LIMIT

    stand_down = _signed(operator, "stand_down", keys)
    at = timezone.now()
    FailsafeCommand.objects.bulk_create(
        [
            FailsafeCommand(engine_id=ENGINE, action="pause", nonce=f"in-force-{n}", issued_at=PAST, expires_at=PAST,
                            status="ready", signed=True, signatures=[{"key_id": "op0", "sig": "00" * 64}],
                            ready_at=at, in_force=True)
            for n in range(POLL_STOP_LIMIT)
        ],
        batch_size=500,
    )
    answer = _poll()
    body = answer.json()
    assert body[0]["nonce"] == stand_down["nonce"], body[0]["action"]
    assert len(body) == POLL_STOP_LIMIT and answer["X-Failsafe-More"] == "true"
    assert answer[IN_FORCE] == "stand_down, pause"


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_the_poll_for_every_engine_answers_each_engines_stop_in_force(keys, clock, operator):
    """A poll that names no engine answers every engine's stop in force, and a
    resume for one engine lifts that engine's pause alone."""
    one = _signed(operator, "pause", keys, engine_id="athena-1")
    two = _signed(operator, "pause", keys, engine_id="athena-2")
    clock(ELEVEN_MINUTES)
    assert sorted(_nonces(None)) == sorted([one["nonce"], two["nonce"]]), "a poll for every engine answers nothing"
    resume = _signed(operator, "resume", keys, engine_id="athena-1")
    assert sorted(_nonces(None)) == sorted([two["nonce"], resume["nonce"]])
    assert _nonces("athena-2") == [two["nonce"]] and _row(two).in_force


@pytest.mark.django_db
@pytest.mark.usefixtures("rates", "service")
def test_the_state_read_lists_the_stops_in_force_and_what_lifts_each(keys, clock, operator):
    """Past its window a stop in force is still listed as ready, saying it is
    in force and what alone lifts it; the stop client's service token sees it
    too. A command that is not a stop in force has the row it always had."""
    stops = {action: _signed(operator, action, keys) for action in ("pause", "stand_down", "terminate")}
    resume = _draft(operator, "resume")
    plain_keys = set(operator.get(f"/api/failsafe/commands/{resume['uuid']}/").data)
    clock(ELEVEN_MINUTES)
    for reader in (operator, _service_client(SERVICE_TOKEN)):
        state = reader.get(f"/api/failsafe/state/?engine_id={ENGINE}")
        assert state.status_code == 200, state.content
        ready = {row["action"]: row for row in state.data["ready"]}
        assert set(ready) == set(stops), f"the stops in force are not listed: {sorted(ready)}"
        assert {action: row["lifted_only_by"] for action, row in ready.items()} == {
            "pause": "resume", "stand_down": "release", "terminate": None}
        for action, row in ready.items():
            assert row["in_force"] is True and row["status"] == "ready" and row["uuid"] == stops[action]["uuid"]
            assert row["ready_at"] and "answered to its engine on every poll" in row["in_force_note"]
            assert set(row) == plain_keys - {"signing_bytes"} | {"in_force", "ready_at", "lifted_only_by",
                                                                 "in_force_note"}
        assert "Nothing ends a terminate" in ready["terminate"]["in_force_note"]
    detail = operator.get(f"/api/failsafe/commands/{stops['pause']['uuid']}/").data
    assert detail["in_force"] is True and detail["lifted_only_by"] == "resume"


# --- 6. Deploy day -----------------------------------------------------------------------------------------


def _historic(action, at, engine_id, status, expires, ready_event=None, nonce=None):
    """A command as master left it: no ``ready_at``, not in force."""
    from failsafe.models import FailsafeAuditEvent, FailsafeCommand

    command = FailsafeCommand.objects.create(
        engine_id=engine_id, action=action, nonce=nonce or f"{engine_id}-{action}-{at.timestamp()}",
        issued_at=at.isoformat(), expires_at=expires, status=status, signed=True,
        signatures=[{"key_id": "op0", "sig": "00" * 64}],
    )
    FailsafeCommand.objects.filter(pk=command.pk).update(created_at=at, updated_at=at)
    if ready_event is not None:
        event = FailsafeAuditEvent.objects.create(command=command, event="ready")
        FailsafeAuditEvent.objects.filter(pk=event.pk).update(timestamp=ready_event)
    return FailsafeCommand.objects.get(pk=command.pk)


@pytest.mark.django_db
def test_the_migration_puts_in_force_only_a_stop_still_inside_its_window():
    """0006's backfill. ``ready_at`` comes from the audit trail. A stop that is
    ready and still inside its window -- answered today anyway -- is in force,
    unless a later start of its own kind already lifted it. A stop past its
    window is NOT put in force: its engine may have been restarted to clear
    it, and the migration must not stop a running engine."""
    from django.apps import apps

    from failsafe.models import FailsafeCommand, FailsafeStopMark

    backfill = importlib.import_module("failsafe.migrations.0006_a_stop_in_force").backfill
    now = timezone.now()
    inside, gone = (now + timedelta(minutes=5)).isoformat(), (now - timedelta(days=3)).isoformat()
    at = now - timedelta(minutes=4)
    live = _historic("pause", at, "e-live", "ready", inside, ready_event=at + timedelta(seconds=5))
    lifted = _historic("pause", at, "e-lifted", "ready", inside, ready_event=at + timedelta(seconds=5))
    resume = _historic("resume", at + timedelta(seconds=10), "e-lifted", "ready", inside,
                       ready_event=at + timedelta(seconds=20))
    not_by_a_release = _historic("pause", at, "e-release", "ready", inside, ready_event=at + timedelta(seconds=5))
    _historic("release", at + timedelta(seconds=10), "e-release", "ready", inside, ready_event=at + timedelta(seconds=20))
    old = now - timedelta(days=3, minutes=10)
    stood_down = _historic("stand_down", old, "e-old", "ready", gone, ready_event=old + timedelta(seconds=5))
    expired = _historic("terminate", old, "e-expired", "expired", gone, ready_event=old + timedelta(seconds=5))
    no_event = _historic("pause", at, "e-no-event", "ready", inside)
    never = _historic("pause", at, "e-never", "awaiting_signatures", inside)
    FailsafeStopMark.objects.create(engine_id="e-live", created_at=live.created_at, stop_uuid=live.uuid, action="pause")
    statuses = dict(FailsafeCommand.objects.values_list("pk", "status"))

    backfill(apps, None)

    got = {row.pk: row for row in FailsafeCommand.objects.all()}
    assert {pk: row.status for pk, row in got.items()} == statuses, "the migration wrote a status"
    assert {name: got[row.pk].in_force for name, row in {
        "live": live, "lifted": lifted, "not by a release": not_by_a_release, "past its window": stood_down,
        "expired": expired, "no event": no_event, "never ready": never, "a start": resume}.items()} == {
        "live": True, "lifted": False, "not by a release": True, "past its window": False, "expired": False,
        "no event": True, "never ready": False, "a start": False}
    assert got[live.pk].ready_at == at + timedelta(seconds=5) and got[no_event.pk].ready_at == no_event.updated_at
    assert got[never.pk].ready_at is None and got[expired.pk].ready_at == old + timedelta(seconds=5)
    assert (got[lifted.pk].lifted_by, got[lifted.pk].lifted_at) == (resume.uuid, at + timedelta(seconds=20))
    assert FailsafeStopMark.objects.get(engine_id="e-live").last_ready_at == at + timedelta(seconds=5)


@pytest.mark.django_db(transaction=True)
def test_the_migration_applies_forward_and_back_and_leaves_the_commands_as_they_were():
    """On a database at 0005 holding historic commands: 0006 applies forward,
    and rolled back it leaves every command, mark and audit event as it was,
    column for column."""
    from django.db.migrations.executor import MigrationExecutor

    before, after = ("failsafe", "0005_stop_marks"), ("failsafe", "0006_a_stop_in_force")
    now = timezone.now()
    inside, gone = (now + timedelta(minutes=5)).isoformat(), (now - timedelta(days=3)).isoformat()

    def snapshot(state):
        return {
            name: sorted(state.apps.get_model("failsafe", name).objects.values_list(), key=repr)
            for name in ("FailsafeCommand", "FailsafeStopMark", "FailsafeAuditEvent")
        }

    try:
        old = MigrationExecutor(connection).migrate([before])
        Command = old.apps.get_model("failsafe", "FailsafeCommand")
        assert not hasattr(Command, "in_force")
        rows = {}
        for name, action, status_, expires in (("live", "stand_down", "ready", inside), ("old", "pause", "ready", gone),
                                               ("spent", "terminate", "expired", gone),
                                               ("draft", "pause", "awaiting_signatures", inside)):
            rows[name] = Command.objects.create(engine_id=f"e-{name}", action=action, nonce=f"n-{name}",
                                                issued_at=now.isoformat(), expires_at=expires, status=status_,
                                                signed=True, signatures=[{"key_id": "op0", "sig": "00" * 64}])
        Event = old.apps.get_model("failsafe", "FailsafeAuditEvent")
        for name in ("live", "old", "spent"):
            Event.objects.create(command_id=rows[name].pk, event="ready")
        old.apps.get_model("failsafe", "FailsafeStopMark").objects.create(
            engine_id="e-live", created_at=rows["live"].created_at, stop_uuid=rows["live"].uuid, action="stand_down")
        was = snapshot(old)
        assert len(was["FailsafeCommand"]) == 4

        new = MigrationExecutor(connection).migrate([after])
        Command = new.apps.get_model("failsafe", "FailsafeCommand")
        forward = {row.nonce: row for row in Command.objects.all()}
        assert {nonce: row.in_force for nonce, row in forward.items()} == {
            "n-live": True, "n-old": False, "n-spent": False, "n-draft": False}
        assert {nonce: row.ready_at is not None for nonce, row in forward.items()} == {
            "n-live": True, "n-old": True, "n-spent": True, "n-draft": False}
        assert {nonce: row.status for nonce, row in forward.items()} == {
            "n-live": "ready", "n-old": "ready", "n-spent": "expired", "n-draft": "awaiting_signatures"}

        back = MigrationExecutor(connection).migrate([before])
        assert snapshot(back) == was, "a rollback did not leave the commands as they were"
    finally:
        MigrationExecutor(connection).migrate([after])


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_the_historic_stops_command_lists_by_default_and_applies_only_what_is_named():
    """The owner's choice. A historic stop past its window is listed, with
    whether the rule would have it in force and why, and nothing is changed.
    ``--apply`` puts in force only a stop that is named, listed for the engine
    named, and that the rule would have in force; then its engine's poll is
    answered with it."""
    from django.core.management import call_command
    from django.core.management.base import CommandError

    from failsafe.models import FailsafeAuditEvent, FailsafeCommand

    old = timezone.now() - timedelta(days=3)
    stood_down = _historic("stand_down", old, "e-old", "expired", PAST)
    paused = _historic("pause", old, "e-resumed", "expired", PAST)
    resume = _historic("resume", old + timedelta(minutes=1), "e-resumed", "expired", PAST)
    for row, at in ((stood_down, old), (paused, old), (resume, old + timedelta(minutes=2))):
        FailsafeCommand.objects.filter(pk=row.pk).update(ready_at=at + timedelta(seconds=5))

    def run(*args):
        out = io.StringIO()
        call_command("failsafe_historic_stops", *args, stdout=out)
        return out.getvalue()

    def state():
        return sorted(FailsafeCommand.objects.values_list("uuid", "status", "in_force"))

    was = state()
    listing = run()
    assert f"e-old\tstand_down\t{stood_down.uuid}" in listing and "WOULD BE IN FORCE: no release" in listing
    assert f"e-resumed\tpause\t{paused.uuid}" in listing and f"not in force: the resume {resume.uuid}" in listing
    assert "Dry run: nothing was changed" in listing and state() == was
    assert str(stood_down.uuid) not in run("--engine", "e-resumed")
    assert run("--engine", "e-old", "--stop", str(stood_down.uuid)).count("Dry run") == 1 and state() == was
    for refused in (("--apply",), ("--apply", "--engine", "e-old"), ("--apply", "--stop", str(stood_down.uuid)),
                    ("--apply", "--engine", "e-resumed", "--stop", str(paused.uuid)),
                    ("--apply", "--engine", "e-resumed", "--stop", str(stood_down.uuid))):
        with pytest.raises(CommandError):
            run(*refused)
        assert state() == was, refused
    assert _nonces("e-old") == []
    assert f"IN FORCE: stand_down {stood_down.uuid} of e-old" in run("--apply", "--engine", "e-old", "--stop",
                                                                     str(stood_down.uuid))
    row = FailsafeCommand.objects.get(pk=stood_down.pk)
    assert (row.in_force, row.status) == (True, "ready") and _nonces("e-old") == [stood_down.nonce]
    assert FailsafeAuditEvent.objects.filter(command=row, event="in_force").count() == 1
    assert FailsafeCommand.objects.get(pk=paused.pk).in_force is False
    assert str(stood_down.uuid) not in run()
