"""A start lifts only a stop it was issued after (AB-STOP-FIXES, part 2).

The plane decided "after" by each command's ``created_at``, the instant its
row was inserted. The engine decides by ``issued_at``, the instant the
operators signed: Mythos-Core #88's governor refuses a resume or a release
whose ``issued_at`` is not strictly later than the latest stop it accepted.
The two are separate reads of the clock -- make_draft's, then the INSERT's --
so a start drafted within one tick of a stop (Windows ticks 15 ms apart), or
across a thread switch between those two lines, could be later by one and not
by the other. The plane then lifted the stop, stopped serving it and dropped
it from X-Failsafe-In-Force, while the engine refused the start and stayed
stopped; and when the engine restarted, the plane served it no stop at all,
and it ran.

Now a start lifts nothing, and is never delivered, unless its ``issued_at``
is strictly later than the engine's mark (which keeps the latest ``issued_at``
of any stop made ready for it, migration 0007) and than every stop in force,
as well as later by ``created_at`` as before. The plane is at least as strict
as the engine's order, so it never serves a start the engine would refuse.

And the one place the two still disagree by design is said where the operator
reads it: after a pause, a stand-down and a release, the plane keeps the pause
in force (a release lifts only stand-downs), while an engine that applied the
release is running until it restarts.
"""

import importlib
from datetime import datetime, timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.db import connection
from django.utils import timezone

from tests import test_a_stop_in_force_keeps_being_served as served
from tests.test_a_stop_in_force_keeps_being_served import ENGINE, IN_FORCE, _draft, _nonces, _poll, _ring, _row, _sign
from tests.test_a_stop_in_force_keeps_being_served import _signed
from tests.test_no_control_holds_back_a_stop import _admin, _client_for
from tests.test_no_control_holds_back_a_stop import configure, rates, service  # noqa: F401 - fixtures, used by name

#: How each scenario's start is issued against its stop, all drafted (created) after it:
#: the same signed instant (S3: one coarse clock tick), or a millisecond before it
#: (S4, S8: a thread switch between make_draft and the INSERT).
SHIFTS = {"the same issued_at": timedelta(0), "issued 1 ms earlier": timedelta(milliseconds=-1)}
PAIRS = [("pause", "resume"), ("stand_down", "release")]


@pytest.fixture()
def keys(settings):
    made = {f"op{n}": Ed25519PrivateKey.generate() for n in range(2)}
    settings.FAILSAFE_OPERATOR_KEYS = {name: key.public_key().public_bytes_raw().hex() for name, key in made.items()}
    settings.FAILSAFE_COMMAND_TTL_SECONDS = 600
    return made


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    """The plane's clock, as test_a_stop_in_force_keeps_being_served keeps it:
    moved on by ``clock(seconds)``, and by one second at every draft (its
    _draft), so which command was drafted first is never a matter of a clock
    that ties (Windows)."""
    real = timezone.now
    served._AHEAD[0] = 0.0
    monkeypatch.setattr(timezone, "now", lambda: real() + timedelta(seconds=served._AHEAD[0]))

    def advance(seconds):
        served._AHEAD[0] += seconds

    return advance


@pytest.fixture()
def operator():
    return _client_for(_admin())


def _instant(text):
    return datetime.fromisoformat(text)


def _draft_issued_at(operator, action, issued, monkeypatch, engine_id=ENGINE):
    """Draft ``action`` now (so its row is created after everything before it),
    signed as issued at ``issued``: the draft's ``issued_at`` is that instant,
    as a draft whose two clock reads disagreed has it."""
    from failsafe import views

    real = views.make_draft

    def shifted(*args, **kwargs):
        draft = real(*args, **kwargs)
        draft["issued_at"] = issued.isoformat()
        return draft

    monkeypatch.setattr(views, "make_draft", shifted)
    try:
        return _draft(operator, action, engine_id)
    finally:
        monkeypatch.setattr(views, "make_draft", real)


def _sign_all(operator, drafted, keys):
    for name in keys:
        answer = _sign(operator, drafted, keys, name)
        assert answer.status_code == 200, answer.content
        if answer.data["status"] == "ready":
            return answer
    raise AssertionError(answer.data)


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
@pytest.mark.parametrize("shift", list(SHIFTS))
@pytest.mark.parametrize("stop,start", PAIRS)
def test_a_start_not_issued_strictly_after_a_stop_never_lifts_it(stop, start, shift, keys, operator, monkeypatch):
    """S3, S4, S8. A stop signed into force, then a start of the kind that
    lifts it, drafted after it but issued at or before it, signed into force.
    Master lifted the stop, served the start alone and named nothing in
    force. The stop stays in force (``lifted_by`` None), the poll serves it and
    not the start, X-Failsafe-In-Force names it, the state read lists it in
    force, and the start's ready event says why it lifted nothing."""
    from failsafe.models import FailsafeAuditEvent

    stopped = _signed(operator, stop, keys)
    started = _draft_issued_at(operator, start, _instant(stopped["issued_at"]) + SHIFTS[shift], monkeypatch)
    assert _row(started).created_at > _row(stopped).created_at, "the start must be drafted after the stop"
    assert _sign_all(operator, started, keys).data["status"] == "ready"

    row = _row(stopped)
    assert (row.in_force, row.lifted_by, row.lifted_at) == (True, None, None), "a start issued at or before it lifted it"
    answer = _poll()
    assert [c["nonce"] for c in answer.json()] == [stopped["nonce"]], [c["action"] for c in answer.json()]
    assert answer[IN_FORCE] == stop
    state = operator.get(f"/api/failsafe/state/?engine_id={ENGINE}").data
    assert [r["uuid"] for r in state["ready"] if r.get("in_force")] == [stopped["uuid"]]
    ready = FailsafeAuditEvent.objects.get(command=_row(started), event="ready")
    assert ready.detail["lifted"] == [] and "issued" in ready.detail["lifts_nothing"], ready.detail


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
@pytest.mark.parametrize("stop,start", PAIRS)
def test_a_start_issued_before_a_stop_is_held_by_the_poll_and_superseded_by_the_state_read(
    stop, start, keys, operator, monkeypatch
):
    """The poll judges a start on its own, whatever its signature lifted, and
    the state read marks a held start superseded, saying why. A start issued
    a millisecond before the stop it follows, drafted and signed after it, is
    never served beside it; then the state read supersedes it, naming the
    stop. A start issued after the stop is answered, and lifts it."""
    from failsafe.models import FailsafeAuditEvent

    stopped = _signed(operator, stop, keys)
    early = _draft_issued_at(operator, start, _instant(stopped["issued_at"]) - timedelta(milliseconds=1), monkeypatch)
    _sign_all(operator, early, keys)
    assert _nonces() == [stopped["nonce"]], "a start issued before the stop was served after it"
    operator.get(f"/api/failsafe/state/?engine_id={ENGINE}")
    assert _row(early).status == "superseded"
    event = FailsafeAuditEvent.objects.get(command=_row(early), event="superseded")
    assert event.detail["superseded_by"] == stopped["uuid"]
    assert event.detail["reason"].startswith("issued at or before"), event.detail["reason"]

    later = _signed(operator, start, keys)
    assert _nonces() == [later["nonce"]] and str(_row(stopped).lifted_by) == later["uuid"]


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_ready_stop_holds_a_start_issued_before_it_past_a_stale_mark(keys, operator, monkeypatch):
    """The mark could not be moved when a stand-down was signed (its write
    failed, logged), so it still names an older pause and its instant. While
    the stand-down is ready, the poll holds back a release drafted after it but
    issued before it, by the stand-down on its own page; and a ready stop whose
    ``issued_at`` cannot be read holds back every start of its engine."""
    from failsafe.models import FailsafeCommand, FailsafeStopMark

    pause = _signed(operator, "pause", keys)
    stand_down = _signed(operator, "stand_down", keys)
    FailsafeStopMark.objects.filter(engine_id=ENGINE).update(
        created_at=_row(pause).created_at, stop_uuid=pause["uuid"], action="pause", issued=_instant(pause["issued_at"]))
    release = _draft_issued_at(operator, "release", _instant(stand_down["issued_at"]) - timedelta(milliseconds=1),
                               monkeypatch)
    _sign_all(operator, release, keys)
    assert _row(stand_down).in_force, "a release issued before the stand-down lifted it"
    assert _nonces() == [stand_down["nonce"], pause["nonce"]], "a release issued before a ready stop was served"

    FailsafeCommand.objects.filter(uuid=stand_down["uuid"]).update(issued_at="not an instant")
    FailsafeStopMark.objects.filter(engine_id=ENGINE).update(issued=_instant(pause["issued_at"]))
    later = _draft(operator, "resume")
    _sign_all(operator, later, keys)
    assert later["nonce"] not in _nonces(), "a start was served past a ready stop whose issued_at cannot be read"


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_the_engines_mark_keeps_the_latest_issued_at_of_any_stop_made_ready(keys, clock, operator, monkeypatch):
    """The mark moves forward by ``issued_at`` in the UPDATE that moves it by
    ``created_at``, never back: a stop drafted later but issued earlier moves
    the mark's stop and leaves its ``issued`` where it was. Once the stop in
    force is lifted and past its window, the mark alone holds a start issued
    at or before the latest stop -- and lets one issued after it through."""
    from failsafe.models import FailsafeStopMark

    def issued():
        return FailsafeStopMark.objects.get(engine_id=ENGINE).issued

    first = _signed(operator, "pause", keys)
    assert issued() == _instant(first["issued_at"])
    second = _draft_issued_at(operator, "pause", _instant(first["issued_at"]) - timedelta(milliseconds=5), monkeypatch)
    _sign_all(operator, second, keys)
    mark = FailsafeStopMark.objects.get(engine_id=ENGINE)
    assert str(mark.stop_uuid) == second["uuid"], "the mark did not move to the stop drafted last"
    assert mark.issued == _instant(first["issued_at"]), "the mark's issued moved back"
    third = _signed(operator, "stand_down", keys)
    assert issued() == _instant(third["issued_at"]), "the mark's issued did not move forward"

    # Every stop lifted, past its window, and marked expired by a read: only the mark is left.
    resume = _signed(operator, "resume", keys)
    release = _signed(operator, "release", keys)
    assert not any(_row(s).in_force for s in (first, second, third)), [_row(s).lifted_by for s in (first, second)]
    clock(11 * 60)
    operator.get(f"/api/failsafe/state/?engine_id={ENGINE}")
    assert {_row(s).status for s in (first, second, third, resume, release)} == {"expired"}
    late = _draft_issued_at(operator, "resume", _instant(third["issued_at"]), monkeypatch)
    _sign_all(operator, late, keys)
    assert _nonces() == [], "a start issued with the latest stop was served by the mark alone"
    after = _signed(operator, "resume", keys)
    assert _nonces() == [after["nonce"]]


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
@pytest.mark.parametrize("stop,start", PAIRS)
def test_an_engine_restarted_after_a_refused_start_is_still_stopped(stop, start, keys, operator, monkeypatch):
    """The plane's answers, through the engine's governor (mythos_core.failsafe,
    as pinned). The engine polls after each signature and applies each answer
    in its order; then it restarts: a fresh governor -- a new nonce ledger, a
    new start-order mark -- applies the last answer. On master the plane's last
    answer was the start alone, and a restarted engine ran. Both governors now
    end stopped, as the operators left the engine: by its signed order, the
    start came before the stop."""
    from mythos_core.failsafe import Command, Governor

    stopped_state = {"pause": "paused", "stand_down": "stood_down"}[stop]
    governor = Governor(engine_id=ENGINE, keyring=_ring(keys))
    stopped = _signed(operator, stop, keys)
    answers = [_poll().json()]
    started = _draft_issued_at(operator, start, _instant(stopped["issued_at"]) - timedelta(milliseconds=1), monkeypatch)
    _sign_all(operator, started, keys)
    answers.append(_poll().json())
    engine_clock = _instant(stopped["issued_at"]).timestamp() + 5.0
    for answer in answers:
        for document in answer:
            governor.apply(Command.from_dict(document), now=engine_clock)
    assert governor.state.value == stopped_state, [c["action"] for c in answers[-1]]
    restarted = Governor(engine_id=ENGINE, keyring=_ring(keys))
    for document in answers[-1]:
        restarted.apply(Command.from_dict(document), now=engine_clock)
    assert restarted.state.value == stopped_state, f"a restarted engine ran: the plane served {answers[-1]}"


# --- D5: what the plane holds and an engine may not -------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_pause_in_force_after_a_stand_down_and_a_release_says_an_engine_may_be_running(keys, clock, operator):
    """After a pause, a stand-down and a release, the plane keeps the pause in
    force: a release lifts only stand-downs, and only a resume lifts a pause.
    An engine went paused, stood down, and running on the release, and rejects
    the pause as a replay until it restarts. The pause's state row says so, in
    plain words, where the operator reads it."""
    pause = _signed(operator, "pause", keys)
    _signed(operator, "stand_down", keys)
    _signed(operator, "release", keys)
    assert _row(pause).in_force
    state = operator.get(f"/api/failsafe/state/?engine_id={ENGINE}").data
    (row,) = [r for r in state["ready"] if r["uuid"] == pause["uuid"]]
    note = row["in_force_note"]
    assert "stand-down and a release" in note
    assert "may be running" in note and "until it restarts" in note, note
    assert "sign a new pause" in note, note


# --- Deploy day (migration 0007) ---------------------------------------------------------------------------


@pytest.mark.django_db
def test_the_migration_backfills_each_marks_issued_from_its_stop_row():
    """0007's backfill: each mark's ``issued`` is its stop's signed instant,
    read from the stop's row. A mark whose stop row is gone, or whose
    ``issued_at`` cannot be read, is left unknown (None), which holds every
    start of its engine until a stop is made ready again: never "no stop"."""
    from django.apps import apps

    from failsafe.models import FailsafeCommand, FailsafeStopMark

    backfill = importlib.import_module("failsafe.migrations.0007_a_stop_marks_signed_instant").backfill
    now = timezone.now()

    def stop(engine_id, issued_at):
        command = FailsafeCommand.objects.create(
            engine_id=engine_id, action="pause", nonce=f"n-{engine_id}", issued_at=issued_at,
            expires_at=(now + timedelta(minutes=5)).isoformat(), status="ready", signed=True, in_force=True,
            signatures=[{"key_id": "op0", "sig": "00" * 64}], ready_at=now,
        )
        FailsafeStopMark.objects.create(engine_id=engine_id, created_at=command.created_at, stop_uuid=command.uuid,
                                        action="pause", last_ready_at=now)
        return command

    readable = stop("e-readable", (now - timedelta(seconds=3)).isoformat())
    stop("e-unreadable", "not an instant")
    stop("e-naive", (now - timedelta(seconds=3)).replace(tzinfo=None).isoformat())
    gone = stop("e-gone", now.isoformat())
    FailsafeCommand.objects.filter(pk=gone.pk).delete()
    FailsafeStopMark.objects.update(issued=None)

    backfill(apps, None)

    assert dict(FailsafeStopMark.objects.values_list("engine_id", "issued")) == {
        "e-readable": _instant(readable.issued_at), "e-unreadable": None, "e-naive": None, "e-gone": None}


@pytest.mark.django_db(transaction=True)
def test_the_migration_applies_forward_and_back_and_changes_no_command():
    """On a database at 0006 holding commands and marks: 0007 applies forward
    (each mark's ``issued`` from its stop), and rolled back it leaves every
    command, mark and audit event as it was, column for column. It writes no
    command."""
    from django.db.migrations.executor import MigrationExecutor

    before, after = ("failsafe", "0006_a_stop_in_force"), ("failsafe", "0007_a_stop_marks_signed_instant")
    now = timezone.now()

    def snapshot(state):
        return {
            name: sorted(state.apps.get_model("failsafe", name).objects.values_list(), key=repr)
            for name in ("FailsafeCommand", "FailsafeStopMark", "FailsafeAuditEvent")
        }

    try:
        old = MigrationExecutor(connection).migrate([before])
        Command, Mark = (old.apps.get_model("failsafe", name) for name in ("FailsafeCommand", "FailsafeStopMark"))
        assert not hasattr(Mark, "issued")
        issued = (now - timedelta(seconds=2)).isoformat()
        stand_down = Command.objects.create(
            engine_id="e-live", action="stand_down", nonce="n-live", issued_at=issued,
            expires_at=(now + timedelta(minutes=5)).isoformat(), status="ready", signed=True, in_force=True,
            ready_at=now, signatures=[{"key_id": "op0", "sig": "00" * 64}])
        Command.objects.create(engine_id="e-live", action="release", nonce="n-release", issued_at=now.isoformat(),
                               expires_at=(now + timedelta(minutes=5)).isoformat(), status="awaiting_signatures")
        Mark.objects.create(engine_id="e-live", created_at=stand_down.created_at, stop_uuid=stand_down.uuid,
                            action="stand_down", last_ready_at=now)
        old.apps.get_model("failsafe", "FailsafeAuditEvent").objects.create(command_id=stand_down.pk, event="ready")
        was = snapshot(old)

        new = MigrationExecutor(connection).migrate([after])
        commands = snapshot(new)["FailsafeCommand"]
        assert commands == was["FailsafeCommand"], "the migration wrote a command"
        mark = new.apps.get_model("failsafe", "FailsafeStopMark").objects.get(engine_id="e-live")
        assert mark.issued == _instant(issued)

        back = MigrationExecutor(connection).migrate([before])
        assert snapshot(back) == was, "a rollback did not leave the commands and marks as they were"
    finally:
        executor = MigrationExecutor(connection)
        executor.migrate(executor.loader.graph.leaf_nodes())
