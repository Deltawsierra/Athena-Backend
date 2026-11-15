"""No failsafe command in flight is left off a list, and every list has a real
next page (AB-FAILSAFE-CURSOR).

Two gaps in failsafe.views, found by the dashboard's DASH-FAILSAFE-3:

1. The list's row cap (COMMAND_LIST_LIMIT, 50) spanned history. Read by an
   operator's JWT, the newest 50 commands besides the stop commands awaiting a
   signature were taken across every status, consumed, canceled and expired
   ones included. So once 51 commands existed, a ready stop, a ready resume or
   a resume awaiting its signature older than the newest 50 was left off every
   list read. The state read's ``ready`` was the newest 20 of every action, so
   21 ready resumes left a ready pause off it.
2. Neither read took a cursor, so a reader told ``more`` could never read the
   rest.

Now every read lists what is in flight (awaiting a signature, or ready) before
any history, the stops first, within the same caps; and both reads take an
opaque keyset cursor (``cursor``), answering the next one in X-Failsafe-Next
(and the state read's ``next``) whenever they say ``more``. A bad cursor is
answered 400. None of this is on a stop's path: a stop is answered within its
bound while a read of 10,000 commands is in its middle.
"""

import base64
import json
import threading
import time
import uuid
from urllib.parse import quote

import pytest
from django.db import connection

from tests.test_no_control_holds_back_a_stop import STOP_LATENCY_BOUND, _admin, _client_for, _service_client, _user
from tests.test_no_control_holds_back_a_stop import configure, rates, service  # noqa: F401 - fixtures, used by name

MORE = "X-Failsafe-More"
NEXT = "X-Failsafe-Next"
TOO_LARGE = "X-Failsafe-Too-Large"
IN_FLIGHT = ("awaiting_signatures", "ready")
STOPS = ("pause", "stand_down", "terminate")
STARTS = ("resume", "release")


def _make(specs, engine_id="athena-1", initiator=None):
    """Commands made in this order (so oldest first), one per (action, status,
    signed) spec, as drafts and signatures would leave them."""
    from failsafe.models import FailsafeCommand

    return FailsafeCommand.objects.bulk_create(
        [
            FailsafeCommand(engine_id=engine_id, action=action, nonce=uuid.uuid4().hex, issued_at="t",
                            expires_at="2999-01-01T00:00:00+00:00", status=state, signed=signed,
                            required_signatures=2 if action in ("stand_down", "terminate") else 1,
                            initiator=initiator)
            for action, state, signed in specs
        ],
        batch_size=500,
    )


def _with_cursor(path, cursor):
    return f"{path}{'&' if '?' in path else '?'}cursor={quote(cursor, safe='')}"


def _walk(client, path, between=None, most=400):
    """Every page of one read, following its cursor: the answers, in order."""
    answers, cursor = [], None
    for _ in range(most):
        answer = client.get(_with_cursor(path, cursor) if cursor else path)
        assert answer.status_code == 200, (path, answer.status_code, getattr(answer, "data", None))
        answers.append(answer)
        more = answer[MORE]
        assert more in ("true", "false"), more
        following = answer.headers.get(NEXT)
        if "state" in path:
            assert answer.data["more"] is (more == "true")
            assert answer.data["next"] == following
        if more == "false":
            assert following is None, following
            return answers
        assert following, f"{path}: the read said more and gave no next page"
        cursor = following
        if between is not None:
            between()
    raise AssertionError(f"{path}: {most} pages and still more")


def _uuids(rows):
    return [row["uuid"] for row in rows]


def _listed(answers):
    return [row for answer in answers for row in answer.data]


def _in_flight_then_history(rows):
    kinds = ["live" if row["status"] in IN_FLIGHT else "history" for row in rows]
    return kinds == sorted(kinds, key=lambda kind: kind == "history")


# --- 1. What is in flight comes first, and is never cut by history -----------------


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_an_old_command_in_flight_is_listed_before_every_command_of_history():
    """60 commands: the oldest a ready resume, then a stand-down awaiting its
    second signature, a ready stand-down and a resume awaiting a signature;
    then 56 newer commands of history. Master listed the stand-down awaiting
    a signature (the awaiting stops are read first) and the newest 50 of the
    rest: the ready resume, the ready stand-down and the awaiting resume were
    left off. Now all four are listed, before any history, the stops first."""
    from failsafe.views import COMMAND_LIST_LIMIT

    old = _make([("resume", "ready", True), ("stand_down", "awaiting_signatures", True),
                 ("stand_down", "ready", True), ("resume", "awaiting_signatures", False)])
    _make([(("pause", "terminate", "resume")[i % 3], ("consumed", "canceled", "expired")[i % 3], i % 2 == 0)
           for i in range(56)])
    ready_resume, awaiting_stand_down, ready_stand_down, awaiting_resume = (str(c.uuid) for c in old)
    reader = _client_for(_admin())
    for path in ("/api/failsafe/commands/", "/api/failsafe/commands/?engine_id=athena-1"):
        answer = reader.get(path)
        rows = answer.data
        order = _uuids(rows)
        assert order[:4] == [awaiting_stand_down, ready_stand_down, awaiting_resume, ready_resume], (path, order[:4])
        assert _in_flight_then_history(rows), path
        # The caps stay: the awaiting stop, then 50 others; the rest is on the next page.
        assert len(rows) == 1 + COMMAND_LIST_LIMIT and answer[MORE] == "true", path
    # Each status read alone is whole for what is in flight.
    assert _uuids(reader.get("/api/failsafe/commands/?status=ready").data) == [ready_stand_down, ready_resume]


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_the_state_reads_a_ready_stop_before_any_ready_resume():
    """The state's ready list was the newest 20 ready commands of every action:
    a ready pause older than 25 ready resumes was left off it. A stop comes
    first now, and the resumes past the cap are on the next page."""
    pause = _make([("pause", "ready", True)])[0]
    _make([("resume", "ready", True)] * 25)
    state = _client_for(_admin()).get("/api/failsafe/state/?engine_id=athena-1")
    assert state.data["ready"][0]["uuid"] == str(pause.uuid)
    assert len(state.data["ready"]) == 20 and state.data["more"] is True and state[MORE] == "true"


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_when_what_is_in_flight_alone_passes_a_cap_the_stops_come_first():
    """60 ready resumes and 60 resumes awaiting a signature, newer than 3 ready
    pauses: the list's 50 are the pauses and then the newest starts, and say
    more; no history is listed before any of them."""
    pauses = _make([("pause", "ready", True)] * 3)
    _make([("resume", "ready", True), ("release", "awaiting_signatures", False)] * 60)
    _make([("pause", "consumed", True)] * 10)
    answer = _client_for(_admin()).get("/api/failsafe/commands/")
    rows = answer.data
    assert {row["uuid"] for row in rows[:3]} == {str(p.uuid) for p in pauses}
    assert all(row["status"] in IN_FLIGHT for row in rows) and answer[MORE] == "true"


# --- 2. A real next page --------------------------------------------------------------


def _mixed_thousand(initiators):
    """1,000 commands of every kind, in an interleaved order."""
    kinds = [
        *[(STOPS[i % 3], "awaiting_signatures", i % 4 == 0) for i in range(300)],
        *[(STOPS[i % 3], "ready", True) for i in range(100)],
        *[(STARTS[i % 2], "awaiting_signatures", i % 3 == 0) for i in range(100)],
        *[(STARTS[i % 2], "ready", True) for i in range(100)],
        *[((*STOPS, *STARTS)[i % 5], ("consumed", "expired", "canceled", "superseded")[i % 4], i % 2 == 0)
          for i in range(400)],
    ]
    # Interleave so no kind is all older or all newer than another.
    kinds = [kinds[(i * 7) % 1000] for i in range(1000)]
    made = []
    for n, initiator in enumerate(initiators):
        made += _make(kinds[n::len(initiators)], engine_id=f"athena-{n % 2}", initiator=initiator)
    return made


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_paging_lists_every_command_exactly_once_while_new_ones_are_drafted():
    """1,000 commands, paged through by the cursor while every page is followed
    by new drafts, signatures and history: every one of the 1,000 is listed
    exactly once, and no row twice. Every page is within the cap, and what is
    in flight is listed before any history."""
    from failsafe.views import COMMAND_LIST_LIMIT

    from failsafe.models import FailsafeCommand

    accounts = [_user("analyst") for _ in range(3)]
    made = {str(c.uuid) for c in _mixed_thousand(accounts)}
    assert len(made) == FailsafeCommand.objects.count() == 1000
    added = []

    def between():
        added.extend(str(c.uuid) for c in _make(
            [("resume", "awaiting_signatures", False), ("pause", "awaiting_signatures", False),
             ("terminate", "ready", True), ("release", "ready", True), ("pause", "consumed", True),
             ("stand_down", "expired", True)], engine_id="athena-0", initiator=accounts[0]))

    answers = _walk(_client_for(_admin()), "/api/failsafe/commands/", between=between)
    listed = _uuids(_listed(answers))
    assert len(answers) > 10
    assert len(listed) == len(set(listed)), "a row was listed twice"
    assert made <= set(listed), f"{len(made - set(listed))} of the 1,000 were never listed"
    assert set(listed) - made <= set(added)
    assert all(len(answer.data) <= 500 + COMMAND_LIST_LIMIT for answer in answers[:1])
    assert all(len(answer.data) <= COMMAND_LIST_LIMIT for answer in answers[1:])
    original = [row for row in _listed(answers) if row["uuid"] in made]
    assert _in_flight_then_history(original)


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_paging_one_engine_or_one_status_lists_exactly_those_once():
    accounts = [_user("analyst") for _ in range(2)]
    made = _mixed_thousand(accounts)
    reader = _client_for(_admin())
    for query, wanted in (
        ("?engine_id=athena-1", {str(c.uuid) for c in made if c.engine_id == "athena-1"}),
        ("?status=ready", {str(c.uuid) for c in made if c.status == "ready"}),
        ("?status=consumed&engine_id=athena-0",
         {str(c.uuid) for c in made if c.status == "consumed" and c.engine_id == "athena-0"}),
    ):
        listed = _uuids(_listed(_walk(reader, f"/api/failsafe/commands/{query}")))
        assert len(listed) == len(set(listed)) and set(listed) == wanted, query


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_commands_made_in_one_clock_tick_are_each_listed_once():
    """Commands drafted in one tick of the clock share a creation time (on
    Windows the clock can step in milliseconds): the primary key orders them,
    so a page boundary inside a tie neither skips nor repeats one."""
    from django.utils import timezone

    from failsafe.models import FailsafeCommand

    made = _make([("resume", "ready", True), ("pause", "consumed", True), ("stand_down", "ready", True),
                  ("release", "awaiting_signatures", False)] * 70)
    FailsafeCommand.objects.update(created_at=timezone.now())
    reader = _client_for(_admin())
    listed = _uuids(_listed(_walk(reader, "/api/failsafe/commands/")))
    assert len(listed) == len(set(listed)) == len(made)
    answers = _walk(reader, "/api/failsafe/state/")
    in_flight = _uuids(row for answer in answers for key in ("awaiting_signatures", "ready") for row in answer.data[key])
    assert len(in_flight) == len(set(in_flight)) == 3 * 70


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_awaiting_stops_past_the_first_page_are_each_read_on_the_pages_after_it():
    """More stop commands await a signature than the first page lists
    (AWAITING_STOP_LIMIT): the first page lists them in a co-signer's order,
    as before, and says more; the pages after it list every one of them,
    exactly once, signed ones first -- none is out of reach."""
    from failsafe.views import AWAITING_STOP_LIMIT

    accounts = [_user("analyst") for _ in range(3)]
    stops = []
    for n, account in enumerate(accounts):
        stops += _make([(STOPS[i % 3], "awaiting_signatures", i % 25 == 0) for i in range(180)],
                       engine_id=f"flood-{n}", initiator=account)
    answers = _walk(_client_for(_admin()), "/api/failsafe/commands/?status=awaiting_signatures")
    first, after = answers[0].data, _listed(answers[1:])
    assert len(first) == AWAITING_STOP_LIMIT and answers[0][MORE] == "true"
    walked = _uuids(after)
    assert len(walked) == len(set(walked)) and set(walked) == {str(c.uuid) for c in stops}
    signed_ones = {str(c.uuid) for c in stops if c.signed}
    signed = [row["uuid"] in signed_ones for row in after]
    assert signed == sorted(signed, reverse=True), "a signed stop after an unsigned one"


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_the_state_pages_through_every_command_in_flight_and_nothing_else():
    accounts = [_user("analyst") for _ in range(2)]
    made = _mixed_thousand(accounts)
    reader = _client_for(_admin())
    for query in ("?engine_id=athena-1", ""):
        answers = _walk(reader, f"/api/failsafe/state/{query}")
        awaiting = _uuids(row for answer in answers for row in answer.data["awaiting_signatures"])
        ready = [row for answer in answers for row in answer.data["ready"]]
        wanted = [c for c in made if c.status in IN_FLIGHT and (not query or c.engine_id == "athena-1")]
        assert len(awaiting) == len(set(awaiting))
        assert set(awaiting) == {str(c.uuid) for c in wanted if c.status == "awaiting_signatures"}, query
        assert len(ready) == len({row["uuid"] for row in ready})
        assert {row["uuid"] for row in ready} == {str(c.uuid) for c in wanted if c.status == "ready"}, query
        # The ready stops first, across every page.
        stop_first = [row["action"] in STOPS for row in ready]
        assert stop_first == sorted(stop_first, reverse=True), query
        assert all(answer.data["recent"] == [] for answer in answers[1:])
        assert all(len(answer.data["ready"]) <= 20 for answer in answers)


@pytest.mark.django_db
@pytest.mark.usefixtures("rates", "service")
def test_the_service_token_pages_through_the_stops_in_flight_and_nothing_else():
    from failsafe.views import AWAITING_STOP_LIMIT

    ready_stops = _make([(STOPS[i % 3], "ready", True) for i in range(AWAITING_STOP_LIMIT + 30)])
    awaiting = _make([("pause", "awaiting_signatures", False)] * 5)
    _make([("resume", "ready", True), ("release", "awaiting_signatures", False), ("pause", "consumed", True)] * 30)
    client = _service_client()
    listed = _uuids(_listed(_walk(client, "/api/failsafe/commands/")))
    assert len(listed) == len(set(listed))
    assert set(listed) == {str(c.uuid) for c in (*ready_stops, *awaiting)}
    answers = _walk(client, "/api/failsafe/state/")
    ready = _uuids(row for answer in answers for row in answer.data["ready"])
    assert len(ready) == len(set(ready)) and set(ready) == {str(c.uuid) for c in ready_stops}
    assert all(answer.data["recent"] == [] for answer in answers)


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_reader_that_sends_no_cursor_reads_the_first_page_as_before():
    """Compatible: no cursor, the first page; the list's body is the bare array,
    the state's keys are those it had, with ``next`` beside ``more``; a read
    that left nothing out gives no next page."""
    _make([("pause", "awaiting_signatures", False), ("resume", "ready", True), ("pause", "consumed", True)])
    reader = _client_for(_admin())
    listed = reader.get("/api/failsafe/commands/")
    assert isinstance(listed.data, list) and len(listed.data) == 3
    assert listed[MORE] == "false" and listed.headers.get(NEXT) is None
    state = reader.get("/api/failsafe/state/")
    assert set(state.data) == {"engine_id", "engine_state", "engine_state_available", "awaiting_signatures",
                               "ready", "recent", "more", "next"}
    assert state.data["more"] is False and state.data["next"] is None and state.headers.get(NEXT) is None
    # An empty cursor is no cursor.
    assert _uuids(reader.get("/api/failsafe/commands/?cursor=").data) == _uuids(listed.data)


# --- 3. A bad cursor is a 400, never a 500 --------------------------------------------


def _encoded(value):
    raw = value if isinstance(value, bytes) else json.dumps(value).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


@pytest.mark.django_db
@pytest.mark.usefixtures("rates", "service")
def test_a_cursor_that_cannot_be_read_is_answered_400_and_never_500():
    _make([(STOPS[i % 3], "ready", True) for i in range(30)] + [("resume", "ready", True)] * 60)
    reader = _client_for(_admin())
    good = reader.get("/api/failsafe/commands/").headers[NEXT]
    good_state = reader.get("/api/failsafe/state/").headers[NEXT]
    decoded = json.loads(base64.urlsafe_b64decode(good + "=" * (-len(good) % 4)))
    bad = [
        "!!!", "not base64 at all", "%00", "a" * 5000, _encoded(b"\xff\xfe"), _encoded(b"[]"), _encoded("x"),
        _encoded(None), _encoded([1, 2]), _encoded({}), _encoded({**decoded, "v": 2}),
        _encoded({**decoded, "v": True}), _encoded({key: value for key, value in decoded.items() if key != "l"}),
        _encoded({**decoded, "extra": 1}), _encoded({key: value for key, value in decoded.items() if key != "k"}),
    ]
    for lane, position in decoded["l"].items():
        when = position[1]
        # The same moment with its zone dropped, or a zone added: never what the read wrote.
        other_zone = when[:-6] if when.endswith("+00:00") else when + "+00:00"
        for broken in ([-1, when, position[2]], [9, when, position[2]], [0, "yesterday", 5],
                       [0, when, -4], [0, when, 0], [0, when, "5"], [0, when], [0.5, when, 1],
                       [False, when, 1], [0, when, 2**70], [0, other_zone, 1], [0, when, 1, 2],
                       "start", 7, {}):
            bad.append(_encoded({**decoded, "l": {**decoded["l"], lane: broken}}))
    bad += [_encoded({**decoded, "l": {**decoded["l"], "nope": None}}), _encoded({**decoded, "l": []}),
            _encoded({**decoded, "s": 1}), _encoded({**decoded, "k": "x" * 64})]
    for cursor in bad:
        for path in ("/api/failsafe/commands/", "/api/failsafe/state/"):
            answer = reader.get(_with_cursor(path, cursor))
            assert answer.status_code == 400, (path, cursor[:80], answer.status_code)
            assert "cursor" in str(answer.data["detail"]), answer.data
    # A cursor is for the read that gave it: not another view, engine, status or credential.
    for path in ("/api/failsafe/state/", "/api/failsafe/commands/?engine_id=athena-2",
                 "/api/failsafe/commands/?status=ready"):
        assert reader.get(_with_cursor(path, good)).status_code == 400, path
    assert reader.get(_with_cursor("/api/failsafe/commands/", good_state)).status_code == 400
    assert _service_client().get(_with_cursor("/api/failsafe/commands/", good)).status_code == 400
    # And the good ones still read.
    assert reader.get(_with_cursor("/api/failsafe/commands/", good)).status_code == 200
    assert reader.get(_with_cursor("/api/failsafe/state/", good_state)).status_code == 200


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_command_too_large_for_any_page_is_named_and_passed_over(settings):
    """A row larger than a whole read's byte cap (a legacy reason, at the least
    cap) can never be listed: it is named in X-Failsafe-Too-Large and passed
    over, so the pages after it are still read and none is stuck on it."""
    from failsafe.models import FailsafeCommand

    settings.FAILSAFE_STOP_LANE_READ_BYTES = 64 * 1024
    small = _make([("pause", "ready", True)] * 3)
    huge = _make([("pause", "ready", True)])[0]
    FailsafeCommand.objects.filter(pk=huge.pk).update(reason="x" * 70_000)
    newer = _make([("pause", "ready", True)] * 2)
    answers = _walk(_client_for(_admin()), "/api/failsafe/commands/")
    listed = _uuids(_listed(answers))
    assert listed == [str(c.uuid) for c in reversed([*small, *newer])]
    named = [answer.headers.get(TOO_LARGE) for answer in answers if answer.headers.get(TOO_LARGE)]
    assert named == [str(huge.uuid)]


# --- 4. No stop waits on any of it ------------------------------------------------------


@pytest.mark.django_db(transaction=True)
@pytest.mark.usefixtures("rates")
def test_a_stop_is_answered_within_its_bound_while_a_list_of_ten_thousand_is_read(monkeypatch, settings):
    """A list read of 10,000 commands is held in its middle (a second at most)
    while an operator drafts a pause, a stand-down and a terminate, and signs
    the pause: each is answered within STOP_LATENCY_BOUND. Nothing a list read
    holds is on a stop's path."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from failsafe import views

    key = Ed25519PrivateKey.generate()
    settings.FAILSAFE_OPERATOR_KEYS = {"alice": key.public_key().public_bytes_raw().hex()}
    accounts = [_user("analyst") for _ in range(4)]
    for n in range(10):
        _make([((*STOPS, *STARTS)[i % 5], ("awaiting_signatures", "ready", "consumed", "expired")[i % 4], i % 2 == 0)
               for i in range(1000)], engine_id=f"athena-{n}", initiator=accounts[n % 4])
    operator = _admin()
    stopper = _client_for(operator)
    assert stopper.post("/api/failsafe/commands/", {"action": "pause", "engine_id": "warm"}, format="json").status_code == 201
    inside, release, answers = threading.Event(), threading.Event(), []
    real_fetch = views._fetch

    def held(pks):
        if not inside.is_set():
            inside.set()
            release.wait(1.0)
        return real_fetch(pks)

    monkeypatch.setattr(views, "_fetch", held)

    def read():
        try:
            reader = _client_for(operator)
            first = reader.get("/api/failsafe/commands/")
            answers.append(first.status_code)
            answers.append(reader.get(_with_cursor("/api/failsafe/commands/", first.headers[NEXT])).status_code)
        finally:
            connection.close()

    reading = threading.Thread(target=read)
    reading.start()
    assert inside.wait(30), "the list read never started"
    took = {}
    for action in STOPS:
        began = time.perf_counter()
        drafted = stopper.post("/api/failsafe/commands/", {"action": action, "engine_id": "athena-3"}, format="json")
        took[action] = time.perf_counter() - began
        assert drafted.status_code == 201, (action, drafted.status_code)
        if action == "pause":
            pause = drafted.data
    signature = {"key_id": "alice", "sig": key.sign(bytes.fromhex(pause["signing_bytes"])).hex()}
    began = time.perf_counter()
    signed = stopper.post(f"/api/failsafe/commands/{pause['uuid']}/signatures/", signature, format="json")
    took["signature"] = time.perf_counter() - began
    assert signed.status_code == 200 and signed.data["status"] == "ready"
    still_reading = reading.is_alive()
    release.set()
    reading.join(60)
    slow = {name: round(seconds, 4) for name, seconds in took.items() if seconds > STOP_LATENCY_BOUND}
    assert slow == {}, f"stops over {STOP_LATENCY_BOUND} s while a list read ran: {slow}"
    assert still_reading, "the read finished before the stops were sent: nothing was proved"
    assert answers == [200, 200]
