"""The engine's poll does bounded work, and answers every ready stop first
(AB-POLL-BOUND).

``/api/failsafe/pending/`` is how a signed stop reaches an engine. It walked
every ready command of the engine (``for command in qs``), newest first, with
no limit, and wrote each one past its window expired, one at a time. So:

* 10,000 ready resumes put a ready stand-down 10,000th in the answer, behind
  1.7 MB, and the engine applies an answer in its order;
* the poll loaded every ready row: its work grew with the flood;
* past the engine's read limit (mythos_core.http.safe_http.MAX_RESPONSE_BYTES,
  5 MiB) the engine cuts the body, cannot decode it, and drops every command
  in it, the stops with them;
* a resume or release older than a stop, answered after it, undid it;
* one failed expiry write answered the poll 500: no command reached the engine.

Now the answer is the same JSON list, with every ready stop first --
terminate, then stand-down, then pause -- and at most POLL_START_LIMIT starts
after them, in at most POLL_READ_BYTES; X-Failsafe-More and X-Failsafe-Next
page the rest, and no start is on a page that left a stop for the next. A start
older than a ready stop of its engine is held back. Each read is an index
range of its limit (fsc_st_act_ct, fsc_eng_st_act_ct).
"""

import json
import threading
import time
import uuid
from datetime import timedelta
from urllib.parse import quote

import pytest
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from tests.test_no_control_holds_back_a_stop import POLL_TOKEN, STOP_LATENCY_BOUND, _admin, _client_for
from tests.test_no_control_holds_back_a_stop import configure, rates  # noqa: F401 - fixtures, used by name

MORE = "X-Failsafe-More"
NEXT = "X-Failsafe-Next"
STOPS = ("pause", "stand_down", "terminate")
STARTS = ("resume", "release")
FAR = "2999-01-01T00:00:00+00:00"
PAST = "2000-01-01T00:00:00+00:00"


def _make(actions, at, engine_id="athena-1", reason="", expires=FAR):
    """Ready commands of these actions, made in this order: the first at
    ``at``, each next one a millisecond later. Creation times are set
    explicitly, so a clock that ties (Windows) never reorders them."""
    from failsafe.models import FailsafeCommand

    made = FailsafeCommand.objects.bulk_create(
        [
            FailsafeCommand(engine_id=engine_id, action=action, nonce=uuid.uuid4().hex,
                            issued_at="2026-11-03T00:00:00+00:00", expires_at=expires, reason=reason,
                            status="ready", signed=True, signatures=[{"key_id": "alice", "sig": "00" * 64}],
                            required_signatures=2 if action in ("stand_down", "terminate") else 1)
            for action in actions
        ],
        batch_size=500,
    )
    for n, command in enumerate(made):
        command.created_at = at + timedelta(milliseconds=n)
    FailsafeCommand.objects.bulk_update(made, ["created_at"], batch_size=500)
    return made


def _starts(n):
    return [STARTS[i % 2] for i in range(n)]


def _poll(path="/api/failsafe/pending/?engine_id=athena-1", client=None):
    answer = (client or APIClient()).get(path, HTTP_X_FAILSAFE_POLL_TOKEN=POLL_TOKEN)
    assert answer.status_code == 200, (path, answer.status_code, answer.content[:300])
    return answer


def _with_cursor(path, cursor):
    return f"{path}{'&' if '?' in path else '?'}cursor={quote(cursor, safe='')}"


def _pages(path, most=50):
    """Every page of one poll, following its cursor."""
    answers, cursor = [], None
    for _ in range(most):
        answer = _poll(_with_cursor(path, cursor) if cursor else path)
        answers.append(answer)
        assert answer[MORE] in ("true", "false")
        if answer[MORE] == "false":
            assert NEXT not in answer
            return answers
        cursor = answer[NEXT]
    raise AssertionError(f"{path}: {most} pages and still more")


def _measured(path, monkeypatch):
    """One poll: (answer, rows loaded as commands, statements, SQLite VM steps
    in hundreds)."""
    from failsafe.models import FailsafeCommand

    loaded = []
    real = FailsafeCommand.from_db.__func__
    monkeypatch.setattr(
        FailsafeCommand, "from_db", classmethod(lambda cls, db, names, values: loaded.append(1) or real(cls, db, names, values))
    )
    connection.ensure_connection()
    steps = [0]

    def tick():
        steps[0] += 1
        return 0

    connection.connection.set_progress_handler(tick, 100)
    try:
        with CaptureQueriesContext(connection) as queries:
            answer = _poll(path)
    finally:
        connection.connection.set_progress_handler(None, 100)
        monkeypatch.setattr(FailsafeCommand, "from_db", classmethod(real))
    return answer, len(loaded), len(queries), steps[0]


# --- 1. Bounded work, the stop first ----------------------------------------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
@pytest.mark.parametrize("path", ["/api/failsafe/pending/?engine_id=athena-1", "/api/failsafe/pending/"])
def test_a_flood_of_ready_starts_leaves_the_poll_bounded_and_the_stop_first(path, monkeypatch):
    """One ready stand-down, the OLDEST command, then 0, 1,000 and 10,000
    newer ready resumes and releases (and a tenth as many for another engine).
    Master answered all of them, the stand-down last (index 10,000 of 10,001,
    1.7 MB), and loaded every row. Now the stand-down is first in every answer,
    the starts after it are capped, and the poll loads, runs and answers the
    same with 1,000 starts as with 10,000."""
    from failsafe.views import POLL_START_LIMIT

    at = timezone.now() - timedelta(hours=1)
    stop = _make(["stand_down"], at)[0]
    seen = {}
    for total, added in ((0, 0), (1000, 1000), (10000, 9000)):
        _make(_starts(added), at + timedelta(minutes=1 + total // 1000))
        _make(_starts(added // 10), at + timedelta(minutes=1 + total // 1000), engine_id="athena-2")
        answer, loaded, statements, steps = _measured(path, monkeypatch)
        body = answer.json()
        assert body[0]["nonce"] == stop.nonce, (total, [c["action"] for c in body[:3]])
        assert all(c["action"] in STARTS for c in body[1:]), total
        ready_starts = total + (total // 10 if "engine_id" not in path else 0)
        assert len(body) == 1 + min(ready_starts, POLL_START_LIMIT), (total, len(body))
        assert answer[MORE] == ("true" if total else "false"), total
        assert loaded <= 1 + POLL_START_LIMIT, (total, loaded)
        seen[total] = (statements, steps, len(answer.content))
    # The same statements, the same bytes, and about the same VM work with ten
    # times the flood (master: 1 statement, but every row read and answered).
    assert seen[10000][0] == seen[1000][0], seen
    assert seen[10000][2] == seen[1000][2], seen
    assert seen[10000][1] <= seen[1000][1] * 1.5 + 50, seen


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_every_ready_stop_comes_before_any_start_strongest_first():
    """Four ready stops and 60 newer ready starts: the answer is the
    terminate, the stand-down, the pauses, then 50 starts newest first, and
    the engine's own decoder reads every one of them, in that order."""
    from mythos_core.failsafe.channel import _decode_commands

    from failsafe.views import POLL_START_LIMIT

    at = timezone.now() - timedelta(hours=1)
    stops = _make(["pause", "terminate", "stand_down", "pause"], at)
    starts = _make(_starts(60), at + timedelta(minutes=1))
    answer = _poll()
    body = answer.json()
    assert [c["action"] for c in body[:4]] == ["terminate", "stand_down", "pause", "pause"], body[:4]
    assert [c["nonce"] for c in body[:4]] == [stops[1].nonce, stops[2].nonce, stops[3].nonce, stops[0].nonce]
    assert [c["nonce"] for c in body[4:]] == [c.nonce for c in reversed(starts)][:POLL_START_LIMIT]
    assert answer[MORE] == "true" and answer[NEXT]
    decoded = _decode_commands(answer.content.decode("utf-8"))
    assert [c.nonce for c in decoded] == [c["nonce"] for c in body]
    # The next page holds the other ten starts, and no stop again.
    rest = _poll(_with_cursor("/api/failsafe/pending/?engine_id=athena-1", answer[NEXT]))
    assert [c["nonce"] for c in rest.json()] == [c.nonce for c in reversed(starts)][POLL_START_LIMIT:]
    assert rest[MORE] == "false"


# --- 2. No stop is dropped or put behind a start, whatever the caps ---------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_stops_past_their_row_cap_are_paged_and_no_start_comes_before_one():
    """600 ready pauses (past POLL_STOP_LIMIT) and 60 newer starts: the first
    page is 500 stops and no start; the pages after it list every stop once,
    and the starts only on and after the stops' last page."""
    from failsafe.views import POLL_STOP_LIMIT

    at = timezone.now() - timedelta(hours=1)
    stops = _make(["pause"] * 600, at)
    starts = _make(_starts(60), at + timedelta(minutes=5))
    pages = _pages("/api/failsafe/pending/?engine_id=athena-1")
    bodies = [page.json() for page in pages]
    assert [c["action"] for c in bodies[0]] == ["pause"] * POLL_STOP_LIMIT
    listed = [c for body in bodies for c in body]
    stop_nonces = [c["nonce"] for c in listed if c["action"] in STOPS]
    start_nonces = [c["nonce"] for c in listed if c["action"] in STARTS]
    assert sorted(stop_nonces) == sorted(c.nonce for c in stops), "a stop past the cap was dropped or repeated"
    assert sorted(start_nonces) == sorted(c.nonce for c in starts)
    last_stop_page = max(n for n, body in enumerate(bodies) if any(c["action"] in STOPS for c in body))
    first_start_page = min(n for n, body in enumerate(bodies) if any(c["action"] in STARTS for c in body))
    assert first_start_page >= last_stop_page, (first_start_page, last_stop_page)
    for body in bodies:
        kinds = ["stop" if c["action"] in STOPS else "start" for c in body]
        assert kinds == sorted(kinds, key=lambda kind: kind == "start")


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_no_answer_is_past_the_engines_read_limit_and_no_stop_is_lost_to_one():
    """100 ready stand-downs with 60,000-character reasons (drafted before
    REASON_LIMIT) and 10 newer starts: master answered 6 MB in one body, which
    the engine cuts at 5 MiB and cannot decode -- every stop lost. Now each
    page is within POLL_READ_BYTES, the engine decodes each, and the pages list
    every stop once, before any start."""
    from mythos_core.failsafe.channel import _decode_commands
    from mythos_core.http.safe_http import MAX_RESPONSE_BYTES

    from failsafe.views import POLL_READ_BYTES

    assert POLL_READ_BYTES < MAX_RESPONSE_BYTES
    at = timezone.now() - timedelta(hours=1)
    stops = _make(["stand_down"] * 100, at, reason="r" * 60000)
    starts = _make(_starts(10), at + timedelta(minutes=5))
    pages = _pages("/api/failsafe/pending/?engine_id=athena-1")
    heard = []
    for page in pages:
        assert len(page.content) <= POLL_READ_BYTES, len(page.content)
        # What the engine reads: at most MAX_RESPONSE_BYTES of it, decoded.
        heard += [c.nonce for c in _decode_commands(page.content[:MAX_RESPONSE_BYTES].decode("utf-8", "replace"))]
    assert len(pages) > 1
    assert pages[0].json() and all(c["action"] == "stand_down" for c in pages[0].json())
    assert sorted(heard[:100]) == sorted(c.nonce for c in stops), "a stop the engine never heard"
    assert sorted(heard[100:]) == sorted(c.nonce for c in starts)


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_start_older_than_a_ready_stop_is_held_back_and_a_newer_one_is_answered():
    """A release signed, then a stand-down, both first heard in one poll: the
    engine applies the answer in order, so a release answered after the
    stand-down left the engine running (master answered both). The older
    release is held back while the stand-down is ready; one drafted after it
    is answered, after it; another engine's release is not held by it."""
    at = timezone.now() - timedelta(hours=1)
    old_release = _make(["release"], at)[0]
    other = _make(["release"], at, engine_id="athena-2")[0]
    stand_down = _make(["stand_down"], at + timedelta(minutes=1))[0]
    assert [c["nonce"] for c in _poll().json()] == [stand_down.nonce]
    everyone = [c["nonce"] for c in _poll("/api/failsafe/pending/").json()]
    assert everyone == [stand_down.nonce, other.nonce], everyone
    assert old_release.nonce not in everyone
    new_release = _make(["release"], at + timedelta(minutes=2))[0]
    assert [c["nonce"] for c in _poll().json()] == [stand_down.nonce, new_release.nonce]


# --- 3. The reads are index ranges -----------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
@pytest.mark.parametrize("path", ["/api/failsafe/pending/?engine_id=athena-1", "/api/failsafe/pending/"])
def test_each_ready_by_action_read_is_a_search_of_its_own_index(path):
    """Every statement the poll runs is planned as a search, none reads a
    whole table or sorts (the expiry's candidates were sorted, every command
    past its window read to take the first few), and each ready-by-action read is a range of
    fsc_eng_st_act_ct (with an engine) or fsc_st_act_ct (without): no ready
    command of another action is stepped past."""
    at = timezone.now() - timedelta(hours=1)
    _make(["pause", "terminate"], at)
    _make(_starts(200), at + timedelta(minutes=1))
    _make(_starts(200), at + timedelta(minutes=1), engine_id="athena-2")
    with CaptureQueriesContext(connection) as queries:
        _poll(path)
    index = "fsc_eng_st_act_ct" if "engine_id" in path else "fsc_st_act_ct"
    by_action, plans = 0, []
    for query in queries.captured_queries:
        sql = query["sql"]
        if not sql.startswith("SELECT"):
            continue
        with connection.cursor() as cursor:
            # The captured SQL has its parameters inlined; plan it as run.
            cursor.execute("EXPLAIN QUERY PLAN " + sql)
            plan = [row[-1] for row in cursor.fetchall()]
        plans.append((sql[:200], plan))
        assert not any(step.startswith("SCAN ") for step in plan), (sql[:300], plan)
        # No sort either: a temp B-tree reads every row it sorts, the
        # expiry's candidates included (each command past its window).
        assert not any("TEMP B-TREE" in step for step in plan), (sql[:300], plan)
        if '"action" = ' in sql and "ORDER BY" in sql:
            by_action += 1
            assert any(f"USING INDEX {index}" in step or f"USING COVERING INDEX {index}" in step for step in plan), (
                sql[:300], plan)
    assert by_action == 5, plans  # three stop actions, two start actions


# --- 4. Past their window, and a write that fails ---------------------------------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_commands_past_their_window_are_passed_over_and_marked_in_one_write(monkeypatch):
    """1,000 ready starts past their window and a ready pause: master wrote
    each start expired, one UPDATE apiece. Now the poll answers the pause, and
    marks at most EXPIRE_PER_READ of them in one write."""
    from failsafe.models import FailsafeCommand
    from failsafe.views import EXPIRE_PER_READ

    at = timezone.now() - timedelta(hours=1)
    _make(_starts(1000), at, expires=PAST)
    pause = _make(["pause"], at + timedelta(minutes=1))[0]
    with CaptureQueriesContext(connection) as queries:
        body = _poll().json()
    assert [c["nonce"] for c in body] == [pause.nonce]
    updates = [q for q in queries.captured_queries if q["sql"].startswith("UPDATE")]
    assert len(updates) == 1, len(updates)
    assert FailsafeCommand.objects.filter(status="expired").count() == EXPIRE_PER_READ


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_an_expiry_write_that_fails_never_fails_the_poll(monkeypatch):
    """The write that marks commands expired fails (a locked database): the
    poll still answers the stop. On master it answered 500."""
    from django.db import OperationalError
    from django.db.models import QuerySet

    from failsafe.models import FailsafeCommand

    at = timezone.now() - timedelta(hours=1)
    _make(_starts(3), at, expires=PAST)
    stand_down = _make(["stand_down"], at + timedelta(minutes=1))[0]

    def locked(*args, **kwargs):
        raise OperationalError("database is locked")

    monkeypatch.setattr(QuerySet, "update", locked)
    monkeypatch.setattr(FailsafeCommand, "save", locked)
    assert [c["nonce"] for c in _poll().json()] == [stand_down.nonce]


# --- 5. The cursor -------------------------------------------------------------------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_a_poll_cursor_is_for_its_own_engine_and_a_bad_one_is_400():
    at = timezone.now() - timedelta(hours=1)
    _make(_starts(60), at)
    first = _poll()
    assert first[MORE] == "true"
    for path in ("/api/failsafe/pending/?engine_id=athena-2", "/api/failsafe/pending/"):
        answer = APIClient().get(_with_cursor(path, first[NEXT]), HTTP_X_FAILSAFE_POLL_TOKEN=POLL_TOKEN)
        assert answer.status_code == 400 and "cursor" in answer.json()["detail"], path
    for bad in ("garbage!", "e30", "x" * 2000):
        answer = APIClient().get(_with_cursor("/api/failsafe/pending/?engine_id=athena-1", bad),
                                 HTTP_X_FAILSAFE_POLL_TOKEN=POLL_TOKEN)
        assert answer.status_code == 400, bad
    # Without the token it is 401 before any cursor is read.
    assert APIClient().get(_with_cursor("/api/failsafe/pending/", first[NEXT])).status_code == 401


# --- 6. A stop signed during the flood reaches the poll within its bound ---------------------


@pytest.mark.django_db(transaction=True)
@pytest.mark.usefixtures("rates")
def test_a_stop_signed_during_a_flood_reaches_the_engine_poll_within_its_bound(settings):
    """10,000 ready starts of the engine (and 1,000 of others) while the
    engine polls without pause: an operator drafts a pause and signs it. The
    draft and the signature each answer within STOP_LATENCY_BOUND; every poll
    answers within it; and the first poll that starts after the signature
    answers with the pause first, within the bound of the signature."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    key = Ed25519PrivateKey.generate()
    settings.FAILSAFE_OPERATOR_KEYS = {"alice": key.public_key().public_bytes_raw().hex()}
    at = timezone.now() - timedelta(hours=1)
    _make(_starts(10000), at)
    _make(_starts(1000), at, engine_id="athena-2")
    stopper = _client_for(_admin())
    polls, done, failures = [], threading.Event(), []

    def engine():
        try:
            client = APIClient()
            while not done.is_set():
                began = time.perf_counter()
                answer = client.get("/api/failsafe/pending/?engine_id=athena-1", HTTP_X_FAILSAFE_POLL_TOKEN=POLL_TOKEN)
                ended = time.perf_counter()
                polls.append((began, ended, answer.status_code, [c["nonce"] for c in json.loads(answer.content)]))
        except Exception as exc:  # noqa: BLE001 - reported by the test, not lost on the thread
            failures.append(exc)
        finally:
            connection.close()

    poller = threading.Thread(target=engine)
    poller.start()
    try:
        deadline = time.perf_counter() + 30
        while len(polls) < 3 and time.perf_counter() < deadline:
            time.sleep(0.01)
        began = time.perf_counter()
        drafted = stopper.post("/api/failsafe/commands/", {"action": "pause", "engine_id": "athena-1"}, format="json")
        drafting = time.perf_counter() - began
        assert drafted.status_code == 201, drafted.content
        signature = {"key_id": "alice", "sig": key.sign(bytes.fromhex(drafted.data["signing_bytes"])).hex()}
        began = time.perf_counter()
        signed = stopper.post(f"/api/failsafe/commands/{drafted.data['uuid']}/signatures/", signature, format="json")
        signed_at = time.perf_counter()
        signing = signed_at - began
        assert signed.status_code == 200 and signed.data["status"] == "ready", signed.content
        nonce = drafted.data["nonce"]
        while time.perf_counter() < signed_at + 30 and not any(p[0] >= signed_at for p in polls):
            time.sleep(0.005)
    finally:
        done.set()
        poller.join(60)
    assert failures == []
    after = [p for p in polls if p[0] >= signed_at]
    assert after, "no poll started after the signature"
    first = after[0]
    assert first[2] == 200 and first[3][:1] == [nonce], first[3][:3]
    slow_polls = [round(p[1] - p[0], 4) for p in polls if p[1] - p[0] > STOP_LATENCY_BOUND]
    took = {"draft": drafting, "signature": signing, "to the poll": first[1] - signed_at}
    slow = {name: round(seconds, 4) for name, seconds in took.items() if seconds > STOP_LATENCY_BOUND}
    assert slow == {} and slow_polls == [], (f"over {STOP_LATENCY_BOUND} s during a flood of 10,000 ready starts: "
                                             f"{slow}, polls {slow_polls[:5]}")
