"""No housekeeping write holds back a stop (AB-STOP-FIXES, part 1).

Three writes sat in front of a stop and were not the stop:

* the stop-lane reads -- the state read, where the second operator finds the
  stand-down to co-sign, and the list -- marked commands past their window
  expired with a write that waited for the database's write lock. Any other
  writer holding it held the read: 3.05 s for a 3 s hold, up to busy_timeout
  (20 s). Only the poll's expiry was refused at once;
* a signed stop's audit rows were inserted inside the transaction that made it
  ready: a slow insert held the stop's commit, so the engine was served it
  3.04 s late and the operator answered 3.02 s late;
* a stop draft's bytes to sign came back only after its supersede and its
  audit insert, each waiting for the write lock: the row was signable at
  0.023 s, its answer came at 3.01 s.

Each is housekeeping now. The audit rows and the supersede are written after
the stop's transaction commits, and none of these writes ever waits for the
write lock: refused at once, each is logged, and a missing audit row is still
counted and said on the answer (X-Failsafe-Audit-Missed). The stop mark stays
inside the stop's transaction: it is what holds older starts back.

And the count of missing audit rows lives in memory, per process: after a
restart it read as none. The state read now says since when it counts
(X-Failsafe-Audit-Missed-Since), so a zero reads "none since T".

Each test here MEASURES, on its own connections, as the stop suite does.
"""

import threading
import time
from datetime import datetime

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.db import OperationalError, connection, transaction
from django.utils import timezone
from rest_framework.test import APIClient

from tests.test_no_control_holds_back_a_stop import POLL_TOKEN, _admin, _client_for
from tests.test_no_control_holds_back_a_stop import configure, rates  # noqa: F401 - fixtures, used by name

AUDIT_MISSED = "X-Failsafe-Audit-Missed"
AUDIT_MISSED_SINCE = "X-Failsafe-Audit-Missed-Since"
PAST = "2000-01-01T00:00:00+00:00"
#: How long another writer holds the database's write lock, at most: the hold
#: each defect was measured under.
HOLD = 3.0
#: The longest each read or answer here may take while that lock is held, or
#: while a housekeeping write is slow: a sixth of the hold, so a read that waited
#: for it is never within it.
BOUND = 0.5


@pytest.fixture()
def keys(settings):
    made = {f"op{n}": Ed25519PrivateKey.generate() for n in range(2)}
    settings.FAILSAFE_OPERATOR_KEYS = {name: key.public_key().public_bytes_raw().hex() for name, key in made.items()}
    settings.FAILSAFE_COMMAND_TTL_SECONDS = 600
    return made


def _draft(client, action, engine_id, reason=""):
    answer = client.post("/api/failsafe/commands/", {"action": action, "engine_id": engine_id, "reason": reason},
                         format="json")
    assert answer.status_code in (200, 201), answer.content
    return answer.data


def _sign(client, drafted, keys, name):
    body = {"key_id": name, "sig": keys[name].sign(bytes.fromhex(drafted["signing_bytes"])).hex()}
    return client.post(f"/api/failsafe/commands/{drafted['uuid']}/signatures/", body, format="json")


def _poll(engine_id):
    return APIClient().get(f"/api/failsafe/pending/?engine_id={engine_id}", HTTP_X_FAILSAFE_POLL_TOKEN=POLL_TOKEN)


class _LockHolder:
    """Another connection holding the database's write lock -- a session row,
    a scan or a report being written -- in an open transaction, until
    ``release()`` or HOLD seconds, whichever is first."""

    def __init__(self, user_pk):
        self.user_pk = user_pk
        self.held, self.done = threading.Event(), threading.Event()
        self.error = None
        self.thread = threading.Thread(target=self._hold, name="another-writer", daemon=True)

    def _hold(self):
        try:
            with transaction.atomic():
                get_user_model().objects.filter(pk=self.user_pk).update(last_login=timezone.now())
                self.held.set()
                self.done.wait(HOLD)
        except Exception as exc:  # noqa: BLE001 - reported by the test that started it
            self.error = exc
        finally:
            connection.close()

    def start(self, within=10.0):
        """Start it, and wait until it holds the lock -- at most ``within``
        seconds (a connection that holds the lock itself would wait for ever)."""
        self.thread.start()
        self.held.wait(within)
        return self

    def release(self):
        self.done.set()
        self.thread.join(30)
        assert self.error is None, self.error


def _timed(call):
    began = time.monotonic()
    answer = call()
    return answer, round(time.monotonic() - began, 3)


def _on_a_thread(call):
    """Run ``call`` on a thread of its own (its own connection): (thread, out).
    ``out`` holds when it began and ended (monotonic), and its answer or error."""
    out = {}

    def run():
        try:
            out["began"] = time.monotonic()
            out["answer"] = call()
        except Exception as exc:  # noqa: BLE001 - reported by the test
            out["error"] = exc
        finally:
            out["ended"] = time.monotonic()
            connection.close()

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    while "began" not in out:
        time.sleep(0.001)
    return thread, out


def _served_at(engine_id, nonce, until):
    """When (monotonic) ``nonce`` was first served to a poll of ``engine_id``, each
    poll 20 ms apart, from this thread's connection; None if not by ``until``."""
    while time.monotonic() < until:
        answer = _poll(engine_id)
        if answer.status_code == 200 and any(c["nonce"] == nonce for c in answer.json()):
            return time.monotonic()
        time.sleep(0.02)
    return None


# --- 1. The stop-lane reads: their expiry write never waits for the write lock ------------------------------


@pytest.mark.django_db(transaction=True)
@pytest.mark.usefixtures("rates")
def test_the_stop_lane_reads_never_wait_on_the_write_lock_for_housekeeping(keys):
    """One command past its window, and a stand-down awaiting its second
    signature. Another connection holds the write lock: each read the second
    operator makes -- the state read (where they find the stand-down), the
    list, the command itself, and a signature on the command past its window
    -- answers within BOUND, never after the hold (master: 3.05 s each, up to
    busy_timeout). The expiry each read could not write is not lost: a later
    read, with the lock free, marks the command expired."""
    from failsafe.models import FailsafeCommand

    admin = _admin()
    client = _client_for(admin)
    engine = "housekeeping-reads"
    due = _draft(client, "pause", engine, reason="past its window")
    FailsafeCommand.objects.filter(uuid=due["uuid"]).update(expires_at=PAST)
    stand_down = _draft(client, "stand_down", engine, reason="awaiting its second operator")
    assert _sign(client, stand_down, keys, "op0").data["status"] == "awaiting_signatures"

    reads = {
        "state": (lambda: _client_for(admin).get(f"/api/failsafe/state/?engine_id={engine}"), 200),
        "list": (lambda: _client_for(admin).get(f"/api/failsafe/commands/?engine_id={engine}"), 200),
        "detail": (lambda: _client_for(admin).get(f"/api/failsafe/commands/{due['uuid']}/"), 200),
        "signature": (lambda: _sign(_client_for(admin), due, keys, "op1"), 409),
    }
    took = {}
    for name, (call, code) in reads.items():
        FailsafeCommand.objects.filter(uuid=due["uuid"]).update(status="awaiting_signatures")
        holder = _LockHolder(admin.pk).start()
        assert holder.held.is_set(), "the other writer never took the write lock"
        try:
            answer, took[name] = _timed(call)
        finally:
            holder.release()
        assert answer.status_code == code, (name, answer.status_code, answer.content[:300])
        if name == "state":
            listed = [row["uuid"] for row in answer.data["awaiting_signatures"]]
            assert stand_down["uuid"] in listed, "the co-signer's read did not list the stand-down"
        if name in ("detail", "signature"):
            assert "expired" in str(answer.data), (name, answer.data)
    slow = {name: seconds for name, seconds in took.items() if seconds > BOUND}
    assert slow == {}, f"a stop-lane read waited on the write lock for its housekeeping: {took}"

    assert _client_for(admin).get(f"/api/failsafe/state/?engine_id={engine}").status_code == 200
    assert FailsafeCommand.objects.get(uuid=due["uuid"]).status == "expired", "the expiry was lost, not put off"
    print(f"\nTIMINGS stop-lane reads under a held write lock: {took}")


# --- 2. A signed stop: served the moment it commits ---------------------------------------------------------


@pytest.mark.django_db(transaction=True)
@pytest.mark.usefixtures("rates")
@pytest.mark.parametrize("event", ["signed", "ready"])
def test_no_audit_row_holds_back_a_signed_stop(event, keys, monkeypatch):
    """A pause's ``signed`` or ``ready`` audit insert takes HOLD seconds. The
    pause is served to a poll on another connection within BOUND of its
    signature, not after the insert (master: 3.04 s): its audit rows are
    written after the stop's transaction commits. The signature is answered
    ready, and its audit rows are all written."""
    from failsafe.models import FailsafeAuditEvent

    admin = _admin()
    engine = f"slow-{event}-row"
    drafted = _draft(_client_for(admin), "pause", engine)
    real = FailsafeAuditEvent.save
    signer = {}

    def slow(self, *args, **kwargs):
        if self.event == event and threading.current_thread() is signer.get("thread"):
            time.sleep(HOLD)
        return real(self, *args, **kwargs)

    monkeypatch.setattr(FailsafeAuditEvent, "save", slow)
    signer["thread"], out = _on_a_thread(lambda: _sign(_client_for(admin), drafted, keys, "op0"))
    served = _served_at(engine, drafted["nonce"], out["began"] + 2 * HOLD)
    signer["thread"].join(30)
    assert "error" not in out, out["error"]
    assert out["answer"].status_code == 200 and out["answer"].data["status"] == "ready", out["answer"].data
    assert served is not None, "the pause was never served"
    after = round(served - out["began"], 3)
    assert after <= BOUND, f"the pause was served {after}s after its signature: its {event} audit row held it"
    rows = set(FailsafeAuditEvent.objects.filter(command__uuid=drafted["uuid"]).values_list("event", flat=True))
    assert {"drafted", "signed", "ready"} <= rows, rows
    print(f"\nTIMINGS a slow {event} row: the pause served {after}s after its signature")


@pytest.mark.django_db(transaction=True)
@pytest.mark.usefixtures("rates")
@pytest.mark.parametrize("action", ["pause", "stand_down"])
def test_a_signed_stops_answer_never_waits_on_the_write_lock_for_its_audit_rows(action, keys, monkeypatch):
    """Another connection takes the write lock the moment the stop's
    transaction commits, before its audit rows are written. The signature
    that made it ready is answered within BOUND: the rows are refused at
    once, never queued for the lock, and the answer says how many are missing
    (X-Failsafe-Audit-Missed), as an insert that fails does. The stop is ready,
    in force and served all the same."""
    from failsafe import views

    admin = _admin()
    engine = f"locked-audit-{action}"
    client = _client_for(admin)
    drafted = _draft(client, action, engine)
    if action == "stand_down":
        assert _sign(client, drafted, keys, "op0").data["status"] == "awaiting_signatures"
    real = views._audit_a_stop
    holders = []

    def after_another_writer_takes_the_lock(events, *args, **kwargs):
        if not holders:
            # Inside the stop's own transaction (master) it cannot take the lock: waited for 1 s, then on.
            holders.append(_LockHolder(admin.pk).start(within=1.0))
        return real(events, *args, **kwargs)

    monkeypatch.setattr(views, "_audit_a_stop", after_another_writer_takes_the_lock)
    last = "op1" if action == "stand_down" else "op0"
    try:
        answer, took = _timed(lambda: _sign(_client_for(admin), drafted, keys, last))
    finally:
        for holder in holders:
            holder.release()
    assert answer.status_code == 200 and answer.data["status"] == "ready", answer.data
    assert holders and holders[0].held.is_set(), "the stop's audit rows were not written after it committed"
    assert took <= BOUND, f"the {action}'s answer waited {took}s on the write lock for its audit rows"
    # Its signed and ready rows, refused at once, are said missing.
    assert answer.headers.get(AUDIT_MISSED) == "2", dict(answer.headers)
    assert [c["nonce"] for c in _poll(engine).json()] == [drafted["nonce"]]
    print(f"\nTIMINGS the {action}'s answer with the write lock taken after its commit: {took}s")


@pytest.mark.django_db(transaction=True)
@pytest.mark.usefixtures("rates")
def test_a_stop_and_its_engines_mark_are_written_in_one_transaction(keys, monkeypatch):
    """The mark is what holds a start drafted before the stop back, once the
    stop is no longer ready, so it is never behind the stop: with the mark's
    write slowed, the first poll on another connection that is served the
    pause already reads the engine's mark naming it. (A slow mark therefore
    delays the stop, which is the lead's ruling: the mark stays with it.)"""
    from failsafe import views
    from failsafe.models import FailsafeStopMark

    admin = _admin()
    engine = "mark-with-the-stop"
    drafted = _draft(_client_for(admin), "pause", engine)
    real = views._mark_stop_made_ready

    def slow(command):
        time.sleep(1.0)
        return real(command)

    monkeypatch.setattr(views, "_mark_stop_made_ready", slow)
    thread, out = _on_a_thread(lambda: _sign(_client_for(admin), drafted, keys, "op0"))
    served = _served_at(engine, drafted["nonce"], out["began"] + 2 * HOLD)
    mark = FailsafeStopMark.objects.filter(engine_id=engine).values_list("stop_uuid", flat=True).first()
    thread.join(30)
    assert "error" not in out, out["error"]
    assert served is not None, "the pause was never served"
    assert mark is not None and str(mark) == drafted["uuid"], "the pause was served before its engine's mark moved"


#: The statements the request's own connection made for each stop path on master
#: (6b25920), measured by the test below under this same harness: outside any
#: transaction, as a request runs. (Inside one -- tests/test_a_stop_in_force_keeps_
#: being_served.py's MASTER -- the housekeeping writes stay on the request's
#: connection, which already holds the write lock, and its counts are master's.)
MASTER_OUTSIDE_A_TRANSACTION = {
    "draft": {"select": 3, "begin": 2, "insert": 2, "commit": 2},
    "sign first": {"select": 3, "begin": 1, "update": 3, "insert": 3, "commit": 1},
    "sign later": {"select": 3, "begin": 1, "update": 3, "insert": 2, "commit": 1},
}


@pytest.mark.django_db(transaction=True)
@pytest.mark.usefixtures("rates")
def test_a_stops_housekeeping_adds_no_statement_to_its_request_connection(keys):
    """Outside any transaction, as a request runs, a stop's audit rows and a
    draft's supersede are written on a connection of their own, opened with a
    busy timeout of 0 at connect time: the request's connection makes no
    statement of a kind, or in a number, that master's did not -- no PRAGMA --
    and the audit rows are all written."""
    from failsafe.models import FailsafeAuditEvent
    from tests.test_a_stop_in_force_keeps_being_served import _statements

    client = _client_for(_admin())
    measured, drafted = {}, []
    for when in ("first", "later"):
        answer, measured["draft"], _ = _statements(lambda: client.post(
            "/api/failsafe/commands/", {"action": "pause", "engine_id": "housekeeping-counts"}, format="json"))
        assert answer.status_code == 201 and AUDIT_MISSED not in answer.headers
        signed, measured[f"sign {when}"], _ = _statements(lambda: _sign(client, answer.data, keys, "op0"))  # noqa: B023
        assert signed.data["status"] == "ready" and AUDIT_MISSED not in signed.headers
        drafted.append(answer.data["uuid"])
        for path in ("draft", f"sign {when}"):
            was = MASTER_OUTSIDE_A_TRANSACTION[path]
            more = {kind: n for kind, n in measured[path].items() if n > was.get(kind, 0)}
            assert more == {}, (path, measured[path], was)
    for uuid in drafted:
        events = sorted(FailsafeAuditEvent.objects.filter(command__uuid=uuid).values_list("event", flat=True))
        assert events == ["drafted", "ready", "signed"], events
    print(f"\nSTATEMENTS outside a transaction: master {MASTER_OUTSIDE_A_TRANSACTION}\nbranch {measured}")


# --- 3. A stop draft: its bytes to sign never wait on its housekeeping --------------------------------------


@pytest.mark.django_db(transaction=True)
@pytest.mark.usefixtures("rates")
def test_a_stop_drafts_answer_never_waits_on_the_write_lock_for_its_supersede_or_audit_row(keys, settings):
    """An account past its limit of unsigned stop drafts drafts one more, and
    another connection takes the write lock the moment the draft's own
    transaction commits. The 201 with the bytes to sign arrives within BOUND
    (master: 3.01 s): the supersede and the audit insert are refused at once,
    the supersede is logged and tried again by the next draft, and the missing
    audit row is said. The draft is signable, and signed it is served."""
    from failsafe import views
    from failsafe.models import FailsafeCommand

    settings.FAILSAFE_UNSIGNED_STOP_DRAFTS_PER_ACCOUNT = 1
    admin = _admin()
    client = _client_for(admin)
    older = _draft(client, "pause", "housekeeping-draft-older")
    real = views._supersede_past_limit
    holders = []

    def after_another_writer_takes_the_lock(newest, *args, **kwargs):
        if not holders:
            holders.append(_LockHolder(admin.pk).start(within=1.0))
        return real(newest, *args, **kwargs)

    with pytest.MonkeyPatch.context() as patched:
        patched.setattr(views, "_supersede_past_limit", after_another_writer_takes_the_lock)
        try:
            answer, took = _timed(lambda: _client_for(admin).post(
                "/api/failsafe/commands/", {"action": "pause", "engine_id": "housekeeping-draft"}, format="json"))
        finally:
            for holder in holders:
                holder.release()
    assert answer.status_code == 201 and answer.data["signing_bytes"], answer.content[:300]
    assert holders and holders[0].held.is_set(), "the draft's supersede was not made after its transaction"
    assert took <= BOUND, f"the stop draft's bytes to sign waited {took}s on the write lock for its housekeeping"
    assert answer.headers.get(AUDIT_MISSED) == "1", dict(answer.headers)
    assert FailsafeCommand.objects.get(uuid=older["uuid"]).status == "awaiting_signatures"
    signed = _sign(client, answer.data, keys, "op0")
    assert signed.status_code == 200 and signed.data["status"] == "ready", signed.data
    assert [c["nonce"] for c in _poll("housekeeping-draft").json()] == [answer.data["nonce"]]
    # The next draft supersedes what this one could not.
    _draft(client, "pause", "housekeeping-draft-next")
    assert FailsafeCommand.objects.get(uuid=older["uuid"]).status == "superseded"
    print(f"\nTIMINGS a stop draft with the write lock taken after its commit: {took}s")


# --- 4. The count of missing audit rows says since when -----------------------------------------------------


@pytest.mark.django_db
@pytest.mark.usefixtures("rates")
def test_the_count_of_missing_audit_rows_says_since_when_it_counts(keys, monkeypatch):
    """The count is this process's (it lives in memory). The state read always
    says it, and since when: a zero then reads "none since T", never "none".
    After a restart -- a fresh count -- the state read says 0 since the new
    process began, not a bare 0; master said nothing at all, as if none had
    ever been missed."""
    from failsafe import views
    from failsafe.models import FailsafeAuditEvent

    client = _client_for(_admin())
    engine = "missed-since"

    def said():
        state = client.get(f"/api/failsafe/state/?engine_id={engine}")
        assert state.status_code == 200
        return state.headers.get(AUDIT_MISSED), state.headers.get(AUDIT_MISSED_SINCE)

    count, since = said()
    assert since is not None, "the state read does not say since when its count of missing audit rows counts"
    began = datetime.fromisoformat(since)
    assert began.tzinfo is not None and began == views.AUDIT_ROWS_MISSED.since
    assert count == str(views.AUDIT_ROWS_MISSED.value)

    drafted = _draft(client, "pause", engine)

    def failing(*args, **kwargs):
        raise OperationalError("database or disk is full")

    with pytest.MonkeyPatch.context() as broken:
        broken.setattr(FailsafeAuditEvent, "save", failing)
        assert _sign(client, drafted, keys, "op0").headers.get(AUDIT_MISSED) == "2"
    count, since_after = said()
    assert int(count) >= 2 and since_after == since

    restarted = views._Count()
    monkeypatch.setattr(views, "AUDIT_ROWS_MISSED", restarted)
    count, since_restart = said()
    assert (count, since_restart) == ("0", restarted.since.isoformat())
    assert datetime.fromisoformat(since_restart) >= began
