"""No stop waits on its own garbage-collector hold, and none waits on another's.

``safety.collection`` holds the collector off while a stop is served. Its lock was a
plain ``threading.Lock``, taken by the stop that takes a hold, by every request that
checks the hold's limit, and by whoever lets a hold go. A hold whose response is
dropped is let go by ``weakref.finalize``, which runs wherever the collector runs.

The module assumed no collection could start while its lock was held ("no tracked
object is made under the lock"). Under Python 3.12 that is false: a collection that
is due runs at the next function entry, and the lock's holder enters a function. So
the collector finalized a dropped stop response INSIDE a stop's own critical section,
the finalizer asked for the lock that thread already held, and the stop never
returned. Every later stop in that process then waited on the same lock. Seen on
Windows in CI (Athena-Backend #231 at 9e359ed and #232 at 65a4324, both cancelled
after about fifty minutes without output), in
``tests/test_no_control_holds_back_a_stop.py::test_no_collection_runs_while_a_stop_is_served``:

    safety/collection.py, line 74 in __call__                    `with _LOCK:`
    weakref.py, line 590 in __call__                             a weakref.finalize callback
    safety/collection.py, line 53 in _withdraw_if_held_too_long  its entry, with _LOCK held
    safety/collection.py, line 105 in hold_for_a_stop            `with _LOCK:`
    audit/middleware.py, line 1332 in __call__                   the stop gateway

These tests do not depend on when a collector chooses to run, or on a Python version:
each makes the thing happen where it happened. What they hold:

* a hold let go inside the module's own critical section, in the thread that holds
  the lock, is taken and the stop goes on;
* a stop never waits for the lock: with the lock held by another thread for as long
  as the test likes, a stop takes its turn without a hold and returns;
* letting go never waits either, and a hold let go while the lock was busy is counted
  by the next caller, so the collector is handed back;
* nothing in the module can wait on the lock at all (read from its source).
"""

from __future__ import annotations

import ast
import collections
import gc
import inspect
import threading

import pytest

#: Far longer than anything here takes, and far shorter than a CI job: a call that has
#: not returned by now is not slow, it is stuck.
STUCK = 5.0


@pytest.fixture()
def collection():
    """``safety.collection`` with the collector as it was, put back after the test.

    If a test leaves a thread stuck holding the module's lock (which is what the old
    code does in these tests), the module is given a new lock, so the rest of the run
    is not stuck behind it."""
    from safety import collection as module

    thresholds, enabled = gc.get_threshold(), gc.isenabled()
    yield module
    gc.set_threshold(*thresholds)
    if not module._LOCK.acquire(timeout=1.0):
        module._LOCK = threading.Lock()
        module._LOCK.acquire()
    try:
        module._STATE["epoch"] += 1
        module._STATE["holds"] = 0
        module._STATE["switched_off"] = False
    finally:
        module._LOCK.release()
    getattr(module, "_LET_GO", collections.deque()).clear()
    if enabled:
        gc.enable()


def _in_a_thread_of_its_own(call):
    """Start ``call`` in a thread; returns ``(returned, result)``: an Event set when it
    has returned, and the list its result is put in."""
    returned, result = threading.Event(), []

    def run():
        result.append(call())
        returned.set()

    threading.Thread(target=run, daemon=True).start()
    return returned, result


def test_a_hold_let_go_inside_the_stops_own_critical_section_does_not_stop_it(collection, monkeypatch):
    """The deadlock itself: the collector lets an earlier stop's hold go at the entry
    of ``_withdraw_if_held_too_long``, which a stop calls with the lock held."""
    assert gc.isenabled()
    earlier = collection.hold_for_a_stop()
    real = collection._withdraw_if_held_too_long

    def as_the_collector_does(now):
        earlier()  # what weakref.finalize calls when it finalizes the dropped response
        return real(now)

    monkeypatch.setattr(collection, "_withdraw_if_held_too_long", as_the_collector_does)
    returned, result = _in_a_thread_of_its_own(collection.hold_for_a_stop)
    assert returned.wait(STUCK), "a stop waited on the lock it held itself: it never returns"
    monkeypatch.undo()

    # Nothing was lost: both holds are let go, and the collector is handed back.
    assert not gc.isenabled(), "the stop that got through holds the collector off"
    result[0]()
    assert collection._STATE["holds"] == 0, collection._STATE
    assert gc.isenabled(), "the last hold let go, and the collector was not handed back"


def test_a_dropped_response_finalized_inside_the_critical_section_does_not_stop_the_stop(collection, monkeypatch):
    """The same, with nothing stood in for: a real response in a cycle, dropped, its
    hold attached as the gateway attaches it, and a real collection run where Python
    3.12 runs one."""

    class Response:
        pass

    response = Response()
    response.itself = response  # a cycle: only the collector frees it
    collection.let_go_when_answered(response, collection.hold_for_a_stop())
    del response
    real = collection._withdraw_if_held_too_long

    def a_collection_comes_due_here(now):
        gc.collect()
        return real(now)

    monkeypatch.setattr(collection, "_withdraw_if_held_too_long", a_collection_comes_due_here)
    returned, result = _in_a_thread_of_its_own(collection.hold_for_a_stop)
    assert returned.wait(STUCK), "a stop waited on the lock it held itself: it never returns"
    monkeypatch.undo()

    result[0]()
    assert collection._STATE["holds"] == 0, collection._STATE
    assert gc.isenabled()


def test_a_stop_does_not_wait_for_the_lock_while_another_thread_holds_it(collection):
    """Another thread is inside the module (for a few comparisons, or under Python 3.12
    for as long as a collection that came due there takes). A stop does not wait for it:
    it is served without a hold of its own."""
    with collection._LOCK:
        returned, result = _in_a_thread_of_its_own(collection.hold_for_a_stop)
        assert returned.wait(STUCK), "a stop waited for the collector hold's lock"
        hold = result[0]
        # The stop took no hold, and says so by letting go of nothing.
        assert collection._STATE["holds"] == 0 and not collection._STATE["switched_off"]
        let_go, _ = _in_a_thread_of_its_own(hold)
        assert let_go.wait(STUCK), "letting a hold go waited for the lock"
        checked, _ = _in_a_thread_of_its_own(collection.withdraw_if_held_too_long)
        assert checked.wait(STUCK), "a request that is not a stop waited for the lock"
    assert collection._STATE["holds"] == 0 and gc.isenabled()


def test_a_hold_let_go_while_the_lock_was_busy_is_counted_by_the_next_caller(collection):
    """Letting go never waits; what it could not count at once is not lost. The next
    request through the gateway counts it and hands the collector back."""
    hold = collection.hold_for_a_stop()
    assert not gc.isenabled() and collection._STATE["holds"] == 1
    with collection._LOCK:
        let_go, _ = _in_a_thread_of_its_own(hold)
        assert let_go.wait(STUCK), "letting a hold go waited for the lock"
        assert collection._STATE["holds"] == 1, "counted without the lock"
    collection.withdraw_if_held_too_long()  # the next request that is not a stop
    assert collection._STATE["holds"] == 0, collection._STATE
    assert gc.isenabled(), "the collector was left switched off"


def test_a_hold_let_go_twice_or_after_a_withdrawal_lets_go_of_nothing_more(collection, monkeypatch):
    """A response closed and then dropped lets its hold go twice; a hold withdrawn at
    the limit is let go later by its response. Neither takes a second count."""
    first, second = collection.hold_for_a_stop(), collection.hold_for_a_stop()
    assert collection._STATE["holds"] == 2
    first()
    first()
    assert collection._STATE["holds"] == 1 and not gc.isenabled()
    monkeypatch.setattr(collection, "HOLD_LIMIT", 0.0)
    collection.withdraw_if_held_too_long()
    assert collection._STATE["holds"] == 0 and gc.isenabled(), "withdrawn at the limit"
    third = collection.hold_for_a_stop()
    second()  # from the epoch that was withdrawn: it lets go of nothing
    assert collection._STATE["holds"] == 1 and not gc.isenabled()
    third()
    assert collection._STATE["holds"] == 0 and gc.isenabled()


def test_many_stops_at_once_leave_no_hold_behind_and_none_is_stuck(collection):
    """Stops taking and letting go of holds from many threads, with a collection due at
    every allocation: every thread finishes, no hold is left, the collector is back."""
    gc.set_threshold(1, 1, 1)
    finished = []

    def stops():
        for _ in range(300):
            hold = collection.hold_for_a_stop()
            collection.withdraw_if_held_too_long()
            hold()
        finished.append(True)

    threads = [threading.Thread(target=stops, daemon=True) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(STUCK * 6)
    assert len(finished) == len(threads), f"{len(threads) - len(finished)} thread(s) of stops never finished"
    collection.withdraw_if_held_too_long()
    assert collection._STATE["holds"] == 0, collection._STATE
    assert gc.isenabled()


def test_nothing_in_the_module_can_wait_on_its_lock(collection):
    """Read from the source: the lock is never taken with ``with``, and every
    ``acquire`` says ``blocking=False``. A call that cannot take it goes on without."""
    tree = ast.parse(inspect.getsource(collection))
    waits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.With | ast.AsyncWith):
            for item in node.items:
                if "_LOCK" in ast.unparse(item.context_expr):
                    waits.append(f"line {node.lineno}: with {ast.unparse(item.context_expr)}")
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "acquire":
            keywords = {keyword.arg: ast.unparse(keyword.value) for keyword in node.keywords}
            if node.args or keywords != {"blocking": "False"}:
                waits.append(f"line {node.lineno}: {ast.unparse(node)}")
    assert waits == [], "safety.collection can wait on its lock:\n" + "\n".join(waits)
    assert ".acquire(blocking=False)" in inspect.getsource(collection), "the lock is taken somewhere"
