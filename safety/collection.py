"""No stop waits on the garbage collector.

CPython's cyclic collector runs in whichever thread allocates past its
threshold, at that moment, and a full (generation-2) collection traverses every
tracked object in the process -- the framework, the application and whatever
earlier requests left behind -- so its pause is set by the process, not by the
request it lands in. Measured across the stop test module, a full collection at
about 200,000 tracked objects took from 0.025 s to 0.34 s, and two landed inside
stops on 19 Oct: 0.234 s of a 0.249 s revoke and 0.303 s of a 0.307 s engagement
pause, each in the stop's own thread, its SQL under 2 ms, nothing else waited on
(the latency tripwire's ``_StopClock`` in tests/test_no_control_holds_back_a_stop.py).

So the collector is held off while a stop is served: from the moment
``safety.stops`` judges a request a stop (``audit.middleware.DefenderMiddleware``)
until its response is closed -- a server closes it once it has written it -- or,
if it never is, dropped. When the last stop in flight lets go, the young
generations are collected (:func:`_hand_back`) -- work bounded by what was
allocated since the last young collection, never a pass over the whole heap --
and the collector is switched back on with no full collection due until a
generation-1 collection has run eleven more times (CPython's thresholds), so
none starts in what is left of the request either.

Bounded, so a stop can never switch the collector off for good: once it has
been held off for :data:`HOLD_LIMIT` seconds without a break -- stops
overlapping with no gap, or a response nobody closes or drops -- the holds in
flight are withdrawn and it runs again; the next stop holds it afresh. Nothing
here raises, waits on anything, or switches on a collector something else
switched off.

Nothing here waits on its own lock either. A collection can start inside any
function -- under Python 3.12 a collection that is due runs at the next
function entry, wherever that is -- and it can finalize a dropped stop
response, whose finalizer lets that stop's hold go. This module once assumed
that could not happen while its lock was held, and a stop waited for ever on
the lock its own thread held (tests/test_no_stop_waits_on_its_own_collector_hold.py).
So every call takes the lock only if it is free (``acquire(blocking=False)``):

* a stop that finds it busy is served without a hold -- the collector may run
  in it, as it would with no hold at all -- and lets go of nothing;
* a check of the limit that finds it busy is left to the next request;
* a hold let go while it is busy is put in :data:`_LET_GO`, and whoever holds
  the lock counts it before letting go of the lock (:func:`_leave`), or the
  next caller does. Only the first letting go of a hold counts: that is decided
  under the lock.
"""

from __future__ import annotations

import collections
import gc
import threading
import time
import weakref

#: The longest the collector is held off without a break. Twenty times a
#: stop's bound (0.25 s, the latency tripwire's), so only a hold nobody let go,
#: or stops overlapping without a gap for this long, reaches it.
HOLD_LIMIT = 5.0

#: Only ever taken with ``acquire(blocking=False)``: see the module's docstring.
_LOCK = threading.Lock()
#: The current epoch (a withdrawal starts a new one, and a hold from an older
#: one lets go of nothing), the holds in flight in it, whether this module
#: switched the collector off, and when (monotonic). Read and written only by
#: the holder of _LOCK.
_STATE = {"epoch": 0, "holds": 0, "switched_off": False, "since": 0.0}
#: Holds let go while _LOCK was busy, in the order they were let go: counted by
#: the next holder of _LOCK before it lets go of it. Appending never waits.
_LET_GO = collections.deque()


def _withdraw_if_held_too_long(now) -> None:
    """Under _LOCK: if this module has held the collector off for HOLD_LIMIT,
    withdraw every hold in flight and switch it back on."""
    if _STATE["switched_off"] and now - _STATE["since"] >= HOLD_LIMIT:
        _STATE["epoch"] += 1
        _STATE["holds"] = 0
        _STATE["switched_off"] = False
        gc.enable()


class _Hold:
    """One stop's hold on the collector. Calling it lets go; only the first
    call counts. Calling it never waits."""

    __slots__ = ("epoch", "done", "__weakref__")

    def __init__(self):
        self.epoch = -1
        self.done = False

    def __call__(self) -> None:
        if self.done:
            return
        if not _LOCK.acquire(blocking=False):
            # Busy -- perhaps in this very thread, when the collector finalizes a
            # dropped response inside this module. Whoever holds it counts this.
            _LET_GO.append(self)
            return
        try:
            _let_go(self)
        finally:
            _leave()


def _let_go(hold) -> None:
    """Under _LOCK: count ``hold`` as let go, the first time only, and only if
    it is of the current epoch (a withdrawn hold lets go of nothing)."""
    if not hold.done:
        hold.done = True
        if hold.epoch == _STATE["epoch"]:
            _STATE["holds"] -= 1


def _count_let_go() -> None:
    """Under _LOCK: count the holds let go while it was busy."""
    while _LET_GO:
        _let_go(_LET_GO.popleft())


def _leave() -> None:
    """Let go of _LOCK, which the caller holds: first count what was let go
    while it was held, then, if that was the last hold in flight, hand the
    collector back."""
    _count_let_go()
    hand_back = _STATE["holds"] == 0 and _STATE["switched_off"]
    epoch = _STATE["epoch"]
    _LOCK.release()
    if hand_back:
        _hand_back(epoch)


def _hand_back(epoch) -> None:
    """Collect the young generations, with the collector still off, then switch
    it back on -- unless another stop took hold meanwhile, whose letting go
    hands it back instead. If the lock is busy, its holder hands it back as it
    lets go of the lock (:func:`_leave`)."""
    try:
        gc.collect(1)
    finally:
        if _LOCK.acquire(blocking=False):
            try:
                _count_let_go()
                if _STATE["epoch"] == epoch and _STATE["holds"] == 0 and _STATE["switched_off"]:
                    _STATE["switched_off"] = False
                    gc.enable()
            finally:
                _leave()


def hold_for_a_stop() -> _Hold:
    """Hold the collector off for one stop. Returns the call that lets go.

    Never waits: if the lock is busy, the stop is served without a hold, and
    the call returned lets go of nothing."""
    hold = _Hold()
    now = time.monotonic()
    if not _LOCK.acquire(blocking=False):
        hold.done = True
        return hold
    try:
        _withdraw_if_held_too_long(now)
        _count_let_go()
        if _STATE["holds"] == 0 and not _STATE["switched_off"] and gc.isenabled():
            gc.disable()
            _STATE["switched_off"] = True
            _STATE["since"] = now
        _STATE["holds"] += 1
        hold.epoch = _STATE["epoch"]
    finally:
        _leave()
    return hold


def withdraw_if_held_too_long() -> None:
    """Switch the collector back on if it has been held off for HOLD_LIMIT:
    called on every request that is not a stop, so a hold nobody let go ends
    without waiting for another stop. A clock read and a few comparisons; if
    the lock is busy, the next request checks."""
    now = time.monotonic()
    if not _LOCK.acquire(blocking=False):
        return
    try:
        _withdraw_if_held_too_long(now)
    finally:
        _leave()


def let_go_when_answered(response, hold) -> None:
    """Let ``hold`` go when ``response`` is closed -- a server closes it once it
    has written it -- or, if it never is, when it is dropped."""
    closers = getattr(response, "_resource_closers", None)
    if isinstance(closers, list):
        closers.append(hold)
    try:
        weakref.finalize(response, hold)
    except TypeError:  # cannot be watched: then it is let go on close, or now
        if not isinstance(closers, list):
            hold()
