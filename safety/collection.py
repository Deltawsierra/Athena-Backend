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
here raises, waits on anything but a lock held for a few comparisons, or
switches on a collector something else switched off. No tracked object is made
under the lock, so no collection -- and no finalizer that lets a hold go -- can
start while it is held.
"""

from __future__ import annotations

import gc
import threading
import time
import weakref

#: The longest the collector is held off without a break. Twenty times a
#: stop's bound (0.25 s, the latency tripwire's), so only a hold nobody let go,
#: or stops overlapping without a gap for this long, reaches it.
HOLD_LIMIT = 5.0

_LOCK = threading.Lock()
#: The current epoch (a withdrawal starts a new one, and a hold from an older
#: one lets go of nothing), the holds in flight in it, whether this module
#: switched the collector off, and when (monotonic). Only items are assigned
#: here under _LOCK: no tracked object is made while it is held.
_STATE = {"epoch": 0, "holds": 0, "switched_off": False, "since": 0.0}


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
    call counts."""

    __slots__ = ("epoch", "done", "__weakref__")

    def __init__(self):
        self.epoch = -1
        self.done = False

    def __call__(self) -> None:
        with _LOCK:
            if self.done:
                return
            self.done = True
            if self.epoch != _STATE["epoch"]:
                return  # withdrawn: the collector already runs again
            _STATE["holds"] -= 1
            hand_back = _STATE["holds"] == 0 and _STATE["switched_off"]
            epoch = _STATE["epoch"]
        if hand_back:
            _hand_back(epoch)


def _hand_back(epoch) -> None:
    """Collect the young generations, with the collector still off, then switch
    it back on -- unless another stop took hold meanwhile, whose letting go
    hands it back instead."""
    try:
        gc.collect(1)
    finally:
        with _LOCK:
            if _STATE["epoch"] == epoch and _STATE["holds"] == 0 and _STATE["switched_off"]:
                _STATE["switched_off"] = False
                gc.enable()


def hold_for_a_stop() -> _Hold:
    """Hold the collector off for one stop. Returns the call that lets go."""
    hold = _Hold()
    now = time.monotonic()
    with _LOCK:
        _withdraw_if_held_too_long(now)
        if _STATE["holds"] == 0 and not _STATE["switched_off"] and gc.isenabled():
            gc.disable()
            _STATE["switched_off"] = True
            _STATE["since"] = now
        _STATE["holds"] += 1
        hold.epoch = _STATE["epoch"]
    return hold


def withdraw_if_held_too_long() -> None:
    """Switch the collector back on if it has been held off for HOLD_LIMIT:
    called on every request that is not a stop, so a hold nobody let go ends
    without waiting for another stop. A clock read and a few comparisons."""
    now = time.monotonic()
    with _LOCK:
        _withdraw_if_held_too_long(now)


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
