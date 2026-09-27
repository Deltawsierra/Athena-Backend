"""The project's default throttles, which never refuse or count a stop.

DRF's anonymous (30/min per address) and per-user (300/min) throttles applied to
every view, stops included. A user flooded past their rate got 429 on a pause, a
revoke or a stand-down (#310). The engines' poll of ``/api/failsafe/pending/``
is anonymous, and the engines poll every 2 s, which is exactly 30/min: one extra
poll, or a second engine behind the same address, got 429 with Retry-After 60,
and every pause, stand-down and terminate waited behind it.

A stop (:func:`safety.stops.is_stop`) is allowed before the rate is looked at,
so it is never refused and never recorded: a flood cannot exhaust a stop, and a
stop does not spend the caller's budget. A poll without the poll token is not a
stop, so it keeps the anonymous throttle and the token cannot be guessed at
speed.
"""

from __future__ import annotations

from rest_framework.throttling import AnonRateThrottle, UserRateThrottle

from .stops import is_stop


class StopsPass:
    """Mixin for a DRF throttle: a stop passes, uncounted."""

    def allow_request(self, request, view):
        if is_stop(getattr(request, "_request", request)):
            return True
        return super().allow_request(request, view)


class StopExemptAnonRateThrottle(StopsPass, AnonRateThrottle):
    pass


class StopExemptUserRateThrottle(StopsPass, UserRateThrottle):
    pass
