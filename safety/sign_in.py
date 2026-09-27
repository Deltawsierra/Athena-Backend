"""Sign-in that no flood can lock an operator out of.

An operator signs in to press stop. Sign-in (``/api/token/``) used the default
anonymous throttle: one bucket of 30 a minute per address, shared by every
anonymous request. Thirty wrong-token polls of ``/api/failsafe/pending/``, or
thirty bad sign-ins for any name, from the operator's address -- which behind a
proxy with ``DEFENDER_TRUSTED_PROXY_COUNT`` unset is everyone's address -- and
the operator's correct password was answered 429 for a minute.

Now only FAILED sign-ins are counted, per address AND username. A correct
credential is refused only when that username has itself failed too often from
that address; nothing any other name or any other route does can refuse it, and
a successful sign-in clears the count. The token refresh is exempt from the
gateway and the throttles when its refresh token verifies (safety.stops), so a
signed-in operator stays signed in whatever else is happening.

What this gives up: one address can try one password against many usernames,
each within its own budget. The gateway still sees every sign-in.
"""

from __future__ import annotations

import hashlib
import math

from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.response import Response
from rest_framework.throttling import SimpleRateThrottle
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.views import TokenObtainPairView


class SignInFailures(SimpleRateThrottle):
    """The failed sign-ins of one username from one address, in a sliding window.

    Not installed as a throttle: :class:`SignInView` asks it before and tells it
    after, because only a failure may count. Its rate is the ``sign_in`` rate;
    none (as in the test settings) switches it off."""

    scope = "sign_in"

    def __init__(self, request):
        super().__init__()
        self.key = None
        if self.rate is not None:
            name = _username(request)
            ident = self.get_ident(request)
            digest = hashlib.sha256(f"{ident}\x00{name}".encode("utf-8", "surrogatepass")).hexdigest()
            self.key = self.cache_format % {"scope": self.scope, "ident": digest}

    def get_rate(self):
        return self.THROTTLE_RATES.get(self.scope)

    def _recent(self):
        now = self.timer()
        return [moment for moment in self.cache.get(self.key, []) if moment > now - self.duration], now

    def locked_for(self):
        """Seconds until this username may try again from this address, or None."""
        if self.key is None:
            return None
        recent, now = self._recent()
        if len(recent) < self.num_requests:
            return None
        return max(1, math.ceil(self.duration - (now - recent[self.num_requests - 1])))

    def failed(self):
        if self.key is None:
            return
        recent, now = self._recent()
        self.cache.set(self.key, [now, *recent], self.duration)

    def succeeded(self):
        if self.key is not None:
            self.cache.delete(self.key)


def _username(request):
    from django.contrib.auth import get_user_model

    try:
        value = request.data.get(get_user_model().USERNAME_FIELD)
    except Exception:  # noqa: BLE001 - a body the parser refuses names nobody; the view answers it
        return ""
    return value if isinstance(value, str) else ""


class SignInView(TokenObtainPairView):
    """``/api/token/``: SimpleJWT's sign-in, limited by its own failures only."""

    # The shared anonymous bucket is not applied: see the module docstring.
    throttle_classes = ()

    def post(self, request, *args, **kwargs):
        failures = SignInFailures(request)
        wait = failures.locked_for()
        if wait is not None:
            response = Response(
                {"detail": "Too many failed sign-ins for this username from this address."},
                status=status.HTTP_429_TOO_MANY_REQUESTS,
            )
            response["Retry-After"] = str(wait)
            return response
        try:
            response = super().post(request, *args, **kwargs)
        except (AuthenticationFailed, InvalidToken):
            failures.failed()
            raise
        if response.status_code == status.HTTP_200_OK:
            failures.succeeded()
        return response
