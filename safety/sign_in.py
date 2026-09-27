"""Password sign-in, limited by its own failures.

Sign-in (``/api/token/``) used the default anonymous throttle: one bucket of 30
a minute per address, shared by every anonymous request, so thirty wrong-token
polls from the operator's address refused their correct password. Round 2
counted only failed sign-ins, per address and username -- but keyed on the name
as sent, and SimpleJWT trims it before it authenticates, so ``" operator1"``,
``"operator1\\t"`` and every other padding each had a budget of their own and
each signed in as operator1: unlimited guesses at one account from one address.
And with no per-address cap, every attempt with a new name cost a password hash.

Now two windows count failures, and only failures:

* per address and username: ``sign_in``, default 10 a minute. The username is
  the one authentication will look up -- read by SimpleJWT's own username field,
  so trimmed exactly as it trims it -- then NFKC-normalised and case-folded, so
  every spelling that can authenticate as one account shares one budget (the
  folding only merges more spellings, never fewer);
* per address, across every username: ``sign_in_address``, default 60 a minute.

Both are checked before the password is: an address past either limit is
answered 429 without a password hash, so a flood of names costs nothing after
its 60th failure. A successful sign-in clears only its own address-and-username
count.

What this gives up: a sign-in from an address under a guessing flood can be
refused -- the operator's own, if they share the attacker's address (a proxy
with ``DEFENDER_TRUSTED_PROXY_COUNT`` unset is everyone's address). No stop
needs a password sign-in any more: a stop client presents the failsafe service
token on the stop itself (safety.service_token), and an operator already signed
in keeps their session by refreshing (safety.stops). The gateway still sees
every sign-in.
"""

from __future__ import annotations

import hashlib
import math
import unicodedata

from rest_framework import status
from rest_framework.exceptions import AuthenticationFailed
from rest_framework.fields import SkipField
from rest_framework.response import Response
from rest_framework.throttling import BaseThrottle, SimpleRateThrottle
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.views import TokenObtainPairView


class FailureWindow(SimpleRateThrottle):
    """The failures under one key, in a sliding window of the ``scope``'s rate.

    Not installed as a throttle: :class:`SignInView` asks it before and tells it
    after, because only a failure may count. A scope with no rate (as in the
    test settings) switches it off."""

    def __init__(self, scope, ident):
        self.scope = scope
        super().__init__()
        self.key = None
        if self.rate is not None:
            digest = hashlib.sha256(ident.encode("utf-8", "surrogatepass")).hexdigest()
            self.key = self.cache_format % {"scope": scope, "ident": digest}

    def get_rate(self):
        return self.THROTTLE_RATES.get(self.scope)

    def _recent(self):
        now = self.timer()
        return [moment for moment in self.cache.get(self.key, []) if moment > now - self.duration], now

    def locked_for(self):
        """Seconds until this key may try again, or None if it may now."""
        if self.key is None:
            return None
        recent, now = self._recent()
        if len(recent) < self.num_requests:
            return None
        if not recent:
            # A rate of zero: every attempt waits the whole window.
            return max(1, math.ceil(self.duration))
        oldest_that_counts = recent[max(0, self.num_requests - 1)]
        return max(1, math.ceil(self.duration - (now - oldest_that_counts)))

    def failed(self):
        if self.key is None:
            return
        recent, now = self._recent()
        self.cache.set(self.key, [now, *recent], self.duration)

    def succeeded(self):
        if self.key is not None:
            self.cache.delete(self.key)


def normalised_username(serializer_class, request):
    """The username ``authenticate()`` will be given, as one budget's name, or
    None when the serializer refuses it (the view then answers 400 and never
    hashes a password, so nothing is counted).

    SimpleJWT's username field reads and cleans it (``CharField``: trims
    Unicode whitespace, coerces a number); the result is NFKC-normalised and
    case-folded on top, which only ever merges spellings."""
    serializer = serializer_class()
    field = serializer.fields[serializer.username_field]
    try:
        name = field.run_validation(field.get_value(request.data))
    except SkipField:
        return None
    except Exception:  # noqa: BLE001 - a body or name the serializer refuses: the view answers 400
        return None
    if not isinstance(name, str):
        return None
    return unicodedata.normalize("NFKC", name).casefold()


def _refused(detail, wait):
    response = Response({"detail": detail}, status=status.HTTP_429_TOO_MANY_REQUESTS)
    response["Retry-After"] = str(wait)
    return response


class SignInView(TokenObtainPairView):
    """``/api/token/``: SimpleJWT's sign-in, limited by its own failures only."""

    # The shared anonymous bucket is not applied: see the module docstring.
    throttle_classes = ()

    def post(self, request, *args, **kwargs):
        ident = BaseThrottle().get_ident(request)
        address = FailureWindow("sign_in_address", ident)
        wait = address.locked_for()
        if wait is not None:
            return _refused("Too many failed sign-ins from this address.", wait)
        name = normalised_username(self.get_serializer_class(), request)
        if name is None:
            # Refused by the serializer before any password is checked.
            return super().post(request, *args, **kwargs)
        account = FailureWindow("sign_in", f"{ident}\x00{name}")
        wait = account.locked_for()
        if wait is not None:
            return _refused("Too many failed sign-ins for this username from this address.", wait)
        try:
            response = super().post(request, *args, **kwargs)
        except (AuthenticationFailed, InvalidToken):
            account.failed()
            address.failed()
            raise
        if response.status_code == status.HTTP_200_OK:
            account.succeeded()
        return response
