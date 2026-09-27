"""Password sign-in, limited by the attempts that reach a password hash.

Sign-in (``/api/token/``) used the default anonymous throttle: one bucket of 30
a minute per address, shared by every anonymous request, so thirty wrong-token
polls from the operator's address refused their correct password. Round 2
counted only failed sign-ins, per address and username, keyed on the name as
sent -- and SimpleJWT trims it before it authenticates, so every padding of one
name had a budget of its own. Round 3 keyed the budget on the name as
authentication reads it, but it checked the count before the hash and added to
it after: every request of a burst passed the check before any of them was
counted, so 40 simultaneous guesses at one account were 40 hashes against a
limit of 10. And the count lived in the per-process cache, so each worker had
limits of its own.

Now each attempt is counted BEFORE its password is hashed, by one atomic
``UPDATE ... SET count = count + 1`` on a row in the database
(:class:`safety.models.SignInCount`), which every worker process shares. The
attempt is refused, unhashed, once the count is over the limit. Two limits:

* per address and username: ``sign_in``, default 10 a minute. The username is
  the one authentication will look up -- read by SimpleJWT's own username field,
  so trimmed exactly as it trims it -- then NFKC-normalised and case-folded, so
  every spelling that can authenticate as one account shares one budget;
* per address, across every username: ``sign_in_address``, default 60 a minute.

A window is a sliding estimate over two fixed windows (the current count, plus
the previous window's weighted by how much of it still overlaps), so a burst
straddling a window's edge is not allowed twice. However many attempts arrive
together, at most the limit of them are hashed in a window: each attempt reads
the count after its own increment, and a count read later can only be higher.

Only what reaches the hash stays counted, as before: an attempt refused by one
limit is given back to the other, and a successful sign-in gives its attempt
back to the address and clears its own address-and-username count. A window
that is already full refuses with a read and no write, so a flood of attempts
past the limit adds nothing for a stop's own database writes to wait behind. If
the count cannot be written the sign-in is answered 503 and no password is
hashed.

What this gives up: a sign-in from an address under a guessing flood can be
refused -- the operator's own, if they share the attacker's address (a proxy
with ``DEFENDER_TRUSTED_PROXY_COUNT`` unset is everyone's address). A stop does
not need a password sign-in when its client presents the failsafe service token
(safety.service_token); an operator already signed in keeps their session by
refreshing (safety.refresh). The gateway still sees every sign-in.
"""

from __future__ import annotations

import hashlib
import logging
import math
import secrets
import time
import unicodedata

from django.db import transaction
from django.db.models import F
from rest_framework import status
from rest_framework.fields import SkipField
from rest_framework.response import Response
from rest_framework.throttling import BaseThrottle, SimpleRateThrottle
from rest_framework_simplejwt.views import TokenObtainPairView

logger = logging.getLogger(__name__)


class AttemptWindow:
    """The attempts under one key in a sliding window of the ``scope``'s rate,
    counted in the database.

    Not a throttle: :class:`SignInView` takes an attempt before the password is
    hashed and gives it back when it is not a failure. A scope with no rate (as
    in the test settings) switches it off. The rate is read where the project's
    throttles read theirs."""

    def __init__(self, scope, ident):
        self.key = None
        self.window = None
        rate = SimpleRateThrottle.THROTTLE_RATES.get(scope)
        if rate is None:
            return
        self.limit, duration = SimpleRateThrottle.parse_rate(None, rate)
        self.duration = max(1, int(duration))
        self.key = hashlib.sha256(f"{scope}\x00{ident}".encode("utf-8", "surrogatepass")).hexdigest()

    def take(self):
        """Count one attempt. Returns None when it may go ahead, or the seconds
        to wait when the window is over its limit -- in which case the attempt
        is not counted (or is given back), since it is refused before any hash."""
        from .models import SignInCount

        if self.key is None:
            return None
        now = time.time()
        self.window = int(now // self.duration)
        elapsed = now - self.window * self.duration
        rows = SignInCount.objects.filter(key=self.key)
        # A window already full refuses with a read and no write, so a flood
        # of attempts past the limit adds no writes for a stop's own writes to
        # wait behind. Only an attempt that may go ahead is counted -- and then
        # checked again after its own increment, which is what bounds a burst.
        counts = dict(rows.filter(window__in=(self.window - 1, self.window)).values_list("window", "count"))
        current, previous = counts.get(self.window, 0), counts.get(self.window - 1, 0)
        if current + 1 + previous * (1 - elapsed / self.duration) > self.limit:
            self.window = None
            return self._wait(current, previous, elapsed)
        with transaction.atomic():
            SignInCount.objects.bulk_create(
                [SignInCount(key=self.key, window=self.window, until=(self.window + 2) * self.duration)],
                ignore_conflicts=True,
            )
            rows.filter(window=self.window).update(count=F("count") + 1)
        counts = dict(rows.filter(window__in=(self.window - 1, self.window)).values_list("window", "count"))
        current, previous = counts.get(self.window, 1), counts.get(self.window - 1, 0)
        if current + previous * (1 - elapsed / self.duration) <= self.limit:
            if secrets.randbelow(64) == 0:
                SignInCount.objects.filter(until__lt=int(now)).delete()
            return None
        self.give_back()
        return self._wait(current - 1, previous, elapsed)

    def _wait(self, current, previous, elapsed):
        """Seconds until one more attempt would be under the limit, if no other
        attempt came in the meantime."""
        duration, limit = self.duration, self.limit
        if previous and current + 1 <= limit:
            share = 1 - (limit - current - 1) / previous
            return max(1, math.ceil(share * duration - elapsed))
        rest = duration - elapsed
        if limit <= 0:
            return max(1, math.ceil(rest + duration))
        share = max(0.0, 1 - (limit - 1) / current) if current else 0.0
        return max(1, math.ceil(rest + share * duration))

    def give_back(self):
        from .models import SignInCount

        if self.key is not None and self.window is not None:
            SignInCount.objects.filter(key=self.key, window=self.window, count__gt=0).update(count=F("count") - 1)

    def clear(self):
        from .models import SignInCount

        if self.key is not None:
            SignInCount.objects.filter(key=self.key).delete()


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


def _refused(detail, wait, code=status.HTTP_429_TOO_MANY_REQUESTS):
    response = Response({"detail": detail}, status=code)
    response["Retry-After"] = str(wait)
    return response


class SignInView(TokenObtainPairView):
    """``/api/token/``: SimpleJWT's sign-in, limited by the attempts that reach
    a password hash, counted before the hash."""

    # The shared anonymous bucket is not applied: see the module docstring.
    throttle_classes = ()

    def post(self, request, *args, **kwargs):
        name = normalised_username(self.get_serializer_class(), request)
        if name is None:
            # Refused by the serializer before any password is checked.
            return super().post(request, *args, **kwargs)
        ident = BaseThrottle().get_ident(request)
        address = AttemptWindow("sign_in_address", ident)
        account = AttemptWindow("sign_in", f"{ident}\x00{name}")
        try:
            wait = address.take()
            if wait is not None:
                return _refused("Too many failed sign-ins from this address.", wait)
            wait = account.take()
            if wait is not None:
                address.give_back()
                return _refused("Too many failed sign-ins for this username from this address.", wait)
        except Exception:  # noqa: BLE001 - no attempt is hashed uncounted: refuse it instead
            logger.exception("a sign-in attempt could not be counted; it is refused unchecked")
            return _refused(
                "Sign-in is unavailable: the attempt could not be counted. Try again.", 1,
                code=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        response = super().post(request, *args, **kwargs)
        if response.status_code == status.HTTP_200_OK:
            try:
                account.clear()
                address.give_back()
            except Exception:  # noqa: BLE001 - the sign-in succeeded; a count left over only expires
                logger.exception("a successful sign-in's attempt could not be given back")
        return response
