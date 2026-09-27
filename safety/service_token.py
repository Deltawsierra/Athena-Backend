"""The failsafe service credential: how a stop client stops without a password.

The dashboard's server makes every stop it relays as one service account, and it
got that account's token by signing in with a password -- on first use, after
every restart, and every hour when the access token expired. Sign-in is not a
stop: the gateway judges it (in enforce mode its block answered 403), and ten
wrong guesses at the service username from the shared address locked it out
for as long as the guesses kept coming. Every dashboard stop then answered 503.

So a stop no longer needs a password sign-in. ``FAILSAFE_SERVICE_TOKEN`` is a
pre-shared secret, like the engines' poll token, presented in the
``X-Failsafe-Service-Token`` header. It is accepted ONLY on a request that is a
stop (safety.stops.is_stop) on a route a stop client relays stops on
(:data:`SERVICE_ROUTES`: every stop route but the engines' poll and the two
account routes), the three stop-lane reads included (failsafe:state, the
failsafe:commands list and a command's detail), and it authenticates as the
account named by
``FAILSAFE_SERVICE_USER``, whose role the views check as they check any
operator's. It is tried before any other authentication, so a stale bearer
header beside it cannot refuse the stop.

What it cannot do is as important. Anywhere else -- a lift, a resume or release
draft, a routine recompute, any read that is not in the stop lane, an operator
demoted or removed, the engines' poll, a refresh -- the header is ignored and
the request is judged and authenticated exactly as if it were absent. A stolen
service token can stop things and read the stop lane; it can start nothing,
and it cannot demote or remove an operator. A token that does not match is
ignored the same way: the request takes the normal path, and the
token confers no exemption of its own. (A stop is exempt from the gateway and
the throttles because it is a stop, with or without this header.)

Checking it is cheap and bounded, because the gateway and the throttles run
before authentication: the stop judgement is made once per request and kept on
it, the token is compared as two HMAC-SHA256 digests of one length in constant
time, and only a token that matches costs a read -- the one account, by its
unique username.

A token shorter than :data:`MIN_TOKEN_LENGTH` characters is treated as unset:
the stop requests it is accepted on are exempt from every throttle, so a short
one could be guessed at speed. ``openssl rand -hex 32`` makes one.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import secrets

from django.conf import settings
from rest_framework.authentication import BaseAuthentication

from .stops import STOP_ROUTES, is_stop, view_name

logger = logging.getLogger(__name__)

HEADER = "X-Failsafe-Service-Token"
_META = "HTTP_X_FAILSAFE_SERVICE_TOKEN"

#: The shortest token accepted. A shorter one is treated as unset.
MIN_TOKEN_LENGTH = 32

#: The stop routes the token is accepted on: every one a stop client relays
#: stops or reads the stop lane on. Not the engines' poll, which has its own
#: token; and not the two account routes -- demoting or removing an operator is
#: an admin's own act, made with their own session, and a stolen service token
#: must not be able to remove every operator who could stop anything.
SERVICE_ROUTES = frozenset(STOP_ROUTES) - {"failsafe:pending", "accounts:user-set-role", "accounts:user-detail"}

#: A per-process key for the digests: it only makes the two sides one length,
#: so it never needs to be shared or kept.
_DIGEST_KEY = secrets.token_bytes(32)


def _digest(value):
    return hmac.new(_DIGEST_KEY, str(value).encode("utf-8", "surrogatepass"), hashlib.sha256).digest()


def configured_token():
    """The service token, or None when it is unset or too short to be safe."""
    token = getattr(settings, "FAILSAFE_SERVICE_TOKEN", None)
    if not isinstance(token, str) or len(token) < MIN_TOKEN_LENGTH:
        return None
    return token


def presented(request):
    """Whether ``request`` (a Django ``HttpRequest``) carries the header at all."""
    return _META in request.META


def token_matches(request):
    """Whether ``request`` carries the configured service token."""
    expected = configured_token()
    provided = request.META.get(_META)
    if expected is None or provided is None:
        return False
    return hmac.compare_digest(_digest(provided), _digest(expected))


def accepted(request):
    """Whether the service token authenticates ``request``: it is a stop on a
    service route, and the token matches. No database read."""
    if not presented(request):
        return False
    if view_name(request) not in SERVICE_ROUTES:
        return False
    if not is_stop(request):
        return False
    return token_matches(request)


class ServiceCredential:
    """``request.auth`` for a request the service token authenticated."""

    def __repr__(self):
        return "<failsafe service token>"


class FailsafeServiceTokenAuthentication(BaseAuthentication):
    """DRF authentication by the failsafe service token, on stops only.

    Returns None -- the next authentication class decides -- for a request the
    token is not accepted on, including one whose token does not match. First
    in DEFAULT_AUTHENTICATION_CLASSES."""

    def authenticate(self, request):
        django_request = getattr(request, "_request", request)
        if not accepted(django_request):
            return None
        username = getattr(settings, "FAILSAFE_SERVICE_USER", None)
        if not username:
            logger.error("FAILSAFE_SERVICE_TOKEN is set but FAILSAFE_SERVICE_USER is not; the token is ignored")
            return None
        from django.contrib.auth import get_user_model

        User = get_user_model()
        try:
            user = User._default_manager.filter(**{User.USERNAME_FIELD: username}, is_active=True).first()
        except Exception:  # noqa: BLE001 - a failed read authenticates nobody; the next class decides
            logger.exception("the failsafe service account could not be read")
            return None
        if user is None:
            logger.error("FAILSAFE_SERVICE_USER %r is not an active account; the service token is ignored", username)
            return None
        return user, ServiceCredential()

    def authenticate_header(self, request):
        # The first class's header is the one DRF sends with a 401. Without it a
        # request that authenticates no way at all would be answered 403, and a
        # client that signs in again on 401 would never do so.
        from rest_framework_simplejwt.authentication import JWTAuthentication

        return JWTAuthentication().authenticate_header(request)
