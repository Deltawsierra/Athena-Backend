"""Signing out: a refresh token revoked, for good, at once.

The dashboard used to reach this backend for every read as ONE service account,
which sees every tenant (T6). It now signs each person in as themselves and holds
their refresh token on its own server, never in a browser. When that person's
session ends -- they sign out, sign in again, or an admin deactivates or removes
their dashboard account -- the dashboard sends the refresh token here and it is
spent: blacklisted, so no refresh can mint another access token from it. Until
now there was no such route, and a signed-out person's refresh token stayed
good until it expired.

What it does: the token is verified (signature, expiry, type and jti, as
:func:`safety.stops._verified_refresh` reads it -- not the blacklist), then its
outstanding row is found or made and blacklisted. Revoking a token already spent
or revoked is the same answer and writes nothing new, so a sign-out sent twice,
or after a refresh spent the token, is never refused. A token that does not
verify is answered 401 ``token_not_valid`` and nothing is written.

Who may: whoever holds the token. The route authenticates nothing else -- a
stale bearer header cannot refuse it -- and the token is the credential: holding
it already lets its holder refresh it, and revoking it only takes access away.
The access token it was issued with lives on to its own expiry (SimpleJWT access
tokens are not looked up); the dashboard forgets it at once.

SAFETY: a revocation only takes access away, so it is a stop
(``safety.stops.STOP_ROUTES``, ``token_revoke``): for a token that verifies it is
exempt from the gateway and the throttles, like every other revoke, and nothing
on its path waits on anything but the token's own two rows. Nothing it does sits
on another stop's path.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.db import transaction
from rest_framework import serializers
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.utils import datetime_from_epoch
from rest_framework_simplejwt.views import TokenViewBase


def revoke(refresh):
    """Blacklist the verified refresh token ``refresh``: its outstanding row is
    found or made, and blacklisted unless it already is. Idempotent."""
    payload = refresh.payload
    jti = payload[api_settings.JTI_CLAIM]
    user_id = payload.get(api_settings.USER_ID_CLAIM)
    user = None
    if user_id is not None:
        user = get_user_model()._default_manager.filter(**{api_settings.USER_ID_FIELD: user_id}).first()
    with transaction.atomic():
        outstanding, _created = OutstandingToken.objects.get_or_create(
            jti=jti,
            defaults={
                "user": user,
                "created_at": refresh.current_time,
                "token": str(refresh),
                "expires_at": datetime_from_epoch(payload["exp"]),
            },
        )
        BlacklistedToken.objects.get_or_create(token=outstanding)


class RevokeSerializer(serializers.Serializer):
    refresh = serializers.CharField()

    def validate(self, attrs):
        from .stops import _verified_refresh

        refresh = _verified_refresh(attrs["refresh"])
        if refresh is None:
            raise InvalidToken("the refresh token does not verify: nothing was revoked")
        revoke(refresh)
        return {"revoked": True}


class RevokeView(TokenViewBase):
    """``/api/token/revoke/``: sign-out, the refresh token sent revoked for good.
    Its throttles are the project's defaults, unchanged; a token that verifies is
    exempt from them and from the gateway (safety.stops)."""

    serializer_class = RevokeSerializer
