"""The token refresh, which spends its refresh token exactly once.

``token_blacklist`` makes a refresh spend the token it is given, but SimpleJWT
checks the blacklist and then writes to it (a ``get_or_create``): two refreshes
of one token that overlap both pass the check, and both are answered with a new
token. Measured on round 3: 8 simultaneous refreshes of one token forked it
into 8 live chains, or answered some with 401 and signed that tab out. A thief
racing the owner's refresh kept a chain of their own, every link of it exempt
from the gateway as a valid refresh (safety.stops).

Here the spend is one conditional insert: the blacklist row for the token's
jti, whose uniqueness the database enforces (``BlacklistedToken.token`` is a
one-to-one). Exactly one refresh inserts it and is answered with a new token;
every other one, however close behind -- or long after -- is answered 401
"refresh token already used" and issued nothing. Nothing is issued before the
insert succeeds.

The account must exist and be active, as on the refresh's exemption: a removed
operator's token was answered 500 (``DoesNotExist``) and a deactivated one's
401, both past the gateway. Both are 401 now, and neither is exempt.
"""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from rest_framework import exceptions
from rest_framework_simplejwt.exceptions import DetailDictMixin
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.settings import api_settings
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.utils import datetime_from_epoch
from rest_framework_simplejwt.views import TokenRefreshView


class RefreshTokenAlreadyUsed(DetailDictMixin, exceptions.AuthenticationFailed):
    """Answered with its code, as SimpleJWT's own token errors are, so a client
    can tell "another refresh of this token got the new one" -- another tab,
    whose token is on its way to storage -- from a token that is simply bad
    (frontend/src/lib/refresh-token.ts)."""

    default_detail = "refresh token already used"
    default_code = "refresh_token_already_used"


def spend(refresh, user):
    """Blacklist ``refresh`` for good, or raise :class:`RefreshTokenAlreadyUsed`
    when another refresh has already done so -- including one that is still
    running beside this one. The database decides, not a read before it."""
    jti = refresh.payload[api_settings.JTI_CLAIM]
    with transaction.atomic():
        outstanding, _created = OutstandingToken.objects.get_or_create(
            jti=jti,
            defaults={
                "user": user,
                "created_at": refresh.current_time,
                "token": str(refresh),
                "expires_at": datetime_from_epoch(refresh.payload["exp"]),
            },
        )
        try:
            with transaction.atomic():
                BlacklistedToken.objects.create(token=outstanding)
        except IntegrityError:
            raise RefreshTokenAlreadyUsed() from None


class RefreshSerializer(TokenRefreshSerializer):
    def validate(self, attrs):
        # Signature, expiry, type and jti. A token already on the blacklist is
        # refused here without a write; one spent by a refresh still running
        # beside this one is refused by spend(). Either way the answer is the same.
        from .stops import _verified_refresh

        refresh = _verified_refresh(attrs["refresh"])
        if refresh is None:
            # SimpleJWT's own reading, for its own message.
            refresh = self.token_class(attrs["refresh"])
        jti = refresh.payload[api_settings.JTI_CLAIM]
        if BlacklistedToken.objects.filter(token__jti=jti).exists():
            raise RefreshTokenAlreadyUsed()
        user_id = refresh.payload.get(api_settings.USER_ID_CLAIM)
        user = None
        if user_id is not None:
            user = get_user_model()._default_manager.filter(**{api_settings.USER_ID_FIELD: user_id}).first()
        if user is None or not api_settings.USER_AUTHENTICATION_RULE(user):
            raise exceptions.AuthenticationFailed(self.error_messages["no_active_account"], "no_active_account")

        spend(refresh, user)

        data = {"access": str(refresh.access_token)}
        refresh.set_jti()
        refresh.set_exp()
        refresh.set_iat()
        refresh.outstand()
        data["refresh"] = str(refresh)
        return data


class RefreshView(TokenRefreshView):
    """``/api/token/refresh/``: SimpleJWT's refresh, spending its token once.
    Its throttles and authentication are SimpleJWT's and the project's
    defaults, unchanged; a valid refresh is exempt from them (safety.stops)."""

    serializer_class = RefreshSerializer
