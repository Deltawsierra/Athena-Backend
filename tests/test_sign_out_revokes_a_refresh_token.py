"""Sign-out revokes a refresh token for good (safety.revoke; T6).

The dashboard now signs each person in to this backend as themselves, instead of
reaching it for every read as one service account that sees every tenant, and it
holds each person's refresh token on its own server. When the person's session
ends it sends that token to ``/api/token/revoke/``. Until this route there was no
way to revoke one: a signed-out person's refresh token stayed good to its expiry.

Pinned here:

* a revoked refresh token renews nothing, and the revocation is recorded;
* revoking is never refused for a token that verifies: twice, after a refresh
  spent it, for a token never recorded as outstanding, or for an operator since
  removed -- and a stale bearer header beside it cannot refuse it;
* another session's refresh token is untouched;
* a token that does not verify (not one, an access token, an expired one) is
  refused 401 and nothing is written;
* the request the dashboard sends is a stop (it only takes access away), so
  neither the gateway nor a throttle can hold it back; one that does not verify,
  or carries anything beside the token, is not, and stays limited. (Driven
  through the whole stack with every limit saturated in
  test_no_control_holds_back_a_stop.py, EVERY_STOP "sign out".)
"""

from __future__ import annotations

import json
from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.test import RequestFactory
from rest_framework.test import APIClient
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
from rest_framework_simplejwt.tokens import AccessToken, RefreshToken

from safety import stops

User = get_user_model()
REVOKE = "/api/token/revoke/"
REFRESH = "/api/token/refresh/"

_n = [0]


def _user(role="viewer"):
    _n[0] += 1
    return User.objects.create_user(username=f"t6-sign-out-{_n[0]}", password="x", role=role)


def _jti(token):
    return RefreshToken(token, verify=False).payload["jti"]


def _revoke(token, client=None):
    return (client or APIClient()).post(REVOKE, {"refresh": token}, format="json")


@pytest.mark.django_db
def test_a_revoked_refresh_token_renews_nothing():
    token = str(RefreshToken.for_user(_user()))
    answer = _revoke(token)
    assert answer.status_code == 200
    assert answer.json() == {"revoked": True}
    assert BlacklistedToken.objects.filter(token__jti=_jti(token)).count() == 1
    refused = APIClient().post(REFRESH, {"refresh": token}, format="json")
    assert refused.status_code == 401
    assert "access" not in refused.json()


@pytest.mark.django_db
def test_revoking_is_never_refused_for_a_token_that_verifies():
    user = _user()
    token = str(RefreshToken.for_user(user))
    # Twice: the same answer, and one revocation.
    assert _revoke(token).status_code == 200
    assert _revoke(token).status_code == 200
    assert BlacklistedToken.objects.filter(token__jti=_jti(token)).count() == 1

    # After a refresh spent it (the dashboard signing out mid-renewal): revoked
    # without refusal, and the rotated token is revoked by its own sign-out.
    spent = str(RefreshToken.for_user(user))
    rotated = APIClient().post(REFRESH, {"refresh": spent}, format="json").json()["refresh"]
    assert _revoke(spent).status_code == 200
    assert _revoke(rotated).status_code == 200
    assert APIClient().post(REFRESH, {"refresh": rotated}, format="json").status_code == 401

    # A token never recorded as outstanding: recorded, and revoked.
    unrecorded = str(RefreshToken.for_user(user))
    OutstandingToken.objects.filter(jti=_jti(unrecorded)).delete()
    assert _revoke(unrecorded).status_code == 200
    assert BlacklistedToken.objects.filter(token__jti=_jti(unrecorded)).exists()

    # A stale bearer header beside it cannot refuse it: the route authenticates nothing else.
    stale = APIClient()
    stale.credentials(HTTP_AUTHORIZATION="Bearer header.payload.signature")
    beside = str(RefreshToken.for_user(user))
    assert _revoke(beside, stale).status_code == 200
    assert BlacklistedToken.objects.filter(token__jti=_jti(beside)).exists()


@pytest.mark.django_db
def test_a_removed_operators_token_is_revoked_too():
    user = _user()
    token = str(RefreshToken.for_user(user))
    user.delete()
    assert _revoke(token).status_code == 200
    assert BlacklistedToken.objects.filter(token__jti=_jti(token)).exists()


@pytest.mark.django_db
def test_another_sessions_refresh_token_is_untouched():
    user = _user()
    signed_out = str(RefreshToken.for_user(user))
    other = str(RefreshToken.for_user(user))
    assert _revoke(signed_out).status_code == 200
    renewed = APIClient().post(REFRESH, {"refresh": other}, format="json")
    assert renewed.status_code == 200
    assert renewed.json()["access"]


@pytest.mark.django_db
def test_a_token_that_does_not_verify_is_refused_and_nothing_is_written():
    user = _user()
    expired = RefreshToken.for_user(user)
    expired.set_exp(lifetime=timedelta(seconds=-1))
    before = (OutstandingToken.objects.count(), BlacklistedToken.objects.count())
    for refresh in ("not-a-token", "x.y.z", str(AccessToken.for_user(user)), str(expired)):
        answer = _revoke(refresh)
        assert answer.status_code == 401, refresh
        assert "revoked" not in answer.json()
    assert APIClient().post(REVOKE, {}, format="json").status_code == 400
    assert (OutstandingToken.objects.count(), BlacklistedToken.objects.count()) == before


def _as_the_dashboard_sends_it(body):
    """athena-dashboard server/person-credential.ts: POST, Content-Type and Accept
    application/json, JSON.stringify of the body (compact), no bearer."""
    return RequestFactory().generic(
        "POST", REVOKE, data=json.dumps(body, separators=(",", ":")).encode(),
        content_type="application/json", HTTP_ACCEPT="application/json",
    )


@pytest.mark.django_db
def test_the_dashboards_sign_out_is_a_stop_and_nothing_wider_is():
    token = str(RefreshToken.for_user(_user()))
    assert stops.view_name(_as_the_dashboard_sends_it({"refresh": token})) == "token_revoke"
    assert stops.is_stop(_as_the_dashboard_sends_it({"refresh": token}))
    # Not a token that verifies, or anything beside it: not a stop, so still limited.
    for body in ({"refresh": "x.y.z"}, {"refresh": token, "everywhere": True}, {"refresh": [token]}, {}):
        assert not stops.is_stop(_as_the_dashboard_sends_it(body)), body
    assert "token_revoke" in stops.STOP_ROUTES
