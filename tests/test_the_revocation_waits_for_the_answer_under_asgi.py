"""A withdrawal's revocation waits for the answer under ASGI too (AB-ASGI-DEFER).

AB-GRANT-LEASE signs a revocation when an operator's role is withdrawn -- a demotion,
a removal, a deactivation -- and signs it AFTER the stop is answered
(:func:`assurance.identity_emitter.after_the_answer`): the work is noted while the
request is served (``request_started``) and run once its response is closed
(``request_finished``). Its tests drive Django's WSGI handler. Under ASGI
(``config.asgi``: Django's ``ASGIHandler``, as uvicorn or daphne serves it) a request
is served on an event loop, the signals and the view in a worker thread of the
request's own, and "after the answer" could have meant before the response is sent,
a stalled loop, or never.

Each stop here is served through ``config.asgi.application`` as an ASGI server calls
it, and:

1. every stop's response is sent -- its last body message -- before any identity work
   starts, and none of that work runs on the event loop's thread;
2. a withdrawal's revocation is still signed once it is answered, so a later effect
   reads ``delegation_revoked``; also when the client went away before the answer
   (as under WSGI, where the view runs to its end and the response is closed); and a
   revocation that cannot be signed changes nothing answered and extends no lease;
3. while one withdrawal's revocation is slow (a signer that takes 2 s), a stop made on
   the same loop is answered within the stop suite's bound, and the loop never stalls.
"""

from __future__ import annotations

import asyncio
import contextvars
import json
import threading
import time
from unittest import mock

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from assurance import identity_evidence
from tests.test_a_demoted_operators_grant_stops_proving import (
    PASSWORD,
    STOPS,
    _active_role_records,
    _codes,
    _hop,
    _now,
    _promoted,
    _revocations,
    _role_hop,
)
from tests.test_no_control_holds_back_a_stop import STOP_LATENCY_BOUND
from tests.test_spine_authority_chain import _base
from tests.test_the_backend_sign_in_emits_signed_identity_records import (  # noqa: F401 - the fixture
    emitter,
)

# The handler serves each request in a worker thread of its own, on a database
# connection of that thread's: what it writes is committed, and read back here.
pytestmark = [pytest.mark.django_db(transaction=True), pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()

WITHDRAWALS = ("demote", "remove", "deactivate_on_remove")
#: How long the slow signer takes: far longer than any stop's bound.
SLOW_SIGNER_SECONDS = 2.0

#: Every entry to the identity code (as AB-GRANT-LEASE's stop test watches them).
IDENTITY_ENTRIES = {
    "identity_emitter": (
        "emit_revocations", "emit_role_grant", "emit_sign_in", "reconcile", "_emit_documents", "sign",
        "signing_key", "live_leases", "held_grant",
    ),
    "identity_evidence": ("in_force", "ingest", "records_for"),
}


def _asgi_module():
    """config.asgi, imported without configuring Django again."""
    import django

    with mock.patch.object(django, "setup"):
        from config import asgi
    return asgi


class _Asgi:
    """Serves requests through ``config.asgi.application`` as an ASGI server does --
    one ``http`` scope, the body in one message, the client still connected until it
    is answered -- with a Django ``ASGIHandler`` of its own behind it, built under the
    settings in force in the test (as the stop suite's ``_WsgiHandler`` does for
    ``config.wsgi``): whatever the entry point puts in front of Django is in front of
    every request. The owed-dispatch sweeper it starts on a first request is not
    started here (the dispatch suite tests that)."""

    def __init__(self, monkeypatch):
        from django.core.handlers.asgi import ASGIHandler

        from assurance import dispatch

        asgi = _asgi_module()
        self.entered = []
        monkeypatch.setattr(dispatch, "ensure_owed_sweeper", lambda: self.entered.append(1))
        monkeypatch.setattr(asgi, "_application", ASGIHandler())
        self.application = asgi.application

    async def request(self, method, path, *, token=None, body=None, events=None, gone=None):
        """Serve one request. What it answers: ``status`` (None: nothing was sent),
        ``took`` (seconds to its last body message: the answer), and ``done`` (seconds
        until the handler returned, after the work it ran once the answer was given).
        ``events`` gets ``("answered", thread)`` when the last body message is sent.
        ``gone``, an :class:`asyncio.Event`: once it is set the client disconnects."""
        payload = json.dumps(body).encode() if body is not None else b""
        headers = [(b"host", b"testserver")]
        if body is not None:
            headers += [(b"content-type", b"application/json"), (b"content-length", str(len(payload)).encode())]
        if token is not None:
            headers.append((b"authorization", f"Bearer {token}".encode()))
        scope = {
            "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
            "method": method, "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
            "root_path": "", "headers": headers, "client": ("127.0.0.1", 50000), "server": ("testserver", 80),
        }
        delivered = False

        async def receive():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": payload, "more_body": False}
            # Still connected: the handler stops listening once it has answered.
            await (gone or asyncio.Event()).wait()
            return {"type": "http.disconnect"}

        answer = {"status": None, "body": b"", "took": None}
        began = time.monotonic()

        async def send(message):
            if message["type"] == "http.response.start":
                answer["status"] = message["status"]
            elif message["type"] == "http.response.body":
                answer["body"] += message.get("body", b"")
                if not message.get("more_body", False):
                    answer["took"] = time.monotonic() - began
                    if events is not None:
                        events.append(("answered", threading.get_ident()))

        await self.application(scope, receive, send)
        answer["done"] = time.monotonic() - began
        return answer


def _token(user):
    from rest_framework_simplejwt.tokens import AccessToken

    return str(AccessToken.for_user(user))


def _watch(monkeypatch, events):
    """Each entry to the identity code notes ``(its name, the thread it ran on)``."""
    from assurance import identity_emitter

    modules = {"identity_emitter": identity_emitter, "identity_evidence": identity_evidence}
    for module_name, names in IDENTITY_ENTRIES.items():
        module = modules[module_name]
        for name in names:
            real = getattr(module, name)

            def watched(*args, _real=real, _name=name, **kwargs):
                events.append((_name, threading.get_ident()))
                return _real(*args, **kwargs)

            monkeypatch.setattr(module, name, watched)


def _stop(kind, dep, granter, agent, refresh):
    """The stop ``kind`` (AB-GRANT-LEASE's ``STOPS``) as an ASGI request: method, path,
    token, body, and the statuses it is served with."""
    if kind == "demote":
        return ("PATCH", f"/api/accounts/users/{agent.pk}/set_role/", _token(granter), {"role": "viewer"}), (200,)
    if kind in ("remove", "deactivate_on_remove"):
        return ("DELETE", f"/api/accounts/users/{agent.pk}/", _token(granter), None), (200, 204)
    if kind == "token_revoke":
        return ("POST", "/api/token/revoke/", None, {"refresh": refresh}), (200, 204, 205)
    return ("POST", _base(dep) + "recompute/", _token(dep.owner), {"paused": True}), (200,)


def _protected(monkeypatch):
    """The removal refused by a protected reference: the account is deactivated."""
    from django.db.models import ProtectedError

    from accounts import views as account_views

    def protected(self, instance):
        raise ProtectedError("a decision they made", set())

    monkeypatch.setattr(account_views.UserViewSet, "perform_destroy", protected)


def _run(coroutine):
    """Run ``coroutine`` on an event loop of its own, in a context of its own: an ASGI
    server's loop starts with nothing set in it, whereas this test's thread has served
    the test client's requests, whose ``request_started`` and ``request_finished`` ran
    here -- a loop that inherited what they set would be served under it."""
    return contextvars.Context().run(asyncio.run, coroutine)


def _serve(server, request, **kwargs):
    """Serve one request on a loop of its own; the loop's thread with what it answered."""

    async def serve():
        method, path, token, body = request
        return threading.get_ident(), await server.request(method, path, token=token, body=body, **kwargs)

    return _run(serve())


# ------------------------------------------------- 1. answered before any identity work


@pytest.mark.parametrize("kind", STOPS)
def test_every_stop_is_answered_before_any_identity_work_runs_under_asgi(
    emitter, django_capture_on_commit_callbacks, monkeypatch, kind  # noqa: F811
):
    dep, _client, _permit, granter, agent, _admin = _promoted(django_capture_on_commit_callbacks)
    if kind == "deactivate_on_remove":
        _protected(monkeypatch)
    refresh = None
    if kind == "token_revoke":
        refresh = APIClient().post(
            "/api/token/", {"username": agent.username, "password": PASSWORD}, format="json"
        ).json()["refresh"]
    request, statuses = _stop(kind, dep, granter, agent, refresh)
    server = _Asgi(monkeypatch)
    events = []
    _watch(monkeypatch, events)

    loop_thread, answer = _serve(server, request, events=events)

    assert answer["status"] in statuses, answer
    assert server.entered, "the request was not served through config.asgi.application"
    names = [name for name, _thread in events]
    if kind in WITHDRAWALS:
        assert names[0] == "answered", names
        assert "emit_revocations" in names and "sign" in names, names
        assert _revocations(), "the withdrawal was answered but its revocation never signed"
    else:
        assert names == ["answered"], names
    on_the_loop = [name for name, thread in events if name != "answered" and thread == loop_thread]
    assert on_the_loop == [], f"identity work ran on the event loop's thread: {on_the_loop}"


# ------------------------------------------------- 2. and still signed after the answer


@pytest.mark.parametrize("kind", WITHDRAWALS)
def test_a_withdrawal_answered_under_asgi_reads_revoked_for_a_later_effect(
    emitter, django_capture_on_commit_callbacks, monkeypatch, kind  # noqa: F811
):
    dep, client, permit, granter, agent, _admin = _promoted(django_capture_on_commit_callbacks)
    if kind == "deactivate_on_remove":
        _protected(monkeypatch)
    before = _role_hop(client, dep, permit, granter, agent.username, "analyst", _now())
    assert _hop(client, dep, before)["verdict"] == "proven"
    request, statuses = _stop(kind, dep, granter, agent, None)
    server = _Asgi(monkeypatch)

    _loop, answer = _serve(server, request)

    assert answer["status"] in statuses, answer
    assert server.entered
    after = _role_hop(client, dep, permit, granter, agent.username, "analyst", _now())
    hop = _hop(client, dep, after)
    assert hop["verdict"] == "unproven", f"the {kind} operator's old grant still proves a later effect: {hop}"
    assert _codes(hop) == ["delegation_revoked"]
    assert _hop(client, dep, before)["verdict"] == "proven"


def test_a_withdrawal_whose_client_went_away_before_the_answer_is_still_revoked(
    emitter, django_capture_on_commit_callbacks, monkeypatch  # noqa: F811
):
    """The client disconnects while the demotion's view is still running: the handler
    cancels the response, but the view runs to its end in its thread and the
    demotion stands -- as under WSGI, where the response is still closed -- so its
    revocation is signed, after the view, never dropped."""
    from accounts import views as account_views

    dep, _client, _permit, granter, agent, _admin = _promoted(django_capture_on_commit_callbacks)
    started, release = threading.Event(), threading.Event()
    real = account_views.UserViewSet.set_role

    def held_open(self, *args, **kwargs):
        started.set()
        assert release.wait(30), "the test never let the view go on"
        return real(self, *args, **kwargs)

    monkeypatch.setattr(account_views.UserViewSet, "set_role", held_open)
    server = _Asgi(monkeypatch)
    (method, path, token, body), _statuses = _stop("demote", dep, granter, agent, None)

    async def serve():
        gone = asyncio.Event()
        served = asyncio.create_task(server.request(method, path, token=token, body=body, gone=gone))
        for _ in range(3000):
            if started.is_set():
                break
            await asyncio.sleep(0.01)
        assert started.is_set(), "the demotion's view never started"
        gone.set()
        await asyncio.sleep(0.2)  # the handler sees the client gone and cancels the response
        release.set()
        return await served

    answer = _run(serve())

    assert answer["status"] is None, f"the client was gone but a response was sent: {answer}"
    assert User.objects.get(pk=agent.pk).role == "viewer"
    assert _revocations(), "the client went away and the withdrawal's revocation was never signed"


def test_a_revocation_that_cannot_be_signed_under_asgi_changes_no_answer_and_extends_nothing(
    emitter, django_capture_on_commit_callbacks, monkeypatch, caplog  # noqa: F811
):
    """The signer fails after the answer: the demotion is answered and stands, the
    failure is logged, and nothing is extended -- the grant's one record keeps the
    lease it had, so it lapses to ``delegation_expired`` where it always would (the
    reconcile tests of AB-GRANT-LEASE)."""
    from assurance import identity_emitter

    dep, _client, _permit, granter, agent, _admin = _promoted(django_capture_on_commit_callbacks)
    leases = [(row.pk, row.document["grant"]["not_after"]) for row in _active_role_records()]
    assert len(leases) == 1

    def raises(*args, **kwargs):
        raise RuntimeError("the signer failed")

    monkeypatch.setattr(identity_emitter, "sign", raises)
    request, statuses = _stop("demote", dep, granter, agent, None)

    _loop, answer = _serve(_Asgi(monkeypatch), request)

    assert answer["status"] in statuses, answer
    assert User.objects.get(pk=agent.pk).role == "viewer"
    assert not _revocations()
    assert [(row.pk, row.document["grant"]["not_after"]) for row in _active_role_records()] == leases
    assert "was not emitted" in caplog.text


# ------------------------------------- 3. a slow revocation never holds back a stop


def test_a_stop_on_the_same_loop_is_answered_within_its_bound_while_a_revocation_is_slow(
    emitter, django_capture_on_commit_callbacks, monkeypatch  # noqa: F811
):
    """One loop serves a demotion whose revocation takes 2 s to sign, and, once that
    signer is at work, a pause. The pause is answered within the stop suite's bound
    while the signer is still at work; the demotion itself was answered long before
    its signer finished; the loop never stalled (a heartbeat on it); and the
    revocation was signed in the end."""
    from assurance import identity_emitter

    dep, _client, _permit, granter, agent, _admin = _promoted(django_capture_on_commit_callbacks)
    server = _Asgi(monkeypatch)
    signing, signed = threading.Event(), threading.Event()
    real_sign = identity_emitter.sign

    def slow_sign(*args, **kwargs):
        signing.set()
        try:
            time.sleep(SLOW_SIGNER_SECONDS)
            return real_sign(*args, **kwargs)
        finally:
            signed.set()

    monkeypatch.setattr(identity_emitter, "sign", slow_sign)
    (d_method, d_path, d_token, d_body), _statuses = _stop("demote", dep, granter, agent, None)
    (p_method, p_path, p_token, p_body), _statuses = _stop("pause", dep, granter, agent, None)

    async def serve():
        # The first request through a new handler loads its middleware and the URLconf.
        warm = await server.request("GET", f"/api/accounts/users/{agent.pk}/", token=_token(granter))
        assert warm["status"] == 200, warm
        gaps, beating = [], [True]

        async def heartbeat():
            last = time.monotonic()
            while beating[0]:
                await asyncio.sleep(0.005)
                now = time.monotonic()
                gaps.append(now - last)
                last = now

        beat = asyncio.create_task(heartbeat())
        demotion = asyncio.create_task(server.request(d_method, d_path, token=d_token, body=d_body))
        for _ in range(3000):
            if signing.is_set():
                break
            await asyncio.sleep(0.01)
        assert signing.is_set(), "the demotion's revocation never began signing"
        made_during = not signed.is_set()
        pause = await server.request(p_method, p_path, token=p_token, body=p_body)
        answered_during = not signed.is_set()
        demoted = await demotion
        beating[0] = False
        await beat
        return demoted, pause, made_during, answered_during, max(gaps)

    demoted, pause, made_during, answered_during, stalled = _run(serve())

    assert demoted["status"] == 200 and pause["status"] == 200, (demoted, pause)
    # First: a loop stalled by the slow work could not even make the pause in time.
    assert stalled <= STOP_LATENCY_BOUND, f"the event loop stalled for {stalled:.3f}s while a revocation was signing"
    # Made while the revocation was still being signed, or this proved nothing.
    assert made_during, "the signer had finished before the pause was made"
    assert pause["took"] <= STOP_LATENCY_BOUND, (
        f"a pause made while a revocation was signing took {pause['took']:.3f}s (bound {STOP_LATENCY_BOUND}s)"
    )
    assert answered_during, "the pause was answered only once the revocation was signed"
    # The demotion -- a stop too -- was answered within the bound, before its slow
    # revocation, which its handler then ran.
    assert demoted["took"] <= STOP_LATENCY_BOUND, (
        f"a demotion whose revocation was slow took {demoted['took']:.3f}s to answer (bound {STOP_LATENCY_BOUND}s)"
    )
    assert SLOW_SIGNER_SECONDS <= demoted["done"], demoted
    assert _revocations(), "the slow revocation was never signed"
