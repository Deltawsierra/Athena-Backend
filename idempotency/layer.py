"""Idempotency keys for the routes that start something outside this backend.

A client that sends a request again -- its answer was lost, or it stopped waiting --
must not scan a customer's system twice, send a report twice or file a second ticket
in a customer's tracker. On the routes this layer is on (:data:`ROUTES`: the two scan
launches, a report resent, a finding pushed to a tracker by hand) the client can say
it is sending the same request again: it sends an ``Idempotency-Key`` header. The
first request with a key, for that account and route, is recorded with a digest of
the request (route, method, the URL's own arguments, query and body) and the answer
it got. The same key again:

- with the same request, answered: that answer, replayed, marked
  ``Idempotent-Replayed: true``. Nothing is started.
- with the same request, not answered: 409, saying its outcome is unknown -- it is
  still running, or it raised, or its process died before it recorded an answer.
  Nothing is started. An outcome this backend did not observe is never recorded as
  done, and never as failed.
- with a different request: 422. Nothing is done.

A key that is not 1 to 255 printable ASCII characters is refused, 400, and nothing is
done. WITHOUT A KEY THE ROUTE IS UNCHANGED: a request sent again runs again.

Authentication and the route's permissions run before this layer on every request, a
replay included: an account removed or demoted since the first attempt is refused
before any record is read. A replay starts nothing -- it is given what the first
attempt was answered, under the authority that held then (an engagement withdrawn
since does not re-run it; a new request is judged afresh). A request whose key has
been forgotten runs the route afresh, every check included.

Bounded: a key is kept ``IDEMPOTENCY_KEY_TTL_SECONDS`` (default 24 h) and then
forgotten; an account keeps at most ``IDEMPOTENCY_KEYS_PER_ACCOUNT`` (default 1,000),
its oldest forgotten first; an answer is kept whole up to
``IDEMPOTENCY_MAX_RESPONSE_BYTES`` (default 1 MiB), and one larger is replayed as its
status and its top-level scalar fields. A forgotten key is a new request.

NEVER ON A STOP (safety.stops; the SAFETY RULE). :func:`idempotent` refuses, at
import, a route that is a stop or what an operator needs to make one; and a request
that resolves to such a route passes straight through, its key unread and nothing
recorded. A stop sent again is always processed, never answered from a record, and
never waits on this table.
"""

from __future__ import annotations

import functools
import hashlib
import json
import logging
from datetime import timedelta

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, PermissionDenied
from django.db import DatabaseError, IntegrityError, transaction
from django.http import Http404, QueryDict
from django.utils import timezone
from rest_framework import exceptions
from rest_framework.request import Request
from rest_framework.response import Response
from rest_framework.utils.encoders import JSONEncoder

from .models import IdempotencyRecord

logger = logging.getLogger(__name__)

HEADER = "Idempotency-Key"
_META = "HTTP_IDEMPOTENCY_KEY"
#: Set on an answer that is a replay of the one recorded.
REPLAYED = "Idempotent-Replayed"
MAX_KEY_LENGTH = 255

#: The bounds, as ``setting: default``: how long a key is kept (seconds), how many an
#: account keeps, and the largest answer kept whole (bytes).
BOUNDS = {
    "IDEMPOTENCY_KEY_TTL_SECONDS": 24 * 60 * 60,
    "IDEMPOTENCY_KEYS_PER_ACCOUNT": 1000,
    "IDEMPOTENCY_MAX_RESPONSE_BYTES": 1024 * 1024,
}
#: At most this many keys are forgotten per keyed request, of each kind (an account's
#: past its bound, anyone's expired).
_FORGET_BATCH = 100
#: The routes this layer is on, by URL name (filled by :func:`idempotent`).
ROUTES: set[str] = set()

_DIGEST_DOMAIN = "athena.idempotency/1"
_State = IdempotencyRecord.State
_reported: set = set()


def bound(name: str) -> int:
    """The bound ``name`` (one of :data:`BOUNDS`) as configured, or its default when
    the setting is not a positive whole number (said once, at ERROR)."""
    default = BOUNDS[name]
    raw = getattr(settings, name, default)
    try:
        value = int(raw) if not isinstance(raw, bool) else 0
    except (TypeError, ValueError):
        value = 0
    if value >= 1:
        return value
    if (name, repr(raw)) not in _reported:
        _reported.add((name, repr(raw)))
        logger.error("%s=%r is not a positive whole number; %s is used instead", name, raw, default)
    return default


def idempotent(route: str):
    """Put the key layer on the view that URL name ``route`` serves -- a function view
    (under ``@api_view`` and its permission classes) or a ViewSet action. A stop
    route, or what an operator needs to make a stop, is refused."""
    from safety.stops import EXEMPT_ROUTES

    if route in EXEMPT_ROUTES:
        raise ImproperlyConfigured(
            f"{route} is a stop route, or what an operator needs to make a stop (safety.stops): the "
            "idempotency layer is never put on one. A stop sent again is always processed."
        )
    ROUTES.add(route)

    def wrap(view):
        @functools.wraps(view)
        def keyed(*args, **kwargs):
            request = args[0] if isinstance(args[0], Request) else args[1]
            return answer(route, request, kwargs, lambda: view(*args, **kwargs))

        return keyed

    return wrap


def answer(route: str, request, target: dict, run):
    """What ``request`` on ``route`` is answered: ``run()``'s answer, recorded under its
    key -- or, for a key already recorded, the answer that says so (the module
    docstring). ``target``: the URL's own arguments."""
    if _on_a_stop_route(request):
        return run()
    raw = request.META.get(_META)
    user = getattr(request, "user", None)
    if raw is None or user is None or not user.is_authenticated:
        return run()
    key = raw.strip()
    if not (0 < len(key) <= MAX_KEY_LENGTH and all(" " <= char <= "~" for char in key)):
        return Response(
            {"detail": f"{HEADER} must be 1 to {MAX_KEY_LENGTH} printable ASCII characters. Nothing was done."},
            status=400,
        )
    record, instead = _claim(user, route, key, request_digest(route, request, target))
    if record is None:
        return instead
    try:
        response = run()
    except BaseException as exc:
        refusal = _refusal(exc)
        if refusal is None:
            # Raised before it answered: whether it started anything was not observed.
            _end(record, _State.UNKNOWN)
        else:
            _end(record, _State.DONE, *refusal)
        raise
    _end(record, _State.DONE, *_kept(response))
    return response


def _on_a_stop_route(request) -> bool:
    from safety.stops import EXEMPT_ROUTES, view_name

    try:
        return view_name(getattr(request, "_request", request)) in EXEMPT_ROUTES
    except Exception:  # noqa: BLE001 - a route that cannot be read is passed through untouched, as a stop is
        return True


class _Canonical(JSONEncoder):
    """DRF's encoder, and ``repr`` for anything it cannot write."""

    def default(self, obj):
        try:
            return super().default(obj)
        except TypeError:
            return repr(obj)


def request_digest(route: str, request, target: dict) -> str:
    """The request a key is bound to: the route, its method, the URL's own arguments
    (the scan or deployment it names), the query and the body -- parsed, so the same
    JSON written in another key order is the same request."""
    body = request.data
    if isinstance(body, QueryDict):
        body = {name: body.getlist(name) for name in body}
    query = {name: request.query_params.getlist(name) for name in request.query_params}
    canonical = json.dumps(
        [_DIGEST_DOMAIN, route, request.method, {name: str(value) for name, value in target.items()}, query, body],
        sort_keys=True,
        separators=(",", ":"),
        cls=_Canonical,
    )
    return hashlib.sha256(canonical.encode()).hexdigest()


def _claim(user, route: str, key: str, digest: str):
    """``(record, None)``: this request is the first with its key, recorded IN_FLIGHT
    before the route runs. ``(None, answer)``: it is not, and ``answer`` is what it is
    given instead of running the route."""
    now = timezone.now()
    mine = IdempotencyRecord.objects.filter(user_id=user.pk, route=route, key=key)
    mine.filter(expires_at__lte=now).delete()  # forgotten: the key is a new request again
    try:
        with transaction.atomic():
            record = IdempotencyRecord.objects.create(
                user_id=user.pk,
                route=route,
                key=key,
                request_digest=digest,
                state=_State.IN_FLIGHT,
                created_at=now,
                expires_at=now + timedelta(seconds=bound("IDEMPOTENCY_KEY_TTL_SECONDS")),
            )
    except IntegrityError:
        return None, _given_instead(mine.first(), digest)
    _forget_past_bounds(user.pk, now)
    return record, None


def _forget_past_bounds(user_id, now) -> None:
    """Keep the store bounded: this account's keys past its bound, oldest first, and
    expired keys of any account -- at most :data:`_FORGET_BATCH` of each per request."""
    keep = bound("IDEMPOTENCY_KEYS_PER_ACCOUNT")
    try:
        over = list(
            IdempotencyRecord.objects.filter(user_id=user_id)
            .order_by("-created_at", "-pk")
            .values_list("pk", flat=True)[keep: keep + _FORGET_BATCH]
        )
        expired = list(
            IdempotencyRecord.objects.filter(expires_at__lte=now)
            .order_by("expires_at")
            .values_list("pk", flat=True)[:_FORGET_BATCH]
        )
        if over or expired:
            IdempotencyRecord.objects.filter(pk__in=[*over, *expired]).delete()
    except DatabaseError:
        logger.exception("could not forget idempotency keys past their bounds; the next keyed request tries again")


def _said(record) -> dict:
    if record is None:
        return {}
    return {"state": record.state, "since": record.created_at.isoformat()}


def _given_instead(earlier, digest: str) -> Response:
    """The answer to a request whose key is already recorded (``earlier``; ``None``
    when it was forgotten between the two reads -- another request holds it now)."""
    if earlier is not None and earlier.request_digest != digest:
        return Response(
            {
                "detail": (
                    "This Idempotency-Key was already used on this route for a different request (another "
                    "body, query or target). Nothing was done: send a new request with a new key."
                ),
                "idempotency": _said(earlier),
            },
            status=422,
        )
    if earlier is not None and earlier.state == _State.DONE:
        replay = Response(
            json.loads(earlier.response_body) if earlier.response_body else None, status=earlier.response_status
        )
        replay[REPLAYED] = "true"
        return replay
    if earlier is not None and earlier.state == _State.UNKNOWN:
        detail = (
            "The first request with this Idempotency-Key raised before it recorded an answer, so whether it "
            "started anything is unknown. Nothing was started by this one. Find out what the first did before "
            "sending the work again, with a new key."
        )
    else:
        detail = (
            "The first request with this Idempotency-Key has not recorded an answer: it is still running, or it "
            "stopped before it could, so its outcome is unknown. Nothing was started by this one; send the same "
            "request with this key later to read its answer."
        )
    return Response({"detail": detail, "idempotency": _said(earlier)}, status=409)


def _refusal(exc):
    """``(status, kept body)`` for an exception the route raised as its answer -- a
    refusal DRF renders (400, 403, 404 ...) -- or ``None`` for any other, whose outcome
    this backend did not observe."""
    if isinstance(exc, Http404):
        exc = exceptions.NotFound()
    elif isinstance(exc, PermissionDenied):
        exc = exceptions.PermissionDenied()
    if not isinstance(exc, exceptions.APIException):
        return None
    body = exc.detail if isinstance(exc.detail, (list, dict)) else {"detail": exc.detail}
    return _kept(Response(body, status=exc.status_code))


def _kept(response):
    """``(status, body)`` as recorded for a replay: the answer whole, or -- past the size
    bound, or when it is not JSON -- its status and its top-level scalar fields."""
    status = response.status_code
    if not hasattr(response, "data"):
        return status, json.dumps(_summary(status, None, "it is not a JSON answer"))
    data = response.data
    try:
        text = json.dumps(data, cls=JSONEncoder)
    except (TypeError, ValueError):
        return status, json.dumps(_summary(status, None, "it could not be kept"))
    limit = bound("IDEMPOTENCY_MAX_RESPONSE_BYTES")
    if len(text.encode()) > limit:
        return status, json.dumps(_summary(status, data, f"it is larger than the {limit} bytes kept"), cls=_Canonical)
    return status, text


def _summary(status: int, data, why: str) -> dict:
    kept = {}
    if isinstance(data, dict):
        kept = {
            name: value
            for name, value in data.items()
            if isinstance(name, str)
            and (value is None or isinstance(value, (bool, int, float)) or (isinstance(value, str) and len(value) <= 1000))
        }
    kept["idempotency"] = {
        "state": _State.DONE,
        "note": (
            f"The first request with this Idempotency-Key was answered {status}; its answer is not replayed "
            f"whole because {why}. Nothing was started by this request."
        ),
    }
    return kept


def _end(record, state: str, status: int | None = None, body: str = "") -> None:
    """Record how the request ended. A record that cannot be written stays IN_FLIGHT --
    read as unknown until it expires, never as done or failed."""
    try:
        IdempotencyRecord.objects.filter(pk=record.pk, state=_State.IN_FLIGHT).update(
            state=state, response_status=status, response_body=body, finished_at=timezone.now()
        )
    except DatabaseError:
        logger.exception(
            "the answer to %s under Idempotency-Key %r could not be recorded; it reads as unknown until it expires",
            record.route,
            record.key,
        )
