"""The customer parameter-set API, and raising a source's trust tier.

Mounted under ``/api/assurance/`` by :mod:`assurance.urls`
(``docs/economics/spec-v1.md``, section 19, and section 6.1 for the trust raises):

- ``GET  deployments/<uuid>/economics/parameter-sets/<set_key>/``: the current
  version of the deployment's set ``set_key`` (the highest); 404 when it has none.
- ``GET  deployments/<uuid>/economics/parameter-sets/<set_key>/versions/``: every
  version, newest first, without their figures.
- ``POST deployments/<uuid>/economics/parameter-sets/<set_key>/versions/``: record
  the next version (append-only), from a document of the schema's variables
  (:mod:`assurance.economics.engine.parameter_set`). 201 with the version. Each
  entry may state the distribution it draws from in a simulation, and the document
  the scenario's frequency (spec, section 19.2): each is held to the simulation's
  own range test of its row's figures before anything is written (from both sides;
  the frequency by the rate its count implies), and refused with
  that test's code (``distribution_contradicts_range``, naming the variable and the
  test, or ``distribution_on_fixed_row``).

Access follows the assurance API's own rules (:mod:`assurance.views`): a signed-in
account; a deployment the caller cannot see is 404, whether or not it exists
(admins and analysts see every deployment, anyone else their own); and only an
admin or an analyst writes, as for a scenario (spec, section 6), so a viewer is
refused 403. A version names its author, the signed-in account, and nothing the
body says. Nothing here reads or writes another deployment's set.

The body is JSON only, read strictly, and at most :data:`MAX_BODY_BYTES` long
(413, on the declared length before anything is read, and the parser never reads
past it): a key that appears twice in one object, a bare ``NaN`` or ``Infinity``,
and a JSON number where a decimal string belongs are refused; so is any field the
schema does not hold. A refusal is 400 with the engine's code and the field's
path. While economics cannot read its currency table, what needs the table is
refused 503 and nothing is recorded; so is a document that states a distribution
while the probabilistic engine (numpy) will not import. A document that states
none never imports it.

Raising a financial source's trust tier (the owner's decision of 12 Oct 2026;
:class:`~assurance.economics.models.FinancialSourceTrustRaise`):

- ``GET  economics/sources/<uuid>/trust-raises/``: every raise of the source the
  version ``<uuid>`` belongs to (its tenant and key, every version), newest first.
- ``POST economics/sources/<uuid>/trust-raises/``: raise that version to
  ``to_tier`` for ``reason`` (the body's only two fields). Below ``authoritative``
  the new version is recorded at once (201, ``done``); ``authoritative`` is
  recorded ``pending`` (201), and no version is written until a second admin
  approves it.
- ``POST economics/trust-raises/<uuid>/approve/``: a pending raise approved by an
  admin other than its requester, while the requester is still an active admin
  (200, ``done``, the new version recorded). This route is the ONLY approver: the
  operator's command never approves.
- ``POST economics/trust-raises/<uuid>/withdraw/``: a pending raise withdrawn by any
  admin (200, ``withdrawn``, naming who withdrew it).

Each raise records the channel it came through, ``api`` here. A source is visible as
a deployment is: a platform-wide one to every signed-in account, a tenant's to those
who see that deployment (404 otherwise, whether or not it exists). Reading needs no
more. Every write is an admin's only, refused 403 (``admin_required``) for anyone
else, before the body is read; so is an approval by the requester
(``second_person_required``). A raise whose state or source moved meanwhile is 409
(``trust_raise_not_pending``, ``source_superseded``, ``requester_no_longer_admin``,
or another version of the source recorded at the same moment), and every other
refusal 400 with its code. A write that meets a lock it cannot get ("database is
locked", a serialisation failure) is 503 with Retry-After (``trust_raise_busy``), as
the stops' service-token path answers a busy database, and writes nothing. A
request's body is read as the parameter-set route reads one: strict JSON, at most
:data:`MAX_BODY_BYTES` (413, saying what the route takes); an approval or a
withdrawal takes no body (none, or ``{}``), and one that says anything is 400.

None of these routes is a stop, and none sits on a stop's path: each is classified
in ``safety.stops.NOT_STOPS``, and none reads or writes anything a stop or the
decision reads. This module does nothing at import but define its views, and
:mod:`assurance.urls` imports it GUARDED: if it fails to import, its routes are
logged and not served, and the URLconf, every stop and the system checks load
without them (``tests/test_economics_engine.py``,
``test_an_economics_fault_never_takes_down_a_stop``).
"""

from __future__ import annotations

import json

from django.db import IntegrityError, OperationalError
from django.db.models import Q
from django.http import QueryDict
from django.shortcuts import get_object_or_404
from django.urls import path
from rest_framework import permissions, status
from rest_framework.exceptions import APIException, ParseError, PermissionDenied, UnsupportedMediaType, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from assurance.models import Deployment
from config.parsers import SafeJSONParser

from .engine import currency as _currency
from .engine import parameter_set as pset
from .engine.parameters import ParameterRefused
from .models import (
    CustomerParameterSet,
    EconomicsRefused,
    FinancialSource,
    FinancialSourceTrustRaise,
    require_trust_admin,
)

#: The most versions the list returns: a custom view's list is not paginated by
#: the project's default pagination, so it carries its own bound.
VERSION_LIST_LIMIT = 200

#: The largest body a version is posted in. A full version -- thirty variables and
#: a sublimit for every family -- is about 15 KiB, and about 33 KiB with every entry
#: and the frequency stating a splice, the largest stated distribution; a body over
#: this is refused (413) on its declared Content-Length before anything reads it,
#: and the parser reads no more than this however long the body turns out to be.
MAX_BODY_BYTES = 64 * 1024


class BodyTooLarge(APIException):
    status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    default_detail = f"A parameter-set version is posted in at most {MAX_BODY_BYTES} bytes."
    default_code = "body_too_large"


def _no_duplicate_keys(pairs):
    seen = {}
    for key, value in pairs:
        if key in seen:
            raise ParseError(f"JSON parse error - duplicate_id: the key {key!r} appears twice in one object")
        seen[key] = value
    return seen


def _no_constant(name):
    raise ParseError(f"JSON parse error - {name} is not a value")


class StrictJSONParser(SafeJSONParser):
    """JSON only, and strictly: a duplicate key in any object, and a bare NaN or
    Infinity, are refused, where ``json`` would keep the last key and read NaN."""

    #: What a body past the limit is refused with: a route's own 413.
    too_large = BodyTooLarge

    def parse(self, stream, media_type=None, parser_context=None):
        parser_context = parser_context or {}
        encoding = parser_context.get("encoding", "utf-8")
        # Bounded whatever Content-Length said, or if it said nothing: one byte past
        # the limit is enough to know the body is too large.
        raw = stream.read(MAX_BODY_BYTES + 1)
        if len(raw) > MAX_BODY_BYTES:
            raise self.too_large()
        try:
            text = raw.decode(encoding)
            return json.loads(text, object_pairs_hook=_no_duplicate_keys, parse_constant=_no_constant)
        except RecursionError:
            raise ParseError("JSON parse error - the body is nested too deeply") from None
        except (UnicodeDecodeError, ValueError) as exc:
            raise ParseError(f"JSON parse error - {exc}") from None


def _is_privileged(user) -> bool:
    """Who sees every deployment: as :func:`assurance.views._is_privileged`."""
    return bool(
        getattr(user, "is_superuser", False) or getattr(user, "is_admin", False) or getattr(user, "is_analyst", False)
    )


def _may_write(user) -> bool:
    """Who records a parameter-set version: an admin or an analyst, the roles that
    author a scenario (spec, section 6). A viewer reads and never writes."""
    return _is_privileged(user)


def visible_deployments(user):
    """The deployments ``user`` may read, exactly as the deployment list scopes
    them: every one for an admin or analyst, their own for anyone else."""
    deployments = Deployment.objects.all()
    if _is_privileged(user):
        return deployments
    return deployments.filter(owner=user)


def _deployment(request, deployment_uuid):
    return get_object_or_404(visible_deployments(request.user), uuid=deployment_uuid)


def _refused(refused: EconomicsRefused) -> ValidationError:
    return ValidationError({"code": refused.code, "detail": refused.detail or str(refused)})


def _table_unavailable() -> Response:
    """Economics cannot read its currency table (mythos-core's module will not
    import, or it is not the one pinned): it refuses what needs it, 503, and records
    nothing. Nothing outside economics is refused for it."""
    return Response(
        {"detail": "Economic Exposure cannot read its currency table now; nothing was recorded or computed."},
        status=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


def _engine_unavailable() -> Response:
    """The probabilistic engine (numpy) will not import, so a stated distribution
    cannot be checked: refused 503, and nothing recorded."""
    return Response(
        {"detail": "Economic Exposure cannot check a stated distribution now; nothing was recorded."},
        status=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


def _set_key(set_key: str) -> str:
    try:
        return pset.check_set_key(set_key)
    except ParameterRefused as refused:
        raise ValidationError({"code": refused.code, "detail": refused.detail}) from None


class ParameterSetCurrentView(APIView):
    """The current version of one parameter set."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid, set_key):
        deployment = _deployment(request, uuid)
        _set_key(set_key)
        current = CustomerParameterSet.current(deployment, set_key)
        if current is None:
            return Response(
                {"detail": f"The deployment has no parameter set {set_key!r}."}, status=status.HTTP_404_NOT_FOUND
            )
        try:
            served = current.as_dict(current_version=current.version)
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        return Response({"deployment": str(deployment.uuid), **served})


class ParameterSetVersionsView(APIView):
    """Every version of one parameter set, and recording the next."""

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [StrictJSONParser]

    def get(self, request, uuid, set_key):
        deployment = _deployment(request, uuid)
        _set_key(set_key)
        versions = list(
            CustomerParameterSet.objects.filter(deployment=deployment, set_key=set_key).order_by("-version")[
                : VERSION_LIST_LIMIT + 1
            ]
        )
        truncated = len(versions) > VERSION_LIST_LIMIT
        versions = versions[:VERSION_LIST_LIMIT]
        current = versions[0].version if versions else None
        return Response(
            {
                "deployment": str(deployment.uuid),
                "set_key": set_key,
                "current": current,
                "truncated": truncated,
                "versions": [
                    {
                        "version": v.version,
                        "current": v.version == current,
                        "author": v.author_username or None,
                        "recorded_at": v.recorded_at.isoformat(),
                        "content_digest": v.content_digest,
                        "variable_count": v.variable_count,
                    }
                    for v in versions
                ],
            }
        )

    def post(self, request, uuid, set_key):
        deployment = _deployment(request, uuid)
        if not _may_write(request.user):
            raise PermissionDenied("Recording a customer parameter set requires an admin or analyst role.")
        _set_key(set_key)
        # The DECLARED length, before the body is read, as the observed-outcomes
        # route does: a body too large is refused without parsing it.
        try:
            declared = int(request.META.get("CONTENT_LENGTH") or 0)
        except ValueError:
            raise ValidationError({"detail": "Content-Length is not a number"}) from None
        if declared > MAX_BODY_BYTES:
            raise BodyTooLarge()
        document = request.data
        if isinstance(document, QueryDict):
            # A form whose stream the gateway already read reaches here as an empty
            # QueryDict, never through the JSON parser: refused as the form it is.
            raise UnsupportedMediaType(request.content_type)
        try:
            version = CustomerParameterSet.record(deployment, set_key, document, author=request.user)
            served = version.as_dict(current_version=version.version)
        except EconomicsRefused as refused:
            raise _refused(refused) from None
        except IntegrityError:
            return Response(
                {"detail": "Another version of this set was recorded at the same moment; send it again."},
                status=status.HTTP_409_CONFLICT,
            )
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        except pset.ProbabilisticEngineUnavailable:
            return _engine_unavailable()
        return Response({"deployment": str(deployment.uuid), **served}, status=status.HTTP_201_CREATED)


# ---------------------------------------------------------------------------
# Raising a source's trust tier
# ---------------------------------------------------------------------------

#: The most raises the list returns, newest first.
TRUST_RAISE_LIST_LIMIT = 200

#: The fields a raise is posted with, and nothing else.
_TRUST_RAISE_FIELDS = frozenset({"to_tier", "reason"})


class TrustRaiseTooLarge(BodyTooLarge):
    default_detail = (
        f"A trust raise is posted in at most {MAX_BODY_BYTES} bytes: a JSON object holding to_tier and reason, "
        "and nothing else."
    )


class TrustDecisionTooLarge(BodyTooLarge):
    default_detail = (
        f"Approving or withdrawing a trust raise takes no body: send none, or {{}} (at most {MAX_BODY_BYTES} "
        "bytes are read)."
    )


class TrustRaiseJSONParser(StrictJSONParser):
    too_large = TrustRaiseTooLarge


class TrustDecisionJSONParser(StrictJSONParser):
    too_large = TrustDecisionTooLarge

#: The answer to a refused raise, by its code: a person who may not do this (403),
#: and a raise whose state or source moved meanwhile (409). Any other code is a
#: body the rules refuse (400).
_TRUST_REFUSAL_STATUS = {
    "admin_required": status.HTTP_403_FORBIDDEN,
    "second_person_required": status.HTTP_403_FORBIDDEN,
    "trust_raise_not_pending": status.HTTP_409_CONFLICT,
    "source_superseded": status.HTTP_409_CONFLICT,
    "requester_no_longer_admin": status.HTTP_409_CONFLICT,
}

#: How long a caller waits before sending a write again that met a lock.
TRUST_RAISE_RETRY_AFTER_SECONDS = 1


def _visible(prefix: str, user) -> Q:
    """Platform-wide sources, and those of a deployment ``user`` may see, as
    :func:`visible_deployments` scopes them."""
    return Q(**{f"{prefix}deployment__isnull": True}) | Q(**{f"{prefix}deployment__in": visible_deployments(user)})


def _visible_source(request, source_uuid) -> FinancialSource:
    return get_object_or_404(FinancialSource.objects.filter(_visible("", request.user)), uuid=source_uuid)


def _visible_raise(request, raise_uuid) -> FinancialSourceTrustRaise:
    return get_object_or_404(
        FinancialSourceTrustRaise.objects.filter(_visible("from_version__", request.user)), uuid=raise_uuid
    )


def _trust_refused(refused: EconomicsRefused) -> Response:
    return Response(
        {"code": refused.code, "detail": refused.detail or str(refused)},
        status=_TRUST_REFUSAL_STATUS.get(refused.code, status.HTTP_400_BAD_REQUEST),
    )


def _trust_admin(request) -> Response | None:
    """The admin check, before anything else is read: a 403 with its code."""
    try:
        require_trust_admin(request.user)
    except EconomicsRefused as refused:
        return _trust_refused(refused)
    return None


def _declared_length(request, too_large) -> None:
    """The DECLARED length, before the body is read, as the parameter-set route does."""
    try:
        declared = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        raise ValidationError({"detail": "Content-Length is not a number"}) from None
    if declared > MAX_BODY_BYTES:
        raise too_large()


def _no_body(request) -> None:
    """An approval or a withdrawal says nothing: no body, or ``{}``. A body that says
    anything -- a field, a list, a value -- is refused (400), never ignored."""
    _declared_length(request, TrustDecisionTooLarge)
    body = request.data
    if isinstance(body, QueryDict):
        if body:
            raise UnsupportedMediaType(request.content_type)
        return
    if body != {}:
        raise ValidationError({"detail": "Approving or withdrawing a trust raise takes no body: send none, or {}."})


def _busy() -> Response:
    """A write that met a lock it could not get: nothing was written, and the same
    request may be sent again. 503 with Retry-After, as the stops' service-token
    path answers a busy database (``safety.service_token``)."""
    return Response(
        {
            "code": "trust_raise_busy",
            "detail": "The database was busy and nothing was recorded; send the same request again.",
        },
        status=status.HTTP_503_SERVICE_UNAVAILABLE,
        headers={"Retry-After": str(TRUST_RAISE_RETRY_AFTER_SECONDS)},
    )


def _raced() -> Response:
    return Response(
        {"detail": "Another version of this source was recorded at the same moment; nothing was recorded."},
        status=status.HTTP_409_CONFLICT,
    )


class SourceTrustRaisesView(APIView):
    """Every raise of one source's trust tier, and requesting the next."""

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [TrustRaiseJSONParser]

    def get(self, request, uuid):
        source = _visible_source(request, uuid)
        raises = list(
            FinancialSourceTrustRaise.objects.filter(
                from_version__deployment_id=source.deployment_id, from_version__source_key=source.source_key
            )
            .select_related("from_version", "from_version__deployment", "to_version")
            .order_by("-id")[: TRUST_RAISE_LIST_LIMIT + 1]
        )
        truncated = len(raises) > TRUST_RAISE_LIST_LIMIT
        return Response(
            {
                "source_key": source.source_key,
                "deployment": str(source.deployment.uuid) if source.deployment_id is not None else None,
                "truncated": truncated,
                "raises": [raised.as_dict() for raised in raises[:TRUST_RAISE_LIST_LIMIT]],
            }
        )

    def post(self, request, uuid):
        source = _visible_source(request, uuid)
        refused = _trust_admin(request)
        if refused is not None:
            return refused
        _declared_length(request, TrustRaiseTooLarge)
        body = request.data
        if isinstance(body, QueryDict):
            raise UnsupportedMediaType(request.content_type)
        if not isinstance(body, dict):
            raise ValidationError({"detail": "Send an object with to_tier and reason."})
        unknown = sorted(set(body) - _TRUST_RAISE_FIELDS)
        if unknown:
            raise ValidationError({"detail": f"A raise holds to_tier and reason only; not {unknown}."})
        try:
            raised = FinancialSourceTrustRaise.request(
                source, body.get("to_tier"), body.get("reason"), by=request.user, channel="api"
            )
        except EconomicsRefused as refused:
            return _trust_refused(refused)
        except IntegrityError:
            return _raced()
        except OperationalError:
            return _busy()
        return Response(FinancialSourceTrustRaise.objects.get(pk=raised.pk).as_dict(), status=status.HTTP_201_CREATED)


class TrustRaiseApproveView(APIView):
    """A pending raise approved by an admin other than the one who requested it."""

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [TrustDecisionJSONParser]

    def post(self, request, uuid):
        found = _visible_raise(request, uuid)
        refused = _trust_admin(request)
        if refused is not None:
            return refused
        _no_body(request)
        try:
            done = found.approve(by=request.user, channel="api")
        except EconomicsRefused as refused:
            return _trust_refused(refused)
        except IntegrityError:
            return _raced()
        except OperationalError:
            return _busy()
        return Response(done.as_dict())


class TrustRaiseWithdrawView(APIView):
    """A pending raise withdrawn by any admin."""

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [TrustDecisionJSONParser]

    def post(self, request, uuid):
        found = _visible_raise(request, uuid)
        refused = _trust_admin(request)
        if refused is not None:
            return refused
        _no_body(request)
        try:
            withdrawn = found.withdraw(by=request.user, channel="api")
        except EconomicsRefused as refused:
            return _trust_refused(refused)
        except OperationalError:
            return _busy()
        return Response(withdrawn.as_dict())


urlpatterns = [
    path(
        "deployments/<uuid:uuid>/economics/parameter-sets/<str:set_key>/",
        ParameterSetCurrentView.as_view(),
        name="deployment-economics-parameter-set",
    ),
    path(
        "deployments/<uuid:uuid>/economics/parameter-sets/<str:set_key>/versions/",
        ParameterSetVersionsView.as_view(),
        name="deployment-economics-parameter-set-versions",
    ),
    path(
        "economics/sources/<uuid:uuid>/trust-raises/",
        SourceTrustRaisesView.as_view(),
        name="economics-source-trust-raises",
    ),
    path(
        "economics/trust-raises/<uuid:uuid>/approve/",
        TrustRaiseApproveView.as_view(),
        name="economics-trust-raise-approve",
    ),
    path(
        "economics/trust-raises/<uuid:uuid>/withdraw/",
        TrustRaiseWithdrawView.as_view(),
        name="economics-trust-raise-withdraw",
    ),
]
