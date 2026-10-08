"""The customer parameter-set API: the one Economic Exposure route module.

Mounted under ``/api/assurance/`` by :mod:`assurance.urls`
(``docs/economics/spec-v1.md``, section 19):

- ``GET  deployments/<uuid>/economics/parameter-sets/<set_key>/``: the current
  version of the deployment's set ``set_key`` (the highest); 404 when it has none.
- ``GET  deployments/<uuid>/economics/parameter-sets/<set_key>/versions/``: every
  version, newest first, without their figures.
- ``POST deployments/<uuid>/economics/parameter-sets/<set_key>/versions/``: record
  the next version (append-only), from a document of the schema's variables
  (:mod:`assurance.economics.engine.parameter_set`). 201 with the version.

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
refused 503 and nothing is recorded.

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

from django.db import IntegrityError
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
from .models import CustomerParameterSet, EconomicsRefused

#: The most versions the list returns: a custom view's list is not paginated by
#: the project's default pagination, so it carries its own bound.
VERSION_LIST_LIMIT = 200

#: The largest body a version is posted in. A full version -- thirty variables and
#: a sublimit for every family -- is about 15 KiB; a body over this is refused
#: (413) on its declared Content-Length before anything reads it, and the parser
#: reads no more than this however long the body turns out to be.
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

    def parse(self, stream, media_type=None, parser_context=None):
        parser_context = parser_context or {}
        encoding = parser_context.get("encoding", "utf-8")
        # Bounded whatever Content-Length said, or if it said nothing: one byte past
        # the limit is enough to know the body is too large.
        raw = stream.read(MAX_BODY_BYTES + 1)
        if len(raw) > MAX_BODY_BYTES:
            raise BodyTooLarge()
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
        return Response({"deployment": str(deployment.uuid), **served}, status=status.HTTP_201_CREATED)


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
]
