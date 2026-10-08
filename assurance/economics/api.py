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

The body is JSON only, read strictly: a key that appears twice in one object, a
bare ``NaN`` or ``Infinity``, and a JSON number where a decimal string belongs are
refused; so is any field the schema does not hold. A refusal is 400 with the
engine's code and the field's path.

None of these routes is a stop, and none sits on a stop's path: each is classified
in ``safety.stops.NOT_STOPS``, none reads or writes anything a stop or the
decision reads, and this module does nothing at import but define its views, so
it cannot take the URLconf, and every stop with it, down.
"""

from __future__ import annotations

import json

from django.db import IntegrityError
from django.http import QueryDict
from django.shortcuts import get_object_or_404
from django.urls import path
from rest_framework import permissions, status
from rest_framework.exceptions import ParseError, PermissionDenied, UnsupportedMediaType, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from assurance.models import Deployment
from config.parsers import SafeJSONParser

from .engine import parameter_set as pset
from .engine.parameters import ParameterRefused
from .models import CustomerParameterSet, EconomicsRefused

#: The most versions the list returns: a custom view's list is not paginated by
#: the project's default pagination, so it carries its own bound.
VERSION_LIST_LIMIT = 200


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
        try:
            text = stream.read().decode(encoding)
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
        return Response(
            {"deployment": str(deployment.uuid), **current.as_dict(current_version=current.version)}
        )


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
        document = request.data
        if isinstance(document, QueryDict):
            # A form whose stream the gateway already read reaches here as an empty
            # QueryDict, never through the JSON parser: refused as the form it is.
            raise UnsupportedMediaType(request.content_type)
        try:
            version = CustomerParameterSet.record(deployment, set_key, document, author=request.user)
        except EconomicsRefused as refused:
            raise _refused(refused) from None
        except IntegrityError:
            return Response(
                {"detail": "Another version of this set was recorded at the same moment; send it again."},
                status=status.HTTP_409_CONFLICT,
            )
        return Response(
            {"deployment": str(deployment.uuid), **version.as_dict(current_version=version.version)},
            status=status.HTTP_201_CREATED,
        )


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
