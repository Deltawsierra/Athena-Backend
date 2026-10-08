"""The scenario builder's routes (``docs/economics/spec-v1.md``, section 23.8).

Mounted under ``/api/assurance/`` by :mod:`assurance.urls`, GUARDED, in a guard of
its own: a fault here, or in the builder or the template module it imports, leaves
these two routes unserved and nothing else -- not the parameter-set routes, not the
URLconf, not a stop (``tests/test_economics_builder.py``,
``test_a_builder_fault_never_takes_down_a_stop``).

- ``POST deployments/<uuid>/economics/scenarios/build/``: build a scenario draft from
  the effects and findings the body names and a customer parameter-set version
  (:func:`assurance.economics.builder.build`). 201 with the scenario and its events;
  200 with the scenario already built when the same inputs were built before; 409
  when a build of the same inputs is recorded at the same moment, and nothing is
  written.
- ``GET deployments/<uuid>/economics/scenarios/<scenario uuid>/events/``: the
  scenario's events with their effects, findings, components and provenance.

Access is the parameter-set routes' (:mod:`assurance.economics.api`): a signed-in
account; a deployment the caller cannot see, or a scenario of another deployment,
is 404; only an admin or an analyst builds (the roles that author a scenario), and
the draft names the signed-in account as its author, so the review rule of section
7 holds for it. The body is strict JSON, at most 64 KiB (413 on the declared length,
and the parser never reads past the limit).

Neither route is a stop, and neither reads or writes anything a stop or the decision
reads: both are in ``safety.stops.NOT_STOPS``.
"""

from __future__ import annotations

from django.db import IntegrityError
from django.http import QueryDict
from django.shortcuts import get_object_or_404
from django.urls import path
from rest_framework import permissions, status
from rest_framework.exceptions import PermissionDenied, UnsupportedMediaType, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from . import builder
from .api import MAX_BODY_BYTES, BodyTooLarge, StrictJSONParser, _deployment, _may_write, _table_unavailable
from .engine import currency as _currency
from .engine.money import MoneyRefused
from .models import EconomicsRefused, FinancialScenario


def _refused(code: str, detail: str) -> ValidationError:
    return ValidationError({"code": code, "detail": detail})


class ScenarioBuildView(APIView):
    """Build a scenario draft from effects, findings and a parameter-set version."""

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [StrictJSONParser]

    def post(self, request, uuid):
        deployment = _deployment(request, uuid)
        if not _may_write(request.user):
            raise PermissionDenied("Building a scenario requires an admin or analyst role.")
        try:
            declared = int(request.META.get("CONTENT_LENGTH") or 0)
        except ValueError:
            raise ValidationError({"detail": "Content-Length is not a number"}) from None
        if declared > MAX_BODY_BYTES:
            raise BodyTooLarge()
        body = request.data
        if isinstance(body, QueryDict):
            raise UnsupportedMediaType(request.content_type)
        try:
            scenario, created = builder.build(deployment, body, author=request.user)
            served = builder.describe(scenario)
        except EconomicsRefused as refused:
            raise _refused(refused.code, refused.detail or str(refused)) from None
        except MoneyRefused as refused:
            raise _refused(refused.code, refused.detail or str(refused)) from None
        except IntegrityError:
            return Response(
                {"detail": "A build of the same inputs was recorded at the same moment; send it again to read it."},
                status=status.HTTP_409_CONFLICT,
            )
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        return Response(
            {"deployment": str(deployment.uuid), "created": created, **served},
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


class ScenarioEventsView(APIView):
    """A built scenario's events, with their findings, components and provenance."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid, scenario):
        deployment = _deployment(request, uuid)
        found = get_object_or_404(FinancialScenario.objects.filter(deployment=deployment), uuid=scenario)
        try:
            served = builder.describe(found)
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        return Response({"deployment": str(deployment.uuid), **served})


urlpatterns = [
    path(
        "deployments/<uuid:uuid>/economics/scenarios/build/",
        ScenarioBuildView.as_view(),
        name="deployment-economics-scenario-build",
    ),
    path(
        "deployments/<uuid:uuid>/economics/scenarios/<uuid:scenario>/events/",
        ScenarioEventsView.as_view(),
        name="deployment-economics-scenario-events",
    ),
]
