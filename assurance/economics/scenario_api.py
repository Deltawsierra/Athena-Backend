"""The scenario builder's routes (``docs/economics/spec-v1.md``, section 24.8).

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
  scenario's events with their effects, findings, components and provenance, and the
  Unknown banner rule of the report (``docs/economics/spec-v1.md``, sections 24.8 and
  27.6), applied to the scenario version's latest stored result and its Validity Card:
  ``grade`` (the card document's, where every stored row verifies), ``banner``,
  ``excluded_from_totals`` and ``banner_reason``. With no verified grade A to D (no
  result yet, a refused run, no card, rows that do not verify, or graded Unknown) the
  banner is ``Unknown: not for capital decisions`` and the scenario is excluded from
  every total. The figures stay: they are step 4's deterministic low, base and high,
  not a result.

Access is the parameter-set routes' (:mod:`assurance.economics.api`): a signed-in
account; a deployment the caller cannot see, or a scenario of another deployment,
is 404; only an admin or an analyst builds (the roles that author a scenario), and
the draft names the signed-in account as its author, so the review rule of section
7 holds for it. The body is strict JSON, at most 64 KiB (413 on the declared length,
and the parser never reads past the limit). An effect's attribute may state the
distribution it draws from in a simulation, held to the same range test of its
figures as a parameter set's (spec, section 25.1); a body that states one while the
probabilistic engine will not import is 503, and nothing is written.

Neither route is a stop, and neither reads or writes anything a stop or the decision
reads: both are in ``safety.stops.NOT_STOPS``. The events route reads the economics
rows of one result (its record, card and series) and hashes them, and nothing else.

The banner rule is :mod:`assurance.economics.report`'s, imported inside the events view
and not at load, so a report that will not import leaves the build route and the
parameter-set routes served (``tests/economics_fault_cases.py``) and the events route
answering an error with no figures: it never serves figures without the banner.
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
from .api import (
    MAX_BODY_BYTES,
    BodyTooLarge,
    StrictJSONParser,
    _deployment,
    _engine_unavailable,
    _may_write,
    _table_unavailable,
)
from .engine import currency as _currency
from .engine.money import MoneyRefused
from .engine.parameter_set import ProbabilisticEngineUnavailable
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
        except ProbabilisticEngineUnavailable:
            return _engine_unavailable()
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
        from . import report  # not at load: see the module's last paragraph

        try:
            served = builder.describe(found)
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        except EconomicsRefused as refused:
            # A stored row that no longer holds (a figure's normalization record, section
            # 36) is refused, never served.
            return Response({"code": refused.code, "detail": refused.detail}, status=status.HTTP_409_CONFLICT)
        # The figures are step 4's, not a result: they stay. Only the banner rule is added.
        return Response({"deployment": str(deployment.uuid), **served, **report.standing(found)})


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
