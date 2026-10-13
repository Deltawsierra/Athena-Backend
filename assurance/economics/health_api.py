"""The data-health route (MVP step 10; ``docs/economics/spec-v1.md``, section 29.7),
and step 11's two context routes (section 31.8): a prefill suggestion and a
scenario's enforcement precedents.

Mounted under ``/api/assurance/`` by :mod:`assurance.urls`, GUARDED, in a guard of
its own: a fault here leaves this route unserved and nothing else -- not the other
economics routes, not the URLconf, not a stop.

- ``GET deployments/<uuid>/economics/data-health/``: every feed source a run of the
  deployment can read (:func:`assurance.economics.feeds.data_health`), on today's
  date: its latest version, the version a run uses, its age, SLA and state
  (``fresh``, ``stale``, ``blocked`` or ``missing``), the last fetch that failed (its
  code only) and the Unknowns it causes -- the deployment's current parameters that
  name it, where it is blocked or missing.

- ``GET deployments/<uuid>/economics/suggestions/?source=&target=[&observation=...&quantity=]``
  (MVP step 11): a cloud cost, or a public company's revenue or operating margin,
  as a SUGGESTION for one parameter-set variable
  (:func:`assurance.economics.context_service.suggest`). It writes nothing: a person
  accepts it by recording its entry in a parameter-set version. A refusal is 400
  with its code.
- ``GET deployments/<uuid>/economics/scenarios/<scenario>/precedents/`` (MVP step 11):
  the enforcement records the scenario version lists as precedent, each with its
  citation; context only, never a figure
  (:func:`assurance.economics.context_service.precedents`).

Access is the parameter-set routes' (:mod:`assurance.economics.api`): a signed-in
account, and a deployment the caller cannot see is 404 whether or not it exists; a
viewer reads. It takes no query parameter (400 for any, never ignored), and answers
canonical JSON: the same stored rows on the same date give the same bytes. It reads
no currency table and writes nothing.

None of it is a stop, and it reads or writes nothing a stop or the decision reads:
each route is in ``safety.stops.NOT_STOPS``. It does nothing at import but define its views, and imports the feed
module (and through it the outbound client) and the context service only inside them: nothing Django loads at start
imports it.
"""

from __future__ import annotations

import json

from django.http import HttpResponse
from django.shortcuts import get_object_or_404
from django.urls import path
from rest_framework import permissions
from rest_framework.exceptions import ValidationError
from rest_framework.views import APIView

from .api import _deployment
from .models import FinancialScenario


def canonical_bytes(document) -> bytes:
    """One spelling of the answer: sorted keys, no whitespace, UTF-8."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class DataHealthView(APIView):
    """Feed freshness, source failures and the Unknowns they cause, for one deployment."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid):
        deployment = _deployment(request, uuid)
        if request.query_params:
            raise ValidationError(
                {"code": "field_malformed", "detail": "the data-health route takes no query parameter"}
            )
        from . import feeds

        return HttpResponse(canonical_bytes(feeds.data_health(deployment)), content_type="application/json")


def _scenario(deployment, scenario_uuid) -> FinancialScenario:
    """The deployment's own scenario version, or 404 (another deployment's is never found)."""
    return get_object_or_404(FinancialScenario.objects.filter(deployment=deployment), uuid=scenario_uuid)


def _strict_answer(document, status: int = 200) -> HttpResponse:
    return HttpResponse(canonical_bytes(document), content_type="application/json", status=status)


class SuggestionView(APIView):
    """A prefill suggestion for one parameter-set variable (MVP step 11): read only."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid):
        deployment = _deployment(request, uuid)
        query = {name: request.query_params.getlist(name) for name in request.query_params}
        from . import context_service

        try:
            answer = context_service.suggest(deployment, query)
        except context_service.Refused as refused:
            return _strict_answer({"code": refused.code, "detail": refused.detail, "meaning": refused.meaning}, 400)
        return _strict_answer(answer)


class PrecedentsView(APIView):
    """The enforcement records one scenario version lists as precedent (MVP step 11):
    context only, read only."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid, scenario):
        deployment = _deployment(request, uuid)
        found = _scenario(deployment, scenario)
        if request.query_params:
            raise ValidationError({"code": "field_malformed", "detail": "the precedents route takes no query parameter"})
        from . import context_service

        return _strict_answer(context_service.precedents(deployment, found))


urlpatterns = [
    path(
        "deployments/<uuid:uuid>/economics/data-health/",
        DataHealthView.as_view(),
        name="deployment-economics-data-health",
    ),
    path(
        "deployments/<uuid:uuid>/economics/suggestions/",
        SuggestionView.as_view(),
        name="deployment-economics-suggestions",
    ),
    path(
        "deployments/<uuid:uuid>/economics/scenarios/<uuid:scenario>/precedents/",
        PrecedentsView.as_view(),
        name="deployment-economics-scenario-precedents",
    ),
]
