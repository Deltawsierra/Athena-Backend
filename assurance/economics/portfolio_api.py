"""The portfolio routes (Economic Exposure E5; ``docs/economics/spec-v1.md``,
section 33; the owner's specification's ``GET /financial/portfolio``).

Mounted under ``/api/assurance/`` by :mod:`assurance.urls`, GUARDED, in a guard of
its own: a fault here leaves these three routes unserved and nothing else -- not the
other economics routes, not the URLconf, not a stop
(``tests/test_economics_portfolio.py``, ``test_a_portfolio_fault_never_takes_down_a_stop``).

- ``POST deployments/<uuid>/economics/portfolio/groups/``: record a version of one
  of the deployment's correlation groups, authored by the caller (an admin or an
  analyst), or return its key's latest version where that states the same group
  (:func:`assurance.economics.portfolio.record_group`); ``GET`` lists every version,
  each with its author and time. A portfolio names the versions it draws with.

- ``POST deployments/<uuid>/economics/portfolio/simulate/``: total the deployment's
  scenarios (:func:`assurance.economics.portfolio.simulate_portfolio`) for a seed, a
  simulation policy (step 6's), a reporting currency and a valuation date, with an
  optional normalisation policy and the recorded correlation group versions it
  draws with, by uuid: IDEMPOTENT, the same inputs
  return the stored portfolio (200) and never draw a second; a new one is 201. An
  admin or an analyst only.
- ``GET deployments/<uuid>/economics/portfolio/``: the portfolio's report
  (``?result=<uuid>``, else the deployment's latest), canonical bytes carrying their
  own digest, built from the stored rows only and checked first
  (:func:`assurance.economics.portfolio.build_document`).

Access, tenancy (404), strict JSON, 64 KiB (413), 415 for a form, the 503 while
economics cannot read its currency table, and one deadline per request
(:data:`assurance.economics.report_api.REQUEST_BUDGET_SECONDS`) are step 6's. A
portfolio the engine cannot make now (it will not import, the deadline, memory) is
503 and records nothing; a request the rows refuse is 400 and records nothing.

No route here is a stop, and none reads or writes anything a stop or the decision
reads: each is in ``safety.stops.NOT_STOPS``. The draws hold no transaction
and no lock. This module imports the engine only inside a view: nothing Django loads
at start imports it, or numpy.
"""

from __future__ import annotations

from django.http import HttpResponse, QueryDict
from django.urls import path, reverse
from rest_framework import permissions, status
from rest_framework.exceptions import PermissionDenied, UnsupportedMediaType, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from . import portfolio, report
from .api import MAX_BODY_BYTES, BodyTooLarge, StrictJSONParser, _deployment, _may_write, _table_unavailable
from .engine import currency as _currency
from .models import SIMULATION_COMPLETED
from .report_api import REQUEST_BUDGET_SECONDS, SIMULATION_POLICIES, parse_simulate


def _refused(code: str, detail: str) -> ValidationError:
    return ValidationError({"code": code, "detail": detail})


class PortfolioView(APIView):
    """The deployment's portfolio report: ``?result=<uuid>``, else its latest."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid):
        deployment = _deployment(request, uuid)
        named = request.query_params.get("result")
        if named is not None:
            row = portfolio.find(deployment, named)
            if row is None:
                return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        else:
            row = portfolio.latest(deployment)
            if row is None:
                return Response(
                    {"detail": "The deployment has no portfolio result: simulate one first."},
                    status=status.HTTP_404_NOT_FOUND,
                )
        try:
            body = report.canonical_bytes(portfolio.build_document(row))
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        return HttpResponse(body, content_type="application/json")


class PortfolioSimulateView(APIView):
    """Total a deployment's scenarios, or return the portfolio already totalled."""

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [StrictJSONParser]

    def post(self, request, uuid):
        deployment = _deployment(request, uuid)
        if not _may_write(request.user):
            raise PermissionDenied("Totalling a portfolio requires an admin or analyst role.")
        try:
            declared = int(request.META.get("CONTENT_LENGTH") or 0)
        except ValueError:
            raise ValidationError({"detail": "Content-Length is not a number"}) from None
        if declared > MAX_BODY_BYTES:
            raise BodyTooLarge()
        body = request.data
        if isinstance(body, QueryDict):
            raise UnsupportedMediaType(request.content_type)
        if not portfolio.table_available():
            return _table_unavailable()
        try:
            wanted = portfolio.parse_request(body, policies=SIMULATION_POLICIES, parse_seed=parse_simulate)
        except portfolio.PortfolioRequestRefused as refused:
            raise _refused(refused.code, refused.detail) from None
        outcome = portfolio.simulate_portfolio(deployment, wanted, time_budget=REQUEST_BUDGET_SECONDS)
        if outcome.result is None:
            unavailable = not outcome.refused_request and outcome.code in portfolio.UNRECORDED
            return Response(
                {"code": outcome.code, "detail": outcome.detail, "recorded": False},
                status=status.HTTP_503_SERVICE_UNAVAILABLE if unavailable else status.HTTP_400_BAD_REQUEST,
            )
        row = outcome.result
        inputs = row.inputs
        url = reverse("deployment-economics-portfolio", kwargs={"uuid": deployment.uuid})
        served = {
            "deployment": str(deployment.uuid),
            "created": outcome.created,
            "policy": {
                "name": wanted.policy,
                "draws": wanted.draws,
                "severe_percentile": str(wanted.severe_percentile),
            },
            "portfolio": {
                "uuid": str(row.uuid),
                "status": row.status,
                "seed": row.seed,
                "draws": row.draws,
                "reporting_currency": row.reporting_currency,
                "valuation_date": row.valuation_date.isoformat(),
                "input_digest": row.input_digest,
                "result_digest": row.result_digest or None,
                "refusal": None if not row.refusal_code
                else {"code": row.refusal_code, "detail": row.refusal_detail},
            },
            "included": [m["scenario"] for m in inputs["members"]],
            "excluded": [
                {"scenario": e["scenario"], "code": e["code"], "reason": e["reason"]} for e in inputs["excluded"]
            ],
            # A refused portfolio has no figures, so no grade (review round 1, NIT-2).
            "grade": portfolio.portfolio_grade(inputs)["grade"] if row.status == SIMULATION_COMPLETED else None,
            "report": f"{url}?result={row.uuid}",
        }
        return Response(served, status=status.HTTP_201_CREATED if outcome.created else status.HTTP_200_OK)


class PortfolioGroupsView(APIView):
    """The deployment's correlation groups: every recorded version (GET), or a new
    version recorded by the caller (POST, an admin or analyst)."""

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [StrictJSONParser]

    def get(self, request, uuid):
        deployment = _deployment(request, uuid)
        return Response({"deployment": str(deployment.uuid), "groups": portfolio.list_groups(deployment)})

    def post(self, request, uuid):
        deployment = _deployment(request, uuid)
        if not _may_write(request.user):
            raise PermissionDenied("Recording a correlation group requires an admin or analyst role.")
        try:
            declared = int(request.META.get("CONTENT_LENGTH") or 0)
        except ValueError:
            raise ValidationError({"detail": "Content-Length is not a number"}) from None
        if declared > MAX_BODY_BYTES:
            raise BodyTooLarge()
        body = request.data
        if isinstance(body, QueryDict):
            raise UnsupportedMediaType(request.content_type)
        outcome = portfolio.record_group(deployment, body, author=request.user)
        if outcome.group is None:
            conflict = outcome.code == "group_version_taken"
            return Response(
                {"code": outcome.code, "detail": outcome.detail, "recorded": False},
                status=status.HTTP_409_CONFLICT if conflict else status.HTTP_400_BAD_REQUEST,
            )
        return Response(
            {"deployment": str(deployment.uuid), "created": outcome.created, "group": outcome.group.as_dict()},
            status=status.HTTP_201_CREATED if outcome.created else status.HTTP_200_OK,
        )


urlpatterns = [
    path(
        "deployments/<uuid:uuid>/economics/portfolio/",
        PortfolioView.as_view(),
        name="deployment-economics-portfolio",
    ),
    path(
        "deployments/<uuid:uuid>/economics/portfolio/simulate/",
        PortfolioSimulateView.as_view(),
        name="deployment-economics-portfolio-simulate",
    ),
    path(
        "deployments/<uuid:uuid>/economics/portfolio/groups/",
        PortfolioGroupsView.as_view(),
        name="deployment-economics-portfolio-groups",
    ),
]
