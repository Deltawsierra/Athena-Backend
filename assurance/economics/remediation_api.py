"""One remediation option per scenario version and its economics (MVP step 13;
``docs/economics/spec-v1.md``, section 28; the owner's specification, section 18's
``POST /financial/scenarios/{id}/mitigations`` and ``GET .../roi``).

Mounted under ``/api/assurance/`` by :mod:`assurance.urls`, GUARDED, in a guard of
its own: a fault here leaves these three routes unserved and nothing else -- not
the parameter-set, builder or report routes, not the URLconf, not a stop
(``tests/test_economics_remediation.py``, ``test_a_remediation_fault_never_takes_down_a_stop``).

- ``POST deployments/<uuid>/economics/scenarios/<scenario uuid>/mitigations/``:
  records the scenario version's ONE remediation option, authored by the signed-in
  admin or analyst (201); the same option again returns it (200); another option is
  409 (``remediation_option_held``): it is a new version.
- ``POST .../mitigations/<option uuid>/simulate/``: the current run (where it is
  missing) and the option's residual run, with a seed and a simulation policy, each
  with its Validity Card, under ONE deadline: IDEMPOTENT, 201 where a run was
  recorded and 200 where both were. A run the engine refuses is recorded and served
  so; one it cannot make now (the time budget, memory, an engine that will not
  import) is 503 and records nothing. Both runs are made in ONE of the host's
  economics run slots (:mod:`assurance.economics.capacity`): when none is free the
  request is answered at once, 503 ``economics_capacity`` with ``Retry-After``.
- ``GET .../scenarios/<scenario uuid>/roi/``: the ROI document of the version's
  option (``?simulation=<residual run uuid>``, else its latest), canonical bytes
  carrying their own digest, from stored rows only.

Access is the report routes': a signed-in account; a deployment the caller cannot
see, or a scenario, option or run of another, is 404; only an admin or an analyst
records or simulates (403 for a viewer, even the owner), and every role reads. A
body is strict JSON of at most 64 KiB (413 on the declared length; the parser
never reads past it; a duplicated key is 400; a form is 415). While economics
cannot read its currency table every route answers 503 and records nothing.

None of these routes is a stop, and none reads or writes anything a stop or the
decision reads: each is in ``safety.stops.NOT_STOPS``. The simulation and card
services are imported only inside the simulate view (through the service), never
at load: nothing Django loads at start imports them, or numpy.
"""

from __future__ import annotations

import uuid as _uuid

from django.http import HttpResponse, QueryDict
from django.shortcuts import get_object_or_404
from django.urls import path, reverse
from rest_framework import permissions, status
from rest_framework.exceptions import PermissionDenied, UnsupportedMediaType, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from . import capacity, remediation_service, report
from .api import MAX_BODY_BYTES, BodyTooLarge, StrictJSONParser, _deployment, _may_write, _table_unavailable
from .engine import currency as _currency
from .engine import parameter_set as pset
from .engine import remediation as engine_remediation
from .engine.money import MoneyRefused
from .engine.parameters import ParameterRefused
from .models import EconomicsRefused, FinancialScenario, RemediationOption, SimulationResult
from .report_api import REQUEST_BUDGET_SECONDS, SIMULATION_POLICIES, parse_simulate


def _refused(code: str, detail: str) -> ValidationError:
    return ValidationError({"code": code, "detail": detail})


def _scenario(deployment, scenario_uuid) -> FinancialScenario:
    return get_object_or_404(FinancialScenario.objects.filter(deployment=deployment), uuid=scenario_uuid)


def _body(request):
    try:
        declared = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        raise ValidationError({"detail": "Content-Length is not a number"}) from None
    if declared > MAX_BODY_BYTES:
        raise BodyTooLarge()
    body = request.data
    if isinstance(body, QueryDict):
        raise UnsupportedMediaType(request.content_type)
    return body


def _engine_unavailable() -> Response:
    return Response(
        {"code": "remediation_engine_unavailable", "detail": engine_remediation.REFUSALS["remediation_engine_unavailable"],
         "recorded": False},
        status=status.HTTP_503_SERVICE_UNAVAILABLE,
    )


def _option_body(option: RemediationOption, deployment, scenario) -> dict:
    roi = reverse("deployment-economics-scenario-roi", kwargs={"uuid": deployment.uuid, "scenario": scenario.uuid})
    simulate = reverse(
        "deployment-economics-mitigation-simulate",
        kwargs={"uuid": deployment.uuid, "scenario": scenario.uuid, "option": option.uuid},
    )
    return {
        "deployment": str(deployment.uuid),
        "scenario": str(scenario.uuid),
        "option": {
            "uuid": str(option.uuid),
            "digest": option.option_digest,
            "author": option.author_username or None,
            "recorded_at": option.recorded_at.isoformat(),
            "document": option.document,
        },
        "simulate": simulate,
        "roi": roi,
    }


class MitigationsView(APIView):
    """Record a scenario version's ONE remediation option."""

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [StrictJSONParser]

    def post(self, request, uuid, scenario):
        deployment = _deployment(request, uuid)
        if not _may_write(request.user):
            raise PermissionDenied("Recording a remediation option requires an admin or analyst role.")
        found = _scenario(deployment, scenario)
        body = _body(request)
        try:
            _currency.require_pinned()
            option, created = remediation_service.record_option(found, body, author=request.user)
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        except pset.ProbabilisticEngineUnavailable:
            return _engine_unavailable()
        except EconomicsRefused as refused:
            if refused.code == "remediation_option_held":
                return Response({"code": refused.code, "detail": refused.detail}, status=status.HTTP_409_CONFLICT)
            raise _refused(refused.code, refused.detail or str(refused)) from None
        except (engine_remediation.RemediationRefused, ParameterRefused, MoneyRefused) as refused:
            raise _refused(refused.code, refused.detail) from None
        except remediation_service._EngineCode as refused:
            raise _refused(refused.code, f"{refused.meaning} ({refused.detail})") from None
        return Response(
            _option_body(option, deployment, found),
            status=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        )


def _run_part(outcome) -> dict | None:
    if outcome is None or outcome.result is None:
        return None
    result = outcome.result
    return {
        "uuid": str(result.uuid),
        "created": outcome.created,
        "status": result.status,
        "seed": result.seed,
        "draws": result.draws,
        "severe_percentile": result.severe_percentile,
        "input_digest": result.input_digest,
        "result_digest": result.result_digest or None,
        "refusal": None if not result.refusal_code else {"code": result.refusal_code, "detail": result.refusal_detail},
    }


def _card_part(card, outcome) -> dict | None:
    if card is None:
        return None
    if card.card is None:
        return {"issued": False, "code": card.code, "detail": card.detail}
    return {"issued": True, "created": card.created, "grade": report.verified_grade(card.card, outcome.result),
            "digest": card.card.card_digest}


class MitigationSimulateView(APIView):
    """Run, or return, the current and the residual run of one remediation option."""

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [StrictJSONParser]

    @capacity.capped
    def post(self, request, uuid, scenario, option):
        deployment = _deployment(request, uuid)
        if not _may_write(request.user):
            raise PermissionDenied("Simulating a remediation option requires an admin or analyst role.")
        found = _scenario(deployment, scenario)
        held = get_object_or_404(RemediationOption.objects.filter(scenario=found, deployment=deployment), uuid=option)
        body = _body(request)
        if isinstance(body, dict) and "receipt" in body:
            raise _refused("field_unrecognised", "body: ['receipt']: a residual run is not receipted")
        seed, policy_name, _ = parse_simulate(body)
        policy = SIMULATION_POLICIES[policy_name]
        try:
            _currency.require_pinned()
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        from . import simulation_service

        runs = remediation_service.simulate_option(
            held, seed=seed, draws=policy["draws"], severe_percentile=policy["severe_percentile"],
            time_budget=REQUEST_BUDGET_SECONDS,
        )
        roi = reverse("deployment-economics-scenario-roi", kwargs={"uuid": deployment.uuid, "scenario": found.uuid})
        served = {
            "deployment": str(deployment.uuid),
            "scenario": str(found.uuid),
            "option": str(held.uuid),
            "created": runs.created,
            "policy": {"name": policy_name, "draws": policy["draws"],
                       "severe_percentile": str(policy["severe_percentile"])},
            "current": {"run": _run_part(runs.current), "validity_card": _card_part(runs.current_card, runs.current)},
            "residual": {"run": _run_part(runs.residual),
                         "validity_card": _card_part(runs.residual_card, runs.residual)},
            "roi": None if runs.residual is None or runs.residual.result is None
            else f"{roi}?simulation={runs.residual.result.uuid}",
        }
        if runs.code is not None:
            unavailable = runs.code in simulation_service.UNRECORDED
            return Response(
                {**served, "code": runs.code, "detail": runs.detail, "stage": runs.stage},
                status=status.HTTP_503_SERVICE_UNAVAILABLE if unavailable else status.HTTP_400_BAD_REQUEST,
            )
        if runs.overrun:
            return Response(
                {**served, "code": "time_over_budget",
                 "detail": f"the request's {REQUEST_BUDGET_SECONDS:g} s ran out before {', '.join(runs.overrun)}: "
                 "what was recorded stays; send the same request again to issue what is missing"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return Response(served, status=status.HTTP_201_CREATED if runs.created else status.HTTP_200_OK)


class RoiView(APIView):
    """The ROI document of a scenario version's remediation option."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid, scenario):
        deployment = _deployment(request, uuid)
        found = _scenario(deployment, scenario)
        residual = None
        named = request.query_params.get("simulation")
        if named is not None:
            try:
                wanted = _uuid.UUID(named)
            except ValueError:
                raise _refused("field_malformed", "simulation is a residual run's uuid") from None
            residual = get_object_or_404(
                SimulationResult.objects.filter(scenario=found, deployment=deployment, remediation__isnull=False),
                uuid=wanted,
            )
        try:
            document = remediation_service.roi_document(found, residual)
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        if document is None:
            return Response(
                {"detail": "The scenario has no remediation option with a residual run: record one and simulate it."},
                status=status.HTTP_404_NOT_FOUND,
            )
        return HttpResponse(report.canonical_bytes(document), content_type="application/json")


urlpatterns = [
    path(
        "deployments/<uuid:uuid>/economics/scenarios/<uuid:scenario>/mitigations/",
        MitigationsView.as_view(),
        name="deployment-economics-scenario-mitigations",
    ),
    path(
        "deployments/<uuid:uuid>/economics/scenarios/<uuid:scenario>/mitigations/<uuid:option>/simulate/",
        MitigationSimulateView.as_view(),
        name="deployment-economics-mitigation-simulate",
    ),
    path(
        "deployments/<uuid:uuid>/economics/scenarios/<uuid:scenario>/roi/",
        RoiView.as_view(),
        name="deployment-economics-scenario-roi",
    ),
]
