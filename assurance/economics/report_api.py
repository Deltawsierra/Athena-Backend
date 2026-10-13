"""The scenario endpoints and the report (MVP step 6; ``docs/economics/spec-v1.md``,
section 27).

Mounted under ``/api/assurance/`` by :mod:`assurance.urls`, GUARDED, in a guard of
its own: a fault here leaves these three routes unserved and nothing else -- not the
parameter-set or builder routes, not the URLconf, not a stop
(``tests/test_economics_report.py``, ``test_a_report_fault_never_takes_down_a_stop``).

- ``GET deployments/<uuid>/economics/scenarios/<scenario uuid>/``: the scenario
  version, every parameter it reads with its provenance, its validity (each
  simulation result with its grade) and its evidence as SPINE ids, never copies
  (:func:`assurance.economics.report.scenario_document`).
- ``POST deployments/<uuid>/economics/scenarios/<scenario uuid>/simulate/``: run, or
  return, a simulation of the scenario version with a seed and a simulation policy
  (:data:`SIMULATION_POLICIES`) over its source snapshot set (the parameter-set
  version its build names, the build, its own parameters), through
  :mod:`assurance.economics.simulation_service`: IDEMPOTENT, the same inputs return
  the stored result (200) and never run a second; a new one is 201. The result's
  Validity Card (step 8) and chart series are then issued, each once per result; and,
  where the body asks (``"receipt": true``) and the run completed, its Financial
  Exposure Receipt, signed by the engine. A run the engine refuses is recorded as its
  refusal, and served so. ONE deadline bounds the whole request
  (:data:`REQUEST_BUDGET_SECONDS`): the run, the card's analysis and the series share
  it, each given what remains; past it the request is 503 ``time_over_budget``, the
  stage that ran out records nothing, and the same request again issues what is
  missing.
- ``GET deployments/<uuid>/economics/scenarios/<scenario uuid>/results/``: the report
  JSON of one result (``?simulation=<uuid>``, else the scenario's latest), as
  canonical bytes carrying their own digest (:mod:`assurance.economics.report`).

Access is the parameter-set routes' (:mod:`assurance.economics.api`): a signed-in
account; a deployment the caller cannot see, or a scenario or result of another
deployment, is 404; only an admin or an analyst simulates, and a viewer reads. The
body is strict JSON of at most 64 KiB (413 on the declared length, and the parser
never reads past it). While economics cannot read its currency table, every route
answers 503 and records nothing; a run the engine cannot make now (it will not
import, the time budget, memory) is 503 too, and nothing is recorded.

None of these routes is a stop, and none reads or writes anything a stop or the
decision reads: each is in ``safety.stops.NOT_STOPS``. This module imports the
simulation, the card, the series and the receipt services only inside a view: nothing
Django loads at start imports them, or numpy.
"""

from __future__ import annotations

import time
import uuid as _uuid
from decimal import Decimal

from django.http import HttpResponse, QueryDict
from django.shortcuts import get_object_or_404
from django.urls import path, reverse
from rest_framework import permissions, status
from rest_framework.exceptions import PermissionDenied, UnsupportedMediaType, ValidationError
from rest_framework.response import Response
from rest_framework.views import APIView

from . import report
from .api import (
    MAX_BODY_BYTES,
    BodyTooLarge,
    StrictJSONParser,
    _deployment,
    _may_write,
    _table_unavailable,
)
from .engine import currency as _currency
from .engine import parameter_set as pset
from .engine.parameters import ParameterRefused
from .models import SIMULATION_COMPLETED, FinancialScenario, SimulationResult

#: The simulation policies a run is made under: the draws, and the percentile its
#: severe-but-plausible figure is (section 23.12). Named as the owner's
#: specification's scenario request names one (``standard_100k``).
SIMULATION_POLICIES = {
    "standard_100k": {"draws": 100_000, "severe_percentile": Decimal(95)},
    "quick_10k": {"draws": 10_000, "severe_percentile": Decimal(95)},
    "detailed_1m": {"draws": 1_000_000, "severe_percentile": Decimal(95)},
}
DEFAULT_POLICY = "standard_100k"
#: The largest seed: 2^64 - 1 (section 23.3).
MAX_SEED = 2**64 - 1
#: The most digits a seed sent as text may have: 2^64 - 1 has 20. A longer string is
#: refused before it is read as a number (review round 1, LOW-1).
MAX_SEED_DIGITS = 20
#: The one deadline of a simulate request (review round 1, LOW-5): step 7b's run
#: budget, shared by the run, the card's analysis and the series.
REQUEST_BUDGET_SECONDS = 120.0

_SIMULATE_REQUIRED = frozenset({"seed"})
_SIMULATE_OPTIONAL = frozenset({"policy", "receipt"})


def _refused(code: str, detail: str) -> ValidationError:
    return ValidationError({"code": code, "detail": detail})


def parse_simulate(body) -> tuple[int, str, bool]:
    """``(seed, policy, receipt)`` read exactly from a simulate request, or refused:
    the seed a whole number from 0 to 2^64 - 1, as a JSON integer or as decimal
    digits (``seed_malformed``); the policy one of :data:`SIMULATION_POLICIES`
    (``policy_unrecognised``); ``receipt`` true or false."""
    try:
        body = pset._object(body, "body", _SIMULATE_REQUIRED, _SIMULATE_OPTIONAL)
    except ParameterRefused as refused:
        raise _refused(refused.code, refused.detail) from None
    seed = body["seed"]
    if (
        isinstance(seed, str)
        and len(seed) <= MAX_SEED_DIGITS
        and seed.isascii()
        and seed.isdigit()
        and (seed == "0" or not seed.startswith("0"))
    ):
        try:
            seed = int(seed)
        except ValueError:
            raise _refused("seed_malformed", "seed is not a whole number") from None
    if isinstance(seed, bool) or not isinstance(seed, int) or not 0 <= seed <= MAX_SEED:
        raise _refused("seed_malformed", "seed is a whole number from 0 to 2^64 - 1, as an integer or its digits")
    policy = body.get("policy", DEFAULT_POLICY)
    if not isinstance(policy, str) or policy not in SIMULATION_POLICIES:
        raise _refused("policy_unrecognised", f"policy is one of {sorted(SIMULATION_POLICIES)}")
    receipt = body.get("receipt", False)
    if not isinstance(receipt, bool):
        raise _refused("field_malformed", "receipt is true or false")
    return seed, policy, receipt


def _scenario(deployment, scenario_uuid) -> FinancialScenario:
    return get_object_or_404(FinancialScenario.objects.filter(deployment=deployment), uuid=scenario_uuid)


def _engine_keyring():
    """The ReceiptKeyring of the engine's published economics-receipt keys, or the
    reason there is none (section 26.5): never raises. The reason is the error's type
    and, where it has one, its HTTP status, never its text, which may carry the
    engine's response body or its host (review round 1, LOW-2), as the signer's path
    reports it."""
    from . import receipt_service

    try:
        return receipt_service.engine_keyring(), ""
    except Exception as error:  # noqa: BLE001 - no keyring is a returned refusal: the receipt is not issued
        status = getattr(error, "status", None)
        return None, type(error).__name__ + ("" if status is None else f" (status {status})")


def _overrun(stage: str) -> dict:
    return {
        "code": "time_over_budget",
        "detail": f"the request's {REQUEST_BUDGET_SECONDS:g} s ran out before {stage}: nothing more was recorded; send "
        "the same request again to issue what is missing",
    }


def _issued(row, outcome, describe) -> dict:
    """What an issue gave: its ``row``, described, or the ``outcome``'s failure code."""
    if row is None:
        return {"issued": False, "code": outcome.code, "detail": outcome.detail}
    return {"issued": True, "created": outcome.created, **describe(row)}


class ScenarioView(APIView):
    """One scenario version: its parameters with provenance, validity and evidence."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid, scenario):
        deployment = _deployment(request, uuid)
        found = _scenario(deployment, scenario)
        try:
            served = report.scenario_document(found)
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        return Response({"deployment": str(deployment.uuid), **served})


class ScenarioSimulateView(APIView):
    """Run, or return, a simulation of one scenario version."""

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [StrictJSONParser]

    def post(self, request, uuid, scenario):
        deployment = _deployment(request, uuid)
        if not _may_write(request.user):
            raise PermissionDenied("Simulating a scenario requires an admin or analyst role.")
        found = _scenario(deployment, scenario)
        try:
            declared = int(request.META.get("CONTENT_LENGTH") or 0)
        except ValueError:
            raise ValidationError({"detail": "Content-Length is not a number"}) from None
        if declared > MAX_BODY_BYTES:
            raise BodyTooLarge()
        body = request.data
        if isinstance(body, QueryDict):
            raise UnsupportedMediaType(request.content_type)
        seed, policy_name, want_receipt = parse_simulate(body)
        policy = SIMULATION_POLICIES[policy_name]
        from . import charts_service, receipt_service, simulation_service, validity_service

        deadline = time.monotonic() + REQUEST_BUDGET_SECONDS

        def remaining() -> float:
            return deadline - time.monotonic()

        try:
            # Checked before anything runs: a run needs the table, and the service would
            # otherwise return its absence as a fault.
            _currency.require_pinned()
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        outcome = simulation_service.simulate_scenario(
            found, seed=seed, draws=policy["draws"], severe_percentile=policy["severe_percentile"],
            time_budget=remaining(),
        )
        if outcome.result is None:
            unavailable = outcome.code in simulation_service.UNRECORDED
            return Response(
                {"code": outcome.code, "detail": outcome.detail, "recorded": False},
                status=status.HTTP_503_SERVICE_UNAVAILABLE if unavailable else status.HTTP_400_BAD_REQUEST,
            )
        result = outcome.result
        # The card's analysis and the series share what remains of the one deadline; a
        # stage with nothing left is not started.
        card = (validity_service.issue_card(result, time_budget=remaining()) if remaining() > 0
                else validity_service.CardOutcome(None, False, **_overrun("the Validity Card")))
        charts = (charts_service.issue_charts(result, time_budget=remaining()) if remaining() > 0
                  else charts_service.ChartsOutcome(None, False, **_overrun("the chart series")))
        overrun = "time_over_budget" in (card.code, charts.code)
        if not want_receipt:
            receipt_part = {"issued": False, "code": None, "detail": "not asked: send \"receipt\": true to sign one"}
        elif result.status != SIMULATION_COMPLETED:
            # A refused run has no figures to sign: the engine's keyring is not fetched.
            receipt_part = {"issued": False, "code": "result_not_completed",
                            "detail": "a refused run has no figures to sign"}
        elif overrun:
            receipt_part = {"issued": False, **_overrun("the receipt")}
        else:
            keyring, why = _engine_keyring()
            receipt = (
                receipt_service.issue_receipt(result, keyring=keyring)
                if keyring is not None
                else receipt_service.ReceiptOutcome(None, False, "keyring_unavailable", why)
            )
            receipt_part = _issued(
                receipt.receipt, receipt, lambda row: {"receipt_id": row.receipt_id, "key_id": row.key_id}
            )
        snapshots = report.served_snapshots(found)
        results_url = reverse("deployment-economics-scenario-results", kwargs={"uuid": deployment.uuid,
                                                                              "scenario": found.uuid})
        served = {
            "deployment": str(deployment.uuid),
            "scenario": str(found.uuid),
            "created": outcome.created,
            "policy": {"name": policy_name, "draws": policy["draws"],
                       "severe_percentile": str(policy["severe_percentile"])},
            "simulation": {
                "uuid": str(result.uuid),
                "status": result.status,
                "seed": result.seed,
                "draws": result.draws,
                "severe_percentile": result.severe_percentile,
                "input_digest": result.input_digest,
                "result_digest": result.result_digest or None,
                "refusal": None if not result.refusal_code
                else {"code": result.refusal_code, "detail": result.refusal_detail},
            },
            "source_snapshots": snapshots,
            "validity_card": _issued(card.card, card, lambda row: {"grade": report.verified_grade(row, result),
                                                                   "digest": row.card_digest}),
            "charts": _issued(charts.charts, charts, lambda row: {"digest": row.charts_digest}),
            "receipt": receipt_part,
            "report": f"{results_url}?simulation={result.uuid}",
        }
        if overrun:
            # The one deadline ran out: what was not issued is recorded nowhere, and the
            # same request again returns the stored result and issues it.
            return Response(
                {
                    **served,
                    "code": "time_over_budget",
                    "detail": f"the request's {REQUEST_BUDGET_SECONDS:g} s ran out: the result is recorded, and what "
                    "was not issued is recorded nowhere; send the same request again to issue it",
                },
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return Response(served, status=status.HTTP_201_CREATED if outcome.created else status.HTTP_200_OK)


class ScenarioResultsView(APIView):
    """The report JSON of one of a scenario version's simulation results."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid, scenario):
        deployment = _deployment(request, uuid)
        found = _scenario(deployment, scenario)
        # The scenario's own runs only: a residual run under a remediation option is
        # never the scenario's exposure, and is served by the ROI route (section 28).
        results = SimulationResult.objects.filter(scenario=found, deployment=deployment, remediation__isnull=True)
        named = request.query_params.get("simulation")
        if named is not None:
            try:
                wanted = _uuid.UUID(named)
            except ValueError:
                raise _refused("field_malformed", "simulation is a result's uuid") from None
            result = get_object_or_404(results, uuid=wanted)
        else:
            result = results.order_by("-id").first()
            if result is None:
                return Response(
                    {"detail": "The scenario has no simulation result: simulate it first."},
                    status=status.HTTP_404_NOT_FOUND,
                )
        try:
            body = report.canonical_bytes(report.build_report(result))
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        return HttpResponse(body, content_type="application/json")


urlpatterns = [
    path(
        "deployments/<uuid:uuid>/economics/scenarios/<uuid:scenario>/",
        ScenarioView.as_view(),
        name="deployment-economics-scenario",
    ),
    path(
        "deployments/<uuid:uuid>/economics/scenarios/<uuid:scenario>/simulate/",
        ScenarioSimulateView.as_view(),
        name="deployment-economics-scenario-simulate",
    ),
    path(
        "deployments/<uuid:uuid>/economics/scenarios/<uuid:scenario>/results/",
        ScenarioResultsView.as_view(),
        name="deployment-economics-scenario-results",
    ),
]
