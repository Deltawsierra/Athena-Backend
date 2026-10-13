"""The scenario endpoints and the report (MVP step 6; ``docs/economics/spec-v1.md``,
section 27).

Mounted under ``/api/assurance/`` by :mod:`assurance.urls`, GUARDED, in a guard of
its own: a fault here leaves these eight routes unserved and nothing else -- not the
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
  missing. It runs only in one of the host's economics run slots
  (:mod:`assurance.economics.capacity`): when none is free it is answered at once,
  503 ``economics_capacity`` with ``Retry-After``, and nothing runs or is recorded.
- ``GET deployments/<uuid>/economics/scenarios/<scenario uuid>/results/``: the report
  JSON of one result (``?simulation=<uuid>``, else the scenario's latest), as
  canonical bytes carrying their own digest (:mod:`assurance.economics.report`), with
  the run's valuation date and its currency bridge (schema v2), answered ``no-store``.

The read routes the dashboard needs (section 30), each answered ``no-store``, its
query read strictly (an unknown key is ``field_unrecognised``, a repeated or
malformed one ``field_malformed``):

- ``GET deployments/<uuid>/economics/scenarios/?page=<n>&page_size=<n>``: the
  deployment's scenario versions in record order, :data:`SCENARIO_PAGE_SIZE` a page
  unless the request names up to :data:`SCENARIO_PAGE_SIZE_MAX`, each with its
  templates, its latest EXPOSURE run's status (a residual run is never listed) and
  that run's grade, banner and ``excluded_from_totals`` (:func:`report.scenario_entry`).
- ``GET deployments/<uuid>/economics/receipts/<receipt id>/``: a Financial Exposure
  Receipt's signed DSSE envelope, as stored, in its canonical spelling, as a download
  (``attachment``, ``nosniff``) with the SHA-256 of the bytes in ``X-Content-SHA256``.
  The receipt id is the one the report and the scenario document name, in its dashed
  form. A receipt of another deployment (tenant) is 404, and so is one of a residual
  run (none exists). Nothing is signed, verified or re-encoded: the reader verifies the
  envelope against the engine's published economics-receipt keys.

Continuous financial assurance (E6, section 34), on the same conventions:

- ``GET deployments/<uuid>/economics/scenarios/<scenario uuid>/freshness/``: one
  run's freshness in full (``?simulation=<uuid>``, else the version's latest exposure
  run): what it was recorded as depending on, current or stale and why, its refresh
  obligations and what superseded it, and what a refresh must refresh now. Every role
  reads; it writes nothing.
- ``GET deployments/<uuid>/economics/assurance/``: every current scenario version's
  latest exposure run, current or stale, and every open refresh obligation. ``POST``
  (admin or analyst) runs the check: each stale current run is recorded with the
  refresh it owes. It runs no Monte Carlo and takes no run slot; it holds no
  transaction while it reads, and inserts each row in a short one of its own.
- ``POST deployments/<uuid>/economics/scenarios/<scenario uuid>/refresh/``: the one
  way a stale run is recomputed, and only when an analyst asks: the stale version is
  rebuilt from its parameter set's current version as of ``as_of`` (today, UTC,
  unless the body names one), superseding it; the rebuilt version is run under the
  body's seed and policy, carded, charted and, where ``"receipt": true``, receipted;
  and the version's open obligations close only when the new run stands. A Monte
  Carlo route: capped (:mod:`.capacity`), one deadline, as the simulate route. A
  version with nothing stale is 409 ``exposure_current`` and runs nothing.

The receipt route says whether the receipt's run is current, in headers beside the
bytes it serves unchanged (``X-Exposure-Freshness``, ``X-Exposure-Stale-Reasons``,
``X-Exposure-Superseded-By-Run``, ``X-Exposure-Superseded-By-Receipt``); the report,
the list and the events route say it in their banner (:mod:`.report`).

Access is the parameter-set routes' (:mod:`assurance.economics.api`): a signed-in
account; a deployment the caller cannot see, or a scenario or result of another
deployment, is 404; only an admin or an analyst simulates, and a viewer reads. The
body is strict JSON of at most 64 KiB (413 on the declared length, and the parser
never reads past it). While economics cannot read its currency table, every route
answers 503 and records nothing; a run the engine cannot make now (it will not
import, the time budget, memory) is 503 too, and nothing is recorded.

None of these routes is a stop, and none reads or writes anything a stop or the
decision reads: each is in ``safety.stops.NOT_STOPS``. The reads hold no lock and open
no transaction: a Stop is answered while one is held open mid-read
(``tests/test_economics_read_routes.py``). This module imports the
simulation, the card, the series and the receipt services only inside a view: nothing
Django loads at start imports them, or numpy.
"""

from __future__ import annotations

import hashlib
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

from . import capacity, report
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
from .engine.money import MoneyRefused
from .engine.parameters import ParameterRefused
from .models import SIMULATION_COMPLETED, FinancialExposureReceipt, FinancialScenario, SimulationResult

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
#: budget, shared by the run, the card's analysis and the series. How many such
#: requests run at once is capped too, without waiting (:mod:`.capacity`).
REQUEST_BUDGET_SECONDS = 120.0
#: The scenario versions a page of the list holds unless the request names another
#: size, and the most it may name (section 30): a larger page is refused, never cut
#: short.
SCENARIO_PAGE_SIZE = 25
SCENARIO_PAGE_SIZE_MAX = 100
#: The most digits a page number or a page size may be written with: a longer one is
#: refused before it is read as a number.
MAX_QUERY_DIGITS = 9
#: What every answer of the read routes the dashboard needs carries (section 30), and
#: the report and the ROI document too: a tenant's figures and signed receipts are
#: never kept by a cache on the way.
NO_STORE = "no-store"

_SIMULATE_REQUIRED = frozenset({"seed"})
_SIMULATE_OPTIONAL = frozenset({"policy", "receipt"})
#: A refresh's body: a simulate request's, and the as-of date the version is rebuilt
#: at (E6, section 34.4).
_REFRESH_OPTIONAL = frozenset({"as_of"})


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


def parse_refresh(body, today) -> tuple[int, str, bool, object]:
    """``(seed, policy, receipt, as_of)`` read exactly from a refresh request: a
    simulate request's fields (:func:`parse_simulate`) and ``as_of``, a ``YYYY-MM-DD``
    date no later than ``today`` (default ``today``)."""
    if not isinstance(body, dict):
        raise _refused("field_malformed", "body is not an object")
    as_of = today
    if "as_of" in body:
        try:
            as_of = pset._date(body["as_of"], "as_of")
        except MoneyRefused as refused:
            raise _refused(refused.code, refused.detail) from None
        if as_of > today:
            raise _refused("field_malformed", "as_of is a date no later than today (UTC)")
    seed, policy, receipt = parse_simulate({key: value for key, value in body.items() if key not in _REFRESH_OPTIONAL})
    return seed, policy, receipt, as_of


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

    @capacity.capped
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
        results = SimulationResult.objects.exposure_runs().filter(scenario=found, deployment=deployment)
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
        return HttpResponse(body, content_type="application/json", headers={"Cache-Control": NO_STORE})


# ------------------------------------------------------------------ the read routes the dashboard needs


def _strict_query(request, allowed: tuple[str, ...]) -> dict[str, str]:
    """The query string read strictly (section 30): only the keys ``allowed``
    (``field_unrecognised`` otherwise), each given once (``field_malformed``)."""
    query = request.query_params
    unknown = sorted(set(query) - set(allowed))
    if unknown:
        raise _refused("field_unrecognised", f"query: {unknown}: this route reads only {list(allowed)}")
    for key in query:
        if len(query.getlist(key)) != 1:
            raise _refused("field_malformed", f"{key} is given once")
    return {key: query[key] for key in query}


def _whole(query: dict[str, str], key: str, default: int, most: int) -> int:
    """``query[key]`` read as a whole number from 1 to ``most``: ASCII digits, no sign
    and no leading zero, at most :data:`MAX_QUERY_DIGITS` of them; ``default`` where
    the key is absent; refused otherwise (``field_malformed``)."""
    text = query.get(key)
    if text is None:
        return default
    if (
        0 < len(text) <= MAX_QUERY_DIGITS
        and text.isascii()
        and text.isdigit()
        and not text.startswith("0")
        and int(text) <= most
    ):
        return int(text)
    raise _refused("field_malformed", f"{key} is a whole number from 1 to {most}")


class ScenarioListView(APIView):
    """A deployment's scenario versions, a page at a time, each with its templates and
    its latest exposure run's status, grade and exclusion from totals."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid):
        deployment = _deployment(request, uuid)
        query = _strict_query(request, ("page", "page_size"))
        size = _whole(query, "page_size", SCENARIO_PAGE_SIZE, SCENARIO_PAGE_SIZE_MAX)
        page = _whole(query, "page", 1, 10**MAX_QUERY_DIGITS - 1)
        versions = FinancialScenario.objects.filter(deployment=deployment)
        count = versions.count()
        start = (page - 1) * size
        rows = list(versions.select_related("supersedes").order_by("id")[start:start + size])
        templates = report.templates_of(rows)
        from . import continuous_service

        # What holds now, read once for the page (E6): each entry's freshness reads it.
        now = continuous_service.Now(deployment.pk)
        pages = -(-count // size)
        response = Response(
            {
                "deployment": str(deployment.uuid),
                "count": count,
                "page": page,
                "page_size": size,
                "pages": pages,
                "previous": page - 1 if page > 1 else None,
                "next": page + 1 if page < pages else None,
                "scenarios": [report.scenario_entry(row, templates.get(row.pk, []), now=now) for row in rows],
                "statement": "every scenario version of the deployment, in record order; each with its latest "
                "exposure run (a residual run under a remediation option is never one) and that run's standing under "
                "the report's banner rule, current or stale",
            }
        )
        response["Cache-Control"] = NO_STORE
        return response


class ReceiptView(APIView):
    """A Financial Exposure Receipt's signed DSSE envelope, as stored, as a download."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid, receipt):
        deployment = _deployment(request, uuid)
        _strict_query(request, ())
        # The tenant's own receipt, of a scenario's own run: a residual run is never
        # receipted (the service and the row refuse one), and is never served as one.
        row = (
            FinancialExposureReceipt.objects.filter(
                deployment=deployment, receipt_id=receipt.hex, simulation__remediation__isnull=True
            )
            .order_by("id")
            .first()
        )
        if row is None:
            return Response({"detail": "The deployment has no such receipt."}, status=status.HTTP_404_NOT_FOUND)
        # The envelope the signer returned and the row stores, in its one canonical
        # spelling: nothing is signed, verified or re-encoded here.
        body = report.canonical_bytes(row.envelope)
        response = HttpResponse(body, content_type="application/json")
        response["X-Content-Type-Options"] = "nosniff"
        response["Content-Disposition"] = f'attachment; filename="financial-exposure-receipt-{row.receipt_id}.json"'
        response["X-Content-SHA256"] = "sha256:" + hashlib.sha256(body).hexdigest()
        response["Cache-Control"] = NO_STORE
        # Whether its run is current (E6): beside the signed bytes, never in them.
        from . import continuous_service

        for name, value in continuous_service.receipt_headers(row).items():
            response[name] = value
        return response


# ------------------------------------------------------------------ continuous financial assurance (E6)


class ScenarioFreshnessView(APIView):
    """One run's freshness in full: its dependency map, its state and reasons, its
    obligations and what superseded it."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid, scenario):
        deployment = _deployment(request, uuid)
        found = _scenario(deployment, scenario)
        query = _strict_query(request, ("simulation",))
        from . import continuous_service

        result = None
        if "simulation" in query:
            try:
                wanted = _uuid.UUID(query["simulation"])
            except ValueError:
                raise _refused("field_malformed", "simulation is a result's uuid") from None
            result = get_object_or_404(
                SimulationResult.objects.exposure_runs().filter(scenario=found, deployment=deployment), uuid=wanted
            )
        try:
            served = continuous_service.scenario_freshness(found, result)
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        response = Response({"deployment": str(deployment.uuid), **served})
        response["Cache-Control"] = NO_STORE
        return response


class AssuranceView(APIView):
    """The deployment's exposure, current or stale (GET), and the check that records
    each stale run with the refresh it owes (POST). Runs no Monte Carlo."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid):
        deployment = _deployment(request, uuid)
        _strict_query(request, ())
        from . import continuous_service

        try:
            served = continuous_service.overview(deployment)
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        response = Response(served)
        response["Cache-Control"] = NO_STORE
        return response

    def post(self, request, uuid):
        deployment = _deployment(request, uuid)
        if not _may_write(request.user):
            raise PermissionDenied("Checking the deployment's exposure requires an admin or analyst role.")
        _strict_query(request, ())
        from . import continuous_service

        try:
            served = continuous_service.check(deployment)
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        response = Response({"deployment": str(deployment.uuid), **served})
        response["Cache-Control"] = NO_STORE
        return response


class ScenarioRefreshView(APIView):
    """Refresh a stale scenario version: rebuild, run, card and receipt it, and close
    its obligations once the new run stands."""

    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [StrictJSONParser]

    @capacity.capped
    def post(self, request, uuid, scenario):
        deployment = _deployment(request, uuid)
        if not _may_write(request.user):
            raise PermissionDenied("Refreshing a scenario requires an admin or analyst role.")
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
        from django.db import IntegrityError

        from . import builder, charts_service, continuous_service, receipt_service, simulation_service, validity_service
        from .api import _engine_unavailable
        from .engine.parameter_set import ProbabilisticEngineUnavailable
        from .models import EconomicsRefused

        seed, policy_name, want_receipt, as_of = parse_refresh(body, continuous_service._today())
        policy = SIMULATION_POLICIES[policy_name]
        deadline = time.monotonic() + REQUEST_BUDGET_SECONDS

        def remaining() -> float:
            return deadline - time.monotonic()

        try:
            _currency.require_pinned()
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        try:
            prepared = continuous_service.prepare_refresh(found, as_of=as_of)
        except continuous_service.RefreshRefused as refused:
            return Response({"code": refused.code, "detail": refused.detail, "recorded": False},
                            status=refused.status)
        try:
            rebuilt, rebuilt_now = builder.build(deployment, prepared.body, author=request.user)
        except (EconomicsRefused, MoneyRefused) as refused:
            raise _refused(refused.code, refused.detail or str(refused)) from None
        except IntegrityError:
            return Response(
                {"detail": "A build of the same inputs was recorded at the same moment; send the refresh again."},
                status=status.HTTP_409_CONFLICT,
            )
        except _currency.CurrencyTableInvalid:
            return _table_unavailable()
        except ProbabilisticEngineUnavailable:
            return _engine_unavailable()
        outcome = simulation_service.simulate_scenario(
            rebuilt, seed=seed, draws=policy["draws"], severe_percentile=policy["severe_percentile"],
            time_budget=remaining(),
        )
        rebuilt_part = {"scenario": str(rebuilt.uuid), "created": rebuilt_now,
                        "supersedes": None if rebuilt.supersedes_id is None else str(rebuilt.supersedes.uuid)}
        if outcome.result is None:
            unavailable = outcome.code in simulation_service.UNRECORDED
            return Response(
                {"code": outcome.code, "detail": outcome.detail, "recorded": False, "rebuilt": rebuilt_part},
                status=status.HTTP_503_SERVICE_UNAVAILABLE if unavailable else status.HTTP_400_BAD_REQUEST,
            )
        result = outcome.result
        if result.pk == prepared.stale.pk:
            return Response(
                {"code": "refresh_same_run", "recorded": False, "rebuilt": rebuilt_part,
                 "detail": "the rebuild and the run are the stale run's own (nothing it is built from moved, and the "
                 "seed is the same): send another seed or as_of"},
                status=status.HTTP_409_CONFLICT,
            )
        card = (validity_service.issue_card(result, time_budget=remaining()) if remaining() > 0
                else validity_service.CardOutcome(None, False, **_overrun("the Validity Card")))
        charts = (charts_service.issue_charts(result, time_budget=remaining()) if remaining() > 0
                  else charts_service.ChartsOutcome(None, False, **_overrun("the chart series")))
        overrun = "time_over_budget" in (card.code, charts.code)
        receipt_row = None
        if not want_receipt:
            receipt_part = {"issued": False, "code": None, "detail": "not asked: send \"receipt\": true to sign one"}
        elif result.status != SIMULATION_COMPLETED:
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
            receipt_row = receipt.receipt
            receipt_part = _issued(
                receipt.receipt, receipt, lambda row: {"receipt_id": row.receipt_id, "key_id": row.key_id}
            )
        if result.status != SIMULATION_COMPLETED:
            closures, why_open = [], f"the new run was refused ({result.refusal_code}): it has no figures"
        elif overrun:
            closures, why_open = [], "the request's deadline ran out before the new run was carded"
        else:
            closures, why_open = continuous_service.close_obligations(
                found, result, card.card, receipt_row, author=request.user
            )
        still_open = [str(row.uuid) for row in continuous_service.open_obligations(found)]
        results_url = reverse("deployment-economics-scenario-results", kwargs={"uuid": deployment.uuid,
                                                                              "scenario": rebuilt.uuid})
        served = {
            "deployment": str(deployment.uuid),
            "scenario": str(found.uuid),
            "stale_simulation": str(prepared.stale.uuid),
            "refresh": prepared.obligations[-1].refresh if prepared.obligations else None,
            "rebuilt": rebuilt_part,
            "created": outcome.created,
            "policy": {"name": policy_name, "draws": policy["draws"],
                       "severe_percentile": str(policy["severe_percentile"])},
            "simulation": {
                "uuid": str(result.uuid),
                "status": result.status,
                "seed": result.seed,
                "draws": result.draws,
                "input_digest": result.input_digest,
                "result_digest": result.result_digest or None,
                "refusal": None if not result.refusal_code
                else {"code": result.refusal_code, "detail": result.refusal_detail},
            },
            "validity_card": _issued(card.card, card, lambda row: {"grade": report.verified_grade(row, result),
                                                                   "digest": row.card_digest}),
            "charts": _issued(charts.charts, charts, lambda row: {"digest": row.charts_digest}),
            "receipt": receipt_part,
            "obligations": {
                "closed": [continuous_service.closure_document(row) for row in closures],
                "open": still_open,
                "why_open": None if not still_open else why_open,
            },
            "report": f"{results_url}?simulation={result.uuid}",
        }
        if overrun:
            return Response(
                {**served, "code": "time_over_budget",
                 "detail": f"the request's {REQUEST_BUDGET_SECONDS:g} s ran out: the run is recorded, and what was not "
                 "issued is recorded nowhere; send the same refresh again to issue it and close the obligations"},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
            )
        return Response(served, status=status.HTTP_201_CREATED if outcome.created else status.HTTP_200_OK)


urlpatterns = [
    path(
        "deployments/<uuid:uuid>/economics/scenarios/",
        ScenarioListView.as_view(),
        name="deployment-economics-scenarios",
    ),
    path(
        "deployments/<uuid:uuid>/economics/receipts/<uuid:receipt>/",
        ReceiptView.as_view(),
        name="deployment-economics-receipt",
    ),
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
    # Continuous financial assurance (E6, section 34).
    path(
        "deployments/<uuid:uuid>/economics/assurance/",
        AssuranceView.as_view(),
        name="deployment-economics-assurance",
    ),
    path(
        "deployments/<uuid:uuid>/economics/scenarios/<uuid:scenario>/freshness/",
        ScenarioFreshnessView.as_view(),
        name="deployment-economics-scenario-freshness",
    ),
    path(
        "deployments/<uuid:uuid>/economics/scenarios/<uuid:scenario>/refresh/",
        ScenarioRefreshView.as_view(),
        name="deployment-economics-scenario-refresh",
    ),
]
