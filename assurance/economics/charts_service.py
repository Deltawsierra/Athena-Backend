"""The chart-ready series of a stored simulation result (MVP step 6;
``docs/economics/spec-v1.md``, section 27.4): the thin Django half of
:mod:`assurance.economics.engine.charts`.

:func:`issue_charts` returns the series recorded for a completed result, or makes it
on the run's own draws -- the scenario version loaded as step 7b read it, its inputs
and its draws checked against the run's digests -- and records it as a
:class:`~assurance.economics.models.SimulationCharts`, once per result. The report
(:mod:`assurance.economics.report`) reads the stored series and never runs a
simulation to draw them.

A failure the stored rows do not decide (the engine will not import, the draws are
not reproduced on this platform, the time budget, memory, a fault) is returned with
its code and never recorded, so a later issue is not refused by an accident; a
refused run has no draws and no series (``result_not_completed``). **Never raises.**
Nothing here is on a stop path; nothing Django loads at start imports it, and it
imports the engine, and numpy, only when called.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from decimal import Decimal

from django.db import IntegrityError, transaction

from . import simulation_service
from .models import (
    SIMULATION_COMPLETED,
    EconomicsRefused,
    FinancialScenario,
    SimulationCharts,
    SimulationResult,
    canonical_digest,
)

#: The longest a series may take to make, checked between its stages: the run's own.
TIME_BUDGET_SECONDS = simulation_service.TIME_BUDGET_SECONDS

#: Every failure: none is recorded.
UNRECORDED = frozenset(
    {
        "result_not_completed",
        "engine_unavailable",
        "inputs_changed",
        "result_not_reproduced",
        "time_over_budget",
        "memory_exhausted",
        "invariant_broken",
        "charts_failed",
    }
)


@dataclass(frozen=True)
class ChartsOutcome:
    """What :func:`issue_charts` gives: the recorded series (``None`` when nothing
    was recorded), whether this call recorded it, and the failure's code and detail."""

    charts: SimulationCharts | None
    created: bool
    code: str | None = None
    detail: str = ""


def _engine():
    from .engine import charts, distributions, money, scenario_simulation, simulation

    return charts, distributions, money, scenario_simulation, simulation


def _code(error) -> tuple[str, str]:
    return getattr(error, "code", "charts_failed"), getattr(error, "detail", "") or str(error)


def issue_charts(result: SimulationResult, *, time_budget: float = TIME_BUDGET_SECONDS) -> ChartsOutcome:
    """The chart series of ``result``: the one recorded, or one made and recorded
    now. Never raises: see the module's rules."""
    try:
        return _issue(result, time_budget)
    except MemoryError:
        return ChartsOutcome(None, False, "memory_exhausted", "the series could not hold their values")
    except Exception as error:  # noqa: BLE001 - the service never raises: a fault is returned with its code
        return ChartsOutcome(None, False, "charts_failed", f"{type(error).__name__}: {error}")


def _issue(result: SimulationResult, time_budget: float) -> ChartsOutcome:
    found = SimulationCharts.objects.filter(simulation=result).first()
    if found is not None:
        return ChartsOutcome(found, False)
    if result.status != SIMULATION_COMPLETED:
        return ChartsOutcome(None, False, "result_not_completed", f"refused: {result.refusal_code}")
    try:
        charts, distributions, money, ss, sim = _engine()
    except Exception as error:  # noqa: BLE001 - an import fault of numpy or the engine is a returned refusal
        return ChartsOutcome(None, False, "engine_unavailable", f"{type(error).__name__}: {error}")
    clock = time.monotonic()

    def check_time(stage: str) -> None:
        if time.monotonic() - clock > time_budget:
            raise ss.ScenarioSimulationRefused("time_over_budget", f"past {time_budget} s at {stage}")

    refusals = (
        charts.ChartsRefused,
        ss.ScenarioSimulationRefused,
        sim.SimulationRefused,
        distributions.DistributionRefused,
        money.MoneyRefused,
        EconomicsRefused,
    )
    scenario = FinancialScenario.objects.get(pk=result.scenario_id)
    try:
        series = charts.series(
            simulation_service.load_input_of(result),
            seed=int(result.seed),
            draws=result.draws,
            severe_percentile=Decimal(result.severe_percentile),
            input_digest=result.input_digest,
            outcomes_sha256=result.record["outcomes_sha256"],
            check_time=check_time,
        )
    except refusals as refused:
        return ChartsOutcome(None, False, *_code(refused))
    except (sim.InvariantBroken, AssertionError) as broken:
        return ChartsOutcome(None, False, "invariant_broken", f"{type(broken).__name__}: {broken}")
    row = SimulationCharts(
        deployment_id=result.deployment_id,
        scenario=scenario,
        simulation=result,
        schema=charts.SCHEMA,
        charts=series,
        charts_digest=canonical_digest(series),
    )
    try:
        # Every check, the lookup of a series of the same result included, before the
        # transaction, which only inserts (as step 7b's result and step 8's card).
        row.check_new()
        with transaction.atomic():
            row.insert_checked()
    except (IntegrityError, EconomicsRefused) as raced:
        if isinstance(raced, EconomicsRefused) and raced.code != "duplicate_id":
            raise
        found = SimulationCharts.objects.filter(simulation=result).first()
        if found is None:
            raise
        return ChartsOutcome(found, False)
    return ChartsOutcome(row, True)


__all__ = ["TIME_BUDGET_SECONDS", "UNRECORDED", "ChartsOutcome", "issue_charts"]
