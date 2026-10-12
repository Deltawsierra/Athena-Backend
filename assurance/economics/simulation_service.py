"""Simulating a stored scenario version (phase E2, MVP step 7b;
``docs/economics/spec-v1.md``, section 25.7): the thin Django half of
:mod:`assurance.economics.engine.scenario_simulation`.

:func:`simulate_scenario` loads one scenario version as the scenario engine reads
it (its loss events, each component recomputed from the parameters it cites; the
insurance policy of the parameter-set version it was built from; each cited
parameter's stated distribution; its frequency parameter, if it holds one),
runs it, and records the run as a :class:`~assurance.economics.models.SimulationResult`:

- **Idempotent.** A run's identity is its scenario version, the digest of its
  canonical inputs (every parameter's figures, source and stated distribution,
  every formula, the policy, the frequency, the rules and every version), its
  seed and its draws. The same identity returns the row already recorded and
  runs nothing; two runs racing past that read are stopped by the unique
  constraint, and the later returns the first's row. Never a second.
- **A refusal is recorded too**, where the inputs decide it (a parameter with no
  admissible distribution, a formula without a twin, too many values to hold):
  the same inputs are refused the same way, and the row says why. A refusal the
  inputs do not decide (the time budget, memory, a defect) is returned and never
  recorded, so a later run of the same inputs is not refused by an accident.
- **Never raises.** Every failure, an import fault of numpy or the engine
  included, comes back as a :class:`SimulationOutcome` naming its code.
- **Bounded**: in draws and values by the engine's limits, and in time by
  :data:`TIME_BUDGET_SECONDS`, checked between the run's stages.

Nothing here is on a stop path, and nothing Django loads at start imports this
module or the engine; it imports the engine (and numpy) only when it is called.
No route serves it in this step: step 6 serves reports and scenario endpoints.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from django.db import IntegrityError, transaction
from django.utils import timezone

from .models import (
    SIMULATION_COMPLETED,
    SIMULATION_REFUSED,
    CustomerParameterSet,
    EconomicsRefused,
    FinancialParameter,
    FinancialScenario,
    LossEvent,
    ScenarioBuild,
    SimulationResult,
)

#: The longest a run may take, checked between its stages.
TIME_BUDGET_SECONDS = 120.0

#: Refusals the inputs do not decide: returned, never recorded.
UNRECORDED = frozenset(
    {"time_over_budget", "memory_exhausted", "invariant_broken", "engine_unavailable", "simulation_failed"}
)


@dataclass(frozen=True)
class SimulationOutcome:
    """What :func:`simulate_scenario` gives: the recorded result (``None`` when
    nothing was recorded), whether this call recorded it, and the refusal's code
    and detail where the run was refused or failed (``None`` when it completed)."""

    result: SimulationResult | None
    created: bool
    code: str | None = None
    detail: str = ""

    @property
    def completed(self) -> bool:
        return self.result is not None and self.result.status == SIMULATION_COMPLETED


def _engine():
    from .engine import distributions, money, scenario_simulation, simulation

    return distributions, money, scenario_simulation, simulation


def load_input(scenario: FinancialScenario):
    """The scenario version as one run reads it (a ``ScenarioInput``): its events
    in key order, each component recomputed from the rows it cites; the policy of
    the parameter-set version it was built from; every cited row's stated
    distribution; the parameter set's variables and policy terms as shared (drawn
    once per simulated year), the effects' attributes per occurrence; and the
    scenario's frequency parameter, if it holds one."""
    _, _, ss, _ = _engine()
    build_row = ScenarioBuild.objects.filter(scenario=scenario).first()
    events = tuple(row.as_engine() for row in LossEvent.objects.filter(scenario=scenario).order_by("event_key"))
    policy = None
    currency = build_row.currency if build_row is not None else (events[0].currency if events else "")
    if build_row is not None:
        policy = CustomerParameterSet.objects.get(pk=build_row.parameter_set_id).content().insurance_policy()
    frequency_row = FinancialParameter.objects.filter(scenario=scenario, name=ss.FREQUENCY_PARAMETER).first()
    frequency = frequency_row.as_engine() if frequency_row is not None else None

    cited = {
        cited.parameter.parameter_id
        for event in events
        for component in event.components
        for cited in component.inputs
        if cited.parameter.parameter_id
    }
    if policy is not None:
        terms = [policy.deductible, policy.limit, *policy.sublimits.values()]
        if policy.waiting_period_hours is not None:
            terms.append(policy.waiting_period_hours)
        cited.update(term.parameter_id for term in terms if term.parameter_id)
    rows = list(FinancialParameter.objects.filter(uuid__in=sorted(cited)))
    if frequency_row is not None:
        rows.append(frequency_row)
    stated = {}
    shared = set()
    for row in rows:
        if row.distribution is not None:
            stated[row.name] = row.stated_distribution()
        if row.parameter_set_id is not None or row.pk == getattr(frequency_row, "pk", None):
            shared.add(row.name)
    return ss.ScenarioInput(
        scenario_id=str(scenario.uuid),
        currency=currency,
        events=events,
        policy=policy,
        stated=stated,
        shared=frozenset(shared),
        frequency=frequency,
    )


def _existing(scenario, input_digest: str, seed: int, draws: int) -> SimulationResult | None:
    return SimulationResult.objects.filter(
        scenario=scenario, input_digest=input_digest, seed=str(seed), draws=draws
    ).first()


def _code(error) -> tuple[str, str]:
    return getattr(error, "code", "simulation_failed"), getattr(error, "detail", "") or str(error)


def simulate_scenario(
    scenario: FinancialScenario,
    *,
    seed: int,
    draws: int | None = None,
    severe_percentile=None,
    time_budget: float = TIME_BUDGET_SECONDS,
) -> SimulationOutcome:
    """Simulate ``scenario`` with ``seed`` and ``draws`` (the engine's default when
    not given), and record the run, or return the one recorded for the same
    inputs. Never raises: see the module's rules."""
    try:
        return _simulate(scenario, seed, draws, severe_percentile, time_budget)
    except MemoryError:
        return SimulationOutcome(None, False, "memory_exhausted", "the run could not hold its values")
    except Exception as error:  # noqa: BLE001 - the service never raises: a fault is returned with its code
        return SimulationOutcome(None, False, "simulation_failed", f"{type(error).__name__}: {error}")


def _simulate(scenario, seed, draws, severe_percentile, time_budget) -> SimulationOutcome:
    try:
        distributions, money, ss, sim = _engine()
    except Exception as error:  # noqa: BLE001 - an import fault of numpy or the engine is a returned refusal
        return SimulationOutcome(None, False, "engine_unavailable", f"{type(error).__name__}: {error}")
    refusals = (
        ss.ScenarioSimulationRefused,
        sim.SimulationRefused,
        distributions.DistributionRefused,
        money.MoneyRefused,
        EconomicsRefused,
    )
    draws = sim.DEFAULT_DRAWS if draws is None else draws
    severe_percentile = sim.DEFAULT_SEVERE_PERCENTILE if severe_percentile is None else severe_percentile
    try:
        sim.check_seed(seed)
        sim.check_draws(draws)
        severe = sim.check_severe_percentile(severe_percentile)
        si = load_input(scenario)
        inputs = ss.canonical_inputs(si, severe_percentile=severe)
    except refusals as refused:
        # Not recorded: without a valid seed, draws and inputs, a run has no identity.
        return SimulationOutcome(None, False, *_code(refused))
    input_digest = ss.digest_of(inputs)
    found = _existing(scenario, input_digest, seed, draws)
    if found is not None:
        return SimulationOutcome(found, False, found.refusal_code or None, found.refusal_detail)

    started_at = timezone.now()
    clock = time.monotonic()

    def check_time(stage: str) -> None:
        if time.monotonic() - clock > time_budget:
            raise ss.ScenarioSimulationRefused("time_over_budget", f"past {time_budget} s at {stage}")

    result = refusal = None
    try:
        result = ss.run(si, seed=seed, draws=draws, severe_percentile=severe, check_time=check_time)
    except refusals as refused:
        refusal = _code(refused)
    except (sim.InvariantBroken, AssertionError) as broken:
        return SimulationOutcome(None, False, "invariant_broken", f"{type(broken).__name__}: {broken}")
    if refusal is not None and refusal[0] in UNRECORDED:
        return SimulationOutcome(None, False, *refusal)
    finished_at = timezone.now()
    duration_ms = int(round((time.monotonic() - clock) * 1000))

    row = SimulationResult(
        deployment_id=scenario.deployment_id,
        scenario=scenario,
        seed=str(seed),
        draws=draws,
        severe_percentile=inputs["severe_percentile"],
        input_digest=input_digest,
        result_digest=result.digest if result is not None else "",
        status=SIMULATION_COMPLETED if result is not None else SIMULATION_REFUSED,
        refusal_code="" if refusal is None else refusal[0],
        refusal_detail="" if refusal is None else refusal[1],
        inputs=inputs,
        versions=inputs["versions"],
        summaries=None if result is None else SimulationResult.summaries_of(result.record),
        record=None if result is None else dict(result.record),
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=duration_ms,
    )
    try:
        with transaction.atomic():
            row.save()
    except (IntegrityError, EconomicsRefused) as raced:
        if isinstance(raced, EconomicsRefused) and raced.code != "duplicate_id":
            raise
        found = _existing(scenario, input_digest, seed, draws)
        if found is None:
            raise
        return SimulationOutcome(found, False, found.refusal_code or None, found.refusal_detail)
    return SimulationOutcome(row, True, row.refusal_code or None, row.refusal_detail)


__all__ = ["TIME_BUDGET_SECONDS", "UNRECORDED", "SimulationOutcome", "load_input", "simulate_scenario"]
