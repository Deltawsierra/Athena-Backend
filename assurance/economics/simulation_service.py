"""Simulating a stored scenario version (phase E2, MVP step 7b;
``docs/economics/spec-v1.md``, section 25.7): the thin Django half of
:mod:`assurance.economics.engine.scenario_simulation`.

:func:`simulate_scenario` loads one scenario version as the scenario engine reads
it (its loss events, each component recomputed from the parameters it cites; the
insurance policy of the parameter-set version it was built from; each cited
parameter's stated distribution; its frequency, the one the parameter-set version
states or, failing that, a parameter of its own), runs it, and records the run as a
:class:`~assurance.economics.models.SimulationResult`:

- **Idempotent.** A run's identity is its scenario version, the digest of its
  canonical inputs (every parameter's figures, source and stated distribution,
  every formula, the policy, the frequency, the rules and every version and
  limit), its seed and its draws. The same identity returns the row already
  recorded and runs nothing; every check of the row runs before its
  transaction, which only inserts, so two runs racing past that read are
  stopped by the unique constraint, and the later returns the first's row.
  Never a second.
- **A refusal is recorded too**, where the inputs decide it (a parameter with no
  admissible distribution, a formula without a twin, too many values to hold):
  the same inputs are refused the same way, and the row says why. A refusal the
  inputs do not decide (the time budget, memory, a defect) is returned and never
  recorded, so a later run of the same inputs is not refused by an accident.
- **Never raises.** Every failure, an import fault of numpy or the engine
  included, comes back as a :class:`SimulationOutcome` naming its code.
- **Bounded**: in draws and values by the engine's limits, and in time by
  :data:`TIME_BUDGET_SECONDS`, checked between the run's stages.
- **Its dependencies recorded** (E6, spec section 34.1): before an exposure run is
  made, what it depends on is read (:func:`assurance.economics.continuous_service.capture`:
  SPINE's claims and input fingerprints, the assets, findings and observed effects
  of its effects, its parameter-set version, its feed sources and the engine
  release), and recorded with the run once it completes, so a later read can say
  whether it is still current. A map that cannot be read or recorded never fails
  the run: the run then reads stale (``dependencies_unrecorded``). A residual run
  under a remediation option is never exposure and has none.

Nothing here is on a stop path, and nothing Django loads at start imports this
module or the engine; it imports the engine (and numpy) only when it is called.
No route serves it in this step: step 6 serves reports and scenario endpoints.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from django.db import IntegrityError, transaction
from django.utils import timezone

from . import run_normalization
from .models import (
    SIMULATION_COMPLETED,
    SIMULATION_REFUSED,
    EconomicsRefused,
    FinancialParameter,
    FinancialScenario,
    LossEvent,
    RemediationOption,
    ScenarioBuild,
    SimulationResult,
)

logger = logging.getLogger(__name__)

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


def remediation_of(option: RemediationOption):
    """A remediation option's control effect as a residual run reads it (spec,
    section 28): its id and digest, its reductions with their stated
    distributions, and what it acts on. An option whose stored document no longer
    holds to its form is refused (``remediation_record_malformed``)."""
    from .engine import remediation as engine_remediation

    _, money, ss, _ = _engine()
    try:
        parsed = option.option()
        stated = {name: ss.parse_stated(form, f"{name}.distribution") for name, form in parsed.distributions.items()}
    except (engine_remediation.RemediationRefused, ss.ScenarioSimulationRefused, money.MoneyRefused,
            ValueError) as refused:
        detail = f"{getattr(refused, 'code', type(refused).__name__)}: {getattr(refused, 'detail', '')}"
        raise EconomicsRefused("remediation_record_malformed", detail) from None
    return ss.Remediation(
        option_id=str(option.uuid),
        option_digest=option.option_digest,
        frequency_reduction=parsed.frequency_reduction,
        magnitude_reduction=parsed.magnitude_reduction,
        stated=stated,
        families=parsed.families,
        components=parsed.components,
    )


def load_input_of(result: SimulationResult):
    """The ``ScenarioInput`` a stored result was run on: its scenario version's, and,
    for a residual run, its remediation option's control effect with it."""
    scenario = FinancialScenario.objects.get(pk=result.scenario_id)
    option = None
    if result.remediation_id is not None:
        option = RemediationOption.objects.get(pk=result.remediation_id)
    return load_input(scenario, remediation=option)


def load_input(scenario: FinancialScenario, *, remediation: RemediationOption | None = None):
    """The scenario version as one run reads it (a ``ScenarioInput``): its events
    in key order, each component recomputed from the rows it cites; the policy of
    the parameter-set version it was built from; every cited row's stated
    distribution; each derived row's contributors (``derived_from``), with
    theirs; and the scenario's frequency: the one the parameter-set version it was
    built from states (spec, section 19.2), read as the policy is, or a parameter
    of its own named ``frequency``. Both is a conflict, refused (``duplicate_id``),
    never resolved by taking one. Every parameter is drawn once per simulated
    year: nothing here names one to be drawn per occurrence. A figure the build
    normalized (spec, section 36) is read as its normalized parameter, a policy term
    among them, and its record is in the input (``normalizations``). For a residual run,
    ``remediation`` is the option whose control effect it applies (spec, section
    28); every other input is exactly the current run's."""
    _, _, ss, _ = _engine()
    build_row = ScenarioBuild.objects.filter(scenario=scenario).first()
    events = tuple(row.as_engine() for row in LossEvent.objects.filter(scenario=scenario).order_by("event_key"))
    policy = None
    currency = build_row.currency if build_row is not None else (events[0].currency if events else "")
    if build_row is not None:
        policy = run_normalization.policy_of(build_row)
    frequency_row = FinancialParameter.objects.filter(scenario=scenario, name=ss.FREQUENCY_PARAMETER).first()
    if build_row is not None:
        stated_by_set = FinancialParameter.objects.filter(
            parameter_set_id=build_row.parameter_set_id, name=ss.FREQUENCY_PARAMETER
        ).first()
        if stated_by_set is not None:
            if frequency_row is not None:
                raise EconomicsRefused(
                    "duplicate_id",
                    "the scenario and the parameter-set version it was built from each state a frequency",
                )
            frequency_row = stated_by_set
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
    contributors = {
        str(row.uuid): row
        for row in FinancialParameter.objects.filter(
            scenario=scenario, uuid__in=sorted({u for row in rows for u in row.derived_from})
        )
    }
    derived = {}
    for row in rows:
        if row.derived_from:
            missing = [u for u in row.derived_from if u not in contributors]
            if missing:
                raise EconomicsRefused("parameter_not_found", f"{row.name} is derived from {missing}")
            derived[row.name] = tuple(contributors[u].as_engine() for u in row.derived_from)
    rows.extend(contributors.values())
    if frequency_row is not None:
        rows.append(frequency_row)
    stated = {row.name: row.stated_distribution() for row in rows if row.distribution is not None}
    if remediation is not None and remediation.scenario_id != scenario.pk:
        raise EconomicsRefused("cross_tenant_reference", "the option is another scenario version's")
    return ss.ScenarioInput(
        scenario_id=str(scenario.uuid),
        currency=currency,
        events=events,
        policy=policy,
        stated=stated,
        frequency=frequency,
        derived=derived,
        remediation=None if remediation is None else remediation_of(remediation),
        normalizations=run_normalization.normalization_records(scenario),
    )


def _existing(scenario, input_digest: str, seed: int, draws: int) -> SimulationResult | None:
    return SimulationResult.objects.filter(
        scenario=scenario, input_digest=input_digest, seed=str(seed), draws=draws
    ).first()


def _code(error) -> tuple[str, str]:
    return getattr(error, "code", "simulation_failed"), getattr(error, "detail", "") or str(error)


#: The refusals a pair of runs is checked for before either runs (spec, section 28.2).
BUDGET_REFUSALS = frozenset({"values_over_budget", "events_over_limit"})


def residual_unfit(scenario: FinancialScenario, option: RemediationOption, *, seed: int, draws: int
                   ) -> tuple[str, str] | None:
    """``(code, detail)`` where ``option``'s residual run of ``scenario`` with ``seed``
    and ``draws`` would not fit the engine's values or events budget -- checked before
    the current run is made, so a pair is refused whole and up front (nothing run,
    nothing recorded) -- else ``None``. Any other refusal, or a fault, is left to the
    runs themselves, which record or return it as step 7b does. Never raises."""
    try:
        _, _, ss, _ = _engine()
        ss.check_fits(load_input(scenario, remediation=option), seed=seed, draws=draws)
    except Exception as error:  # noqa: BLE001 - only a budget refusal is this check's to answer
        code = getattr(error, "code", None)
        if code in BUDGET_REFUSALS:
            return code, (
                f"the residual run would not fit ({error.detail}); it holds more values than its current run (its "
                "reduction factor, uniform draws and a reduction's draws per occurrence): choose a smaller policy. "
                "Nothing was run or recorded"
            )
        return None
    return None


def simulate_scenario(
    scenario: FinancialScenario,
    *,
    seed: int,
    draws: int | None = None,
    severe_percentile=None,
    time_budget: float = TIME_BUDGET_SECONDS,
    remediation: RemediationOption | None = None,
) -> SimulationOutcome:
    """Simulate ``scenario`` with ``seed`` and ``draws`` (the engine's default when
    not given), and record the run, or return the one recorded for the same
    inputs. With ``remediation``, the residual run of that option (spec, section
    28): the same seed, draws and streams, the option's control effect applied, its
    digest in the canonical inputs, and the option on the row. Never raises: see
    the module's rules."""
    try:
        return _simulate(scenario, seed, draws, severe_percentile, time_budget, remediation)
    except MemoryError:
        return SimulationOutcome(None, False, "memory_exhausted", "the run could not hold its values")
    except Exception as error:  # noqa: BLE001 - the service never raises: a fault is returned with its code
        return SimulationOutcome(None, False, "simulation_failed", f"{type(error).__name__}: {error}")


def _simulate(scenario, seed, draws, severe_percentile, time_budget, remediation=None) -> SimulationOutcome:
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
        si = load_input(scenario, remediation=remediation)
        inputs = ss.canonical_inputs(si, severe_percentile=severe)
    except refusals as refused:
        # Not recorded: without a valid seed, draws and inputs, a run has no identity.
        return SimulationOutcome(None, False, *_code(refused))
    input_digest = ss.digest_of(inputs)
    found = _existing(scenario, input_digest, seed, draws)
    if found is not None:
        return SimulationOutcome(found, False, found.refusal_code or None, found.refusal_detail)
    # What the run depends on, read BEFORE it runs: a change during the run then reads
    # as a change (E6). Never a residual run's: it is never exposure.
    captured = None if remediation is not None else _capture(scenario, inputs)

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
        remediation=remediation,
    )
    try:
        # Every check, the lookup of the same identity included, before the
        # transaction, which only inserts: a run that raced past both is stopped
        # by the unique constraint, and the first's row is returned.
        row.check_new()
        with transaction.atomic():
            row.insert_checked()
    except (IntegrityError, EconomicsRefused) as raced:
        if isinstance(raced, EconomicsRefused) and raced.code != "duplicate_id":
            raise
        found = _existing(scenario, input_digest, seed, draws)
        if found is None:
            raise
        return SimulationOutcome(found, False, found.refusal_code or None, found.refusal_detail)
    if captured is not None:
        _record_dependencies(row, captured)
    return SimulationOutcome(row, True, row.refusal_code or None, row.refusal_detail)


def _capture(scenario, inputs) -> tuple[dict, object] | None:
    """``(map, when it was read)`` of what a run of ``scenario`` on ``inputs``
    depends on, or ``None`` where it cannot be read: the run is then made and reads
    stale. Never raises."""
    try:
        from . import continuous_service

        captured_at = timezone.now()
        return continuous_service.capture(scenario, inputs), captured_at
    except Exception:  # noqa: BLE001 - a map that cannot be read never fails a run; the run reads stale
        logger.exception("the dependency map of a run of scenario %s could not be read", scenario.pk)
        return None


def _record_dependencies(row: SimulationResult, captured: tuple[dict, object]) -> None:
    """Record ``captured`` as ``row``'s dependency map. Never raises: a map that is
    not recorded leaves the run reading stale, never failed."""
    document, captured_at = captured
    try:
        from . import continuous_service

        continuous_service.record_dependencies(row, document, captured_at=captured_at)
    except Exception:  # noqa: BLE001 - a map that cannot be recorded never fails a run; the run reads stale
        logger.exception("the dependency map of simulation %s could not be recorded", row.pk)


__all__ = [
    "TIME_BUDGET_SECONDS",
    "UNRECORDED",
    "SimulationOutcome",
    "BUDGET_REFUSALS",
    "load_input",
    "load_input_of",
    "remediation_of",
    "residual_unfit",
    "simulate_scenario",
]
