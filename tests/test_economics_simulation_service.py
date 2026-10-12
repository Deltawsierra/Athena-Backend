"""The simulation service and its stored result (MVP step 7b;
``docs/economics/spec-v1.md``, sections 25.6 and 25.7).

- a stored scenario version is loaded as the scenario engine reads it, simulated
  and recorded once: the same inputs, seed and draws return the row already
  recorded, under a race too, and the database holds it;
- a refusal the inputs decide is recorded and returned the same way; one they do
  not decide (time, memory, a fault, an import fault) is returned, never recorded,
  and the service never raises;
- a parameter's stated distribution is checked when its row is written;
- the result holds no float, both digests are recomputed on save, and a recorded
  result is never rewritten;
- five findings on one effect make one event in the simulation too.
"""

from __future__ import annotations

import hashlib
import uuid
from datetime import date
from decimal import Decimal

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, models, transaction

from assurance.economics import builder, simulation_service
from assurance.economics.engine import scenario_simulation as ss
from assurance.economics.engine import simulation as sim
from assurance.economics.models import (
    CustomerParameterSet,
    EconomicsRefused,
    EconomicsRewriteRefused,
    EngineRefused,
    FinancialParameter,
    FinancialScenario,
    LossComponent,
    LossEvent,
    ScenarioBuild,
    SimulationResult,
)
from assurance.models import Asset, Deployment, Finding
from tests.test_economics_scenarios import _entry

pytestmark = pytest.mark.django_db
User = get_user_model()
AS_OF = date(2026, 10, 6)
LABEL = "SYNTHETIC / ILLUSTRATIVE"
SET_KEY = "bank_prod_2026q4"
GAMMA = {"id": "gamma", "version": 1, "params": {"shape": "4", "scale": "25000"}}
POISSON = {"id": "poisson", "version": 1, "params": {"rate": "2"}}


@pytest.fixture
def people():
    return {
        "analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
        "owner": User.objects.create_user(username="vic", password="x", role="viewer"),
        "other": User.objects.create_user(username="oto", password="x", role="viewer"),
    }


@pytest.fixture
def deployment(people):
    return Deployment.objects.create(name="payments-agent", owner=people["owner"])


def _parameter(scenario, name, unit, low, base=None, high=None, *, source="EXPERT_ESTIMATE", distribution=None):
    base = low if base is None else base
    high = base if high is None else high
    return FinancialParameter.objects.create(
        scenario=scenario,
        name=name,
        unit=unit,
        source_type=source,
        currency="USD" if unit.startswith("money") else "",
        low=low,
        base=base,
        high=high,
        evidence_ref=f"{LABEL}: made up",
        effective_date=date(2026, 9, 1),
        distribution=distribution,
    )


def _stored(deployment, author, *, regulatory=GAMMA, policy=False, frequency=None, version=1):
    """A scenario version as rows: one event of two components (notification and a
    regulatory lump sum) reading two set variables and two scenario parameters,
    and its build record naming the parameter-set version."""
    variables = {
        "notification_unit_cost": _entry("money_per_unit", "2"),
        "notification_fixed_cost": _entry("money", "40000"),
    }
    if policy:
        variables["insurance_deductible"] = _entry("money", "100000")
        variables["insurance_limit"] = _entry("money", "1000000")
        variables["insurance_waiting_period_hours"] = _entry("hours", "0")
    pset = CustomerParameterSet.record(deployment, SET_KEY, {"variables": variables}, author=author)
    assert pset.version == version
    scenario = FinancialScenario.objects.create(deployment=deployment, title="Cross-customer exposure", author=author)
    affected = _parameter(scenario, "exposure.affected_customers", "count", "20000", "50000", "120000")
    amount = _parameter(scenario, "exposure.regulatory_response_cost", "money", "0", "100000", "500000",
                        source="CUSTOMER_PROVIDED", distribution=regulatory)
    if frequency is not None:
        _parameter(scenario, ss.FREQUENCY_PARAMETER, "count", "1", "2", "4", source="INDUSTRY_BENCHMARK",
                   distribution=frequency)
    rows = {row.name: row for row in pset.parameter_rows()}
    event = LossEvent.objects.create(scenario=scenario, event_key="ev-exposure", currency="USD")
    LossComponent.objects.create(
        loss_event=event, component_key="notification", family="notification", formula_id="per_affected_plus_fixed",
        formula_version=1, as_of=AS_OF,
        cited_parameters={"affected": str(affected.uuid), "unit_cost": str(rows["notification_unit_cost"].uuid),
                          "fixed_cost": str(rows["notification_fixed_cost"].uuid)},
    )
    LossComponent.objects.create(
        loss_event=event, component_key="regulatory", family="regulatory_compliance", formula_id="lump_sum",
        formula_version=1, as_of=AS_OF, cited_parameters={"amount": str(amount.uuid)},
    )
    ScenarioBuild.objects.create(
        scenario=scenario, deployment=deployment, parameter_set=pset,
        build_digest="sha256:" + hashlib.sha256(str(scenario.uuid).encode()).hexdigest(),
        builder_version="test-fixture", grouping_version="test-fixture", pack="test-fixture", currency="USD",
        as_of=AS_OF, inputs={"fixture": str(scenario.uuid)},
    )
    return scenario


# ======================================================================
# Simulated and recorded once
# ======================================================================


def test_a_scenario_version_is_simulated_and_recorded_once(deployment, people):
    scenario = _stored(deployment, people["analyst"])
    outcome = simulation_service.simulate_scenario(scenario, seed=7, draws=20_000)
    assert outcome.completed and outcome.created and outcome.code is None, (outcome.code, outcome.detail)
    row = outcome.result
    row.refresh_from_db()
    assert (row.seed, row.draws, row.status, row.refusal_code) == ("7", 20_000, "completed", "")
    assert row.deployment_id == deployment.pk and row.scenario_id == scenario.pk
    assert row.result_digest == ss.digest_of(row.record) and row.input_digest == ss.digest_of(row.inputs)
    assert row.versions["numpy"] and row.versions["sampler"] == sim.SAMPLER_VERSION
    assert row.versions["formulas"] == ["lump_sum/1", "per_affected_plus_fixed/1"]
    assert row.summaries == {"scenario": row.record["scenario"], "events": row.record["events"]}
    assert Decimal(row.summaries["scenario"]["gross_cash"]["p50"]) > 0
    assert row.started_at <= row.finished_at and row.duration_ms >= 0
    # The figures are the pure engine's, from the inputs as loaded.
    again = ss.run(simulation_service.load_input(scenario), seed=7, draws=20_000)
    assert again.digest == row.result_digest

    for _ in range(2):
        repeat = simulation_service.simulate_scenario(scenario, seed=7, draws=20_000)
        assert repeat.result.pk == row.pk and repeat.created is False
    assert SimulationResult.objects.count() == 1
    other_seed = simulation_service.simulate_scenario(scenario, seed=8, draws=20_000)
    other_draws = simulation_service.simulate_scenario(scenario, seed=7, draws=21_000)
    assert other_seed.created and other_draws.created
    assert other_seed.result.input_digest == row.input_digest and other_seed.result.result_digest != row.result_digest
    assert SimulationResult.objects.count() == 3


def test_every_parameter_is_drawn_once_a_year_and_the_policy_applies_per_event(deployment, people):
    scenario = _stored(deployment, people["analyst"], policy=True, frequency=POISSON)
    outcome = simulation_service.simulate_scenario(scenario, seed=3, draws=10_000)
    assert outcome.completed, (outcome.code, outcome.detail)
    record = outcome.result.record
    parameters = record["parameters"]
    assert parameters["notification_unit_cost"]["variation"] == ss.SHARED
    assert parameters["insurance_deductible"]["variation"] == ss.SHARED
    # An effect's attribute too: a range is uncertainty about the figure (section 25.2).
    assert parameters["exposure.affected_customers"]["variation"] == ss.SHARED
    assert parameters["exposure.affected_customers"]["rule"] == ss.RULE_PERT_DEFAULT
    assert parameters["exposure.regulatory_response_cost"]["rule"] == ss.RULE_STATED
    assert record["basis"] == "annual_loss" and record["frequency"]["distribution"]["id"] == "poisson"
    scenario_record = record["scenario"]
    assert scenario_record["headline"] == "retained_cash"
    assert scenario_record["retained_cash"]["expected_annual_exposure"] == scenario_record["retained_cash"]["mean"]
    assert Decimal(scenario_record["retained_cash"]["mean"]) <= Decimal(scenario_record["gross_cash"]["mean"])
    assert record["events"][0]["insurance"] == "applied to this event, once per occurrence"


def test_a_refusal_the_inputs_decide_is_recorded_and_returned_the_same_way(deployment, people):
    scenario = _stored(deployment, people["analyst"], regulatory=None)
    outcome = simulation_service.simulate_scenario(scenario, seed=1, draws=1_000)
    assert outcome.created and not outcome.completed
    assert outcome.code == "no_admissible_distribution"
    assert "exposure.regulatory_response_cost" in outcome.detail
    row = outcome.result
    assert (row.status, row.result_digest, row.record, row.summaries) == ("refused", "", None, None)
    again = simulation_service.simulate_scenario(scenario, seed=1, draws=1_000)
    assert again.result.pk == row.pk and again.created is False and again.code == "no_admissible_distribution"
    assert SimulationResult.objects.count() == 1


def test_a_race_past_the_lookup_returns_the_first_row_and_writes_no_second(deployment, people, monkeypatch):
    scenario = _stored(deployment, people["analyst"])
    first = simulation_service.simulate_scenario(scenario, seed=5, draws=2_000).result
    real = simulation_service._existing
    calls = []

    def raced(*args):
        calls.append(args)
        return None if len(calls) == 1 else real(*args)  # the other run had not committed yet

    monkeypatch.setattr(simulation_service, "_existing", raced)
    outcome = simulation_service.simulate_scenario(scenario, seed=5, draws=2_000)
    assert len(calls) == 2
    assert outcome.result.pk == first.pk and outcome.created is False and outcome.completed
    assert SimulationResult.objects.count() == 1


def test_the_database_holds_one_result_per_inputs_seed_and_draws(deployment, people):
    scenario = _stored(deployment, people["analyst"])
    first = simulation_service.simulate_scenario(scenario, seed=5, draws=2_000).result
    copy = SimulationResult.objects.get(pk=first.pk)
    copy.pk = copy.id = None
    copy.uuid = uuid.uuid4()
    copy._state.adding = True
    with pytest.raises(EconomicsRefused) as refused:
        copy.save()
    assert refused.value.code == "duplicate_id"
    with pytest.raises(IntegrityError), transaction.atomic():
        models.Model.save(copy, force_insert=True)  # past the model's checks: the constraint
    assert SimulationResult.objects.count() == 1


# ======================================================================
# Never raises; records only what the inputs decide
# ======================================================================


@pytest.mark.parametrize(
    "fault, code",
    [
        (RuntimeError("a defect"), "simulation_failed"),
        (MemoryError(), "memory_exhausted"),
        (sim.InvariantBroken("broken"), "invariant_broken"),
    ],
)
def test_a_fault_is_returned_never_raised_and_never_recorded(deployment, people, monkeypatch, fault, code):
    scenario = _stored(deployment, people["analyst"])

    def fail(*args, **kwargs):
        raise fault

    monkeypatch.setattr(ss, "run", fail)
    outcome = simulation_service.simulate_scenario(scenario, seed=1, draws=1_000)
    assert (outcome.result, outcome.created, outcome.code) == (None, False, code)
    assert SimulationResult.objects.count() == 0


def test_the_time_budget_is_returned_never_recorded(deployment, people):
    scenario = _stored(deployment, people["analyst"])
    outcome = simulation_service.simulate_scenario(scenario, seed=1, draws=1_000, time_budget=-1.0)
    assert (outcome.result, outcome.code) == (None, "time_over_budget")
    assert SimulationResult.objects.count() == 0
    assert simulation_service.simulate_scenario(scenario, seed=1, draws=1_000).completed


def test_an_engine_that_will_not_import_is_returned_never_raised(deployment, people, monkeypatch):
    scenario = _stored(deployment, people["analyst"])

    def broken():
        raise ImportError("numpy is unavailable")

    monkeypatch.setattr(simulation_service, "_engine", broken)
    outcome = simulation_service.simulate_scenario(scenario, seed=1, draws=1_000)
    assert (outcome.result, outcome.code) == (None, "engine_unavailable")
    assert SimulationResult.objects.count() == 0


@pytest.mark.parametrize(
    "seed, draws, code",
    [(-1, 1_000, "seed_malformed"), (2**64, 1_000, "seed_malformed"), (1, 1_000_001, "draws_out_of_range"),
     (1, 999, "draws_out_of_range")],
)
def test_a_run_with_no_identity_is_refused_and_not_recorded(deployment, people, seed, draws, code):
    scenario = _stored(deployment, people["analyst"])
    outcome = simulation_service.simulate_scenario(scenario, seed=seed, draws=draws)
    assert (outcome.result, outcome.code) == (None, code)
    assert SimulationResult.objects.count() == 0


def test_the_largest_seed_is_kept_as_text(deployment, people):
    scenario = _stored(deployment, people["analyst"])
    outcome = simulation_service.simulate_scenario(scenario, seed=2**64 - 1, draws=1_000)
    outcome.result.refresh_from_db()
    assert outcome.result.seed == "18446744073709551615" == outcome.result.record["seed"]


# ======================================================================
# The rows
# ======================================================================


@pytest.mark.parametrize(
    "name, unit, source, distribution, code",
    [
        ("r", "ratio", "EXPERT_ESTIMATE", {"id": "lognormal", "version": 1, "params": {"mu": "0", "sigma": "1"}},
         "distribution_not_for_unit"),
        ("x", "money", "CUSTOMER_PROVIDED", {"id": "pert", "version": 1,
                                             "params": {"minimum": "1", "mode": "2", "maximum": "4"}},
         "expert_not_allowed"),
        ("x", "money", "CUSTOMER_PROVIDED", {"id": "gamma", "version": 1, "params": {"shape": 2}},
         "distribution_malformed"),
        ("x", "money", "CUSTOMER_PROVIDED", {"id": "gamma", "version": 9, "params": {"shape": "2", "scale": "1"}},
         "distribution_version_unknown"),
        ("x", "money", "CUSTOMER_PROVIDED", {"id": "gamma", "version": 1, "params": {"shape": "0", "scale": "1"}},
         "shape_out_of_range"),
        (ss.FREQUENCY_PARAMETER, "count", "INDUSTRY_BENCHMARK", GAMMA, "frequency_not_a_count"),
    ],
)
def test_a_stated_distribution_is_checked_when_its_row_is_written(deployment, people, name, unit, source,
                                                                  distribution, code):
    scenario = FinancialScenario.objects.create(deployment=deployment, title="t", author=people["analyst"])
    with pytest.raises(EconomicsRefused) as refused:
        _parameter(scenario, name, unit, "0", "0.5", "1", source=source, distribution=distribution)
    assert refused.value.code == code
    assert FinancialParameter.objects.count() == 0


def test_a_stated_distribution_is_stored_in_the_one_spelling(deployment, people):
    scenario = FinancialScenario.objects.create(deployment=deployment, title="t", author=people["analyst"])
    row = _parameter(scenario, "x", "money", "3000", "10000", "36000", source="CUSTOMER_PROVIDED",
                     distribution={"id": "lognormal", "version": 1, "params": {"mu": "9.20", "sigma": "0.80"}})
    row.refresh_from_db()
    assert row.distribution == {"id": "lognormal", "version": 1, "params": {"mu": "9.2", "sigma": "0.8"}}
    assert isinstance(row.stated_distribution(), ss.StatedDistribution)
    assert isinstance(EngineRefused("x_code", "a meaning"), EconomicsRefused)


def _completed(deployment, people):
    scenario = _stored(deployment, people["analyst"])
    return simulation_service.simulate_scenario(scenario, seed=5, draws=1_000).result


def _copy(row, **over):
    copy = SimulationResult.objects.get(pk=row.pk)
    copy.pk = copy.id = None
    copy.uuid = uuid.uuid4()
    copy._state.adding = True
    copy.seed = "6"
    for key, value in over.items():
        setattr(copy, key, value)
    return copy


@pytest.mark.parametrize(
    "change, code",
    [
        (lambda row: {"record": {**row.record, "simulations": 1.5}}, "result_malformed"),
        (lambda row: {"inputs": {**row.inputs, "severe_percentile": 95.0}}, "result_malformed"),
        (lambda row: {"result_digest": "sha256:" + "0" * 64}, "digest_mismatch"),
        (lambda row: {"inputs": {**row.inputs, "reporting_currency": "EUR"}}, "digest_mismatch"),
        (lambda row: {"seed": "018"}, "result_malformed"),
        (lambda row: {"seed": str(2**64)}, "result_malformed"),
        (lambda row: {"refusal_code": "no_admissible_distribution"}, "result_malformed"),
    ],
)
def test_a_result_is_checked_when_it_is_written(deployment, people, change, code):
    row = _completed(deployment, people)
    with pytest.raises(EconomicsRefused) as refused:
        _copy(row, **change(row)).save()
    assert refused.value.code == code


def test_a_result_of_another_deployments_scenario_is_refused(deployment, people):
    row = _completed(deployment, people)
    elsewhere = Deployment.objects.create(name="someone-elses", owner=people["other"])
    with pytest.raises(EconomicsRefused) as refused:
        _copy(row, deployment=elsewhere).save()
    assert refused.value.code == "cross_tenant_reference"


def test_a_recorded_result_is_never_rewritten(deployment, people):
    row = _completed(deployment, people)
    with pytest.raises(EconomicsRewriteRefused):
        row.save()
    with pytest.raises(EconomicsRewriteRefused):
        SimulationResult.objects.filter(pk=row.pk).update(seed="9")
    with pytest.raises(EconomicsRewriteRefused):
        SimulationResult.objects.filter(pk=row.pk).delete()
    with pytest.raises(EconomicsRewriteRefused):
        row.delete()


# ======================================================================
# Review round 1
# ======================================================================


def test_a_stated_distribution_that_contradicts_its_row_is_refused_when_written(deployment, people):
    """M1, at write time: the reviewer's lognormal(0, 1) on 100,000 / 200,000 /
    400,000 is refused, and nothing is written."""
    scenario = FinancialScenario.objects.create(deployment=deployment, title="t", author=people["analyst"])
    with pytest.raises(EngineRefused) as refused:
        _parameter(scenario, "c.amt", "money", "100000", "200000", "400000", source="CUSTOMER_PROVIDED",
                   distribution={"id": "lognormal", "version": 1, "params": {"mu": "0", "sigma": "1"}})
    assert refused.value.code == "distribution_contradicts_range" and "c.amt" in refused.value.detail
    assert FinancialParameter.objects.count() == 0
    _parameter(scenario, "c.amt", "money", "100000", "200000", "400000", source="CUSTOMER_PROVIDED",
               distribution={"id": "lognormal", "version": 1, "params": {"mu": "12.2", "sigma": "0.4"}})


def test_a_refusal_under_a_lower_limit_is_not_returned_under_the_default(deployment, people, monkeypatch):
    """L3. Refused at a low values budget and recorded; at the default the same
    scenario, seed and draws run and are recorded under another input digest."""
    scenario = _stored(deployment, people["analyst"])
    monkeypatch.setattr(sim, "MAX_VALUES", 1_000)
    low = simulation_service.simulate_scenario(scenario, seed=1, draws=1_000)
    assert low.created and low.code == "values_over_budget"
    monkeypatch.undo()
    default = simulation_service.simulate_scenario(scenario, seed=1, draws=1_000)
    assert default.created and default.completed, (default.code, default.detail)
    assert default.result.input_digest != low.result.input_digest
    assert default.result.versions["limits"]["max_values"] == sim.MAX_VALUES
    assert SimulationResult.objects.count() == 2


def test_a_row_that_lands_between_the_check_and_the_insert_is_returned(deployment, people, monkeypatch):
    """L5. The other run's row lands after this run's checks and before its
    INSERT: the unique constraint stops the INSERT (IntegrityError), and the
    other's row is returned, never a second."""
    scenario = _stored(deployment, people["analyst"])
    real = SimulationResult.check_new
    landed = []

    def check_then_race(row):
        real(row)
        if not landed:
            fields = SimulationResult._meta.concrete_fields
            other = SimulationResult(**{f.attname: getattr(row, f.attname) for f in fields if not f.primary_key})
            other.uuid = uuid.uuid4()
            models.Model.save(other, force_insert=True)  # the other run's row, committed meanwhile
            landed.append(other)

    monkeypatch.setattr(SimulationResult, "check_new", check_then_race)
    outcome = simulation_service.simulate_scenario(scenario, seed=6, draws=1_000)
    assert landed, "the race was not run"
    assert (outcome.result.pk, outcome.created, outcome.code) == (landed[0].pk, False, None), outcome.detail
    assert SimulationResult.objects.count() == 1


def test_a_result_is_inserted_only_as_it_was_checked(deployment, people):
    row = _completed(deployment, people)
    copy = _copy(row, uuid=uuid.uuid4())
    with pytest.raises(EconomicsRewriteRefused):
        copy.insert_checked()  # never checked
    with pytest.raises(EconomicsRefused):
        copy.check_new()  # the record names another seed
    with pytest.raises(EconomicsRewriteRefused):
        row.insert_checked()  # recorded already
    assert SimulationResult.objects.count() == 1


def _two_effect_body(asset, finding, incident=("100000", "165000", "300000"), other=("120000", "150000", "400000"),
                     other_source="EXPERT_ESTIMATE"):
    def effect(key, figures, source):
        return {
            "key": key, "origin": "hypothetical", "effect_type": "funds_transfer_altered",
            "asset": str(asset.uuid), "business_process": "payments",
            "attributes": {
                "success_rate": _attribute("ratio", "0.35"),
                "exploitable_window_hours": _attribute("hours", "1.25"),
                "incident_response_cost": _entry("money", *figures, source_type=source,
                                                 evidence_ref=f"{LABEL}: made up"),
                "legal_response_cost": _attribute("money", "825000"),
            },
        }

    return {
        "title": "Payment agent: two effects, one event",
        "parameter_set": {"set_key": SET_KEY, "version": 1}, "currency": "USD", "as_of": "2026-10-06",
        "effects": [effect("redirect", incident, "EXPERT_ESTIMATE"), effect("redirect-2", other, other_source)],
        "findings": [{"finding": str(finding.uuid), "effect": key, "role": "prerequisite"}
                     for key in ("redirect", "redirect-2")],
    }


def _payment_set(deployment, author):
    variables = {
        "transactions_per_day": _entry("count_per_day", "18000"),
        "average_transaction_value": _entry("money_per_unit", "25000"),
        "recovery_rate": _entry("ratio", "0.825"),
    }
    CustomerParameterSet.record(deployment, SET_KEY, {"variables": variables}, author=author)
    asset = Asset.objects.create(deployment=deployment, kind="agent", name="payments-agent",
                                 identifier="agent://payments-agent")
    finding = Finding.objects.create(deployment=deployment, fingerprint="fp-0", finding_type="approval_check_missing",
                                     title="finding 0", severity="high")
    return asset, finding


def test_two_effects_joined_in_one_event_are_simulated_by_their_contributors(deployment, people):
    """L6, end to end: the builder joins two effects' expert ranges into one
    CALCULATED parameter (derived_from); the simulation draws each by its own rule
    and takes the larger loss per draw, where it refused the merge before."""
    author = people["analyst"]
    asset, finding = _payment_set(deployment, author)
    scenario, created = builder.build(deployment, _two_effect_body(asset, finding), author=author)
    assert created
    merged = FinancialParameter.objects.get(scenario=scenario, name__endswith=":incident_response_cost")
    assert merged.source_type == "CALCULATED" and len(merged.derived_from) == 2
    outcome = simulation_service.simulate_scenario(scenario, seed=12, draws=2_000)
    assert outcome.completed, (outcome.code, outcome.detail)
    record = outcome.result.record["parameters"][merged.name]
    assert record["rule"] == ss.RULE_DERIVED and record["direction"] == "increases"
    assert sorted(record["contributors"]) == ["redirect-2.incident_response_cost", "redirect.incident_response_cost"]
    assert all(c["rule"] == ss.RULE_PERT_DEFAULT for c in record["contributors"].values())
    assert sorted(outcome.result.inputs["derived"][merged.name]) == sorted(record["contributors"])
    # A contributor no rule admits refuses the merge, naming it.
    refused_scenario, _ = builder.build(
        deployment, {**_two_effect_body(asset, finding, other_source="CUSTOMER_PROVIDED"), "title": "refused"},
        author=author)
    refused = simulation_service.simulate_scenario(refused_scenario, seed=12, draws=2_000)
    assert refused.code == "no_admissible_distribution" and "redirect-2.incident_response_cost" in refused.detail


def test_a_derived_row_states_no_distribution(deployment, people):
    scenario = FinancialScenario.objects.create(deployment=deployment, title="t", author=people["analyst"])
    one = _parameter(scenario, "e1.amount", "money", "100", "200", "300")
    two = _parameter(scenario, "e2.amount", "money", "150", "180", "400")
    with pytest.raises(EngineRefused) as refused:
        FinancialParameter.objects.create(
            scenario=scenario, name="ev:amount", unit="money", source_type="CALCULATED", currency="USD", low="150",
            base="200", high="400", evidence_ref=f"{LABEL}: made up", effective_date=date(2026, 9, 1),
            derived_from=[str(one.uuid), str(two.uuid)], distribution=GAMMA)
    assert refused.value.code == "derived_malformed"


# ======================================================================
# The double-count invariant, end to end
# ======================================================================


def _attribute(unit, figure):
    return _entry(unit, figure, source_type="EXPERT_ESTIMATE", evidence_ref=f"{LABEL}: made up")


def test_five_findings_on_one_effect_make_one_event_in_the_simulation_too(deployment, people):
    """Section 27's own test, through the builder and the simulation: one, then
    five, findings enabling one payment loss build one event each time, and the
    simulated loss is the same, never multiplied."""
    author = people["analyst"]
    variables = {
        "transactions_per_day": _entry("count_per_day", "18000"),
        "average_transaction_value": _entry("money_per_unit", "25000"),
        "recovery_rate": _entry("ratio", "0.825"),
    }
    CustomerParameterSet.record(deployment, SET_KEY, {"variables": variables}, author=author)
    asset = Asset.objects.create(deployment=deployment, kind="agent", name="payments-agent",
                                 identifier="agent://payments-agent")
    findings = [
        Finding.objects.create(deployment=deployment, fingerprint=f"fp-{n}", finding_type="approval_check_missing",
                               title=f"finding {n}", severity="high")
        for n in range(5)
    ]
    effect = {
        "key": "redirect", "origin": "hypothetical", "effect_type": "funds_transfer_altered",
        "asset": str(asset.uuid), "business_process": "payments",
        "attributes": {
            "success_rate": _attribute("ratio", "0.35"),
            "exploitable_window_hours": _attribute("hours", "1.25"),
            "incident_response_cost": _attribute("money", "165000"),
            "legal_response_cost": _attribute("money", "825000"),
        },
    }
    figures = []
    for n in (1, 5):
        body = {
            "title": "Payment agent: destination changed after approval",
            "parameter_set": {"set_key": SET_KEY, "version": 1}, "currency": "USD", "as_of": "2026-10-06",
            "effects": [effect],
            "findings": [{"finding": str(f.uuid), "effect": "redirect", "role": "prerequisite"} for f in findings[:n]],
        }
        scenario, created = builder.build(deployment, body, author=author)
        assert created
        outcome = simulation_service.simulate_scenario(scenario, seed=30, draws=1_000)
        assert outcome.completed, (outcome.code, outcome.detail)
        record = outcome.result.record
        assert len(record["events"]) == 1
        assert [c["component_id"] for c in record["events"][0]["components"]] == [
            "direct-loss", "incident-response", "legal-regulatory-response"]
        figures.append(record["scenario"]["gross_cash"]["p50"])
    # Section 30's base, once: 1,435,546.875 + 165,000 + 825,000.
    assert figures == ["2425546.875", "2425546.875"]
