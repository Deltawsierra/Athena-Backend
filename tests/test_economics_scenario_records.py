"""Economic Exposure's scenario records and the customer parameter-set API,
against the database (``docs/economics/spec-v1.md``, sections 19 and 20).

- ``CustomerParameterSet``, ``FinancialParameter``, ``LossEvent`` and
  ``LossComponent`` are append-only like every economics record, go with their
  deployment, and never hold back the removal of an operator (a stop);
- a parameter set is deployment-scoped and versioned, records its author, and is
  sealed once recorded; its rows read back to the digest it was recorded with;
- a parameter belongs to exactly one scenario or one set version, and is refused
  with the engine's code for everything the engine refuses;
- a component's amounts are computed from the parameters it cites, never taken
  from the caller; a missing input makes it unknown; it never cites another
  deployment's parameter;
- the API: tenant isolation, role checks, append-only, unknown fields refused,
  strict decimals; none of its routes is a stop.
"""

from __future__ import annotations

import dataclasses
import json
import uuid
from datetime import date
from decimal import Decimal

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, models, transaction
from django.urls import URLResolver, get_resolver
from rest_framework.test import APIClient

from assurance.economics.engine.parameters import POINTS
from assurance.economics.models import (
    CustomerParameterSet,
    EconomicsRefused,
    EconomicsRewriteRefused,
    FinancialParameter,
    FinancialScenario,
    LossComponent,
    LossEvent,
)
from assurance.models import Deployment
from safety import stops
from tests.test_economics_known_answers import example_b_components
from tests.test_economics_scenarios import full_document

pytestmark = pytest.mark.django_db

User = get_user_model()
AS_OF = date(2026, 10, 6)
EFFECT = "sha256:" + "e1" * 32


@pytest.fixture
def people():
    return {
        "admin": User.objects.create_user(username="ada", password="x", role="admin"),
        "analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
        "viewer": User.objects.create_user(username="vic", password="x", role="viewer"),
        "other": User.objects.create_user(username="oto", password="x", role="viewer"),
    }


@pytest.fixture
def deployment(people):
    return Deployment.objects.create(name="payments-agent", owner=people["viewer"])


@pytest.fixture
def other_deployment(people):
    return Deployment.objects.create(name="someone-elses", owner=people["other"])


def _scenario(deployment, author=None):
    return FinancialScenario.objects.create(deployment=deployment, title="Cross-customer exposure", author=author)


def _parameter(scenario=None, parameter_set=None, **over):
    fields = {
        "scenario": scenario,
        "parameter_set": parameter_set,
        "name": "forensics_hours",
        "unit": "hours",
        "source_type": "EXPERT_ESTIMATE",
        "low": "200",
        "base": "400",
        "high": "800",
        "evidence_ref": "SYNTHETIC: made up",
        "effective_date": date(2026, 9, 1),
    }
    fields.update(over)
    return FinancialParameter.objects.create(**fields)


def _store(scenario, engine_parameter):
    # The worked examples' parameters name no date; a stored one holds from one.
    dated = dataclasses.replace(engine_parameter, effective_date=date(2026, 9, 1))
    row = FinancialParameter.from_engine(dated, scenario=scenario)
    row.save()
    return row


def _event(scenario, key="cross-customer", **over):
    return LossEvent.objects.create(scenario=scenario, event_key=key, currency="USD", **over)


def _component(event, key, family, formula_id, cited, **over):
    return LossComponent.objects.create(
        loss_event=event,
        component_key=key,
        family=family,
        formula_id=formula_id,
        formula_version=1,
        as_of=AS_OF,
        cited_parameters={name: str(row.uuid) for name, row in cited.items()},
        **over,
    )


def _every_record(deployment, people):
    pset = CustomerParameterSet.record(deployment, "bank_prod_2026q4", full_document(), author=people["analyst"])
    scenario = _scenario(deployment, people["analyst"])
    hours = _parameter(scenario)
    rate = _parameter(scenario, name="forensics_rate", unit="money_per_hour", currency="USD",
                      low="300", base="400", high="500")
    fixed = _parameter(scenario, name="forensics_fixed", unit="money", currency="USD",
                       low="50000", base="75000", high="100000")
    event = _event(scenario)
    component = _component(event, "forensics", "incident_response", "fixed_plus_hours",
                           {"fixed_cost": fixed, "hourly_rate": rate, "hours": hours})
    return [pset, pset.parameter_rows()[0], hours, event, component]


# ---------------------------------------------------------------- append-only


def test_every_new_record_is_append_only(deployment, people):
    for row in _every_record(deployment, people):
        model = type(row)
        with pytest.raises(EconomicsRewriteRefused):
            row.save()
        with pytest.raises(EconomicsRewriteRefused):
            row.delete()
        rows = model.objects.filter(pk=row.pk)
        with pytest.raises(EconomicsRewriteRefused):
            rows.update(uuid=row.uuid)
        with pytest.raises(EconomicsRewriteRefused):
            rows.delete()
        with pytest.raises(EconomicsRewriteRefused):
            model.objects.bulk_update([row], ["uuid"])
        with pytest.raises(EconomicsRefused) as refused:
            model.objects.bulk_create([model()])
        assert refused.value.code == "bulk_create_refused"
        assert model.objects.filter(pk=row.pk).exists()


def test_the_base_manager_stays_djangos_plain_one():
    for model in (CustomerParameterSet, FinancialParameter, LossEvent, LossComponent):
        assert model._meta.base_manager_name is None, model
        assert type(model._base_manager) is models.Manager, model


def test_the_records_go_with_their_deployment(deployment, people, other_deployment):
    _every_record(deployment, people)
    kept = CustomerParameterSet.record(other_deployment, "q4", full_document(), author=people["admin"])
    deployment.delete()
    assert list(CustomerParameterSet.objects.all()) == [kept]
    assert set(FinancialParameter.objects.values_list("parameter_set_id", flat=True)) == {kept.pk}
    assert not LossEvent.objects.exists() and not LossComponent.objects.exists()


def test_removing_an_operator_is_never_held_back_by_a_parameter_set(deployment, people):
    """Removing an operator is a stop (``accounts:user-detail`` DELETE): it answers
    204 through the real route with the operator the author of a set version, nulls
    the account and keeps the name."""
    leaver = User.objects.create_user(username="leaver", password="x", role="analyst")
    version = CustomerParameterSet.record(deployment, "q4", full_document(), author=leaver)
    client = APIClient()
    client.force_authenticate(user=people["admin"])
    response = client.delete(f"/api/accounts/users/{leaver.pk}/")
    assert response.status_code == 204, response.content
    stored = CustomerParameterSet.objects.get(pk=version.pk)
    assert (stored.author_id, stored.author_username) == (None, "leaver")
    assert stored.intact()


# -------------------------------------------------------------- parameter sets


def test_a_set_is_versioned_per_deployment_and_key_and_names_its_author(deployment, other_deployment, people):
    first = CustomerParameterSet.record(deployment, "q4", full_document(), author=people["analyst"])
    second = CustomerParameterSet.record(deployment, "q4", full_document(), author=people["admin"])
    other_key = CustomerParameterSet.record(deployment, "q3", full_document(), author=people["admin"])
    elsewhere = CustomerParameterSet.record(other_deployment, "q4", full_document(), author=people["admin"])
    assert [first.version, second.version, other_key.version, elsewhere.version] == [1, 2, 1, 1]
    assert CustomerParameterSet.current(deployment, "q4") == second
    assert CustomerParameterSet.current(other_deployment, "q4") == elsewhere
    assert CustomerParameterSet.current(deployment, "q2") is None
    assert (first.author_username, second.author_username) == ("ann", "ada")
    with pytest.raises(IntegrityError), transaction.atomic():
        CustomerParameterSet.objects.create(
            deployment=deployment, set_key="q4", version=1, variable_count=1, content_digest=first.content_digest
        )


def test_a_set_reads_back_to_the_digest_it_was_recorded_with(deployment, people):
    from assurance.economics.engine import parameter_set

    document = full_document()
    version = CustomerParameterSet.record(deployment, "q4", document, author=people["analyst"])
    assert version.content_digest == parameter_set.parse_document(document).digest()
    assert version.variable_count == 31
    assert version.intact()
    rows = version.parameter_rows()
    assert len(rows) == 31
    revenue = next(r for r in rows if r.name == "annual_revenue")
    assert (revenue.unit, revenue.currency, revenue.low) == ("money_per_year", "USD", "4200000000")
    sublimit = next(r for r in rows if r.name == "insurance_sublimit:notification")
    assert (sublimit.unit, sublimit.low) == ("money", "150000")
    assert version.insurance_exclusions == ["regulatory_compliance"]
    policy = version.content().insurance_policy()
    assert policy.deductible.low.amount == 250000 and policy.deductible.parameter_id == str(
        next(r for r in rows if r.name == "insurance_deductible").uuid
    )


def test_nothing_is_added_to_a_recorded_version(deployment, people):
    document = {"variables": {"recovery_rate": full_document()["variables"]["recovery_rate"]}}
    version = CustomerParameterSet.record(deployment, "q4", document, author=people["analyst"])
    with pytest.raises(EconomicsRefused) as refused:
        _parameter(parameter_set=version, name="customer_count", unit="count", low="1", base="1", high="1")
    assert refused.value.code == "parameter_set_sealed"
    assert version.intact() and len(version.parameter_rows()) == 1


def test_a_set_refuses_what_its_schema_refuses_and_writes_nothing(deployment, people):
    bad = full_document()
    bad["variables"]["recovery_rate"]["high"] = "1.5"
    with pytest.raises(EconomicsRefused) as refused:
        CustomerParameterSet.record(deployment, "q4", bad, author=people["analyst"])
    assert refused.value.code == "ratio_out_of_range"
    with pytest.raises(EconomicsRefused) as refused:
        CustomerParameterSet.record(deployment, "Q4!", full_document(), author=people["analyst"])
    assert refused.value.code == "set_key_malformed"
    assert not CustomerParameterSet.objects.exists() and not FinancialParameter.objects.exists()


def test_a_set_row_checks_its_own_fields(deployment):
    base = {"deployment": deployment, "set_key": "q4", "variable_count": 1, "content_digest": "sha256:" + "a" * 64}
    cases = [
        ({"insurance_exclusions": ["fines"]}, "loss_family_unrecognised"),
        ({"insurance_exclusions": ["legal", "legal"]}, "duplicate_id"),
        ({"insurance_exclusions": "legal"}, "field_malformed"),
        ({"variable_count": 0}, "field_missing"),
        ({"content_digest": "a" * 64}, "snapshot_hash_malformed"),
        ({"schema_version": "v0"}, "code_unrecognised"),
        ({"set_key": "Q4"}, "set_key_malformed"),
    ]
    for over, code in cases:
        with pytest.raises(EconomicsRefused) as refused:
            CustomerParameterSet.objects.create(**{**base, **over})
        assert refused.value.code == code, over
    assert not CustomerParameterSet.objects.exists()


# ------------------------------------------------------------------ parameters


def test_a_parameter_belongs_to_exactly_one_parent(deployment, people):
    scenario = _scenario(deployment)
    version = CustomerParameterSet.record(deployment, "q4", full_document(), author=people["analyst"])
    for parents in ({}, {"scenario": scenario, "parameter_set": version}):
        with pytest.raises(EconomicsRefused) as refused:
            _parameter(**parents)
        assert refused.value.code == "parent_required"
    row = FinancialParameter(name="x", unit="count", source_type="UNKNOWN", low="1", base="1", high="1",
                             evidence_ref="e", effective_date=date(2026, 9, 1))
    with pytest.raises(IntegrityError), transaction.atomic():
        models.Model.save(row, force_insert=True)


PARAMETER_REFUSALS = [
    ({"low": "abc"}, "not_decimal"),
    ({"low": "1e3"}, "not_decimal"),
    ({"low": "NaN"}, "not_decimal"),
    ({"low": "-1"}, "negative_value"),
    ({"unit": "ratio", "low": "0.5", "base": "0.9", "high": "1.1"}, "ratio_out_of_range"),
    ({"low": "900"}, "range_inverted"),
    ({"currency": "USD"}, "unit_mismatch"),
    ({"unit": "money"}, "currency_unknown"),
    ({"unit": "furlongs"}, "unit_unrecognised"),
    ({"source_type": "GUESS"}, "source_type_unrecognised"),
    ({"evidence_ref": " "}, "evidence_ref_missing"),
    ({"evidence_ref": "x" * 501}, "field_malformed"),
    ({"fresh_until": date(2026, 8, 1)}, "date_inversion"),
    ({"name": ""}, "required_field_blank"),
]


@pytest.mark.parametrize("over, code", PARAMETER_REFUSALS, ids=[c for _, c in PARAMETER_REFUSALS])
def test_a_parameter_row_is_refused_with_the_engines_code(deployment, over, code):
    scenario = _scenario(deployment)
    with pytest.raises(EconomicsRefused) as refused:
        _parameter(scenario, **over)
    assert refused.value.code == code
    assert not FinancialParameter.objects.exists()


def test_a_parameter_is_stored_in_the_one_spelling_and_once_per_parent(deployment):
    scenario = _scenario(deployment)
    row = _parameter(scenario, low="200.000", base="0400", high="800.50")
    assert (row.low, row.base, row.high) == ("200", "400", "800.5")
    with pytest.raises(EconomicsRefused) as refused:
        _parameter(scenario)
    assert refused.value.code == "duplicate_id"
    with pytest.raises(IntegrityError), transaction.atomic():
        models.Model.save(
            FinancialParameter(scenario=scenario, name="forensics_hours", unit="hours", source_type="UNKNOWN",
                               low="1", base="1", high="1", evidence_ref="e", effective_date=date(2026, 9, 1)),
            force_insert=True,
        )
    for field, value in (("unit", "furlongs"), ("source_type", "GUESS")):
        stray = FinancialParameter(scenario=scenario, name=f"k-{field}", unit="hours", source_type="UNKNOWN",
                                   low="1", base="1", high="1", evidence_ref="e", effective_date=date(2026, 9, 1))
        setattr(stray, field, value)
        with pytest.raises(IntegrityError), transaction.atomic():
            models.Model.save(stray, force_insert=True)


# ---------------------------------------------------- loss events and components


def test_a_component_is_computed_from_the_parameters_it_cites(deployment, people):
    scenario = _scenario(deployment, people["analyst"])
    fixed = _parameter(scenario, name="forensics_fixed", unit="money", currency="USD", low="50000", base="75000",
                       high="100000")
    rate = _parameter(scenario, name="forensics_rate", unit="money_per_hour", currency="USD", low="300", base="400",
                      high="500")
    hours = _parameter(scenario)
    event = _event(scenario, effect=EFFECT, trigger="cross-tenant read")
    # Whatever the caller says the amounts are is not read.
    component = _component(event, "forensics", "incident_response", "fixed_plus_hours",
                           {"fixed_cost": fixed, "hourly_rate": rate, "hours": hours},
                           low="1", base="1", high="1", status="unknown")
    # 50,000 + 300 x 200 = 110,000; 75,000 + 400 x 400 = 235,000; 100,000 + 500 x 800 = 500,000
    assert (component.status, component.currency) == ("estimated", "USD")
    assert (component.low, component.base, component.high) == ("110000", "235000", "500000")
    assert component.insurance_treatment == "gross"
    engine = component.as_engine()
    assert [engine.at(p).amount for p in POINTS] == [110000, 235000, 500000]
    assert {c.parameter.parameter_id for c in engine.inputs} == {str(fixed.uuid), str(rate.uuid), str(hours.uuid)}


def test_a_component_missing_an_input_is_unknown_with_no_amount(deployment):
    scenario = _scenario(deployment)
    hours = _parameter(scenario)
    component = _component(_event(scenario), "forensics", "incident_response", "fixed_plus_hours", {"hours": hours})
    assert (component.status, component.low, component.base, component.high) == ("unknown", "", "", "")
    assert component.unknown_reason == "input_missing"
    assert component.missing_inputs == ["fixed_cost", "hourly_rate"]


def test_a_component_never_cites_another_deployments_parameter(deployment, other_deployment, people):
    mine = _scenario(deployment)
    theirs = _scenario(other_deployment)
    their_set = CustomerParameterSet.record(other_deployment, "q4", full_document(), author=people["admin"])
    their_amount = next(r for r in their_set.parameter_rows() if r.name == "legal_retainer")
    their_scenario_amount = _parameter(theirs, name="fee", unit="money", currency="USD", low="1", base="1", high="1")
    event = _event(mine)
    for row in (their_amount, their_scenario_amount):
        with pytest.raises(EconomicsRefused) as refused:
            _component(event, f"legal-{row.pk}", "legal", "lump_sum", {"amount": row})
        assert refused.value.code == "cross_tenant_reference"
    # Its own deployment's set is citable.
    my_set = CustomerParameterSet.record(deployment, "q4", full_document(), author=people["admin"])
    retainer = next(r for r in my_set.parameter_rows() if r.name == "legal_retainer")
    component = _component(event, "legal", "legal", "lump_sum", {"amount": retainer})
    assert component.base == "250000"


def test_a_component_refuses_what_it_cannot_compute(deployment):
    scenario = _scenario(deployment)
    fee = _parameter(scenario, name="fee", unit="money", currency="USD", low="1", base="1", high="1")
    euro = _parameter(scenario, name="fee_eur", unit="money", currency="EUR", low="1", base="1", high="1")
    hours = _parameter(scenario)
    event = _event(scenario)
    cases = [
        (("a", "legal", "lump_sum", {"amount": hours}), {}, "unit_mismatch"),
        (("b", "direct_financial", "fixed_plus_hours", {"hours": hours}), {}, "formula_not_for_family"),
        (("c", "legal", "no_such_formula", {"amount": fee}), {}, "formula_unknown"),
        (("d", "legal", "lump_sum", {"amount": euro}), {}, "currency_mismatch"),
        (("e", "legal", "lump_sum", {"minutes": fee}), {}, "input_unrecognised"),
        (("f", "fines", "lump_sum", {"amount": fee}), {}, "loss_family_unrecognised"),
    ]
    for (key, family, formula_id, cited), over, code in cases:
        with pytest.raises(EconomicsRefused) as refused:
            _component(event, key, family, formula_id, cited, **over)
        assert refused.value.code == code, key
    for cited, code in (({"amount": str(uuid.uuid4())}, "parameter_not_found"),
                        ({"amount": "not-a-uuid"}, "parameter_not_found"),
                        ({"amount": 7}, "field_malformed"),
                        (["amount"], "field_malformed")):
        with pytest.raises(EconomicsRefused) as refused:
            LossComponent.objects.create(loss_event=event, component_key="g", family="legal", formula_id="lump_sum",
                                         formula_version=1, as_of=AS_OF, cited_parameters=cited)
        assert refused.value.code == code, cited
    _component(event, "fee", "legal", "lump_sum", {"amount": fee})
    with pytest.raises(EconomicsRefused) as refused:
        _component(event, "fee", "legal", "lump_sum", {"amount": fee})
    assert refused.value.code == "duplicate_id"
    assert LossComponent.objects.count() == 1


def test_an_event_checks_its_key_effect_and_currency(deployment):
    scenario = _scenario(deployment)
    _event(scenario, "one")
    cases = [
        ({"event_key": "one"}, "duplicate_id"),
        ({"event_key": ""}, "required_field_blank"),
        ({"event_key": "x" * 101}, "field_malformed"),
        ({"event_key": "two", "effect": "e1" * 32}, "spine_reference_malformed"),
        ({"event_key": "two", "currency": "DEM"}, "currency_retired"),
        ({"event_key": "two", "currency": "usd"}, "currency_unknown"),
    ]
    for over, code in cases:
        with pytest.raises(EconomicsRefused) as refused:
            LossEvent.objects.create(**{"scenario": scenario, "event_key": "two", "currency": "USD", **over})
        assert refused.value.code == code, over


def test_the_database_holds_a_component_gross_and_in_its_codes(deployment):
    scenario = _scenario(deployment)
    fee = _parameter(scenario, name="fee", unit="money", currency="USD", low="1", base="1", high="1")
    event = _event(scenario)
    for field, value in (("insurance_treatment", "net"), ("family", "fines"), ("status", "guessed")):
        row = LossComponent(loss_event=event, component_key=f"k-{field}", family="legal", formula_id="lump_sum",
                            formula_version=1, as_of=AS_OF, cited_parameters={"amount": str(fee.uuid)},
                            status="estimated", currency="USD", low="1", base="1", high="1")
        setattr(row, field, value)
        with pytest.raises(IntegrityError), transaction.atomic():
            models.Model.save(row, force_insert=True)


def test_worked_example_b_stored_and_read_back_gives_the_same_answer(deployment, people):
    """Example B's parameters stored on a scenario, its policy in a parameter set,
    its components citing the rows: the event read back assesses exactly as the
    engine does from the objects."""
    from assurance.economics.engine.loss import LossEvent as EngineEvent
    from assurance.economics.engine.loss import assess

    scenario = _scenario(deployment, people["analyst"])
    event = _event(scenario)
    stored = {}
    for component in example_b_components():
        cited = {}
        for input_ in component.inputs:
            name = input_.parameter.name
            if name not in stored:
                stored[name] = _store(scenario, input_.parameter)
            cited[input_.input.name] = stored[name]
        _component(event, component.component_id, component.family, component.formula.formula_id, cited)
    document = full_document()
    document["variables"]["insurance_deductible"] = {**document["variables"]["insurance_deductible"],
                                                     "low": "100000", "base": "100000", "high": "100000"}
    document["variables"]["insurance_limit"] = {**document["variables"]["insurance_limit"],
                                                "low": "1000000", "base": "1000000", "high": "1000000"}
    document["variables"].pop("insurance_waiting_period_hours")
    policy = CustomerParameterSet.record(deployment, "q4", document, author=people["analyst"]).content().insurance_policy()

    read_back = event.as_engine()
    result = assess(read_back, policy)
    direct = assess(EngineEvent("cross-customer", "USD", example_b_components()), policy)
    for point in POINTS:
        assert result.gross.total.at(point) == direct.gross.total.at(point)
        assert result.insured.retained.at(point) == direct.insured.retained.at(point)
    assert [result.insured.retained.at(p).amount for p in POINTS] == [100000, 231250, 1580000]
    assert LossComponent.objects.get(component_key="customer-loss").status == "unknown"


# ========================================================================= API


def _url(deployment, set_key="bank_prod_2026q4", versions=False):
    base = f"/api/assurance/deployments/{deployment.uuid}/economics/parameter-sets/{set_key}/"
    return base + "versions/" if versions else base


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


def _post(client, deployment, body, set_key="bank_prod_2026q4", raw=False):
    data = body if raw else json.dumps(body)
    return client.post(_url(deployment, set_key, versions=True), data=data, content_type="application/json")


def test_an_admin_or_analyst_records_versions_and_anyone_who_sees_the_deployment_reads_them(deployment, people):
    first = _post(_client(people["admin"]), deployment, full_document())
    assert first.status_code == 201, first.content
    body = first.json()
    assert (body["version"], body["current"], body["author"], body["intact"]) == (1, True, "ada", True)
    assert body["deployment"] == str(deployment.uuid)
    assert body["variables"]["transactions_per_day"]["unit"] == "count_per_day"
    assert body["variables"]["transactions_per_day"]["domain"] == "transactions"
    assert body["variables"]["annual_revenue"]["currency"] == "USD"
    assert body["insurance_exclusions"] == ["regulatory_compliance"]
    changed = full_document()
    changed["variables"]["recovery_rate"]["base"] = "0.9"
    changed["variables"]["recovery_rate"]["high"] = "0.95"
    second = _post(_client(people["analyst"]), deployment, changed)
    assert second.status_code == 201, second.content
    assert (second.json()["version"], second.json()["author"]) == (2, "ann")

    # The owner, a viewer, reads the current version and the list.
    reader = _client(people["viewer"])
    current = reader.get(_url(deployment))
    assert current.status_code == 200, current.content
    assert current.json()["version"] == 2 and current.json()["variables"]["recovery_rate"]["base"] == "0.9"
    listed = reader.get(_url(deployment, versions=True))
    assert listed.status_code == 200
    assert [v["version"] for v in listed.json()["versions"]] == [2, 1]
    assert listed.json()["current"] == 2 and listed.json()["truncated"] is False
    assert [v["author"] for v in listed.json()["versions"]] == ["ann", "ada"]
    # Version 1 is as it was: append-only.
    v1 = CustomerParameterSet.objects.get(deployment=deployment, version=1)
    assert v1.intact() and v1.content().variables["recovery_rate"].base == Decimal("0.85")
    assert reader.get(_url(deployment, "no_such_set")).status_code == 404


def test_a_viewer_never_writes(deployment, people):
    response = _post(_client(people["viewer"]), deployment, full_document())
    assert response.status_code == 403, response.content
    assert not CustomerParameterSet.objects.exists()


def test_a_deployment_the_caller_cannot_see_is_not_found(deployment, other_deployment, people):
    _post(_client(people["admin"]), other_deployment, full_document())
    viewer = _client(people["viewer"])
    # Another tenant's set: 404 on every route, the same as a deployment that does not exist.
    for response in (
        viewer.get(_url(other_deployment)),
        viewer.get(_url(other_deployment, versions=True)),
        _post(viewer, other_deployment, full_document()),
    ):
        assert response.status_code == 404, response.content
    missing = Deployment(name="never-saved")
    assert viewer.get(_url(missing)).status_code == 404
    # The same key in another deployment is another set.
    assert viewer.get(_url(deployment)).status_code == 404
    assert CustomerParameterSet.objects.filter(deployment=other_deployment).count() == 1
    assert not CustomerParameterSet.objects.filter(deployment=deployment).exists()


def test_the_api_scopes_deployments_as_the_deployment_list_does(deployment, other_deployment, people):
    from assurance.economics.api import visible_deployments

    for user in people.values():
        listed = _client(user).get("/api/assurance/deployments/")
        rows = listed.json()
        rows = rows["results"] if isinstance(rows, dict) else rows
        assert {r["uuid"] for r in rows} == {str(d.uuid) for d in visible_deployments(user)}, user.username


def test_a_signed_out_caller_is_refused(deployment):
    client = _client()
    assert client.get(_url(deployment)).status_code == 401
    assert _post(client, deployment, full_document()).status_code == 401
    assert not CustomerParameterSet.objects.exists()


def test_a_recorded_version_is_never_edited_or_deleted_over_the_api(deployment, people):
    _post(_client(people["admin"]), deployment, full_document())
    admin = _client(people["admin"])
    for url in (_url(deployment), _url(deployment, versions=True)):
        assert admin.put(url, {}, format="json").status_code == 405
        assert admin.patch(url, {}, format="json").status_code == 405
        assert admin.delete(url).status_code == 405
    assert admin.post(_url(deployment), {}, format="json").status_code == 405
    assert CustomerParameterSet.objects.get().intact()


API_REFUSALS = [
    ("an unknown top-level field", lambda d: d.update(author="mallory"), "field_unrecognised"),
    ("an unknown variable", lambda d: d["variables"].update(ebitda=d["variables"]["legal_retainer"]), "field_unrecognised"),
    ("an unknown entry field", lambda d: d["variables"]["recovery_rate"].update(note="x"), "field_unrecognised"),
    ("a JSON number", lambda d: d["variables"]["recovery_rate"].update(low=0.7), "not_decimal"),
    ("an exponent", lambda d: d["variables"]["customer_count"].update(base="1.2e6"), "not_decimal"),
    ("a NaN string", lambda d: d["variables"]["customer_count"].update(base="NaN"), "not_decimal"),
    ("the wrong unit", lambda d: d["variables"]["transactions_per_day"].update(unit="count"), "unit_mismatch"),
    ("a rate above 1", lambda d: d["variables"]["recovery_rate"].update(high="1.01"), "ratio_out_of_range"),
    ("a negative count", lambda d: d["variables"]["customer_count"].update(low="-5"), "negative_value"),
    ("fresh before effective", lambda d: d["variables"]["recovery_rate"].update(fresh_until="2026-01-01"), "date_inversion"),
    ("no variables", lambda d: d.update(variables={}), "field_missing"),
]


@pytest.mark.parametrize("what, edit, code", API_REFUSALS, ids=[c[0] for c in API_REFUSALS])
def test_the_api_refuses_with_the_engines_code_and_records_nothing(deployment, people, what, edit, code):
    document = full_document()
    edit(document)
    response = _post(_client(people["analyst"]), deployment, document)
    assert response.status_code == 400, response.content
    assert response.json()["code"] == code, response.json()
    assert not CustomerParameterSet.objects.exists() and not FinancialParameter.objects.exists()


def test_the_api_reads_json_strictly(deployment, people):
    client = _client(people["analyst"])
    text = json.dumps(full_document())
    duplicate = text.replace('"variables": {', '"variables": {"recovery_rate": {}, ', 1)
    bare_nan = text.replace('"0.85"', "NaN", 1)
    for body in (duplicate, bare_nan, "{", "[]", '"variables"'):
        response = _post(client, deployment, body, raw=True)
        assert response.status_code == 400, (body[:40], response.content)
    form = client.post(_url(deployment, versions=True), {"variables": "x"}, format="multipart")
    assert form.status_code == 415, form.content
    bad_key = _post(client, deployment, full_document(), set_key="Not-A-Key")
    assert bad_key.status_code == 400 and bad_key.json()["code"] == "set_key_malformed"
    assert not CustomerParameterSet.objects.exists()


def test_no_economics_route_is_a_stop():
    """Every route the economics module serves is classified as not a stop, and
    none is in the stop set or rides its exemption."""
    found = {}

    def walk(patterns):
        for pattern in patterns:
            if isinstance(pattern, URLResolver):
                walk(pattern.url_patterns)
                continue
            view = getattr(pattern.callback, "cls", None) or getattr(pattern.callback, "view_class", None)
            if view is not None and view.__module__.startswith("assurance.economics"):
                found[pattern.name] = view

    walk(get_resolver().url_patterns)
    assert set(found) == {"deployment-economics-parameter-set", "deployment-economics-parameter-set-versions"}
    for name in found:
        assert name not in stops.STOP_ROUTES and name not in stops.EXEMPT_ROUTES
        assert name in stops.NOT_STOPS
    assert set(stops.NOT_STOPS["deployment-economics-parameter-set-versions"]) == {"GET", "POST"}
    assert set(stops.NOT_STOPS["deployment-economics-parameter-set"]) == {"GET"}
