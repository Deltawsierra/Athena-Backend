"""The industry packs against the database and the routes (Economic Exposure E7;
``docs/economics/spec-v1.md``, section 37).

- BANKING UNCHANGED: a banking build is byte for byte the build master made before E7
  (its build digest and its events, components, figures and sources, both pinned as
  master computed them), and a banking card names no pack;
- a parameter set names its pack and states its inputs through the route; nothing is
  required at record time (choice 2), and a set answers ONE pack in every version
  (``set_pack_changed``), so every scenario built on it can refresh;
- a scenario builds under exactly ONE pack through the build route, recorded on the
  version (its build row and document, with the pack's digest and statements), shown
  on the events route (each template's pack, an input read from the pack's schema), in
  the report (its build and its limitations) and on the Validity Card, which state what
  the BUILD recorded even when the registry no longer holds the pack; the refresh
  rebuilds it under its pack;
- refused with its code, nothing written: a build under one pack on a set of another
  (``pack_mismatch``), a template whose input the set lacks (``pack_input_missing``),
  harm to a person (``safety_monetisation_refused``);
- the registry's route serves every pack to a signed-in caller.

SYNTHETIC / ILLUSTRATIVE: every figure here is made up.
"""

from __future__ import annotations

import hashlib
import json
import re
import uuid
from datetime import date
from decimal import Decimal

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from assurance.economics import builder, continuous_service, report, validity_service
from assurance.economics.engine import pack_inputs, pack_registry
from assurance.economics.engine.pack_base import HARM_EXCLUDED, PHYSICAL_WORLD_CAUTION
from assurance.economics.engine.parameters import MONEY_UNITS, ParameterRefused, Unit
from assurance.economics.models import (
    CausalEffect,
    CustomerParameterSet,
    FinancialParameter,
    FinancialScenario,
    FinancialValidityCard,
    LossEvent,
    ScenarioBuild,
    SimulationResult,
)
from assurance.models import Asset, Deployment, Finding
from tests import test_economics_packs as packs
from tests.test_economics_scenarios import _entry

pytestmark = pytest.mark.django_db

User = get_user_model()
INSURANCE = "mythos.economics.insurance-pack/v1"
HEALTHCARE = "mythos.economics.healthcare-pack/v1"
SAAS = "mythos.economics.saas-pack/v1"
POISSON = {"id": "poisson", "version": 1, "params": {"rate": "2"}}
QUICK = "quick_10k"


@pytest.fixture
def people():
    return {
        "admin": User.objects.create_user(username="ada", password="x", role="admin"),
        "analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
        "viewer": User.objects.create_user(username="vic", password="x", role="viewer"),
    }


@pytest.fixture
def deployment(people):
    return Deployment.objects.create(name="claims-agent", owner=people["viewer"])


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


def _figures(figures, unit, source):
    low, base, high = (figures * 3)[:3] if len(figures) == 1 else figures
    return _entry(unit, low, base, high, source_type=source, evidence_ref="SYNTHETIC / ILLUSTRATIVE")


def set_document(pack_id, *, drop=(), variables=None, frequency=False, inputs=None) -> dict:
    """A parameter-set document for ``pack_id``: the shared variables and every input of
    its schema (less ``drop``), each the customer's own, from the pack tests' figures."""
    pack = pack_registry.PACKS[pack_id]
    document = {
        "variables": {
            name: _figures(figures[1:], figures[0], "CUSTOMER_PROVIDED")
            for name, figures in (packs.VARIABLES if variables is None else variables).items()
        },
        "pack": pack_id,
        "pack_inputs": {
            name: _figures((inputs or packs.INPUTS)[name], entry.unit.value, "CUSTOMER_PROVIDED")
            for name, entry in pack.inputs.items()
            if name not in drop
        },
    }
    if frequency:
        document["frequency"] = _entry("count", "1", "2", "4", source_type="INDUSTRY_BENCHMARK",
                                       evidence_ref="SYNTHETIC / ILLUSTRATIVE", distribution=POISSON)
    return document


def attributes_of(template_id, *, source="EXPERT_ESTIMATE", figures=None) -> dict:
    """Every attribute the template reads, from the pack tests' figures."""
    chosen = pack_registry.template(template_id, 1)
    pack = pack_registry.PACKS[chosen.pack]
    names = {s.name for c in chosen.components for s in c.sources.values() if s.kind.value == "effect_attribute"}
    found = {}
    for name in sorted(names):
        unit = pack.attributes[name].unit
        # Customer loss reads the customer's own churn figure only (section 31).
        found[name] = _figures((figures or packs.ATTRIBUTES)[name], unit.value,
                               "CUSTOMER_PROVIDED" if name == "churn_rate" else source)
    return found


def _asset(deployment, name="claims-agent"):
    return Asset.objects.create(deployment=deployment, kind="agent", name=name, identifier=f"agent://{name}")


def _finding(deployment, n=1):
    return Finding.objects.create(deployment=deployment, fingerprint=f"fp-{n}-{uuid.uuid4().hex[:8]}",
                                  finding_type="approval_check_missing", title=f"finding {n}", severity="high")


def record_set(client, deployment, document, set_key="pack_set"):
    return client.post(f"/api/assurance/deployments/{deployment.uuid}/economics/parameter-sets/{set_key}/versions/",
                       data=json.dumps(document), content_type="application/json")


def build_body(effects, finding, *, pack=None, set_key="pack_set", version=1):
    body = {
        "title": "An industry pack's scenario",
        "parameter_set": {"set_key": set_key, "version": version},
        "currency": "USD",
        "as_of": "2026-10-06",
        "effects": effects,
        "findings": [{"finding": str(finding.uuid), "effect": e["key"], "role": "prerequisite"} for e in effects],
    }
    if pack is not None:
        body["pack"] = pack
    return body


def effect(key, asset, effect_type, process, attributes):
    return {"key": key, "origin": "hypothetical", "effect_type": effect_type, "asset": str(asset.uuid),
            "business_process": process, "attributes": attributes}


def build(client, deployment, body):
    return client.post(f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/build/",
                       data=json.dumps(body), content_type="application/json")


def _range(served) -> list[Decimal]:
    return [Decimal(served[p]) for p in ("low", "base", "high")]


def _counts() -> dict:
    return {model.__name__: model.objects.count()
            for model in (CustomerParameterSet, FinancialScenario, ScenarioBuild, CausalEffect, LossEvent,
                          FinancialParameter)}


# ======================================================================
# Banking, byte for byte
# ======================================================================

#: Fixed ids, so that a banking build's digest is the same in every run: the build
#: below, run on master at ddee17d (before E7), gave these two digests.
DEPLOYMENT = uuid.UUID("e7e70000-0000-4000-8000-000000000001")
ASSETS = (uuid.UUID("e7e70000-0000-4000-8000-000000000002"), uuid.UUID("e7e70000-0000-4000-8000-000000000003"))
FINDINGS = (uuid.UUID("e7e70000-0000-4000-8000-000000000004"), uuid.UUID("e7e70000-0000-4000-8000-000000000005"))
MASTER_BUILD_DIGEST = "sha256:669dd1e59d9ef2a98da54920d21e877d448c3001acaae37536ce10e4e4caf0d1"
MASTER_PROJECTION_DIGEST = "sha256:a92b2ce5b03796215bb829970640d3f9c80d806c821ca3eca5925a0434d25241"
_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
_TIME = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(\+00:00|Z)?")


def _attr(unit, low, base=None, high=None, source="EXPERT_ESTIMATE"):
    return _entry(unit, low, base, high, source_type=source, evidence_ref="SYNTHETIC / ILLUSTRATIVE: made up")


def banking_build():
    """Section 30's payment loss, an approval bypassed on the same agent, and section
    31's cross-customer exposure: three banking effects, two events, under no pack."""
    owner = User.objects.create_user(username="e7-owner", password="x", role="viewer")
    analyst = User.objects.create_user(username="e7-analyst", password="x", role="analyst")
    deployment = Deployment.objects.create(uuid=DEPLOYMENT, name="payments-agent", owner=owner)
    payments = Asset.objects.create(uuid=ASSETS[0], deployment=deployment, kind="agent", name="payments-agent",
                                    identifier="agent://payments-agent")
    crm = Asset.objects.create(uuid=ASSETS[1], deployment=deployment, kind="data_store", name="crm-store",
                               identifier="data_store://crm-store")
    findings = [
        Finding.objects.create(uuid=u, deployment=deployment, fingerprint=f"fp-e7-{n}",
                               finding_type="approval_check_missing", title=f"finding {n}", severity="high")
        for n, u in enumerate(FINDINGS, 1)
    ]
    variables = {
        "transactions_per_day": _entry("count_per_day", "18000"),
        "average_transaction_value": _entry("money_per_unit", "25000"),
        "recovery_rate": _entry("ratio", "0.70", "0.825", "0.95"),
        "notification_unit_cost": _entry("money_per_unit", "1.50", "2.00", "3.00"),
        "notification_fixed_cost": _entry("money", "25000", "40000", "60000"),
        "support_agent_hourly_rate": _entry("money_per_hour", "40", "55", "70"),
        "security_responder_hourly_rate": _entry("money_per_hour", "300", "400", "500"),
        "legal_retainer": _entry("money", "25000", "50000", "100000"),
        "external_counsel_hourly_rate": _entry("money_per_hour", "450", "600", "800"),
        "insurance_deductible": _entry("money", "100000"),
        "insurance_limit": _entry("money", "1000000"),
    }
    CustomerParameterSet.record(deployment, "bank_prod_2026q4", {"variables": variables}, author=analyst)
    redirect = {
        "success_rate": _attr("ratio", "0.35"),
        "exploitable_window_hours": _attr("hours", "0.5", "1.25", "2.0"),
        "incident_response_cost": _attr("money", "80000", "165000", "250000"),
        "legal_response_cost": _attr("money", "150000", "825000", "1500000"),
    }
    exposure = {
        "affected_customers": _attr("count", "20000", "50000", "120000"),
        "contact_rate": _attr("ratio", "0.05", "0.10", "0.20", "INDUSTRY_BENCHMARK"),
        "handling_hours": _attr("hours", "0.10", "0.15", "0.25"),
        "forensics_fixed_cost": _attr("money", "50000", "75000", "100000"),
        "investigation_hours": _attr("hours", "200", "400", "800"),
        "counsel_hours": _attr("hours", "100", "300", "800"),
        "regulatory_response_cost": _attr("money", "0", "100000", "500000"),
        "churn_rate": _attr("ratio", "0.01", "0.02", "0.04", "CUSTOMER_PROVIDED"),
        "margin_per_customer_per_year": _attr("money_per_unit", "120", "150", "200"),
        "churn_recovery_years": _attr("years", "1", "1", "2"),
    }
    body = {
        "title": "Banking, byte for byte",
        "parameter_set": {"set_key": "bank_prod_2026q4", "version": 1},
        "currency": "USD",
        "as_of": "2026-10-06",
        "effects": [
            {"key": "redirect", "origin": "hypothetical", "effect_type": "funds_transfer_altered",
             "asset": str(payments.uuid), "business_process": "payments", "attributes": redirect},
            {"key": "bypass", "origin": "hypothetical", "effect_type": "approval_bypassed",
             "asset": str(payments.uuid), "business_process": "payments", "attributes": redirect},
            {"key": "exposure", "origin": "hypothetical", "effect_type": "cross_customer_disclosure",
             "asset": str(crm.uuid), "business_process": "customer_service", "attributes": exposure},
        ],
        "findings": [
            {"finding": str(findings[0].uuid), "effect": "redirect", "role": "prerequisite"},
            {"finding": str(findings[1].uuid), "effect": "bypass", "role": "amplifier"},
            {"finding": str(findings[1].uuid), "effect": "exposure", "role": "prerequisite"},
        ],
    }
    scenario, created = builder.build(deployment, body, author=analyst)
    assert created
    return scenario


def projection_digest(scenario) -> str:
    """The digest of what the events route shows of a build -- its build, events,
    components, figures and every input's source -- with only the ids a run draws
    afresh (rows' uuids) and the instants set aside."""
    described = builder.describe(scenario)
    kept = {"build": described["build"], "events": described["events"], "totals": described["totals"]}
    text = json.dumps(kept, sort_keys=True, separators=(",", ":"))
    fixed = {str(u) for u in (DEPLOYMENT, *ASSETS, *FINDINGS)}
    text = _UUID.sub(lambda m: m.group(0) if m.group(0) in fixed else "<uuid>", text)
    text = _TIME.sub("<time>", text)
    return "sha256:" + hashlib.sha256(text.encode("utf-8")).hexdigest()


def test_a_banking_build_is_byte_for_byte_what_it_was():
    """BANKING UNCHANGED. A build that names no pack is the banking pack's, and it is the
    build master made before E7, byte for byte: the same build digest (everything it is
    built from, the pack and its six templates among them), and the same events,
    components, figures and sources as the events route shows them."""
    scenario = banking_build()
    row = ScenarioBuild.objects.get(scenario=scenario)
    assert row.build_digest == MASTER_BUILD_DIGEST
    assert projection_digest(scenario) == MASTER_PROJECTION_DIGEST
    assert row.pack == "mythos.economics.banking-pack/v1"
    assert sorted(row.inputs) == ["as_of", "builder", "currency", "deployment", "effects", "findings", "grouping",
                                  "grouping_window_hours", "pack", "parameter_set", "templates"]
    assert CustomerParameterSet.objects.get(deployment=scenario.deployment).pack == ""
    # The same build named under its own pack, explicitly, is refused: one spelling.
    body = continuous_service.rebuild_body(scenario, as_of=date(2026, 10, 6))
    assert "pack" not in body
    with pytest.raises(ParameterRefused) as refused:
        builder.parse_request({**body, "pack": "mythos.economics.banking-pack/v1"})
    assert refused.value.code == "pack_unrecognised"


# ======================================================================
# The parameter set, through its route
# ======================================================================


@pytest.mark.parametrize("pack_id", [INSURANCE, HEALTHCARE, SAAS])
def test_a_set_names_its_pack_and_states_its_inputs_through_the_route(deployment, people, pack_id):
    client = _client(people["analyst"])
    response = record_set(client, deployment, set_document(pack_id))
    assert response.status_code == 201, response.content
    served = response.json()
    assert served["pack"] == pack_id
    schema = pack_inputs.SCHEMAS[pack_id]
    assert set(served["pack_inputs"]) == set(schema.inputs)
    for name, entry in served["pack_inputs"].items():
        assert entry["unit"] == schema.inputs[name].unit.value and entry["meaning"] == schema.inputs[name].meaning
        assert "required" not in entry  # required only by a build that reads it (choice 2)
        assert entry["source_type"] == "CUSTOMER_PROVIDED" and entry["evidence_ref"]
    version = CustomerParameterSet.objects.get(deployment=deployment)
    assert version.pack == pack_id and version.intact()
    names = {row.name for row in version.parameter_rows()}
    assert {pack_inputs.PACK_INPUT_PREFIX + name for name in schema.inputs} <= names
    current = client.get(f"/api/assurance/deployments/{deployment.uuid}/economics/parameter-sets/pack_set/")
    assert current.status_code == 200 and current.json()["pack_inputs"] == served["pack_inputs"]


def test_a_banking_set_is_served_as_it_was(deployment, people):
    response = record_set(_client(people["analyst"]), deployment,
                          {"variables": {"legal_retainer": _entry("money", "50000")}})
    assert response.status_code == 201, response.content
    assert "pack" not in response.json() and "pack_inputs" not in response.json()


@pytest.mark.parametrize("pack_id", [INSURANCE, HEALTHCARE, SAAS])
def test_a_set_records_without_inputs_and_what_it_names_wrongly_is_refused(deployment, people, pack_id):
    """Choice 2 (interim): a set is never pushed to state an input -- with none it
    records -- and a set that names a pack wrongly is refused with its code, nothing
    recorded."""
    response = record_set(_client(people["analyst"]), deployment,
                          set_document(pack_id, drop=set(pack_inputs.SCHEMAS[pack_id].inputs)), set_key="bare")
    assert response.status_code == 201, response.content
    assert response.json()["pack"] == pack_id and response.json()["pack_inputs"] == {}
    before = _counts()
    for document, code in (
        ({**set_document(pack_id), "pack": "mythos.economics.no-such-pack/v1"}, "pack_unrecognised"),
        ({**set_document(pack_id), "pack": "mythos.economics.banking-pack/v1"}, "pack_unrecognised"),
        ({"variables": {"legal_retainer": _entry("money", "1")}, "pack_inputs": {}}, "field_unrecognised"),
    ):
        response = record_set(_client(people["analyst"]), deployment, document)
        assert response.status_code == 400 and response.json()["code"] == code, response.content
    assert _counts() == before


# ======================================================================
# One pack per build, recorded
# ======================================================================


def test_an_insurance_scenario_builds_under_its_pack_and_says_so(deployment, people):
    """Two effects on the claims agent -- a claim overpaid and an approval bypassed on
    the claims process -- are ONE loss event of insurance_claims_overpayment (the lower
    precedence of the two templates that cover the bypass), at the template's known
    answer; the version records the pack, and the events route names it and the input
    each figure was read from."""
    analyst = _client(people["analyst"])
    assert record_set(analyst, deployment, set_document(INSURANCE)).status_code == 201
    asset, finding = _asset(deployment), _finding(deployment)
    attributes = attributes_of("insurance_claims_overpayment")
    body = build_body(
        [effect("overpay", asset, "claim_overpaid", "claims", attributes),
         effect("bypass", asset, "approval_bypassed", "claims", attributes)],
        finding, pack=INSURANCE,
    )
    response = build(analyst, deployment, body)
    assert response.status_code == 201, response.content
    served = response.json()
    assert served["build"]["pack"] == INSURANCE
    (event,) = served["events"]
    assert event["template"]["template_id"] == "insurance_claims_overpayment"
    assert event["template"]["pack"] == INSURANCE and "cautions" not in event["template"]
    assert {e["key"] for e in event["effects"]} == {"overpay", "bypass"}
    bypass = next(e for e in event["effects"] if e["key"] == "bypass")
    assert bypass["in_scope_of"] == [["insurance_claims_overpayment", 1], ["insurance_agent_approval_bypass", 1]]
    assert _range(event["gross_cash"]) == [Decimal(x) for x in packs.KNOWN_GROSS["insurance_claims_overpayment"]]
    overpaid = next(c for c in event["components"] if c["component_id"] == "overpaid-claims")
    source = overpaid["sources"]["transactions_per_day"]
    assert source["template"] == {"from": "pack_input", "name": "claims_per_day"}
    assert source["read"] == {"from": "pack_input", "name": "claims_per_day",
                              "parameter_set": {"set_key": "pack_set", "version": 1}}
    scenario = FinancialScenario.objects.get(uuid=served["scenario"]["uuid"])
    row = ScenarioBuild.objects.get(scenario=scenario)
    assert row.pack == INSURANCE and row.inputs["pack"] == INSURANCE
    assert row.inputs["templates"] == [[t.template_id, 1] for t in pack_registry.PACKS[INSURANCE].templates]
    # The build records the digest of the pack it was built under, and what its figures
    # are read with (F1, F5).
    assert row.inputs["pack_digest"] == pack_registry.PACKS[INSURANCE].digest == pack_registry.RELEASED[INSURANCE]
    assert row.inputs["pack_statements"] == {"cautions": [], "excluded": [HARM_EXCLUDED]}
    assert row.pack_record() == {"id": INSURANCE, "digest": row.inputs["pack_digest"], "cautions": [],
                                 "excluded": [HARM_EXCLUDED]}
    # The events route says the same; the refresh rebuilds under the same pack, and the
    # same inputs return the same scenario, never a second.
    events = analyst.get(f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario.uuid}/events/")
    assert events.status_code == 200 and events.json()["events"] == served["events"]
    rebuilt = continuous_service.rebuild_body(scenario, as_of=date(2026, 10, 6))
    assert rebuilt["pack"] == INSURANCE
    assert builder.parse_request(rebuilt).pack is pack_registry.PACKS[INSURANCE]
    again = build(analyst, deployment, body)
    assert again.status_code == 200 and again.json()["scenario"]["uuid"] == served["scenario"]["uuid"]


def test_a_build_under_one_pack_on_a_set_of_another_is_refused(deployment, people):
    analyst = _client(people["analyst"])
    assert record_set(analyst, deployment, set_document(INSURANCE)).status_code == 201
    assert record_set(analyst, deployment, {"variables": {"legal_retainer": _entry("money", "1")}},
                      set_key="bank_set").status_code == 201
    assert record_set(analyst, deployment, set_document(SAAS), set_key="saas_set").status_code == 201
    asset, finding = _asset(deployment), _finding(deployment)
    overpay = effect("overpay", asset, "claim_overpaid", "claims", attributes_of("insurance_claims_overpayment"))
    payment = effect("redirect", asset, "funds_transfer_altered", "payments", {})
    before = _counts()
    for body in (
        build_body([payment], finding),  # a banking build on an insurance set
        build_body([overpay], finding, pack=INSURANCE, set_key="bank_set"),  # an insurance build on a banking set
        build_body([overpay], finding, pack=INSURANCE, set_key="saas_set"),  # on another pack's set
    ):
        response = build(analyst, deployment, body)
        assert response.status_code == 400, response.content
        assert response.json()["code"] == "pack_mismatch"
    assert _counts() == before


def test_a_template_whose_input_the_set_lacks_is_refused_never_defaulted(deployment, people):
    """The provider-outage template reads the customer's cost of handling a claim by
    hand, which the pack does not require: a set without it is recorded, and a build
    whose effect that template takes is refused, naming both."""
    analyst = _client(people["analyst"])
    response = record_set(analyst, deployment, set_document(INSURANCE, drop={"manual_claim_handling_cost"}))
    assert response.status_code == 201, response.content
    asset, finding = _asset(deployment), _finding(deployment)
    outage = effect("outage", asset, "provider_outage", "claims", attributes_of("insurance_provider_outage"))
    before = _counts()
    response = build(analyst, deployment, build_body([outage], finding, pack=INSURANCE))
    assert response.status_code == 400, response.content
    assert response.json()["code"] == "pack_input_missing"
    assert "insurance_provider_outage" in response.json()["detail"]
    assert "manual_claim_handling_cost" in response.json()["detail"]
    assert _counts() == before
    # A template that reads only what the set states builds.
    overpay = effect("overpay", asset, "claim_overpaid", "claims", attributes_of("insurance_claims_overpayment"))
    assert build(analyst, deployment, build_body([overpay], finding, pack=INSURANCE)).status_code == 201


def test_harm_to_a_person_is_refused_through_the_route(deployment, people):
    analyst = _client(people["analyst"])
    assert record_set(analyst, deployment, set_document(HEALTHCARE)).status_code == 201
    asset, finding = _asset(deployment), _finding(deployment)
    harmed = effect("harm", asset, "patient_harmed", "clinical_care", {})
    priced = effect("review", asset, "clinical_workflow_interrupted", "clinical_care",
                    {**attributes_of("healthcare_clinical_workflow_interruption"),
                     "injury_cost": _attr("money", "1000")})
    before = _counts()
    for body in (build_body([harmed], finding, pack=HEALTHCARE), build_body([priced], finding, pack=HEALTHCARE)):
        response = build(analyst, deployment, body)
        assert response.status_code == 400, response.content
        assert response.json()["code"] == "safety_monetisation_refused"
    assert _counts() == before


def test_an_unknown_pack_or_another_packs_vocabulary_is_refused(deployment, people):
    analyst = _client(people["analyst"])
    assert record_set(analyst, deployment, set_document(SAAS)).status_code == 201
    asset, finding = _asset(deployment), _finding(deployment)
    outage = effect("outage", asset, "platform_outage", "tenant_platform", attributes_of("saas_platform_outage"))
    cases = (
        (build_body([outage], finding, pack="mythos.economics.saas-pack/v9"), "pack_unrecognised"),
        (build_body([{**outage, "attributes": {}}], finding, pack=INSURANCE), "effect_type_unrecognised"),
        (build_body([{**outage, "business_process": "payments"}], finding, pack=SAAS), "business_process_unrecognised"),
        (build_body([{**outage, "attributes": {"success_rate": _attr("ratio", "0.1")}}], finding, pack=SAAS),
         "attribute_unrecognised"),
    )
    for body, code in cases:
        response = build(analyst, deployment, body)
        assert response.status_code == 400 and response.json()["code"] == code, (code, response.content)


# ======================================================================
# The report and the Validity Card
# ======================================================================

#: A hospital's clinical workflow interrupted: SYNTHETIC / ILLUSTRATIVE.
#:   care-disruption    4 h x 15,000 = 60,000;  12 h x 15,000 = 180,000;  48 h x 15,000 = 720,000
#:   workflow-recovery  10,000 + 200 x 40 = 18,000; 25,000 + 200 x 120 = 49,000; 50,000 + 200 x 300 = 110,000
#:   clinical-review    20,000 / 60,000 / 150,000
#:   gross              98,000 / 289,000 / 980,000
CLINICAL_GROSS = [Decimal(98000), Decimal(289000), Decimal(980000)]


def _simulated(deployment, people, pack_id, template_id, effect_type, process, variables, inputs):
    analyst = _client(people["analyst"])
    response = record_set(analyst, deployment, set_document(pack_id, variables=variables, inputs=inputs,
                                                            frequency=True))
    assert response.status_code == 201, response.content
    asset, finding = _asset(deployment), _finding(deployment)
    body = build_body([effect("e", asset, effect_type, process, attributes_of(template_id))], finding, pack=pack_id)
    built = build(analyst, deployment, body)
    assert built.status_code == 201, built.content
    scenario = FinancialScenario.objects.get(uuid=built.json()["scenario"]["uuid"])
    base = f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario.uuid}/"
    run = analyst.post(base + "simulate/", data=json.dumps({"seed": 7, "policy": QUICK}),
                       content_type="application/json")
    assert run.status_code == 201, run.content
    served = analyst.get(base + "results/")
    assert served.status_code == 200, served.content
    return built.json(), served.json(), SimulationResult.objects.get(scenario=scenario)


def test_an_industry_packs_report_and_card_name_the_pack_and_its_caution(deployment, people):
    """A physical-world template's scenario, built and simulated: the events route shows
    its caution, the report names the pack in its build and adds the pack's statements
    after its own limitations, and the Validity Card -- which the receipt signs --
    names the pack, the caution and what the pack never prices."""
    # The customer's own figures at a point; the effect's, an expert's ranges.
    variables = {"engineering_hourly_rate": ("money_per_hour", "200")}
    inputs = {name: (figures[1] if len(figures) == 3 else figures[0],) for name, figures in packs.INPUTS.items()}
    built, served, result = _simulated(
        deployment, people, HEALTHCARE, "healthcare_clinical_workflow_interruption", "clinical_workflow_interrupted",
        "clinical_care", variables, inputs,
    )
    (event,) = built["events"]
    assert event["template"]["cautions"] == [PHYSICAL_WORLD_CAUTION]
    assert _range(event["gross_cash"]) == CLINICAL_GROSS
    assert served["build"]["pack"] == HEALTHCARE
    added = served["limitations"][len(report.LIMITATIONS):]
    assert served["limitations"][: len(report.LIMITATIONS)] == list(report.LIMITATIONS)
    assert added[0].startswith(f"built under the industry pack {HEALTHCARE}")
    assert added[1:] == [PHYSICAL_WORLD_CAUTION, HARM_EXCLUDED]
    card = FinancialValidityCard.objects.get(simulation=result)
    assert card.card["fields"]["scenario"]["pack"] == {
        "id": HEALTHCARE, "digest": pack_registry.RELEASED[HEALTHCARE], "cautions": [PHYSICAL_WORLD_CAUTION],
        "excluded": [HARM_EXCLUDED],
    }
    assert validity_service.reproduces(card)


def test_a_report_and_card_keep_the_packs_statements_when_the_registry_no_longer_holds_it(
    deployment, people, monkeypatch
):
    """F5: a report and a card state what the BUILD recorded of its pack -- its digest,
    the cautions of its templates, what it never prices -- never what the registry holds
    now. A release that no longer holds the pack still states them, says it does not
    hold the pack, and never shows the scenario as a banking one; its card still
    reproduces; and its refresh names the pack, which the build then refuses, never a
    banking rebuild."""
    variables = {"engineering_hourly_rate": ("money_per_hour", "200")}
    inputs = {name: (figures[1] if len(figures) == 3 else figures[0],) for name, figures in packs.INPUTS.items()}
    built, served, result = _simulated(
        deployment, people, HEALTHCARE, "healthcare_clinical_workflow_interruption", "clinical_workflow_interrupted",
        "clinical_care", variables, inputs,
    )
    scenario = FinancialScenario.objects.get(uuid=built["scenario"]["uuid"])
    row = ScenarioBuild.objects.get(scenario=scenario)
    card = FinancialValidityCard.objects.get(simulation=result)
    held = served["limitations"][len(report.LIMITATIONS):]
    # A later release that no longer holds the healthcare pack.
    monkeypatch.setattr(pack_registry, "PACKS", {k: v for k, v in pack_registry.PACKS.items() if k != HEALTHCARE})
    monkeypatch.setattr(pack_registry, "TEMPLATES",
                        {k: t for k, t in pack_registry.TEMPLATES.items() if t.pack != HEALTHCARE})
    schemas = {k: v for k, v in pack_inputs.SCHEMAS.items() if k != HEALTHCARE}
    monkeypatch.setattr(pack_inputs, "SCHEMAS", schemas)
    for module in (report, validity_service, continuous_service):
        monkeypatch.setattr(module, "INDUSTRY_PACKS", schemas, raising=False)
    limitations = report.pack_limitations(row, scenario)
    assert limitations[0] == held[0] and limitations[0].startswith(f"built under the industry pack {HEALTHCARE}")
    assert pack_registry.RELEASED[HEALTHCARE] in limitations[0]
    assert limitations[1] == (
        f"this release does not hold the industry pack {HEALTHCARE}: the cautions and exclusions below are the ones "
        "recorded with the build"
    )
    assert limitations[2:] == [PHYSICAL_WORLD_CAUTION, HARM_EXCLUDED] == held[1:]
    assert validity_service.pack_statement(row) == card.card["fields"]["scenario"]["pack"]
    assert validity_service.reproduces(card)
    body = continuous_service.rebuild_body(scenario, as_of=date(2026, 10, 6))
    assert body["pack"] == HEALTHCARE
    with pytest.raises(ParameterRefused) as refused:
        builder.parse_request(body)
    assert refused.value.code == "pack_unrecognised"


def test_a_banking_card_and_report_name_no_pack(people):
    """A banking build simulated: its card's scenario names no pack and its report's
    limitations are the report's own, as before E7."""
    owner = people["viewer"]
    deployment = Deployment.objects.create(name="payments-agent", owner=owner)
    analyst = _client(people["analyst"])
    variables = {
        "transactions_per_day": _entry("count_per_day", "18000"),
        "average_transaction_value": _entry("money_per_unit", "25000"),
        "recovery_rate": _entry("ratio", "0.825"),
    }
    frequency = _entry("count", "1", "2", "4", source_type="INDUSTRY_BENCHMARK", evidence_ref="SYNTHETIC",
                       distribution=POISSON)
    assert record_set(analyst, deployment, {"variables": variables, "frequency": frequency},
                      set_key="bank_set").status_code == 201
    asset, finding = _asset(deployment, "payments-agent"), _finding(deployment)
    attributes = {
        "success_rate": _attr("ratio", "0.35"),
        "exploitable_window_hours": _attr("hours", "0.5", "1.25", "2.0"),
        "incident_response_cost": _attr("money", "80000", "165000", "250000"),
        "legal_response_cost": _attr("money", "150000", "825000", "1500000"),
    }
    body = build_body([effect("redirect", asset, "funds_transfer_altered", "payments", attributes)], finding,
                      set_key="bank_set")
    built = build(analyst, deployment, body)
    assert built.status_code == 201, built.content
    scenario = FinancialScenario.objects.get(uuid=built.json()["scenario"]["uuid"])
    base = f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario.uuid}/"
    assert analyst.post(base + "simulate/", data=json.dumps({"seed": 7, "policy": QUICK}),
                        content_type="application/json").status_code == 201
    served = analyst.get(base + "results/").json()
    assert served["build"]["pack"] == "mythos.economics.banking-pack/v1"
    assert served["limitations"] == list(report.LIMITATIONS)
    card = FinancialValidityCard.objects.get(simulation=SimulationResult.objects.get(scenario=scenario))
    assert "pack" not in card.card["fields"]["scenario"]


# ======================================================================
# A set answers one pack; a build requires only what it reads; usage revenue
# ======================================================================


def test_a_set_answers_one_pack_in_every_version_so_its_scenarios_refresh(deployment, people):
    """F6: a new version of a set that names another pack -- another industry pack, or
    none (banking), or a banking set gaining one -- is refused (``set_pack_changed``),
    nothing recorded; a new version under the same pack records, and a scenario built on
    an earlier version refreshes against it."""
    analyst = _client(people["analyst"])
    assert record_set(analyst, deployment, set_document(INSURANCE)).status_code == 201
    assert record_set(analyst, deployment, {"variables": {"legal_retainer": _entry("money", "1")}},
                      set_key="bank_set").status_code == 201
    asset, finding = _asset(deployment), _finding(deployment)
    overpay = effect("overpay", asset, "claim_overpaid", "claims", attributes_of("insurance_claims_overpayment"))
    built = build(analyst, deployment, build_body([overpay], finding, pack=INSURANCE))
    assert built.status_code == 201, built.content
    before = _counts()
    for document, set_key in (
        (set_document(SAAS), "pack_set"),
        ({"variables": {"legal_retainer": _entry("money", "1")}}, "pack_set"),
        (set_document(INSURANCE), "bank_set"),
    ):
        response = record_set(analyst, deployment, document, set_key=set_key)
        assert response.status_code == 400, response.content
        assert response.json()["code"] == "set_pack_changed", response.content
    assert _counts() == before
    changed = set_document(INSURANCE, inputs={**packs.INPUTS, "claims_per_day": ("1500",)})
    assert record_set(analyst, deployment, changed).status_code == 201
    scenario = FinancialScenario.objects.get(uuid=built.json()["scenario"]["uuid"])
    body = continuous_service.rebuild_body(scenario, as_of=date(2026, 10, 6))
    assert body["parameter_set"] == {"set_key": "pack_set", "version": 2} and body["pack"] == INSURANCE
    refreshed = build(analyst, deployment, body)
    assert refreshed.status_code == 201, refreshed.content
    assert refreshed.json()["build"]["pack"] == INSURANCE


def test_a_build_requires_only_the_inputs_its_templates_read(deployment, people):
    """Choice 2 (interim): a hospital that states only what a PHI exposure reads -- its
    records and its breach cost per record -- records its set and builds that scenario;
    it is never pushed to state a care-disruption cost; a build that reads one it does
    not state is refused, naming it, and nothing is written."""
    analyst = _client(people["analyst"])
    kept = {"patient_record_count", "breach_cost_per_record"}
    document = set_document(HEALTHCARE, drop=set(pack_inputs.SCHEMAS[HEALTHCARE].inputs) - kept)
    assert record_set(analyst, deployment, document).status_code == 201
    asset, finding = _asset(deployment), _finding(deployment)
    phi = effect("phi", asset, "phi_disclosure", "patient_records", attributes_of("healthcare_phi_exposure"))
    assert build(analyst, deployment, build_body([phi], finding, pack=HEALTHCARE)).status_code == 201
    clinical = effect("care", asset, "clinical_workflow_interrupted", "clinical_care",
                      attributes_of("healthcare_clinical_workflow_interruption"))
    before = _counts()
    response = build(analyst, deployment, build_body([clinical], finding, pack=HEALTHCARE))
    assert response.status_code == 400 and response.json()["code"] == "pack_input_missing", response.content
    assert "care_disruption_cost_per_hour" in response.json()["detail"]
    assert _counts() == before


def test_a_saas_outage_prices_usage_revenue_only_where_the_set_states_it(deployment, people):
    """Choice 8 (interim), through the route: a platform that bills by usage states its
    usage margin and its outage prices usage revenue; one that bills by subscription
    alone states none, and builds the outage without it, never a zero, never refused."""
    analyst = _client(people["analyst"])
    asset, finding = _asset(deployment), _finding(deployment)
    outage = effect("outage", asset, "platform_outage", "tenant_platform", attributes_of("saas_platform_outage"))
    figures = {}
    for set_key, drop in (("usage", ()), ("subscription", {"usage_margin_per_hour"})):
        assert record_set(analyst, deployment, set_document(SAAS, drop=drop), set_key=set_key).status_code == 201
        response = build(analyst, deployment, build_body([outage], finding, pack=SAAS, set_key=set_key))
        assert response.status_code == 201, response.content
        (event,) = response.json()["events"]
        figures[set_key] = ({c["component_id"] for c in event["components"]}, _range(event["gross_cash"]))
    assert "usage-revenue" in figures["usage"][0] and "usage-revenue" not in figures["subscription"][0]
    assert figures["usage"][1] == [Decimal(x) for x in packs.KNOWN_GROSS["saas_platform_outage"]]
    assert figures["subscription"][1] == [Decimal(x) for x in packs.OUTAGE_WITHOUT_USAGE]


# ======================================================================
# The registry's route
# ======================================================================


def test_the_registry_route_serves_every_pack_to_a_signed_in_caller(people):
    response = _client(people["viewer"]).get("/api/assurance/economics/packs/")
    assert response.status_code == 200, response.content
    served = response.json()
    assert [p["pack"] for p in served["packs"]] == list(pack_registry.PACKS)
    assert served == json.loads(json.dumps(pack_registry.registry_document()))
    assert _client().get("/api/assurance/economics/packs/").status_code == 401


def test_an_input_named_for_the_schema_is_stored_in_its_unit(deployment, people):
    """A stored pack input is held to its schema's unit when its row is saved, as a
    variable is: the parent's pack decides it."""
    record_set(_client(people["analyst"]), deployment, set_document(SAAS))
    version = CustomerParameterSet.objects.get(deployment=deployment)
    row = next(r for r in version.parameter_rows() if r.name == pack_inputs.PACK_INPUT_PREFIX + "tenant_count")
    assert Unit(row.unit) is Unit.COUNT and Unit(row.unit) not in MONEY_UNITS
