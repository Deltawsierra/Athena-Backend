"""The scenario builder, its records and its routes, against the database
(``docs/economics/spec-v1.md``, section 23).

- section 30's bank payment agent, BUILT FROM A SPINE OBSERVED EFFECT, comes out
  exactly as #146's known answer; section 31's from hypothetical effects too;
- the double-count invariant: 1, 2 and 5 findings on one effect make one event with
  the same totals; two distinct effects make two; a rebuild makes nothing new; a late
  finding joins its event and adds no component; an effect two templates cover is in
  one event; and the database holds an effect, and an observation, to one event;
- a missing input is unknown, never zero, and every value names its recorded source;
- tenant isolation, roles, strict JSON, the 413 cap, idempotency under a race (409,
  nothing duplicated), the review rule;
- SAFETY: a builder or template module that will not import leaves the scan's Stop
  answering 202 and ``deliver_owed_stops`` running.

SYNTHETIC / ILLUSTRATIVE: every figure here is made up (section 30's are the
specification's own illustrative ones).
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import uuid
from datetime import date, datetime, timedelta
from datetime import timezone as dt_timezone
from decimal import Decimal
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.db import IntegrityError, models, transaction
from django.urls import URLResolver, get_resolver
from rest_framework.test import APIClient

from assurance.economics import builder
from assurance.economics.engine import templates as tpl
from assurance.economics.engine.parameters import Parameter
from assurance.economics.models import (
    CausalEffect,
    CustomerParameterSet,
    EconomicsRefused,
    EconomicsRewriteRefused,
    EffectFinding,
    FinancialParameter,
    FinancialScenario,
    LossComponent,
    LossEvent,
    ScenarioBuild,
    ScenarioReview,
    SeparationOfDutiesRefused,
)
from assurance.models import Asset, Deployment, Finding, WorkflowChainOutcome
from safety import stops
from tests import signed_chains
from tests.test_economics_scenarios import _entry

pytestmark = pytest.mark.django_db

User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "docs" / "economics" / "spec-v1.md"
LABEL = "SYNTHETIC / ILLUSTRATIVE"
SET_KEY = "bank_prod_2026q4"

SECTION_30_GROSS = [Decimal("394062.50"), Decimal("2425546.875"), Decimal("5687500")]
SECTION_30_DIRECT = [Decimal("164062.50"), Decimal("1435546.875"), Decimal("3937500")]


@pytest.fixture
def people():
    return {
        "admin": User.objects.create_user(username="ada", password="x", role="admin"),
        "analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
        "reviewer": User.objects.create_user(username="bea", password="x", role="analyst"),
        "viewer": User.objects.create_user(username="vic", password="x", role="viewer"),
        "other": User.objects.create_user(username="oto", password="x", role="viewer"),
    }


@pytest.fixture
def deployment(people):
    return Deployment.objects.create(name="payments-agent", owner=people["viewer"])


@pytest.fixture
def other_deployment(people):
    return Deployment.objects.create(name="someone-elses", owner=people["other"])


def _asset(deployment, name="payments-agent", kind="agent"):
    return Asset.objects.create(deployment=deployment, kind=kind, name=name, identifier=f"{kind}://{name}")


def _finding(deployment, n=1):
    return Finding.objects.create(
        deployment=deployment,
        fingerprint=f"fp-{n}-{uuid.uuid4().hex[:8]}",
        finding_type="approval_check_missing",
        title=f"finding {n}",
        severity="high",
    )


def _attr(unit, low, base=None, high=None, *, source="EXPERT_ESTIMATE", why="made up"):
    return _entry(unit, low, base, high, source_type=source, evidence_ref=f"{LABEL}: {why}")


SECTION_30_SET = {
    "transactions_per_day": _entry("count_per_day", "18000"),
    "average_transaction_value": _entry("money_per_unit", "25000"),
    "recovery_rate": _entry("ratio", "0.70", "0.825", "0.95"),
}


def _section_30_attributes(success_source="EXPERT_ESTIMATE"):
    return {
        "success_rate": _attr("ratio", "0.35", source=success_source, why="7 unauthorized effects in 20 attempts"),
        "exploitable_window_hours": _attr("hours", "0.5", "1.25", "2.0", why="repeatable window"),
        "incident_response_cost": _attr("money", "80000", "165000", "250000", why="incident response"),
        "legal_response_cost": _attr("money", "150000", "825000", "1500000", why="legal/regulatory response"),
    }


def _pset(deployment, author, variables=None, **extra):
    document = {"variables": dict(SECTION_30_SET if variables is None else variables), **extra}
    return CustomerParameterSet.record(deployment, SET_KEY, document, author=author)


def _effect(key, asset, *, origin="hypothetical", effect_type="funds_transfer_altered", process="payments",
            attributes=None, observed=None):
    effect = {
        "key": key,
        "origin": origin,
        "effect_type": effect_type,
        "asset": str(asset.uuid),
        "business_process": process,
        "attributes": _section_30_attributes() if attributes is None else attributes,
    }
    if observed is not None:
        effect["observed_effect"] = str(observed.uuid)
    return effect


def _link(finding, effect, role="prerequisite"):
    return {"finding": str(finding.uuid), "effect": effect, "role": role}


def _body(effects, findings=(), *, version=1, **over):
    body = {
        "title": "Payment agent: destination changed after approval",
        "parameter_set": {"set_key": SET_KEY, "version": version},
        "currency": "USD",
        "as_of": "2026-10-06",
        "effects": list(effects),
        "findings": list(findings),
    }
    body.update(over)
    return body


def _url(deployment, scenario=None):
    base = f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/"
    return base + "build/" if scenario is None else base + f"{scenario}/events/"


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


def _build(client, deployment, body, raw=False, **extra):
    data = body if raw else json.dumps(body)
    return client.post(_url(deployment), data=data, content_type="application/json", **extra)


def _figures(range_) -> list[Decimal]:
    return [Decimal(range_[point]) for point in ("low", "base", "high")]


def _counts() -> dict:
    return {
        model.__name__: model.objects.count()
        for model in (FinancialScenario, ScenarioBuild, CausalEffect, EffectFinding, FinancialParameter, LossEvent,
                      LossComponent)
    }


def _payment_world(deployment, people, n_findings=1):
    asset = _asset(deployment)
    _pset(deployment, people["analyst"])
    findings = [_finding(deployment, n) for n in range(1, n_findings + 1)]
    return asset, findings


def _now(minutes=1):
    return datetime.now(dt_timezone.utc) - timedelta(minutes=minutes)


def _observed(deployment, minutes=1, workflow="payments", tool=("tool", "payments-api")):
    return signed_chains.record_observed_effect(
        deployment, workflow, uuid.uuid4().hex, _now(minutes), schema="v1", tool=tool
    )


# ======================================================== the known answers


@pytest.mark.usefixtures("engine_keyring")
def test_section_30_built_from_an_observed_effect_is_146s_known_answer(deployment, people):
    """Section 30, built from a SPINE observed effect (Achilles changed a transfer's
    destination after approval) and three findings that enable it, gives exactly the
    figures #146 computed by hand: direct loss 164,062.50 / 1,435,546.875 / 3,937,500
    and gross cash loss 394,062.50 / 2,425,546.875 / 5,687,500."""
    asset, findings = _payment_world(deployment, people, 3)
    row = _observed(deployment)
    effect = _effect("redirect", asset, origin="observed", observed=row,
                     attributes=_section_30_attributes(success_source="MYTHOS_OBSERVED"))
    links = [_link(findings[0], "redirect"), _link(findings[1], "redirect", "amplifier"),
             _link(findings[2], "redirect", "alternate_path")]
    response = _build(_client(people["analyst"]), deployment, _body([effect], links))
    assert response.status_code == 201, response.content
    body = response.json()
    assert body["created"] is True and body["scenario"]["author"] == "ann"
    (event,) = body["events"]
    assert _figures(event["gross_cash"]) == SECTION_30_GROSS
    assert event["gross_cash"]["complete"] is True
    components = {c["component_id"]: c for c in event["components"]}
    assert list(components) == ["direct-loss", "incident-response", "legal-regulatory-response"]
    assert [Decimal(components["direct-loss"][p]) for p in ("low", "base", "high")] == SECTION_30_DIRECT
    assert [c["formula"]["formula_id"] for c in event["components"]] == ["repeat_in_window", "lump_sum", "lump_sum"]
    # The template that made it, the effect as SPINE names it, and the observation.
    assert event["template"]["template_id"] == "payment_agent_misuse"
    (built,) = event["effects"]
    assert built["origin"] == "observed" and built["observed_effect"] == str(row.uuid)
    assert built["observation"] == row.evidence_digest
    assert built["spine_effect"] == event["effect"] and event["effect"].startswith("sha256:")
    assert datetime.fromisoformat(built["occurred_at"]) == row.observed_at
    assert {f["finding"] for f in built["findings"]} == {str(f.uuid) for f in findings}
    assert {f["role"] for f in built["findings"]} == {"prerequisite", "amplifier", "alternate_path"}
    # Where each input came from: the customer's figures from the parameter set, the
    # observed rate from the effect.
    sources = components["direct-loss"]["sources"]
    assert sources["transactions_per_day"]["read"] == {
        "from": "parameter_set", "name": "transactions_per_day", "parameter_set": {"set_key": SET_KEY, "version": 1}
    }
    assert sources["success_rate"]["read"] == {"from": "effect_attribute", "name": "success_rate", "effect": "redirect"}
    read = {i["input"]: i["parameter"]["source_type"] for i in components["direct-loss"]["inputs"]}
    assert read["success_rate"] == "MYTHOS_OBSERVED" and read["value_per_transaction"] == "CUSTOMER_PROVIDED"
    # The events route reads the same back.
    again = _client(people["viewer"]).get(_url(deployment, body["scenario"]["uuid"]))
    assert again.status_code == 200, again.content
    assert again.json()["events"] == body["events"] and again.json()["totals"] == body["totals"]


def test_section_31_built_from_effects_is_146s_known_answer(deployment, people):
    """Section 31 (cross-customer data exposure), built from a hypothetical effect,
    gives #146's answer: gross cash loss at least 239,000 / 746,250 / 2,580,000 (the
    churn figure is a benchmark, so customer loss is unknown) and, with the set's
    policy, at least 100,000 / 231,250 / 1,580,000 retained."""
    asset = _asset(deployment, "crm-store", "data_store")
    variables = {
        "notification_unit_cost": _entry("money_per_unit", "1.50", "2.00", "3.00"),
        "notification_fixed_cost": _entry("money", "25000", "40000", "60000"),
        "support_agent_hourly_rate": _entry("money_per_hour", "40", "55", "70"),
        "security_responder_hourly_rate": _entry("money_per_hour", "300", "400", "500"),
        "legal_retainer": _entry("money", "25000", "50000", "100000"),
        "external_counsel_hourly_rate": _entry("money_per_hour", "450", "600", "800"),
        "insurance_deductible": _entry("money", "100000"),
        "insurance_limit": _entry("money", "1000000"),
    }
    _pset(deployment, people["analyst"], variables, insurance_sublimits={"notification": _entry("money", "150000")},
          insurance_exclusions=["regulatory_compliance"])
    attributes = {
        "affected_customers": _attr("count", "20000", "50000", "120000", why="reachable records"),
        "contact_rate": _attr("ratio", "0.05", "0.10", "0.20", source="INDUSTRY_BENCHMARK"),
        "handling_hours": _attr("hours", "0.10", "0.15", "0.25"),
        "forensics_fixed_cost": _attr("money", "50000", "75000", "100000"),
        "investigation_hours": _attr("hours", "200", "400", "800"),
        "counsel_hours": _attr("hours", "100", "300", "800"),
        "regulatory_response_cost": _attr("money", "0", "100000", "500000", why="scenario bounds"),
        "churn_rate": _attr("ratio", "0.01", "0.02", "0.04", source="INDUSTRY_BENCHMARK"),
        "margin_per_customer_per_year": _attr("money_per_unit", "120", "150", "200"),
        "churn_recovery_years": _attr("years", "1", "1", "2"),
    }
    finding = _finding(deployment)
    effect = _effect("exposure", asset, effect_type="cross_customer_disclosure", process="customer_service",
                     attributes=attributes)
    response = _build(_client(people["admin"]), deployment, _body([effect], [_link(finding, "exposure")]))
    assert response.status_code == 201, response.content
    (event,) = response.json()["events"]
    assert _figures(event["gross_cash"]) == [Decimal(239000), Decimal(746250), Decimal(2580000)]
    assert event["gross_cash"]["complete"] is False
    assert event["gross_cash"]["unknown_components"] == ["customer-loss"]
    assert _figures(event["retained_cash"]) == [Decimal(100000), Decimal(231250), Decimal(1580000)]
    assert event["unknown_components"] == ["customer-loss", "share-price-reaction"]
    assert event["market_value"]["never_added_to_cash"] is True


# ============================================================ the invariant


def test_one_two_and_five_findings_on_one_effect_make_one_event_with_the_same_totals(deployment, people):
    """The specification's own test (section 27): five findings that enable one
    payment loss make ONE event, and the loss is not multiplied."""
    asset, findings = _payment_world(deployment, people, 5)
    client = _client(people["analyst"])
    seen = []
    for n in (1, 2, 5):
        links = [_link(f, "redirect") for f in findings[:n]]
        response = _build(client, deployment, _body([_effect("redirect", asset)], links))
        assert response.status_code == 201, response.content
        body = response.json()
        (event,) = body["events"]
        assert len(event["findings"]) == n
        assert [c["component_id"] for c in event["components"]] == [
            "direct-loss", "incident-response", "legal-regulatory-response"
        ]
        assert _figures(event["gross_cash"]) == SECTION_30_GROSS
        assert _figures(body["totals"]["gross_cash"]) == SECTION_30_GROSS
        seen.append(event["event_key"])
    assert len(set(seen)) == 1
    assert LossEvent.objects.count() == 3 and LossComponent.objects.count() == 9  # three builds, never more


def test_two_distinct_effects_make_two_events(deployment, people):
    asset, findings = _payment_world(deployment, people, 2)
    second = _asset(deployment, "treasury-agent")
    effects = [_effect("redirect", asset), _effect("treasury", second)]
    links = [_link(findings[0], "redirect"), _link(findings[1], "treasury")]
    response = _build(_client(people["analyst"]), deployment, _body(effects, links))
    assert response.status_code == 201, response.content
    body = response.json()
    assert len(body["events"]) == 2
    assert {tuple(e["key"] for e in event["effects"]) for event in body["events"]} == {("redirect",), ("treasury",)}
    for event in body["events"]:
        assert _figures(event["gross_cash"]) == SECTION_30_GROSS
    assert _figures(body["totals"]["gross_cash"]) == [2 * x for x in SECTION_30_GROSS]


def test_one_finding_enabling_two_effects_counts_each_effect_once(deployment, people):
    asset, (finding,) = _payment_world(deployment, people, 1)
    second = _asset(deployment, "treasury-agent")
    effects = [_effect("redirect", asset), _effect("treasury", second)]
    links = [_link(finding, "redirect"), _link(finding, "treasury")]
    body = _build(_client(people["analyst"]), deployment, _body(effects, links)).json()
    assert len(body["events"]) == 2
    assert _figures(body["totals"]["gross_cash"]) == [2 * x for x in SECTION_30_GROSS]


def test_a_rebuild_returns_the_same_scenario_and_writes_nothing(deployment, people):
    asset, findings = _payment_world(deployment, people, 2)
    body = _body([_effect("redirect", asset)], [_link(f, "redirect") for f in findings])
    first = _build(_client(people["analyst"]), deployment, body)
    assert first.status_code == 201, first.content
    before = _counts()
    # The same inputs, in another order, by another person, under another title.
    shuffled = _body([_effect("redirect", asset)], [_link(f, "redirect") for f in reversed(findings)],
                     title="the same build, retitled")
    again = _build(_client(people["admin"]), deployment, shuffled)
    assert again.status_code == 200, again.content
    assert again.json()["created"] is False
    assert again.json()["scenario"]["uuid"] == first.json()["scenario"]["uuid"]
    assert again.json()["events"] == first.json()["events"]
    assert again.json()["build"]["digest"] == first.json()["build"]["digest"]
    assert _counts() == before


def test_a_late_finding_joins_its_event_and_adds_no_component(deployment, people):
    asset, (early, late) = _payment_world(deployment, people, 2)
    client = _client(people["analyst"])
    first = _build(client, deployment, _body([_effect("redirect", asset)], [_link(early, "redirect")])).json()
    second = _build(
        client,
        deployment,
        _body([_effect("redirect", asset)], [_link(early, "redirect"), _link(late, "redirect", "amplifier")],
              supersedes=first["scenario"]["uuid"]),
    )
    assert second.status_code == 201, second.content
    second = second.json()
    assert second["scenario"]["supersedes"] == first["scenario"]["uuid"]
    (before,), (after,) = first["events"], second["events"]
    assert after["event_key"] == before["event_key"]
    assert [c["component_id"] for c in after["components"]] == [c["component_id"] for c in before["components"]]
    assert _figures(after["gross_cash"]) == _figures(before["gross_cash"]) == SECTION_30_GROSS
    assert after["findings"] == sorted([str(early.uuid), str(late.uuid)])
    assert before["findings"] == [str(early.uuid)]


@pytest.mark.parametrize("process, template", [("payments", "payment_agent_misuse"),
                                               ("fraud_aml", "fraud_aml_workflow_failure"),
                                               ("lending", "agent_approval_bypass")])
def test_an_effect_two_templates_cover_is_in_one_event(deployment, people, process, template):
    asset, (finding,) = _payment_world(deployment, people, 1)
    effect = _effect("bypass", asset, effect_type="approval_bypassed", process=process)
    response = _build(_client(people["analyst"]), deployment, _body([effect], [_link(finding, "bypass")]))
    assert response.status_code == 201, response.content
    (event,) = response.json()["events"]
    assert event["template"]["template_id"] == template
    (built,) = event["effects"]
    in_scope = [t for t, _ in built["in_scope_of"]]
    assert in_scope[0] == template and "agent_approval_bypass" in in_scope
    assert CausalEffect.objects.count() == 1 and LossEvent.objects.count() == 1
    assert {c.component_key for c in LossComponent.objects.all()} == {
        c.component_key for c in tpl.CATALOGUE[(template, 1)].components
    }


def test_the_database_holds_an_effect_to_one_event(deployment, people):
    """Past the model's checks, the database still refuses a second row for one
    effect key, or one SPINE observation, in a scenario, and an observed effect with
    no observation; the model refuses them first, with ``duplicate_id``."""
    asset, (finding,) = _payment_world(deployment, people, 1)
    body = _build(_client(people["analyst"]), deployment,
                  _body([_effect("redirect", asset)], [_link(finding, "redirect")])).json()
    scenario = FinancialScenario.objects.get(uuid=body["scenario"]["uuid"])
    (effect,) = CausalEffect.objects.all()
    other_event = LossEvent.objects.create(scenario=scenario, event_key="ev-second", currency="USD")
    fields = {f.name: getattr(effect, f.name) for f in CausalEffect._meta.concrete_fields if f.name not in ("id", "uuid")}
    fields["loss_event"] = other_event
    with pytest.raises(EconomicsRefused) as refused:
        CausalEffect.objects.create(**fields)
    assert refused.value.code == "duplicate_id"
    with pytest.raises(IntegrityError), transaction.atomic():
        models.Model.save(CausalEffect(**fields), force_insert=True)
    observed = {**fields, "effect_key": "again", "origin": "observed", "observed_effect": str(uuid.uuid4()),
                "observation": "sha256:" + "ab" * 32}
    models.Model.save(CausalEffect(**observed), force_insert=True)
    with pytest.raises(IntegrityError), transaction.atomic():
        models.Model.save(CausalEffect(**{**observed, "effect_key": "third"}), force_insert=True)
    with pytest.raises(IntegrityError), transaction.atomic():
        models.Model.save(CausalEffect(**{**observed, "effect_key": "fourth", "observation": ""}), force_insert=True)


def test_a_finding_enables_an_effect_once(deployment, people):
    asset, (finding,) = _payment_world(deployment, people, 1)
    _build(_client(people["analyst"]), deployment, _body([_effect("redirect", asset)], [_link(finding, "redirect")]))
    (link,) = EffectFinding.objects.all()
    with pytest.raises(EconomicsRefused) as refused:
        EffectFinding.objects.create(effect=link.effect, finding=link.finding, role="amplifier")
    assert refused.value.code == "duplicate_id"
    with pytest.raises(IntegrityError), transaction.atomic():
        models.Model.save(EffectFinding(effect=link.effect, finding=link.finding, role="amplifier"), force_insert=True)
    duplicate = _body([_effect("redirect", asset)], [_link(finding, "redirect"), _link(finding, "redirect", "amplifier")])
    response = _build(_client(people["analyst"]), deployment, duplicate)
    assert response.status_code == 400 and response.json()["code"] == "duplicate_id"


# =============================================================== grouping


def _input(key, *, asset="a" * 8 + "-0000-4000-8000-" + "0" * 12, effect_type=tpl.EffectType.FUNDS_TRANSFER_ALTERED,
           process=tpl.BusinessProcess.PAYMENTS, at=None, origin=None):
    observed = at is not None
    return builder.EffectInput(
        key=key,
        origin=origin or (tpl.Origin.OBSERVED if observed else tpl.Origin.HYPOTHETICAL),
        effect_type=effect_type,
        asset=asset,
        business_process=process,
        observed_effect=str(uuid.uuid4()) if observed else "",
        observation=("sha256:" + uuid.uuid4().hex * 2) if observed else "",
        occurred_at=at,
    )


def _links(effect, n):
    return [builder.LinkInput(str(uuid.uuid4()), effect, tpl.FindingRole.PREREQUISITE) for _ in range(n)]


T0 = datetime(2026, 10, 1, 9, 0, tzinfo=dt_timezone.utc)


def test_findings_never_make_events_of_their_own():
    for n in (1, 2, 5):
        (plan,) = builder.group([_input("redirect")], _links("redirect", n))
        assert len(plan.links) == n and [e.key for e in plan.effects] == ["redirect"]


def test_the_window_joins_observed_effects_and_a_hypothetical_joins_the_first():
    effects = [
        _input("first", at=T0),
        _input("an-hour-later", at=T0 + timedelta(hours=1)),
        _input("at-the-edge", at=T0 + timedelta(hours=24)),
        _input("next-day", at=T0 + timedelta(hours=25)),
        _input("hypothetical"),
        _input("other-asset", at=T0, asset="b" * 8 + "-0000-4000-8000-" + "0" * 12),
        _input("other-type", at=T0, effect_type=tpl.EffectType.APPROVAL_BYPASSED),
    ]
    plans = builder.group(effects, [])
    events = sorted([e.key for e in plan.effects] for plan in plans)
    assert events == sorted([
        ["first", "an-hour-later", "at-the-edge", "hypothetical"],
        ["next-day"],
        ["other-asset"],
        ["other-type"],
    ])
    # The lead is the window's first: its attributes are what the components read.
    lead = next(plan for plan in plans if "first" in [e.key for e in plan.effects])
    assert lead.lead.key == "first"
    # Hypothetical effects alone, one bucket: one event.
    (alone,) = builder.group([_input("x"), _input("y")], _links("x", 1) + _links("y", 1))
    assert [e.key for e in alone.effects] == ["x", "y"] and alone.anchor is None


def test_grouping_is_deterministic_and_order_free():
    effects = [_input("a", at=T0), _input("b", at=T0 + timedelta(hours=30)), _input("c")]
    links = _links("a", 2) + _links("c", 3)
    once = builder.group(effects, links)
    twice = builder.group(list(reversed(effects)), list(reversed(links)))
    assert [(p.event_key, [e.key for e in p.effects], p.links) for p in once] == [
        (p.event_key, [e.key for e in p.effects], p.links) for p in twice
    ]
    # A finding added to an effect leaves the event's key as it was.
    more = builder.group(effects, links + _links("a", 1))
    assert [p.event_key for p in more] == [p.event_key for p in once]


@pytest.mark.parametrize("process", [tpl.BusinessProcess.PAYMENTS, tpl.BusinessProcess.FRAUD_AML])
def test_an_effect_two_templates_cover_makes_one_plan(process):
    effect = _input("bypass", effect_type=tpl.EffectType.APPROVAL_BYPASSED, process=process)
    (plan,) = builder.group([effect], _links("bypass", 2))
    assert len(tpl.in_scope(effect.effect_type, process)) == 2
    assert plan.template is tpl.select(effect.effect_type, process).template
    assert [e.key for e in plan.effects] == ["bypass"]


def test_the_grouping_key_names_no_finding():
    effect = _input("redirect")
    selection = tpl.select(effect.effect_type, effect.business_process)
    one, two = (builder.Member(effect, selection, link) for link in _links("redirect", 2))
    assert builder.grouping_key(one) == builder.grouping_key(two) == builder.grouping_key(
        builder.Member(effect, selection)
    )
    assert builder.grouping_key(one) == ("payment_agent_misuse", "1", "funds_transfer_altered", effect.asset, "payments")


# ============================================================ idempotency


#: One observed effect, fixed, so two documents built from it differ only where a
#: test changes them.
BASE_EFFECT = builder.EffectInput(
    key="redirect",
    origin=tpl.Origin.OBSERVED,
    effect_type=tpl.EffectType.FUNDS_TRANSFER_ALTERED,
    asset="a" * 8 + "-0000-4000-8000-" + "0" * 12,
    business_process=tpl.BusinessProcess.PAYMENTS,
    observed_effect="0" * 8 + "-0000-4000-8000-" + "1" * 12,
    observation="sha256:" + "7" * 64,
    spine_effect="sha256:" + "8" * 64,
    occurred_at=T0,
)


def _document(**over):
    effect = BASE_EFFECT
    attribute = Parameter("redirect.success_rate", "ratio", "EXPERT_ESTIMATE", Decimal("0.35"), Decimal("0.35"),
                          Decimal("0.35"), "e", date(2026, 9, 30))
    fields = {
        "deployment_uuid": "d" * 8 + "-0000-4000-8000-" + "0" * 12,
        "parameter_set": {"set_key": SET_KEY, "version": 1, "content_digest": "sha256:" + "0" * 64},
        "currency": "USD",
        "as_of": date(2026, 10, 6),
        "effects": [builder.EffectInput(**{**effect.__dict__, "attributes": {"success_rate": attribute}})],
        "links": [builder.LinkInput("f" * 8 + "-0000-4000-8000-" + "0" * 12, "redirect", tpl.FindingRole.PREREQUISITE)],
    }
    fields.update(over)
    return builder.build_document(**fields)


def test_the_digest_changes_with_every_input():
    base = builder.build_digest(_document())
    effect = _document()["effects"][0]
    attribute = Parameter("redirect.success_rate", "ratio", "EXPERT_ESTIMATE", Decimal("0.35"), Decimal("0.35"),
                          Decimal("0.35"), "e", date(2026, 9, 30))
    original = BASE_EFFECT

    def effect_with(**change):
        fields = {**original.__dict__, "attributes": {"success_rate": attribute}, **change}
        return [builder.EffectInput(**fields)]

    variants = {
        "deployment": _document(deployment_uuid="e" * 8 + "-0000-4000-8000-" + "0" * 12),
        "parameter-set version": _document(parameter_set={"set_key": SET_KEY, "version": 2,
                                                          "content_digest": "sha256:" + "0" * 64}),
        "parameter-set digest": _document(parameter_set={"set_key": SET_KEY, "version": 1,
                                                         "content_digest": "sha256:" + "1" * 64}),
        "currency": _document(currency="EUR"),
        "as-of": _document(as_of=date(2026, 10, 7)),
        "effect type": _document(effects=effect_with(effect_type=tpl.EffectType.APPROVAL_BYPASSED)),
        "asset": _document(effects=effect_with(asset="c" * 8 + "-0000-4000-8000-" + "0" * 12)),
        "process": _document(effects=effect_with(business_process=tpl.BusinessProcess.LENDING)),
        "occurred": _document(effects=effect_with(occurred_at=T0 + timedelta(seconds=1))),
        "observation": _document(effects=effect_with(observation="sha256:" + "9" * 64)),
        "observed effect": _document(effects=effect_with(observed_effect="0" * 8 + "-0000-4000-8000-" + "2" * 12)),
        "spine effect": _document(effects=effect_with(spine_effect="sha256:" + "6" * 64)),
        "origin": _document(effects=effect_with(origin=tpl.Origin.HYPOTHETICAL)),
        "effect key": _document(effects=effect_with(key="redirect-2")),
        "attribute value": _document(effects=effect_with(attributes={"success_rate": Parameter(
            "redirect.success_rate", "ratio", "EXPERT_ESTIMATE", Decimal("0.35"), Decimal("0.35"), Decimal("0.36"),
            "e", date(2026, 9, 30))})),
        "attribute source": _document(effects=effect_with(attributes={"success_rate": Parameter(
            "redirect.success_rate", "ratio", "CUSTOMER_PROVIDED", Decimal("0.35"), Decimal("0.35"), Decimal("0.35"),
            "e", date(2026, 9, 30))})),
        "no finding": _document(links=[]),
        "finding role": _document(links=[builder.LinkInput("f" * 8 + "-0000-4000-8000-" + "0" * 12, "redirect",
                                                           tpl.FindingRole.AMPLIFIER)]),
    }
    digests = {name: builder.build_digest(document) for name, document in variants.items()}
    for name, digest in digests.items():
        assert digest != base, name
    assert len(set(digests.values())) == len(digests)
    assert effect["attributes"]["success_rate"]["source_type"] == "EXPERT_ESTIMATE"
    assert builder.build_digest(_document()) == base


def test_a_changed_input_builds_a_new_scenario(deployment, people):
    asset, (finding,) = _payment_world(deployment, people, 1)
    client = _client(people["analyst"])
    first = _build(client, deployment, _body([_effect("redirect", asset)], [_link(finding, "redirect")]))
    attributes = _section_30_attributes()
    attributes["exploitable_window_hours"] = _attr("hours", "0.5", "1.25", "3.0")
    changed = _build(client, deployment, _body([_effect("redirect", asset, attributes=attributes)],
                                               [_link(finding, "redirect")]))
    assert first.status_code == 201 and changed.status_code == 201, changed.content
    assert changed.json()["scenario"]["uuid"] != first.json()["scenario"]["uuid"]
    assert _figures(changed.json()["totals"]["gross_cash"])[2] > SECTION_30_GROSS[2]
    # A new parameter-set version is another input too.
    _pset(deployment, people["analyst"])
    third = _build(client, deployment, _body([_effect("redirect", asset)], [_link(finding, "redirect")], version=2))
    assert third.status_code == 201, third.content


def test_a_build_raced_by_the_same_build_is_409_and_writes_nothing(deployment, people, monkeypatch):
    """Two builds of the same inputs that both found none recorded: the digest's
    unique constraint refuses the second, which answers 409 and writes nothing."""
    asset, (finding,) = _payment_world(deployment, people, 1)
    body = _body([_effect("redirect", asset)], [_link(finding, "redirect")])
    client = _client(people["analyst"])
    assert _build(client, deployment, body).status_code == 201
    before = _counts()
    monkeypatch.setattr(builder, "existing", lambda deployment, digest: None)
    raced = _build(client, deployment, body)
    assert raced.status_code == 409, raced.content
    assert _counts() == before
    monkeypatch.undo()
    assert _build(client, deployment, body).status_code == 200


# ================================================= unknown, and its source


def test_a_missing_input_is_unknown_never_zero_and_names_its_source(deployment, people):
    asset = _asset(deployment)
    lacking = {k: v for k, v in SECTION_30_SET.items() if k != "average_transaction_value"}
    _pset(deployment, people["analyst"], lacking)
    attributes = _section_30_attributes()
    del attributes["legal_response_cost"]
    finding = _finding(deployment)
    response = _build(_client(people["analyst"]), deployment,
                      _body([_effect("redirect", asset, attributes=attributes)], [_link(finding, "redirect")]))
    assert response.status_code == 201, response.content
    (event,) = response.json()["events"]
    components = {c["component_id"]: c for c in event["components"]}
    direct = components["direct-loss"]
    assert direct["status"] == "unknown" and direct["low"] is None and direct["base"] is None
    assert direct["unknown"] == {"reason": "input_missing", "inputs": ["value_per_transaction"]}
    assert direct["sources"]["value_per_transaction"] == {
        "template": {"from": "parameter_set", "name": "average_transaction_value"}, "read": None, "parameter": None
    }
    legal = components["legal-regulatory-response"]
    assert legal["status"] == "unknown" and legal["unknown"]["inputs"] == ["amount"]
    assert legal["sources"]["amount"]["template"] == {"from": "effect_attribute", "name": "legal_response_cost"}
    # Only the incident response is known: the total is that, and reads "at least".
    assert _figures(event["gross_cash"]) == [Decimal(80000), Decimal(165000), Decimal(250000)]
    assert event["gross_cash"]["complete"] is False
    assert event["gross_cash"]["reads_as"] == "at least: the known components only"
    stored = LossComponent.objects.get(component_key="direct-loss")
    assert (stored.status, stored.low, stored.base, stored.high) == ("unknown", "", "", "")
    assert stored.missing_inputs == ["value_per_transaction"]


def test_every_value_is_a_recorded_parameter_with_its_source(deployment, people):
    asset, (finding,) = _payment_world(deployment, people, 1)
    body = _build(_client(people["analyst"]), deployment,
                  _body([_effect("redirect", asset)], [_link(finding, "redirect")])).json()
    for event in body["events"]:
        for component in event["components"]:
            assert component["status"] == "estimated"
            for name, source in component["sources"].items():
                row = FinancialParameter.objects.get(uuid=source["parameter"])
                assert row.source_type and row.evidence_ref.strip()
                assert source["read"]["name"] == source["template"]["name"]
                assert source["read"]["from"] == source["template"]["from"]
                if source["read"]["from"] == "parameter_set":
                    assert row.parameter_set_id is not None and row.name == source["template"]["name"]
                else:
                    assert row.scenario_id is not None and row.name == f"redirect.{source['template']['name']}"
            cited = LossComponent.objects.get(component_key=component["component_id"]).cited_parameters
            assert set(cited.values()) == {s["parameter"] for s in component["sources"].values()}


# ========================================================= market value


def test_market_value_is_reported_apart_and_never_summed_into_cash(deployment, people):
    asset = _asset(deployment, "crm-store", "data_store")
    _pset(deployment, people["analyst"], {"legal_retainer": _entry("money", "25000"),
                                          "external_counsel_hourly_rate": _entry("money_per_hour", "500")})
    attributes = {
        "counsel_hours": _attr("hours", "10"),
        "market_capitalisation": _attr("money", "2000000000"),
        "share_price_decline": _attr("ratio", "0.01", "0.02", "0.05"),
    }
    finding = _finding(deployment)
    effect = _effect("exposure", asset, effect_type="cross_customer_disclosure", process="customer_service",
                     attributes=attributes)
    body = _build(_client(people["analyst"]), deployment, _body([effect], [_link(finding, "exposure")])).json()
    (event,) = body["events"]
    # Cash: only the legal component is known, 25,000 + 500 x 10 = 30,000.
    assert _figures(event["gross_cash"]) == [Decimal(30000)] * 3
    assert _figures(event["market_value"]) == [Decimal(20000000), Decimal(40000000), Decimal(100000000)]
    assert _figures(body["totals"]["gross_cash"]) == [Decimal(30000)] * 3
    assert _figures(body["totals"]["market_value"]) == [Decimal(20000000), Decimal(40000000), Decimal(100000000)]
    assert body["totals"]["market_value"]["never_added_to_cash"] is True


# ====================================================== tenant and roles


def test_another_deployments_findings_and_effects_are_refused(deployment, other_deployment, people):
    asset, (finding,) = _payment_world(deployment, people, 1)
    theirs = _finding(other_deployment)
    their_asset = _asset(other_deployment)
    client = _client(people["admin"])
    for body, code in (
        (_body([_effect("redirect", asset)], [_link(theirs, "redirect")]), "finding_not_found"),
        (_body([_effect("redirect", their_asset)], [_link(finding, "redirect")]), "asset_not_found"),
    ):
        response = _build(client, deployment, body)
        assert response.status_code == 400, response.content
        assert response.json()["code"] == code
    # Another deployment's parameter set, under the same key, is not this one's.
    _pset(other_deployment, people["admin"])
    response = _build(client, deployment, _body([_effect("redirect", asset)], [_link(finding, "redirect")], version=2))
    assert response.status_code == 400 and response.json()["code"] == "parameter_set_not_found"
    assert not FinancialScenario.objects.exists() and not ScenarioBuild.objects.exists()


@pytest.mark.usefixtures("engine_keyring")
def test_another_deployments_observed_effect_is_refused(deployment, other_deployment, people):
    asset, (finding,) = _payment_world(deployment, people, 1)
    theirs = _observed(other_deployment)
    effect = _effect("redirect", asset, origin="observed", observed=theirs)
    response = _build(_client(people["admin"]), deployment, _body([effect], [_link(finding, "redirect")]))
    assert response.status_code == 400 and response.json()["code"] == "observed_effect_not_found", response.content
    assert not FinancialScenario.objects.exists()


@pytest.mark.usefixtures("engine_keyring")
def test_an_observed_effect_that_does_not_stand_is_refused(deployment, people, monkeypatch):
    from assurance import observed_outcomes

    asset, (finding,) = _payment_world(deployment, people, 1)
    row = _observed(deployment)
    typed = WorkflowChainOutcome.objects.create(
        deployment=deployment, workflow="payments", status="held", basis="demonstrated",
        effect_evidence=row.effect_evidence, evidence_digest=row.evidence_digest, observer_engine="achilles-effect",
    )
    client = _client(people["admin"])
    # A row typed in with an observed effect's evidence and no signature behind it.
    response = _build(client, deployment, _body([_effect("redirect", asset, origin="observed", observed=typed)],
                                                [_link(finding, "redirect")]))
    assert response.status_code == 400 and response.json()["code"] == "observed_effect_not_in_force"
    # A signed one, read with no keyring to verify it now.
    monkeypatch.delenv(observed_outcomes.KEYRING_ENV)
    response = _build(client, deployment, _body([_effect("redirect", asset, origin="observed", observed=row)],
                                                [_link(finding, "redirect")]))
    assert response.status_code == 400 and response.json()["code"] == "observed_effect_not_in_force"
    assert not FinancialScenario.objects.exists()


def test_a_viewer_reads_and_never_builds(deployment, other_deployment, people):
    asset, (finding,) = _payment_world(deployment, people, 1)
    body = _body([_effect("redirect", asset)], [_link(finding, "redirect")])
    assert _build(_client(people["viewer"]), deployment, body).status_code == 403
    assert _build(_client(), deployment, body).status_code == 401
    assert not FinancialScenario.objects.exists()
    built = _build(_client(people["analyst"]), deployment, body).json()["scenario"]["uuid"]
    assert _client(people["viewer"]).get(_url(deployment, built)).status_code == 200
    assert _client().get(_url(deployment, built)).status_code == 401
    # A deployment the caller cannot see is 404, and so is a scenario of another
    # deployment under this one's path.
    assert _client(people["other"]).get(_url(deployment, built)).status_code == 404
    assert _build(_client(people["other"]), deployment, body).status_code == 404
    assert _client(people["admin"]).get(_url(other_deployment, built)).status_code == 404
    assert _client(people["admin"]).get(_url(deployment, uuid.uuid4())).status_code == 404


def test_the_author_never_reviews_their_draft(deployment, people):
    asset, (finding,) = _payment_world(deployment, people, 1)
    body = _build(_client(people["analyst"]), deployment,
                  _body([_effect("redirect", asset)], [_link(finding, "redirect")])).json()
    scenario = FinancialScenario.objects.get(uuid=body["scenario"]["uuid"])
    assert (scenario.author, scenario.author_username) == (people["analyst"], "ann")
    with pytest.raises(SeparationOfDutiesRefused) as refused:
        ScenarioReview.objects.create(scenario=scenario, reviewer=people["analyst"], verdict="approved")
    assert refused.value.code == "author_reviews_own_scenario"
    ScenarioReview.objects.create(scenario=scenario, reviewer=people["reviewer"], verdict="approved")


# ============================================================ strict JSON


def test_the_body_is_read_strictly(deployment, people):
    asset, (finding,) = _payment_world(deployment, people, 1)
    client = _client(people["analyst"])
    good = _body([_effect("redirect", asset)], [_link(finding, "redirect")])
    text = json.dumps(good)
    for raw in (text.replace('"currency": "USD"', '"currency": "USD", "currency": "EUR"', 1),
                text.replace('"0.35"', "NaN", 1), "{", "[]"):
        response = _build(client, deployment, raw, raw=True)
        assert response.status_code == 400, (raw[:40], response.content)
    form = client.post(_url(deployment), {"title": "x"}, format="multipart")
    assert form.status_code == 415, form.content

    def edited(change):
        body = json.loads(text)
        change(body)
        return body

    refusals = [
        (lambda b: b.update(author="mallory"), "field_unrecognised"),
        (lambda b: b["effects"][0].update(note="x"), "field_unrecognised"),
        (lambda b: b["effects"][0]["attributes"]["success_rate"].update(low=0.35), "not_decimal"),
        (lambda b: b["effects"][0].update(effect_type="wire_fraud"), "effect_type_unrecognised"),
        (lambda b: b["effects"][0].update(business_process="Payments"), "business_process_unrecognised"),
        (lambda b: b["effects"][0].update(asset=str(asset.uuid).upper()), "field_malformed"),
        (lambda b: b["effects"][0]["attributes"].update(ebitda={}), "attribute_unrecognised"),
        (lambda b: b["effects"][0]["attributes"]["success_rate"].update(source_type="MYTHOS_OBSERVED"),
         "observed_source_on_hypothetical"),
        (lambda b: b["effects"][0].update(observed_effect=str(uuid.uuid4())), "field_unrecognised"),
        (lambda b: b["effects"][0].update(origin="observed"), "field_missing"),
        (lambda b: b.update(findings=[]), "effect_without_finding"),
        (lambda b: b["findings"][0].update(effect="nothing"), "effect_not_declared"),
        (lambda b: b["findings"][0].update(role="cause"), "finding_role_unrecognised"),
        (lambda b: b.update(effects=[]), "field_missing"),
        (lambda b: b.update(effects=b["effects"] * 2), "duplicate_id"),
        (lambda b: b.update(currency="usd"), "currency_unknown"),
        (lambda b: b.update(as_of="2026-13-01"), "date_malformed"),
        (lambda b: b.update(as_of="2026-09-01"), "date_inversion"),
        (lambda b: b["parameter_set"].update(version="1"), "field_malformed"),
        (lambda b: b.update(supersedes=str(uuid.uuid4())), "scenario_not_found"),
    ]
    for change, code in refusals:
        response = _build(client, deployment, edited(change))
        assert response.status_code == 400, (code, response.content)
        assert response.json()["code"] == code, (code, response.json())
    assert not FinancialScenario.objects.exists() and not FinancialParameter.objects.filter(scenario__isnull=False).exists()
    assert _build(client, deployment, good).status_code == 201


def test_a_body_too_large_is_refused_before_it_is_read(deployment, people):
    from assurance.economics.api import MAX_BODY_BYTES

    asset, (finding,) = _payment_world(deployment, people, 1)
    client = _client(people["analyst"])
    body = json.dumps(_body([_effect("redirect", asset)], [_link(finding, "redirect")]))
    padded = body[:-1] + ", " + json.dumps({"padding": "x" * MAX_BODY_BYTES})[1:]
    assert _build(client, deployment, padded, raw=True).status_code == 413
    declared = client.post(_url(deployment), data=body, content_type="application/json",
                           CONTENT_LENGTH=str(MAX_BODY_BYTES + 1))
    assert declared.status_code == 413, declared.content
    assert not FinancialScenario.objects.exists()
    assert _build(client, deployment, body, raw=True).status_code == 201


# =========================================================== the records


def _every_record(deployment, people):
    asset, (finding,) = _payment_world(deployment, people, 1)
    _build(_client(people["analyst"]), deployment, _body([_effect("redirect", asset)], [_link(finding, "redirect")]))
    return [ScenarioBuild.objects.get(), CausalEffect.objects.get(), EffectFinding.objects.get()]


def test_the_new_records_are_append_only(deployment, people):
    for row in _every_record(deployment, people):
        model = type(row)
        with pytest.raises(EconomicsRewriteRefused):
            row.save()
        with pytest.raises(EconomicsRewriteRefused):
            row.delete()
        with pytest.raises(EconomicsRewriteRefused):
            model.objects.filter(pk=row.pk).update(uuid=row.uuid)
        with pytest.raises(EconomicsRewriteRefused):
            model.objects.filter(pk=row.pk).delete()
        with pytest.raises(EconomicsRefused) as refused:
            model.objects.bulk_create([model()])
        assert refused.value.code == "bulk_create_refused"
        assert model._meta.base_manager_name is None and type(model._base_manager) is models.Manager
        for field in model._meta.get_fields():
            if field.many_to_one or field.one_to_one:
                if field.concrete:
                    assert field.remote_field.related_name == "+", (model.__name__, field.name)


def test_the_records_go_with_their_deployment_and_never_hold_back_a_stop(deployment, other_deployment, people):
    _every_record(deployment, people)
    leaver = people["analyst"]
    response = _client(people["admin"]).delete(f"/api/accounts/users/{leaver.pk}/")
    assert response.status_code == 204, response.content
    scenario = FinancialScenario.objects.get()
    assert (scenario.author_id, scenario.author_username) == (None, "ann")
    assert ScenarioBuild.objects.count() == CausalEffect.objects.count() == EffectFinding.objects.count() == 1
    deployment.delete()
    for model in (ScenarioBuild, CausalEffect, EffectFinding, LossEvent, LossComponent, FinancialScenario):
        assert not model.objects.exists(), model.__name__


# ============================================================== off the stops


def test_no_builder_route_is_a_stop():
    found = {}

    def walk(patterns):
        for pattern in patterns:
            if isinstance(pattern, URLResolver):
                walk(pattern.url_patterns)
                continue
            view = getattr(pattern.callback, "cls", None) or getattr(pattern.callback, "view_class", None)
            if view is not None and view.__module__ == "assurance.economics.scenario_api":
                found[pattern.name] = view

    walk(get_resolver().url_patterns)
    assert set(found) == {"deployment-economics-scenario-build", "deployment-economics-scenario-events"}
    for name in found:
        assert name not in stops.STOP_ROUTES and name not in stops.EXEMPT_ROUTES
    assert set(stops.NOT_STOPS["deployment-economics-scenario-build"]) == {"POST"}
    assert set(stops.NOT_STOPS["deployment-economics-scenario-events"]) == {"GET"}


def test_a_builder_fault_never_takes_down_a_stop():
    """SAFETY. A fresh pytest, under a plugin that makes the builder and the template
    module raise at import, before Django loads, runs
    ``tests/economics_fault_cases.py``: Django loads, the scan's Stop is answered
    (202) and saved, ``deliver_owed_stops`` runs the system checks and reaches its
    handler, ``manage.py check`` passes, the parameter-set routes are still served,
    and only the builder's routes are not."""
    env = dict(
        os.environ,
        DJANGO_SECRET_KEY=os.environ.get("DJANGO_SECRET_KEY", "ci-secret-key-not-used-outside-ci"),
        ECONOMICS_FAULT="builder",
    )
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-p", "no:cacheprovider", "-p", "tests.economics_broken_builder",
         "-q", "tests/economics_fault_cases.py"],
        cwd=REPO, env=env, capture_output=True, text=True, timeout=600, check=False,
    )
    assert result.returncode == 0, (result.stdout[-4000:], result.stderr[-2000:])
    assert "4 passed" in result.stdout, result.stdout[-2000:]


# ============================================================ the spec


SPEC_PHRASES = (
    "Findings that enable the same effect join ONE loss event",
    "A template never invents a number",
    "one effect is in exactly one loss event of its scenario version",
    "five findings that enable one payment loss make ONE event",
    "the grouping key never names a finding",
    "never a second",
    "test_a_builder_fault_never_takes_down_a_stop",
    "Market value is never cash",
    "SYNTHETIC / ILLUSTRATIVE",
)


@pytest.mark.parametrize("phrase", SPEC_PHRASES)
def test_the_spec_states_the_builder(phrase):
    assert phrase in " ".join(SPEC.read_text(encoding="utf-8").split())


def test_the_spec_names_every_builder_code():
    text = SPEC.read_text(encoding="utf-8")
    codes = [
        tpl.PACK, builder.BUILDER_VERSION, builder.GROUPING_VERSION,
        *tpl.REFUSALS, *tpl.EffectType, *tpl.BusinessProcess, *tpl.Origin, *tpl.FindingRole, *tpl.ATTRIBUTES,
        *tpl.SourceKind,
        *(t.template_id for t in tpl.TEMPLATES),
        *(c.component_key for t in tpl.TEMPLATES for c in t.components),
        "deployment-economics-scenario-build", "deployment-economics-scenario-events",
        "ScenarioBuild", "CausalEffect", "EffectFinding",
    ]
    missing = sorted({str(code) for code in codes if f"`{code}`" not in text})
    assert not missing, missing
