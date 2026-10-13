"""Economic Exposure E6: continuous financial assurance (``docs/economics/spec-v1.md``,
section 34). A change event makes stale exactly the exposure that depends on it,
names what to refresh, and a refresh an analyst asks for makes a new run, card and
receipt that supersede the stale ones.

- **The known answer** (the owner's specification, section 27, "Change
  invalidation": a SPINE change marks only dependent scenarios stale and leaves
  unaffected scenarios current). Two scenarios of one deployment: a payment agent's
  misuse (bound to the ``effective_access`` and ``ai_bom`` claims, built from one
  parameter set) and a provider outage (``data_boundary`` and ``ai_bom``, from
  another). A boundary change SPINE invalidates stales the outage only; a permission
  change the payment only; and so for a supersede and a status move, a parameter-set
  version, a feed-source version and an engine release.
- **Stale is visible on every read** -- the report, the events route, the scenario
  list, the scenario document, the freshness and assurance routes, the receipt's
  route -- a stale run is never totalled as current, and its receipt still verifies,
  served byte for byte as signed.
- **The refresh obligation** is recorded by the check, once, naming exactly what to
  refresh; the check runs no Monte Carlo, and neither does SPINE's own
  check-invalidations. A recorded staleness holds after the dependency moves back.
- **The refresh** re-runs only the obligation's scenario; the new receipt supersedes
  the old, which is never rewritten; the obligation closes only once the new run
  stands -- never while SPINE's retest of a claim it rests on is open -- with SPINE's
  outcome: restored, contradicted, Unknown or superseded.
- **The safety rule**: a scan Stop is answered within its bound while a large check is
  held open mid-way, and the check holds no transaction; the refresh is capped; no
  route here is a stop; Django and the URLconf never import the service.

Every figure is SYNTHETIC / ILLUSTRATIVE.
"""

from __future__ import annotations

import copy
import dataclasses
import json
import threading
import time
import uuid
from datetime import date, timedelta
from pathlib import Path
from types import MappingProxyType

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext
from rest_framework.test import APIClient

from assurance.claims import apply_claim_transition, derive_claims
from assurance.economics import (
    builder,
    capacity,
    charts_service,
    continuous_service,
    receipt_service,
    report,
    report_api,
    simulation_service,
    validity_service,
)
from assurance.economics.engine import feeds as feed_engine
from assurance.economics.models import (
    STALE_REASONS,
    CustomerParameterSet,
    EconomicsRefused,
    EconomicsRewriteRefused,
    ExposureDependencies,
    ExposureRefresh,
    ExposureStaleness,
    FinancialExposureReceipt,
    FinancialScenario,
    SimulationResult,
    canonical_digest,
)
from assurance.invalidation import check_invalidations
from assurance.models import Asset, AssuranceClaim, Deployment, Finding
from pentest.models import PentestScan
from safety import stops
from tests import test_no_control_holds_back_a_stop as tripwire
from tests.test_economics_read_routes import _economics_writes, _signing
from tests.test_economics_report import stored
from tests.test_economics_scenarios import _entry
from tests.test_economics_stated_distributions import ATV, ATV_GOOD, FREQUENCY_GOOD, RR, RR_GOOD, TPD, TPD_GOOD
from tests.test_spine_per_claim_inputs import _deployment as spine_deployment
from tests.test_spine_per_claim_inputs import _grant_permission, _move_provider_region, _widen_boundary

pytestmark = pytest.mark.django_db
User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
SPEC = REPO / "docs" / "economics" / "spec-v1.md"
README = REPO / "README.md"
LABEL = "SYNTHETIC / ILLUSTRATIVE"
AS_OF = "2026-10-06"
QUICK = "quick_10k"
PAYMENTS, OPERATIONS = "bank_payments", "bank_operations"
#: The day freshness is read on in these tests: a fixed one, never the wall clock.
TODAY = date(2026, 10, 13)


@pytest.fixture(autouse=True)
def fixed_today(monkeypatch):
    monkeypatch.setattr(continuous_service, "_today", lambda: TODAY)


@pytest.fixture
def people():
    return {
        "admin": User.objects.create_user(username="ada", password="x", role="admin"),
        "analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
        "viewer": User.objects.create_user(username="vic", password="x", role="viewer"),
    }


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


def _base(deployment):
    return f"/api/assurance/deployments/{deployment.uuid}/economics/"


def _post(client, url, body=None):
    return client.post(url, data=json.dumps({} if body is None else body), content_type="application/json")


# ======================================================================
# The world: two scenarios that rest on different SPINE claims and sets
# ======================================================================


def _frequency():
    return _entry("count", "1", "2", "4", source_type="INDUSTRY_BENCHMARK", evidence_ref=f"{LABEL}: industry loss data",
                  distribution=FREQUENCY_GOOD)


def payments_document(*, atv=ATV, atv_evidence=None):
    """The payment agent's set: three customer ranges, each stating its distribution,
    and the frequency."""
    average = {**_entry("money_per_unit", *atv), "distribution": ATV_GOOD}
    if atv_evidence is not None:
        average["evidence_ref"] = atv_evidence
    return {
        "variables": {
            "transactions_per_day": {**_entry("count_per_day", *TPD), "distribution": TPD_GOOD},
            "average_transaction_value": average,
            "recovery_rate": {**_entry("ratio", *RR), "distribution": RR_GOOD},
        },
        "frequency": _frequency(),
    }


def operations_document(*, margin="40000", insurance=False):
    """The operations set: the critical service's margin and the engineers' rate,
    each the customer's point, and the frequency; with ``insurance``, a policy."""
    variables = {
        "margin_per_hour": _entry("money_per_hour", margin),
        "engineering_hourly_rate": _entry("money_per_hour", "150"),
    }
    if insurance:
        variables["insurance_deductible"] = _entry("money", "100000")
        variables["insurance_limit"] = _entry("money", "1000000")
    return {"variables": variables, "frequency": _frequency()}


def _expert(unit, *figures):
    return _entry(unit, *figures, source_type="EXPERT_ESTIMATE", evidence_ref=f"{LABEL}: made up")


def payment_body(asset, finding, *, as_of=AS_OF, version=1):
    return {
        "title": "Payment agent: destination changed after approval",
        "parameter_set": {"set_key": PAYMENTS, "version": version}, "currency": "USD", "as_of": as_of,
        "effects": [{
            "key": "redirect", "origin": "hypothetical", "effect_type": "funds_transfer_altered",
            "asset": str(asset.uuid), "business_process": "payments",
            "attributes": {
                "success_rate": _expert("ratio", "0.35"),
                "exploitable_window_hours": _expert("hours", "1.25"),
                "incident_response_cost": _expert("money", "165000"),
                "legal_response_cost": _expert("money", "825000"),
            },
        }],
        "findings": [{"finding": str(finding.uuid), "effect": "redirect", "role": "prerequisite"}],
    }


def outage_body(asset, finding, *, as_of=AS_OF, version=1):
    return {
        "title": "Model provider outage",
        "parameter_set": {"set_key": OPERATIONS, "version": version}, "currency": "USD", "as_of": as_of,
        "effects": [{
            "key": "outage", "origin": "hypothetical", "effect_type": "provider_outage",
            "asset": str(asset.uuid), "business_process": "operations",
            "attributes": {
                "outage_hours": _expert("hours", "2", "6", "12"),
                "recovery_fixed_cost": _expert("money", "20000"),
                "recovery_hours": _expert("hours", "40"),
                "sla_credit_per_hour": _expert("money_per_hour", "1000"),
                "sla_credit_cap": _expert("money", "50000"),
            },
        }],
        "findings": [{"finding": str(finding.uuid), "effect": "outage", "role": "prerequisite"}],
    }


@dataclasses.dataclass
class World:
    deployment: Deployment
    analyst: object
    payment: FinancialScenario
    outage: FinancialScenario

    def run(self, scenario, *, seed=7, draws=2_000) -> SimulationResult:
        outcome = simulation_service.simulate_scenario(scenario, seed=seed, draws=draws)
        assert outcome.completed, (outcome.code, outcome.detail)
        card = validity_service.issue_card(outcome.result)
        assert card.card is not None, (card.code, card.detail)
        return outcome.result


def build_world(deployment, analyst, *, payments=None, operations=None, as_of=AS_OF) -> World:
    """The two scenarios built in ``deployment``: the payment agent's misuse on its
    agent, the provider outage on its model, each enabled by a finding of its own."""
    CustomerParameterSet.record(deployment, PAYMENTS, payments or payments_document(), author=analyst)
    CustomerParameterSet.record(deployment, OPERATIONS, operations or operations_document(), author=analyst)
    agent = Asset.objects.filter(deployment=deployment, kind="agent").order_by("id").first()
    model = Asset.objects.filter(deployment=deployment, kind="model").order_by("id").first()
    findings = [
        Finding.objects.create(deployment=deployment, fingerprint=f"fp-{key}", finding_type=key, title=key,
                               severity="high")
        for key in ("approval_check_missing", "single_provider")
    ]
    payment, _ = builder.build(deployment, payment_body(agent, findings[0], as_of=as_of), author=analyst)
    outage, _ = builder.build(deployment, outage_body(model, findings[1], as_of=as_of), author=analyst)
    return World(deployment, analyst, payment, outage)


@pytest.fixture
def world(people):
    """A deployment every SPINE assessor reads something in (a model behind a
    provider, an agent, a tool, an approved boundary, a declared architecture), its
    three claims derived, and the two scenarios built on it."""
    deployment = spine_deployment()
    deployment.owner = people["viewer"]  # the viewer reads its own deployment
    deployment.save(update_fields=["owner"])
    derive_claims(deployment)
    return build_world(deployment, people["analyst"])


def freshness(result, *, today=TODAY):
    return continuous_service.assess(result, now=continuous_service.Now(result.deployment_id, today=today))


def codes(result, **kwargs) -> set[str]:
    return {reason["code"] for reason in freshness(result, **kwargs).reasons}


def current(result, **kwargs) -> bool:
    found = freshness(result, **kwargs)
    return found.state == "current" and found.reasons == []


def _claim(deployment, claim_type):
    return AssuranceClaim.objects.filter(deployment=deployment, claim_type=claim_type).current().get()


# ======================================================================
# The dependency map
# ======================================================================


def test_each_template_rests_on_the_claims_its_loss_follows_from(world):
    assert continuous_service.bound_claim_types(world.payment) == ("ai_bom", "effective_access")
    assert continuous_service.bound_claim_types(world.outage) == ("ai_bom", "data_boundary")
    assert set(continuous_service.TEMPLATE_CLAIMS) == {
        "payment_agent_misuse", "cross_customer_data_exposure", "customer_service_ai_misstatement",
        "fraud_aml_workflow_failure", "agent_approval_bypass", "third_party_provider_outage",
    }
    for claims in continuous_service.TEMPLATE_CLAIMS.values():
        assert set(claims) <= set(continuous_service.ALL_CLAIM_TYPES) and claims


def test_a_run_records_what_it_depends_on_read_before_it_ran(world):
    result = world.run(world.payment)
    mapped = ExposureDependencies.objects.get(simulation=result)
    deps = mapped.dependencies
    assert mapped.dependencies_digest == canonical_digest(deps)
    assert deps["schema"] == continuous_service.DEPENDENCIES_SCHEMA and deps["scenario"] == str(world.payment.uuid)
    assert deps["claim_types"] == ["ai_bom", "effective_access"]
    access = _claim(world.deployment, "effective_access")
    (entry,) = deps["claims"]["effective_access"]
    assert (entry["identity"], entry["version"], entry["status"]) == (access.fingerprint, str(access.uuid),
                                                                      access.status)
    assert entry["retest_open"] is False
    agent = Asset.objects.get(deployment=world.deployment, kind="agent")
    assert set(deps["assets"]) == {str(agent.uuid)} and deps["assets"][str(agent.uuid)]
    (finding,) = deps["findings"].values()
    assert finding == {"status": "open", "severity": "high"}
    version = CustomerParameterSet.current(world.deployment, PAYMENTS)
    assert deps["parameter_set"] == {"set_key": PAYMENTS, "version": 1, "content_digest": version.content_digest}
    assert deps["release"]["digest"] and deps["release"]["record"]["engine"]["scenario_simulation"]
    assert mapped.captured_at <= result.started_at
    # Recorded once, append-only.
    with pytest.raises(EconomicsRewriteRefused):
        mapped.save()
    with pytest.raises(EconomicsRefused):
        continuous_service.ExposureDependencies(
            deployment=world.deployment, scenario=world.payment, simulation=result,
            schema=continuous_service.DEPENDENCIES_SCHEMA, dependencies=deps,
            dependencies_digest=mapped.dependencies_digest, captured_at=mapped.captured_at,
        ).check_new()
    # Nothing moved: current.
    assert current(result)


def test_a_run_whose_map_cannot_be_read_is_made_and_reads_stale(world, monkeypatch):
    def broken(*args, **kwargs):
        raise RuntimeError("the map cannot be read")

    monkeypatch.setattr(continuous_service, "capture", broken)
    result = world.run(world.payment)
    assert not ExposureDependencies.objects.filter(simulation=result).exists()
    assert codes(result) == {"dependencies_unrecorded"}


def test_a_residual_or_refused_run_is_not_assessed(world):
    result = world.run(world.payment)
    result.status = "refused"
    assert continuous_service.assess(result).state == "not_assessed"
    result.status = "completed"
    result.remediation_id = 1
    assert continuous_service.assess(result).state == "not_assessed"


# ======================================================================
# The known answer: a change stales only the scenarios that depend on it
# ======================================================================


def test_a_claim_spine_invalidates_stales_only_the_scenario_bound_to_it(world):
    """The section 27 row. The boundary is widened: the data-boundary claim's inputs
    move (SPINE's own predicate) before SPINE's check has run, and SPINE then
    invalidates it. Only the outage rests on it; the payment stays current."""
    payment, outage = world.run(world.payment), world.run(world.outage)
    assert current(payment) and current(outage)
    _widen_boundary(world.deployment)
    assert codes(outage) == {"fingerprint_moved"}
    assert current(payment)
    check_invalidations(world.deployment)
    assert codes(outage) == {"fingerprint_moved", "claim_invalidated"}
    assert all(r["dependency"] in ("claim:data_boundary", "inputs:data_boundary") for r in freshness(outage).reasons)
    assert current(payment)


def test_a_permission_change_stales_only_the_scenario_that_rests_on_access(world):
    payment, outage = world.run(world.payment), world.run(world.outage)
    _grant_permission(world.deployment)
    check_invalidations(world.deployment)
    assert codes(payment) == {"fingerprint_moved", "claim_invalidated"}
    assert current(outage)


def test_a_supersede_stales_only_the_scenario_bound_to_the_claim(world):
    payment, outage = world.run(world.payment), world.run(world.outage)
    _widen_boundary(world.deployment)
    derive_claims(world.deployment)  # SPINE supersedes the boundary claim
    assert codes(outage) == {"claim_superseded"}
    (reason,) = freshness(outage).reasons
    assert reason["now"] == str(_claim(world.deployment, "data_boundary").uuid)
    assert current(payment)


def test_a_status_move_stales_only_the_scenario_bound_to_the_claim(world, people):
    payment, outage = world.run(world.payment), world.run(world.outage)
    apply_claim_transition(_claim(world.deployment, "data_boundary"), "contradicted", actor=people["admin"],
                           note="the boundary does not hold")
    assert codes(outage) == {"claim_status_moved"}
    assert current(payment)


def test_a_claim_spine_establishes_after_the_run_stales_the_scenario_resting_on_its_type(people):
    deployment = spine_deployment()
    world = build_world(deployment, people["analyst"])
    payment = world.run(world.payment)
    assert current(payment)
    derive_claims(deployment)
    assert codes(payment) == {"claim_established"}


def test_a_parameter_set_version_stales_only_the_scenarios_built_from_it(world, people):
    payment, outage = world.run(world.payment), world.run(world.outage)
    CustomerParameterSet.record(world.deployment, PAYMENTS, payments_document(atv=("21000", "26000", "33000")),
                                author=people["analyst"])
    assert codes(payment) == {"parameter_set_superseded"}
    (reason,) = freshness(payment).reasons
    assert reason["changed"] == ["average_transaction_value"] and (reason["was"], reason["now"]) == ("1", "2")
    assert current(outage)


def test_a_change_to_the_insurance_terms_is_a_contract_change(world, people):
    payment, outage = world.run(world.payment), world.run(world.outage)
    CustomerParameterSet.record(world.deployment, OPERATIONS, operations_document(insurance=True),
                                author=people["analyst"])
    assert codes(outage) == {"parameter_set_superseded", "contract_terms_changed"}
    terms = next(r for r in freshness(outage).reasons if r["code"] == "contract_terms_changed")
    assert terms["changed"] == ["insurance_deductible", "insurance_limit"]
    assert current(payment)


def test_a_release_change_stales_only_the_runs_made_under_the_old_release(world, monkeypatch):
    payment = world.run(world.payment)
    monkeypatch.setattr(validity_service, "TOP_DRIVERS", validity_service.TOP_DRIVERS + 1)
    assert codes(payment) == {"release_changed"}
    assert freshness(payment).reasons[0]["changed"] == ["card"]
    outage = world.run(world.outage)  # made under the release in force now
    assert current(outage)


def test_an_asset_or_finding_or_scenario_supersede_is_a_reason(world):
    payment = world.run(world.payment)
    agent = Asset.objects.get(deployment=world.deployment, kind="agent")
    finding = Finding.objects.get(deployment=world.deployment, fingerprint="fp-approval_check_missing")
    finding.severity = "critical"
    finding.save(update_fields=["severity"])
    assert "finding_changed" in codes(payment)
    agent.classification = Asset.Classification.UNKNOWN
    agent.save(update_fields=["classification"])
    assert "asset_changed" in codes(payment)


# ---------------------------------------------------------------- a feed source


ECB = "ecb-eur-reference-rates"


@pytest.fixture
def staging_world(people, monkeypatch):
    """A staging deployment (the gate takes a reviewed, unverified version there) whose
    payment set cites the ECB rates; the outage cites no source. The ECB rates as
    fetched on 13 Oct, the as-of date their newest observation."""
    from assurance.economics.models import FXObservation
    from tests.test_economics_feeds import _fetch

    registry = dict(feed_engine.REGISTRY)
    registry[ECB] = dataclasses.replace(registry[ECB], license_class="open")
    monkeypatch.setattr(feed_engine, "REGISTRY", MappingProxyType(registry))
    _fetch(ECB)
    through = max(FXObservation.objects.values_list("effective_date", flat=True))
    deployment = Deployment.objects.create(name="payments-staging", environment="staging")
    Asset.objects.create(deployment=deployment, kind="agent", name="agent", identifier="agent")
    Asset.objects.create(deployment=deployment, kind="model", name="gpt", identifier="gpt")
    world = build_world(
        deployment, people["analyst"], as_of=through.isoformat(),
        payments=payments_document(atv_evidence=f"financial-source:{ECB} EUR/USD at the as-of date"),
    )
    return world, through


def test_a_source_version_or_a_source_going_stale_stales_only_the_scenario_citing_it(staging_world):
    from tests.test_economics_feeds import FILES, NOW, _fetch, _rows, fixture

    world, through = staging_world
    payment, outage = world.run(world.payment), world.run(world.outage)
    assert current(payment, today=through) and current(outage, today=through)
    (source,) = ExposureDependencies.objects.get(simulation=payment).dependencies["sources"].items()
    assert source[0] == ECB and source[1]["version"] == 1 and source[1]["state"] == "fresh"
    # The source goes stale (step 10's SLA) with no newer version: only the payment cites it.
    assert codes(payment, today=through + timedelta(days=30)) == {"source_stale"}
    assert current(outage, today=through + timedelta(days=30))
    # A newer version of the source that covers the run's as-of date.
    raw = fixture(FILES[ECB])
    _fetch(ECB, raw.replace(f",{_rows(raw)[1][7]},".encode(), b",0.99999,", 1), now=NOW + timedelta(hours=1))
    assert codes(payment, today=through) == {"source_superseded"}
    reason = freshness(payment, today=through).reasons[0]
    assert (reason["was"], reason["now"], reason["dependency"]) == ("1", "2", f"source:{ECB}")
    assert current(outage, today=through)


# ======================================================================
# Stale is visible on every read, and never totalled as current
# ======================================================================


def _stale_outage(world, people, monkeypatch):
    """Both scenarios simulated through the route with a receipt; then a new version
    of the operations set stales the outage, and only it."""
    ring, _signed = _signing(monkeypatch)
    analyst = _client(people["analyst"])
    receipts = {}
    for scenario in (world.payment, world.outage):
        response = _post(analyst, _base(world.deployment) + f"scenarios/{scenario.uuid}/simulate/",
                         {"seed": 7, "policy": QUICK, "receipt": True})
        assert response.status_code == 201, response.content
        assert response.json()["receipt"]["issued"] is True, response.json()["receipt"]
        receipts[scenario.pk] = FinancialExposureReceipt.objects.get(scenario=scenario)
    reader = _client(people["viewer"])
    before = {pk: reader.get(_base(world.deployment) + f"receipts/{uuid.UUID(row.receipt_id)}/").content
              for pk, row in receipts.items()}
    CustomerParameterSet.record(world.deployment, OPERATIONS, operations_document(margin="45000"),
                                author=people["analyst"])
    return ring, receipts, before


def test_stale_is_said_on_every_read_and_a_stale_run_is_never_totalled(world, people, monkeypatch):
    ring, receipts, before = _stale_outage(world, people, monkeypatch)
    reader = _client(people["viewer"])
    base = _base(world.deployment)
    outage_run = SimulationResult.objects.get(scenario=world.outage)
    payment_run = SimulationResult.objects.get(scenario=world.payment)
    # The report: the stale banner, excluded, the reasons; never totalled.
    stale = json.loads(reader.get(base + f"scenarios/{world.outage.uuid}/results/").content)
    fine = json.loads(reader.get(base + f"scenarios/{world.payment.uuid}/results/").content)
    assert report.verifies(stale) and report.verifies(fine)
    assert stale["banner"] == report.STALE_BANNER and stale["excluded_from_totals"] is True
    assert stale["banner_reason"].startswith("stale: parameter_set_superseded (parameter_set:bank_operations)")
    assert stale["grade"] in report.GRADES_FOR_TOTALS  # a sound run, graded: stale is what excludes it
    assert {u["id"] for u in stale["unknowns"] if u["kind"] == "stale"} == {"parameter_set_superseded"}
    assert report.may_be_totalled(stale) is False and report.stands(stale) is True
    assert fine["banner"] is None and fine["excluded_from_totals"] is False and report.may_be_totalled(fine)
    # The events route and the scenario list: the same rule.
    events = reader.get(base + f"scenarios/{world.outage.uuid}/events/").json()
    assert (events["banner"], events["excluded_from_totals"]) == (report.STALE_BANNER, True)
    listed = {entry["uuid"]: entry for entry in reader.get(base + "scenarios/").json()["scenarios"]}
    assert listed[str(world.outage.uuid)]["freshness"]["state"] == "stale"
    assert listed[str(world.outage.uuid)]["banner"] == report.STALE_BANNER
    assert listed[str(world.payment.uuid)]["freshness"] == {"state": "current", "reasons": []}
    # The scenario document, each result's freshness.
    document = reader.get(base + f"scenarios/{world.outage.uuid}/").json()
    (run,) = document["validity"]["simulations"]
    assert run["freshness"]["state"] == "stale" and run["grade"] in report.GRADES_FOR_TOTALS
    # The freshness route: the map, the reasons, what to refresh.
    served = reader.get(base + f"scenarios/{world.outage.uuid}/freshness/").json()
    assert served["simulation"] == str(outage_run.uuid) and served["freshness"]["state"] == "stale"
    assert served["dependencies"]["digest"] == ExposureDependencies.objects.get(simulation=outage_run).dependencies_digest
    assert served["refresh"]["parameters"] == ["margin_per_hour"] and served["refresh"]["scenario"] == str(
        world.outage.uuid)
    assert served["refresh"]["awaits_spine"] is False
    # The deployment's assurance read.
    overview = reader.get(base + "assurance/").json()
    states = {entry["scenario"]: entry["freshness"]["state"] for entry in overview["scenarios"]}
    assert states == {str(world.payment.uuid): "current", str(world.outage.uuid): "stale"}
    # The receipt: served byte for byte as signed, its freshness beside it, and it verifies.
    outage_receipt = receipts[world.outage.pk]
    answer = reader.get(base + f"receipts/{uuid.UUID(outage_receipt.receipt_id)}/")
    assert answer.content == before[world.outage.pk]
    assert answer["X-Exposure-Freshness"] == "stale"
    assert answer["X-Exposure-Stale-Reasons"] == "parameter_set_superseded"
    fine_answer = reader.get(base + f"receipts/{uuid.UUID(receipts[world.payment.pk].receipt_id)}/")
    assert fine_answer["X-Exposure-Freshness"] == "current" and fine_answer.content == before[world.payment.pk]
    check = receipt_service.verify_stored_receipt(outage_receipt, ring)
    assert check.verified and check.code == "authentic", check
    assert payment_run.pk != outage_run.pk


def test_the_portfolio_hook_names_a_stale_member(world, people):
    payment, outage = world.run(world.payment), world.run(world.outage)
    CustomerParameterSet.record(world.deployment, OPERATIONS, operations_document(margin="45000"),
                                author=people["analyst"])
    excluded = continuous_service.portfolio_exclusion(outage)
    assert excluded["code"] == "stale"
    assert excluded["reasons"] == [{"code": "parameter_set_superseded", "dependency": "parameter_set:bank_operations"}]
    assert continuous_service.portfolio_exclusion(payment) is None
    # Before E5 merges a total already leaves it out: its report is excluded.
    assert report.may_be_totalled(report.build_report(outage)) is False
    assert report.may_be_totalled(report.build_report(payment)) is True


def test_the_reads_fired_twice_give_the_same_bytes_and_write_nothing(world, people):
    world.run(world.outage)
    CustomerParameterSet.record(world.deployment, OPERATIONS, operations_document(margin="45000"),
                                author=people["analyst"])
    reader = _client(people["viewer"])
    for url in (f"scenarios/{world.outage.uuid}/freshness/", "assurance/", f"scenarios/{world.outage.uuid}/results/",
                "scenarios/"):
        first = reader.get(_base(world.deployment) + url)
        with CaptureQueriesContext(connection) as queries:
            second = reader.get(_base(world.deployment) + url)
        assert first.status_code == second.status_code == 200, url
        assert first.content == second.content, url
        assert _economics_writes(queries.captured_queries) == [], url
        assert first["Cache-Control"] == "no-store", url
    assert not ExposureStaleness.objects.exists()


# ======================================================================
# The obligation: recorded by the check, once; no recompute in a request
# ======================================================================


def _no_run_anywhere(monkeypatch):
    """Every entry point that runs a Monte Carlo, or issues what rests on one, made to
    fail the test where it is called."""
    called = []

    def refuse(name):
        def run(*args, **kwargs):
            called.append(name)
            raise AssertionError(f"{name} was called")

        return run

    for module, name in ((simulation_service, "simulate_scenario"), (validity_service, "issue_card"),
                         (charts_service, "issue_charts"), (receipt_service, "issue_receipt")):
        monkeypatch.setattr(module, name, refuse(name))
    return called


def test_the_check_records_each_stale_run_once_naming_exactly_what_to_refresh(world, people, monkeypatch):
    payment, outage = world.run(world.payment), world.run(world.outage)
    _widen_boundary(world.deployment)
    check_invalidations(world.deployment)
    called = _no_run_anywhere(monkeypatch)
    url = _base(world.deployment) + "assurance/"
    assert _post(_client(people["viewer"]), url).status_code == 403
    response = _post(_client(people["analyst"]), url)
    assert response.status_code == 200, response.content
    body = response.json()
    assert (body["checked"], body["stale"], body["current"], body["obligations_recorded"]) == (2, 1, 1, 1)
    row = ExposureStaleness.objects.get()
    assert row.simulation_id == outage.pk and row.scenario_id == world.outage.pk
    assert row.refresh["scenario"] == str(world.outage.uuid)
    assert row.refresh["claims"] == ["data_boundary"] and row.refresh["awaits_spine"] is True
    assert row.refresh["parameters"] == [] and row.refresh["sources"] == [] and row.refresh["release"] is False
    assert {r["code"] for r in row.reasons} == {"fingerprint_moved", "claim_invalidated"}
    assert all(r["code"] in STALE_REASONS for r in row.reasons)
    # Idempotent: the same reasons are recorded once.
    assert _post(_client(people["analyst"]), url).json()["obligations_recorded"] == 0
    assert ExposureStaleness.objects.count() == 1
    # Open, and listed as open.
    overview = _client(people["viewer"]).get(url).json()
    assert [o["uuid"] for o in overview["open_obligations"]] == [str(row.uuid)]
    # Nothing was recomputed, by the check or by SPINE's own check-invalidations.
    spine = _post(_client(people["admin"]), f"/api/assurance/deployments/{world.deployment.uuid}/check-invalidations/")
    assert spine.status_code == 200, spine.content
    assert called == []
    assert SimulationResult.objects.count() == 2
    assert current(payment)


def test_a_recorded_staleness_holds_after_the_dependency_moves_back(world, monkeypatch):
    payment = world.run(world.payment)
    moved = validity_service.TOP_DRIVERS + 1
    monkeypatch.setattr(validity_service, "TOP_DRIVERS", moved)
    assert continuous_service.check(world.deployment)["obligations_recorded"] == 1
    monkeypatch.setattr(validity_service, "TOP_DRIVERS", moved - 1)  # the release moves back
    assert freshness(payment).live == []
    assert codes(payment) == {"release_changed"}  # recorded: stale until a refresh supersedes it


def test_the_command_checks_and_recomputes_nothing(world, people, monkeypatch, capsys):
    from django.core.management import call_command

    world.run(world.outage)
    CustomerParameterSet.record(world.deployment, OPERATIONS, operations_document(margin="45000"),
                                author=people["analyst"])
    called = _no_run_anywhere(monkeypatch)
    call_command("check_financial_assurance", "--deployment", str(world.deployment.uuid))
    assert f"{world.deployment.uuid}: 1 run(s) read, 1 stale, 1 obligation(s) recorded" in capsys.readouterr().out
    assert called == [] and ExposureStaleness.objects.count() == 1


# ======================================================================
# The refresh
# ======================================================================


def _refresh(client, deployment, scenario, **body):
    return _post(client, _base(deployment) + f"scenarios/{scenario.uuid}/refresh/",
                 {"seed": 11, "policy": QUICK, "as_of": AS_OF, **body})


def test_a_refresh_reruns_only_the_obligations_scenario_and_its_receipt_supersedes(world, people, monkeypatch):
    ring, receipts, before = _stale_outage(world, people, monkeypatch)
    old_receipt = receipts[world.outage.pk]
    kept = (old_receipt.pk, copy.deepcopy(old_receipt.document), copy.deepcopy(old_receipt.envelope))
    analyst = _client(people["analyst"])
    assert _post(analyst, _base(world.deployment) + "assurance/").json()["obligations_recorded"] == 1
    payment_runs = SimulationResult.objects.filter(scenario=world.payment).count()
    response = _refresh(analyst, world.deployment, world.outage, receipt=True)
    assert response.status_code == 201, response.content
    body = response.json()
    rebuilt = FinancialScenario.objects.get(uuid=body["rebuilt"]["scenario"])
    assert body["rebuilt"]["created"] is True and rebuilt.supersedes_id == world.outage.pk
    assert body["receipt"]["issued"] is True
    (closed,) = body["obligations"]["closed"]
    assert closed["spine_outcome"] == "superseded" and body["obligations"]["open"] == []
    new_run = SimulationResult.objects.get(uuid=body["simulation"]["uuid"])
    new_receipt = FinancialExposureReceipt.objects.get(simulation=new_run)
    assert closed["receipt_id"] == new_receipt.receipt_id and closed["simulation"] == str(new_run.uuid)
    closure = ExposureRefresh.objects.get()
    assert (closure.stale_simulation.scenario_id, closure.simulation_id, closure.card.simulation_id) == (
        world.outage.pk, new_run.pk, new_run.pk)
    assert closure.author_username == "ann"
    # Only the obligation's scenario re-ran.
    assert SimulationResult.objects.filter(scenario=world.payment).count() == payment_runs
    # The new run stands; the old one stays stale, superseded, its receipt untouched and verifying.
    assert report.may_be_totalled(report.build_report(new_run)) is True
    old_run = SimulationResult.objects.get(scenario=world.outage)
    found = freshness(old_run)
    assert found.stale and found.superseded_by["simulation"] == str(new_run.uuid)
    assert {"scenario_superseded", "parameter_set_superseded"} <= {r["code"] for r in found.reasons}
    old_receipt.refresh_from_db()
    assert (old_receipt.pk, old_receipt.document, old_receipt.envelope) == kept
    assert FinancialExposureReceipt.objects.filter(scenario__in=[world.outage, rebuilt]).count() == 2
    assert receipt_service.verify_stored_receipt(old_receipt, ring).verified
    assert receipt_service.verify_stored_receipt(new_receipt, ring).verified
    reader = _client(people["viewer"])
    answer = reader.get(_base(world.deployment) + f"receipts/{uuid.UUID(old_receipt.receipt_id)}/")
    assert answer.content == before[world.outage.pk]
    assert answer["X-Exposure-Superseded-By-Receipt"] == new_receipt.receipt_id
    assert answer["X-Exposure-Superseded-By-Run"] == str(new_run.uuid)
    # Nothing left to refresh on the new version; the old one is superseded.
    assert _refresh(analyst, world.deployment, rebuilt, seed=12).json()["code"] == "exposure_current"
    assert _refresh(analyst, world.deployment, world.outage, seed=12).json()["code"] == "scenario_superseded"


def test_an_obligation_closes_only_when_the_new_run_stands_and_spine_has_answered(world, people):
    """A technical staleness: SPINE invalidated the boundary claim. A refresh made while
    SPINE's retest is open makes a run that rests on a stale claim: stale itself, it
    does not stand, and every obligation stays open. Once SPINE re-derives the claim,
    a refresh closes them all, the claim restored."""
    world.run(world.payment)
    outage = world.run(world.outage)
    _widen_boundary(world.deployment)
    check_invalidations(world.deployment)
    analyst = _client(people["analyst"])
    first = _refresh(analyst, world.deployment, world.outage)
    assert first.status_code == 201, first.content
    body = first.json()
    assert body["obligations"]["closed"] == [] and len(body["obligations"]["open"]) == 1
    assert body["obligations"]["why_open"].startswith("stale: ")
    assert "claim_invalidated" in body["obligations"]["why_open"]
    assert not ExposureRefresh.objects.exists()
    rebuilt = FinancialScenario.objects.get(uuid=body["rebuilt"]["scenario"])
    second_run = SimulationResult.objects.get(uuid=body["simulation"]["uuid"])
    assert "claim_invalidated" in codes(second_run)  # born stale: SPINE's retest was open
    # SPINE re-derives: the claim is restored. The refresh of the latest version closes
    # its obligation and the one of the version it supersedes.
    derive_claims(world.deployment)
    second = _refresh(analyst, world.deployment, rebuilt, seed=12)
    assert second.status_code == 201, second.content
    closed = second.json()["obligations"]["closed"]
    assert {c["spine_outcome"] for c in closed} == {"restored"} and len(closed) == 2
    assert second.json()["obligations"]["open"] == []
    assert {row.stale_simulation_id for row in ExposureRefresh.objects.all()} == {outage.pk, second_run.pk}


def test_a_contradicted_claim_closes_the_obligation_as_contradicted(world, people):
    world.run(world.outage)
    _move_provider_region(world.deployment)
    derive_claims(world.deployment)
    assert _claim(world.deployment, "data_boundary").status == "contradicted"
    response = _refresh(_client(people["analyst"]), world.deployment, world.outage)
    assert response.status_code == 201, response.content
    (closed,) = response.json()["obligations"]["closed"]
    assert closed["spine_outcome"] == "contradicted"
    assert closed["outcome"]["claims"]["data_boundary"] == "contradicted"


def test_removing_the_operator_who_refreshed_is_never_held_back(world, people):
    """Removing an operator is a stop: it answers 204 through the real route, nulls
    the refresh's account and keeps the name. The map and the staleness name no
    account; every row goes with its deployment."""
    world.run(world.outage)
    CustomerParameterSet.record(world.deployment, OPERATIONS, operations_document(margin="45000"),
                                author=people["analyst"])
    leaver = User.objects.create_user(username="lea", password="x", role="analyst")
    response = _refresh(_client(leaver), world.deployment, world.outage)
    assert response.status_code == 201 and response.json()["obligations"]["closed"], response.content
    removed = _client(people["admin"]).delete(f"/api/accounts/users/{leaver.pk}/")
    assert removed.status_code == 204, removed.content
    closure = ExposureRefresh.objects.get()
    assert (closure.author_id, closure.author_username) == (None, "lea")
    Deployment.objects.get(pk=world.deployment.pk).delete()
    assert not ExposureDependencies.objects.exists() and not ExposureStaleness.objects.exists()
    assert not ExposureRefresh.objects.exists()


def test_spine_outcome_for_the_financial_claim():
    technical = [{"code": "claim_invalidated", "dependency": "claim:data_boundary"}]
    financial = [{"code": "parameter_set_superseded", "dependency": "parameter_set:x"}]

    def deps(**statuses):
        return {"claim_types": sorted(statuses),
                "claims": {k: ([] if v is None else [{"status": v}]) for k, v in statuses.items()}}

    assert continuous_service.spine_outcome(financial, deps(ai_bom="verified"))[0] == "superseded"
    assert continuous_service.spine_outcome(technical, deps(ai_bom="verified", data_boundary="supported"))[0] == (
        "restored")
    assert continuous_service.spine_outcome(technical, deps(ai_bom="verified", data_boundary="contradicted"))[0] == (
        "contradicted")
    assert continuous_service.spine_outcome(technical, deps(ai_bom="verified", data_boundary="unknown"))[0] == "unknown"
    assert continuous_service.spine_outcome(technical, deps(ai_bom="verified", data_boundary=None))[0] == "unknown"


def test_a_refresh_with_nothing_stale_runs_nothing(world, people, monkeypatch):
    world.run(world.outage)
    called = _no_run_anywhere(monkeypatch)
    response = _refresh(_client(people["analyst"]), world.deployment, world.outage)
    assert response.status_code == 409 and response.json()["code"] == "exposure_current"
    assert called == [] and FinancialScenario.objects.count() == 2


def test_the_refresh_body_is_read_strictly(world, people):
    world.run(world.outage)
    analyst = _client(people["analyst"])
    assert _refresh(_client(people["viewer"]), world.deployment, world.outage).status_code == 403
    assert _refresh(analyst, world.deployment, world.outage, as_of="2026-13-01").json()["code"] == "date_malformed"
    future = (TODAY + timedelta(days=1)).isoformat()
    assert _refresh(analyst, world.deployment, world.outage, as_of=future).json()["code"] == "field_malformed"
    assert _refresh(analyst, world.deployment, world.outage, note="x").json()["code"] == "field_unrecognised"


def test_a_scenario_the_builder_did_not_build_is_not_rebuilt(people):
    deployment = Deployment.objects.create(name="rows")
    scenario = stored(deployment, people["analyst"])
    simulation_service.simulate_scenario(scenario, seed=1, draws=1_000)
    CustomerParameterSet.record(deployment, "bank_prod_2026q4", {"variables": {
        "notification_unit_cost": _entry("money_per_unit", "3"),
        "notification_fixed_cost": _entry("money", "40000"),
    }}, author=people["analyst"])
    response = _refresh(_client(people["analyst"]), deployment, scenario)
    assert response.status_code == 400 and response.json()["code"] == "refresh_not_rebuildable"
    assert ExposureStaleness.objects.count() == 1  # the obligation is recorded, and stays open


def test_the_refresh_route_takes_a_run_slot(world, people, monkeypatch):
    assert getattr(report_api.ScenarioRefreshView.post, "economics_capped", False) is True
    world.run(world.outage)
    CustomerParameterSet.record(world.deployment, OPERATIONS, operations_document(margin="45000"),
                                author=people["analyst"])
    slots, _why = capacity.acquire(str(world.deployment.uuid))
    try:
        response = _refresh(_client(people["analyst"]), world.deployment, world.outage)
    finally:
        if slots is not None:
            slots.release()
    assert response.status_code == 503 and response.json()["code"] == capacity.CODE
    assert FinancialScenario.objects.count() == 2 and not ExposureStaleness.objects.exists()


# ======================================================================
# The safety rule
# ======================================================================


def test_no_route_here_is_a_stop_and_only_the_refresh_is_capped():
    for name in ("deployment-economics-scenario-freshness", "deployment-economics-assurance",
                 "deployment-economics-scenario-refresh"):
        assert name not in stops.STOP_ROUTES and name not in stops.EXEMPT_ROUTES
    assert set(stops.NOT_STOPS["deployment-economics-scenario-freshness"]) == {"GET"}
    assert set(stops.NOT_STOPS["deployment-economics-assurance"]) == {"GET", "POST"}
    assert set(stops.NOT_STOPS["deployment-economics-scenario-refresh"]) == {"POST"}
    assert not getattr(report_api.AssuranceView.post, "economics_capped", False)
    assert "assurance.economics.report_api.ScenarioRefreshView.post" in capacity.CAPPED


@pytest.mark.django_db(transaction=True)
def test_a_stop_is_answered_in_its_bound_while_a_large_check_is_held_open(monkeypatch):
    """SAFETY. ``transaction=True`` IS THE TEST: a check of many stale runs is held
    open mid-way on another thread, and the scan's Stop is sent meanwhile. It is
    answered (202) and saved within the stop tripwire's bound while the check is still
    held, and the check held no transaction."""
    analyst = User.objects.create_user(username="ann", password="x", role="analyst")
    deployment = Deployment.objects.create(name="large")
    many = 16
    for index in range(many):
        scenario = stored(deployment, analyst, set_key=f"set-{index}")
        assert simulation_service.simulate_scenario(scenario, seed=1, draws=1_000).completed
    for index in range(many):  # every run stale: a newer version of each set
        CustomerParameterSet.record(deployment, f"set-{index}", {"variables": {
            "notification_unit_cost": _entry("money_per_unit", "3"),
            "notification_fixed_cost": _entry("money", "40000"),
        }}, author=analyst)
    scan = PentestScan.objects.create(
        user=analyst, target_url="https://offline.invalid/", consent=True, status=PentestScan.STATUS_PENDING
    )
    inside, release = threading.Event(), threading.Event()
    seen = {"count": 0}

    def held():
        seen["count"] += 1
        if seen["count"] == many // 2:
            seen["atomic"] = connection.in_atomic_block
            inside.set()
            release.wait(timeout=60)

    monkeypatch.setattr(continuous_service, "_between_runs", held)
    out = {}

    def checking():
        try:
            out["response"] = _post(_client(analyst), _base(deployment) + "assurance/")
        except Exception as exc:  # noqa: BLE001 - reported by the assertion below
            out["error"] = exc
        finally:
            connection.close()

    thread = threading.Thread(target=checking)
    thread.start()
    try:
        assert inside.wait(timeout=120), f"the check never reached the middle: {out}"
        began = time.perf_counter()
        stop = _client(analyst).post(f"/api/pentest/scans/{scan.uuid}/stop/", {}, format="json")
        took = time.perf_counter() - began
        still_held = thread.is_alive() and not release.is_set()
    finally:
        release.set()
        thread.join(timeout=120)
    assert stop.status_code == 202, stop.content
    assert stop.json()["stop_saved"] is True
    assert still_held, "the Stop was answered only once the check had let go"
    assert took <= tripwire.STOP_LATENCY_BOUND, f"the Stop took {took * 1000:.1f} ms"
    assert seen["atomic"] is False, "the check held a transaction while it read"
    scan.refresh_from_db()
    assert scan.stop_requested_at is not None
    assert out["response"].status_code == 200, out
    assert out["response"].json()["obligations_recorded"] == many


def test_nothing_django_loads_imports_the_service():
    """Read, not run: the service is imported only inside a function or a view -- by
    step 7b's service, the report, the routes and the operator's command -- never at
    a module's top level by anything Django loads at start (the models, the URLconf,
    the route modules, the report). ``tests/test_economics_simulation.py``'s
    ``test_django_and_the_urlconf_never_import_the_probabilistic_engine`` runs
    ``django.setup()`` and every URLconf and finds it unloaded."""
    import ast

    for relative in ("assurance/economics/models.py", "assurance/economics/report.py",
                     "assurance/economics/report_api.py", "assurance/economics/simulation_service.py",
                     "assurance/urls.py", "assurance/models.py"):
        tree = ast.parse((REPO / relative).read_text(encoding="utf-8"))
        top = [node for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))]
        for node in top:
            names = [alias.name for alias in node.names]
            module = getattr(node, "module", "") or ""
            assert "continuous_service" not in module and "continuous_service" not in names, relative


# ======================================================================
# The spec and the README
# ======================================================================


SPEC_PHRASES = (
    "## 34. Continuous financial assurance (E6)",
    "### 34.1 The dependency map",
    "### 34.2 Change makes stale",
    "### 34.3 The refresh obligation",
    "### 34.4 The refresh",
    "### Choices for the owner",
    "`deployment-economics-scenario-refresh`",
    "`deployment-economics-assurance`",
    "`deployment-economics-scenario-freshness`",
    "`continuous_service.TEMPLATE_CLAIMS`",
    "`manage.py check_financial_assurance`",
    "`0073_exposure_assurance.py`",
)


def test_the_spec_and_the_readme_state_continuous_assurance():
    text = SPEC.read_text(encoding="utf-8")
    for phrase in SPEC_PHRASES:
        assert phrase in text, phrase
    for code in STALE_REASONS:
        assert f"`{code}`" in text, code
    readme = README.read_text(encoding="utf-8")
    for phrase in ("economics/scenarios/<scenario uuid>/refresh/", "economics/assurance/", "check_financial_assurance"):
        assert phrase in readme, phrase
