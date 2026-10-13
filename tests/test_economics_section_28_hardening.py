"""Section 28 hardening: the remaining MEDIUM findings of the section 28 audit
(``docs/economics/spec-v1.md``, section 35). Each test replays the audit's probe and
asserts the defence.

- T5 (the audit's probe T4a): a result's record and the card rewritten together past
  the ORM, digests recomputed, are refused wherever they are served, carded or
  receipted: the recorded receipt's signed document binds the stored rows
  (``receipt_binding``), and nothing is served as a number.
- T2a: a crafted, unsigned, non-synthetic snapshot file earns no licence or trust it
  states: the feed registry decides its licence, and it registers ``unverified``.
- T2c: an observation row rewritten, removed or added past the ORM is found on read
  (each row's own digest, and the version's digest over its rows) and the version is
  demoted (``snapshot_rows_mismatch``).
- T9a: a signed receipt needs the scenario version's latest review approved by a
  person who authored no version of it (``scenario_not_reviewed``), ON unless
  ``ATHENA_ECONOMICS_RECEIPT_REVIEW`` is exactly ``off``; the review route.
- T1/T4: a material change of the customer parameter set against the version before
  it needs a sensitive override IN FORCE (``material_change_unapproved``), and an
  override counts only while in force: two approvers, not expired, not revoked; a
  revocation is never refused.
- T9b: an approver an author or requester promoted, who promoted themselves, or who
  was promoted after the request, is refused (``approver_role_not_independent``);
  a demotion is never refused.

New names are read through their modules, so that on the base, where they do not
exist, each test fails on what it asserts rather than the whole file on its import.
SYNTHETIC / ILLUSTRATIVE figures only.
"""

from __future__ import annotations

import copy
import dataclasses
import importlib
import json
from datetime import date, timedelta
from decimal import Decimal

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.contrib.auth import get_user_model
from django.utils import timezone
from mythos_core import exposure_receipt as core
from rest_framework.test import APIClient

from assurance.economics import builder, receipt_service, report, simulation_service, snapshots, validity_service
from assurance.economics import models as econ
from assurance.economics.engine import fx
from assurance.economics.engine.fx import FXBook, FXPolicy
from assurance.economics.engine.money import Money
from assurance.economics.models import (
    CostIndexObservation,
    EconomicsRefused,
    FinancialExposureReceipt,
    FinancialSource,
    FinancialValidityCard,
    FXObservation,
    ScenarioReview,
    SensitiveOverride,
    SimulationResult,
    SourceNotUsableForProduction,
    canonical_digest,
    card_digest,
)
from assurance.models import Deployment
from tests.test_economics_report import QUICK, stored
from tests.test_economics_scenarios import _entry
from tests.test_economics_stated_distributions import _build_body, _payment_world, _point_document, stated

pytestmark = pytest.mark.django_db
User = get_user_model()
LABEL = "SYNTHETIC / ILLUSTRATIVE"
REVIEW_ENV = "ATHENA_ECONOMICS_RECEIPT_REVIEW"


@pytest.fixture(autouse=True)
def _review_gate_unset(monkeypatch):
    """Every test here starts with the review gate's variable unset: the default."""
    monkeypatch.delenv(REVIEW_ENV, raising=False)


@pytest.fixture
def people():
    return {
        "admin": User.objects.create_user(username="ada", password="x", role="admin"),
        "admin2": User.objects.create_user(username="bea", password="x", role="admin"),
        "analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
        "reviewer": User.objects.create_user(username="rex", password="x", role="analyst"),
        "owner": User.objects.create_user(username="vic", password="x", role="viewer"),
        "sock": User.objects.create_user(username="mal", password="x", role="viewer"),
    }


@pytest.fixture
def deployment(people):
    return Deployment.objects.create(name="payments-agent", owner=people["owner"])


@pytest.fixture
def keys(monkeypatch):
    """A receipt key the engine's published keyring holds, and the engine's signer
    standing in for the engine: the tests' keys, never a real one."""
    key = Ed25519PrivateKey.generate()
    other = Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ring = core.receipt_keyring([key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)],
                                other_roles={"engine-outcome": [other]})
    monkeypatch.setattr(receipt_service, "engine_keyring", lambda: ring)
    monkeypatch.setattr(receipt_service, "engine_signer", lambda document: core.sign_receipt(document, key))
    return {"ring": ring, "sign": lambda document: core.sign_receipt(document, key)}


def _client(user=None):
    client = APIClient()
    if user is not None:
        client.force_authenticate(user=user)
    return client


def _post(client, url, body=None):
    return client.post(url, data=json.dumps({} if body is None else body), content_type="application/json")


def _base(deployment, scenario):
    return f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/{scenario.uuid}/"


def _override_url(deployment, override, action):
    return f"/api/assurance/deployments/{deployment.uuid}/economics/overrides/{override}/{action}/"


def _approve(deployment, scenario, reviewer):
    response = _post(_client(reviewer), _base(deployment, scenario) + "reviews/", {"verdict": "approved"})
    assert response.status_code == 201, response.content
    return response.json()


def _simulate_with_receipt(deployment, scenario, author):
    response = _post(_client(author), _base(deployment, scenario) + "simulate/",
                     {"seed": 7, "policy": QUICK, "receipt": True})
    assert response.status_code == 201, response.content
    return response.json()


def _review_service():
    return importlib.import_module("assurance.economics.review_service")


# =====================================================================================
# T5: the stored report is bound to its receipt
# =====================================================================================


def _receipted(deployment, people):
    scenario = stored(deployment, people["analyst"])
    ScenarioReview.objects.create(scenario=scenario, reviewer=people["reviewer"], verdict="approved")
    body = _simulate_with_receipt(deployment, scenario, people["analyst"])
    assert body["receipt"]["issued"] is True, body["receipt"]
    return scenario


def _forge(result: SimulationResult) -> str:
    """The audit's T4a: the record's gross P50 and its digest, and the card's
    reproduction and its digest, rewritten together past the ORM."""
    record = json.loads(json.dumps(result.record))
    record["scenario"]["gross_cash"]["p50"] = "1.00"
    forged = canonical_digest(record)
    SimulationResult._base_manager.filter(pk=result.pk).update(record=record, result_digest=forged)
    card = FinancialValidityCard.objects.get(simulation=result)
    document = json.loads(json.dumps(card.card))
    document["fields"]["reproduction"]["result_digest"] = forged
    FinancialValidityCard._base_manager.filter(pk=card.pk).update(card=document, card_digest=card_digest(document))
    return forged


def test_t5_an_untouched_receipted_result_is_served_verified(deployment, people, keys):
    scenario = _receipted(deployment, people)
    body = _client(people["owner"]).get(_base(deployment, scenario) + "results/").json()
    assert body["integrity"]["verified"] is True and body["integrity"]["failed"] == []
    assert "receipt_binding" in body["integrity"]["checks"]
    assert body["receipt"]["validity_card_digest"] == body["validity_card"]["digest"]
    result = SimulationResult.objects.get()
    card = FinancialValidityCard.objects.get()
    assert report.verified_grade(card, result) == card.confidence_grade
    assert receipt_service.verify_stored_receipt(FinancialExposureReceipt.objects.get(), keys["ring"]).verified


def test_t5_a_coordinated_rewrite_is_never_served_carded_or_receipted(deployment, people, keys):
    """The audit's T4a: before this, the report said ``integrity.verified: true`` and
    ``may_be_totalled`` admitted the forged P50."""
    scenario = _receipted(deployment, people)
    result = SimulationResult.objects.get()
    _forge(result)
    result = SimulationResult.objects.get()
    owner = _client(people["owner"])
    # Served: a refusal, never a number.
    body = owner.get(_base(deployment, scenario) + "results/").json()
    assert body["integrity"]["verified"] is False
    assert "receipt_binding" in body["integrity"]["failed"], body["integrity"]
    assert body["refusal"]["code"] == "stored_row_unverified"
    assert set(body["summary"]) == {"not_reported"} and body["grade"] is None
    assert set(body["validity_card"]) == {"not_reported"}
    assert report.verifies(body) and report.may_be_totalled(body) is False
    assert "1.00" not in json.dumps(body["summary"])
    # The scenario list, the scenario's document and the events route's standing.
    listed = owner.get(f"/api/assurance/deployments/{deployment.uuid}/economics/scenarios/").json()
    (entry,) = listed["scenarios"]
    assert entry["grade"] is None and entry["excluded_from_totals"] is True
    document = owner.get(_base(deployment, scenario)).json()
    (simulation,) = document["validity"]["simulations"]
    assert simulation["grade"] is None and simulation["card_verified"] is False
    assert report.standing(scenario)["excluded_from_totals"] is True
    card = FinancialValidityCard.objects.get()
    assert report.verified_grade(card, result) is None
    assert "receipt_binding" in report.stored_row_failures(result, card, None, scenario)
    # Carded: the card recorded is not returned.
    carded = validity_service.issue_card(result)
    assert carded.card is None and carded.code == "stored_row_unverified", (carded.code, carded.detail)
    # Receipted: the recorded receipt does not verify, and is not returned.
    again = receipt_service.issue_receipt(result, keyring=keys["ring"])
    assert again.receipt is None and again.code == "recorded_receipt_unverified"


def test_t5_a_receipt_document_that_is_not_its_envelopes_payload_breaks_the_binding(deployment, people, keys):
    scenario = _receipted(deployment, people)
    receipt = FinancialExposureReceipt.objects.get()
    document = json.loads(json.dumps(receipt.document))
    document["result"]["p50"]["amount"] = "1.00"
    FinancialExposureReceipt._base_manager.filter(pk=receipt.pk).update(document=document)
    body = _client(people["owner"]).get(_base(deployment, scenario) + "results/").json()
    assert body["integrity"]["failed"] == ["receipt_binding"], body["integrity"]
    assert set(body["summary"]) == {"not_reported"}


def test_t5_a_record_rewritten_before_its_card_or_receipt_is_never_carded_or_signed(deployment, people, keys):
    """A record edited past the ORM (its digest left) before anything was issued: the
    card is never made from it, and no receipt signs it."""
    scenario = stored(deployment, people["analyst"])
    ScenarioReview.objects.create(scenario=scenario, reviewer=people["reviewer"], verdict="approved")
    result = simulation_service.simulate_scenario(scenario, seed=7, draws=10_000).result
    record = json.loads(json.dumps(result.record))
    record["scenario"]["gross_cash"]["p50"] = "1.00"
    SimulationResult._base_manager.filter(pk=result.pk).update(record=record)
    result = SimulationResult.objects.get(pk=result.pk)
    carded = validity_service.issue_card(result)
    assert carded.card is None and carded.code == "stored_row_unverified", (carded.code, carded.detail)
    signed = receipt_service.issue_receipt(result, signer=keys["sign"], keyring=keys["ring"])
    assert signed.receipt is None and signed.code == "stored_row_unverified", (signed.code, signed.detail)
    assert not FinancialValidityCard.objects.exists() and not FinancialExposureReceipt.objects.exists()


# =====================================================================================
# T2a: a crafted snapshot file earns no licence or trust it states
# =====================================================================================


def _crafted(tmp_path, *, rate="0.0100", **source_over):
    document = json.loads(snapshots.SYNTHETIC_SNAPSHOT.read_bytes())
    document["synthetic"] = False
    document["label"] = "a vendor snapshot"
    document["source"].update(source_key="vendor-fx", provider="Vendor", dataset="vendor fx")
    document["source"].update(source_over)
    for row in document["fx"]:
        if (row["provider"], row["base"], row["quote"], row["effective_date"]) == (
            "SYNTHETIC-REF", "EUR", "USD", "2020-03-02"
        ):
            row["rate"] = rate
    path = tmp_path / f"crafted-{len(list(tmp_path.iterdir()))}.json"
    path.write_text(json.dumps(document, indent=2), encoding="utf-8")
    return path


def test_t2a_a_crafted_file_registers_unreviewed_and_unverified_whatever_it_states(tmp_path, deployment):
    """The audit's T2a: an unsigned file stating ``licensed`` / ``licensed_vendor``
    was production-usable, and a run read its EUR/USD of 0.01."""
    source = snapshots.register_snapshot(_crafted(tmp_path, license_class="licensed", trust_tier="licensed_vendor"))
    assert (source.license_class, source.trust_tier, source.synthetic) == ("unreviewed", "unverified", False)
    with pytest.raises(SourceNotUsableForProduction) as refused:
        source.check_usable_for_production(deployment)
    assert refused.value.code == "unreviewed_license"


def test_t2a_the_feed_registry_decides_a_files_licence(tmp_path, monkeypatch):
    """A file whose source key is the registry's takes the licence of the registry's
    line, and still registers ``unverified``: trust comes from an admin's raise."""
    from assurance.economics.engine import feeds as feed_rules

    key = sorted(feed_rules.REGISTRY)[0]
    line = feed_rules.REGISTRY[key]
    monkeypatch.setattr(feed_rules, "REGISTRY", {key: dataclasses.replace(line, license_class="open")})
    source = snapshots.register_snapshot(
        _crafted(tmp_path, source_key=key, license_class="licensed", trust_tier="benchmark")
    )
    assert (source.source_key, source.license_class, source.trust_tier) == (key, "open", "unverified")


def test_t2a_a_synthetic_file_and_an_authoritative_one_are_as_before(tmp_path):
    synthetic = snapshots.register_snapshot()
    assert (synthetic.license_class, synthetic.trust_tier, synthetic.synthetic) == ("open", "unverified", True)
    with pytest.raises(EconomicsRefused) as refused:
        snapshots.register_snapshot(_crafted(tmp_path, license_class="licensed", trust_tier="authoritative"))
    assert refused.value.code == "second_person_required"
    assert not FinancialSource.objects.filter(source_key="vendor-fx").exists()


# =====================================================================================
# T2c: an observation row rewritten past the ORM is found, and its version demoted
# =====================================================================================


def _usable(tmp_path):
    """A production-usable version, registered as a feed's answer is (the registry's
    terms, here stated by the snapshot itself)."""
    snapshot = snapshots.read_snapshot(_crafted(tmp_path, rate="1.1000", license_class="licensed",
                                                trust_tier="licensed_vendor"))
    version, created = snapshots.register(snapshot)
    assert created
    return version


def _eur_usd(book: FXBook):
    return fx.convert(Money(Decimal("1000"), "EUR"), "USD", date(2020, 3, 2), book, FXPolicy(("SYNTHETIC-REF",)))


def _eur_usd_row(source):
    return FXObservation.objects.get(source=source, provider="SYNTHETIC-REF", base_currency="EUR",
                                     quote_currency="USD", effective_date=date(2020, 3, 2))


def test_t2c_an_fx_row_rewritten_past_the_orm_demotes_its_version(tmp_path, deployment):
    """The audit's T2c: the book served the rewritten rate under the original hash."""
    source = _usable(tmp_path)
    source.check_usable_for_production(deployment)
    assert _eur_usd(snapshots.fx_book([source], deployment=deployment)).output.amount == Decimal("1100.0000")
    FXObservation._base_manager.filter(pk=_eur_usd_row(source).pk).update(rate=Decimal("0.0100"))
    with pytest.raises(EconomicsRefused) as refused:
        snapshots.fx_book([source], deployment=deployment)
    assert refused.value.code == "snapshot_rows_mismatch"
    with pytest.raises(SourceNotUsableForProduction) as demoted:
        source.check_usable_for_production(deployment)
    assert demoted.value.code == "snapshot_rows_mismatch"
    assert source.production_use_refusal(deployment) == "snapshot_rows_mismatch"


def test_t2c_a_row_rewritten_with_its_own_digest_or_removed_is_found(tmp_path, deployment):
    source = _usable(tmp_path)
    row = _eur_usd_row(source)
    row.rate = Decimal("0.0100")
    FXObservation._base_manager.filter(pk=row.pk).update(rate=row.rate, row_digest=row.computed_digest())
    with pytest.raises(EconomicsRefused) as refused:
        snapshots.fx_book([source], deployment=deployment)
    assert refused.value.code == "snapshot_rows_mismatch"
    other = _usable_again(tmp_path)
    index_row = CostIndexObservation.objects.filter(source=other).order_by("id").first()
    CostIndexObservation._base_manager.filter(pk=index_row.pk).delete()
    with pytest.raises(EconomicsRefused) as refused:
        snapshots.index_book([other], deployment=deployment)
    assert refused.value.code == "snapshot_rows_mismatch"


def _usable_again(tmp_path):
    snapshot = snapshots.read_snapshot(_crafted(tmp_path, rate="1.2000", source_key="vendor-fx-2",
                                                license_class="licensed", trust_tier="licensed_vendor"))
    version, _ = snapshots.register(snapshot)
    return version


def test_t2c_a_raised_version_reads_and_checks_the_rows_it_was_registered_with(tmp_path, deployment, people):
    source = _usable(tmp_path)
    raised = econ.FinancialSourceTrustRaise.request(source, "authoritative", "official", by=people["admin"],
                                                    channel="api")
    raised.approve(by=people["admin2"], channel="api")
    top = FinancialSource.objects.get(source_key=source.source_key, version=2)
    assert top.observations_digest == source.observations_digest != ""
    top.check_usable_for_production(deployment)
    FXObservation._base_manager.filter(pk=_eur_usd_row(source).pk).update(rate=Decimal("0.0100"))
    with pytest.raises(SourceNotUsableForProduction) as demoted:
        top.check_usable_for_production(deployment)
    assert demoted.value.code == "snapshot_rows_mismatch"


# =====================================================================================
# T9a: a signed receipt needs an approved review by someone other than the author
# =====================================================================================


def test_t9a_no_receipt_without_an_approved_review(deployment, people, keys):
    """The audit's T8a: one analyst went from rows to a signed receipt over a draft."""
    scenario = stored(deployment, people["analyst"])
    body = _simulate_with_receipt(deployment, scenario, people["analyst"])
    assert body["receipt"]["issued"] is False and body["receipt"]["code"] == "scenario_not_reviewed", body
    assert not FinancialExposureReceipt.objects.exists()


def test_t9a_a_colleague_approves_through_the_route_and_the_receipt_is_signed(deployment, people, keys):
    scenario = stored(deployment, people["analyst"])
    url = _base(deployment, scenario) + "reviews/"
    # The author may not review it, nor may a viewer.
    own = _post(_client(people["analyst"]), url, {"verdict": "approved"})
    assert own.status_code == 403 and own.json()["code"] == "author_reviews_own_scenario", own.content
    assert _post(_client(people["owner"]), url, {"verdict": "approved"}).status_code == 403
    assert _post(_client(people["reviewer"]), url, {"verdict": "fine"}).status_code == 400
    assert _post(_client(people["reviewer"]), url, {"verdict": "approved", "at": "x"}).status_code == 400
    gate = _client(people["owner"]).get(url).json()["receipt_gate"]
    assert gate["satisfied"] is False and gate["review_refusal"]["code"] == "scenario_not_reviewed"
    assert gate["review"] == "required"
    approved = _post(_client(people["reviewer"]), url, {"verdict": "approved", "note": "checked the inputs"})
    assert approved.status_code == 201, approved.content
    assert approved.json()["review"]["reviewer"] == "rex" and approved.json()["receipt_gate"]["satisfied"] is True
    body = _simulate_with_receipt(deployment, scenario, people["analyst"])
    assert body["receipt"]["issued"] is True, body["receipt"]


def test_t9a_a_returned_review_stands_until_it_is_approved_again(deployment, people, keys):
    scenario = stored(deployment, people["analyst"])
    _approve(deployment, scenario, people["reviewer"])
    returned = _post(_client(people["admin"]), _base(deployment, scenario) + "reviews/", {"verdict": "returned"})
    assert returned.status_code == 201
    body = _simulate_with_receipt(deployment, scenario, people["analyst"])
    assert body["receipt"]["code"] == "scenario_not_reviewed", body["receipt"]


@pytest.mark.parametrize("value, required", [
    (None, True), ("required", True), ("off", False), ("OFF", True), ("no", True), ("", True), (" off", True),
])
def test_t9a_the_gate_is_on_unless_its_variable_is_exactly_off(monkeypatch, value, required):
    if value is None:
        monkeypatch.delenv(REVIEW_ENV, raising=False)
    else:
        monkeypatch.setenv(REVIEW_ENV, value)
    gates = _review_service()
    assert gates.review_gate() == ("required" if required else "off")


def test_t9a_switched_off_a_receipt_needs_no_review(deployment, people, keys, monkeypatch):
    monkeypatch.setenv(REVIEW_ENV, "off")
    scenario = stored(deployment, people["analyst"])
    body = _simulate_with_receipt(deployment, scenario, people["analyst"])
    assert body["receipt"]["issued"] is True, body["receipt"]


# =====================================================================================
# T1/T4: a material change needs an override in force, and counts only while in force
# =====================================================================================


def _set_url(deployment):
    return f"/api/assurance/deployments/{deployment.uuid}/economics/parameter-sets/bank_prod_2026q4/versions/"


def _frequency(rate: str) -> dict:
    return _entry("count", rate, rate, rate, source_type="INDUSTRY_BENCHMARK",
                  evidence_ref=f"{LABEL}: industry loss data", distribution=stated("poisson", rate=rate))


def _two_versions(deployment, people, edit):
    """v1 and v2 of the set, by one analyst through the route, and a scenario version
    built on v2 and approved by a colleague: the audit's probes T1b and T3a."""
    analyst = _client(people["analyst"])
    v1 = _point_document()
    v1["frequency"] = _frequency("2")
    assert _post(analyst, _set_url(deployment), v1).status_code == 201
    v2 = copy.deepcopy(v1)
    edit(v2)
    response = _post(analyst, _set_url(deployment), v2)
    assert response.status_code == 201, response.content
    asset, finding = _payment_world(deployment)
    scenario, _ = builder.build(deployment, _build_body(asset, finding, version=2, title="payment agent v2"),
                                author=people["analyst"])
    _approve(deployment, scenario, people["reviewer"])
    result = simulation_service.simulate_scenario(scenario, seed=4, draws=2_000).result
    return scenario, result


def _cut(document):
    """The audit's T1b: transactions and value cut 1000x, by the same analyst."""
    document["variables"]["transactions_per_day"] = _entry("count_per_day", "18", evidence_ref="trust me")
    document["variables"]["average_transaction_value"] = _entry("money_per_unit", "25", evidence_ref="trust me")


def test_t1_a_material_cut_needs_overrides_in_force_before_a_receipt(deployment, people, keys):
    scenario, result = _two_versions(deployment, people, _cut)
    refused = receipt_service.issue_receipt(result, signer=keys["sign"], keyring=keys["ring"])
    assert (refused.receipt, refused.code) == (None, "material_change_unapproved"), (refused.code, refused.detail)
    url = _base(deployment, scenario) + "overrides/"
    served = _client(people["owner"]).get(url).json()
    subjects = [change["subject"] for change in served["receipt_gate"]["sensitive_changes"]]
    assert subjects == ["parameter-set:bank_prod_2026q4:v2:average_transaction_value",
                        "parameter-set:bank_prod_2026q4:v2:transactions_per_day"], subjects
    for subject in subjects:
        asked = _post(_client(people["analyst"]), url, {"subject": subject, "reason": "customer confirmed"})
        assert asked.status_code == 201, asked.content
        override = asked.json()["override"]
        assert override["in_force"] is False and override["not_in_force_because"] == "override_needs_two_approvers"
        own = _post(_client(people["analyst"]), _override_url(deployment, override["uuid"], "approve"))
        assert own.status_code == 403 and own.json()["code"] == "requester_approves_own_override"
        for approver in ("reviewer", "admin"):
            done = _post(_client(people[approver]), _override_url(deployment, override["uuid"], "approve"))
            assert done.status_code == 200, done.content
        assert done.json()["override"]["in_force"] is True
    signed = receipt_service.issue_receipt(result, signer=keys["sign"], keyring=keys["ring"])
    assert signed.receipt is not None, (signed.code, signed.detail)


def test_t4_a_frequency_prior_cut_fourfold_is_a_sensitive_change(deployment, people, keys):
    def cut(document):
        document["frequency"] = _frequency("0.5")

    scenario, result = _two_versions(deployment, people, cut)
    changes = _review_service().sensitive_changes(scenario.pk)
    assert [c["subject"] for c in changes] == ["parameter-set:bank_prod_2026q4:v2:frequency"], changes
    refused = receipt_service.issue_receipt(result, signer=keys["sign"], keyring=keys["ring"])
    assert refused.code == "material_change_unapproved"


def _in_force(deployment, people, scenario, subject):
    override = SensitiveOverride.objects.create(scenario=scenario, subject=subject, reason="confirmed",
                                                requested_by=people["analyst"])
    for approver in ("reviewer", "admin"):
        econ.OverrideApproval.objects.create(override=override, approver=people[approver])
    assert override.in_force
    return override


def test_t1_t4_an_override_counts_only_while_in_force(deployment, people, keys):
    scenario, result = _two_versions(deployment, people, lambda d: d.update(frequency=_frequency("0.5")))
    subject = "parameter-set:bank_prod_2026q4:v2:frequency"
    gates = _review_service()
    first = _in_force(deployment, people, scenario, subject)
    assert gates.override_refusal(scenario.pk) is None
    # Expired: thirty days after its request, it counts for nothing.
    SensitiveOverride._base_manager.filter(pk=first.pk).update(
        requested_at=timezone.now() - timedelta(days=30, seconds=1)
    )
    assert first.approval_refusal() == "override_expired"
    assert gates.override_refusal(scenario.pk)[0] == "material_change_unapproved"
    late = _post(_client(people["admin2"]), _override_url(deployment, first.uuid, "approve"))
    assert late.status_code == 409 and late.json()["code"] == "override_expired"
    # Revoked: never refused, by anyone who writes, in any state; final.
    second = _in_force(deployment, people, scenario, subject)
    assert gates.override_refusal(scenario.pk) is None
    for revoker, target in (("analyst", second), ("analyst", second), ("reviewer", first)):
        done = _post(_client(people[revoker]), _override_url(deployment, target.uuid, "revoke"), {"reason": "wrong"})
        assert done.status_code == 200, done.content
        assert done.json()["override"]["in_force"] is False
    assert second.approval_refusal() == "override_revoked"
    assert gates.override_refusal(scenario.pk)[0] == "material_change_unapproved"
    # Who may write economics records revokes; a viewer writes nothing.
    assert _post(_client(people["owner"]), _override_url(deployment, second.uuid, "revoke")).status_code == 403
    after = _post(_client(people["admin2"]), _override_url(deployment, second.uuid, "approve"))
    assert after.status_code == 409 and after.json()["code"] == "override_revoked"
    refused = receipt_service.issue_receipt(result, signer=keys["sign"], keyring=keys["ring"])
    assert refused.code == "material_change_unapproved"


# =====================================================================================
# T9b: an approver who was promoted for it is not a second person
# =====================================================================================


def _source_at(tier="benchmark"):
    return FinancialSource.objects.create(
        source_key="fed-h10-daily", provider="Federal Reserve", dataset="H.10", url="https://example.invalid/",
        license_class="open", trust_tier=tier, retrieved_at="2026-10-01T00:00:00+00:00",
        snapshot_hash="sha256:" + "ab" * 32, schema_version="1",
    )


def _ask_authoritative(client, source):
    asked = _post(client, f"/api/assurance/economics/sources/{source.uuid}/trust-raises/",
                  {"to_tier": "authoritative", "reason": "official publisher"})
    assert asked.status_code == 201 and asked.json()["state"] == "pending", asked.content
    return asked.json()["uuid"]


def _promote(by, account, role="admin"):
    response = _client(by).patch(f"/api/accounts/users/{account.pk}/set_role/", data={"role": role}, format="json")
    assert response.status_code == 200, response.content
    account.refresh_from_db()
    return account


def test_t9b_an_admin_the_requester_promoted_cannot_approve_their_raise(people):
    """The audit's T8c: ada asked, promoted mal (an account she holds), and mal
    approved; the record said two people acted."""
    source = _source_at()
    raise_uuid = _ask_authoritative(_client(people["admin"]), source)
    mal = _promote(people["admin"], people["sock"])
    grant = _grants().latest_for(mal.pk)
    assert (grant.role, grant.granted_by_username, grant.granted_by_pk) == ("admin", "ada", people["admin"].pk)
    approved = _post(_client(mal), f"/api/assurance/economics/trust-raises/{raise_uuid}/approve/")
    assert approved.status_code == 403 and approved.json()["code"] == "approver_role_not_independent", approved.content
    assert econ.FinancialSourceTrustRaise.objects.get().state == "pending"
    assert not FinancialSource.objects.filter(trust_tier="authoritative").exists()
    # A second admin who held the role before the request approves it.
    done = _post(_client(people["admin2"]), f"/api/assurance/economics/trust-raises/{raise_uuid}/approve/")
    assert done.status_code == 200 and done.json()["state"] == "done", done.content


def test_t9b_an_admin_promoted_after_the_request_by_anyone_is_refused(people):
    source = _source_at()
    raise_uuid = _ask_authoritative(_client(people["admin"]), source)
    mal = _promote(people["admin2"], people["sock"])
    approved = _post(_client(mal), f"/api/assurance/economics/trust-raises/{raise_uuid}/approve/")
    assert approved.status_code == 403 and approved.json()["code"] == "approver_role_not_independent"


def test_t9b_a_demotion_is_never_refused_and_records_no_grant(people):
    grants = _grants().objects.count()
    demoted = _promote(people["admin"], people["admin2"], role="viewer")
    assert demoted.role == "viewer"
    # Its own demotion, too.
    assert _promote(people["admin"], people["admin"], role="analyst").role == "analyst"
    assert _grants().objects.count() == grants
    # The account table is as it was: a grant is a row of its own, never a column an
    # account load (every request's, stops included) reads.
    assert not [f.name for f in User._meta.concrete_fields if "grant" in f.name]


def _grants():
    return importlib.import_module("accounts.models").RoleGrant


def test_t9b_a_reviewer_or_override_approver_an_author_promoted_is_refused(deployment, people, keys):
    scenario = stored(deployment, people["admin"])
    mal = _promote(people["admin"], people["sock"], role="analyst")
    review = _post(_client(mal), _base(deployment, scenario) + "reviews/", {"verdict": "approved"})
    assert review.status_code == 403 and review.json()["code"] == "approver_role_not_independent", review.content
    # Returning it is never refused by the rule: it takes approval away.
    returned = _post(_client(mal), _base(deployment, scenario) + "reviews/", {"verdict": "returned"})
    assert returned.status_code == 201, returned.content
    asked = _post(_client(people["analyst"]), _base(deployment, scenario) + "overrides/",
                  {"subject": "x", "reason": "y"})
    assert asked.status_code == 201
    # Promoted after the override was asked for, by an admin who did not ask for it.
    promoted = _promote(people["admin2"], people["owner"], role="analyst")
    approval = _post(_client(promoted), _override_url(deployment, asked.json()["override"]["uuid"], "approve"))
    assert approval.status_code == 403 and approval.json()["code"] == "approver_role_not_independent"


def test_t2c_the_migration_gives_stored_rows_the_digests_a_read_recomputes(tmp_path, deployment, people):
    """Migration 0074 gives the rows and versions already stored their digests from
    the rows as they stand: the same digests a read recomputes, so nothing stored
    before it is demoted by it, a raised version included."""
    from django.apps import apps

    migration = importlib.import_module("assurance.migrations.0074_section_28_hardening")
    source = _usable(tmp_path)
    econ.FinancialSourceTrustRaise.request(source, "authoritative", "official", by=people["admin"], channel="api")
    econ.FinancialSourceTrustRaise.objects.get().approve(by=people["admin2"], channel="api")
    synthetic = snapshots.register_snapshot()
    # As stored before the migration: no digest anywhere.
    for model in (FXObservation, CostIndexObservation):
        model._base_manager.update(row_digest="")
    FinancialSource._base_manager.update(observations_digest="")
    assert econ.observation_rows_refusal(FinancialSource.objects.values_list("pk", flat=True))[0] == (
        "snapshot_rows_mismatch"
    )
    migration.give_the_stored_rows_their_digests(apps, None)
    versions = list(FinancialSource.objects.order_by("pk"))
    assert len(versions) == 3 and all(v.observations_digest for v in versions)
    assert econ.observation_rows_refusal([v.pk for v in versions]) is None
    assert FinancialSource.objects.get(source_key=source.source_key, version=2).observations_digest == (
        FinancialSource.objects.get(pk=source.pk).observations_digest
    )
    assert synthetic.pk in {v.pk for v in versions}
