"""The Validity Card and the signed Financial Exposure Receipt of a stored
simulation result (MVP step 8; ``docs/economics/spec-v1.md``, sections 26.3 to
26.8).

- the card: every field of the owner's table is on it, none holds an invented
  value, what has no data says so, and it is reproducible from what is stored; it
  is recorded once per result, append-only; a refused run is carded Unknown;
- the receipt: signed then verified; a tampered card, result, source snapshot or
  signature is refused with its code, and so is a wrong key; it is recorded once
  per result; what cannot be built or signed is returned, never recorded;
- the records go with their deployment and never hold back a stop.
"""

from __future__ import annotations

import base64
import hashlib
import json
import uuid
from datetime import date
from pathlib import Path
from decimal import Decimal

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.contrib.auth import get_user_model
from mythos_core import exposure_receipt as core
from rest_framework.test import APIClient

from assurance.economics import builder, receipt_service, simulation_service, validity_service
from assurance.economics.engine import grade as g
from assurance.economics.engine import scenario_simulation as ss
from assurance.economics.engine import sensitivity as sens
from assurance.economics.models import (
    CausalEffect,
    CustomerParameterSet,
    EconomicsRefused,
    EconomicsRewriteRefused,
    EffectFinding,
    FinancialExposureReceipt,
    FinancialParameter,
    FinancialScenario,
    FinancialValidityCard,
    LossComponent,
    LossEvent,
    ScenarioBuild,
    SimulationResult,
    canonical_digest,
    card_digest,
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
FINGERPRINT = "ab" * 32
DRAWS = 5_000

#: The owner's specification, section 8: the card's fields, in its table's order.
OWNER_FIELDS = (
    "scenario",  # Scenario ID / description
    "model_version",  # Model version
    "system_fingerprint",  # System fingerprint
    "technical_evidence",  # Technical evidence
    "customer_specific_share",  # Customer-specific share
    "benchmark_derived_share",  # Benchmark-derived share
    "expert_estimated_share",  # Expert-estimated share
    "confidence_grade",  # Confidence grade
    "last_calibrated",  # Last calibrated
    "most_sensitive_variables",  # Most sensitive variables
    "data_freshness",  # Data freshness
    "figures",  # P10/P50/P90/mean
    "unknown_variables",  # Unknown variables
    "reproduction",  # Reproduction seed/hash
)
#: The owner's specification, section 15: FinancialValidityCard's key fields.
ENTITY_FIELDS = ("scenario_id", "evidence_mix", "assumptions", "unknowns", "freshness", "calibration_date",
                 "reviewer_status")


@pytest.fixture
def people():
    return {
        "admin": User.objects.create_user(username="ada", password="x", role="admin"),
        "analyst": User.objects.create_user(username="ann", password="x", role="analyst"),
        "owner": User.objects.create_user(username="vic", password="x", role="viewer"),
    }


@pytest.fixture
def deployment(people):
    return Deployment.objects.create(name="payments-agent", owner=people["owner"])


def _raw(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


@pytest.fixture
def keys():
    """Test keys, generated per test as the existing receipt tests make theirs: the
    receipt key, a key of another role, and a stranger."""
    receipt, other, stranger = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    return {
        "receipt": receipt,
        "other": other,
        "stranger": stranger,
        "ring": core.receipt_keyring([_raw(receipt)], other_roles={"engine-outcome": [_raw(other)]}),
    }


def _signer(key, calls=None):
    def sign(document):
        if calls is not None:
            calls.append(document["receipt_id"])
        return core.sign_receipt(document, key)

    return sign


def _parameter(scenario, name, unit, low, base=None, high=None, *, source="EXPERT_ESTIMATE", distribution=None,
               fresh_until=None):
    base = low if base is None else base
    high = base if high is None else high
    return FinancialParameter.objects.create(
        scenario=scenario, name=name, unit=unit, source_type=source,
        currency="USD" if unit.startswith("money") else "", low=low, base=base, high=high,
        evidence_ref=f"{LABEL}: made up", effective_date=date(2026, 9, 1), fresh_until=fresh_until,
        distribution=distribution,
    )


def stored(deployment, author, *, frequency=True, fingerprint=FINGERPRINT, stale=False, version=1):
    """A scenario version as rows: one event of two components (notification and a
    regulatory lump sum), an expert-ranged affected population, a customer's stated
    regulatory range, a benchmark frequency where asked; one hypothetical effect on
    an asset, enabled by one finding; and its build record, whose digest is its
    inputs'. SYNTHETIC / ILLUSTRATIVE."""
    variables = {
        "notification_unit_cost": _entry("money_per_unit", "2"),
        "notification_fixed_cost": _entry("money", "40000"),
    }
    pset = CustomerParameterSet.record(deployment, SET_KEY, {"variables": variables}, author=author)
    assert pset.version == version
    scenario = FinancialScenario.objects.create(
        deployment=deployment, title="Cross-customer exposure", author=author, system_fingerprint=fingerprint
    )
    affected = _parameter(scenario, "exposure.affected_customers", "count", "20000", "50000", "120000")
    amount = _parameter(scenario, "exposure.regulatory_response_cost", "money", "0", "100000", "500000",
                        source="CUSTOMER_PROVIDED", distribution=GAMMA,
                        fresh_until=date(2026, 9, 15) if stale else None)
    if frequency:
        _parameter(scenario, ss.FREQUENCY_PARAMETER, "count", "1", "2", "4", source="INDUSTRY_BENCHMARK",
                   distribution=POISSON)
    rows = {row.name: row for row in pset.parameter_rows()}
    event = LossEvent.objects.create(scenario=scenario, event_key="ev-exposure", currency="USD",
                                     trigger="cross_customer_disclosure", business_process="customer_service")
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
    asset = Asset.objects.create(deployment=deployment, kind="agent", name="support-agent",
                                 identifier=f"agent://support-{uuid.uuid4().hex[:6]}")
    finding = Finding.objects.create(deployment=deployment, fingerprint=f"fp-{uuid.uuid4().hex[:8]}",
                                     finding_type="tenant_isolation_missing", title="tenant isolation", severity="high")
    effect = CausalEffect.objects.create(
        scenario=scenario, loss_event=event, effect_key="exposure", origin="hypothetical",
        effect_type="cross_customer_disclosure", asset=str(asset.uuid), business_process="customer_service",
        template_id="cross_customer_data_exposure", template_version=1, in_scope_of=[["cross_customer_data_exposure", 1]],
    )
    EffectFinding.objects.create(effect=effect, finding=str(finding.uuid), role="prerequisite")
    inputs = {"fixture": str(scenario.uuid), "label": LABEL}
    ScenarioBuild.objects.create(
        scenario=scenario, deployment=deployment, parameter_set=pset, build_digest=builder.build_digest(inputs),
        builder_version="test-fixture", grouping_version="test-fixture", pack="test-fixture", currency="USD",
        as_of=AS_OF, inputs=inputs,
    )
    return scenario


def simulated(scenario, seed=7, draws=DRAWS) -> SimulationResult:
    outcome = simulation_service.simulate_scenario(scenario, seed=seed, draws=draws)
    assert outcome.result is not None, (outcome.code, outcome.detail)
    return outcome.result


def carded(deployment, people, **kwargs):
    result = simulated(stored(deployment, people["analyst"], **kwargs))
    outcome = validity_service.issue_card(result)
    assert outcome.card is not None, (outcome.code, outcome.detail)
    return result, outcome.card


def receipted(deployment, people, keys, **kwargs):
    result, card = carded(deployment, people, **kwargs)
    outcome = receipt_service.issue_receipt(result, signer=_signer(keys["receipt"]), keyring=keys["ring"])
    assert outcome.receipt is not None, (outcome.code, outcome.detail)
    return result, card, outcome.receipt


def _float_free(value) -> bool:
    if isinstance(value, float):
        return False
    if isinstance(value, dict):
        return all(_float_free(v) for v in value.values())
    if isinstance(value, list):
        return all(_float_free(v) for v in value)
    return True


# ======================================================================
# The card
# ======================================================================


def test_every_owner_field_is_on_the_card(deployment, people):
    result, card = carded(deployment, people)
    body = card.card
    assert tuple(body["fields"]) == OWNER_FIELDS
    for name in ENTITY_FIELDS:
        assert name in body, name
    assert body["scenario_id"] == str(FinancialScenario.objects.get(pk=result.scenario_id).uuid)
    assert body["confidence_grade"] == card.confidence_grade == body["fields"]["confidence_grade"]["grade"]
    assert body["fields"]["confidence_grade"]["reason"].startswith(card.confidence_grade)
    assert card.grade_version_digest == g.version_digest() == body["fields"]["confidence_grade"]["version_digest"]
    assert card.card_digest == card_digest(body) == core.card_digest_of(body)
    assert _float_free(body) and _float_free(card.sensitivity)
    fields = body["fields"]
    assert "Cross-customer exposure" in fields["scenario"]["description"]
    assert "cross_customer_disclosure on customer_service" in fields["scenario"]["description"]
    assert fields["most_sensitive_variables"]["variables"][0]["name"] == card.sensitivity["ranked"][0]["name"]
    assert len(fields["most_sensitive_variables"]["variables"]) <= validity_service.TOP_DRIVERS
    assert fields["technical_evidence"]["hypothetical_effects"][0]["effect_key"] == "exposure"
    (finding,) = fields["technical_evidence"]["findings"]
    assert finding["role"] == "prerequisite" and finding["status_at_issue"]["severity"] == "high"
    assert body["reviewer_status"]["status"] == "draft"


def test_the_card_invents_no_value_and_says_what_has_no_data(deployment, people):
    result, card = carded(deployment, people)
    fields = card.card["fields"]
    record = result.record
    headline = record["scenario"][record["scenario"]["headline"]]
    for name in ("p10", "p50", "p90", "mean", "expected_annual_exposure", "severe_plausible"):
        assert fields["figures"][name] == headline[name]
    assert fields["figures"]["reporting_currency"] == "USD" and fields["figures"]["basis"] == ss.ANNUAL_BASIS
    assert fields["last_calibrated"] == {"date": None, "calibration_set": None,
                                         "statement": "never; no calibration set exists"}
    assert card.card["calibration_date"] is None
    assert fields["system_fingerprint"]["value"] == FINGERPRINT and fields["system_fingerprint"]["binding"] == "scenario"
    assert fields["model_version"]["inventory"]["entry"] is None
    assert "no model inventory entry" in fields["model_version"]["inventory"]["statement"]
    assert fields["model_version"]["release"]["engine"] == result.versions
    assert fields["model_version"]["build_digest"] == canonical_digest(fields["model_version"]["release"])
    reproduction = fields["reproduction"]
    assert (reproduction["seed"], reproduction["draws"], reproduction["input_digest"], reproduction["result_digest"],
            reproduction["outcomes_sha256"]) == (result.seed, result.draws, result.input_digest, result.result_digest,
                                                 record["outcomes_sha256"])
    assert reproduction["sensitivity_digest"] == card.sensitivity_digest
    # The shares are the grade's evidence mix, weighed by each figure's share of the level.
    mix = card.card["evidence_mix"]
    assert fields["customer_specific_share"]["share"] == mix["customer"]
    assert fields["benchmark_derived_share"]["share"] == mix["benchmark"]
    assert Decimal(fields["expert_estimated_share"]["share"]) == Decimal(mix["expert"]) + Decimal(mix["unsourced"])
    # Every customer figure the gross reads is listed with its level share, the
    # parameter set's fixed figures as much as the regulatory range (review round 1,
    # H1), and its importance beside it: a fixed figure has none.
    entries = {e["name"]: e for e in fields["customer_specific_share"]["parameters"]}
    assert set(entries) == {"exposure.regulatory_response_cost", "notification_fixed_cost", "notification_unit_cost"}
    assert all(Decimal(e["level_share"]) > 0 for e in entries.values())
    assert Decimal(entries["notification_fixed_cost"]["importance"]) == 0
    total = sum(Decimal(e["level_share"]) for e in entries.values())
    assert abs(total - Decimal(mix["customer"])) < Decimal("0.000001")
    # The parameter set's point masses are fixed, and the analysis says so.
    assert {f["name"] for f in card.sensitivity["fixed"]} >= {"notification_fixed_cost", "notification_unit_cost"}


def test_a_scenario_with_no_fingerprint_says_so(deployment, people, monkeypatch):
    import assurance.fingerprint as fingerprint

    def unreadable(_deployment):
        raise RuntimeError("the asset graph could not be read")

    monkeypatch.setattr(fingerprint, "compute_system_fingerprint", unreadable)
    _, card = carded(deployment, people, fingerprint="")
    field = card.card["fields"]["system_fingerprint"]
    assert field["value"] is None and field["binding"] is None
    assert field["statement"].startswith("unavailable") and "could not be read" in field["statement"]


def test_a_scenario_with_no_fingerprint_reads_the_deployments_at_issue(deployment, people):
    from assurance.fingerprint import compute_system_fingerprint

    _, card = carded(deployment, people, fingerprint="")
    field = card.card["fields"]["system_fingerprint"]
    assert field["binding"] == "deployment_at_issue"
    assert field["value"] == compute_system_fingerprint(Deployment.objects.get(pk=deployment.pk))
    assert "not when the scenario was built" in field["statement"]


def test_the_card_is_reproducible_from_the_stored_result(deployment, people):
    result, card = carded(deployment, people)
    assert validity_service.reproduces(card)
    again = validity_service.build_card(SimulationResult.objects.get(pk=result.pk), sensitivity=card.sensitivity,
                                        issued=card.card["issued"])
    assert card_digest(again) == card.card_digest
    # The analysis is the run's own: made again, it is the stored one.
    si = simulation_service.load_input(FinancialScenario.objects.get(pk=result.scenario_id))
    made_again = sens.analyse(si, seed=int(result.seed), draws=result.draws, severe_percentile=Decimal(95),
                              input_digest=result.input_digest, outcomes_sha256=result.record["outcomes_sha256"])
    assert made_again == card.sensitivity


def test_a_card_is_recorded_once_and_never_rewritten(deployment, people):
    result, card = carded(deployment, people)
    again = validity_service.issue_card(result)
    assert again.card.pk == card.pk and again.created is False
    assert FinancialValidityCard.objects.count() == 1
    with pytest.raises(EconomicsRewriteRefused):
        card.save()
    with pytest.raises(EconomicsRewriteRefused):
        FinancialValidityCard.objects.filter(pk=card.pk).update(confidence_grade="A")
    twin = FinancialValidityCard(
        deployment=deployment, scenario_id=result.scenario_id, simulation=result, schema=card.schema,
        confidence_grade=card.confidence_grade, grade_version_digest=card.grade_version_digest, card=card.card,
        card_digest=card.card_digest, sensitivity=card.sensitivity, sensitivity_digest=card.sensitivity_digest,
        issued_at=card.issued_at,
    )
    with pytest.raises(EconomicsRefused) as refused:
        twin.save()
    assert refused.value.code == "duplicate_id"


def test_a_card_whose_digest_or_grade_is_not_its_own_is_refused(deployment, people):
    result, card = carded(deployment, people)
    other = simulated(FinancialScenario.objects.get(pk=result.scenario_id), seed=8)
    base = {
        "deployment": deployment, "scenario_id": result.scenario_id, "simulation": other, "schema": card.schema,
        "grade_version_digest": card.grade_version_digest, "sensitivity": card.sensitivity,
        "sensitivity_digest": card.sensitivity_digest, "issued_at": card.issued_at,
    }
    for change in (
        {"card": card.card, "card_digest": "sha256:" + "0" * 64, "confidence_grade": card.confidence_grade},
        {"card": card.card, "card_digest": card.card_digest, "confidence_grade": "A" if card.confidence_grade != "A" else "B"},
        {"card": {**card.card, "x": 0.5}, "card_digest": card_digest({**card.card, "x": 0.5}),
         "confidence_grade": card.confidence_grade},
    ):
        with pytest.raises(EconomicsRefused) as refused:
            FinancialValidityCard(**base, **change).save()
        assert refused.value.code == "card_record_malformed"


def test_a_refused_run_is_carded_unknown(deployment, people):
    # A customer's range with no distribution of its own: refused by the rule.
    other = FinancialScenario.objects.create(deployment=deployment, title="Refused", author=people["analyst"],
                                             system_fingerprint=FINGERPRINT)
    amount = _parameter(other, "x.amount", "money", "1000", "2000", "4000", source="CUSTOMER_PROVIDED")
    event = LossEvent.objects.create(scenario=other, event_key="ev-x", currency="USD")
    LossComponent.objects.create(loss_event=event, component_key="x", family="legal", formula_id="lump_sum",
                                 formula_version=1, as_of=AS_OF, cited_parameters={"amount": str(amount.uuid)})
    outcome = simulation_service.simulate_scenario(other, seed=1, draws=1_000)
    assert outcome.result.status == "refused" and outcome.code == "no_admissible_distribution"
    card = validity_service.issue_card(outcome.result).card
    assert card.confidence_grade == "Unknown" and card.sensitivity is None and card.sensitivity_digest == ""
    fields = card.card["fields"]
    assert "refused (no_admissible_distribution)" in fields["confidence_grade"]["reason"]
    assert fields["figures"]["unavailable"].startswith("the run was refused")
    assert fields["most_sensitive_variables"]["unavailable"]
    assert fields["unknown_variables"]["refusal"]["code"] == "no_admissible_distribution"
    assert validity_service.reproduces(card)
    # And no receipt: a refused run has no figures to sign.
    key = Ed25519PrivateKey.generate()
    receipt = receipt_service.issue_receipt(outcome.result, signer=_signer(key),
                                            keyring=core.receipt_keyring([_raw(key)], other_roles={}))
    assert receipt.receipt is None and receipt.code == "result_not_completed"


def test_a_stale_figure_lowers_the_grade_one_step(deployment, people):
    _, fresh = carded(deployment, people)
    other = Deployment.objects.create(name="second", owner=people["owner"])
    _, stale = carded(other, people, stale=True)
    assert "exposure.regulatory_response_cost" in stale.card["fields"]["data_freshness"]["stale"]
    stale_grade = stale.card["fields"]["confidence_grade"]
    assert g.STALE in [d["rule"] for d in stale_grade["downgrades"]]
    assert fresh.card["fields"]["data_freshness"]["stale"] == []
    ladder = ["A", "B", "C", "D"]
    expected = ladder[min(ladder.index(fresh.confidence_grade) + 1, 3)]
    assert stale.confidence_grade == expected


def test_draws_that_do_not_reproduce_record_no_card(deployment, people):
    result = simulated(stored(deployment, people["analyst"]))
    record = dict(result.record, outcomes_sha256="sha256:" + "1" * 64)
    # Moved past the append-only checks, as a different platform's draws would differ.
    SimulationResult._base_manager.filter(pk=result.pk).update(record=record)
    outcome = validity_service.issue_card(SimulationResult.objects.get(pk=result.pk))
    assert outcome.card is None and outcome.code == "result_not_reproduced"
    assert not FinancialValidityCard.objects.exists()


# ======================================================================
# The receipt
# ======================================================================


def test_a_receipt_is_signed_then_verified(deployment, people, keys):
    result, card, receipt = receipted(deployment, people, keys)
    check = receipt_service.verify_stored_receipt(receipt, keys["ring"])
    assert check.verified and check.code == core.AUTHENTIC, check
    document = receipt.document
    assert document["schema"] == core.RECEIPT_SCHEMA
    # It covers the card: the card's digest and grade.
    assert document["validity_card"] == {"digest": card.card_digest, "confidence_grade": card.confidence_grade}
    assert document["scenario_id"] == card.card["scenario_id"]
    assert document["tenant_id"] == str(deployment.uuid)
    assert document["system_fingerprint"] == FINGERPRINT
    assert document["simulation"] == {"seed": 7, "draws": DRAWS, "parameter_set_digest": result.input_digest}
    release = validity_service.model_release(result.versions)
    assert document["model"] == {"version": release["version"], "build_digest": release["build_digest"]}
    assert [s["snapshot_id"].split(":")[0] for s in document["sources"]] == [
        "parameter-set", "scenario-build", "scenario-parameters"]
    assert document["evidence"]["nodes"] and document["evidence"]["claims"] == []
    headline = result.record["scenario"][result.record["scenario"]["headline"]]
    assert Decimal(document["result"]["p50"]["amount"]) == Decimal(headline["p50"]).quantize(Decimal("0.01"))
    assert receipt.key_id == receipt.envelope["signatures"][0]["keyid"]


def test_a_receipt_is_recorded_once_per_result(deployment, people, keys):
    result, _, receipt = receipted(deployment, people, keys)
    calls = []
    again = receipt_service.issue_receipt(result, signer=_signer(keys["receipt"], calls), keyring=keys["ring"])
    assert again.receipt.pk == receipt.pk and again.created is False and calls == []
    assert FinancialExposureReceipt.objects.count() == 1
    with pytest.raises(EconomicsRewriteRefused):
        receipt.save()
    with pytest.raises(EconomicsRewriteRefused):
        FinancialExposureReceipt.objects.filter(pk=receipt.pk).delete()


def test_a_tampered_card_is_refused(deployment, people, keys):
    _, card, receipt = receipted(deployment, people, keys)
    changed = dict(card.card, confidence_grade="A")
    FinancialValidityCard._base_manager.filter(pk=card.pk).update(card=changed)
    check = receipt_service.verify_stored_receipt(FinancialExposureReceipt.objects.get(pk=receipt.pk), keys["ring"])
    assert not check.verified and check.code == core.CARD_DIGEST_MISMATCH


def test_a_tampered_result_is_refused(deployment, people, keys):
    result, _, receipt = receipted(deployment, people, keys)
    record = json.loads(json.dumps(result.record))
    line = record["scenario"]["headline"]
    record["scenario"][line]["p50"] = "1"
    SimulationResult._base_manager.filter(pk=result.pk).update(record=record)
    check = receipt_service.verify_stored_receipt(receipt, keys["ring"])
    assert not check.verified and check.code == "result_digest_mismatch"
    # Its digest moved with it: the card and the receipt still name the old one.
    SimulationResult._base_manager.filter(pk=result.pk).update(
        result_digest="sha256:" + hashlib.sha256(json.dumps(record, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    )
    check = receipt_service.verify_stored_receipt(receipt, keys["ring"])
    assert not check.verified and check.code == "result_mismatch"


def test_a_tampered_source_snapshot_is_refused(deployment, people, keys):
    result, _, receipt = receipted(deployment, people, keys)
    scenario = FinancialScenario.objects.get(pk=result.scenario_id)
    pset = ScenarioBuild.objects.get(scenario=scenario).parameter_set
    row = FinancialParameter.objects.get(parameter_set=pset, name="notification_unit_cost")
    FinancialParameter._base_manager.filter(pk=row.pk).update(low="3", base="3", high="3")
    check = receipt_service.verify_stored_receipt(receipt, keys["ring"])
    assert not check.verified and check.code == "source_snapshot_mismatch"


def test_a_tampered_scenario_parameter_is_refused(deployment, people, keys):
    result, _, receipt = receipted(deployment, people, keys)
    row = FinancialParameter.objects.get(scenario_id=result.scenario_id, name="exposure.affected_customers")
    FinancialParameter._base_manager.filter(pk=row.pk).update(high="999999")
    check = receipt_service.verify_stored_receipt(receipt, keys["ring"])
    assert not check.verified and check.code == "source_snapshot_mismatch"


def test_a_tampered_signature_is_refused(deployment, people, keys):
    _, _, receipt = receipted(deployment, people, keys)
    envelope = json.loads(json.dumps(receipt.envelope))
    envelope["signatures"][0]["sig"] = base64.b64encode(keys["receipt"].sign(b"something else")).decode("ascii")
    FinancialExposureReceipt._base_manager.filter(pk=receipt.pk).update(envelope=envelope)
    check = receipt_service.verify_stored_receipt(FinancialExposureReceipt.objects.get(pk=receipt.pk), keys["ring"])
    assert not check.verified and check.code == core.FORGED


def test_a_tampered_document_is_refused(deployment, people, keys):
    _, _, receipt = receipted(deployment, people, keys)
    document = json.loads(json.dumps(receipt.document))
    document["system_fingerprint"] = "cd" * 32
    FinancialExposureReceipt._base_manager.filter(pk=receipt.pk).update(document=document)
    check = receipt_service.verify_stored_receipt(FinancialExposureReceipt.objects.get(pk=receipt.pk), keys["ring"])
    assert not check.verified and check.code == "receipt_mismatch"


def test_a_wrong_key_is_refused(deployment, people, keys):
    _, _, receipt = receipted(deployment, people, keys)
    stranger = core.receipt_keyring([_raw(keys["stranger"])], other_roles={})
    assert receipt_service.verify_stored_receipt(receipt, stranger).code == core.UNKNOWN_KEY
    # The signing key filed under another role is refused before the signature.
    wrong_role = core.receipt_keyring([_raw(keys["stranger"])], other_roles={"engine-outcome": [_raw(keys["receipt"])]})
    assert receipt_service.verify_stored_receipt(receipt, wrong_role).code == core.WRONG_ROLE
    # A plain mapping is not a receipt keyring.
    assert receipt_service.verify_stored_receipt(receipt, {}).code == core.UNKNOWN_KEY


def test_a_receipt_signed_by_the_wrong_key_is_never_recorded(deployment, people, keys):
    result, _ = carded(deployment, people)
    outcome = receipt_service.issue_receipt(result, signer=_signer(keys["stranger"]), keyring=keys["ring"])
    assert outcome.receipt is None and outcome.code == core.UNKNOWN_KEY
    assert not FinancialExposureReceipt.objects.exists()


def test_the_engine_signs_on_the_assurance_receipts_path(deployment, people, keys, monkeypatch):
    from ai_engine.services.cyberengine_client import CyberEngineClient, EngineError

    result, _ = carded(deployment, people)
    sent = []

    class Engine:
        def sign_exposure_receipt(self, document):
            sent.append(document)
            return core.sign_receipt(document, keys["receipt"])

    class Down:
        def sign_exposure_receipt(self, document):
            raise EngineError("Engine refused (404)")

    monkeypatch.setattr(CyberEngineClient, "from_settings", classmethod(lambda cls: Down()))
    outcome = receipt_service.issue_receipt(result, keyring=keys["ring"])
    assert outcome.receipt is None and outcome.code == "signer_unavailable"
    assert not FinancialExposureReceipt.objects.exists()
    monkeypatch.setattr(CyberEngineClient, "from_settings", classmethod(lambda cls: Engine()))
    outcome = receipt_service.issue_receipt(result, keyring=keys["ring"])
    assert outcome.created and len(sent) == 1 and outcome.receipt.document == sent[0]
    assert receipt_service.verify_stored_receipt(outcome.receipt, keys["ring"]).verified


def test_an_envelope_over_another_document_is_never_recorded(deployment, people, keys):
    result, _ = carded(deployment, people)

    def swapped(document):
        return core.sign_receipt(dict(document, receipt_id=uuid.uuid4().hex), keys["receipt"])

    outcome = receipt_service.issue_receipt(result, signer=swapped, keyring=keys["ring"])
    assert outcome.receipt is None and outcome.code == "envelope_not_over_receipt"


def test_a_receipt_needs_every_figure_and_a_fingerprint(deployment, people, keys, monkeypatch):
    # No frequency: no expected annual exposure, which is never estimated.
    result, card = carded(deployment, people, frequency=False)
    assert card.card["fields"]["figures"]["expected_annual_exposure"] is None
    outcome = receipt_service.issue_receipt(result, signer=_signer(keys["receipt"]), keyring=keys["ring"])
    assert outcome.receipt is None and outcome.code == "receipt_figure_unavailable"
    assert "expected_annual_exposure" in outcome.detail
    # No fingerprint at all: nothing to bind.
    import assurance.fingerprint as fingerprint

    def unreadable(_deployment):
        raise RuntimeError("the asset graph could not be read")

    monkeypatch.setattr(fingerprint, "compute_system_fingerprint", unreadable)
    other = Deployment.objects.create(name="second", owner=people["owner"])
    result, _ = carded(other, people, fingerprint="")
    outcome = receipt_service.issue_receipt(result, signer=_signer(keys["receipt"]), keyring=keys["ring"])
    assert outcome.receipt is None and outcome.code == "system_fingerprint_unavailable"
    assert not FinancialExposureReceipt.objects.exists()


# ======================================================================
# The records' discipline, and the stops
# ======================================================================


def test_the_new_records_are_append_only_with_no_reverse_accessor(deployment, people, keys):
    from django.db import models

    _, card, receipt = receipted(deployment, people, keys)
    for row in (card, receipt):
        model = type(row)
        with pytest.raises(EconomicsRewriteRefused):
            row.delete()
        with pytest.raises(EconomicsRewriteRefused):
            model.objects.filter(pk=row.pk).update(uuid=row.uuid)
        with pytest.raises(EconomicsRefused) as refused:
            model.objects.bulk_create([model()])
        assert refused.value.code == "bulk_create_refused"
        assert model._meta.base_manager_name is None and type(model._base_manager) is models.Manager
        for field in model._meta.get_fields():
            if (field.many_to_one or field.one_to_one) and field.concrete:
                assert field.remote_field.related_name == "+", (model.__name__, field.name)
        # No account column: removing an operator, a stop, never writes it.
        assert not [f for f in model._meta.concrete_fields if f.is_relation and f.related_model is User]


def test_the_records_go_with_their_deployment_and_never_hold_back_a_stop(deployment, people, keys):
    receipted(deployment, people, keys)
    client = APIClient()
    client.force_authenticate(user=people["admin"])
    response = client.delete(f"/api/accounts/users/{people['analyst'].pk}/")
    assert response.status_code == 204, response.content
    assert FinancialValidityCard.objects.count() == FinancialExposureReceipt.objects.count() == 1
    deployment.delete()
    assert not FinancialValidityCard.objects.exists() and not FinancialExposureReceipt.objects.exists()


# ======================================================================
# Review round 1
# ======================================================================


def custom(deployment, author, *, variables, components, frequency_source=None, set_key="probe_set"):
    """A scenario version of one event whose components are given as (key, family,
    formula, {input: a scenario parameter row, or a parameter-set variable's name}),
    with one hypothetical effect, its finding and its build. SYNTHETIC / ILLUSTRATIVE."""
    pset = CustomerParameterSet.record(deployment, set_key, {"variables": variables}, author=author)
    scenario = FinancialScenario.objects.create(deployment=deployment, title="Probe", author=author,
                                                system_fingerprint=FINGERPRINT)
    rows = {row.name: row for row in pset.parameter_rows()}
    if frequency_source:
        _parameter(scenario, ss.FREQUENCY_PARAMETER, "count", "1", "2", "4", source=frequency_source,
                   distribution=POISSON)
    event = LossEvent.objects.create(scenario=scenario, event_key="ev-probe", currency="USD", trigger="probe",
                                     business_process="payments")
    for key, family, formula, cites in components(scenario):
        cited = {name: str((rows[p] if isinstance(p, str) else p).uuid) for name, p in cites.items()}
        LossComponent.objects.create(loss_event=event, component_key=key, family=family, formula_id=formula,
                                     formula_version=1, as_of=AS_OF, cited_parameters=cited)
    asset = Asset.objects.create(deployment=deployment, kind="agent", name="probe-agent",
                                 identifier=f"agent://probe-{uuid.uuid4().hex[:6]}")
    finding = Finding.objects.create(deployment=deployment, fingerprint=f"fp-{uuid.uuid4().hex[:8]}",
                                     finding_type="tenant_isolation_missing", title="probe", severity="high")
    effect = CausalEffect.objects.create(
        scenario=scenario, loss_event=event, effect_key="probe", origin="hypothetical",
        effect_type="cross_customer_disclosure", asset=str(asset.uuid), business_process="payments",
        template_id="cross_customer_data_exposure", template_version=1, in_scope_of=[["cross_customer_data_exposure", 1]],
    )
    EffectFinding.objects.create(effect=effect, finding=str(finding.uuid), role="prerequisite")
    inputs = {"fixture": str(scenario.uuid), "label": LABEL}
    ScenarioBuild.objects.create(
        scenario=scenario, deployment=deployment, parameter_set=pset, build_digest=builder.build_digest(inputs),
        builder_version="test-fixture", grouping_version="test-fixture", pack="test-fixture", currency="USD",
        as_of=AS_OF, inputs=inputs,
    )
    return scenario


def card_of(scenario, draws=DRAWS):
    result = simulated(scenario, draws=draws)
    assert result.status == "completed", (result.refusal_code, result.refusal_detail)
    issued = validity_service.issue_card(result)
    assert issued.card is not None, (issued.code, issued.detail)
    return result, issued.card


def _fine_and_cost(low, base, high):
    def components(scenario):
        fine = _parameter(scenario, "probe.regulatory_fine", "money", low, base, high, source="EXPERT_ESTIMATE")
        cost = _parameter(scenario, "probe.response_cost", "money", "0", "100000", "500000",
                          source="CUSTOMER_PROVIDED", distribution=GAMMA)
        return [("fine", "regulatory_compliance", "lump_sum", {"amount": fine}),
                ("response", "legal", "lump_sum", {"amount": cost})]

    return components


VARIABLES = {"notification_unit_cost": _entry("money_per_unit", "2")}
LADDER = ("A", "B", "C", "D")


@pytest.mark.parametrize("frequency_source", [None, "CUSTOMER_PROVIDED"])
def test_an_expert_fine_stated_as_one_figure_grades_no_higher_than_as_a_range(people, frequency_source):
    """H1, the reviewer's cases: the fine as a range of 4M-6M and as the one figure
    5M, everything else the same (with and without a customer frequency): the fixed
    figure carries its share of the level, so the grade is D both ways, never A."""
    grades = {}
    for tag, figures in (("range", ("4000000", "5000000", "6000000")), ("point", ("5000000",) * 3)):
        deployment = Deployment.objects.create(name=f"dep-{tag}", owner=people["owner"])
        _, card = card_of(custom(deployment, people["analyst"], variables=VARIABLES,
                                 components=_fine_and_cost(*figures), frequency_source=frequency_source))
        grades[tag] = card.confidence_grade
        mix = card.card["evidence_mix"]
        assert Decimal(mix["expert"]) > Decimal("0.45"), mix
        assert g.EXPERT in [d["rule"] for d in card.card["fields"]["confidence_grade"]["downgrades"]]
    assert grades == {"range": "D", "point": "D"}
    assert LADDER.index(grades["point"]) >= LADDER.index(grades["range"])


def test_twenty_customer_dollars_and_an_expert_fine_never_grade_a(deployment, people):
    """H1, the reviewer's third case: nothing uncertain, twenty customer figures of
    $1 and one expert figure of $5,000,000. Weighed by level, not by count: D."""

    def components(scenario):
        out = [("fine", "regulatory_compliance", "lump_sum",
                {"amount": _parameter(scenario, "probe.fine", "money", "5000000", source="EXPERT_ESTIMATE")})]
        for i in range(20):
            out.append((f"c{i:02d}", "legal", "lump_sum",
                        {"amount": _parameter(scenario, f"probe.c{i:02d}", "money", "1", source="CUSTOMER_PROVIDED")}))
        return out

    _, card = card_of(custom(deployment, people["analyst"], variables=VARIABLES, components=components))
    graded_ = card.card["fields"]["confidence_grade"]
    assert card.confidence_grade == "D" and graded_["weighting"] == "level"
    assert Decimal(card.card["evidence_mix"]["expert"]) > Decimal("0.9999")
    assert graded_["material_expert_figures"] == ["probe.fine"]


def test_every_figure_is_evaluated_for_freshness_and_a_stale_policy_term_lowers_the_grade(deployment, people):
    """M3: the policy's limit is past its fresh_until at the run's as-of; a set
    variable no component reads is stale too. Both are evaluated and said stale;
    the policy term lowers the grade (the run applies the policy), the unread
    variable is shown and does not. No figure reads stale: false unevaluated."""

    def components(scenario):
        cost = _parameter(scenario, "probe.response_cost", "money", "0", "100000", "500000",
                          source="CUSTOMER_PROVIDED", distribution=GAMMA)
        return [("response", "legal", "lump_sum", {"amount": cost})]

    variables = {
        "notification_unit_cost": _entry("money_per_unit", "2", fresh_until="2026-10-01"),
        "insurance_deductible": _entry("money", "10000"),
        "insurance_limit": _entry("money", "50000", fresh_until="2026-10-01"),
    }
    result, card = card_of(custom(deployment, people["analyst"], variables=variables, components=components,
                                  frequency_source="CUSTOMER_PROVIDED"))
    assert result.record["scenario"]["headline"] == "retained_cash"
    freshness = card.card["fields"]["data_freshness"]
    rows = {row["name"]: row for row in freshness["parameters"]}
    assert rows["insurance_limit"]["stale"] is True and rows["insurance_limit"]["read_by"] == ["policy"]
    assert rows["insurance_limit"]["counts_toward_grade"] is True
    assert rows["notification_unit_cost"]["stale"] is True and rows["notification_unit_cost"]["counts_toward_grade"] is False
    assert freshness["stale"] == ["insurance_limit"] and freshness["stale_not_graded"] == ["notification_unit_cost"]
    assert all(row["evaluated"] is True and isinstance(row["stale"], bool) for row in rows.values())
    assert set(rows) >= {"insurance_deductible", "insurance_limit", "notification_unit_cost", "probe.response_cost",
                         ss.FREQUENCY_PARAMETER}
    assert g.STALE in [d["rule"] for d in card.card["fields"]["confidence_grade"]["downgrades"]]


def test_a_stale_derived_contributor_lowers_the_grade(deployment, people):
    """M3: a contributor of a derived value is drawn in every year, though the
    derived row's own dates are its suppliers'; a stale one counts."""

    def components(scenario):
        e1 = _parameter(scenario, "e1.amount", "money", "100000", "200000", "300000")
        e2 = _parameter(scenario, "e2.amount", "money", "150000", fresh_until=date(2026, 9, 15))
        merged = FinancialParameter.objects.create(
            scenario=scenario, name="ev:amount", unit="money", source_type="CALCULATED", currency="USD",
            low="150000", base="200000", high="300000", evidence_ref=f"{LABEL}: the larger loss",
            effective_date=date(2026, 9, 1), derived_from=[str(e1.uuid), str(e2.uuid)],
        )
        return [("lump", "legal", "lump_sum", {"amount": merged})]

    _, card = card_of(custom(deployment, people["analyst"], variables=VARIABLES, components=components,
                             frequency_source="CUSTOMER_PROVIDED"))
    rows = {row["name"]: row for row in card.card["fields"]["data_freshness"]["parameters"]}
    assert rows["e2.amount"]["stale"] is True and rows["e2.amount"]["read_by"] == ["contributor"]
    assert card.card["fields"]["data_freshness"]["stale"] == ["e2.amount"]


def test_a_card_with_no_as_of_says_its_figures_were_not_evaluated(deployment, people):
    """M3: a run with no event has no as-of; nothing is said fresh."""
    scenario = FinancialScenario.objects.create(deployment=deployment, title="Empty", author=people["analyst"])
    _parameter(scenario, "x.amount", "money", "1000")
    outcome = simulation_service.simulate_scenario(scenario, seed=1, draws=1_000)
    assert outcome.result.status == "refused"
    card = validity_service.issue_card(outcome.result).card
    freshness = card.card["fields"]["data_freshness"]
    assert freshness["as_of"] is None and freshness["statement"].startswith("not evaluated")
    assert all(row["evaluated"] is False and row["stale"] is None for row in freshness["parameters"])


def test_no_keyring_records_nothing_and_returns_nothing(deployment, people, keys):
    """M2: without the published economics-receipt keys nothing is recorded, and a
    recorded receipt is not returned either."""
    result, _ = carded(deployment, people)
    for keyring in (None, {}, [_raw(keys["receipt"])]):
        outcome = receipt_service.issue_receipt(result, signer=_signer(keys["receipt"]), keyring=keyring)
        assert outcome.receipt is None and outcome.code == "keyring_unavailable"
    assert not FinancialExposureReceipt.objects.exists()
    receipt_service.issue_receipt(result, signer=_signer(keys["receipt"]), keyring=keys["ring"])
    again = receipt_service.issue_receipt(result, signer=_signer(keys["receipt"]))
    assert again.receipt is None and again.code == "keyring_unavailable"


def test_a_signature_that_does_not_verify_is_never_recorded(deployment, people, keys):
    """M2: the reviewer's wrong-role signer and a signature that is the integer
    12345: refused by core's verifier before the row, nothing recorded; the row's
    own check refuses the malformed signature too."""
    result, card = carded(deployment, people)
    wrong = receipt_service.issue_receipt(result, signer=_signer(keys["other"]), keyring=keys["ring"])
    assert wrong.receipt is None and wrong.code == core.WRONG_ROLE

    def junk(document):
        envelope = core.sign_receipt(document, keys["receipt"])
        envelope["signatures"][0]["sig"] = 12345
        return envelope

    outcome = receipt_service.issue_receipt(result, signer=junk, keyring=keys["ring"])
    assert outcome.receipt is None and outcome.code == core.ENVELOPE_MALFORMED
    assert not FinancialExposureReceipt.objects.exists()
    # The row's own check, past the service: core's signature form.
    good = receipt_service.issue_receipt(result, signer=_signer(keys["receipt"]), keyring=keys["ring"]).receipt
    # 12345; 87 characters; 88 characters of base64 that decode to 66 bytes, not 64.
    for sig in (12345, "A" * 87, base64.b64encode(b"x" * 66).decode("ascii")):
        envelope = json.loads(json.dumps(good.envelope))
        envelope["signatures"][0]["sig"] = sig
        twin = FinancialExposureReceipt(
            deployment=deployment, scenario_id=result.scenario_id, simulation=result, card=card,
            receipt_id=good.receipt_id, document=good.document, envelope=envelope, key_id=good.key_id,
            generated_at=good.generated_at,
        )
        with pytest.raises(EconomicsRefused) as refused:
            twin.check_new()
        assert refused.value.code == "receipt_record_malformed", sig


def test_a_recorded_receipt_that_does_not_verify_is_not_returned_or_overwritten(deployment, people, keys):
    """M2: a stored row that fails verification (here its signature, moved past the
    append-only checks) is never returned as the result's receipt, and a valid
    issue never overwrites it: the caller is told why."""
    result, _, receipt = receipted(deployment, people, keys)
    envelope = json.loads(json.dumps(receipt.envelope))
    envelope["signatures"][0]["sig"] = base64.b64encode(keys["receipt"].sign(b"another")).decode("ascii")
    FinancialExposureReceipt._base_manager.filter(pk=receipt.pk).update(envelope=envelope)
    outcome = receipt_service.issue_receipt(result, signer=_signer(keys["receipt"]), keyring=keys["ring"])
    assert outcome.receipt is None and outcome.code == "recorded_receipt_unverified"
    assert outcome.detail.startswith(core.FORGED)
    assert FinancialExposureReceipt.objects.get().envelope == envelope


def _keyring_document(*entries):
    """A keyring in the engine's published form (``engine.evidence.keyring``)."""
    return {"version": 1, "keys": {
        f"k{i}": {"public_key": base64.b64encode(_raw(key)).decode(), "status": status, "created_at": None,
                  "retired_at": None, "reason": None}
        for i, (key, status) in enumerate(entries)}}


def test_the_keyring_is_built_from_the_engines_published_keys(deployment, people, keys):
    """M2, and athena-engine #88's published keyring: ``keys`` are the artifact
    role's, ``roles["economics-receipt"]`` the receipt role's. A retired receipt key
    still verifies; a revoked one verifies nothing; a receipt the artifact key signed
    is refused as wrong_role; a keyring with no economics-receipt role is no keyring."""
    result, card, receipt = receipted(deployment, people, keys)
    published = {**_keyring_document((keys["other"], "active")),
                 "roles": {"economics-receipt": _keyring_document((keys["receipt"], "retired"))},
                 "caveat": "a retired key still verifies receipts it signed"}
    ring = receipt_service.keyring_from_published(published)
    assert sorted(ring.roles().values()) == ["artifact", "economics-receipt"]
    assert receipt_service.verify_stored_receipt(receipt, ring).verified
    revoked = receipt_service.keyring_from_published(
        {**published, "roles": {"economics-receipt": _keyring_document((keys["receipt"], "revoked"))}})
    assert receipt_service.verify_stored_receipt(receipt, revoked).code == core.UNKNOWN_KEY
    artifact_signed = core.sign_receipt(receipt.document, keys["other"])
    assert core.verify_receipt(artifact_signed, ring, card=card.card).verdict == core.WRONG_ROLE
    with pytest.raises(ValueError):
        receipt_service.keyring_from_published(_keyring_document((keys["receipt"], "active")))


def _http(status, body):
    import requests

    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode()
    response.headers["Content-Type"] = "application/json"
    return response


def test_a_document_the_engine_refuses_is_refused_by_the_signer_not_unavailable(deployment, people, keys, monkeypatch):
    """The #88 reviewer: an engine 400 whose detail is core's code is the signer
    refusing the DOCUMENT -- `receipt_refused_by_signer`, carrying core's code --
    never `signer_unavailable`, and nothing is recorded. A 503, a connection failure,
    and a 400 that names no code stay `signer_unavailable`."""
    import requests

    from ai_engine.services.cyberengine_client import CyberEngineClient
    from safety import outbound

    result, _ = carded(deployment, people)
    answers = []

    def engine(url, **_kwargs):
        assert url == "https://engine.test/api/economics/exposure-receipt/sign"
        answer = answers.pop(0)
        if isinstance(answer, Exception):
            raise answer
        return answer

    monkeypatch.setattr(outbound, "post", engine)
    monkeypatch.setattr(CyberEngineClient, "from_settings",
                        classmethod(lambda cls: CyberEngineClient("https://engine.test", "operator-key")))
    answers.append(_http(400, {"detail": {"code": "amount_precision", "reason": "result.p50.amount has 3 digits"}}))
    outcome = receipt_service.issue_receipt(result, keyring=keys["ring"])
    assert outcome.receipt is None and outcome.code == "receipt_refused_by_signer"
    assert outcome.signer_code == "amount_precision" and outcome.detail.startswith("amount_precision: result.p50")
    for answer in (
        _http(503, {"detail": {"code": "signer_not_configured", "reason": "set ENGINE_ECONOMICS_RECEIPT_KEY"}}),
        requests.ConnectionError("the engine is not reachable"),
        requests.Timeout("the engine did not answer in time"),
        _http(400, {"detail": "something else"}),
    ):
        answers.append(answer)
        outcome = receipt_service.issue_receipt(result, keyring=keys["ring"])
        assert outcome.receipt is None and outcome.code == "signer_unavailable" and outcome.signer_code is None, answer
    assert not FinancialExposureReceipt.objects.exists()


def test_tampered_result_inputs_are_refused(deployment, people, keys):
    """M4: the run's stored inputs no longer give its input digest."""
    result, _, receipt = receipted(deployment, people, keys)
    inputs = json.loads(json.dumps(result.inputs))
    inputs["parameters"]["exposure.affected_customers"]["base"] = "9999999"
    SimulationResult._base_manager.filter(pk=result.pk).update(inputs=inputs)
    check = receipt_service.verify_stored_receipt(receipt, keys["ring"])
    assert not check.verified and check.code == "result_digest_mismatch"


def test_a_receipt_row_moved_or_relabelled_is_refused(deployment, people, keys):
    """L5: the row's own deployment, key id, receipt id and instant are checked
    against its result, card, document and envelope."""
    result, _, receipt = receipted(deployment, people, keys)
    other = Deployment.objects.create(name="other-tenant", owner=people["owner"])
    for change in ({"deployment": other}, {"key_id": "forged-key-id"}, {"receipt_id": uuid.uuid4().hex},
                   {"generated_at": receipt.generated_at.replace(year=2020)}):
        FinancialExposureReceipt._base_manager.filter(pk=receipt.pk).update(**change)
        check = receipt_service.verify_stored_receipt(FinancialExposureReceipt.objects.get(pk=receipt.pk), keys["ring"])
        assert not check.verified and check.code == "receipt_row_mismatch", change
        FinancialExposureReceipt._base_manager.filter(pk=receipt.pk).update(
            deployment=deployment, key_id=receipt.key_id, receipt_id=receipt.receipt_id,
            generated_at=receipt.generated_at)
    assert receipt_service.verify_stored_receipt(FinancialExposureReceipt.objects.get(pk=receipt.pk),
                                                 keys["ring"]).verified


def test_a_changed_release_is_a_note_not_tampering(deployment, people, keys, monkeypatch):
    """L7: a change to a grade constant since the receipt was made: still authentic,
    with the note release_changed (and, round 2, card_not_rebuilt); a tampered result
    is still refused."""
    result, card, receipt = receipted(deployment, people, keys)
    assert receipt_service.verify_stored_receipt(receipt, keys["ring"]).notes == ()
    monkeypatch.setattr(g, "MATERIAL_SHARE", Decimal("0.06"))
    check = receipt_service.verify_stored_receipt(receipt, keys["ring"])
    assert check.verified and check.notes == ("release_changed", "card_not_rebuilt")
    # The release the card recorded, and its digest, are what the receipt names.
    recorded = card.card["fields"]["model_version"]
    assert receipt.document["model"] == {"version": recorded["version"], "build_digest": recorded["build_digest"]}
    versions = json.loads(json.dumps(result.versions))
    versions["numpy"] = "0.0.0"
    SimulationResult._base_manager.filter(pk=result.pk).update(versions=versions)
    assert receipt_service.verify_stored_receipt(receipt, keys["ring"]).code == "model_build_mismatch"


# ======================================================================
# Review round 2
# ======================================================================


def _lump_beside_a_recovery(fine, count, rate, loss="1000000"):
    """The reviewer's (a) and (b): an expert lump beside a customer repeat_loss."""

    def components(scenario):
        guess = _parameter(scenario, "probe.expert_fine", "money", fine, source="EXPERT_ESTIMATE")
        repeat = _parameter(scenario, "probe.repeat_count", "count", count, source="CUSTOMER_PROVIDED")
        each = _parameter(scenario, "probe.loss_per_event", "money_per_unit", loss, source="CUSTOMER_PROVIDED")
        recovery = _parameter(scenario, "probe.recovery_rate", "ratio", rate, source="CUSTOMER_PROVIDED")
        return [("fine", "regulatory_compliance", "lump_sum", {"amount": guess}),
                ("repeat", "direct_financial", "repeat_loss",
                 {"repeat_count": repeat, "loss_per_event": each, "recovery_rate": recovery})]

    return components


def _lump_beside_support_contacts(scenario):
    """The reviewer's (c): an expert lump of 200,000 beside a customer four-factor product of 1,000,000."""
    guess = _parameter(scenario, "probe.expert_fine", "money", "200000", source="EXPERT_ESTIMATE")
    affected = _parameter(scenario, "probe.affected", "count", "10000", source="CUSTOMER_PROVIDED")
    rate = _parameter(scenario, "probe.contact_rate", "ratio", "0.5", source="CUSTOMER_PROVIDED")
    hours = _parameter(scenario, "probe.handling_hours", "hours", "1", source="CUSTOMER_PROVIDED")
    loaded = _parameter(scenario, "probe.loaded_rate", "money_per_hour", "200", source="CUSTOMER_PROVIDED")
    return [("fine", "regulatory_compliance", "lump_sum", {"amount": guess}),
            ("support", "notification", "support_contacts",
             {"affected": affected, "contact_rate": rate, "handling_hours": hours, "loaded_rate": loaded})]


def _a_customer_recovery(scenario):
    """The reviewer's (d), beside an expert frequency: a customer repeat_loss of 10 x 100,000 x (1 - 0.95)."""
    count = _parameter(scenario, "probe.repeat_count", "count", "10", source="CUSTOMER_PROVIDED")
    loss = _parameter(scenario, "probe.loss_per_event", "money_per_unit", "100000", source="CUSTOMER_PROVIDED")
    recovery = _parameter(scenario, "probe.recovery_rate", "ratio", "0.95", source="CUSTOMER_PROVIDED")
    return [("repeat", "direct_financial", "repeat_loss",
             {"repeat_count": count, "loss_per_event": loss, "recovery_rate": recovery})]


def _expert_count_times_a_recovery(rate):
    """The reviewer's (e): an expert repeat_count (a range 2-200) x a customer loss x (1 - a customer recovery)."""

    def components(scenario):
        count = _parameter(scenario, "probe.repeat_count", "count", "2", "20", "200", source="EXPERT_ESTIMATE")
        loss = _parameter(scenario, "probe.loss_per_event", "money_per_unit", "100000", source="CUSTOMER_PROVIDED")
        recovery = _parameter(scenario, "probe.recovery_rate", "ratio", rate, source="CUSTOMER_PROVIDED")
        return [("repeat", "direct_financial", "repeat_loss",
                 {"repeat_count": count, "loss_per_event": loss, "recovery_rate": recovery})]

    return components


#: The reviewer's round-2 probes (test_rv153b_h1.py), each with the expert share of
#: the level and the grade it must have: every one graded A at a8c0ecc.
HIGH1_CASES = {
    "a_expert_lump_75pct_beside_a_recovery_of_0_99": (_lump_beside_a_recovery("3000000", "100", "0.99"), None,
                                                       "0.75", "D"),
    "b_expert_lump_95pct_beside_a_recovery_of_0_999": (_lump_beside_a_recovery("19000000", "1000", "0.999"), None,
                                                        "0.95", "D"),
    "c_expert_lump_beside_a_four_factor_product": (_lump_beside_support_contacts, None, "0.166667", "C"),
    "d_expert_frequency_beside_a_recovery_of_0_95": (_a_customer_recovery, "EXPERT_ESTIMATE", "0.5", "D"),
    "e_expert_count_at_a_recovery_of_0_5": (_expert_count_times_a_recovery("0.5"), None, "0.333333", "D"),
    "e_expert_count_at_a_recovery_of_0_9": (_expert_count_times_a_recovery("0.9"), None, "0.333333", "D"),
    "e_expert_count_at_a_recovery_of_0_99": (_expert_count_times_a_recovery("0.99"), None, "0.333333", "D"),
}


@pytest.mark.parametrize("case", sorted(HIGH1_CASES))
def test_products_and_complements_no_longer_hide_an_expert_figure(people, case):
    """Round 2, HIGH 1 (the reviewer's cases (a)-(e), each graded A before): the level
    is an additive decomposition at base, so an expert figure carries its real share
    -- a lump its base over the total, one factor of k its 1/k of the product, the
    frequency one half -- whatever products and recoveries stand beside it."""
    components, frequency_source, expert, grade_ = HIGH1_CASES[case]
    deployment = Deployment.objects.create(name=f"dep-{case}"[:60], owner=people["owner"])
    _, card = card_of(custom(deployment, people["analyst"], variables=VARIABLES, components=components,
                             frequency_source=frequency_source))
    assert card.card["evidence_mix"]["expert"] == expert, card.card["fields"]["confidence_grade"]["reason"]
    assert card.confidence_grade == grade_, card.card["fields"]["confidence_grade"]["reason"]
    assert card.card["fields"]["expert_estimated_share"]["share"] == expert


@pytest.mark.parametrize("term, figures, gross_grade, retained_grade", [
    ("deductible", {"insurance_deductible": ("50000", "EXPERT_ESTIMATE"), "insurance_limit": ("10000000", None)},
     "A", "D"),
    ("limit", {"insurance_deductible": ("0", None), "insurance_limit": ("950000", "EXPERT_ESTIMATE")}, "A", "C"),
])
def test_an_expert_policy_term_that_carries_the_retained_cash_lowers_the_headline_grade(
        people, term, figures, gross_grade, retained_grade):
    """Round 2, MEDIUM 2 (the reviewer's insurance probe): a customer gross of
    1,000,000 and a customer frequency, under an expert's deductible of 50,000 (the
    retained cash per occurrence is the deductible) or limit of 950,000. Both lines are
    graded: the gross A, the retained cash lower, and the headline -- the card's grade,
    the receipt's -- is the lower of the two. Before: A, 100% customer."""

    def components(scenario):
        cost = _parameter(scenario, "probe.response_cost", "money", "1000000", source="CUSTOMER_PROVIDED")
        return [("response", "legal", "lump_sum", {"amount": cost})]

    variables = {**VARIABLES}
    for name, (figure, source) in figures.items():
        variables[name] = _entry("money", figure, **({"source_type": source} if source else {}))
    deployment = Deployment.objects.create(name=f"dep-ins-{term}", owner=people["owner"])
    result, card = card_of(custom(deployment, people["analyst"], variables=variables, components=components,
                                  frequency_source="CUSTOMER_PROVIDED"))
    assert result.record["scenario"]["headline"] == "retained_cash"
    graded_ = card.card["fields"]["confidence_grade"]
    assert card.confidence_grade == retained_grade, graded_["reason"]
    assert graded_["lines"]["gross_cash"]["grade"] == gross_grade
    assert graded_["lines"]["retained_cash"]["grade"] == retained_grade, graded_["lines"]["retained_cash"]["reason"]
    assert graded_["line"] == "retained_cash" and graded_["rule"] == g.HEADLINE_RULE
    assert card.confidence_grade == graded_["grade"] == card.card["confidence_grade"] == retained_grade
    assert f"insurance_{term}" in graded_["material_expert_figures"]
    assert card.card["fields"]["expert_estimated_share"]["line"] == "retained_cash"


def test_a_frequency_whose_base_is_zero_grades_unknown(deployment, people):
    """Round 2, LOW 3 (the reviewer's h1-zero probe): a frequency of 0 / 0 / 1
    (Poisson 0.01) and a customer lump of 100,000. A base-case year holds no
    occurrence: no level to weigh, and the grade is Unknown. Before: A, defined."""

    def components(scenario):
        FinancialParameter.objects.create(
            scenario=scenario, name=ss.FREQUENCY_PARAMETER, unit="count", source_type="CUSTOMER_PROVIDED",
            currency="", low="0", base="0", high="1", evidence_ref=f"{LABEL}: made up", effective_date=date(2026, 9, 1),
            distribution={"id": "poisson", "version": 1, "params": {"rate": "0.01"}},
        )
        cost = _parameter(scenario, "probe.cost", "money", "100000", source="CUSTOMER_PROVIDED")
        return [("c", "legal", "lump_sum", {"amount": cost})]

    _, card = card_of(custom(deployment, people["analyst"], variables=VARIABLES, components=components))
    graded_ = card.card["fields"]["confidence_grade"]
    assert card.confidence_grade == "Unknown" and "the frequency's base is zero" in graded_["reason"]
    assert card.sensitivity["level"]["gross_cash"]["defined"] is False
    assert card.card["fields"]["expert_estimated_share"]["share"] is None


def test_a_scenario_parameter_nothing_reads_is_on_the_card(deployment, people):
    """Round 2, LOW 4 (the reviewer's probe): a stale expert parameter of the scenario
    version that nothing reads -- the receipt still binds it among the scenario's
    parameters -- is evaluated and shown, read by "nothing", and does not grade."""

    def components(scenario):
        cost = _parameter(scenario, "probe.response_cost", "money", "100000", source="CUSTOMER_PROVIDED")
        _parameter(scenario, "probe.orphan", "money", "5000", source="EXPERT_ESTIMATE", fresh_until=date(2026, 9, 2))
        return [("response", "legal", "lump_sum", {"amount": cost})]

    _, card = card_of(custom(deployment, people["analyst"], variables=VARIABLES, components=components))
    freshness = card.card["fields"]["data_freshness"]
    rows = {row["name"]: row for row in freshness["parameters"]}
    orphan = rows["probe.orphan"]
    assert orphan["read_by"] == [validity_service.UNREAD["scenario"]] and orphan["read_by"][0].startswith("nothing")
    assert orphan["stale"] is True and orphan["counts_toward_grade"] is False and orphan["evaluated"] is True
    assert orphan["source_type"] == "EXPERT_ESTIMATE"
    assert "probe.orphan" in freshness["stale_not_graded"] and "probe.orphan" not in freshness["stale"]
    assert rows["notification_unit_cost"]["read_by"] == [validity_service.UNREAD["parameter_set"]]
    assert card.confidence_grade == "A"


def test_under_a_changed_release_a_matching_analysis_verifies_and_says_the_card_was_not_rebuilt(
        deployment, people, keys, monkeypatch):
    """Round 2, LOW 5, the match: after a release change today's code cannot rebuild
    the card; the stored analysis is the one the card signs, so the receipt is
    authentic, and the verdict says the card was NOT rebuilt (before: it claimed "the
    card" was verified)."""
    _, _, receipt = receipted(deployment, people, keys)
    monkeypatch.setattr(g, "MATERIAL_SHARE", Decimal("0.06"))
    check = receipt_service.verify_stored_receipt(receipt, keys["ring"])
    assert check.verified and check.notes == ("release_changed", "card_not_rebuilt")
    assert "NOT rebuilt" in check.reason and "stored analysis" in check.reason


def test_under_a_changed_release_a_tampered_analysis_is_refused(deployment, people, keys, monkeypatch):
    """Round 2, LOW 5, the mismatch (the reviewer's probe): the stored analysis
    tampered is refused under a changed release (verified before) and under today's,
    by the digest the card signs, which does not depend on the release."""
    _, card, receipt = receipted(deployment, people, keys)
    monkeypatch.setattr(g, "MATERIAL_SHARE", Decimal("0.06"))
    analysis = json.loads(json.dumps(card.sensitivity))
    analysis["ranked"][0]["importance"] = "0.999"
    FinancialValidityCard._base_manager.filter(pk=card.pk).update(sensitivity=analysis)
    check = receipt_service.verify_stored_receipt(receipt, keys["ring"])
    assert not check.verified and check.code == "sensitivity_digest_mismatch", check
    monkeypatch.setattr(g, "MATERIAL_SHARE", Decimal("0.05"))
    check = receipt_service.verify_stored_receipt(receipt, keys["ring"])
    assert not check.verified and check.code == "sensitivity_digest_mismatch"
    FinancialValidityCard._base_manager.filter(pk=card.pk).update(sensitivity=card.sensitivity)
    check = receipt_service.verify_stored_receipt(receipt, keys["ring"])
    assert check.verified and check.notes == ()


def test_an_engine_400_with_a_code_that_is_not_cores_is_not_carried_as_cores(deployment, people, keys, monkeypatch):
    """Round 2, LOW 6 (the reviewer's 400 probe): a 400 whose code is not one of
    core's document codes (``rate_limited``, or ``signer_not_configured`` at 400) is
    still the signer refusing the document, shown with that code, but never carried as
    core's code; nothing is recorded. Core's own code is still carried."""
    from ai_engine.services.cyberengine_client import CyberEngineClient
    from safety import outbound

    result, _ = carded(deployment, people)
    answers = []
    monkeypatch.setattr(outbound, "post", lambda url, **_kwargs: answers.pop(0))
    monkeypatch.setattr(CyberEngineClient, "from_settings",
                        classmethod(lambda cls: CyberEngineClient("https://engine.test", "operator-key")))
    for code in ("rate_limited", "signer_not_configured"):
        answers.append(_http(400, {"detail": {"code": code, "reason": "not now"}}))
        outcome = receipt_service.issue_receipt(result, keyring=keys["ring"])
        assert outcome.receipt is None and outcome.code == "receipt_refused_by_signer", code
        assert outcome.signer_code is None and repr(code) in outcome.detail and "not one of core's" in outcome.detail
    answers.append(_http(400, {"detail": {"code": "amount_precision", "reason": "x"}}))
    assert receipt_service.issue_receipt(result, keyring=keys["ring"]).signer_code == "amount_precision"
    assert not FinancialExposureReceipt.objects.exists()


@pytest.mark.parametrize("entry", [{"status": "active"}, {"status": "active", "public_key": 5},
                                   {"status": "retired", "public_key": None},
                                   {"status": "active", "public_key": "not base64 at all!"}])
def test_a_published_key_entry_without_base64_public_key_text_is_a_value_error(keys, entry):
    """Round 2, nit (the reviewer's probe): a malformed entry is the documented
    ValueError, never a KeyError or a TypeError, in the receipt role or the artifact's."""
    good = _keyring_document((keys["receipt"], "active"))
    with pytest.raises(ValueError):
        receipt_service.keyring_from_published(
            {"version": 1, "keys": {}, "roles": {"economics-receipt": {"version": 1, "keys": {"x": entry}}}})
    with pytest.raises(ValueError):
        receipt_service.keyring_from_published({"version": 1, "keys": {"a": entry}, "roles": {"economics-receipt": good}})


def test_a_result_digest_mismatch_names_what_it_compared(deployment, people, keys):
    """Round 2, nit: tampered inputs are said to be the inputs, a tampered record the record."""
    result, _, receipt = receipted(deployment, people, keys)
    inputs = json.loads(json.dumps(result.inputs))
    inputs["parameters"]["exposure.affected_customers"]["base"] = "9999999"
    SimulationResult._base_manager.filter(pk=result.pk).update(inputs=inputs)
    check = receipt_service.verify_stored_receipt(receipt, keys["ring"])
    assert check.code == "result_digest_mismatch" and "result.inputs" in check.reason
    assert "input digest" in check.reason and "record" not in check.reason
    record = json.loads(json.dumps(result.record))
    record["tampered"] = True
    SimulationResult._base_manager.filter(pk=result.pk).update(inputs=result.inputs, record=record)
    check = receipt_service.verify_stored_receipt(receipt, keys["ring"])
    assert check.code == "result_digest_mismatch" and "result.record" in check.reason


# ======================================================================
# A system fingerprint recorded at build (the follow-up to #153)
# ======================================================================


def _now_fingerprint(deployment) -> str:
    from assurance.fingerprint import compute_system_fingerprint

    return compute_system_fingerprint(Deployment.objects.get(pk=deployment.pk))


def built(deployment, author):
    """A scenario version BUILT by the builder (spec, section 24): section 30's
    payment agent, one hypothetical effect and the finding enabling it, from a
    customer parameter set. No writer states a frequency yet (section 25.9) and a
    receipt needs one, so the scenario's frequency is added after the build, as the
    fixtures above state theirs. SYNTHETIC / ILLUSTRATIVE."""
    variables = {
        "transactions_per_day": _entry("count_per_day", "18000"),
        "average_transaction_value": _entry("money_per_unit", "25000"),
        "recovery_rate": _entry("ratio", "0.825"),
    }
    CustomerParameterSet.record(deployment, "payments_2026q4", {"variables": variables}, author=author)
    asset = Asset.objects.create(deployment=deployment, kind="agent", name="payments-agent",
                                 identifier=f"agent://payments-{uuid.uuid4().hex[:6]}")
    finding = Finding.objects.create(deployment=deployment, fingerprint=f"fp-{uuid.uuid4().hex[:8]}",
                                     finding_type="approval_check_missing", title="approval check", severity="high")

    def attribute(unit, *figures):
        return _entry(unit, *figures, source_type="EXPERT_ESTIMATE", evidence_ref=f"{LABEL}: made up")

    body = {
        "title": "Payment agent: destination changed after approval",
        "parameter_set": {"set_key": "payments_2026q4", "version": 1}, "currency": "USD", "as_of": AS_OF.isoformat(),
        "effects": [{"key": "redirect", "origin": "hypothetical", "effect_type": "funds_transfer_altered",
                     "asset": str(asset.uuid), "business_process": "payments", "attributes": {
                         "success_rate": attribute("ratio", "0.35"),
                         "exploitable_window_hours": attribute("hours", "0.5", "1.25", "2.0"),
                         "incident_response_cost": attribute("money", "80000", "165000", "250000"),
                         "legal_response_cost": attribute("money", "150000", "825000", "1500000")}}],
        "findings": [{"finding": str(finding.uuid), "effect": "redirect", "role": "prerequisite"}],
    }
    scenario, created = builder.build(deployment, body, author=author)
    assert created
    _parameter(scenario, ss.FREQUENCY_PARAMETER, "count", "1", "2", "4", source="CUSTOMER_PROVIDED",
               distribution=POISSON)
    return FinancialScenario.objects.get(pk=scenario.pk)


def test_a_built_scenario_binds_the_fingerprint_it_was_built_in_after_the_deployment_changes(deployment, people, keys):
    """The builder records the deployment's system fingerprint on the version it
    builds. The deployment then changes (a tool joins its graph): the card binds the
    BUILD's fingerprint (``binding: scenario``) and says nothing of the deployment's
    current one -- it is not read, and is nowhere on the card -- and the receipt binds
    the build's value, against which its check passes."""
    scenario = built(deployment, people["analyst"])
    at_build = _now_fingerprint(deployment)  # nothing in the deployment has changed since the build
    assert scenario.system_fingerprint == at_build
    assert scenario.system_fingerprint_unavailable == ""
    Asset.objects.create(deployment=deployment, kind="tool", name="wire-api", identifier="tool://wire-api")
    now = _now_fingerprint(deployment)
    assert now != at_build
    result = simulated(scenario)
    issued = validity_service.issue_card(result)
    assert issued.card is not None, (issued.code, issued.detail)
    card = issued.card
    assert card.card["fields"]["system_fingerprint"] == {
        "value": at_build,
        "binding": "scenario",
        "statement": "the SPINE system fingerprint the scenario version was bound to when it was recorded",
    }
    assert card.card["issued"]["deployment_system_fingerprint"] is None
    assert now not in json.dumps(card.card) and now not in json.dumps(card.sensitivity)
    assert "deployment_at_issue" not in json.dumps(card.card)
    assert validity_service.reproduces(card)
    outcome = receipt_service.issue_receipt(result, signer=_signer(keys["receipt"]), keyring=keys["ring"])
    assert outcome.receipt is not None, (outcome.code, outcome.detail)
    assert outcome.receipt.document["system_fingerprint"] == at_build
    check = receipt_service.verify_stored_receipt(outcome.receipt, keys["ring"])
    assert check.verified and check.code == core.AUTHENTIC and check.notes == (), check


def test_a_fingerprint_the_builder_could_not_compute_is_none_and_the_card_says_why(deployment, people, keys,
                                                                                    monkeypatch):
    """A fingerprint the builder could not compute is recorded as none, with the
    reason, and the build stands. Its card reads the deployment's at issue, as for an
    older version, and says why the build has none; where that cannot be read either,
    the card says both and the receipt has nothing to bind."""
    import assurance.fingerprint as fingerprint

    real = fingerprint.compute_system_fingerprint

    def unreadable(_deployment):
        raise RuntimeError("the asset graph could not be read")

    monkeypatch.setattr(fingerprint, "compute_system_fingerprint", unreadable)
    scenario = built(deployment, people["analyst"])
    assert scenario.system_fingerprint == ""
    assert scenario.system_fingerprint_unavailable == "RuntimeError: the asset graph could not be read"
    at_build = ("the builder could not compute the system fingerprint when it built the scenario version "
                "(RuntimeError: the asset graph could not be read), and recorded none")
    monkeypatch.setattr(fingerprint, "compute_system_fingerprint", real)
    field = validity_service.issue_card(simulated(scenario)).card.card["fields"]["system_fingerprint"]
    assert field == {
        "value": _now_fingerprint(deployment),
        "binding": "deployment_at_issue",
        "statement": f"{at_build}; this is the deployment's SPINE fingerprint when the card was issued, not when the "
                     "scenario was built",
    }
    monkeypatch.setattr(fingerprint, "compute_system_fingerprint", unreadable)
    result = simulated(scenario, seed=8)
    field = validity_service.issue_card(result).card.card["fields"]["system_fingerprint"]
    assert field["value"] is None and field["binding"] is None
    assert field["statement"] == (f"unavailable: {at_build}, and the deployment's could not be read "
                                  "(RuntimeError: the asset graph could not be read)")
    outcome = receipt_service.issue_receipt(result, signer=_signer(keys["receipt"]), keyring=keys["ring"])
    assert outcome.receipt is None and outcome.code == "system_fingerprint_unavailable"


def test_an_older_version_with_no_fingerprint_keeps_the_fallback_unchanged(deployment, people):
    """A version that records neither a fingerprint nor why it has none -- recorded
    before the builder recorded one -- reads exactly as it did at #153: the
    deployment's fingerprint at issue, in the same words."""
    _, card = carded(deployment, people, fingerprint="")
    now = _now_fingerprint(deployment)
    assert card.card["issued"]["deployment_system_fingerprint"] == {"value": now, "unavailable": None}
    assert card.card["fields"]["system_fingerprint"] == {
        "value": now,
        "binding": "deployment_at_issue",
        "statement": "the scenario version records no system fingerprint (the builder records none yet, spec section "
                     "24.9); this is the deployment's SPINE fingerprint when the card was issued, not when the scenario "
                     "was built",
    }


# ======================================================================
# The codes and the spec
# ======================================================================

SPEC = Path(__file__).resolve().parent.parent / "docs" / "economics" / "spec-v1.md"


def test_cores_receipt_codes_are_the_ones_the_spec_lists():
    """Section 26.7 lists core's verdicts and codes as b1f6e9d publishes them: a
    core bump that changes them fails here until the spec moves with it."""
    assert core.VERDICTS == ("authentic", "forged", "unknown_key", "wrong_role", "wrong_type", "malformed", "wrong_card")
    assert core.MALFORMED_CODES == (
        "envelope_malformed", "not_json", "not_canonical", "wrong_schema", "unknown_field", "missing_field",
        "wrong_field_type", "bad_identifier", "bad_tenant", "bad_digest", "bad_instant", "bad_date", "bad_integer",
        "bad_grade", "list_not_canonical", "amount_not_decimal_string", "amount_malformed", "amount_precision",
        "currency_unknown", "currency_retired", "currency_mismatch", "percentiles_out_of_order",
    )
    assert core.CARD_CODES == ("card_malformed", "card_digest_mismatch", "card_scenario_mismatch", "card_grade_mismatch")
    assert core.KEYRING_CODES == ("key_refused", "key_reused", "role_invalid")
    assert core.GRADES == ("A", "B", "C", "D", "Unknown")


def test_no_code_is_published_twice_with_another_meaning():
    from assurance.economics.models import CARD_RECORD_REFUSALS

    core_codes = set(core.VERDICTS) | set(core.MALFORMED_CODES) | set(core.CARD_CODES) | set(core.KEYRING_CODES)
    ours = set(receipt_service.REFUSALS) | set(sens.REFUSALS) | set(CARD_RECORD_REFUSALS)
    assert not ours & core_codes
    assert not set(receipt_service.REFUSALS) & set(sens.REFUSALS)
    text = SPEC.read_text(encoding="utf-8").split("## 26. Sensitivity, grade, Validity Card and receipt", 1)[1]
    for code in sorted(ours | core_codes):
        assert f"`{code}`" in text, code


SPEC_PHRASES = (
    "## 26. Sensitivity, grade, Validity Card and receipt (MVP step 8)",
    "### 26.1 Sensitivity",
    "### 26.2 The confidence grade",
    "### 26.3 The Validity Card",
    "### 26.5 The receipt",
    "### 26.6 Verification",
    "### 26.9 What is still not done",
    "### 26.10 Decisions this step takes, which the owner may change",
    "**never by a raw count**",
    "**each firing at most once**",
    "**Collapsing a range to one figure at its base never raises the grade**",
    "**a fixed\nfigure exactly as a range at the same base**",
    "**no signature nobody has checked is ever recorded**",
    "**never read as tampering**",
    "test_collapsing_a_range_to_its_base_never_raises_the_grade",
    "`expert_figures`",
    "15. **Every figure is evaluated for freshness at the run's as-of date**",
    "never; no calibration set exists",
    "**the same result gives the same receipt row**",
    "**signed on the path the backend's signed assurance receipts take**",
    "`MAX_SWINGS` (20)",
    "test_the_records_go_with_their_deployment_and_never_hold_back_a_stop",
    "- **Step 8 is done** (section 26)",
    "**an ADDITIVE decomposition at base**",
    "**Two lines, and the headline grade is the lower of the two**",
    "18. **Under a policy both lines are graded, and the headline grade is the lower**",
    "19. **A frequency whose base is zero has no level**",
    # Step 8's follow-up: additive terms inside one formula, and the fingerprint at build.
    "**by its additive terms first, where its formula is a sum**",
    "**Aumann-Shapley attribution**",
    "test_an_older_version_with_no_fingerprint_keeps_the_fallback_unchanged",
)


def test_the_spec_states_step_8():
    text = SPEC.read_text(encoding="utf-8")
    for phrase in SPEC_PHRASES:
        assert phrase in text, phrase
    # Every owner field is in the field-to-source table.
    table = text.split("### 26.3 The Validity Card", 1)[1].split("### 26.4", 1)[0]
    for key in OWNER_FIELDS:
        assert f"| `{key}` |" in table, key
    # The thresholds the spec states are the constants.
    assert "| A | 0.80 | 0.05 |" in text and "| B | 0.50 | 0.25 |" in text and "| C | -- | 0.50 |" in text
    assert g.THRESHOLDS[g.ConfidenceGrade.A]["evidence_at_least"] == Decimal("0.80")
    assert g.THRESHOLDS[g.ConfidenceGrade.B]["assumption_at_most"] == Decimal("0.25")
    assert g.THRESHOLDS[g.ConfidenceGrade.C]["assumption_at_most"] == Decimal("0.50")
    assert g.MATERIAL_SHARE == Decimal("0.05") and sens.MAX_SWINGS == 20
    assert validity_service.TOP_DRIVERS == 5
