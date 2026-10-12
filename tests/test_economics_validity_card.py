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
    assert fields["model_version"]["engine"] == result.versions
    reproduction = fields["reproduction"]
    assert (reproduction["seed"], reproduction["draws"], reproduction["input_digest"], reproduction["result_digest"],
            reproduction["outcomes_sha256"]) == (result.seed, result.draws, result.input_digest, result.result_digest,
                                                 record["outcomes_sha256"])
    assert reproduction["sensitivity_digest"] == card.sensitivity_digest
    # The shares are the grade's evidence mix, weighed by importance.
    mix = card.card["evidence_mix"]
    assert fields["customer_specific_share"]["share"] == mix["customer"]
    assert fields["benchmark_derived_share"]["share"] == mix["benchmark"]
    assert Decimal(fields["expert_estimated_share"]["share"]) == Decimal(mix["expert"]) + Decimal(mix["unsourced"])
    # Every customer figure the gross reads is listed with its weight: the parameter
    # set's point masses carry none, the regulatory range carries its importance.
    weights = {e["name"]: Decimal(e["importance"]) for e in fields["customer_specific_share"]["parameters"]}
    assert set(weights) == {"exposure.regulatory_response_cost", "notification_fixed_cost", "notification_unit_cost"}
    assert weights["notification_fixed_cost"] == weights["notification_unit_cost"] == 0
    assert weights["exposure.regulatory_response_cost"] > 0
    assert abs(weights["exposure.regulatory_response_cost"] - Decimal(mix["customer"])) < Decimal("0.000001")
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
    receipt = receipt_service.issue_receipt(outcome.result, signer=_signer(Ed25519PrivateKey.generate()))
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
    outcome = receipt_service.issue_receipt(result)
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

    outcome = receipt_service.issue_receipt(result, signer=swapped)
    assert outcome.receipt is None and outcome.code == "envelope_not_over_receipt"


def test_a_receipt_needs_every_figure_and_a_fingerprint(deployment, people, keys, monkeypatch):
    # No frequency: no expected annual exposure, which is never estimated.
    result, card = carded(deployment, people, frequency=False)
    assert card.card["fields"]["figures"]["expected_annual_exposure"] is None
    outcome = receipt_service.issue_receipt(result, signer=_signer(keys["receipt"]))
    assert outcome.receipt is None and outcome.code == "receipt_figure_unavailable"
    assert "expected_annual_exposure" in outcome.detail
    # No fingerprint at all: nothing to bind.
    import assurance.fingerprint as fingerprint

    def unreadable(_deployment):
        raise RuntimeError("the asset graph could not be read")

    monkeypatch.setattr(fingerprint, "compute_system_fingerprint", unreadable)
    other = Deployment.objects.create(name="second", owner=people["owner"])
    result, _ = carded(other, people, fingerprint="")
    outcome = receipt_service.issue_receipt(result, signer=_signer(keys["receipt"]))
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
    "**never by\na raw count**",
    "**each firing at most once**",
    "never; no calibration set exists",
    "**the same result gives the same receipt row**",
    "**signed on the path the backend's signed assurance receipts take**",
    "`MAX_SWINGS` (20)",
    "test_the_records_go_with_their_deployment_and_never_hold_back_a_stop",
    "- **Step 8 is done** (section 26)",
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
    assert g.MATERIAL_IMPORTANCE == Decimal("0.05") and sens.MAX_SWINGS == 20
    assert validity_service.TOP_DRIVERS == 5
