"""Section 28 hardening, review round 1 of #169 (``docs/economics/spec-v1.md``, section
35): each test replays the reviewer's probe and asserts the fix.

- H1 (SAFETY RULE): the override revoke is a STOP. It is in ``safety.stops.STOP_ROUTES``
  (a body that is a remark at most), and no body, gateway, throttle, rule, state or
  lock holds it back: one read of the override it names, one insert, no transaction.
- M1: a result and its card are bound by a MAC under the row key
  (``ATHENA_ECONOMICS_ROW_KEY``), which the database never holds: a record (and its
  card, and its receipt row) rewritten with every digest recomputed -- before the
  card, before a receipt or after one -- is never carded, signed or served as
  verified. Without the key no receipt is signed.
- M2: the whole chain of grants is read: a two-hop promotion is not a second person.
- M3: whoever recorded the parameter-set versions a run rests on is an author: they
  neither review it nor approve an override of it.
- M4: the override gate measures a parameter-set version against its anchor -- the
  latest version that passed an approved non-author review -- so stepwise cuts
  accumulate, and a new set is measured too.
- M5: a blanked observations digest on a version that holds rows demotes it.
- L1: an approval by a reviewer since demoted or deactivated no longer counts.

New names are read through their modules, so that on the base, where they do not
exist, each test fails on what it asserts rather than the whole file on its import.
SYNTHETIC / ILLUSTRATIVE figures only.
"""

from __future__ import annotations

import base64
import copy
import importlib
import importlib.util
import json
from datetime import timedelta
from decimal import Decimal

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import connection
from django.utils import timezone
from mythos_core import exposure_receipt as core

from assurance.economics import builder, receipt_service, report, simulation_service, snapshots, validity_service
from assurance.economics import models as econ
from assurance.economics.models import (
    CustomerParameterSet,
    FinancialExposureReceipt,
    FinancialSource,
    FinancialValidityCard,
    FXObservation,
    OverrideRevocation,
    ScenarioReview,
    SensitiveOverride,
    SimulationResult,
    canonical_digest,
    card_digest,
)
from assurance.models import Deployment
from safety import stops
from tests.test_economics_report import stored
from tests.test_economics_scenarios import _entry
from tests.test_economics_section_28_hardening import (
    _approve,
    _base,
    _client,
    _crafted,
    _eur_usd,
    _eur_usd_row,
    _frequency,
    _override_url,
    _post,
    _promote,
    _review_service,
    _set_url,
    _simulate_with_receipt,
    _source_at,
)
from tests.test_economics_stated_distributions import _build_body, _payment_world, _point_document

pytestmark = pytest.mark.django_db
ROW_KEY_ENV = "ATHENA_ECONOMICS_ROW_KEY"
REVIEW_ENV = "ATHENA_ECONOMICS_RECEIPT_REVIEW"
REVOKE = "deployment-economics-override-revoke"


User = get_user_model()


@pytest.fixture(autouse=True)
def _review_gate_unset(monkeypatch):
    monkeypatch.delenv(REVIEW_ENV, raising=False)


@pytest.fixture
def people():
    """As ``tests/test_economics_section_28_hardening.py``'s."""
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


def _row_mac():
    return importlib.import_module("assurance.economics.row_mac")


# =====================================================================================
# H1: the override revoke is a stop
# =====================================================================================


def _override(deployment, people):
    scenario = stored(deployment, people["analyst"])
    override = SensitiveOverride.objects.create(
        scenario=scenario, subject="parameter-set:bank_prod_2026q4:v1:notification_unit_cost", reason="confirmed",
        requested_by=people["analyst"],
    )
    for approver in ("reviewer", "admin"):
        econ.OverrideApproval.objects.create(override=override, approver=people[approver])
    assert override.in_force
    return override


def _raw_post(user, url, data: bytes, content_type: str | None):
    client = _client(user)
    if content_type is None:
        return client.generic("POST", url, data)
    return client.generic("POST", url, data, content_type=content_type)


def test_h1_the_override_revoke_is_in_the_stop_set():
    """The reviewer's H1: it was in NOT_STOPS, behind the gateway and the throttles."""
    assert set(stops.STOP_ROUTES.get(REVOKE, {})) == {"POST"}
    assert REVOKE not in stops.NOT_STOPS
    from django.test import RequestFactory

    url = "/api/assurance/deployments/11111111-2222-4333-8444-555555555555/economics/overrides/" \
          "11111111-2222-4333-8444-555555555555/revoke/"
    factory = RequestFactory()
    for body, content_type, stop in (
        (b"", "application/json", True),
        (b"{}", "application/json", True),
        (b'{"reason": "approved in error"}', "application/json", True),
        (b'{"note": "x", "reason": "y"}', "application/json", True),
        (b"reason=approved+in+error", "application/x-www-form-urlencoded", True),
        (b'{"reason": null}', "application/json", False),
        (b'{"reason": "x", "approve": true}', "application/json", False),
        (b"revoke", "text/plain", False),
        (json.dumps({"reason": "a" * 70_000}).encode(), "application/json", False),
    ):
        request = factory.generic("POST", url, data=body, content_type=content_type)
        assert stops.is_stop(request) is stop, (body[:40], content_type)


#: (label, body bytes, content type): what the reviewer sent (P4c) and more; each is
#: recorded, none refused.
BODIES = [
    ("no body", b"", None),
    ("empty JSON object", b"{}", "application/json"),
    ("a reason", b'{"reason": "approved in error"}', "application/json"),
    ("a note, the stop set's remark field", b'{"note": "x"}', "application/json"),
    ("a reason that is null", b'{"reason": null}', "application/json"),
    ("a reason that is a number", b'{"reason": 5}', "application/json"),
    ("an unknown field", b'{"reason": "x", "subject": "y"}', "application/json"),
    ("form-encoded", b"reason=approved+in+error", "application/x-www-form-urlencoded"),
    ("text/plain", b"revoke it", "text/plain"),
    ("multipart", b'--zz\r\nContent-Disposition: form-data; name="reason"\r\n\r\nx\r\n--zz--\r\n',
     "multipart/form-data; boundary=zz"),
    ("JSON that does not parse", b'{"reason": ', "application/json"),
    ("a JSON array", b'["reason"]', "application/json"),
    ("past 64 KiB", json.dumps({"reason": "a" * 70_000}).encode(), "application/json"),
]


@pytest.mark.parametrize(("label", "body", "content_type"), BODIES, ids=[b[0] for b in BODIES])
def test_h1_no_body_holds_back_an_override_revoke(deployment, people, label, body, content_type):
    """The reviewer's P4c: ``{"note": "x"}`` was 400, ``{"reason": null}`` 400, a form
    415, text/plain 415 -- each a revoke dropped. Every one is now recorded: 200, the
    override not in force, a revocation row."""
    override = _override(deployment, people)
    answer = _raw_post(people["reviewer"], _override_url(deployment, override.uuid, "revoke"), body, content_type)
    assert answer.status_code == 200, (label, answer.status_code, answer.content[:200])
    assert answer.json()["override"]["in_force"] is False
    assert OverrideRevocation.objects.filter(override=override).count() == 1
    assert SensitiveOverride.standing_refusal(override.pk) == "override_revoked"
    reason = OverrideRevocation.objects.get(override=override).reason
    assert reason in ("", "approved in error", "x") and len(reason) <= 2000


def test_h1_a_reason_is_kept_and_cut_never_refused(deployment, people):
    override = _override(deployment, people)
    url = _override_url(deployment, override.uuid, "revoke")
    long = _post(_client(people["admin"]), url, {"reason": "r" * 5000})
    assert long.status_code == 200 and long.json()["revocation"]["reason"] == "r" * 2000
    # Revoked again, by the requester: every revocation is recorded, none refused.
    again = _post(_client(people["analyst"]), url, {"note": "and again"})
    assert again.status_code == 200 and again.json()["revocation"]["reason"] == "and again"
    assert OverrideRevocation.objects.filter(override=override).count() == 2


def test_h1_only_authorisation_is_refused(deployment, people):
    """A viewer is 403 and an override the caller cannot see on that deployment 404:
    authorisation, not a control. Nothing is recorded for either."""
    override = _override(deployment, people)
    viewer = _post(_client(people["owner"]), _override_url(deployment, override.uuid, "revoke"), {"reason": "x"})
    assert viewer.status_code == 403
    other = Deployment.objects.create(name="another")
    unseen = _post(_client(people["admin"]), _override_url(other, override.uuid, "revoke"), {"reason": "x"})
    assert unseen.status_code == 404
    assert not OverrideRevocation.objects.exists()
    assert override.in_force


@pytest.mark.django_db(transaction=True)
def test_h1_a_revoke_is_one_read_and_one_insert_in_no_transaction(people, deployment):
    """``transaction=True`` IS THE TEST: no lock it does not own. The revoke reads the
    override it names (one statement), inserts the revocation (one statement), in
    autocommit, and reads nothing after: the answer is made from what is in hand."""
    override = _override(deployment, people)
    client = _client(people["reviewer"])
    seen = []

    def record(execute, sql, params, many, context):
        seen.append((sql.split(" ", 1)[0].upper(), connection.in_atomic_block))
        return execute(sql, params, many, context)

    with connection.execute_wrapper(record):
        answer = _post(client, _override_url(deployment, override.uuid, "revoke"), {"reason": "approved in error"})
    assert answer.status_code == 200, answer.content
    assert seen == [("SELECT", False), ("INSERT", False)], seen
    assert SensitiveOverride.standing_refusal(override.pk) == "override_revoked"


# =====================================================================================
# M1: rows bound by a MAC under a key the database never holds
# =====================================================================================


def _rewrite_record(result: SimulationResult, p50="1.00") -> str:
    """The record's gross P50 and its digest rewritten past the ORM."""
    record = json.loads(json.dumps(result.record))
    record["scenario"]["gross_cash"]["p50"] = p50
    forged = canonical_digest(record)
    SimulationResult._base_manager.filter(pk=result.pk).update(record=record, result_digest=forged)
    return forged


def _rewrite_card(card: FinancialValidityCard, result_digest: str) -> dict:
    document = json.loads(json.dumps(card.card))
    document["fields"]["reproduction"]["result_digest"] = result_digest
    FinancialValidityCard._base_manager.filter(pk=card.pk).update(card=document, card_digest=card_digest(document))
    return document


def _reviewed(deployment, people):
    scenario = stored(deployment, people["analyst"])
    ScenarioReview.objects.create(scenario=scenario, reviewer=people["reviewer"], verdict="approved")
    return scenario


def test_m1_a_record_rewritten_before_its_card_is_never_carded_or_signed(deployment, people, keys):
    """The reviewer's P1c: the record and its digest rewritten before the card was
    issued; the card was made from it and the receipt signed P50 1.00."""
    scenario = _reviewed(deployment, people)
    result = simulation_service.simulate_scenario(scenario, seed=7, draws=10_000).result
    _rewrite_record(result)
    result = SimulationResult.objects.get(pk=result.pk)
    carded = validity_service.issue_card(result)
    assert carded.card is None and carded.code == "stored_row_unverified", (carded.code, carded.detail)
    assert "result_mac" in carded.detail
    signed = receipt_service.issue_receipt(result, signer=keys["sign"], keyring=keys["ring"])
    assert signed.receipt is None and signed.code == "stored_row_unverified", (signed.code, signed.detail)
    assert not FinancialExposureReceipt.objects.exists()


def test_m1_a_record_and_card_rewritten_before_a_receipt_are_never_signed(deployment, people, keys):
    """The reviewer's P1b (spec 35.8's documented gap): record + digest and the card's
    reproduction + its digest rewritten after the card, before any receipt."""
    scenario = _reviewed(deployment, people)
    result = simulation_service.simulate_scenario(scenario, seed=7, draws=10_000).result
    card = validity_service.issue_card(result).card
    assert card is not None
    forged = _rewrite_record(result)
    _rewrite_card(card, forged)
    result = SimulationResult.objects.get(pk=result.pk)
    signed = receipt_service.issue_receipt(result, signer=keys["sign"], keyring=keys["ring"])
    assert signed.receipt is None and signed.code == "stored_row_unverified", (signed.code, signed.detail)
    body = _client(people["owner"]).get(_base(deployment, scenario) + "results/").json()
    assert body["integrity"]["verified"] is False
    assert {"result_mac", "card_mac"} <= set(body["integrity"]["failed"]), body["integrity"]
    assert set(body["summary"]) == {"not_reported"} and report.may_be_totalled(body) is False


def test_m1_rows_and_receipt_rewritten_after_a_receipt_are_never_served_verified(deployment, people, keys):
    """The reviewer's P1d: after a receipt, the record, the card AND the receipt row's
    document and envelope payload rewritten together (the signature untouched): the
    report said ``verified: true``, ``may_be_totalled: true``."""
    scenario = _reviewed(deployment, people)
    body = _simulate_with_receipt(deployment, scenario, people["analyst"])
    assert body["receipt"]["issued"] is True, body["receipt"]
    result = SimulationResult.objects.get()
    card = FinancialValidityCard.objects.get()
    forged = _rewrite_record(result)
    document = _rewrite_card(card, forged)
    receipt = FinancialExposureReceipt.objects.get()
    signed = json.loads(json.dumps(receipt.document))
    signed["result"]["p50"]["amount"] = "1.00"
    signed["validity_card"]["digest"] = card_digest(document)
    envelope = dict(receipt.envelope)
    envelope["payload"] = base64.b64encode(
        json.dumps(signed, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    FinancialExposureReceipt._base_manager.filter(pk=receipt.pk).update(document=signed, envelope=envelope)
    served = _client(people["owner"]).get(_base(deployment, scenario) + "results/").json()
    assert served["integrity"]["verified"] is False, served["integrity"]
    assert {"result_mac", "card_mac"} <= set(served["integrity"]["failed"]), served["integrity"]
    assert report.may_be_totalled(served) is False
    assert "1.00" not in json.dumps(served["summary"])


def test_m1_a_blanked_mac_is_a_rewrite(deployment, people, keys):
    scenario = _reviewed(deployment, people)
    _simulate_with_receipt(deployment, scenario, people["analyst"])
    result = SimulationResult.objects.get()
    assert result.row_mac.startswith("hmac-sha256:") and FinancialValidityCard.objects.get().row_mac
    SimulationResult._base_manager.filter(pk=result.pk).update(row_mac="")
    served = _client(people["owner"]).get(_base(deployment, scenario) + "results/").json()
    assert served["integrity"]["failed"] == ["result_mac"], served["integrity"]


def test_m1_without_the_key_no_receipt_is_signed_and_no_mac_check_is_claimed(deployment, people, keys, monkeypatch):
    monkeypatch.delenv(ROW_KEY_ENV, raising=False)
    scenario = _reviewed(deployment, people)
    body = _simulate_with_receipt(deployment, scenario, people["analyst"])
    assert body["receipt"]["issued"] is False and body["receipt"]["code"] == "row_key_unavailable", body["receipt"]
    assert not FinancialExposureReceipt.objects.exists()
    assert SimulationResult.objects.get().row_mac == "" and FinancialValidityCard.objects.get().row_mac == ""
    served = _client(people["owner"]).get(_base(deployment, scenario) + "results/").json()
    assert served["integrity"]["verified"] is True
    assert not {"result_mac", "card_mac"} & set(served["integrity"]["checks"]), served["integrity"]["checks"]
    # A key too short to be one is no key.
    monkeypatch.setenv(ROW_KEY_ENV, "short")
    assert _row_mac().row_key() is None


def test_m1_the_key_is_read_in_code_from_the_environment(monkeypatch):
    rows = _row_mac()
    monkeypatch.setenv(ROW_KEY_ENV, "k" * 32)
    assert rows.row_key() == b"k" * 32
    monkeypatch.delenv(ROW_KEY_ENV)
    assert rows.row_key() is None
    source = importlib.util.find_spec("assurance.economics.row_mac").origin
    with open(source, encoding="utf-8") as module:
        text = module.read()
    assert "os.environ.get(ROW_KEY_ENV)" in text
    assert "django.conf" not in text and "import settings" not in text


def test_m1_rows_recorded_without_a_key_are_bound_once_where_they_verify(deployment, people, keys, monkeypatch):
    monkeypatch.delenv(ROW_KEY_ENV, raising=False)
    first = _reviewed(deployment, people)
    simulation_service.simulate_scenario(first, seed=7, draws=10_000)
    validity_service.issue_card(SimulationResult.objects.get(scenario=first))
    second = stored(deployment, people["analyst"])
    tampered = simulation_service.simulate_scenario(second, seed=8, draws=10_000).result
    record = json.loads(json.dumps(tampered.record))
    record["scenario"]["gross_cash"]["p50"] = "1.00"
    SimulationResult._base_manager.filter(pk=tampered.pk).update(record=record)
    monkeypatch.setenv(ROW_KEY_ENV, "synthetic-row-key-provisioned-later-0000")
    unbound = _client(people["owner"]).get(_base(deployment, first) + "results/").json()
    assert {"result_mac", "card_mac"} <= set(unbound["integrity"]["failed"]), unbound["integrity"]
    call_command("bind_economics_rows")
    bound = _client(people["owner"]).get(_base(deployment, first) + "results/").json()
    assert bound["integrity"]["verified"] is True, bound["integrity"]
    # A row whose digests fail is never bound: it stays a refusal.
    assert SimulationResult.objects.get(pk=tampered.pk).row_mac == ""
    served = _client(people["owner"]).get(_base(deployment, second) + "results/").json()
    assert "result_mac" in served["integrity"]["failed"]


# =====================================================================================
# M2: the whole chain of grants
# =====================================================================================


def test_m2_a_two_hop_promotion_cannot_approve_a_raise(people):
    """The reviewer's P3a: ada promotes bob (an account she holds), bob promotes mal,
    both before ada asks; mal approved ada's raise to ``authoritative``: 200 ``done``."""
    bob = _promote(people["admin"], people["owner"], role="admin")
    mal = _promote(bob, people["sock"], role="admin")
    source = _source_at()
    asked = _post(_client(people["admin"]), f"/api/assurance/economics/sources/{source.uuid}/trust-raises/",
                  {"to_tier": "authoritative", "reason": "official publisher"})
    assert asked.status_code == 201, asked.content
    approved = _post(_client(mal), f"/api/assurance/economics/trust-raises/{asked.json()['uuid']}/approve/")
    assert approved.status_code == 403 and approved.json()["code"] == "approver_role_not_independent", approved.content
    assert not FinancialSource.objects.filter(trust_tier="authoritative").exists()


def test_m2_a_two_hop_promotion_cannot_review_or_approve_an_override(deployment, people, keys):
    bob = _promote(people["admin"], people["owner"], role="admin")
    mal = _promote(bob, people["sock"], role="analyst")
    scenario = stored(deployment, people["admin"])
    review = _post(_client(mal), _base(deployment, scenario) + "reviews/", {"verdict": "approved"})
    assert review.status_code == 403 and review.json()["code"] == "approver_role_not_independent", review.content
    asked = _post(_client(people["admin"]), _base(deployment, scenario) + "overrides/", {"subject": "x", "reason": "y"})
    assert asked.status_code == 201
    approval = _post(_client(mal), _override_url(deployment, asked.json()["override"]["uuid"], "approve"))
    assert approval.status_code == 403 and approval.json()["code"] == "approver_role_not_independent"


def test_m2_an_independent_chain_still_approves(deployment, people):
    """A chain no requester or author stands in is a second person: bea (an admin of
    her own) promotes carl, who promotes dan; ada asks, dan approves."""
    carl = _promote(people["admin2"], people["owner"], role="admin")
    dan = _promote(carl, people["sock"], role="admin")
    source = _source_at()
    asked = _post(_client(people["admin"]), f"/api/assurance/economics/sources/{source.uuid}/trust-raises/",
                  {"to_tier": "authoritative", "reason": "official publisher"})
    approved = _post(_client(dan), f"/api/assurance/economics/trust-raises/{asked.json()['uuid']}/approve/")
    assert approved.status_code == 200 and approved.json()["state"] == "done", approved.content


def test_m2_a_chain_longer_than_the_walk_is_refused():
    from assurance.economics.engine import governance

    grant = governance.RoleGrant(at=timezone.now() - timedelta(days=1), by=governance.Person(id=2))
    ask = dict(asked_by=[governance.Person(id=1)], approver=governance.Person(id=3), asked_at=timezone.now())
    assert governance.role_grant_refusal(grant, **ask) is None
    assert governance.role_grant_refusal(grant, chain_cut=True, **ask) == "approver_role_not_independent"
    upstream = [governance.RoleGrant(at=grant.at, by=governance.Person(id=1))]
    assert governance.role_grant_refusal(grant, upstream=upstream, **ask) == "approver_role_not_independent"


# =====================================================================================
# M3: the author of the inputs is an author
# =====================================================================================


def _set_by(client, deployment, document):
    response = _post(client, _set_url(deployment), document)
    assert response.status_code == 201, response.content
    return response


def _world(deployment):
    """The payment agent and its finding, made once per deployment."""
    from assurance.models import Asset, Finding

    asset = Asset.objects.filter(deployment=deployment, identifier="agent://payments-agent").first()
    finding = Finding.objects.filter(deployment=deployment, fingerprint="fp-0").first()
    if asset is None or finding is None:
        return _payment_world(deployment)
    return asset, finding


def _built(deployment, people, *, author, version, title, set_key=None):
    asset, finding = _world(deployment)
    body = _build_body(asset, finding, version=version, title=title)
    if set_key is not None:
        body["parameter_set"]["set_key"] = set_key
    scenario, _ = builder.build(deployment, body, author=author)
    return scenario


def test_m3_the_parameter_set_author_cannot_review_what_is_built_on_it(deployment, people, keys):
    """The reviewer's P3c: ann recorded the parameter-set version, bea built the
    scenario, ann approved the review (201) and the receipt was signed."""
    document = _point_document()
    document["frequency"] = _frequency("2")
    _set_by(_client(people["analyst"]), deployment, document)
    scenario = _built(deployment, people, author=people["admin2"], version=1, title="built by bea")
    url = _base(deployment, scenario) + "reviews/"
    own = _post(_client(people["analyst"]), url, {"verdict": "approved"})
    assert own.status_code == 403 and own.json()["code"] == "author_reviews_own_scenario", own.content
    # Recorded past the rules, it does not count at the gate either.
    ScenarioReview._base_manager.bulk_create([ScenarioReview(
        scenario=scenario, reviewer=people["analyst"], reviewer_username="ann", verdict="approved",
        reviewed_at=timezone.now(),
    )])
    refused = _review_service().review_refusal(scenario.pk)
    assert refused is not None and refused[0] == "scenario_not_reviewed", refused
    # A colleague who wrote none of it reviews it.
    assert _post(_client(people["reviewer"]), url, {"verdict": "approved"}).status_code == 201


def _cut_v2(deployment, people):
    """ann records v1 and a 1000x cut v2; bea builds on v2; rex reviews it: P4e."""
    analyst = _client(people["analyst"])
    v1 = _point_document()
    v1["frequency"] = _frequency("2")
    _set_by(analyst, deployment, v1)
    v2 = copy.deepcopy(v1)
    v2["variables"]["transactions_per_day"] = _entry("count_per_day", "18", evidence_ref="trust me")
    _set_by(analyst, deployment, v2)
    scenario = _built(deployment, people, author=people["admin2"], version=2, title="built by bea on v2")
    _approve(deployment, scenario, people["reviewer"])
    return scenario


def test_m3_the_parameter_set_author_cannot_approve_an_override_of_it(deployment, people, keys):
    """The reviewer's P4e: ann recorded a 1000x cut, rex requested the override, ann
    approved it (200) and ada made it in force."""
    scenario = _cut_v2(deployment, people)
    subject = "parameter-set:bank_prod_2026q4:v2:transactions_per_day"
    asked = _post(_client(people["reviewer"]), _base(deployment, scenario) + "overrides/",
                  {"subject": subject, "reason": "customer confirmed"})
    assert asked.status_code == 201, asked.content
    url = _override_url(deployment, asked.json()["override"]["uuid"], "approve")
    own = _post(_client(people["analyst"]), url)
    assert own.status_code == 403 and own.json()["code"] == "author_approves_own_change", own.content
    override = SensitiveOverride.objects.get(uuid=asked.json()["override"]["uuid"])
    # An approval by the change's author recorded past the rules never counts.
    econ.OverrideApproval._base_manager.bulk_create([econ.OverrideApproval(
        override=override, approver=people["analyst"], approver_username="ann", approved_at=timezone.now(),
    )])
    assert _post(_client(people["admin"]), url).status_code == 200
    assert override.approval_refusal() == "override_needs_two_approvers"
    assert _post(_client(people["admin2"]), url).status_code == 200
    assert override.approval_refusal() is None


# =====================================================================================
# M4: the override gate is anchored
# =====================================================================================


def _transactions(document, figure):
    document["variables"]["transactions_per_day"] = _entry("count_per_day", figure)


def test_m4_stepwise_cuts_accumulate_against_the_anchor(deployment, people, keys):
    """The reviewer's P4a: 18000 -> 9500 -> 5000 -> 2700 -> 1400 transactions a day,
    each step under 2x (13x in all): no sensitive change, receipt signed on a review."""
    analyst = _client(people["analyst"])
    document = _point_document()
    document["frequency"] = _frequency("2")
    _set_by(analyst, deployment, document)
    anchor = _built(deployment, people, author=people["analyst"], version=1, title="v1, reviewed")
    _approve(deployment, anchor, people["reviewer"])
    for version, figure in enumerate(("9500", "5000", "2700", "1400"), start=2):
        step = copy.deepcopy(document)
        _transactions(step, figure)
        _set_by(analyst, deployment, step)
    scenario = _built(deployment, people, author=people["analyst"], version=5, title="v5")
    _approve(deployment, scenario, people["reviewer"])
    changes = _review_service().sensitive_changes(scenario.pk)
    assert [c["subject"] for c in changes] == ["parameter-set:bank_prod_2026q4:v5:transactions_per_day"], changes
    assert "bank_prod_2026q4 v1" in changes[0]["change"]
    result = simulation_service.simulate_scenario(scenario, seed=4, draws=2_000).result
    refused = receipt_service.issue_receipt(result, signer=keys["sign"], keyring=keys["ring"])
    assert refused.code == "material_change_unapproved", (refused.code, refused.detail)


def test_m4_a_new_set_is_measured_against_the_anchor(deployment, people, keys):
    """The reviewer's P4b: a new set key whose v1 says 18 a day, 1000x below the set a
    review passed: no sensitive change, receipt signed."""
    analyst = _client(people["analyst"])
    document = _point_document()
    document["frequency"] = _frequency("2")
    _set_by(analyst, deployment, document)
    anchor = _built(deployment, people, author=people["analyst"], version=1, title="v1, reviewed")
    _approve(deployment, anchor, people["reviewer"])
    fresh = copy.deepcopy(document)
    _transactions(fresh, "18")
    response = _post(analyst, f"/api/assurance/deployments/{deployment.uuid}/economics/parameter-sets/"
                              "bank_prod_2027q1/versions/", fresh)
    assert response.status_code == 201, response.content
    scenario = _built(deployment, people, author=people["analyst"], version=1, title="a new set",
                      set_key="bank_prod_2027q1")
    _approve(deployment, scenario, people["reviewer"])
    changes = _review_service().sensitive_changes(scenario.pk)
    assert [c["subject"] for c in changes] == ["parameter-set:bank_prod_2027q1:v1:transactions_per_day"], changes
    result = simulation_service.simulate_scenario(scenario, seed=4, draws=2_000).result
    refused = receipt_service.issue_receipt(result, signer=keys["sign"], keyring=keys["ring"])
    assert refused.code == "material_change_unapproved", (refused.code, refused.detail)


def test_m4_a_passed_review_moves_the_anchor(deployment, people, keys):
    """The anchor is the latest version a review PASSED: once a scenario on the cut is
    approved by a colleague, a version that keeps the cut measures against it."""
    scenario = _cut_v2(deployment, people)
    assert _review_service().sensitive_changes(scenario.pk)
    v3 = _point_document()
    v3["frequency"] = _frequency("2")
    _transactions(v3, "18")
    _set_by(_client(people["analyst"]), deployment, v3)
    later = _built(deployment, people, author=people["admin2"], version=3, title="v3")
    anchor = econ.parameter_set_anchor(CustomerParameterSet.objects.get(set_key="bank_prod_2026q4", version=3))
    assert anchor.version == 2
    assert _review_service().sensitive_changes(later.pk) == []


# =====================================================================================
# M5: a blanked observations digest
# =====================================================================================


def test_m5_a_blanked_observations_digest_does_not_switch_the_rows_check_off(tmp_path, deployment):
    """The reviewer's P2c-blank: the version's digest set to "" (which recorded
    nothing) and an FX row rewritten with its own digest: EUR 1000 read as USD 10."""
    snapshot = snapshots.read_snapshot(_crafted(tmp_path, rate="1.1000", license_class="licensed",
                                                trust_tier="licensed_vendor"))
    source, _ = snapshots.register(snapshot)
    assert _eur_usd(snapshots.fx_book([source], deployment=deployment)).output.amount == Decimal("1100.0000")
    FinancialSource._base_manager.filter(pk=source.pk).update(observations_digest="")
    row = _eur_usd_row(source)
    row.rate = Decimal("0.0100")
    FXObservation._base_manager.filter(pk=row.pk).update(rate=row.rate, row_digest=row.computed_digest())
    with pytest.raises(econ.EconomicsRefused) as refused:
        snapshots.fx_book([source], deployment=deployment)
    assert refused.value.code == "snapshot_rows_mismatch"
    assert FinancialSource.objects.get(pk=source.pk).production_use_refusal(deployment) == "snapshot_rows_mismatch"


def test_m5_a_version_with_no_rows_and_no_digest_is_as_before(deployment):
    source = _source_at()
    assert source.observations_digest == ""
    assert econ.observation_rows_refusal([source.pk]) is None


# =====================================================================================
# L1: an approval by someone since demoted or deactivated no longer counts
# =====================================================================================


@pytest.mark.parametrize("change", ["demoted", "deactivated"])
def test_l1_an_approval_counts_only_while_its_reviewer_still_writes(deployment, people, keys, change):
    """The reviewer's P3b: a reviewer demoted to viewer and deactivated after approving
    still counted, and the receipt was signed."""
    scenario = _reviewed(deployment, people)
    reviewer = people["reviewer"]
    if change == "demoted":
        _promote(people["admin"], reviewer, role="viewer")
    else:
        reviewer.is_active = False
        reviewer.save(update_fields=["is_active"])
    body = _simulate_with_receipt(deployment, scenario, people["analyst"])
    assert body["receipt"]["issued"] is False and body["receipt"]["code"] == "scenario_not_reviewed", body["receipt"]
    assert "no longer" in body["receipt"]["detail"]
    _approve(deployment, scenario, people["admin2"])
    again = receipt_service.issue_receipt(SimulationResult.objects.get(), signer=keys["sign"], keyring=keys["ring"])
    assert again.receipt is not None, (again.code, again.detail)
