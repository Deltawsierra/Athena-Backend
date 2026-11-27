"""SPINE SP-4, part 2b: the backend issues signed recovery receipts.

Mythos-Core defines the recovery receipt (``mythos_core.recovery_receipt``; v2 since
Mythos-Core#86: an engine's support names its key). Part 2a made the record say only what a
receipt could say; nothing issued one. :mod:`assurance.recovery_receipts` does now, through
``POST /api/assurance/findings/<uuid>/recovery-receipts/``, and serves them back through
``GET .../recovery-receipts/`` and ``GET .../recovery-receipts/head/``. Held here:

- the core's v2 vectors (``tests/vectors/recovery-receipt-v2.json``, the core's own file at
  the pinned commit, byte for byte: the core does not install them) pass the issuer's gate,
  and the fake signer (the vectors' recovery-receipt key) signs each to its own envelope;
  every invalid vector is refused by the gate with the vector's verdict and code;
- a receipt of every shape the record takes is built from recorded steps, signed, verified,
  stored and read back equal, and the shapes reach the vectors' own;
- a forged, a wrong-role, an unknown-key envelope, and one over another document or a v1
  document, are never stored; an engine support with no key id is never issued as signed;
  a v1 document is never sent;
- each receipt after the first supersedes the latest and says why; nothing moved returns the
  same latest; an engine that cannot be reached stores nothing and answers 503 with
  ``Retry-After``, and one that refuses is answered with its code;
- a stored receipt that no longer verifies reads ``unknown``; a receipt is never rewritten;
- every route declares its class, none is a stop, and nothing of this loads with the URL conf.

On master there is no issuer, no table and no route, so every test here fails there.
"""

from __future__ import annotations

import ast
import base64
import copy
import functools
import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.db import connection
from django.test import override_settings
from django.utils import timezone
from mythos_core import outcome as oc
from mythos_core import recovery_receipt as core
from mythos_core import status as st
from rest_framework.test import APIClient

from assurance import recovery_receipts as rx
from assurance import recovery_record as rr
from assurance.models import Deployment, Finding, RecoveryReceipt, RecoveryReceiptRewriteRefused, RecoveryRecord
from safety import degraded, outbound, stops
from tests import incident_scopes as scopes
from tests.incident_scopes import declare as declare_scope
from tests.repair_contracts import agree
from tests.test_a_recovery_record_is_derived_from_its_witnesses import COVERED, _incident, _repaired_and_tested
from tests.test_the_recovery_record_says_what_a_receipt_could import _accepted, _scenarios, _signed_links

pytestmark = [pytest.mark.django_db, pytest.mark.usefixtures("engine_keyring")]

User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
VECTORS = Path(__file__).resolve().parent / "vectors" / "recovery-receipt-v2.json"
#: Byte for byte Mythos-Core's tests/vectors/recovery-receipt-v2.json at 1de268c (the pin).
VECTOR_SHA256 = "13b0d302d279a3f433f502f6f0060463cc94adcfb770fa79eb4fc54fd4e0937a"
ENGINE = "https://engine.test"
OPERATOR_KEY = "ce_op_operator-key-not-for-receipts"
SIGN_ROUTE = "/api/assurance/recovery-receipt/sign"
KEYRING_ROUTE = "/api/assurance/keyring"


@functools.lru_cache(maxsize=1)
def _vector_bytes() -> bytes:
    return VECTORS.read_bytes()


def _vectors() -> dict:
    return json.loads(_vector_bytes().decode("utf-8"))


def _private(role="recovery-receipt") -> Ed25519PrivateKey:
    """One of the vectors' test keys: its private seed is the SHA-256 of its phrase."""
    phrase = _vectors()["keys"][role]["phrase"]
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(phrase.encode()).digest())


def _entry(role, status="active") -> dict:
    return {
        "public_key": base64.b64encode(oc.raw_public_key(_private(role))).decode("ascii"), "status": status,
        "created_at": "2026-11-01T00:00:00Z", "retired_at": None, "reason": "",
    }


def _published(receipt_status="active") -> dict:
    """The vectors' keys as the engine publishes its keyring (``GET /api/assurance/keyring``,
    athena-engine #146): the artifact key in ``keys``, each other role under its name in
    ``roles``, and the engine's caveat."""
    roles = ("recovery-receipt", "economics-receipt", "outcome", "effect", "operator")
    return {
        "version": 1,
        "keys": {"sha256:" + "a" * 32: _entry("athena")},
        "roles": {
            role: {
                "version": 1,
                "keys": {f"sha256:{n:032x}": _entry(role, receipt_status if role == "recovery-receipt" else "active")},
            }
            for n, role in enumerate(roles)
        },
        "caveat": "a retired key still verifies receipts it signed; a revoked key verifies nothing",
    }


def _vector_ring():
    ring = _vectors()["keyring"]
    return core.recovery_receipt_keyring(
        [bytes.fromhex(k) for k in ring["receipt_keys"]],
        other_roles={role: [bytes.fromhex(k) for k in keys] for role, keys in ring["other_roles"].items()},
    )


def _dsse(envelope: dict) -> dict:
    """A vector's envelope (hex) as DSSE carries it (base64)."""
    if "payload_hex" not in envelope:
        return envelope
    return {
        "payloadType": envelope["payloadType"],
        "payload": base64.b64encode(bytes.fromhex(envelope["payload_hex"])).decode("ascii"),
        "signatures": [
            {"keyid": s["keyid"], "sig": base64.b64encode(bytes.fromhex(s["sig_hex"])).decode("ascii")}
            for s in envelope["signatures"]
        ],
    }


class Signer:
    """The engine's part, played by the vectors' recovery-receipt key: what it was sent, and
    what it returned. ``envelope_of`` makes the envelope from the document instead."""

    def __init__(self, envelope_of=None):
        self.sent, self.returned = [], []
        self.envelope_of = envelope_of or (lambda document: core.sign_receipt(document, _private()))

    def __call__(self, document):
        self.sent.append(copy.deepcopy(document))
        envelope = self.envelope_of(document)
        self.returned.append(copy.deepcopy(envelope))
        return envelope


@pytest.fixture
def signer(monkeypatch):
    """The engine's keyring (the vectors' keys, as published) and its signer, faked."""
    signer = Signer()
    monkeypatch.setattr(rx, "engine_keyring", lambda: rx.keyring_from_published(_published()))
    monkeypatch.setattr(rx, "engine_signer", signer)
    return signer


@pytest.fixture
def admin():
    return User.objects.create_user(username="receipt-admin", password="x", role=User.Roles.ADMIN)


def _as(person) -> APIClient:
    client = APIClient()
    client.force_authenticate(user=person)
    return client


def _url(finding, tail=""):
    return f"/api/assurance/findings/{finding.uuid}/recovery-receipts/{tail}"


def _issue(person, finding):
    return _as(person).post(_url(finding), {}, format="json")


def _read(person, finding):
    answer = _as(person).get(_url(finding))
    assert answer.status_code == 200, answer.content
    return answer.json()


def _at(monkeypatch, instant):
    monkeypatch.setattr(timezone, "now", lambda: instant)


def _shape(receipt) -> tuple:
    return (
        receipt["state"], receipt["held_back_from"], receipt["release"], receipt["acceptance"] is not None,
        receipt["scope"]["revision"] is not None,
    )


# ------------------------------------------------------------- the core's v2 vectors


def test_the_vectors_are_the_cores_own_v2_file_and_name_its_words():
    assert hashlib.sha256(_vector_bytes()).hexdigest() == VECTOR_SHA256
    v = _vectors()
    assert (v["receipt_schema"], v["payload_type"], v["role"]) == (
        core.RECEIPT_SCHEMA_V2, core.RECEIPT_PAYLOAD_TYPE_V2, core.RECOVERY_RECEIPT_ROLE,
    )
    assert v["keys"]["recovery-receipt"]["key_id"] == oc.key_id_for(oc.raw_public_key(_private()))
    assert tuple(v["sets"]["standings"]) == core.RECEIPT_STANDINGS


def test_every_v2_vector_passes_the_issuers_gate_and_the_fake_signer_signs_it_to_its_own_envelope():
    """Each valid vector's envelope is one the issuer stores for that vector's receipt, and
    the issuer's signer in these tests (the vectors' key) signs the receipt to exactly that
    envelope; over any other receipt it is refused. Every invalid vector is refused by the
    gate with the vector's own verdict and code."""
    ring, v = _vector_ring(), _vectors()
    valid = v["valid"]
    by_ref = {case["receipt"]["receipt_ref"]: case["receipt"] for case in valid}
    for i, case in enumerate(valid):
        envelope = _dsse(case["envelope"])
        assert rx.envelope_problem(case["receipt"], envelope, ring) is None, case["why"]
        assert Signer()(case["receipt"]) == envelope, case["why"]
        other = valid[(i + 1) % len(valid)]["receipt"]
        assert rx.envelope_problem(other, envelope, ring).code == "envelope_not_over_receipt", case["why"]
    assert len(valid) == 13
    for case in v["invalid"]:
        refused = rx.envelope_problem(by_ref[case["edit_of"]], _dsse(case["envelope"]), ring)
        assert (refused.code, refused.verdict, refused.verdict_code) == (
            "envelope_unverified", case["verdict"], case["code"],
        ), case["why"]
    assert len(v["invalid"]) == 23


def _more_shapes(admin) -> dict:
    """Shapes of the record the part-2a scenarios do not take, recorded through ``record``."""
    out = {}
    out["on the incident alone"] = finding = _incident("alone")
    rr.record(finding, by=admin)
    out["on the incident alone, under a scope"] = finding = _incident("alone-scoped")
    declare_scope(finding)
    rr.record(finding, by=admin)
    out["a repair proposed"] = finding = _incident("proposed")
    declare_scope(finding)
    agree(finding)
    rr.record(finding, by=admin, body={"coverage": COVERED})
    out["a repair tested"] = finding = _incident("tested")
    declare_scope(finding)
    _repaired_and_tested(finding)
    rr.record(finding, by=admin, body={"coverage": COVERED})
    out["contained, under a scope"] = finding = _incident("contained-scoped")
    declare_scope(finding)
    permit, receipt = _signed_links(finding)
    rr.record(finding, by=admin, body={"permits": [permit], "receipts": [receipt], "gaps": ["edr-west-offline"]})
    return out


def test_every_shape_of_the_record_is_issued_from_its_steps_signed_verified_stored_and_read_back_equal(
    monkeypatch, signer, admin,
):
    """A receipt of the last step of every shape, issued through the route: built from the
    recorded steps, signed by the fake signer, verified, stored, and read back equal to the
    document signed, standing as the record's own step stands. A step nobody vouches for
    is not issued at all (the core's ``conditions_required``). The shapes issued reach every
    shape of the core's valid vectors that a record of one step can take."""
    findings = {**_scenarios(monkeypatch), **_more_shapes(admin)}
    shapes = set()
    for name, finding in findings.items():
        answer = _issue(admin, finding)
        if name == "stored with no recorder":
            assert answer.status_code == 409, answer.content
            assert (answer.json()["code"], answer.json()["core_code"]) == ("receipt_not_built", core.CONDITIONS_REQUIRED)
            assert not RecoveryReceipt.objects.filter(finding=finding).exists()
            continue
        assert answer.status_code == 201, (name, answer.content)
        sent, returned = signer.sent[-1], signer.returned[-1]
        row = RecoveryReceipt.objects.get(finding=finding)
        assert row.envelope == returned and row.sequence == 1 and row.supersedes is None, name
        assert row.issued_by_ref == f"user:{admin.pk}" and row.key_id == oc.key_id_for(oc.raw_public_key(_private()))
        assert sent["schema"] == core.RECEIPT_SCHEMA_V2 and returned["payloadType"] == core.RECEIPT_PAYLOAD_TYPE_V2
        (served,) = _read(admin, finding)["receipts"]
        assert served["verified"] is True and served["receipt"] == sent == answer.json()["receipt"]["receipt"], name
        assert served["envelope"] == returned and served["unvouched_support"] == []
        assert core.verify_receipt(row.envelope, _vector_ring()).receipt == sent
        record = rr.finding_record(finding)
        step = record["steps"][-1]
        assert (sent["record"], sent["state"], sent["release"]) == (step["ref"], step["state"], step["release"]), name
        # The latest receipt, taken under the current scope: current. A step derived before
        # any scope was declared is taken under none, and stands scope_moved, as the step does.
        head = _read(admin, finding)["head"]
        expected = core.CURRENT if sent["scope"]["revision"] == head["current_scope_revision"] else core.SCOPE_MOVED
        assert served["standing"] == expected, name
        if sent["scope"]["revision"] is None:
            assert served["standing"] == step["standing"], name
        shapes.add(_shape(sent))
    # An acceptance that has ended: read, and issued, at the reader's instant.
    finding = _incident("ended")
    _accepted(finding, until=timezone.now() + timedelta(days=1))
    _at(monkeypatch, timezone.now() + timedelta(days=3))
    assert _issue(admin, finding).status_code == 201
    ended = signer.sent[-1]
    assert (ended["state"], ended["release"], ended["acceptance"]["expires_at"] < ended["as_of"]) == (
        st.REPAIR_TESTED, st.FAIL, True,
    )
    assert _read(admin, finding)["receipts"][0]["standing"] == core.ACCEPTANCE_ENDED
    shapes.add(_shape(ended))
    # The core's chain vectors carry an earlier step's acceptance on a receipt of a later
    # step; this backend's receipt carries the acceptance of the step it is taken of.
    chained = {
        (st.REPAIR_PROPOSED, None, st.FAIL, True, True),
        (st.UNDER_INVESTIGATION, None, st.FAIL, True, True),
    }
    vectors = {_shape(case["receipt"]) for case in _vectors()["valid"]}
    assert shapes >= vectors - chained, sorted(vectors - chained - shapes, key=str)
    assert {release for _, _, release, _, _ in shapes} == {st.PASS, st.FAIL, st.AUDIT_INCOMPLETE}


# ------------------------------------------------------- only what verifies is stored


def _flipped(envelope):
    sig = base64.b64decode(envelope["signatures"][0]["sig"])
    forged = bytes([sig[0] ^ 1]) + sig[1:]
    return {**envelope, "signatures": [{**envelope["signatures"][0], "sig": base64.b64encode(forged).decode("ascii")}]}


@pytest.mark.parametrize(
    ("made", "code", "verdict"),
    [
        (lambda d: _flipped(core.sign_receipt(d, _private())), "envelope_unverified", core.FORGED),
        (lambda d: core.sign_receipt(d, _private("economics-receipt")), "envelope_unverified", core.WRONG_ROLE),
        (lambda d: core.sign_receipt(d, _private("operator")), "envelope_unverified", core.WRONG_ROLE),
        (lambda d: core.sign_receipt(d, _private("athena")), "envelope_unverified", core.WRONG_ROLE),
        (lambda d: core.sign_receipt(d, _private("stranger")), "envelope_unverified", core.UNKNOWN_KEY),
        (
            lambda d: {**core.sign_receipt(d, _private()), "signatures": core.sign_receipt(d, _private())["signatures"] * 2},
            "envelope_unverified", core.MALFORMED,
        ),
        (
            lambda d: core.sign_receipt({**d, "receipt_ref": f"recovery-receipt:{uuid.uuid4()}"}, _private()),
            "envelope_not_over_receipt", core.AUTHENTIC,
        ),
        (
            lambda d: core.sign_receipt({**d, "schema": core.RECEIPT_SCHEMA}, _private()),
            "envelope_not_over_receipt", core.AUTHENTIC,
        ),
    ],
    ids=["forged", "economics-receipt-key", "operator-key", "artifact-key", "unknown-key", "two-signatures",
         "another-document", "v1"],
)
def test_an_envelope_that_does_not_verify_in_the_role_or_is_not_over_the_document_is_never_stored(
    monkeypatch, signer, admin, made, code, verdict,
):
    finding = _incident("gate")
    _accepted(finding)
    signer.envelope_of = made
    answer = _issue(admin, finding)
    assert answer.status_code == 502, answer.content
    assert (answer.json()["code"], answer.json()["verdict"]) == (code, verdict)
    assert len(signer.sent) == 1
    assert not RecoveryReceipt.objects.exists()
    # The same document, signed as the engine signs it, is then issued.
    signer.envelope_of = lambda d: core.sign_receipt(d, _private())
    assert _issue(admin, finding).status_code == 201


def test_an_engine_support_that_names_no_key_id_is_never_issued_as_signed(signer, admin):
    """A step whose permit names its engine and no key id (a row as stored): the receipt
    does not carry that entry as signed; it names the gap with what would close it -- the
    permit, signed by an engine -- and the gap holds the pass back. Every engine entry the
    receipt carries names its key, and the core finds nothing unvouched in it."""
    finding = _incident("keyless")
    permit, receipt = _signed_links(finding)
    _accepted(finding, body={"permits": [permit], "receipts": [receipt]})
    row = RecoveryRecord._base_manager.filter(finding=finding).order_by("-version").first()
    support = copy.deepcopy(row.support)
    entry = next(e for e in support if e["kind"] == "permit")
    entry["key_id"] = None
    RecoveryRecord._base_manager.filter(pk=row.pk).update(support=support)

    answer = _issue(admin, finding)
    assert answer.status_code == 201, answer.content
    sent = signer.sent[-1]
    gap = f"support:{entry['condition']}:permit:{entry['ref']}"
    assert {"gap": gap, "would_close": [{"kind": "permit", "voucher": core.ENGINE}]} in sent["gaps"]
    assert all(e["key_id"] for e in sent["support"] if core.ENGINE in e)
    assert not any(e["kind"] == "permit" for e in sent["support"])
    assert (sent["state"], sent["release"]) == (st.RECOVERY_ACCEPTED, st.AUDIT_INCOMPLETE)
    (served,) = _read(admin, finding)["receipts"]
    assert served["verified"] and served["unvouched_support"] == []


def test_a_v1_document_is_never_issued(monkeypatch, signer, admin):
    """Were the builder to make a v1 document it is never sent: the issuer issues v2 alone.
    (The engine returning a v1 envelope is refused at the gate, above.)"""
    finding = _incident("v1")
    _accepted(finding)
    monkeypatch.setattr(core, "build_receipt", core._build_receipt_v1)
    answer = _issue(admin, finding)
    assert answer.status_code == 409, answer.content
    assert (answer.json()["code"], answer.json()["core_code"]) == ("receipt_not_built", core.WRONG_SCHEMA)
    assert signer.sent == [] and not RecoveryReceipt.objects.exists()


# ------------------------------------------------------- supersession and re-issue


def test_each_receipt_after_the_first_supersedes_the_latest_and_says_why(monkeypatch, signer, admin):
    finding = _incident("chain")
    primary = scopes.asset(finding.deployment, "primary-route")
    declare_scope(finding, primary, by=admin)
    _repaired_and_tested(finding)
    rr.record(finding, by=finding.deployment.owner, body={"coverage": COVERED},
              accept_until=timezone.now() + timedelta(days=5))
    assert _issue(admin, finding).status_code == 201
    first = signer.sent[-1]
    assert (first["supersedes"], first["reason"], first["release"]) == (None, "", st.PASS)

    # The scope widens: the record reads otherwise with no new step.
    backup = scopes.asset(finding.deployment, "backup-route")
    declare_scope(finding, primary, backup, by=admin)
    assert _issue(admin, finding).status_code == 201
    second = signer.sent[-1]
    revision = _revisions(finding)[-1]
    assert (second["supersedes"], second["reason"]) == (first["receipt_ref"], f"scope-revision:{revision.uuid}")
    assert (second["state"], second["held_back_from"], second["release"]) == (
        st.REPAIR_TESTED, st.RECOVERY_ACCEPTED, st.AUDIT_INCOMPLETE,
    )
    core.check_supersedes(first, second)

    # A later step: evidence naming the added item.
    rr.record(finding, by=admin, body={"evidence": [str(scopes.evidence_naming(backup).uuid)], "coverage": COVERED})
    last_step = rr.finding_record(finding)["steps"][-1]
    assert _issue(admin, finding).status_code == 201
    third = signer.sent[-1]
    assert (third["supersedes"], third["reason"]) == (second["receipt_ref"], f"recovery-step:{last_step['ref']}")
    core.check_supersedes(second, third)

    read = _read(admin, finding)
    assert [r["receipt_ref"] for r in read["receipts"]] == [first["receipt_ref"], second["receipt_ref"], third["receipt_ref"]]
    assert [r["sequence"] for r in read["receipts"]] == [1, 2, 3]
    assert [r["standing"] for r in read["receipts"]] == [core.SUPERSEDED, core.SUPERSEDED, core.CURRENT]
    assert read["head"] == {"current_scope_revision": revision.revision, "latest_receipt_ref": third["receipt_ref"]}
    assert core.superseded_refs([r["receipt"] for r in read["receipts"]]) == tuple(
        sorted((first["receipt_ref"], second["receipt_ref"]))
    )


def _revisions(finding):
    from assurance import incident_scope

    return incident_scope.revisions_of([finding.pk])[finding.pk]


def test_an_ended_acceptance_supersedes_the_receipt_that_carried_it(monkeypatch, signer, admin):
    finding = _incident("ending")
    _accepted(finding, until=timezone.now() + timedelta(days=1))
    assert _issue(admin, finding).status_code == 201
    accepted = signer.sent[-1]
    _at(monkeypatch, timezone.now() + timedelta(days=2))
    assert _read(admin, finding)["receipts"][0]["standing"] == core.ACCEPTANCE_ENDED
    assert _issue(admin, finding).status_code == 201
    ended = signer.sent[-1]
    assert (ended["supersedes"], ended["reason"]) == (accepted["receipt_ref"], f"acceptance-ended:{accepted['record']}")
    assert (ended["state"], ended["release"]) == (st.REPAIR_TESTED, st.FAIL)
    core.check_supersedes(accepted, ended)
    assert [r["standing"] for r in _read(admin, finding)["receipts"]] == [core.SUPERSEDED, core.ACCEPTANCE_ENDED]


def test_a_receipt_whose_record_has_not_moved_is_not_issued_again(monkeypatch, signer, admin):
    finding = _incident("still")
    _accepted(finding)
    first = _issue(admin, finding)
    assert first.status_code == 201
    ref = first.json()["receipt"]["receipt_ref"]
    again = _issue(admin, finding)
    assert again.status_code == 200, again.content
    assert (again.json()["issued"], again.json()["receipt"]["receipt_ref"]) == (False, ref)
    _at(monkeypatch, timezone.now() + timedelta(days=1))  # later, the acceptance still in force
    later = _issue(admin, finding)
    assert (later.status_code, later.json()["receipt"]["receipt_ref"]) == (200, ref)
    assert len(signer.sent) == 1 and RecoveryReceipt.objects.filter(finding=finding).count() == 1


# --------------------------------------------- an engine unreachable, or refusing


def _http(status, body):
    response = requests.Response()
    response.status_code = status
    response._content = json.dumps(body).encode()
    response.headers["Content-Type"] = "application/json"
    return response


@pytest.fixture
def engine(monkeypatch):
    """The engine at the far side of the backend's own client: ``answers["keyring"]`` and
    ``answers["sign"]`` say what each route answers (a response, or an exception to raise),
    and every request is recorded with its headers and body."""
    seen, answers = [], {"keyring": _http(200, _published()), "sign": None}

    def _answer(which, document=None):
        answer = answers[which]
        if isinstance(answer, Exception):
            raise answer
        if answer is None:
            return _http(200, core.sign_receipt(document, _private()))
        return answer

    def post(url, **kwargs):
        if url != ENGINE + SIGN_ROUTE:
            # Every other ask of this engine (the gateway's /defend) finds no engine, as in
            # every other test here: the gateway then allows the request, as it always has.
            raise requests.ConnectionError("no engine at this route here")
        seen.append(("POST", url, dict(kwargs.get("headers") or {}), kwargs.get("json")))
        return _answer("sign", kwargs["json"]["receipt"])

    def get(url, **kwargs):
        if url != ENGINE + KEYRING_ROUTE:
            raise requests.ConnectionError("no engine at this route here")
        seen.append(("GET", url, dict(kwargs.get("headers") or {}), None))
        return _answer("keyring")

    monkeypatch.setattr(outbound, "post", post)
    monkeypatch.setattr(outbound, "get", get)
    with override_settings(CYBERENGINE_URL=ENGINE, CYBERENGINE_OPERATOR_KEY=OPERATOR_KEY):
        yield seen, answers


def test_the_engine_is_asked_on_its_recovery_receipt_route_with_the_recovery_signer_key_alone(engine, admin):
    """The real client, end to end, to athena-engine #146's contract: the keyring is read,
    then the document is posted to ``POST /api/assurance/recovery-receipt/sign`` as
    ``{"receipt": <document>}``, once, with the recovery-receipt-signer key
    (``CYBERENGINE_RECOVERY_SIGNER_KEY``, ``ce_rr_``): never the operator key, never the
    exposure route's signer key."""
    from tests.conftest import TEST_ECONOMICS_SIGNER_KEY, TEST_RECOVERY_SIGNER_KEY

    seen, _ = engine
    finding = _incident("wire")
    _accepted(finding)
    answer = _issue(admin, finding)
    assert answer.status_code == 201, answer.content
    assert [(method, url) for method, url, _, _ in seen] == [("GET", ENGINE + KEYRING_ROUTE), ("POST", ENGINE + SIGN_ROUTE)]
    assert [headers["X-API-Key"] for _, _, headers, _ in seen] == [TEST_RECOVERY_SIGNER_KEY] * 2
    for _, _, headers, _ in seen:
        assert OPERATOR_KEY not in headers.values() and TEST_ECONOMICS_SIGNER_KEY not in headers.values()
    (_, _, _, body) = seen[1]
    assert set(body) == {"receipt"} and body["receipt"]["schema"] == core.RECEIPT_SCHEMA_V2
    assert RecoveryReceipt.objects.get(finding=finding).receipt_ref == body["receipt"]["receipt_ref"]


@pytest.mark.parametrize(
    ("where", "answer", "status", "code", "signer_code", "signer_status"),
    [
        ("keyring", requests.ConnectionError("refused"), 503, "engine_unreachable", None, None),
        ("keyring", "codeless-503", 503, "engine_unavailable", None, 503),
        ("sign", requests.ConnectionError("refused"), 503, "engine_unreachable", None, None),
        ("sign", requests.ReadTimeout("no answer"), 503, "engine_unreachable", None, None),
        ("sign", "gateway-502", 503, "engine_unreachable", None, 502),
        ("sign", "codeless-503", 503, "engine_unavailable", None, 503),
        ("sign", "not-configured", 503, "engine_unavailable", "signer_not_configured", 503),
        ("sign", "core-refused", 502, "receipt_refused_by_signer", "bad_key_id", 400),
        ("sign", "v1-refused", 502, "receipt_refused_by_signer", "wrong_schema", 400),
        ("sign", "not-a-core-code", 502, "receipt_refused_by_signer", "not_one_of_the_cores", 400),
        ("sign", "no-route", 502, "signer_refused", None, 404),
        ("sign", "key-refused", 502, "signer_refused", None, 403),
    ],
    ids=["keyring-unreachable", "keyring-unavailable", "unreachable", "timed-out", "gateway-502", "unavailable",
         "not-configured", "core-refused", "v1-refused", "not-a-core-code", "no-route", "key-refused"],
)
def test_an_engine_that_cannot_be_reached_or_refuses_stores_nothing_and_says_why(
    engine, admin, where, answer, status, code, signer_code, signer_status,
):
    seen, answers = engine
    answers[where] = {
        "gateway-502": _http(502, {"detail": "Bad Gateway"}),
        "codeless-503": _http(503, {"detail": "Rate limit store unavailable"}),
        "not-configured": _http(503, {"detail": {"code": "signer_not_configured", "reason": "no recovery-receipt key"}}),
        "core-refused": _http(400, {"detail": {"code": "bad_key_id", "reason": "support[0].key_id is required"}}),
        "v1-refused": _http(400, {"detail": {"code": "wrong_schema", "reason": "v2 alone is signed"}}),
        "not-a-core-code": _http(400, {"detail": {"code": "not_one_of_the_cores", "reason": "another rule"}}),
        "no-route": _http(404, {"detail": "Not Found"}),
        "key-refused": _http(403, {"detail": "Operator or Recovery-Receipt-Signer key required"}),
    }.get(answer, answer)
    finding = _incident("down")
    _accepted(finding)
    refused = _issue(admin, finding)
    assert refused.status_code == status, refused.content
    body = refused.json()
    assert (body["code"], body.get("signer_code"), body.get("signer_status")) == (code, signer_code, signer_status)
    if code in ("engine_unreachable", "engine_unavailable"):
        assert refused["Retry-After"] == str(rx.RETRY_AFTER_SECONDS)
    else:
        assert not refused.has_header("Retry-After")
    if code == "engine_unreachable":
        # Its own words: no text of the exception is quoted.
        assert body["detail"] == rx.REFUSALS["engine_unreachable"][1]
    assert not RecoveryReceipt.objects.exists()
    # One ask of each route at most: no retry on the request thread, and nothing signed
    # before the keyring was read.
    asked = [(method, url) for method, url, _, _ in seen]
    assert asked == ([("GET", ENGINE + KEYRING_ROUTE)] if where == "keyring" else
                     [("GET", ENGINE + KEYRING_ROUTE), ("POST", ENGINE + SIGN_ROUTE)])


@pytest.mark.parametrize(
    "configured",
    ["", OPERATOR_KEY, "synthetic-test-receipt-signer-key-for-ci-only-0000"],
    ids=["none", "the-operator-key", "not-a-recovery-signer-key"],
)
def test_without_a_recovery_signer_key_nothing_is_sent_and_no_other_key_is_sent_instead(engine, admin, configured):
    """The operator key is configured and the exposure signer's too; neither is ever sent
    instead. A recovery-signer setting that is missing, is the operator key, or is not a
    ``ce_rr_`` key is refused here: 503 ``signer_unavailable`` (no Retry-After: asking
    again changes nothing until it is set), and no request leaves at all."""
    seen, _ = engine
    finding = _incident("no-key")
    _accepted(finding)
    with override_settings(CYBERENGINE_RECOVERY_SIGNER_KEY=configured):
        refused = _issue(admin, finding)
    assert (refused.status_code, refused.json()["code"]) == (503, "signer_unavailable"), refused.content
    assert not refused.has_header("Retry-After")
    assert seen == [], "a request left with no recovery-receipt-signer key"
    assert configured == "" or configured not in json.dumps(refused.json())
    assert not RecoveryReceipt.objects.exists()


def test_the_recovery_signing_client_is_built_by_the_issuer_alone_and_its_key_read_by_name_in_the_client_alone():
    """No other call -- a stop least of all -- can present the recovery-receipt-signer key,
    and the key is read in one place, by its literal name. Settings files are never read
    here."""
    builders, readers = set(), set()
    for path in REPO.rglob("*.py"):
        relative = path.relative_to(REPO).as_posix()
        if relative.startswith(("tests/", ".venv/", "venv/", "node_modules/")) or "settings" in relative.lower():
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        if ".for_recovery_receipt_signing()" in text:
            builders.add(relative)
        if "CYBERENGINE_RECOVERY_SIGNER_KEY" in text:
            readers.add(relative)
    assert builders == {"assurance/recovery_receipts.py"}, builders
    assert readers == {"ai_engine/services/cyberengine_client.py"}, readers


@pytest.mark.django_db(transaction=True)
def test_the_engine_is_asked_outside_any_transaction(monkeypatch, admin):
    finding = _incident("no-lock")
    _accepted(finding)
    seen = []

    def keyring():
        seen.append(("keyring", connection.in_atomic_block))
        return rx.keyring_from_published(_published())

    def sign(document):
        seen.append(("sign", connection.in_atomic_block, RecoveryReceipt.objects.count()))
        return core.sign_receipt(document, _private())

    monkeypatch.setattr(rx, "engine_keyring", keyring)
    monkeypatch.setattr(rx, "engine_signer", sign)
    assert _issue(admin, finding).status_code == 201
    assert seen == [("keyring", False), ("sign", False, 0)]


# ----------------------------------------------- a receipt that no longer verifies


def test_a_stored_receipt_that_no_longer_verifies_reads_unknown(monkeypatch, signer, admin):
    finding = _incident("stale")
    _accepted(finding)
    assert _issue(admin, finding).status_code == 201
    (ok,) = _read(admin, finding)["receipts"]
    assert (ok["verified"], ok["standing"]) == (True, core.CURRENT)

    # The key revoked: the keyring holds it no more.
    monkeypatch.setattr(rx, "engine_keyring", lambda: rx.keyring_from_published(_published(receipt_status="revoked")))
    (revoked,) = _read(admin, finding)["receipts"]
    assert (revoked["verified"], revoked["verification"]["verdict"], revoked["standing"]) == (
        False, core.UNKNOWN_KEY, core.UNKNOWN,
    )
    assert revoked["receipt"] is None

    # No keyring at all: every receipt unknown, said, and the read still answers.
    def down():
        from ai_engine.services.cyberengine_client import ENGINE_UNREACHABLE, EngineError

        raise EngineError("Engine unreachable", kind=ENGINE_UNREACHABLE)

    monkeypatch.setattr(rx, "engine_keyring", down)
    read = _read(admin, finding)
    assert read["keyring"] == {"available": False, "code": "engine_unreachable", "detail": rx.REFUSALS["engine_unreachable"][1]}
    assert [r["standing"] for r in read["receipts"]] == [core.UNKNOWN]

    # The envelope rewritten past every guard: forged.
    monkeypatch.setattr(rx, "engine_keyring", lambda: rx.keyring_from_published(_published()))
    row = RecoveryReceipt.objects.get(finding=finding)
    RecoveryReceipt._base_manager.filter(pk=row.pk).update(envelope=_flipped(row.envelope))
    (forged,) = _read(admin, finding)["receipts"]
    assert (forged["verified"], forged["verification"]["verdict"], forged["standing"]) == (False, core.FORGED, core.UNKNOWN)
    # A receipt that does not verify is never superseded here.
    refused = _issue(admin, finding)
    assert (refused.status_code, refused.json()["code"]) == (409, "latest_receipt_unverified")
    assert RecoveryReceipt.objects.filter(finding=finding).count() == 1

    # A column rewritten past every guard: the envelope verifies, the row is not what it signed.
    RecoveryReceipt._base_manager.filter(pk=row.pk).update(envelope=row.envelope, record=str(uuid.uuid4()))
    (moved,) = _read(admin, finding)["receipts"]
    assert (moved["verified"], moved["verification"]["verdict"], moved["standing"]) == (False, core.AUTHENTIC, core.UNKNOWN)
    assert "record" in moved["verification"]["problem"]


# --------------------------------------------------------------- append-only


def test_an_issued_receipt_is_never_rewritten_or_deleted_and_a_row_says_what_it_signed(signer, admin):
    finding = _incident("kept")
    _accepted(finding)
    assert _issue(admin, finding).status_code == 201
    row = RecoveryReceipt.objects.get(finding=finding)
    stored = RecoveryReceipt._base_manager.filter(pk=row.pk).values().get()
    row.reason = "edited"
    with pytest.raises(RecoveryReceiptRewriteRefused):
        row.save()
    with pytest.raises(RecoveryReceiptRewriteRefused):
        row.delete()
    with pytest.raises(RecoveryReceiptRewriteRefused):
        RecoveryReceipt.objects.filter(pk=row.pk).update(reason="edited")
    with pytest.raises(RecoveryReceiptRewriteRefused):
        RecoveryReceipt.objects.filter(pk=row.pk).delete()
    # A new row whose columns are not what its envelope signed is refused at save.
    copied = RecoveryReceipt(
        finding=finding, sequence=2, receipt_ref=f"recovery-receipt:{uuid.uuid4()}", record=stored["record"],
        as_of=stored["as_of"], supersedes=stored["receipt_ref"], reason="recovery-record:x",
        envelope=stored["envelope"], key_id=stored["key_id"], issued_by_ref=stored["issued_by_ref"],
    )
    with pytest.raises(rx.ReceiptRowRefused):
        copied.save()
    assert RecoveryReceipt._base_manager.filter(pk=row.pk).values().get() == stored
    assert RecoveryReceipt.objects.count() == 1


# ----------------------------------------------------- the routes, and the head


def test_the_head_is_the_current_scope_and_the_latest_receipt_and_asks_no_engine(monkeypatch, signer, admin):
    finding = _incident("head")
    assert _as(admin).get(_url(finding, "head/")).json() == {"current_scope_revision": None, "latest_receipt_ref": None}
    _accepted(finding)
    ref = _issue(admin, finding).json()["receipt"]["receipt_ref"]

    def never(*args, **kwargs):
        raise AssertionError("the head asks no engine")

    monkeypatch.setattr(rx, "engine_keyring", never)
    monkeypatch.setattr(rx, "engine_signer", never)
    head = _as(admin).get(_url(finding, "head/"))
    assert head.status_code == 200
    assert head.json() == {"current_scope_revision": _revisions(finding)[-1].revision, "latest_receipt_ref": ref}
    # With no receipt, the list asks no engine either.
    other = _incident("none-yet")
    read = _read(admin, other)
    assert read == {
        "deployment": str(other.deployment.uuid), "finding": str(other.uuid), "as_of": read["as_of"],
        "head": {"current_scope_revision": None, "latest_receipt_ref": None}, "keyring": None, "receipts": [],
    }


def test_the_issue_is_an_admins_takes_no_body_and_reads_are_tenant_scoped(signer, admin):
    finding = _incident("routes")
    _accepted(finding)
    viewer = User.objects.create_user(username="receipt-viewer", password="x", role=User.Roles.VIEWER)
    Deployment.objects.create(name="viewers-own", owner=viewer)
    assert _issue(finding.deployment.owner, finding).status_code == 201  # the owner is an admin here
    refused = _as(admin).post(_url(finding), {"state": "recovery_accepted"}, format="json")
    assert (refused.status_code, refused.json()) == (400, {"state": "unknown field"})
    absent = _as(admin).post(f"/api/assurance/findings/{uuid.uuid4()}/recovery-receipts/", {}, format="json")
    assert absent.status_code == 404
    # A viewer who cannot see the finding is answered as for one that does not exist.
    theirs, nobodys = _as(viewer).get(_url(finding)), _as(viewer).get(f"/api/assurance/findings/{uuid.uuid4()}/recovery-receipts/")
    assert theirs.status_code == nobodys.status_code == 404
    assert _as(viewer).post(_url(finding), {}, format="json").status_code in (403, 404)
    assert RecoveryReceipt.objects.count() == 1
    nobody = _incident("no-record")
    answer = _issue(admin, nobody)
    assert (answer.status_code, answer.json()["code"]) == (409, "no_recovery_record")
    assert Finding.objects.filter(pk=nobody.pk).exists()


def test_every_route_declares_its_class_and_none_is_a_stop():
    for route, methods in (
        ("finding-recovery-receipts", {"GET": degraded.EVIDENCE_READ, "POST": degraded.EFFECT}),
        ("finding-recovery-receipts-head", {"GET": degraded.EVIDENCE_READ}),
    ):
        assert degraded.ROUTES[route] == methods
        assert route not in stops.STOP_ROUTES and route not in stops.EXEMPT_ROUTES
        assert set(stops.NOT_STOPS[route]) == set(methods)
    assert stops.NOT_STOPS["finding-recovery-receipts"]["POST"] == (
        "issues a signed recovery receipt: its own append-only table; it starts and stops nothing"
    )


def test_the_migration_only_adds_the_receipts_table():
    import importlib

    migration = importlib.import_module("assurance.migrations.0089_the_backend_issues_recovery_receipts").Migration
    assert migration.dependencies == [("assurance", "0088_the_record_says_what_a_receipt_could")]
    assert [(type(o).__name__, o.name) for o in migration.operations] == [("CreateModel", "RecoveryReceipt")]
    call_command("makemigrations", "--check", "--dry-run", verbosity=0)


def test_nothing_of_the_receipt_loads_with_the_url_conf_or_with_this_module():
    """The URL conf loads on whatever request a worker serves first, a stop included: it
    loads the issuer, which reads the core's receipt and the engine client at first use."""
    probe = (
        "import sys, django; django.setup(); import config.urls, assurance.recovery_receipts;"
        "sys.exit(3 if 'mythos_core.recovery_receipt' in sys.modules else 0)"
    )
    ran = subprocess.run([sys.executable, "-c", probe], cwd=REPO, env=dict(os.environ), capture_output=True, timeout=120)
    assert ran.returncode == 0, ran.stderr.decode(errors="replace")[-600:]
    tree = ast.parse((REPO / "assurance" / "recovery_receipts.py").read_text(encoding="utf-8"))
    top = {
        name for node in tree.body if isinstance(node, (ast.Import, ast.ImportFrom))
        for name in (getattr(node, "module", None) or "", *(alias.name for alias in node.names))
    }
    assert not any(name.startswith(("ai_engine", "mythos_core.recovery_receipt", "mythos_core.outcome")) for name in top)
    # Nothing a stop runs through imports it (settings files are never read here).
    for package in ("safety", "failsafe", "pentest"):
        for path in sorted((REPO / package).rglob("*.py")):
            if "migrations" in path.parts or "settings" in path.name.lower():
                continue
            names = {
                name for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
                if isinstance(node, (ast.Import, ast.ImportFrom))
                for name in (getattr(node, "module", None) or "", *(alias.name for alias in node.names))
            }
            assert not any("recovery_receipt" in name for name in names), path
