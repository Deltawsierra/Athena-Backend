"""The observed-effect record is Mythos-Core's, and version 5 is taken in.

Until Mythos-Core#83 this backend read the ``mythos.observed-effect`` document and its
reconciliation receipt with rules of its own, kept by hand beside another copy in Achilles; the
two had drifted. ``mythos_core.observed_effect`` is now the one definition, and
:mod:`assurance.observed_effects` and :mod:`assurance.effect_reconciliation` ask it for every
check. This file holds that:

* **every core vector**, of every version, goes through this backend's own intake: each valid one
  is taken in, each invalid one is refused with the core's code;
* **a stored record reads exactly as it did on master**: 9,501 documents built from the version 1
  to 4 vectors and the version 1 receipts, against what master answered for each
  (``tests/fixtures/observed_effect_read_on_master.json``), and the reads a stored row goes through;
* **version 5** is read: keyed references compared under one key id by the core, the tool binding
  and the execution served, a plain digest refused, and a record judged, never refused, for a
  binding whose bound is larger than an approval's;
* **the intake's bound** is the core's, for this route only, and a byte more is refused before the
  body is parsed;
* **a reader's words** for an older record are the core's;
* **nothing is kept by hand** beside the core, and the core is not loaded with the URL conf.

On master every test here fails: there is no ``mythos_core.observed_effect`` at master's pin.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
import os
import subprocess
import sys
import uuid
from datetime import datetime, timedelta, timezone as dt_timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib.auth import get_user_model
from mythos_core import observed_effect as core
from mythos_core import outcome as oc
from rest_framework.test import APIClient

from assurance import authority_chain as rule
from assurance import composition as comp
from assurance import effect_reconciliation, identity_evidence, observed_effects, observed_outcomes
from assurance.models import Deployment, EffectReconciliationReceipt, WorkflowChainOutcome
from tests import observed_effect_corpus as corpus
from tests.test_spine_authority_chain import _admin, _base, _client

User = get_user_model()
TOKEN = "observed-effect-service-token-for-tests-0123456789"  # pragma: allowlist secret
VECTORS = Path(__file__).resolve().parent / "vectors"
REPO = Path(__file__).resolve().parent.parent

#: Every vector file this backend carries of the record, and the sha256 of each: byte for byte
#: Mythos-Core's own (its ``tests/vectors/`` at the pinned commit; the core does not install them).
VECTOR_FILES = {
    "observed-effect-v1.json": "f00db98f243e9c747dce06cd0647ac31acf6172336ef527a9d4b924896281a31",
    "observed-effect-v2.json": "3692ed413f78049c244148b969c511e0b00caf7af60c061361eb2aa4bb0dea46",
    "observed-effect-v3.json": "eaddf06dc3f6cbe7e6b163b8e5346c60a80dd1ffc43cf2661242b67ae5114d89",
    "observed-effect-v4.json": "e2c36d58cd7522e71d33ad3b449fd3c7ce8d9d7faa7342a60a5a39c2b2204f87",
    "observed-effect-v5.json": "bc1154bc51c3e7159233b19808ab5d1ce7b85481af412775d004d0a99af1fbb4",
    "effect-reconciliation-v1.json": "caccb2b8b434aad4c4be7760a1581b8318e8c9a12bb35fc406179a9014b26e42",
    "effect-reconciliation-v2.json": "a690ba0f40380a4f92912a5e56191ab4cd28bd93dcd82c10c72d2f74083af9fb",
}
EFFECT_FILES = [name for name in VECTOR_FILES if name.startswith("observed-effect")]
RECEIPT_FILES = [name for name in VECTOR_FILES if name.startswith("effect-reconciliation")]


def _vector(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def _wire(hexed: dict) -> dict:
    """An envelope as posted, from the vector's hex spelling; a field kept as posted is kept."""
    out = {k: v for k, v in hexed.items() if k not in ("payload_hex", "signatures")}
    if "payload_hex" in hexed:
        out["payload"] = base64.b64encode(bytes.fromhex(hexed["payload_hex"])).decode()
    if "signatures" in hexed:
        out["signatures"] = [
            {"keyid": s["keyid"], "sig": base64.b64encode(bytes.fromhex(s["sig_hex"])).decode()}
            if isinstance(s, dict) and set(s) == {"keyid", "sig_hex"}
            else s
            for s in hexed["signatures"]
        ]
    return out


def _key(phrase: str) -> Ed25519PrivateKey:
    """A vector's test key: made from its phrase, as the vector says, never a real one."""
    return Ed25519PrivateKey.from_private_bytes(hashlib.sha256(phrase.encode()).digest())


def _instant(text: str) -> datetime:
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt_timezone.utc)


def _code(reason: str) -> str:
    """The code a refusal says first (``code: reason``)."""
    return reason.split(":", 1)[0]


@pytest.fixture
def service(monkeypatch):
    """The observed-effect service: its credential, and the account it authenticates as."""
    User.objects.create_user(username="effect-service", password="x")
    monkeypatch.setenv(observed_effects.TOKEN_ENV, TOKEN)
    monkeypatch.setenv(observed_effects.USER_ENV, "effect-service")
    client = APIClient()
    client.credentials(HTTP_X_OBSERVED_EFFECT_TOKEN=TOKEN)
    return client


@pytest.fixture
def at(monkeypatch):
    """Set the intake's clock: a vector's instants are fixed, and the intake takes a record
    only within its window."""

    def set_clock(now: datetime) -> None:
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return now if tz is None else now.astimezone(tz)

        monkeypatch.setattr(observed_outcomes, "datetime", Clock)
        monkeypatch.setattr(effect_reconciliation, "datetime", Clock)

    return set_clock


@pytest.fixture
def trust(tmp_path, monkeypatch):
    """Configure the outcome keyring from public keys: ``trust({engine: public key hex})``."""

    def write(keys: dict[str, str]) -> None:
        path = tmp_path / "vector-keyring.json"
        path.write_text(
            json.dumps(
                [
                    {"engine": engine, "public_key": base64.b64encode(bytes.fromhex(public)).decode()}
                    for engine, public in keys.items()
                ]
            )
        )
        monkeypatch.setenv(observed_outcomes.KEYRING_ENV, str(path))

    return write


def _deployment(token: str) -> Deployment:
    return Deployment.objects.create(name=f"vector-{token[-4:]}", owner=_admin(), uuid=uuid.UUID(token))


def _post_effect(service, dep, envelope, evidence):
    return service.post(_base(dep) + "observed-effects/", {"envelope": envelope, "evidence": evidence}, format="json")


def _post_receipt(service, dep, envelope):
    return service.post(_base(dep) + "effect-reconciliations/", {"envelope": envelope}, format="json")


def _refusal(response) -> str:
    """The one reason a refused post gives, whichever of the route's two refusals it is."""
    body = response.json()
    if "refused" in body:
        return body["refused"][0]["reason"]
    said = body["evidence"]
    return said[0] if isinstance(said, list) else said


def _sign_effect(evidence: dict, key: Ed25519PrivateKey, *, engine: str = core.ENGINE) -> dict:
    """An outcome signed over ``evidence``, as the observed-effect key signs one."""
    outcome = oc.build_outcome(
        deployment=evidence["deployment"],
        workflow=evidence["workflow"],
        status=oc.HELD,
        engine=engine,
        engine_version="0.1.0",
        run_id=f"run-{uuid.uuid4().hex[:8]}",
        evidence_digest=oc.evidence_digest_of(evidence),
        observed_at=_instant(evidence["observed_at"]),
    )
    return oc.sign_outcome(outcome, key)


def _sign_receipt(document, key: Ed25519PrivateKey) -> dict:
    """``document``, signed under the receipt's payload type whatever it holds: so a document
    that is no receipt reaches the rule that refuses it."""
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    signature = key.sign(oc.pae(core.RECONCILIATION_PAYLOAD_TYPE, payload))
    return {
        "payloadType": core.RECONCILIATION_PAYLOAD_TYPE,
        "payload": base64.b64encode(payload).decode(),
        "signatures": [{"keyid": oc.key_id_for(oc.raw_public_key(key)), "sig": base64.b64encode(signature).decode()}],
    }


# ---------------------------------------------------------------- the vector files


def test_every_vector_file_is_the_cores_byte_for_byte():
    """Seven files, each the sha256 of the core's own. Athena-Backend had no version 4 file:
    it gains every version through the core."""
    found = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(VECTORS.glob("*effect*.json"))}
    assert found == VECTOR_FILES
    assert _vector("observed-effect-v5.json")["max_evidence_bytes"] == core.MAX_EVIDENCE_BYTES


# --------------------------------------- every core vector, through this backend's intake


@pytest.mark.django_db
@pytest.mark.parametrize("name", EFFECT_FILES)
def test_every_observed_effect_vector_goes_through_the_intake(service, trust, at, name):
    """Each valid document is taken in, and stored as signed; each invalid one is refused with
    the core's code; each refused envelope is refused with the core's code."""
    v = _vector(name)
    evidence = v["evidence"]
    assert evidence["schema"] == v["schema"] in observed_effects.EVIDENCE_SCHEMAS
    trust({v["effect_engine"]: v["effect_public_key_hex"], "achilles": v["gate_public_key_hex"]})
    at(_instant(evidence["observed_at"]) + timedelta(minutes=1))
    dep = _deployment(evidence["deployment"])

    # Invalid first, against an empty record: nothing of any of them is stored.
    assert len(v["invalid"]) >= {1: 11, 2: 19, 3: 28, 4: 40, 5: 87}[int(name[-6])]
    for case in v["invalid"]:
        try:
            core.validate_evidence(copy.deepcopy(case["evidence"]))
        except core.EvidenceRefused as exc:
            expected = exc.code
        else:
            raise AssertionError(f"the core accepts an invalid vector: {case['why']}")
        assert case.get("code", expected) == expected, case["why"]
        refused = _post_effect(service, dep, _wire(v["envelope"]), case["evidence"])
        assert refused.status_code == 400, (case["why"], refused.content[:300])
        assert _code(_refusal(refused)) == expected, (case["why"], _refusal(refused)[:200])
    for case in v.get("refused_envelopes", []):
        refused = _post_effect(service, dep, _wire(case["envelope"]), case["evidence"])
        assert refused.status_code == 400, (case["why"], refused.content[:300])
        assert _code(_refusal(refused)) == case["code"], (case["why"], _refusal(refused)[:200])
        verdict = core.verify_observed_effect(_wire(case["envelope"]), case["evidence"], observed_outcomes.load_keyring())
        assert (verdict.verdict, verdict.code) == (case["verdict"], case["code"])
    assert not WorkflowChainOutcome.objects.filter(deployment=dep).exists()

    valid = [(v["envelope"], evidence, "the vector's own")]
    valid += [(case["envelope"], case["evidence"], case["why"]) for case in v.get("also_valid", [])]
    taken = 0
    for envelope, document, why in valid:
        sent = _post_effect(service, dep, _wire(envelope), document)
        if document["deployment"] != str(dep.uuid):
            # The core's largest document names a 200-character deployment, which no deployment
            # here can be (a uuid). It is not refused for its size or for anything it holds --
            # the core's verifier, asked as the intake asks it, finds it authentic -- only for
            # the deployment it names. The largest document a deployment here CAN post is taken
            # in below (test_a_body_at_the_bound_is_taken_in_and_one_byte_over_is_refused_unparsed).
            assert len(oc.canonical_bytes(document)) == core.MAX_EVIDENCE_BYTES, why
            assert core.verify_observed_effect(_wire(envelope), document, observed_outcomes.load_keyring()).authentic
            assert sent.status_code == 400 and "not this one" in _refusal(sent), sent.content[:300]
            continue
        assert sent.status_code == 201, (why, sent.content[:300])
        row = WorkflowChainOutcome.objects.get(effect_dispatch_id=document["dispatch_id"])
        assert row.effect_evidence == document and row.evidence_digest == oc.evidence_digest_of(document)
        assert observed_effects.evidence_in_force(row, str(dep.uuid)) == document
        taken += 1
    assert taken == WorkflowChainOutcome.objects.filter(deployment=dep).count() >= 1
    assert taken == (4 if name == "observed-effect-v5.json" else 1)


@pytest.mark.django_db
@pytest.mark.parametrize("name", RECEIPT_FILES)
def test_every_reconciliation_vector_goes_through_the_intake(service, trust, at, name):
    v = _vector(name)
    key = _key(v["effect_key_phrase"])
    assert oc.raw_public_key(key).hex() == v["effect_public_key_hex"]
    assert v["schema"] in effect_reconciliation.SCHEMAS and v["payload_type"] == effect_reconciliation.PAYLOAD_TYPE
    trust({v["effect_engine"]: v["effect_public_key_hex"], "achilles": v["gate_public_key_hex"]})
    documents = [case["document"] for case in v["valid"]]
    at(max(_instant(d["readback"]["read_at"]) for d in documents) + timedelta(minutes=1))
    (token,) = {d["deployment"] for d in documents}
    dep = _deployment(token)

    for case in v["invalid_documents"]:
        try:
            core.validate_reconciliation(copy.deepcopy(case["document"]))
        except core.EvidenceRefused as exc:
            expected = exc.code
        else:
            raise AssertionError(f"the core accepts an invalid receipt: {case['why']}")
        assert case.get("code", expected) == expected, case["why"]
        refused = _post_receipt(service, dep, _sign_receipt(case["document"], key))
        assert refused.status_code == 400, (case["why"], refused.content[:300])
        assert _code(_refusal(refused)) == expected, (case["why"], _refusal(refused)[:200])
    for case in v["invalid_envelopes"]:
        expected = core.verify_reconciliation(_wire(case["envelope"]), observed_outcomes.load_keyring())
        assert not expected.authentic
        assert (case.get("verdict", expected.verdict), case.get("code", expected.code)) == (expected.verdict, expected.code)
        refused = _post_receipt(service, dep, _wire(case["envelope"]))
        assert refused.status_code == 400, (case["why"], refused.content[:300])
        assert _code(_refusal(refused)) == expected.code, (case["why"], _refusal(refused)[:200])
    assert not EffectReconciliationReceipt.objects.exists()

    for case in v["valid"]:
        envelope, document = _wire(case["envelope"]), case["document"]
        sent = _post_receipt(service, dep, envelope)
        assert sent.status_code == 201, (case["name"], sent.content[:300])
        row = EffectReconciliationReceipt.objects.get(receipt_id=document["receipt_id"])
        assert row.envelope == envelope
        assert effect_reconciliation.in_force(row, observed_outcomes.load_keyring()) == document
        read = effect_reconciliation.as_reconciliation(document)
        if document["schema"] == core.RECONCILIATION_SCHEMA_V2:
            assert (read.action_digest, read.action_ref) == ("", document["action_ref"])
            assert read.keyed_under == (document["keyed_under"]["chain"], document["keyed_under"]["chain_key"])
        else:
            assert (read.action_digest, read.action_ref, read.keyed_under) == (document["action_digest"], "", None)
    assert EffectReconciliationReceipt.objects.count() == len(v["valid"]) == 5


# ------------------------------------------- a stored record reads as it did on master


def test_every_stored_document_reads_exactly_as_master_read_it():
    """The corpus (:mod:`tests.observed_effect_corpus`): every version 1 to 4 document and
    version 1 receipt of the vectors, altered one field at a time. What master accepted, the
    core accepts; what master refused, the core refuses. Not one document reads differently.

    The one difference is not a reading: on 52 documents (a tool ``kind`` that is a list or an
    object) master raised a TypeError -- at the intake a 500, so no such row was ever stored --
    and the core refuses each with a code."""
    recorded = json.loads(corpus.RECORDED.read_text(encoding="utf-8"))
    found = corpus.read_all(
        observed_effects.validate_evidence,
        observed_effects.EvidenceRefused,
        effect_reconciliation.validate_receipt,
        effect_reconciliation.ReceiptRefused,
    )
    assert (found["fingerprint"], found["documents"]) == (recorded["fingerprint"], recorded["documents"])
    assert found["documents"] == 9501 and set(found["bases"]) == set(recorded["bases"])
    accepted = errors = 0
    for base, master in recorded["bases"].items():
        mine = found["bases"][base]
        assert mine["documents"] == master["documents"], base
        assert mine["accepted"] == master["accepted"], (
            base,
            sorted(set(mine["accepted"]) ^ set(master["accepted"]))[:5],
        )
        assert mine["errors"] == {}, base
        assert set(master["errors"].values()) <= {"error: TypeError"}, base
        assert all("kind" in label for label in master["errors"]), base
        accepted += len(master["accepted"])
        errors += len(master["errors"])
    assert (accepted, errors) == (1092, 52)


def test_a_stored_row_is_in_force_only_as_what_its_digest_names():
    """The read every stored observed effect goes through, for each version: the row as stored
    reads as its document, byte for byte; a column or a document edited after the fact reads as
    no document."""

    class Row:
        def __init__(self, **columns):
            self.__dict__.update(columns)

    for name in EFFECT_FILES:
        document = _vector(name)["evidence"]
        stored = {
            "effect_evidence": copy.deepcopy(document),
            "evidence_digest": oc.evidence_digest_of(document),
            "workflow": document["workflow"],
            "effect_dispatch_id": document["dispatch_id"],
        }
        deployment = document["deployment"]
        read = observed_effects.evidence_in_force(Row(**stored), deployment)
        assert read == document and oc.canonical_bytes(read) == oc.canonical_bytes(document), name
        edited = {**copy.deepcopy(document), "action": "another:action"}
        for change in (
            {"evidence_digest": "sha256:" + "0" * 64},
            {"workflow": "other"},
            {"effect_dispatch_id": "0" * 32},
            {"effect_evidence": edited},
            {"effect_evidence": None},
            {"effect_evidence": {**copy.deepcopy(document), "schema": "mythos.observed-effect/v6"}},
        ):
            assert observed_effects.evidence_in_force(Row(**{**stored, **change}), deployment) is None, (name, change)
        assert observed_effects.evidence_in_force(Row(**stored), "another-deployment") is None
        recipients = observed_effects.approval_recipients(Row(**stored), deployment)
        if name in ("observed-effect-v4.json", "observed-effect-v5.json"):
            assert recipients == document["dispatch"]["verified"]["approval_recipients"]
        else:
            assert recipients is None, name
    # A version 5 row whose document holds a plain digest is no document, whatever its
    # digest column says: the read asks the core too, not only the intake.
    v5 = _vector("observed-effect-v5.json")
    plain = {**copy.deepcopy(v5["evidence"]), "action_ref": v5["inputs"]["action_digest"]}
    row = Row(
        effect_evidence=plain,
        evidence_digest=oc.evidence_digest_of(plain),
        workflow=plain["workflow"],
        effect_dispatch_id=plain["dispatch_id"],
    )
    assert observed_effects.evidence_in_force(row, plain["deployment"]) is None


# ------------------------------------------------------------------- the intake's bound


def _largest_for(dep) -> tuple[dict, dict]:
    """The largest document a deployment here can post: the core's largest, naming this
    deployment (a uuid, where the core's names 200 characters), signed by the vector's key."""
    v = _vector("observed-effect-v5.json")
    (largest,) = [c["evidence"] for c in v["also_valid"] if len(oc.canonical_bytes(c["evidence"])) == core.MAX_EVIDENCE_BYTES]
    document = copy.deepcopy(largest)
    document["deployment"] = str(dep.uuid)
    document["dispatch"]["verified"]["workflow_approval"]["deployment"] = str(dep.uuid)
    assert core.validate_evidence(copy.deepcopy(document)) == document
    return _sign_effect(document, _key(v["effect_key_phrase"])), document


@pytest.mark.django_db
def test_a_body_at_the_bound_is_taken_in_and_one_byte_over_is_refused_unparsed(service, trust, at, monkeypatch):
    v = _vector("observed-effect-v5.json")
    trust({v["effect_engine"]: v["effect_public_key_hex"]})
    dep = Deployment.objects.create(name="at-the-bound", owner=_admin())
    envelope, document = _largest_for(dep)
    at(_instant(document["observed_at"]) + timedelta(minutes=1))
    bound = observed_effects.MAX_BODY_BYTES
    body = json.dumps({"envelope": envelope, "evidence": document}, separators=(",", ":"), ensure_ascii=False).encode()
    # The largest document and its envelope fit, with room to spare for an envelope at ITS bound.
    assert core.MAX_EVIDENCE_BYTES - 200 < len(body) < bound
    url = _base(dep) + "observed-effects/"

    from config.parsers import SafeJSONParser

    parsed = []
    real = SafeJSONParser.parse

    def counting(self, stream, media_type=None, parser_context=None):
        parsed.append(1)
        return real(self, stream, media_type, parser_context)

    monkeypatch.setattr(SafeJSONParser, "parse", counting)

    over = service.post(url, body + b" " * (bound + 1 - len(body)), content_type="application/json")
    assert over.status_code == 413, over.content[:200]
    assert parsed == [], "a body one byte over the bound is refused before it is parsed"
    junk = service.post(url, b"x" * (bound + 1), content_type="application/json")
    assert junk.status_code == 413 and parsed == []
    assert not WorkflowChainOutcome.objects.filter(deployment=dep).exists()

    exactly = service.post(url, body + b" " * (bound - len(body)), content_type="application/json")
    assert exactly.status_code == 201, exactly.content[:300]
    assert parsed == [1]
    row = WorkflowChainOutcome.objects.get(effect_dispatch_id=document["dispatch_id"])
    assert row.effect_evidence == document
    assert len(oc.canonical_bytes(row.effect_evidence)) == core.MAX_EVIDENCE_BYTES - (200 - 36) * 2


def test_the_bound_is_read_from_the_core_and_no_other_routes_bound_moved(monkeypatch):
    """One envelope and one version 5 document, both the core's numbers: 456,634 bytes where
    master took 81,920. Nothing is typed in here: when the core's number moves, this one does."""
    assert core.MAX_EVIDENCE_BYTES == 391_098 and oc.MAX_PAYLOAD_B64 == 65_536
    assert observed_effects.MAX_BODY_BYTES == oc.MAX_PAYLOAD_B64 + core.MAX_EVIDENCE_BYTES == 456_634
    monkeypatch.setattr(core, "MAX_EVIDENCE_BYTES", 1_000)
    assert observed_effects.MAX_BODY_BYTES == oc.MAX_PAYLOAD_B64 + 1_000
    monkeypatch.undo()
    source = (REPO / "assurance" / "observed_effects.py").read_text(encoding="utf-8")
    for typed in ("391", "456", "81920", "81_920", "16 * 1024"):
        assert typed not in source, f"{typed} is typed into assurance/observed_effects.py"
    # The other routes that take a signed record: each bound is what it is on master.
    assert effect_reconciliation.MAX_BODY_BYTES == 64 * 1024 + 4 * 1024 == 69_632
    assert identity_evidence.MAX_BODY_BYTES == 64 * 1024 + 16 * 1024 == 81_920
    assert observed_outcomes.MAX_BODY_BYTES == 20 * (64 * 1024 + 2048) == 1_351_680


@pytest.mark.django_db
def test_the_receipt_route_still_refuses_what_the_effect_route_now_takes(service):
    dep = Deployment.objects.create(name="other-route", owner=_admin())
    size = effect_reconciliation.MAX_BODY_BYTES + 1
    assert size < observed_effects.MAX_BODY_BYTES
    body = b'{"envelope":"' + b"x" * (size - 15) + b'"}'
    assert len(body) == size
    assert service.post(_base(dep) + "effect-reconciliations/", body, content_type="application/json").status_code == 413
    assert service.post(_base(dep) + "observed-effects/", body, content_type="application/json").status_code == 400


# ------------------------------------------------------- version 5, read and served


def _taken_in(service, trust, at, name: str, *, change=None):
    """A vector's document taken in through the route (``change`` alters it first, signed again
    by the vector's key); the deployment and the row."""
    v = _vector(name)
    document = copy.deepcopy(v["evidence"])
    envelope = _wire(v["envelope"])
    if change is not None:
        change(document)
        envelope = _sign_effect(document, _key(v["effect_key_phrase"]))
    trust({v["effect_engine"]: v["effect_public_key_hex"]})
    at(_instant(document["observed_at"]) + timedelta(minutes=1))
    dep = Deployment.objects.filter(uuid=document["deployment"]).first() or _deployment(document["deployment"])
    sent = _post_effect(service, dep, envelope, document)
    assert sent.status_code == 201, sent.content[:300]
    return dep, WorkflowChainOutcome.objects.get(effect_dispatch_id=document["dispatch_id"]), document


def _served(dep, row) -> dict:
    listed = _client(_admin()).get(_base(dep) + "chain-outcomes/").json()
    rows = listed["outcomes"] if isinstance(listed, dict) else listed
    (found,) = [r for r in rows if r["outcome_id"] == row.outcome_id]
    return found


@pytest.mark.django_db
def test_a_v5_record_is_served_with_its_keyed_references_its_binding_and_its_execution(service, trust, at):
    dep, row, document = _taken_in(service, trust, at, "observed-effect-v5.json")
    served = _served(dep, row)
    binding = document["dispatch"]["verified"]["tool_binding"]
    assert served["effect_reading"] == {
        "schema": "mythos.observed-effect/v5",
        "digests": core.KEYED_NOT_CHECKABLE,
        "digests_served": core.KEYED_NOT_CHECKABLE,
        "action_reference": document["action_ref"],
        "response_reference": document["observed"]["response_ref"],
        "keyed_under": document["keyed_under"],
        "execution": {"state": "accepted", "basis": "observed", "words": core.ACCEPTED_AS_SIGNED},
        "tool_binding": binding,
        "tool_binding_reading": core.WITHIN_ITS_BOUND,
        "findings": [],
    }
    assert core.KEYED_NOT_CHECKABLE == "keyed: not checkable here"
    assert binding["identifier"] == document["tool"]["identifier"] and binding["target_count"] <= binding["max_targets"]
    assert {a["counted"] is None for a in binding["approvals"]} == {True, False}
    assert served["approval_recipients"] == document["dispatch"]["verified"]["approval_recipients"]
    # No plain digest of the action, the answer or a population is served anywhere on the row.
    assert not core.holds_plain_digest(served, [_vector("observed-effect-v5.json")["inputs"]["action_digest"]])
    assert "action_digest" not in json.dumps(served)


@pytest.mark.django_db
def test_a_v5_record_whose_permit_bound_no_tool_says_no_bound_was_recorded(service, trust, at):
    def unbind(document):
        document["dispatch"]["verified"]["tool_binding"] = None
        document["dispatch_id"] = uuid.uuid4().hex

    dep, row, _ = _taken_in(service, trust, at, "observed-effect-v5.json", change=unbind)
    reading = _served(dep, row)["effect_reading"]
    assert (reading["tool_binding"], reading["tool_binding_reading"]) == (None, core.NO_BOUND_RECORDED)
    assert core.NO_BOUND_RECORDED == "no bound recorded" and reading["findings"] == []


@pytest.mark.django_db
@pytest.mark.parametrize("name", EFFECT_FILES[:4])
def test_an_older_record_is_read_in_the_cores_words(service, trust, at, name):
    """Plain digests, withheld from this reader; no tool binding recorded, never "within its
    bound"; accepted, from the recorded 2xx, never "committed". And the stored record is
    untouched: it still verifies."""
    dep, row, document = _taken_in(service, trust, at, name)
    served = _served(dep, row)
    assert served["effect_reading"] == {
        "schema": document["schema"],
        "digests": "plain digests",
        "digests_served": "plain digests: withheld from this reader",
        "action_reference": "withheld:plain-digest",
        "response_reference": "withheld:plain-digest",
        "keyed_under": None,
        "execution": {
            "state": "accepted",
            "basis": "inferred",
            "words": "accepted, from the recorded 2xx; this version has no execution field",
        },
        "tool_binding": None,
        "tool_binding_reading": "no tool binding recorded",
        "findings": [],
    }
    reading = served["effect_reading"]
    assert reading["digests"] == core.digests_reading(document) == core.PLAIN_DIGESTS
    assert reading["digests_served"] == core.withhold_plain_digests(document)[1] == core.PLAIN_DIGESTS_WITHHELD
    assert reading["tool_binding_reading"] == core.tool_binding_reading(document) == core.NO_TOOL_BINDING_RECORDED
    assert reading["execution"]["words"] == core.execution_reading(document).words == core.ACCEPTED_NO_EXECUTION_FIELD
    text = json.dumps(served)
    assert document["action_digest"] not in text and document["observed"]["response_digest"] not in text
    assert "committed" not in text and "within its bound" not in text
    row.refresh_from_db()
    assert row.effect_evidence == document and observed_effects.evidence_in_force(row, str(dep.uuid)) == document


@pytest.mark.django_db
def test_a_row_that_is_no_observed_effect_in_force_has_no_reading(service, trust, at):
    dep, row, document = _taken_in(service, trust, at, "observed-effect-v5.json")
    WorkflowChainOutcome.objects.filter(pk=row.pk).update(effect_evidence={**document, "action": "another:action"})
    served = _served(dep, row)
    assert served["effect_reading"] is None and served["approval_recipients"] is None


@pytest.mark.django_db
def test_a_binding_larger_than_an_approvals_bound_is_taken_in_and_judged_never_refused(service, trust, at):
    """It is evidence of what was dispatched: refusing it at the intake would lose the record
    for good. The record's reading says it, as a named finding."""
    raised = {}

    def raise_the_bound(document):
        binding = document["dispatch"]["verified"]["tool_binding"]
        (limited,) = [a for a in binding["approvals"] if a["max_targets"] is not None]
        binding["max_targets"] = limited["max_targets"] + 5
        raised.update(approval=limited["approval"], limit=limited["max_targets"], bound=binding["max_targets"])
        document["dispatch_id"] = uuid.uuid4().hex

    dep, row, document = _taken_in(service, trust, at, "observed-effect-v5.json", change=raise_the_bound)
    assert row.effect_evidence == document
    reading = _served(dep, row)["effect_reading"]
    (finding,) = reading["findings"]
    assert finding["code"] == observed_effects.BINDING_BOUND_OVER_APPROVAL == "binding_bound_over_approval"
    assert (finding["approval"], finding["approval_max_targets"], finding["binding_max_targets"]) == (
        raised["approval"],
        raised["limit"],
        raised["bound"],
    )
    assert reading["tool_binding"]["max_targets"] == raised["bound"]
    # What the core holds a binding to is still refused, by the core: a population over its bound.
    over = copy.deepcopy(document)
    over["dispatch"]["verified"]["tool_binding"]["target_count"] = raised["bound"] + 1
    with pytest.raises(observed_effects.EvidenceRefused) as refused:
        observed_effects.validate_evidence(over)
    assert refused.value.code == "over_bound"


@pytest.mark.django_db
def test_a_v5_document_holding_a_plain_digest_is_refused_with_the_cores_code(service, trust, at):
    v = _vector("observed-effect-v5.json")
    trust({v["effect_engine"]: v["effect_public_key_hex"]})
    document = v["evidence"]
    at(_instant(document["observed_at"]) + timedelta(minutes=1))
    dep = _deployment(document["deployment"])
    key = _key(v["effect_key_phrase"])
    plain = v["inputs"]["action_digest"]

    def put(path, value):
        changed = copy.deepcopy(document)
        target = changed
        for step in path[:-1]:
            target = target[step]
        target[path[-1]] = value
        return changed

    def renamed(changed, old, new, *path):
        target = changed
        for step in path:
            target = target[step]
        target[new] = target.pop(old)
        return changed

    binding = ("dispatch", "verified", "tool_binding")
    cases = {
        "the action's plain digest where its reference belongs": put(("action_ref",), plain),
        "the same, with its prefix": put(("action_ref",), "sha256:" + plain),
        "the same, in capitals": put(("action_ref",), plain.upper()),
        "the answer's": put(("observed", "response_ref"), "sha256:" + "12" * 32),
        "a population's": put((*binding, "targets_ref"), "ab" * 32),
        "an approval's population's": put((*binding, "approvals", 0, "targets_ref"), "sha256:" + "cd" * 32),
        "a field of the action digest's name": renamed(copy.deepcopy(document), "action_ref", "action_digest"),
        "a field of the answer digest's name": renamed(copy.deepcopy(document), "response_ref", "response_digest", "observed"),
        "a field of the population digest's name": renamed(copy.deepcopy(document), "targets_ref", "targets_digest", *binding),
    }
    for why, changed in cases.items():
        refused = _post_effect(service, dep, _sign_effect(changed, key), changed)
        assert refused.status_code == 400, (why, refused.content[:200])
        assert _code(_refusal(refused)) == "plain_digest", (why, _refusal(refused)[:200])
    withheld = put(("action_ref",), "withheld:chain-key-unkept")
    refused = _post_effect(service, dep, _sign_effect(withheld, key), withheld)
    assert refused.status_code == 400 and _code(_refusal(refused)) == "bad_ref"
    assert not WorkflowChainOutcome.objects.filter(deployment=dep).exists()


# ------------------------------------ what the backend matches by reference, and cannot


WF = "crm-update"
T = datetime(2026, 11, 16, 12, 0, tzinfo=dt_timezone.utc)
KEY_ONE, KEY_TWO = ("v2", "1" * 16), ("v2", "2" * 16)
REF_A, REF_B = "hmac-sha256:" + "a" * 64, "hmac-sha256:" + "b" * 64


def _chain() -> rule.Chain:
    return rule.Chain(
        workflow=WF,
        hops=(
            rule.Hop(rule.Node("policy", WF), rule.INVOKES, rule.Node("mcp_server", "crm-mcp")),
            rule.Hop(rule.Node("mcp_server", "crm-mcp"), rule.THROUGH_IDENTITY, rule.Node("service_account", "svc-x")),
            rule.Hop(rule.Node("service_account", "svc-x"), rule.PERFORMS, rule.Node("action", "customer:update")),
            rule.Hop(rule.Node("action", "customer:update"), rule.PRODUCES, rule.Node("effect", "e")),
        ),
        gate_outcome_id="g1",
    )


def _receipt(**kw) -> rule.Reconciliation:
    values = {
        "receipt_id": "r1", "deployment": "dep", "workflow": WF, "tool_kind": "mcp_server",
        "tool_identifier": "crm-mcp", "action": "customer:update", "action_digest": "",
        "dispatch_id": "d1", "attempt": 1, "permit_digest": "sha256:" + "ef" * 32, "gate_outcome_id": "g1",
        "dispatched_at": T, "answer": "applied", "conclusion": "committed", "provider": "p", "read_at": T,
        "action_ref": REF_A, "keyed_under": KEY_ONE,
    }
    return rule.Reconciliation(**{**values, **kw})


def _effect(**kw) -> rule.CitedOutcome:
    values = {
        "tool_kind": "mcp_server", "tool_identifier": "crm-mcp", "gate_outcome_id": "g1", "dispatch_id": "d1",
        "permit_digest": "sha256:" + "ef" * 32, "action": "customer:update", "observed_at": T,
        "action_ref": REF_A, "keyed_under": KEY_ONE,
    }
    return rule.CitedOutcome("e1", WF, comp.HELD, comp.EVIDENCE_OBSERVED_EFFECT, rule.ObservedEffect(**{**values, **kw}))


def _readback(*receipts, effect=None):
    gate = rule.CitedOutcome("g1", WF, comp.HELD, comp.EVIDENCE_AUTHORIZATION_CHECK)
    outcomes = {"g1": gate, **({"e1": effect} if effect is not None else {})}
    inputs = rule.Inputs(outcomes=outcomes, reconciliations=receipts, deployment="dep")
    return rule.readback(_chain(), inputs)


def test_two_records_of_one_dispatch_under_one_key_id_carry_the_same_reference():
    """Same under one key id: the receipt binds. Different under one key id: a mismatch, which
    proves nothing. The backend holds no key, and tests no guess either way."""
    same = _readback(_receipt(), effect=_effect())
    assert [b.binds for b in same.bindings] == [True] and [r.code for r in same.readings] == ["readback"]
    two = _readback(_receipt(), _receipt(receipt_id="r2", answer="cannot_say", conclusion="unknown"))
    assert [b.binds for b in two.bindings] == [True, True]

    different = _readback(_receipt(action_ref=REF_B), effect=_effect())
    assert [b.binds for b in different.bindings] == [False]
    assert [(r.verdict, r.code) for r in different.readings] == [(rule.UNPROVEN, "reconciliation_mismatch")]
    assert "action_ref" in different.readings[0].detail and "under the same key id" in different.readings[0].detail


@pytest.mark.parametrize(
    ("receipt", "effect", "why"),
    [
        ({"keyed_under": KEY_TWO}, {}, "two key ids, equal references: never equal"),
        ({"keyed_under": KEY_TWO, "action_ref": REF_B}, {}, "two key ids, unequal references: never a conflict"),
        ({"action_ref": "", "keyed_under": None, "action_digest": "ab" * 32}, {}, "a plain digest beside a reference"),
        ({}, {"action_ref": "", "keyed_under": None, "action_digest": "ab" * 32}, "a reference beside a plain digest"),
        ({"action_ref": "withheld:chain-key-unkept"}, {}, "a withheld reference is unknown"),
        ({"keyed_under": ("v9", "1" * 16)}, {"keyed_under": ("v9", "1" * 16)}, "a chain version the core does not know"),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_references_that_cannot_be_compared_are_unknown_never_equal_and_never_a_conflict(receipt, effect, why):
    """Unknown is unknown, never ok: the receipt binds nothing and the hop is unproven under a
    reason of its own -- not a mismatch, and never broken."""
    found = _readback(_receipt(**receipt), effect=_effect(**effect))
    assert [b.binds for b in found.bindings] == [False], why
    assert [(r.verdict, r.code) for r in found.readings] == [(rule.UNPROVEN, "reconciliation_cannot_compare")], why
    assert core.CANNOT_COMPARE in found.bindings[0].why and core.CANNOT_COMPARE in found.readings[0].detail
    assert "reconciliation_cannot_compare" in rule.REASONS
    # A receipt that says the effect was NOT produced, and cannot be compared, breaks nothing either.
    failed = _readback(_receipt(**{**receipt, "answer": "not_applied", "conclusion": "failed"}), effect=_effect(**effect))
    assert [(r.verdict, r.code) for r in failed.readings] == [(rule.UNPROVEN, "reconciliation_cannot_compare")], why


def test_plain_digests_are_compared_as_before_and_a_mismatch_no_longer_quotes_them():
    """Version 1 to 4 documents and version 1 receipts: the comparison is what it was. What a
    reader of the chain is no longer handed is the two plain digests: each lets its reader
    confirm a guess at the action."""
    plain = {"action_ref": "", "keyed_under": None}
    mine, theirs = "cd" * 32, "ab" * 32
    agree = _readback(_receipt(**plain, action_digest=theirs), effect=_effect(**plain, action_digest=theirs))
    assert [b.binds for b in agree.bindings] == [True]
    differ = _readback(_receipt(**plain, action_digest=mine), effect=_effect(**plain, action_digest=theirs))
    assert [(r.verdict, r.code) for r in differ.readings] == [(rule.UNPROVEN, "reconciliation_mismatch")]
    detail = differ.readings[0].detail
    assert "action_digest differs" in detail and core.PLAIN_DIGESTS_WITHHELD in detail
    assert mine not in detail and theirs not in detail
    # The permit's digest is not computable from a guess (it covers the issuer's MAC): still quoted.
    permit = _readback(
        _receipt(**plain, action_digest=theirs, permit_digest="sha256:" + "aa" * 32),
        effect=_effect(**plain, action_digest=theirs),
    )
    assert "sha256:" + "aa" * 32 in permit.readings[0].detail


# -------------------------------------------------------- nothing is kept by hand


def test_every_name_these_modules_keep_is_the_cores_own_object():
    assert observed_effects.EvidenceRefused is core.EvidenceRefused is effect_reconciliation.ReceiptRefused
    assert observed_effects.EVIDENCE_SCHEMAS is core.EVIDENCE_SCHEMAS
    assert observed_effects.EVIDENCE_SCHEMA_V5 == "mythos.observed-effect/v5"
    assert observed_effects.TOOL_KINDS is core.TOOL_KINDS is effect_reconciliation.TOOL_KINDS
    assert observed_effects.VERIFIED_FIELDS_V4 is core.VERIFIED_FIELDS_V4
    assert observed_effects.MAX_APPROVAL_RECIPIENTS is core.MAX_APPROVAL_RECIPIENTS
    assert effect_reconciliation.SCHEMAS is core.RECONCILIATION_SCHEMAS
    assert (effect_reconciliation.SCHEMA, effect_reconciliation.SCHEMA_V2) == core.RECONCILIATION_SCHEMAS
    assert effect_reconciliation.PAYLOAD_TYPE is core.RECONCILIATION_PAYLOAD_TYPE
    assert effect_reconciliation.SIGNER is core.ENGINE
    assert effect_reconciliation.CONCLUSIONS is core.READBACK_CONCLUSIONS
    assert effect_reconciliation.ANSWERS is core.READBACK_ANSWERS
    assert effect_reconciliation.MAX_PAYLOAD_B64 is oc.MAX_PAYLOAD_B64
    with pytest.raises(AttributeError):
        observed_effects.NO_SUCH_NAME  # noqa: B018 - reading it is the test


def test_every_check_is_asked_of_the_core(monkeypatch):
    """Each of this backend's names answers with whatever the core answers: a rule kept here
    beside the core's would answer for itself."""
    said = object()
    monkeypatch.setattr(core, "validate_evidence", lambda document: (said, document))
    monkeypatch.setattr(core, "validate_reconciliation", lambda document: (said, document))
    assert observed_effects.validate_evidence("anything at all") == (said, "anything at all")
    assert effect_reconciliation.validate_receipt(["anything"]) == (said, ["anything"])
    assert observed_effects.read_body({"envelope": 1, "evidence": 2}) == (1, (said, 2))

    verdict = core.EffectVerdict(core.REFUSED, "a_code_of_the_cores", "the core's reason")
    asked = []
    monkeypatch.setattr(core, "verify_observed_effect", lambda *args: asked.append(args) or verdict)
    monkeypatch.setattr(core, "verify_reconciliation", lambda *args: asked.append(args) or verdict)
    outcome = {"observer": {"engine": core.ENGINE}}
    why = observed_effects.examine(outcome, {"d": 1}, envelope={"e": 1}, keyring={"k": 1})
    assert why == "a_code_of_the_cores: the core's reason" and asked == [({"e": 1}, {"d": 1}, {"k": 1})]
    assert effect_reconciliation.verify_envelope({"e": 2}, {"k": 2}) == (None, None, "a_code_of_the_cores: the core's reason")
    assert asked[1] == ({"e": 2}, {"k": 2})
    # And an authentic verdict of the core's is taken as it is.
    document = {"receipt": 1}
    monkeypatch.setattr(core, "verify_reconciliation", lambda *args: core.EffectVerdict(oc.AUTHENTIC, "", "verified", "kid", None, document))
    assert effect_reconciliation.verify_envelope({}, {}) == (document, "kid", "")


def test_no_rule_of_the_record_is_spelled_in_these_modules():
    """No pattern, no field set, no field's name: the modules that kept the rules by hand hold
    none of them now."""
    for name in ("observed_effects.py", "effect_reconciliation.py"):
        source = (REPO / "assurance" / name).read_text(encoding="utf-8")
        code = source.split('"""', 2)[2]
        assert "import re\n" not in code and "re.compile" not in code and ".fullmatch(" not in code, name
        for spelled in ("[0-9a-f]", ".match(", "_MAX_TEXT", "EvidenceRefused(", "ReceiptRefused(", "InvalidSignature", "b64decode"):
            assert spelled not in code, (name, spelled)
        assert code.count("frozenset(") == 1, name  # the body's own two (or one) fields, nothing of the record's
    for removed in ("_validate_dispatch", "_validate_verified", "_validate_recipients", "_HEX64", "DISPATCH_FIELDS", "OBSERVED_FIELDS"):
        assert not hasattr(observed_effects, removed), removed
    for removed in ("_whole", "_exactly", "_effect_key", "FIELDS", "READBACK_FIELDS", "_HEX64"):
        assert not hasattr(effect_reconciliation, removed), removed


def test_the_core_is_not_loaded_with_the_url_conf():
    """The URL conf loads on whatever request a worker serves first, a stop included. It loads
    the route's credential (``assurance.observed_effects``) and the rule; it does not load the
    definition of the record, which only evidence reads."""
    probe = (
        "import sys, django; django.setup(); import config.urls, assurance.observed_effects, assurance.authority_chain;"
        "sys.exit(3 if 'mythos_core.observed_effect' in sys.modules else 0)"
    )
    ran = subprocess.run([sys.executable, "-c", probe], cwd=REPO, env=dict(os.environ), capture_output=True, timeout=120)
    assert ran.returncode == 0, ran.stderr.decode(errors="replace")[-600:]


def test_the_two_routes_are_still_evidence_and_no_stop():
    """The SAFETY RULE: the intake is not a stop path and nothing here was added to one."""
    from safety import stops

    for route in ("deployment-observed-effects", "deployment-effect-reconciliations"):
        assert set(stops.NOT_STOPS[route]) == {"POST"} and "stops nothing" in stops.NOT_STOPS[route]["POST"]
        assert route not in stops.STOP_ROUTES
    for module in ("safety", "failsafe", "pentest"):
        for path in sorted((REPO / module).rglob("*.py")):
            if "settings" in path.name.lower():
                continue
            source = path.read_text(encoding="utf-8")
            assert "mythos_core.observed_effect" not in source and "import observed_effect" not in source, path
