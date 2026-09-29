"""A signed Assurance Receipt says when it was issued, under the signature.

Found by #116 while writing the receipt specification, which states it as a known
limitation (``docs/receipt-spec/v4.0.md``, sections 1 and 10): ``computed_at`` was in
``NOT_SIGNED_OVER`` and the DSSE envelope carries no time, so the signed copy carried
no time at all -- while this module's own docstrings listed "time T" in the tuple the
signable payload carries. Ed25519 is deterministic, so one assurance state signed to
the same bytes on any day, and a retired key goes on verifying what it signed: a
signed ``ready`` from before a regression verified for ever, and nothing in it said
how old it was.

4.1 puts the time in the signed form: ``issued_at``, this backend's clock when it
hands the receipt to be signed (RFC 3339, UTC, whole seconds), INSIDE the signature
and OUTSIDE ``digest``. So the same state still digests identically, two signings of
it differ by their time alone, and a time edited after signing fails the signature.
It is the issuer's clock, not proof of when the state held; a reader applies its own
freshness policy (``tools/verify_receipt.py --max-age``).

The signer is a stand-in that signs the way athena-engine's does: the engine signs
the document it is handed, re-serialised canonically, and builds no payload of its
own (athena-engine a4d3c32, ``api/server.py`` ``sign_assurance_receipt`` ->
``engine/evidence/envelope.py`` ``wrap`` -> ``canonical_bytes``). Keys are generated
here, never read from anywhere, and never printed.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import re
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from ai_engine.services.cyberengine_client import CyberEngineClient
from assurance import policy, receipt
from assurance.models import Deployment, Evidence, EvidenceClass, Finding
from assurance.views import DeploymentViewSet
from tests.decision_surfaces import stamped_under_the_rules_in_force

pytestmark = pytest.mark.django_db

User = get_user_model()

VERIFIER_PATH = Path(__file__).resolve().parent.parent / "tools" / "verify_receipt.py"

#: The backend's clock, held for a signing: distinctive, and in the past.
ISSUED = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
ISSUED_TEXT = "2026-01-02T03:04:05Z"
#: A second signing of the same state, a month on.
LATER = ISSUED + timedelta(days=30)

FOUR_OH = "mythos.assurance.receipt/4.0"

#: Every top-level member no digest covers, in any version: the digest itself and its
#: algorithm, the full form's render time and self-report, and the signed form's time.
_OUTSIDE_DIGEST = frozenset(
    {"algorithm", "digest", "computed_at", "signed", "signature", "unsigned_reason", "issued_at"}
)


def _load_verifier():
    """The offline verifier as an auditor has it: a file loaded by path."""
    spec = importlib.util.spec_from_file_location("verify_receipt_issued_at", VERIFIER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


verifier = _load_verifier()


# ----------------------------------------------------------------- building blocks


def _raw_public(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _key_id(key: Ed25519PrivateKey) -> str:
    return "sha256:" + hashlib.sha256(_raw_public(key)).hexdigest()[:32]


def _engine_bytes(document: dict) -> bytes:
    """``engine.evidence.envelope.canonical_bytes``: sorted keys, no whitespace, raw UTF-8."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def _envelope(body: bytes, key: Ed25519PrivateKey) -> dict:
    """A DSSE envelope over exactly ``body``, as the engine's ``wrap`` builds one."""
    kind = receipt.ASSURANCE_RECEIPT_TYPE.encode("utf-8")
    pae = b" ".join([b"DSSEv1", str(len(kind)).encode(), kind, str(len(body)).encode(), body])
    return {
        "envelope_version": 1,
        "payloadType": receipt.ASSURANCE_RECEIPT_TYPE,
        "payload": base64.b64encode(body).decode("ascii"),
        "signatures": [{"keyid": _key_id(key), "sig": base64.b64encode(key.sign(pae)).decode("ascii")}],
    }


class _Engine:
    """Signs the document it is handed and nothing else, as the engine does."""

    def __init__(self, key: Ed25519PrivateKey):
        self.key = key

    def sign_assurance_receipt(self, document):
        return _envelope(_engine_bytes(document), self.key)


def _keyring(key: Ed25519PrivateKey) -> bytes:
    """The engine's published keyring, holding the one key."""
    entry = {
        "public_key": base64.b64encode(_raw_public(key)).decode("ascii"),
        "status": "active",
        "created_at": None,
        "retired_at": None,
        "reason": None,
    }
    return json.dumps({"version": 1, "keys": {_key_id(key): entry}}).encode()


def _deployment():
    owner = User.objects.create_user(username="owner", password="x", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(
        name="checkout-assistant",
        owner=owner,
        environment=Deployment.Environment.PRODUCTION,
        decision=Deployment.Decision.READY,
    )
    finding = Finding.objects.create(
        deployment=dep, fingerprint="fp1", finding_type="xss", title="F", severity="low"
    )
    Evidence.objects.create(
        finding=finding,
        classification=EvidenceClass.PARTIALLY_VERIFIED,
        source="engine_scan",
        content_hash="a" * 64,
    )
    # The hand-written READY stands for one the rules computed (decision.current_decision).
    return stamped_under_the_rules_in_force(dep), owner


def _signed_answer(monkeypatch, dep, reader, key, *, at: datetime | None = None) -> dict:
    """The signed route's answer, as served. ``at`` holds this backend's clock for the
    signing. ``raising=False`` so this also runs where no such clock exists (a0b504a),
    where holding it changes nothing."""
    monkeypatch.setattr(CyberEngineClient, "from_settings", classmethod(lambda cls: _Engine(key)))
    if at is not None:
        monkeypatch.setattr(receipt, "_utc_now", lambda: at, raising=False)
    request = APIRequestFactory().get(
        f"/api/assurance/deployments/{dep.uuid}/signed-assurance-receipt/", HTTP_ACCEPT="application/json"
    )
    force_authenticate(request, user=reader)
    response = DeploymentViewSet.as_view({"get": "signed_assurance_receipt"})(request, uuid=str(dep.uuid))
    assert response.status_code == 200, response.status_code
    response.render()
    answer = json.loads(response.content)
    assert answer["signed"] is True, answer["reason"]
    return answer


def _hashed(document: dict) -> dict:
    return {name: value for name, value in document.items() if name not in _OUTSIDE_DIGEST}


def _hashed_shape(version: str) -> dict:
    """What a version's digest covers, as its published schema describes it -- every
    hashed member's rule, nested members included -- less the version string itself."""
    properties = receipt.receipt_schema(version)["properties"]
    return {
        name: rule
        for name, rule in properties.items()
        if name not in _OUTSIDE_DIGEST and name != "receipt_version"
    }


def _version_key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.rsplit("/", 1)[1].split("."))


# --------------------------------------------------------------------- the defect


def test_the_signed_document_carries_the_time_it_was_issued(monkeypatch):
    """RED on a0b504a: the signed bytes carried no time at all.

    The time is the backend's clock at the moment it handed the receipt to be signed,
    written as RFC 3339 in UTC to the second, and it is in the SIGNED BYTES -- the
    envelope's payload -- not only in the copy served beside it."""
    dep, reader = _deployment()
    answer = _signed_answer(monkeypatch, dep, reader, Ed25519PrivateKey.generate(), at=ISSUED)

    signed_bytes = base64.b64decode(answer["envelope"]["payload"])
    inside = json.loads(signed_bytes)
    assert inside.get("issued_at") == ISSUED_TEXT, "the signed bytes carry no issue time"
    assert b'"issued_at":"' + ISSUED_TEXT.encode() + b'"' in signed_bytes
    assert re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", inside["issued_at"])
    # The copy served beside the envelope is the document that was signed, time and all.
    assert answer["receipt"] == inside
    # The render time of the unsigned copy is still not what is signed: the signed
    # form carries the issue time instead of it, never both.
    assert "computed_at" not in inside


def test_an_issue_time_edited_after_signing_fails_the_signature(monkeypatch):
    """RED on a0b504a: there was no signed time to edit, so no time a reader could trust.

    The edit is the one that matters -- a month-old receipt dressed as a fresh one --
    made in the envelope's payload AND in the copy served beside it, so the copies
    still agree and the digest still matches: the signature is the only thing left to
    catch it, and it does."""
    dep, reader = _deployment()
    key = Ed25519PrivateKey.generate()
    ring = _keyring(key)
    answer = _signed_answer(monkeypatch, dep, reader, key, at=ISSUED)
    inside = json.loads(base64.b64decode(answer["envelope"]["payload"]))
    assert "issued_at" in inside, "the signed bytes carry no issue time to edit"

    # The control: as signed, it verifies.
    as_signed = verifier.verify(json.dumps(answer).encode(), keyring=ring)
    assert as_signed.verified, as_signed.render()

    edited = {**inside, "issued_at": "2026-02-01T03:04:05Z"}
    answer["envelope"]["payload"] = base64.b64encode(_engine_bytes(edited)).decode("ascii")
    answer["receipt"] = edited
    verdict = verifier.verify(json.dumps(answer).encode(), keyring=ring)

    assert (verdict.verified, verdict.reason) == (False, "bad_signature"), verdict.render()
    # The digest does not see the time -- that is the design -- so it was the signature.
    assert receipt._digest(_hashed(edited)) == edited["digest"]


@pytest.mark.parametrize(
    "written",
    [
        "2026-01-02T03:04:05+00:00",  # an offset where the one form says Z
        "2026-01-02T03:04:05.000Z",  # a fraction where it says whole seconds
        "2026-01-02 03:04:05Z",  # no T
        "2026-13-02T03:04:05Z",  # the right shape, and no such month
        1767323045,  # a number of seconds
    ],
)
def test_an_issue_time_in_any_other_form_is_malformed_even_when_signed(monkeypatch, written):
    """``issued_at`` has one form, ``YYYY-MM-DDTHH:MM:SSZ``. A time in another is read
    as different instants by different readers, or not at all, so the verifier refuses
    it as a receipt the specification does not describe -- here over a document the
    key really did sign, so it is the form that is refused and not the signature."""
    dep, reader = _deployment()
    key = Ed25519PrivateKey.generate()
    document = {**_signed_answer(monkeypatch, dep, reader, key, at=ISSUED)["receipt"], "issued_at": written}
    served = {"receipt": document, "envelope": _envelope(_engine_bytes(document), key)}

    verdict = verifier.verify(json.dumps(served).encode(), keyring=_keyring(key))

    assert (verdict.verified, verdict.reason) == (False, "malformed"), verdict.render()
    assert "issued_at" in verdict.render()


def test_an_issue_time_ahead_of_the_readers_clock_is_said_as_that(monkeypatch):
    """One of the two clocks is wrong, and the verifier cannot tell which. It says so,
    and never shows the receipt as 0 seconds old."""
    dep, reader = _deployment()
    key = Ed25519PrivateKey.generate()
    answer = _signed_answer(monkeypatch, dep, reader, key, at=ISSUED)

    verdict = verifier.verify(
        json.dumps(answer).encode(), keyring=_keyring(key), now=ISSUED - timedelta(seconds=30)
    )

    assert verdict.verified, verdict.render()
    assert f"issued at {ISSUED_TEXT} by the issuer's clock, 30 s AHEAD of this machine's clock" in verdict.render()
    assert " 0 s " not in verdict.render()


# ------------------------------------------------------------ what must not move


def test_two_signings_of_one_state_carry_one_digest(monkeypatch):
    """GREEN on a0b504a and after. "Has anything changed?" is answered by the digest,
    and no clock enters it: two signings of an unchanged deployment a month apart carry
    the digest the unsigned copy carries, and every hashed member is equal."""
    dep, reader = _deployment()
    key = Ed25519PrivateKey.generate()

    first = _signed_answer(monkeypatch, dep, reader, key, at=ISSUED)["receipt"]
    second = _signed_answer(monkeypatch, dep, reader, key, at=LATER)["receipt"]
    unsigned = receipt.build_assurance_receipt(dep)

    assert first["digest"] == second["digest"] == unsigned["digest"]
    assert _hashed(first) == _hashed(second) == _hashed(unsigned)
    assert receipt._digest(_hashed(first)) == first["digest"]


def test_a_4_0_receipt_still_reads(monkeypatch):
    """GREEN on a0b504a and after. A 4.0 signed receipt -- the signed form with no
    issue time, under the 4.0 version string, digested by the unchanged rule, exactly
    what a0b504a's route signed -- verifies offline, and the backend still publishes
    the schema that reads it. 4.1 adds to what a signed receipt can say; it does not
    retire anything a 4.0 one said."""
    dep, reader = _deployment()
    key = Ed25519PrivateKey.generate()
    signed = _signed_answer(monkeypatch, dep, reader, key)["receipt"]

    four = {name: value for name, value in signed.items() if name != "issued_at"}
    four["receipt_version"] = FOUR_OH
    four["digest"] = receipt._digest(_hashed(four))
    served = {"receipt": four, "envelope": _envelope(_engine_bytes(four), key)}

    verdict = verifier.verify(json.dumps(served).encode(), keyring=_keyring(key))
    assert verdict.verified, verdict.render()
    assert f"receipt   {FOUR_OH}" in verdict.render()

    schema = receipt.receipt_schema(FOUR_OH)
    assert schema["properties"]["receipt_version"]["const"] == FOUR_OH
    assert "issued_at" not in schema["properties"]
    signed_form = set(schema["properties"]) - set(receipt.NOT_SIGNED_OVER)
    assert set(four) == signed_form
    assert set(schema["required"]) - set(receipt.NOT_SIGNED_OVER) <= set(four)


def test_the_policy_pins_the_version_that_introduced_the_hashed_content():
    """GREEN on a0b504a and after; RED under a bump of ``RECEIPT_VERSION`` alone.

    The assurance policy pins a receipt version as its ``evaluator_standard``, and the
    pin is what every claim and stored decision is bound to: a moved pin supersedes
    every claim as "Assurance policy changed" and recomputes every stored decision.
    Pinning the version the receipt is STAMPED with made a step that changes only what
    sits outside the digest -- 4.1, the signed issue time -- move the pin, a policy
    change that did not happen, written on every claim on the platform. So it pins the
    version that introduced the hashed content the receipt now carries: a MINOR step
    cannot move it, and a MAJOR one does, as it always did."""
    versions = sorted((receipt.RECEIPT_VERSION, *receipt.SUPERSEDED_VERSIONS), key=_version_key)
    current = _hashed_shape(receipt.RECEIPT_VERSION)
    introduced = next(version for version in versions if _hashed_shape(version) == current)

    assert policy._policy_document()["evaluator_standard"] == introduced
