"""Every Assurance Receipt version ever emitted reads back, named as what it was.

Phase 6 item 13's bar is that a third party can verify a receipt from the published
specification and verifier alone, and that the specification is "versioned and
backward-readable". At d81e9cb two versions were not (``docs/receipt-spec/v4.1.md``,
section 10 there):

* **1.0**, which #27 emitted and #42 replaced. Neither ``receipt_schema`` nor the
  offline verifier described it, so a genuine 1.0 receipt was refused as a version
  nobody defined.
* **2.0**, emitted in two shapes under one version string: #56 gave ``coverage`` five
  members, and #67, the same day, nine. The published 2.0 schema described only #67's,
  so it refused a genuine #56 receipt; the verifier accepted both only because it never
  looked inside ``coverage``, and named neither.

None of these vectors is typed in. ``tests/fixtures/receipts/generate.py`` drove each
commit's own ``assurance-receipt`` route, and ``provenance.json`` beside each vector
records the commit, the mythos-core it ran with, and the SHA-256 of the bytes -- which
the first test checks, so an edit to a vector shows.

A signature over any of these versions is its own finding. No route signed a receipt
before 3.1 (#96, 51484fb), so a signed 1.0, 1.1, 2.0 or 3.0 receipt was not made by
athena-backend's signed route, whoever holds the key. Keys here are generated in the
test, never read from anywhere, and never printed.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from assurance import receipt
from tests.receipt_schema_reading import shapes_read

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "tests" / "fixtures" / "receipts"
VERIFIER_PATH = ROOT / "tools" / "verify_receipt.py"

V1_0 = "mythos.assurance.receipt/1.0"
V2_0 = "mythos.assurance.receipt/2.0"

#: The vector directories, as generate.py names them: (directory, PR, version).
EMITTED = (
    ("pr27-673a40b", "#27", V1_0),
    ("pr56-fdf77bf", "#56", V2_0),
    ("pr67-87e83e7", "#67", V2_0),
)

#: The check axis #67 added to 2.0's coverage without a new version string.
CHECK_AXIS = ("checks_reported", "checks_total", "checks_performed", "checks_complete")


def _load_verifier():
    spec = importlib.util.spec_from_file_location("verify_receipt_back_reading", VERIFIER_PATH)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


verifier = _load_verifier()


def _vector(directory: str) -> bytes:
    return (FIXTURES / directory / "assurance-receipt.json").read_bytes()


def _hashed(document: dict) -> dict:
    outside = ("algorithm", "digest", "computed_at", "issued_at", "signed", "signature", "unsigned_reason")
    return {name: value for name, value in document.items() if name not in outside}


def _signed_claim(document: dict) -> tuple[bytes, bytes]:
    """``document`` inside a DSSE envelope signed the way athena-engine's ``wrap``
    signs, served beside it as the signed route serves one, and a keyring holding the
    key: a genuine signature by a key the verifier is given. Only the version makes
    the claim impossible."""
    key = Ed25519PrivateKey.generate()
    raw = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    body = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    kind = receipt.ASSURANCE_RECEIPT_TYPE.encode()
    pae = b" ".join([b"DSSEv1", str(len(kind)).encode(), kind, str(len(body)).encode(), body])
    key_id = "sha256:" + hashlib.sha256(raw).hexdigest()[:32]
    envelope = {
        "envelope_version": 1,
        "payloadType": receipt.ASSURANCE_RECEIPT_TYPE,
        "payload": base64.b64encode(body).decode(),
        "signatures": [{"keyid": key_id, "sig": base64.b64encode(key.sign(pae)).decode()}],
    }
    ring = {"version": 1, "keys": {key_id: {"public_key": base64.b64encode(raw).decode(), "status": "active"}}}
    return json.dumps({"receipt": document, "envelope": envelope}).encode(), json.dumps(ring).encode()


# ------------------------------------------------------------------ the vectors


@pytest.mark.parametrize(("directory", "pr", "version"), EMITTED, ids=[d for d, _, _ in EMITTED])
def test_each_vector_is_the_bytes_its_commit_emitted(directory, pr, version):
    """GREEN on d81e9cb and after: provenance, not reading."""
    provenance = json.loads((FIXTURES / directory / "provenance.json").read_text())
    raw = _vector(directory)
    assert hashlib.sha256(raw).hexdigest() == provenance["sha256"], "the vector is not the bytes generated"
    assert provenance["emitted_by"]["pr"] == pr
    assert provenance["emitted_by"]["commit"].startswith(directory.split("-", 1)[1])
    assert provenance["generated_by"] == "tests/fixtures/receipts/generate.py"
    assert json.loads(raw)["receipt_version"] == provenance["receipt_version"] == version
    # And the digest it carries is the one its own content gives, by the rule every
    # version has hashed by: the vector was emitted whole, not assembled.
    document = json.loads(raw)
    assert receipt._digest(_hashed(document)) == document["digest"]


# ------------------------------------------------------------------ reading them


def test_a_1_0_receipt_reads_back():
    """RED on d81e9cb: the verifier refused it as ``unknown_version`` and
    ``receipt_schema`` raised. It reads now, and is refused only for what it is --
    a copy nothing signs -- with what it lacks said."""
    raw = _vector("pr27-673a40b")
    document = json.loads(raw)

    verdict = verifier.verify(raw)
    assert (verdict.verified, verdict.reason) == (False, "unsigned"), verdict.render()
    said = verdict.render()
    assert f"receipt   {V1_0}, as emitted by #27 (673a40b)" in said
    assert "lacks     policy_version: " in said
    assert "lacks     issued_at: " in said

    schema = receipt.receipt_schema(V1_0)
    assert schema["properties"]["receipt_version"]["const"] == V1_0
    assert set(schema["required"]) <= set(document) <= set(schema["properties"])
    assert shapes_read(schema, document) == ()
    assert "policy_version" in {member for lack in schema["lacks"] for member in lack["members"]}


@pytest.mark.parametrize(
    ("directory", "pr", "commit"),
    [("pr56-fdf77bf", "#56", "fdf77bf"), ("pr67-87e83e7", "#67", "87e83e7")],
    ids=["as-56-emitted-it", "as-67-emitted-it"],
)
def test_both_2_0_shapes_read_back_named_as_what_they_were(directory, pr, commit):
    """RED on d81e9cb for both. #56's receipt did not read against the published 2.0
    schema, which required the four check-axis members #67 added under the same
    version string. #67's did, but neither was named: the verifier read both as "2.0"
    without looking inside ``coverage``. Now each is read as the shape it was, by
    the backend's schema and the verifier alike, and never as the other."""
    raw = _vector(directory)
    document = json.loads(raw)

    matched = shapes_read(receipt.receipt_schema(V2_0), document)
    assert matched is not None, "the published 2.0 schema does not read this 2.0 receipt"
    assert len(matched) == 1 and f"as emitted by {pr} ({commit}" in matched[0], matched

    verdict = verifier.verify(raw)
    assert (verdict.verified, verdict.reason) == (False, "unsigned"), verdict.render()
    assert f"receipt   {V2_0}, as emitted by {pr} ({commit})" in verdict.render()
    # What a 2.0 receipt of each shape cannot say, said: #56's has no check axis.
    lacks_check_axis = "lacks     coverage.checks_reported, " in verdict.render()
    assert lacks_check_axis is (pr == "#56"), verdict.render()


def test_a_2_0_coverage_neither_shape_is_refused_not_coerced():
    """RED on d81e9cb at the verifier, which read it as a 2.0 receipt: it never
    looked inside ``coverage``. A coverage with two of the check-axis members is a
    shape no commit emitted, so it is not read as either, and its digest -- redone so
    that the shape is the only thing wrong -- does not rescue it."""
    document = json.loads(_vector("pr67-87e83e7"))
    for member in CHECK_AXIS[2:]:
        del document["coverage"][member]
    document["digest"] = receipt._digest(_hashed(document))
    raw = json.dumps(document).encode()

    assert shapes_read(receipt.receipt_schema(V2_0), document) is None
    verdict = verifier.verify(raw)
    assert (verdict.verified, verdict.reason) == (False, "malformed"), verdict.render()


@pytest.mark.parametrize("directory", ["pr27-673a40b", "pr56-fdf77bf", "pr67-87e83e7"])
def test_a_signed_claim_of_a_version_no_route_ever_signed_is_refused(directory):
    """RED on d81e9cb: a 2.0 receipt in a genuine envelope VERIFIED there, and a 1.0
    one was refused for its version rather than for the claim. No route signed a
    receipt before 3.1 (#96), so a signature over one of these was not made by
    athena-backend's signed route, whoever holds the key -- and a verifier that says
    VERIFIED tells its reader the platform issued it."""
    emitted = json.loads(_vector(directory))
    # The signed form, as the signed route would have served it had one existed: the
    # copy without its render time. Well formed in every other respect, so the version
    # is the only thing left to refuse.
    signed_form = {name: value for name, value in emitted.items() if name != "computed_at"}
    served, ring = _signed_claim(signed_form)

    verdict = verifier.verify(served, keyring=ring)

    assert (verdict.verified, verdict.reason) == (False, "never_signed"), verdict.render()
    assert emitted["receipt_version"] in receipt.NEVER_SIGNED
