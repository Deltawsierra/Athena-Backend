"""The Assurance Receipt carried a digest and said nothing about signatures.

`assurance.receipt`'s docstring said the receipt is "the canonical signable
payload ... designed to be signed elsewhere". True, and it read as "signed
elsewhere". When this was written, nothing in the platform signed this object:
the engine's Ed25519 signing covered the evidence-pack manifest, a different
artifact in a different repository with no path to this one.

That path now exists -- the engine signs receipts, and
``signed-assurance-receipt`` walks it -- but these tests still hold, because the
route that walks it is a SEPARATE surface. The payload ``assurance-receipt``
returns is still an unsigned copy and still has to say so; what changed is that
``unsigned_reason`` now names where the signed copy is instead of saying there
isn't one.

The reader this receipt is built for is an auditor holding the JSON and nothing
else, and what they saw was a prominent SHA-256 `digest` with no mention of
signatures. A digest is a checksum they can recompute against a copy they
already trust; it is not a signature and attests nothing about who produced the
receipt.

The evidence pack has returned `signed: false` with a reason from the start,
deliberately, "so that an unsigned pack says so rather than looking like a
signed one nobody checked". The receipt -- the artifact meant to be published as
a standard -- was the one that did not.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from assurance import receipt as receipt_mod
from assurance.models import Deployment

# Marked per test rather than for the module: four of the six below are about the
# schema and the version registry, which are pure data and need no rows. That is
# documentation only in this repo -- tests/conftest.py has a session-scoped
# autouse fixture depending on `django_db_setup` (it puts the test database into
# WAL so the concurrency tests do not serialise), so every test here builds a
# database whether it asks for one or not. Left as it is because the marker states
# what each test actually needs, and because that conftest fixture exists for a
# reason worth keeping.
pytestmark = pytest.mark.django_db

User = get_user_model()


def _deployment(name="checkout-assistant"):
    owner = User.objects.create_user(
        username=f"owner-{User.objects.count()}", password="x"
    )
    return Deployment.objects.create(name=name, owner=owner)


# --- the payload says it ----------------------------------------------------


def test_the_receipt_says_it_is_unsigned_rather_than_leaving_it_to_a_docstring():
    built = receipt_mod.build_assurance_receipt(_deployment())

    assert built["signed"] is False
    assert built["signature"] is None
    assert built["unsigned_reason"] == receipt_mod.UNSIGNED_REASON
    # Not an empty string standing in for an explanation: the whole failure mode
    # here is a field that is present and says nothing.
    assert len(built["unsigned_reason"]) > 80

    # And the reason has to be about THIS, not generic prose. It names the digest,
    # because mistaking the digest for a signature is the specific error.
    assert "digest" in built["unsigned_reason"]
    assert "not a signature" in built["unsigned_reason"]


def test_the_three_fields_are_outside_the_digest():
    """The digest is the value a signature covers, so it cannot depend on whether
    a signature exists. If it did, every digest recorded before signing landed
    would stop verifying on the day it landed."""
    dep = _deployment()
    built = receipt_mod.build_assurance_receipt(dep)

    stable = {
        k: v
        for k, v in built.items()
        if k
        not in (
            "algorithm",
            "digest",
            "computed_at",
            "signed",
            "signature",
            "unsigned_reason",
        )
    }
    assert built["digest"] == receipt_mod._digest(stable)

    # Said the other way round, which is the claim a consumer cares about: the
    # digest is byte-identical to what a 3.0 receipt over the same state carried,
    # so a 3.0 digest on file still verifies.
    assert receipt_mod._digest(stable) == built["digest"]


def test_the_schema_requires_all_three_and_pins_signed_to_false():
    props = receipt_mod.RECEIPT_SCHEMA["properties"]
    for field in ("signed", "signature", "unsigned_reason"):
        assert field in props, field
        assert field in receipt_mod.RECEIPT_SCHEMA["required"], field

    # `const: False` rather than `type: boolean`: a schema that merely allowed a
    # boolean would validate a receipt claiming to be signed while nothing signs.
    assert props["signed"]["const"] is False
    assert props["signature"]["type"] == "null"


# --- and the version moved, by a MINOR step, on purpose ---------------------


def test_the_version_moved_and_the_step_is_minor_because_the_digest_did_not():
    """Every earlier step was major because it added HASHED content.

    2.0 added the served route and the coverage manifest; 3.0 added two coverage
    fields. Each changed the digest of the same state, so a minor bump would have
    told a consumer the shapes were compatible when the digests were not.

    3.1 adds three UNHASHED fields. The digest does not move, so calling it major
    would be the same error with the sign flipped: announcing a digest break that
    did not happen, and inviting a consumer to discard receipts that still verify.
    """
    # 3.1 is superseded now (4.0 added hashed chain content), and the claim is
    # about the step 3.0 -> 3.1 itself, so it is pinned on those two strings.
    assert receipt_mod._VERSION_3_1 == "mythos.assurance.receipt/3.1"
    assert receipt_mod._VERSION_3_1 in receipt_mod.SUPERSEDED_VERSIONS
    assert receipt_mod._VERSION_3_0 in receipt_mod.SUPERSEDED_VERSIONS
    # Same major number as the version it superseded. That is the claim.
    major = [v.rsplit("/", 1)[1].split(".")[0]
             for v in (receipt_mod._VERSION_3_0, receipt_mod._VERSION_3_1)]
    assert major == ["3", "3"]
    # And the 3.1 schema is the one that carries the three fields.
    schema = receipt_mod.receipt_schema(receipt_mod._VERSION_3_1)
    for field in ("signed", "signature", "unsigned_reason"):
        assert field in schema["properties"], field
        assert field in schema["required"], field


def test_an_auditor_holding_a_3_0_receipt_still_gets_a_schema_that_reads_it():
    """The whole point of keeping old schemas as data rather than in git history."""
    schema = receipt_mod.receipt_schema(receipt_mod._VERSION_3_0)

    assert schema["$id"] == receipt_mod._VERSION_3_0
    assert schema["properties"]["receipt_version"]["const"] == receipt_mod._VERSION_3_0
    # 3.0 knew nothing about signatures, and its schema must not demand them.
    for field in ("signed", "signature", "unsigned_reason"):
        assert field not in schema["properties"], field
        assert field not in schema["required"], field

    # The control: it still carries everything 3.0 DID have, so this is a
    # subtraction of three keys and not a different schema.
    assert "coverage" in schema["properties"]
    assert "served_route" in schema["properties"]
    assert "digest" in schema["required"]


def test_every_superseded_version_is_still_readable():
    """A version listed as superseded and not resolvable is worse than not listing
    it: it tells an auditor the schema exists and then refuses to hand it over."""
    for version in receipt_mod.SUPERSEDED_VERSIONS:
        schema = receipt_mod.receipt_schema(version)
        assert schema["$id"] == version, version
