"""A row this side cannot read is a check whose outcome is unknown.

The check axis was built so that "nobody said" could never be confused with
"every check ran". The reader then undid it one layer down. `_reported_checks`
filtered out any row without a truthy `check` and `state` -- and the denominator
shrank with them, so the rows that survived looked like the whole story.

The engine is a separate deployable on its own release cycle. Rename `state` to
`status` in one engine release and the consequence was not a warning:

    honest   decision=audit_incomplete  checks_total=4  checks_performed=2  complete=False
    drifted  decision=ready             checks_total=2  checks_performed=2  complete=True

Two checks that never ran became a signed receipt attesting that every check
performed. The function's own docstring promised the opposite -- "a payload that
is not [the shape] is discarded whole rather than half-read" -- and the per-row
filter was the half-read.

This file holds the rule in both directions: a row that cannot be read reaches
the denominator and never `performed`, and a manifest whose rows are all
readable and all performed is still complete.
"""

from __future__ import annotations

import pytest
from assurance import coverage as cov
from assurance.ingest import _record_reported_checks
from assurance.models import Deployment
from assurance.receipt import (
    RECEIPT_VERSION,
    SUPERSEDED_VERSIONS,
    UnknownReceiptVersion,
    build_assurance_receipt,
    receipt_schema,
)
from django.contrib.auth import get_user_model

pytestmark = pytest.mark.django_db
User = get_user_model()


def _dep(name="d"):
    user = User.objects.create_user(
        username=f"rows-{Deployment.objects.count()}", password="x",
        role=User.Roles.ANALYST,
    )
    return Deployment.objects.create(name=name, owner=user)


class _Scan:
    """The minimum `_record_reported_checks` reads."""

    def __init__(self, engine_response):
        self.engine_response = engine_response


def _store(dep, rows, **extra):
    payload = {"coverage": {"checks": rows, **extra}}
    _record_reported_checks(_Scan(payload), dep)
    dep.refresh_from_db()
    return cov._checks_section(dep)


PERFORMED = {"check": "xss", "state": "performed"}
CLEAN_PAIR = [PERFORMED, {"check": "sqli", "state": "performed"}]


# --------------------------------------------------------------------------
# The negative control first: the honest payload must still read complete.
# --------------------------------------------------------------------------


def test_a_manifest_whose_every_row_performed_is_still_complete():
    section = _store(_dep(), CLEAN_PAIR)
    assert section["reported"] is True
    assert section["total"] == 2
    assert section["performed"] == 2
    assert section["complete"] is True
    assert section["unrecognised"] == []


# --------------------------------------------------------------------------
# The drift that used to clear the cap.
# --------------------------------------------------------------------------


def test_a_row_whose_state_key_the_engine_renamed_is_not_deleted():
    """The whole defect, in the shape an engine release produces."""
    dep = _dep()
    section = _store(dep, [
        PERFORMED,
        {"check": "sqli", "state": "performed"},
        # The engine renamed the key. These two never ran.
        {"check": "tls", "status": "not_performed", "reason": "precondition"},
        {"check": "idor", "status": "not_performed", "reason": "precondition"},
    ])
    assert section["total"] == 4, "the denominator shrank with the rows it dropped"
    assert section["performed"] == 2
    assert section["complete"] is False
    assert [r["check"] for r in section["unrecognised"]] == ["idor", "tls"]
    assert cov.checks_gap(dep) is True
    assert cov.coverage_decision_cap(dep) == Deployment.Decision.AUDIT_INCOMPLETE


def test_a_state_this_side_does_not_know_is_named_not_merely_counted():
    """It already counted against `complete`. It appeared in no list, so an
    operator saw a shortfall and could not learn which check it was."""
    dep = _dep()
    section = _store(dep, [PERFORMED, {"check": "tls", "state": "partial"}])
    assert section["complete"] is False
    assert [r["check"] for r in section["unrecognised"]] == ["tls"]
    assert "does not know" in section["summary"]


def test_a_row_with_no_name_is_counted_without_being_invented():
    """Unnamed, so it cannot be listed -- but it arrived, so it is in the total."""
    dep = _dep()
    section = _store(dep, [PERFORMED, {"state": "performed"}, "not-a-row", 7])
    assert section["total"] == 4
    assert section["performed"] == 1
    assert section["complete"] is False
    assert "could not be read" in section["summary"]
    assert cov.coverage_decision_cap(dep) == Deployment.Decision.AUDIT_INCOMPLETE


def test_a_stored_manifest_with_a_non_dict_row_does_not_crash_the_decision():
    """check_coverage was type-guarded; its rows were not, so a fixture load or a
    shell session could take the decision, the receipt and the API down."""
    dep = _dep()
    dep.check_coverage = {"checks": ["tls", "xss"]}
    dep.save()
    section = cov._checks_section(dep)
    assert section["reported"] is False
    assert cov.checks_gap(dep) is False


# --------------------------------------------------------------------------
# The receipt. Four fields that were load-bearing and wholly untested.
# --------------------------------------------------------------------------


def _coverage_block(dep):
    return build_assurance_receipt(dep)["coverage"]


def test_a_silent_deployment_says_so_in_the_receipt():
    block = _coverage_block(_dep())
    assert block["checks_reported"] is False
    assert block["checks_total"] is None
    assert block["checks_performed"] is None
    assert block["checks_complete"] is None
    assert block["checks_gap_fingerprint"] is None
    assert block["checks_reported_at"] is None


def test_a_fully_performed_deployment_says_so_in_the_receipt():
    dep = _dep()
    _store(dep, CLEAN_PAIR)
    block = _coverage_block(dep)
    assert block["checks_reported"] is True
    assert block["checks_total"] == 2
    assert block["checks_performed"] == 2
    assert block["checks_complete"] is True
    # A digest over an empty gap: the positive statement that nothing fell short,
    # which is not the same as None.
    assert block["checks_gap_fingerprint"] is not None
    assert block["checks_reported_at"] is not None


def test_a_deployment_with_a_gap_says_so_in_the_receipt():
    dep = _dep()
    _store(dep, [PERFORMED, {"check": "tls", "state": "not_performed",
                             "reason": "precondition"}])
    block = _coverage_block(dep)
    assert block["checks_reported"] is True
    assert block["checks_total"] == 2
    assert block["checks_performed"] == 1
    assert block["checks_complete"] is False


def test_two_different_gaps_do_not_sign_to_the_same_receipt():
    """The counts alone cannot tell "we never tested TLS" from "we switched off
    injection testing". Both are four identical numbers."""
    a, b = _dep("a"), _dep("b")
    _store(a, [PERFORMED, {"check": "tls", "state": "not_performed",
                           "reason": "precondition"}])
    _store(b, [PERFORMED, {"check": "sqli", "state": "not_performed",
                           "reason": "disabled"}])
    fa, fb = _coverage_block(a), _coverage_block(b)
    assert (fa["checks_total"], fa["checks_performed"], fa["checks_complete"]) == (
        fb["checks_total"], fb["checks_performed"], fb["checks_complete"]
    ), "the counts should be identical, which is the premise of this test"
    assert fa["checks_gap_fingerprint"] != fb["checks_gap_fingerprint"]


def test_the_same_gap_signs_identically():
    """The negative control: the fingerprint is a digest, not a nonce."""
    a, b = _dep("a"), _dep("b")
    rows = [PERFORMED, {"check": "tls", "state": "not_performed",
                        "reason": "precondition"}]
    _store(a, rows)
    _store(b, list(reversed(rows)))
    assert (
        _coverage_block(a)["checks_gap_fingerprint"]
        == _coverage_block(b)["checks_gap_fingerprint"]
    ), "row order must not change the digest"


# --------------------------------------------------------------------------
# Versioning. Two payload shapes must not share one version string.
# --------------------------------------------------------------------------


def test_the_receipt_version_moved_when_the_coverage_block_gained_required_fields():
    assert RECEIPT_VERSION == "mythos.assurance.receipt/3.1"
    assert "mythos.assurance.receipt/2.0" in SUPERSEDED_VERSIONS
    # 3.0 is superseded too now: 3.1 added signed/signature/unsigned_reason. Those
    # are UNHASHED, so this one is a MINOR step -- a 3.0 digest and a 3.1 digest of
    # the same state are identical, and a major bump would have announced a digest
    # break that did not happen.
    assert "mythos.assurance.receipt/3.0" in SUPERSEDED_VERSIONS


def test_an_auditor_holding_a_2_0_receipt_gets_a_schema_that_reads_it():
    """The failure UnknownReceiptVersion exists to prevent, arriving through the
    front door: the version string did not move when four fields became
    required, so `receipt_schema("2.0")` described a shape 2.0 never had."""
    schema = receipt_schema("mythos.assurance.receipt/2.0")
    assert schema["$id"] == "mythos.assurance.receipt/2.0"
    assert schema["properties"]["receipt_version"]["const"] == (
        "mythos.assurance.receipt/2.0"
    )
    coverage_props = schema["properties"]["coverage"]["properties"]
    assert "checks_reported" in coverage_props
    assert "checks_gap_fingerprint" not in coverage_props
    assert "checks_gap_fingerprint" not in schema["properties"]["coverage"]["required"]


def test_the_current_schema_describes_the_current_coverage_block():
    dep = _dep()
    _store(dep, CLEAN_PAIR)
    built = build_assurance_receipt(dep)
    described = receipt_schema()["properties"]["coverage"]
    assert set(built["coverage"]) == set(described["properties"]), (
        "the receipt emits a coverage key the schema does not describe, or vice versa"
    )
    for name in described["required"]:
        assert name in built["coverage"], name


def test_an_unknown_version_still_refuses_rather_than_guessing():
    with pytest.raises(UnknownReceiptVersion):
        receipt_schema("mythos.assurance.receipt/9.9")
