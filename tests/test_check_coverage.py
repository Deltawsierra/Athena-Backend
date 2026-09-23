"""The second axis: which checks ran, not just which components were assessed.

The failure this exists for is one the asset axis cannot see. Every declared
component is assessed, every fact captured is genuine, the manifest reads COMPLETE
and the decision reads READY -- and the engine never ran the TLS check because the
target was cleartext, never ran the object-level authorisation check because no
second identity was configured, and had every subdomain lookup refused by the
engagement scope. Three questions were never asked, and the report's silence on
them looked exactly like a clean answer.

`Asset.assessed_at` cannot carry this. It records that something assessed a
component; it has no vocabulary for what was asked. So the engine reports its own
manifest and this is the half that reads it.
"""

from __future__ import annotations

import pytest
from assurance.coverage import (
    COMPLETE,
    INCOMPLETE,
    UNDECLARED,
    checks_gap,
    complete_audit_signal,
    coverage_decision_cap,
    coverage_manifest,
    record_assessment,
)
from assurance.ingest import _record_reported_checks, _reported_checks
from assurance.models import Asset, DeclaredComponent, Deployment
from django.contrib.auth import get_user_model

pytestmark = pytest.mark.django_db

User = get_user_model()


def _dep():
    user = User.objects.create_user(
        username=f"chk-{Deployment.objects.count()}", password="x",
        role=User.Roles.ANALYST,
    )
    return Deployment.objects.create(name="d", owner=user)


def _row(check, state, **extra):
    row = {"check": check, "team": "blue", "state": state}
    row.update(extra)
    return row


def _manifest(*rows, limitations=None, notes=None):
    """An engine coverage payload in the shape Athena actually emits."""
    return {
        "complete": all(r["state"] == "performed" for r in rows),
        "checks": list(rows),
        "not_performed": [r["check"] for r in rows if r["state"] == "not_performed"],
        "degraded": [r["check"] for r in rows if r["state"] == "degraded"],
        "unmeasured": [r["check"] for r in rows if r["state"] == "unmeasured"],
        "limitations": limitations or {},
        "notes": notes or [],
    }


class _Scan:
    """The only thing ingest reads off a scan here."""

    def __init__(self, engine_response):
        self.engine_response = engine_response


# -- reading the engine's payload -------------------------------------------

def test_a_payload_with_no_coverage_says_nothing():
    assert _reported_checks({"results": []}) == {}
    assert _reported_checks({"coverage": {}}) == {}
    assert _reported_checks(None) == {}


def test_a_component_only_coverage_payload_is_not_read_as_checks():
    """The `coverage` key carries two independent statements. An engine that
    reports components and not checks must not be read as having reported
    checks, or its silence becomes a claim."""
    assert _reported_checks({
        "coverage": {"assessed": [{"kind": "tool", "name": "t"}], "engine": "achilles/1.0"}
    }) == {}


def test_a_payload_with_no_readable_structure_at_all_is_discarded_whole():
    """Half a coverage claim is worse than none: it would report the checks it
    could parse as the complete list.

    That principle is unchanged. What changed is how it is kept. This case is the
    one where nothing can be salvaged -- `checks` is not a list, or is empty -- so
    there is no claim to read and the answer is "nobody said".
    """
    assert _reported_checks({"coverage": {"checks": "not a list"}}) == {}
    assert _reported_checks({"coverage": {"checks": []}}) == {}
    assert _reported_checks({"coverage": {}}) == {}
    assert _reported_checks({"coverage": "checks"}) == {}


def test_a_row_it_cannot_read_is_kept_rather_than_deleted():
    """The other end of the same principle, and the correction to it.

    These used to return ``{}`` as well, on the reasoning that a payload which is
    not the promised shape should be discarded whole. But discarding a payload
    that DID arrive turns a reported shortfall into silence, and silence imposes
    no cap -- so an engine that renamed one key moved the deployment from
    "audit incomplete" to "ready".

    A row that arrived and cannot be interpreted is a check whose outcome is
    unknown. It is kept, it reaches the denominator, and it never reaches
    ``performed``. That is what stops it being "reported as the complete list".
    """
    read = _reported_checks({"coverage": {"checks": [{"no": "check key"}]}})
    assert read != {}
    assert read["checks"] == []
    assert read["unreadable"] == 1

    read = _reported_checks({"coverage": {"checks": [{"check": "x"}]}})
    assert read["checks"] == [{"check": "x"}]
    assert read["performed"] == [], "a row with no state has not performed"


def test_the_summary_lists_are_recomputed_from_the_rows():
    """Not trusted from the payload. A manifest whose summary disagreed with its
    own rows would otherwise be believed by the summary."""
    read = _reported_checks({
        "coverage": {
            "checks": [_row("tls", "not_performed"), _row("xss", "performed")],
            # Deliberately wrong, and deliberately the reassuring direction.
            "not_performed": [],
            "degraded": ["xss"],
        }
    })
    assert read["not_performed"] == ["tls"]
    assert read["degraded"] == []


# -- storing it --------------------------------------------------------------

def test_ingest_stores_the_manifest_and_stamps_when():
    dep = _dep()
    stored = _record_reported_checks(
        _Scan({"coverage": _manifest(_row("xss", "performed"))}), dep
    )
    dep.refresh_from_db()
    assert stored is True
    assert dep.check_coverage["performed"] == ["xss"]
    assert dep.check_coverage_at is not None


def test_a_later_scan_that_reports_nothing_does_not_erase_what_one_reported():
    """Silence must not lift the cap. An engine that stopped reporting, or an
    older engine re-ingesting the same target, would otherwise clear a known gap."""
    dep = _dep()
    _record_reported_checks(_Scan({"coverage": _manifest(_row("tls", "not_performed"))}), dep)
    stored = _record_reported_checks(_Scan({"results": []}), dep)
    dep.refresh_from_db()
    assert stored is False
    assert dep.check_coverage["not_performed"] == ["tls"]
    assert checks_gap(dep) is True


# -- what the manifest then says --------------------------------------------

def test_nothing_reported_is_not_a_gap_and_not_completeness():
    dep = _dep()
    section = coverage_manifest(dep)["checks"]
    assert section["reported"] is False
    assert section["complete"] is None, "None, not False: it did not fall short, it did not say"
    assert section["total"] is None
    assert checks_gap(dep) is False


def test_every_check_performed_is_complete():
    dep = _dep()
    _record_reported_checks(
        _Scan({"coverage": _manifest(_row("xss", "performed"), _row("tls", "performed"))}), dep
    )
    dep.refresh_from_db()
    section = coverage_manifest(dep)["checks"]
    assert section["complete"] is True
    assert section["performed"] == 2
    assert checks_gap(dep) is False


@pytest.mark.parametrize("state", ["not_performed", "degraded", "unmeasured"])
def test_any_state_short_of_performed_is_a_gap(state):
    """Degraded lost probes; unmeasured cannot say what it looked at. Neither is
    the clean answer, and collapsing them into one would be a third silent zero."""
    dep = _dep()
    _record_reported_checks(
        _Scan({"coverage": _manifest(_row("xss", "performed"), _row("tls", state))}), dep
    )
    dep.refresh_from_db()
    assert coverage_manifest(dep)["checks"]["complete"] is False
    assert checks_gap(dep) is True


def test_a_check_that_did_not_run_carries_its_reason_not_just_its_name():
    """A name with no reason is the thing this replaces."""
    dep = _dep()
    _record_reported_checks(_Scan({"coverage": _manifest(
        _row("tls", "not_performed", reason="precondition",
             detail="The target is http, not https, so there is no TLS configuration."),
    )}), dep)
    dep.refresh_from_db()
    (row,) = coverage_manifest(dep)["checks"]["not_performed"]
    assert row["reason"] == "precondition"
    assert "https" in row["detail"]


def test_a_declared_limitation_survives_into_the_manifest():
    dep = _dep()
    _record_reported_checks(_Scan({"coverage": _manifest(
        _row("header_injection", "performed"),
        limitations={"header_injection": ["Raw CRLF header injection is not probed."]},
    )}), dep)
    dep.refresh_from_db()
    limitations = coverage_manifest(dep)["checks"]["limitations"]
    assert "CRLF" in limitations["header_injection"][0]


# -- and what it does to the decision ---------------------------------------

def test_a_fully_assessed_deployment_is_not_ready_when_a_check_never_ran():
    """The failure in one test.

    Every declared component assessed, nothing found -- and the engine never ran
    the TLS check. Before the check axis existed this deployment read COMPLETE and
    `complete_audit_signal` lifted it to READY.
    """
    dep = _dep()
    DeclaredComponent.objects.create(deployment=dep, kind=Asset.Kind.TOOL,
                                     name="t", identifier="t")
    asset = Asset.objects.create(deployment=dep, kind=Asset.Kind.TOOL, name="t",
                                 identifier="t",
                                 classification=Asset.Classification.KNOWN)
    record_assessment([asset], assessed_by="athena/2.1")

    # Asset axis alone: complete, and READY.
    assert coverage_manifest(dep)["verdict"] == COMPLETE
    assert complete_audit_signal(dep) == Deployment.Decision.READY

    _record_reported_checks(_Scan({"coverage": _manifest(
        _row("xss", "performed"),
        _row("tls", "not_performed", reason="precondition", detail="cleartext target"),
    )}), dep)
    dep.refresh_from_db()

    assert coverage_manifest(dep)["verdict"] == INCOMPLETE
    assert coverage_manifest(dep)["critical_gap"] is True
    assert complete_audit_signal(dep) is None, "a skipped check still read as a clean bill"
    assert coverage_decision_cap(dep) == Deployment.Decision.AUDIT_INCOMPLETE


def test_a_check_gap_caps_a_deployment_with_no_declared_architecture():
    """The one coverage gap that does not need the customer to have declared
    anything. The engine brought its own list of what it can run, so a check that
    did not run is a measured shortfall rather than an absent baseline -- which is
    what UNDECLARED means and what most early deployments would otherwise get.
    """
    dep = _dep()
    assert not dep.declared_components.exists()
    assert coverage_decision_cap(dep) is None  # nothing reported yet

    _record_reported_checks(_Scan({"coverage": _manifest(
        _row("xss", "performed"),
        _row("idor", "not_performed", reason="precondition",
             detail="authenticated scanning was not configured"),
    )}), dep)
    dep.refresh_from_db()

    assert coverage_decision_cap(dep) == Deployment.Decision.AUDIT_INCOMPLETE
    assert coverage_manifest(dep)["verdict"] == INCOMPLETE, (
        "a measured check gap was filed as 'no baseline to measure against'"
    )


def test_an_undeclared_deployment_whose_checks_all_ran_is_still_undeclared():
    """The negative control for the test above: the check axis must not paper
    over a missing declaration, only report its own dimension."""
    dep = _dep()
    _record_reported_checks(
        _Scan({"coverage": _manifest(_row("xss", "performed"))}), dep
    )
    dep.refresh_from_db()
    assert coverage_manifest(dep)["verdict"] == UNDECLARED
    assert coverage_decision_cap(dep) is None


def test_the_summary_names_both_axes():
    dep = _dep()
    _record_reported_checks(_Scan({"coverage": _manifest(
        _row("xss", "performed"), _row("tls", "not_performed"),
    )}), dep)
    dep.refresh_from_db()
    assert "Checks 1/2" in coverage_manifest(dep)["summary"]


# -- the contract, against what the engine actually emits ---------------------

def _real_manifest():
    """Athena's own coverage manifest, captured from a live scan.

    A golden fixture rather than a hand-written shape, because every other test
    in this file asserts against a payload this file also builds -- which proves
    the reader is self-consistent and nothing about whether it matches the engine.
    Regenerate by running a scan and dumping `run_scan(...)["coverage"]`.
    """
    import json
    import pathlib

    path = pathlib.Path(__file__).parent / "fixtures" / "athena_coverage_manifest.json"
    return json.loads(path.read_text())


def test_the_reader_accepts_the_manifest_the_engine_really_emits():
    read = _reported_checks({"coverage": _real_manifest()})
    assert read, "the backend could not read Athena's actual coverage manifest"
    assert len(read["checks"]) == 27
    # The three the engine reported on an ordinary http:// scan of a live fixture.
    assert read["not_performed"] == ["bruteforce", "idor", "tls"]
    assert "header_injection" in read["limitations"]


def test_the_real_manifest_caps_the_decision():
    """End to end on real data: this is the sentence the change exists to change."""
    dep = _dep()
    _record_reported_checks(_Scan({"coverage": _real_manifest()}), dep)
    dep.refresh_from_db()

    manifest = coverage_manifest(dep)
    assert manifest["checks"]["reported"] is True
    assert manifest["checks"]["complete"] is False
    assert manifest["verdict"] == INCOMPLETE
    assert complete_audit_signal(dep) is None
    assert coverage_decision_cap(dep) == Deployment.Decision.AUDIT_INCOMPLETE

    reasons = {row["check"]: row.get("reason") for row in manifest["checks"]["not_performed"]}
    assert reasons["tls"] == "precondition"
    assert reasons["idor"] == "precondition"
    assert reasons["bruteforce"] == "not_selected"


def test_every_state_in_the_real_manifest_is_one_this_side_knows():
    """The engine is a separate deployable. A state it adds must be a deliberate
    change here, not something that silently sorts into `unmeasured` or vanishes
    from every count."""
    from assurance.coverage import (
        CHECK_DEGRADED,
        CHECK_NOT_PERFORMED,
        CHECK_PERFORMED,
        CHECK_UNMEASURED,
    )

    known = {CHECK_PERFORMED, CHECK_DEGRADED, CHECK_NOT_PERFORMED, CHECK_UNMEASURED}
    seen = {row["state"] for row in _real_manifest()["checks"]}
    assert seen <= known, f"the engine reports states this side does not know: {seen - known}"


@pytest.mark.parametrize("state", ["not_performed", "degraded", "unmeasured"])
def test_the_verdict_is_never_complete_while_a_check_fell_short(state):
    """The invariant `complete_audit_signal` relies on instead of re-testing.

    It reads only the verdict, so COMPLETE is the single gate between a coverage
    manifest and a READY recommendation. This is the property that makes reading
    one field sufficient -- and it is asserted on a deployment whose asset axis is
    otherwise spotless, because that is the only case where the check axis is what
    decides.
    """
    dep = _dep()
    DeclaredComponent.objects.create(deployment=dep, kind=Asset.Kind.TOOL,
                                     name="t", identifier="t")
    asset = Asset.objects.create(deployment=dep, kind=Asset.Kind.TOOL, name="t",
                                 identifier="t",
                                 classification=Asset.Classification.KNOWN)
    record_assessment([asset], assessed_by="athena/2.1")
    _record_reported_checks(_Scan({"coverage": _manifest(_row("tls", state))}), dep)
    dep.refresh_from_db()

    assert coverage_manifest(dep)["verdict"] != COMPLETE
    assert complete_audit_signal(dep) is None
