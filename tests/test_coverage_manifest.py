"""Phase 2 item 1: the Coverage Manifest and AUDIT_INCOMPLETE.

The failure this exists for: three agents, seven tools and two MCP servers were
assessed, four, nine and three exist, every captured fact is genuine, and the
decision reads READY because everything *inspected* looked good.
"""

from __future__ import annotations

import pytest
from assurance.coverage import (
    COMPLETE,
    INCOMPLETE,
    UNDECLARED,
    coverage_decision_cap,
    coverage_manifest,
    record_assessment,
)
from assurance.decision import compute_decision
from assurance.models import Asset, DeclaredComponent, Deployment, Finding
from django.contrib.auth import get_user_model
from django.utils import timezone

pytestmark = pytest.mark.django_db

User = get_user_model()


def _dep():
    user = User.objects.create_user(
        username=f"cov-{Deployment.objects.count()}", password="x", role=User.Roles.ANALYST
    )
    return Deployment.objects.create(name="d", owner=user)


def _asset(dep, name, *, kind=Asset.Kind.TOOL, identifier="", classification=None, assessed=False):
    asset = Asset.objects.create(
        deployment=dep,
        kind=kind,
        name=name,
        identifier=identifier or name,
        classification=classification or Asset.Classification.KNOWN,
    )
    if assessed:
        record_assessment([asset], assessed_by="achilles/1.0")
    return asset


def _declare(dep, name, *, kind=Asset.Kind.TOOL, identifier=""):
    # DeclaredComponent is unique on (deployment, kind, identifier), and the
    # manifest matches on identifier-or-name, so giving the identifier the name
    # keeps both the constraint and the match honest.
    return DeclaredComponent.objects.create(
        deployment=dep, kind=kind, name=name, identifier=identifier or name
    )


# ---------------------------------------------------------------------------
# The three sets
# ---------------------------------------------------------------------------


def test_the_manifest_reports_all_three_tallies_and_names_what_is_missing():
    dep = _dep()
    for i in range(3):
        _declare(dep, f"tool-{i}")
    _asset(dep, "tool-0", assessed=True)
    _asset(dep, "tool-1")  # observed, declared, never assessed
    # tool-2 was declared and never observed at all.

    manifest = coverage_manifest(dep)
    assert manifest["expected"] == 3
    assert manifest["observed"] == 2
    assert manifest["assessed"] == 1
    assert manifest["summary"] == "Expected 3 / Observed 2 / Assessed 1 -> INCOMPLETE"

    # Named, not just counted: a completeness figure with nothing named is a number
    # a reader cannot act on.
    assert [c["name"] for c in manifest["never_observed"]] == ["tool-2"]
    assert [c["name"] for c in manifest["declared_but_unassessed"]] == ["tool-1"]


def test_observing_an_asset_is_not_assessing_it():
    """Discovery finding that an MCP server exists says nothing about whether
    anything probed it."""
    dep = _dep()
    _declare(dep, "mcp-a", kind=Asset.Kind.MCP_SERVER)
    _asset(dep, "mcp-a", kind=Asset.Kind.MCP_SERVER)

    manifest = coverage_manifest(dep)
    assert manifest["observed"] == 1
    assert manifest["assessed"] == 0
    assert manifest["verdict"] == INCOMPLETE


def test_a_clean_asset_with_no_findings_is_not_counted_as_assessed():
    """A clean test leaves no finding, so "no finding here" means either "tested
    and clean" or "never tested". Coverage must not be read off the findings."""
    dep = _dep()
    _declare(dep, "tool-0")
    asset = _asset(dep, "tool-0")
    assert dep.findings.count() == 0

    assert coverage_manifest(dep)["assessed"] == 0

    record_assessment([asset], assessed_by="athena/2.1")
    assert coverage_manifest(dep)["assessed"] == 1


def test_recording_an_assessment_says_what_did_it_and_when():
    dep = _dep()
    asset = _asset(dep, "tool-0")
    before = timezone.now()
    assert record_assessment([asset], assessed_by="achilles/1.0") == 1

    asset.refresh_from_db()
    assert asset.assessed_by == "achilles/1.0"
    assert asset.assessed_at >= before
    assert coverage_manifest(dep)["unassessed"] == []


# ---------------------------------------------------------------------------
# The verdict, including the one that is neither complete nor incomplete
# ---------------------------------------------------------------------------


def test_everything_declared_and_assessed_is_complete():
    dep = _dep()
    _declare(dep, "tool-0")
    _asset(dep, "tool-0", assessed=True)

    manifest = coverage_manifest(dep)
    assert manifest["verdict"] == COMPLETE
    assert manifest["complete"] is True
    assert manifest["critical_gap"] is False


def test_no_declared_baseline_is_undeclared_and_never_complete():
    """You cannot confirm an assessment is complete against a declaration that does
    not exist. Calling it complete would turn a missing declaration into a pass."""
    dep = _dep()
    _asset(dep, "tool-0", assessed=True)

    manifest = coverage_manifest(dep)
    assert manifest["verdict"] == UNDECLARED
    assert manifest["complete"] is False
    assert manifest["has_declared_baseline"] is False


def test_an_undeclared_unflagged_asset_is_reported_but_does_not_block():
    """Reporting it is honest; blocking on a component nobody declared and nobody
    flagged would be acting on a judgment nobody made."""
    dep = _dep()
    _declare(dep, "tool-0")
    _asset(dep, "tool-0", assessed=True)
    _asset(dep, "shadow-tool")  # never declared, never assessed, not flagged

    manifest = coverage_manifest(dep)
    assert [c["name"] for c in manifest["unassessed"]] == ["shadow-tool"]
    assert manifest["critical_gap"] is False
    assert manifest["verdict"] == COMPLETE


def test_a_high_risk_unassessed_asset_blocks_even_though_it_was_never_declared():
    """HIGH_RISK is a judgment a deriver or a human recorded deliberately, so it is
    a fact the manifest may act on."""
    dep = _dep()
    _declare(dep, "tool-0")
    _asset(dep, "tool-0", assessed=True)
    _asset(dep, "shadow-agent", kind=Asset.Kind.AGENT, classification=Asset.Classification.HIGH_RISK)

    manifest = coverage_manifest(dep)
    assert [c["name"] for c in manifest["high_risk_unassessed"]] == ["shadow-agent"]
    assert manifest["critical_gap"] is True
    assert manifest["verdict"] == INCOMPLETE


# ---------------------------------------------------------------------------
# The decision
# ---------------------------------------------------------------------------


def test_a_deployment_cannot_be_ready_while_a_declared_component_is_unassessed():
    """The headline: everything inspected looked good, and the audit is short."""
    dep = _dep()
    _declare(dep, "tool-0")
    _declare(dep, "tool-1")
    _asset(dep, "tool-0", assessed=True)
    _asset(dep, "tool-1")

    assert coverage_decision_cap(dep) == Deployment.Decision.AUDIT_INCOMPLETE
    assert compute_decision(dep) == Deployment.Decision.AUDIT_INCOMPLETE


def test_a_complete_audit_imposes_no_cap():
    dep = _dep()
    _declare(dep, "tool-0")
    _asset(dep, "tool-0", assessed=True)
    assert coverage_decision_cap(dep) is None


def test_a_deployment_with_no_declaration_gets_no_cap():
    """Not a judgment that it is fine -- the absence of the thing a cap would be
    measured against. It is reported as UNDECLARED instead of blocking."""
    dep = _dep()
    _asset(dep, "tool-0")
    assert coverage_decision_cap(dep) is None


def test_a_critical_finding_still_outranks_an_incomplete_audit():
    """"We found something bad" is a fact; "we did not look everywhere" is a gap.
    The worse of the two is the finding."""
    dep = _dep()
    _declare(dep, "tool-0")
    _asset(dep, "tool-0")  # declared, unassessed -> AUDIT_INCOMPLETE on its own
    Finding.objects.create(
        deployment=dep, fingerprint="fp-crit", finding_type="t", title="T", severity="critical"
    )
    assert compute_decision(dep) == Deployment.Decision.NOT_RECOMMENDED


def test_audit_incomplete_outranks_needs_more_evidence():
    """Both are "we do not know". A coverage gap is the wider one: weak evidence at
    least has a subject, an unassessed component could hold anything."""
    from assurance.decision import _worse

    assert (
        _worse(Deployment.Decision.NEEDS_MORE_EVIDENCE, Deployment.Decision.AUDIT_INCOMPLETE)
        == Deployment.Decision.AUDIT_INCOMPLETE
    )
    assert (
        _worse(Deployment.Decision.AUDIT_INCOMPLETE, Deployment.Decision.NEEDS_REMEDIATION)
        == Deployment.Decision.NEEDS_REMEDIATION
    )


def test_audit_incomplete_is_a_coverage_state_not_an_evidence_state():
    """Distinct states, and the distinction is the point: one says the assessed
    parts are thinly known, the other says parts were never assessed."""
    assert Deployment.Decision.AUDIT_INCOMPLETE != Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert Deployment.Decision.AUDIT_INCOMPLETE.label == "Audit incomplete"


def test_assessing_the_last_gap_lifts_the_cap():
    dep = _dep()
    _declare(dep, "tool-0")
    asset = _asset(dep, "tool-0")
    assert compute_decision(dep) == Deployment.Decision.AUDIT_INCOMPLETE

    record_assessment([asset], assessed_by="achilles/1.0")
    assert compute_decision(dep) == Deployment.Decision.READY


# ---------------------------------------------------------------------------
# The ingest records coverage only when the engine reports it
# ---------------------------------------------------------------------------


def _completed_scan(user, response):
    from pentest.models import PentestScan

    return PentestScan.objects.create(
        user=user,
        target_url="https://app.client.example/login",
        consent=True,
        status=PentestScan.STATUS_COMPLETED,
        engine_response=response,
    )


def test_an_engine_that_reports_coverage_has_it_recorded():
    from assurance import ingest

    user = User.objects.create_user(username="cov-ing", password="x", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d-ing", owner=user)
    _declare(dep, "chat-model", kind=Asset.Kind.MODEL)
    asset = _asset(dep, "chat-model", kind=Asset.Kind.MODEL)

    ingest.ingest_scan(
        _completed_scan(
            user,
            {
                "findings": [],
                "coverage": {
                    "engine": "achilles/1.4",
                    "assessed": [{"kind": "model", "identifier": "chat-model"}],
                },
            },
        ),
        deployment=dep,
    )

    asset.refresh_from_db()
    assert asset.assessed_at is not None
    assert asset.assessed_by == "achilles/1.4"
    assert coverage_manifest(dep)["verdict"] == COMPLETE


def test_an_engine_that_reports_no_coverage_leaves_everything_unassessed():
    """Not "everything was assessed" -- that reading would make the whole manifest
    decorative, which is worse than not having one."""
    from assurance import ingest

    user = User.objects.create_user(username="cov-ing2", password="x", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d-ing2", owner=user)
    _declare(dep, "chat-model", kind=Asset.Kind.MODEL)
    asset = _asset(dep, "chat-model", kind=Asset.Kind.MODEL)

    ingest.ingest_scan(_completed_scan(user, {"findings": []}), deployment=dep)

    asset.refresh_from_db()
    assert asset.assessed_at is None
    assert coverage_manifest(dep)["verdict"] == INCOMPLETE


def test_a_malformed_coverage_block_records_nothing_rather_than_everything():
    from assurance import ingest

    user = User.objects.create_user(username="cov-ing3", password="x", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d-ing3", owner=user)
    _declare(dep, "chat-model", kind=Asset.Kind.MODEL)
    asset = _asset(dep, "chat-model", kind=Asset.Kind.MODEL)

    ingest.ingest_scan(
        _completed_scan(user, {"findings": [], "coverage": {"assessed": "all of it"}}),
        deployment=dep,
    )
    asset.refresh_from_db()
    assert asset.assessed_at is None


def test_coverage_for_a_component_the_deployment_does_not_have_stamps_nothing():
    """An engine naming something this deployment has no asset for must not create
    one, and must not silently count as coverage of anything else."""
    from assurance import ingest

    user = User.objects.create_user(username="cov-ing4", password="x", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d-ing4", owner=user)
    _declare(dep, "chat-model", kind=Asset.Kind.MODEL)
    asset = _asset(dep, "chat-model", kind=Asset.Kind.MODEL)

    ingest.ingest_scan(
        _completed_scan(
            user,
            {
                "findings": [],
                "coverage": {"engine": "e", "assessed": [{"kind": "model", "identifier": "other"}]},
            },
        ),
        deployment=dep,
    )
    asset.refresh_from_db()
    assert asset.assessed_at is None
    # And it stamped nothing else either. (The ingest's own asset discovery adds
    # the scan target as an asset, which is why this counts stamps rather than
    # assets.)
    assert not dep.assets.exclude(assessed_at=None).exists()
