"""Athena — Executive summary / ROI layer.

Proves the executive summary is an honest roll-up built only from real counts and
true ratios: asset coverage (classified vs unknown/shadow), evidence-strength
distribution, finding posture by severity, remediation velocity, and the standing
six-state decision. Above all it proves the honesty invariants: there is no dollar
figure, ROI amount, or realized-loss number anywhere in the output; a vendor-asserted
finding is not counted as independently evidenced; a resolved *remediation* state is
a process claim, not a security closure; the output is deterministic; and the API
read is open to any operator.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.capability import RISK_BASELINE, RISK_ELEVATED, RISK_HIGH
from assurance.models import (
    Asset,
    Deployment,
    Evidence,
    EvidenceClass,
    Finding,
    RemediationEvent,
)
from assurance.roi import (
    MATURITY_PARTIALLY_EVIDENCED,
    MATURITY_SPARSELY_EVIDENCED,
    MATURITY_WELL_EVIDENCED,
    build_executive_summary,
)
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _asset(dep, *, kind=Asset.Kind.MODEL, classification=Asset.Classification.KNOWN, name="c"):
    return Asset.objects.create(
        deployment=dep, kind=kind, classification=classification, name=name, identifier=name,
    )


def _finding(dep, finding_type="t", severity="high", *, status=Finding.Status.OPEN,
             remediation_state=Finding.RemediationState.NEW, evidence_class=None, n="1"):
    f = Finding.objects.create(
        deployment=dep, fingerprint=f"fp-{finding_type}-{n}", finding_type=finding_type,
        title=finding_type, severity=severity, status=status, remediation_state=remediation_state,
    )
    if evidence_class is not None:
        Evidence.objects.create(finding=f, classification=evidence_class, source="test")
    return f


def _walk_strings_and_keys(obj):
    """Yield every dict key and every string value in a nested structure."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield ("key", k)
            yield from _walk_strings_and_keys(v)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from _walk_strings_and_keys(item)
    elif isinstance(obj, str):
        yield ("value", obj)


def test_asset_coverage_is_real_counts_and_true_ratios():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, name="a", classification=Asset.Classification.KNOWN)
    _asset(dep, name="b", classification=Asset.Classification.APPROVED)
    _asset(dep, name="c", classification=Asset.Classification.UNKNOWN)
    _asset(dep, name="d", classification=Asset.Classification.UNMANAGED)

    cov = build_executive_summary(dep)["asset_coverage"]
    assert cov["total_assets"] == 4
    assert cov["classified"] == 2  # known + approved
    assert cov["managed"] == 2
    assert cov["unknown"] == 1
    # Two, not one. `shadow` used to be `== UNMANAGED`, which called an UNKNOWN
    # asset governed -- so of the two assets here that nothing stands behind,
    # the headline counted one. It is `is_shadow` now: the complement of
    # {APPROVED, KNOWN}, which is the same reading the capability map, the
    # vendor report and the access claim were already using. See
    # assurance.governance.
    assert cov["shadow"] == 2
    assert cov["coverage_ratio"] == 0.5  # 2/4
    assert cov["managed_ratio"] == 0.5


def test_coverage_ratio_is_none_when_no_assets_not_a_fake_zero():
    dep = Deployment.objects.create(name="d", owner=_user())
    cov = build_executive_summary(dep)["asset_coverage"]
    assert cov["total_assets"] == 0
    # None means "no basis to compute", never a fabricated 0%.
    assert cov["coverage_ratio"] is None
    assert cov["managed_ratio"] is None


def test_evidence_distribution_and_independence():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, evidence_class=EvidenceClass.TECHNICALLY_VERIFIED, n="a")
    _finding(dep, evidence_class=EvidenceClass.VENDOR_ASSERTED, n="b")
    _finding(dep, evidence_class=EvidenceClass.UNKNOWN, n="c")

    ev = build_executive_summary(dep)["evidence"]
    assert ev["finding_count"] == 3
    assert ev["by_class"][EvidenceClass.TECHNICALLY_VERIFIED] == 1
    # vendor_asserted is NOT independently evidenced; only technically_verified is.
    assert ev["independently_evidenced"] == 1
    assert ev["unverified"] == 1  # the UNKNOWN one


def test_finding_posture_by_severity_reads_only_active():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, severity="high", n="a")
    _finding(dep, severity="low", n="b")
    _finding(dep, severity="critical", status=Finding.Status.ACCEPTED, n="c")  # resolved

    f = build_executive_summary(dep)["findings"]
    assert f["total"] == 3
    assert f["active"] == 2
    assert f["resolved"] == 1
    assert f["active_by_severity"].get("high") == 1
    assert f["active_by_severity"].get("low") == 1
    # The resolved critical does not set the worst active severity.
    assert f["worst_active_severity"] == "high"


def test_remediation_velocity_from_state_and_events():
    dep = Deployment.objects.create(name="d", owner=_user())
    f1 = _finding(dep, remediation_state=Finding.RemediationState.RESOLVED, n="a")
    f2 = _finding(dep, remediation_state=Finding.RemediationState.IN_PROGRESS, n="b")
    _finding(dep, remediation_state=Finding.RemediationState.WONT_FIX, n="c")
    # A little attributed history.
    RemediationEvent.objects.create(finding=f1, from_state="new", to_state="triaged")
    RemediationEvent.objects.create(finding=f1, from_state="in_review", to_state="resolved")
    RemediationEvent.objects.create(finding=f2, from_state="triaged", to_state="in_progress")

    rem = build_executive_summary(dep)["remediation"]
    assert rem["resolved"] == 1
    assert rem["wont_fix"] == 1
    assert rem["open"] == 1  # only the in_progress one is open work
    assert rem["event_count"] == 3
    assert set(rem["states_reached"]) == {"triaged", "resolved", "in_progress"}
    assert rem["resolution_ratio"] == round(1 / 3, 4)


def test_decision_is_reported_none_safe():
    dep = Deployment.objects.create(name="d", owner=_user())
    result = build_executive_summary(dep)
    # No decision computed yet — never silently read as ready.
    assert result["decision"]["decision"] is None
    assert result["decision"]["decision_label"] is None

    dep.decision = Deployment.Decision.NEEDS_REMEDIATION
    dep.save(update_fields=["decision"])
    result = build_executive_summary(dep)
    assert result["decision"]["decision"] == Deployment.Decision.NEEDS_REMEDIATION
    assert result["decision"]["decision_label"] == "Requires remediation"


def test_no_dollar_figure_anywhere_in_the_output():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, name="a")
    _finding(dep, severity="critical", evidence_class=EvidenceClass.VENDOR_ASSERTED)

    result = build_executive_summary(dep)
    forbidden_keys = {
        "dollar", "dollars", "usd", "currency", "amount", "roi", "revenue",
        "loss", "losses", "arr", "acv", "cost", "savings", "price", "money",
    }
    for kind, text in _walk_strings_and_keys(result):
        low = text.lower()
        if kind == "key":
            assert low not in forbidden_keys, f"forbidden money key: {text!r}"
        # No string value may carry a currency symbol.
        assert "$" not in text and "€" not in text and "£" not in text


def test_posture_band_reuses_risk_vocabulary():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, severity="critical")
    result = build_executive_summary(dep)
    assert result["posture"] in {RISK_HIGH, RISK_ELEVATED, RISK_BASELINE}
    # A critical active finding is a high posture.
    assert result["posture"] == RISK_HIGH


def test_shadow_asset_raises_posture_off_baseline():
    dep = Deployment.objects.create(name="d", owner=_user())
    # No active findings, but a shadow (unmanaged) asset — not baseline.
    _asset(dep, name="shadow", classification=Asset.Classification.UNMANAGED)
    result = build_executive_summary(dep)
    assert result["posture"] == RISK_ELEVATED


def test_assurance_maturity_is_a_qualitative_band_from_coverage():
    valid = {MATURITY_WELL_EVIDENCED, MATURITY_PARTIALLY_EVIDENCED, MATURITY_SPARSELY_EVIDENCED}

    # Fully classified assets, all findings independently evidenced → well evidenced.
    dep = Deployment.objects.create(name="strong", owner=_user("strong-owner"))
    for i in range(4):
        _asset(dep, name=f"a{i}", classification=Asset.Classification.APPROVED)
    _finding(dep, evidence_class=EvidenceClass.TECHNICALLY_VERIFIED)
    strong = build_executive_summary(dep)
    assert strong["assurance_maturity"] in valid
    assert strong["assurance_maturity"] == MATURITY_WELL_EVIDENCED

    # Nothing discovered → sparsely evidenced, honestly.
    empty = Deployment.objects.create(name="empty", owner=_user("empty-owner"))
    assert build_executive_summary(empty)["assurance_maturity"] == MATURITY_SPARSELY_EVIDENCED


def test_assessments_headlines_are_rolled_up():
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, "prompt_injection", "high")
    result = build_executive_summary(dep)
    a = result["assessments"]
    assert set(a) == {"compliance", "business_impact", "capabilities", "boundary", "vendors"}
    # The compliance headline reflects the open finding's control gap.
    assert a["compliance"]["controls_with_active_findings"] >= 1
    assert a["compliance"]["worst_severity"] == "high"


def test_output_is_deterministic():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, name="a", classification=Asset.Classification.KNOWN)
    _asset(dep, name="b", classification=Asset.Classification.UNMANAGED)
    _finding(dep, "sql_injection", "high", evidence_class=EvidenceClass.VENDOR_ASSERTED, n="a")
    _finding(dep, "prompt_injection", "medium", evidence_class=EvidenceClass.UNKNOWN, n="b")
    assert build_executive_summary(dep) == build_executive_summary(dep)


def test_executive_summary_api_is_open_to_any_operator():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    _asset(dep, name="a")
    _finding(dep, severity="high")

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "executive_summary"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/executive-summary/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["findings"]["total"] == 1
    assert resp.data["asset_coverage"]["total_assets"] == 1
    assert "posture" in resp.data and "assurance_maturity" in resp.data
