"""SPINE Stage 1C + 1D — Claims → Decisions, and the targeted revalidation planner.

1C proves the six-state decision now depends on the deployment's CURRENT assurance
claims, combined worst-first with the finding-based signal:

- with no claims, the decision is exactly the finding-based decision (backward
  compatible);
- a live CONTRADICTED claim holds a would-be READY at NEEDS_REMEDIATION;
- a STALE or UNKNOWN claim, or an open retest obligation, holds it at
  NEEDS_MORE_EVIDENCE;
- supported/verified claims impose no cap, so READY stands;
- the cap only ever *lowers* a decision (a critical finding still wins), a human
  REVOKED claim is ignored, and ``paused`` overrides everything;
- with neither findings nor claims the decision is None (never READY).

1D proves the revalidation planner names the MINIMAL work a change implies — the
exact Athena reassessment and Achilles capability areas per invalidated claim — and
lists everything that stays current, rather than "re-run everything".
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.decision import (
    claim_decision_signal,
    compute_decision,
    decision_support,
    recompute_decision,
)
from assurance.models import (
    Asset,
    AssuranceClaim,
    DataBoundary,
    Deployment,
    EvidenceClass,
    Finding,
    Provider,
    ProviderAssertion,
    RetestRequirement,
)
from assurance.revalidation import plan_revalidation
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType
Decision = Deployment.Decision


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _finding(dep, *, severity, status=Finding.Status.OPEN, n="1", evidence=None):
    f = Finding.objects.create(
        deployment=dep,
        fingerprint=f"fp-{severity}-{n}",
        finding_type="probe",
        title="Probe",
        severity=severity,
        status=status,
    )
    if evidence is not None:
        f.evidence.create(classification=evidence)
    return f


def _ready_deployment(name="d", owner=None):
    """A deployment whose finding-based decision is READY: one resolved finding, so
    it has been assessed but nothing is active against it."""
    dep = Deployment.objects.create(name=name, owner=owner or _user(name + "-owner"))
    _finding(dep, severity="high", status=Finding.Status.CLOSED)
    return dep


def _claim(dep, *, status, claim_type=ClaimType.DATA_BOUNDARY, fingerprint=None, evidence_class=EvidenceClass.CONFIGURATION_VERIFIED):
    now = timezone.now()
    return AssuranceClaim.objects.create(
        deployment=dep,
        claim_type=claim_type,
        statement=f"{claim_type} holds",
        fingerprint=fingerprint or f"id-{claim_type}",
        system_fingerprint="sysfp",
        policy_version="v",
        environment=dep.environment,
        status=status,
        evidence_class=evidence_class,
        valid_from=now,
        first_seen=now,
        last_seen=now,
    )


def _retest(dep, claim, reason="System fingerprint changed; retest due."):
    return RetestRequirement.objects.create(
        deployment=dep,
        claim=claim,
        reason=reason,
        triggering_system_fingerprint="newfp",
        opened_at=timezone.now(),
    )


# ---------------------------------------------------------------------------
# 1C — the claim gate on compute_decision
# ---------------------------------------------------------------------------


def test_no_claims_is_backward_compatible():
    """With no claims, the decision is exactly the finding-based decision."""
    ready = _ready_deployment()
    assert compute_decision(ready) == Decision.READY

    crit = Deployment.objects.create(name="c", owner=_user("c-owner"))
    _finding(crit, severity="critical")
    assert compute_decision(crit) == Decision.NOT_RECOMMENDED


def test_no_findings_and_no_claims_is_none():
    dep = Deployment.objects.create(name="d", owner=_user())
    assert compute_decision(dep) is None


def test_contradicted_claim_caps_ready_at_needs_remediation():
    dep = _ready_deployment()
    _claim(dep, status=Status.CONTRADICTED)
    assert compute_decision(dep) == Decision.NEEDS_REMEDIATION


def test_stale_claim_caps_ready_at_needs_more_evidence():
    dep = _ready_deployment()
    _claim(dep, status=Status.STALE)
    assert compute_decision(dep) == Decision.NEEDS_MORE_EVIDENCE


def test_unknown_claim_caps_ready_at_needs_more_evidence():
    dep = _ready_deployment()
    _claim(dep, status=Status.UNKNOWN, evidence_class=EvidenceClass.UNKNOWN)
    assert compute_decision(dep) == Decision.NEEDS_MORE_EVIDENCE


def test_open_retest_obligation_caps_ready_at_needs_more_evidence():
    dep = _ready_deployment()
    claim = _claim(dep, status=Status.SUPPORTED)  # the claim itself still reads supported...
    _retest(dep, claim)  # ...but a change opened a retest obligation on it.
    assert compute_decision(dep) == Decision.NEEDS_MORE_EVIDENCE


def test_a_resolved_retest_does_not_cap():
    dep = _ready_deployment()
    claim = _claim(dep, status=Status.SUPPORTED)
    req = _retest(dep, claim)
    req.resolved_at = timezone.now()
    req.resolving_claim = claim
    req.save()
    assert compute_decision(dep) == Decision.READY


def test_supported_and_verified_claims_do_not_cap():
    dep = _ready_deployment()
    _claim(dep, status=Status.SUPPORTED, fingerprint="a")
    _claim(dep, status=Status.VERIFIED, fingerprint="b", claim_type=ClaimType.EFFECTIVE_ACCESS)
    assert compute_decision(dep) == Decision.READY


def test_cap_only_lowers_never_raises():
    """A critical finding (NOT_RECOMMENDED) is worse than any claim cap, so a stale
    claim cannot make the decision look better."""
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, severity="critical")
    _claim(dep, status=Status.STALE)
    assert compute_decision(dep) == Decision.NOT_RECOMMENDED


def test_contradicted_claim_worse_than_a_low_finding():
    """A LOW finding alone is READY_RESTRICTED; a contradicted claim is worse, so the
    contradiction wins."""
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, severity="low")
    assert compute_decision(dep) == Decision.READY_RESTRICTED
    _claim(dep, status=Status.CONTRADICTED)
    assert compute_decision(dep) == Decision.NEEDS_REMEDIATION


def test_revoked_claim_is_ignored():
    dep = _ready_deployment()
    _claim(dep, status=Status.REVOKED)
    assert compute_decision(dep) == Decision.READY


def test_superseded_version_does_not_cap():
    """A superseded version is not current (valid_to set), so it never caps."""
    dep = _ready_deployment()
    c = _claim(dep, status=Status.CONTRADICTED)
    c.valid_to = timezone.now()
    c.status = Status.SUPERSEDED
    c.save()
    assert compute_decision(dep) == Decision.READY


def test_claims_only_deployment_is_assessed_by_claims():
    """No findings but a contradicted claim: the deployment IS assessed (via the
    claim), so the decision is not None."""
    dep = Deployment.objects.create(name="d", owner=_user())
    _claim(dep, status=Status.CONTRADICTED)
    assert compute_decision(dep) == Decision.NEEDS_REMEDIATION


def test_paused_overrides_everything():
    dep = _ready_deployment()
    _claim(dep, status=Status.CONTRADICTED)
    assert compute_decision(dep, paused=True) == Decision.PAUSED


def test_recompute_decision_persists_the_gated_decision():
    dep = _ready_deployment()
    _claim(dep, status=Status.CONTRADICTED)
    recompute_decision(dep)
    dep.refresh_from_db()
    assert dep.decision == Decision.NEEDS_REMEDIATION


def test_claim_decision_signal_buckets():
    dep = _ready_deployment()
    _claim(dep, status=Status.CONTRADICTED, fingerprint="x")
    _claim(dep, status=Status.SUPPORTED, fingerprint="y", claim_type=ClaimType.AI_BOM)
    signal = claim_decision_signal(dep)
    assert signal["cap"] == Decision.NEEDS_REMEDIATION
    assert len(signal["contradicted"]) == 1
    assert len(signal["supporting"]) == 1
    assert signal["has_claims"] is True


def test_decision_support_explains_a_held_decision():
    dep = _ready_deployment()
    _claim(dep, status=Status.CONTRADICTED)
    support = decision_support(dep)
    assert support["decision"] == Decision.NEEDS_REMEDIATION
    assert support["from_findings"] == Decision.READY
    assert support["claim_cap"] == Decision.NEEDS_REMEDIATION
    assert len(support["claims"]["contradicted"]) == 1
    assert "contradicted" in support["note"].lower()


def test_decision_support_notes_a_supported_ready():
    dep = _ready_deployment()
    _claim(dep, status=Status.VERIFIED)
    support = decision_support(dep)
    assert support["decision"] == Decision.READY
    assert "supported by 1" in support["note"]


# ---------------------------------------------------------------------------
# 1D — the targeted revalidation planner
# ---------------------------------------------------------------------------


def test_open_retest_puts_the_claim_in_required_with_its_minimal_work():
    dep = Deployment.objects.create(name="d", owner=_user())
    access = _claim(dep, status=Status.SUPPORTED, claim_type=ClaimType.EFFECTIVE_ACCESS, fingerprint="acc")
    _claim(dep, status=Status.VERIFIED, claim_type=ClaimType.DATA_BOUNDARY, fingerprint="bnd")
    _retest(dep, access, reason="CRM tool permissions changed.")

    plan = plan_revalidation(dep)
    assert plan["summary"]["required"] == 1
    assert plan["summary"]["still_current"] == 1
    item = plan["required"][0]
    assert item["claim_type"] == ClaimType.EFFECTIVE_ACCESS
    assert item["reason"] == "CRM tool permissions changed."
    assert "effective-access" in item["athena_reassessments"][0]
    assert item["achilles_capabilities"] == ["Permission Boundary", "Agent / Tool Misuse"]
    # The boundary claim is untouched — the whole point of a targeted plan.
    assert plan["still_current"][0]["claim_type"] == ClaimType.DATA_BOUNDARY


def test_ai_bom_has_no_achilles_behavioural_retest():
    dep = Deployment.objects.create(name="d", owner=_user())
    bom = _claim(dep, status=Status.STALE, claim_type=ClaimType.AI_BOM, fingerprint="bom")
    plan = plan_revalidation(dep)
    item = next(w for w in plan["required"] if w["claim_uuid"] == str(bom.uuid))
    assert item["achilles_capabilities"] == []
    assert "AI-BOM" in item["athena_reassessments"][0]


def test_contradicted_and_stale_claims_are_required_with_honest_reasons():
    dep = Deployment.objects.create(name="d", owner=_user())
    _claim(dep, status=Status.CONTRADICTED, claim_type=ClaimType.DATA_BOUNDARY, fingerprint="c")
    _claim(dep, status=Status.STALE, claim_type=ClaimType.EFFECTIVE_ACCESS, fingerprint="s")
    plan = plan_revalidation(dep)
    assert plan["summary"]["required"] == 2
    reasons = " ".join(w["reason"] for w in plan["required"]).lower()
    assert "contradict" in reasons and "expired" in reasons


def test_unknown_claim_is_an_outstanding_gap_not_change_driven():
    dep = Deployment.objects.create(name="d", owner=_user())
    _claim(dep, status=Status.UNKNOWN, evidence_class=EvidenceClass.UNKNOWN, fingerprint="u")
    plan = plan_revalidation(dep)
    assert plan["summary"]["required"] == 0
    assert plan["summary"]["outstanding_unknowns"] == 1


def test_all_current_means_nothing_to_rerun():
    dep = Deployment.objects.create(name="d", owner=_user())
    _claim(dep, status=Status.SUPPORTED, fingerprint="a")
    _claim(dep, status=Status.VERIFIED, fingerprint="b", claim_type=ClaimType.AI_BOM)
    plan = plan_revalidation(dep)
    assert plan["required"] == []
    assert plan["summary"]["still_current"] == 2
    assert "nothing needs to be re-run" in plan["note"].lower()


def test_revoked_claim_is_excluded_from_the_plan():
    dep = Deployment.objects.create(name="d", owner=_user())
    _claim(dep, status=Status.REVOKED, fingerprint="r")
    plan = plan_revalidation(dep)
    assert plan["summary"] == {
        "required": 0,
        "still_current": 0,
        "outstanding_unknowns": 0,
        "workflows_to_exercise": 0,
    }
    assert plan["workflows_to_exercise"] == []


def test_a_retest_left_open_on_a_revoked_claim_is_never_called_nothing_to_re_run():
    """A person revoked a claim a retest was open on. The decision reads every open
    retest on the deployment and is held at needs more evidence; the plan maps retests
    to current, unrevoked claims only, and said "no open retest obligation ... Nothing
    needs to be re-run" beside it (#105 round 5)."""
    dep = _ready_deployment()
    _claim(dep, status=Status.SUPPORTED, fingerprint="kept")
    revoked = _claim(dep, status=Status.REVOKED, fingerprint="r", claim_type=ClaimType.AI_BOM)
    retest = _retest(dep, revoked)

    plan = plan_revalidation(dep)

    assert claim_decision_signal(dep)["retest_pending"] is True
    assert compute_decision(dep) == Decision.NEEDS_MORE_EVIDENCE
    assert plan["required"] == []
    assert "nothing needs to be re-run" not in plan["note"].lower()
    assert not plan["note"].startswith("No claim needs revalidation")
    assert "1 open retest obligation(s)" in plan["note"]
    assert [r["retest_requirement_uuid"] for r in plan["open_retests_without_a_current_claim"]] == [str(retest.uuid)]


def test_plan_carries_a_deterministic_fingerprint():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = Provider.objects.create(name="OpenAI", kind=Provider.Kind.MODEL_PROVIDER)
    ProviderAssertion.objects.create(provider=p, field="region", value="eu", evidence_class=EvidenceClass.CONFIGURATION_VERIFIED)
    Asset.objects.create(deployment=dep, provider=p, kind=Asset.Kind.MODEL, name="m", identifier="m", metadata={"region": "eu"})
    DataBoundary.objects.create(deployment=dep, allowed_regions=["eu"])
    a = plan_revalidation(dep)
    b = plan_revalidation(dep)
    assert a["system_fingerprint"] == b["system_fingerprint"]
    assert len(a["system_fingerprint"]) == 64


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------


def test_decision_support_endpoint_returns_200():
    owner = _user("o")
    dep = _ready_deployment(owner=owner)
    _claim(dep, status=Status.CONTRADICTED)
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "decision_support"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/decision-support/")
    force_authenticate(req, user=owner)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["decision"] == Decision.NEEDS_REMEDIATION
    assert resp.data["claim_cap"] == Decision.NEEDS_REMEDIATION


def test_revalidation_plan_endpoint_returns_200():
    owner = _user("o")
    dep = Deployment.objects.create(name="d", owner=owner)
    claim = _claim(dep, status=Status.SUPPORTED, claim_type=ClaimType.EFFECTIVE_ACCESS)
    _retest(dep, claim)
    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "revalidation_plan"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/revalidation-plan/")
    force_authenticate(req, user=owner)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["summary"]["required"] == 1
