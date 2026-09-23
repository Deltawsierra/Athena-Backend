"""A claim that says "part of the graph could not be read" must not be reported
as one that says "we checked, and it is fine".

``Status.PARTIALLY_VERIFIED`` reached ``_derive_effective_access`` in #77, where
it is the honest answer for a reach computed over a graph with an unplaceable
reference in it. Two places that generate *prose about* claims had not been told
it exists, and both fell through to a default that asserted something false:

- ``revalidation.plan_revalidation`` bucketed it into ``still_current``, whose
  own contract is "supported/verified with no open obligation: explicitly NOT
  re-run", and then said "every current claim is supported or verified ...
  Nothing needs to be re-run." The unplaceable reference is the ONE item in the
  plan a person could actually go and chase.
- ``decision.decision_support`` counted it inside "supported by N current
  assurance claim(s)", with nothing marking it apart.

Neither is a wrong *decision* -- PARTIALLY_VERIFIED deliberately imposes no cap,
because a limit on the measurement is not a defect to remediate. Both are wrong
*statements*, which is the same defect class as a manufactured finding: an
operator acts on the sentence, not on the enum.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone

from assurance.decision import decision_support, recompute_decision
from assurance.models import AssuranceClaim, Deployment, EvidenceClass, Finding
from assurance.revalidation import plan_revalidation

pytestmark = pytest.mark.django_db

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType


def _dep(name):
    owner = User.objects.create_user(username=f"{name}-owner", password="x", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name=name, owner=owner)
    # One closed finding: the deployment HAS been assessed, and nothing is active
    # against it, so the finding-based decision is READY and the claims decide.
    Finding.objects.create(
        deployment=dep, fingerprint=f"fp-{name}", finding_type="probe", title="Probe",
        severity="high", status=Finding.Status.CLOSED,
    )
    return dep


def _claim(dep, *, status, claim_type=ClaimType.EFFECTIVE_ACCESS, evidence_class=EvidenceClass.CONFIGURATION_VERIFIED):
    now = timezone.now()
    return AssuranceClaim.objects.create(
        deployment=dep, claim_type=claim_type, statement=f"{claim_type} holds",
        fingerprint=f"id-{claim_type}", system_fingerprint="sysfp", policy_version="v",
        environment=dep.environment, status=status, evidence_class=evidence_class,
        valid_from=now, first_seen=now, last_seen=now,
    )


# ---- the revalidation plan -------------------------------------------------


def test_a_partially_verified_claim_is_not_reported_as_still_current():
    """It is not "supported/verified with no open obligation". It is a claim that
    could not be fully established, which is what ``outstanding_unknowns`` is
    for: work to reach assurance, distinct from what a change invalidated."""
    dep = _dep("partial")
    _claim(dep, status=Status.PARTIALLY_VERIFIED, evidence_class=EvidenceClass.PARTIALLY_VERIFIED)

    plan = plan_revalidation(dep)

    assert [c["claim_type"] for c in plan["still_current"]] == []
    assert [c["claim_type"] for c in plan["outstanding_unknowns"]] == [ClaimType.EFFECTIVE_ACCESS]
    # And distinguishable from a real UNKNOWN once inside that bucket.
    assert plan["outstanding_unknowns"][0]["status"] == Status.PARTIALLY_VERIFIED


def test_the_plan_does_not_say_nothing_needs_re_running_over_a_gap():
    """The note is the part an operator reads. It said "every current claim is
    supported or verified ... Nothing needs to be re-run" -- two statements, both
    false, about the one claim that exists to record a gap."""
    dep = _dep("note")
    _claim(dep, status=Status.PARTIALLY_VERIFIED, evidence_class=EvidenceClass.PARTIALLY_VERIFIED)

    note = plan_revalidation(dep)["note"]

    assert "Nothing needs to be re-run" not in note
    assert "every current claim is supported or verified" not in note
    assert "not fully established" in note
    # And it says why re-running will not help, which is the actionable part.
    assert "will not close them" in note


def test_a_genuinely_clean_plan_still_says_so():
    """The negative control. Without it, "do not claim everything is fine" could
    be satisfied by never saying anything is fine."""
    dep = _dep("clean")
    _claim(dep, status=Status.VERIFIED)

    plan = plan_revalidation(dep)

    assert [c["claim_type"] for c in plan["still_current"]] == [ClaimType.EFFECTIVE_ACCESS]
    assert plan["outstanding_unknowns"] == []
    assert "Nothing needs to be re-run" in plan["note"]


def test_an_unknown_claim_is_bucketed_exactly_as_before():
    """The other negative control: widening the bucket must not change what was
    already in it."""
    dep = _dep("unknown")
    _claim(dep, status=Status.UNKNOWN, evidence_class=EvidenceClass.UNKNOWN)

    plan = plan_revalidation(dep)

    assert [c["status"] for c in plan["outstanding_unknowns"]] == [Status.UNKNOWN]
    assert plan["still_current"] == []


def test_a_drifted_claim_still_outranks_a_limit():
    """A CONTRADICTED claim is drift and belongs in ``required``; the widened
    bucket must not swallow it."""
    dep = _dep("drift")
    _claim(dep, status=Status.CONTRADICTED)
    _claim(dep, status=Status.PARTIALLY_VERIFIED, claim_type=ClaimType.AI_BOM,
           evidence_class=EvidenceClass.PARTIALLY_VERIFIED)

    plan = plan_revalidation(dep)

    assert [w["claim_type"] for w in plan["required"]] == [ClaimType.EFFECTIVE_ACCESS]
    assert [c["claim_type"] for c in plan["outstanding_unknowns"]] == [ClaimType.AI_BOM]
    assert "need revalidation because of a change" in plan["note"]


# ---- the decision note -----------------------------------------------------


def test_a_partially_verified_claim_is_not_counted_silently_as_supporting():
    """The decision is right -- PARTIALLY_VERIFIED imposes no cap -- but the
    sentence about it said three claims support this when one of them was
    measured over a graph it could not read whole."""
    dep = _dep("support")
    _claim(dep, status=Status.VERIFIED, claim_type=ClaimType.DATA_BOUNDARY)
    _claim(dep, status=Status.PARTIALLY_VERIFIED, claim_type=ClaimType.EFFECTIVE_ACCESS,
           evidence_class=EvidenceClass.PARTIALLY_VERIFIED)
    recompute_decision(dep)

    support = decision_support(dep)

    assert support["decision"] == Deployment.Decision.READY, "the cap must not change"
    assert "2 current assurance claim(s)" in support["note"]
    assert "1 of them only partially verified" in support["note"]
    assert ClaimType.EFFECTIVE_ACCESS in support["note"]


def test_a_fully_supported_deployment_says_it_plainly():
    """The negative control for the note above: with nothing partial, the
    sentence must not acquire a caveat it has not earned."""
    dep = _dep("full")
    _claim(dep, status=Status.VERIFIED, claim_type=ClaimType.DATA_BOUNDARY)
    _claim(dep, status=Status.SUPPORTED, claim_type=ClaimType.EFFECTIVE_ACCESS)
    recompute_decision(dep)

    note = decision_support(dep)["note"]

    assert "2 current assurance claim(s) with no open retest." in note
    assert "partially verified" not in note
