"""Phase 2 items 7 and 8: no invented confidence, and two dispositions that exist.

Three separate honesty problems in the Finding model, all of them the same shape --
a value that reads as knowledge nobody has.

1. ``confidence`` defaulted to 0.5. A number nobody computed, indistinguishable in
   every report from a real 0.5 a detector measured.
2. There was no way to record "a control limits this path but the defect is still
   there" except REMEDIATING, which claims a fix is in progress, or OPEN, which
   claims nobody has looked.
3. Seven modules each kept a private copy of "which statuses count as resolved",
   every one of them commented as mirroring the others.
"""

from __future__ import annotations

import pytest
from assurance import ingest
from assurance.decision import compute_decision
from assurance.models import (
    RESOLVED_FINDING_STATUSES,
    UNTRUSTED_SEVERITY_STATUSES,
    Deployment,
    Evidence,
    EvidenceClass,
    Finding,
    qualitative_evidence_label,
)
from assurance.serializers import FindingSerializer
from django.contrib.auth import get_user_model
from pentest.models import PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user():
    return User.objects.create_user(username="analyst-fh", password="x", role=User.Roles.ANALYST)


def _scan(user, findings):
    return PentestScan.objects.create(
        user=user,
        target_url="https://app.client.example/login",
        consent=True,
        status=PentestScan.STATUS_COMPLETED,
        engine_response={"findings": findings},
    )


def _finding(dep, **kwargs):
    fields = dict(
        deployment=dep,
        fingerprint=f"fp-{Finding.objects.count()}",
        finding_type="t",
        title="T",
        severity="high",
    )
    fields.update(kwargs)
    return Finding.objects.create(**fields)


# ---------------------------------------------------------------------------
# Confidence is measured or absent, never invented
# ---------------------------------------------------------------------------


def test_a_finding_the_engine_gave_no_confidence_for_has_none():
    """0.5 was a number nobody computed, and nothing downstream could tell it from
    a real one."""
    user = _user()
    ingest.ingest_scan(_scan(user, [{"type": "sqli", "severity": "high"}]))
    assert Finding.objects.get().confidence is None


def test_an_unparseable_confidence_is_also_none_and_not_a_default():
    user = _user()
    ingest.ingest_scan(_scan(user, [{"type": "sqli", "severity": "high", "confidence": "high-ish"}]))
    assert Finding.objects.get().confidence is None


def test_a_reported_confidence_is_kept_exactly_including_a_real_half():
    """A measured 0.5 is a real number and must survive: the fix is to stop
    inventing, not to discard."""
    user = _user()
    ingest.ingest_scan(_scan(user, [{"type": "sqli", "severity": "high", "confidence": 0.5}]))
    assert Finding.objects.get().confidence == 0.5


def test_the_model_has_no_confidence_default_at_all():
    """A default is what made every row look measured. Creating a finding without
    naming a confidence must leave it unknown."""
    dep = Deployment.objects.create(name="d", owner=_user())
    assert _finding(dep).confidence is None
    assert Finding._meta.get_field("confidence").has_default() is False


def test_a_null_confidence_serializes_as_null_and_not_as_a_number():
    dep = Deployment.objects.create(name="d", owner=_user())
    data = FindingSerializer(_finding(dep)).data
    assert data["confidence"] is None


# ---------------------------------------------------------------------------
# Contained and Invalidated
# ---------------------------------------------------------------------------


def test_contained_is_not_resolved_and_still_counts_against_readiness():
    """"Contained" must never be read as "removed": one path is limited, the
    defect is not gone, and the deployment is not readier for it."""
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, severity="critical", status=Finding.Status.CONTAINED)

    assert Finding.Status.CONTAINED not in RESOLVED_FINDING_STATUSES
    assert compute_decision(dep) == Deployment.Decision.NOT_RECOMMENDED


def test_contained_is_distinct_from_remediating_in_every_report():
    """REMEDIATING claims a fix is in progress. A contained finding may have no fix
    in progress at all, and reporting one would claim work nobody is doing."""
    dep = Deployment.objects.create(name="d", owner=_user())
    contained = _finding(dep, status=Finding.Status.CONTAINED)

    assert contained.status != Finding.Status.REMEDIATING
    data = FindingSerializer(contained).data
    assert data["status"] == "contained"
    assert "not been removed" in data["status_must_not_imply"]
    assert "no fix is implied" in data["status_must_not_imply"]


def test_invalidated_drives_needs_more_evidence_not_its_stale_severity():
    """The premise moved, so the recorded severity is a number the evidence no
    longer supports -- but the finding is not resolved either."""
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, severity="critical", status=Finding.Status.INVALIDATED)

    assert Finding.Status.INVALIDATED in UNTRUSTED_SEVERITY_STATUSES
    assert compute_decision(dep) == Deployment.Decision.NEEDS_MORE_EVIDENCE


def test_an_invalidated_finding_cannot_be_read_as_a_confirmed_incident():
    dep = Deployment.objects.create(name="d", owner=_user())
    data = FindingSerializer(_finding(dep, status=Finding.Status.INVALIDATED)).data
    assert "No exploitation is implied" in data["status_must_not_imply"]
    assert "not a confirmed incident" in data["status_must_not_imply"]


def test_a_live_finding_beside_an_invalidated_one_still_places_the_deployment():
    """Invalidating one finding must not mask another that is genuinely critical."""
    dep = Deployment.objects.create(name="d", owner=_user())
    _finding(dep, severity="critical", status=Finding.Status.INVALIDATED)
    _finding(dep, severity="critical", status=Finding.Status.OPEN)
    assert compute_decision(dep) == Deployment.Decision.NOT_RECOMMENDED


def test_a_status_with_no_caveat_serializes_as_null_rather_than_an_invented_one():
    dep = Deployment.objects.create(name="d", owner=_user())
    data = FindingSerializer(_finding(dep, status=Finding.Status.OPEN)).data
    assert data["status_must_not_imply"] is None


# ---------------------------------------------------------------------------
# One definition of "resolved"
# ---------------------------------------------------------------------------


def test_every_module_asks_the_same_object_what_resolved_means():
    """Seven modules each kept their own copy of this set, and every one of their
    comments said it mirrored the others so the views would agree -- which is
    exactly the arrangement that lets them stop agreeing. Adding a status meant
    editing eight places, and missing one is silent.
    """
    from assurance import (
        business_impact,
        compliance,
        decision,
        dispatch,
        operational_risk,
        ripple,
        roi,
    )

    for module in (
        business_impact,
        compliance,
        decision,
        dispatch,
        operational_risk,
        ripple,
        roi,
    ):
        assert module._RESOLVED_STATUSES is RESOLVED_FINDING_STATUSES, module.__name__


def test_the_two_new_states_are_not_resolved_anywhere():
    """A contained defect and an invalidated premise are both still live work. If
    either had landed in the resolved set, every assessment would have quietly
    stopped counting it."""
    for status in (Finding.Status.CONTAINED, Finding.Status.INVALIDATED):
        assert status not in RESOLVED_FINDING_STATUSES


# ---------------------------------------------------------------------------
# One evidence vocabulary
# ---------------------------------------------------------------------------


def test_every_evidence_class_has_exactly_one_qualitative_reading():
    from assurance.models import EVIDENCE_STRENGTH_ORDER, QUALITATIVE_EVIDENCE_LABELS

    assert set(QUALITATIVE_EVIDENCE_LABELS) == set(EVIDENCE_STRENGTH_ORDER)
    assert set(QUALITATIVE_EVIDENCE_LABELS.values()) <= {
        "Observed",
        "Reproduced",
        "Inferred",
        "Hypothesized",
        "Unknown",
    }


def test_the_qualitative_reading_never_strengthens_the_claim():
    """Walking the ordinal from strongest to weakest, the label may only weaken."""
    from assurance.models import EVIDENCE_STRENGTH_ORDER

    rank = {"Observed": 0, "Reproduced": 0, "Inferred": 1, "Hypothesized": 2, "Unknown": 3}
    labels = [qualitative_evidence_label(c) for c in EVIDENCE_STRENGTH_ORDER]
    ranks = [rank[label] for label in labels]
    assert ranks == sorted(ranks), list(zip(EVIDENCE_STRENGTH_ORDER, labels))


def test_an_unrecognised_class_reads_as_unknown_not_as_observed():
    assert qualitative_evidence_label("something-nobody-defined") == "Unknown"
    assert qualitative_evidence_label("") == "Unknown"


def test_reproduced_is_claimed_by_no_class_on_its_own():
    """Reproduction is a property of how a finding was established, not of the
    evidence class. Asserting it from a class alone would invent a fact."""
    from assurance.models import QUALITATIVE_EVIDENCE_LABELS

    assert "Reproduced" not in QUALITATIVE_EVIDENCE_LABELS.values()


def test_the_weakest_evidence_still_wins_and_carries_its_own_label():
    dep = Deployment.objects.create(name="d", owner=_user())
    finding = _finding(dep)
    Evidence.objects.create(finding=finding, classification=EvidenceClass.TECHNICALLY_VERIFIED)
    Evidence.objects.create(finding=finding, classification=EvidenceClass.VENDOR_ASSERTED)

    assert finding.evidence_class == EvidenceClass.VENDOR_ASSERTED
    assert qualitative_evidence_label(finding.evidence_class) == "Inferred"
