"""Athena Phase 0.4 — the Unknowns Register.

Proves that an unverified finding becomes a managed :class:`Unknown`, that the
deriver is idempotent and never clobbers human-set disposition, that a gap
auto-resolves when its finding is dispositioned or its evidence is upgraded, that
manually raised Unknowns are left alone, and that a completed scan populates the
register end to end through ingestion.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from assurance.models import (
    Deployment,
    Evidence,
    EvidenceClass,
    Finding,
    Unknown,
)
from assurance.unknowns import derive_unknowns
from pentest.models import PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user():
    return User.objects.create_user(username="analyst", password="x", role=User.Roles.ANALYST)


def _deployment():
    return Deployment.objects.create(name="acme-chatbot")


def _finding(deployment, *, evidence_class=EvidenceClass.UNKNOWN, severity="high",
             status=Finding.Status.OPEN, fp="fp1"):
    finding = Finding.objects.create(
        deployment=deployment,
        fingerprint=fp,
        finding_type="prompt_injection",
        title="Prompt injection may be possible",
        severity=severity,
        status=status,
    )
    if evidence_class is not None:
        Evidence.objects.create(
            finding=finding, classification=evidence_class, source="engine_scan"
        )
    return finding


def test_unverified_finding_becomes_an_unknown():
    deployment = _deployment()
    _finding(deployment, evidence_class=EvidenceClass.UNKNOWN, severity="high")

    open_unknowns = derive_unknowns(deployment)

    assert len(open_unknowns) == 1
    unknown = Unknown.objects.get()
    assert unknown.source == Unknown.Source.DERIVED
    assert unknown.status == Unknown.Status.OPEN
    assert unknown.deployment_impact == Unknown.Impact.HIGH  # high finding → high gap
    assert unknown.question  # it asks something
    assert unknown.evidence_needed  # and says how to close it


def test_verified_finding_creates_no_unknown():
    deployment = _deployment()
    _finding(deployment, evidence_class=EvidenceClass.TECHNICALLY_VERIFIED)

    open_unknowns = derive_unknowns(deployment)

    assert open_unknowns == []
    assert Unknown.objects.count() == 0


def test_derive_is_idempotent_and_preserves_human_state():
    deployment = _deployment()
    _finding(deployment, evidence_class=EvidenceClass.NOT_DOCUMENTED)

    derive_unknowns(deployment)
    unknown = Unknown.objects.get()
    # A human works the gap.
    owner = _user()
    unknown.status = Unknown.Status.INVESTIGATING
    unknown.owner = owner
    unknown.notes = "chasing the vendor"
    unknown.save()

    # Re-derive (a re-scan): no duplicate, human fields survive, machine fields fresh.
    derive_unknowns(deployment)
    assert Unknown.objects.count() == 1
    unknown.refresh_from_db()
    assert unknown.status == Unknown.Status.INVESTIGATING
    assert unknown.owner_id == owner.pk
    assert unknown.notes == "chasing the vendor"


def test_gap_auto_resolves_when_finding_is_dispositioned():
    deployment = _deployment()
    finding = _finding(deployment, evidence_class=EvidenceClass.UNKNOWN)
    derive_unknowns(deployment)
    assert Unknown.objects.get().status == Unknown.Status.OPEN

    # The finding is closed → its derived gap is no longer live.
    finding.status = Finding.Status.FALSE_POSITIVE
    finding.save(update_fields=["status"])
    derive_unknowns(deployment)

    assert Unknown.objects.get().status == Unknown.Status.RESOLVED


def test_gap_auto_resolves_when_evidence_is_upgraded():
    deployment = _deployment()
    finding = _finding(deployment, evidence_class=EvidenceClass.UNKNOWN)
    derive_unknowns(deployment)

    # Fresh evidence upgrades the finding's class above "unverified".
    finding.evidence.update(classification=EvidenceClass.TECHNICALLY_VERIFIED)
    derive_unknowns(deployment)

    assert Unknown.objects.get().status == Unknown.Status.RESOLVED


def test_manual_unknown_is_never_touched():
    deployment = _deployment()
    manual = Unknown.objects.create(
        deployment=deployment,
        fingerprint="manual-1",
        question="Where is the model hosted?",
        source=Unknown.Source.MANUAL,
        status=Unknown.Status.OPEN,
    )

    derive_unknowns(deployment)  # no findings; a stale-resolve pass runs

    manual.refresh_from_db()
    assert manual.status == Unknown.Status.OPEN  # a manual gap is not auto-resolved


def test_auto_resolved_gap_reopens_when_finding_flaps_back():
    """A gap the machine auto-resolved must re-open if the finding is unverified again."""
    deployment = _deployment()
    finding = _finding(deployment, evidence_class=EvidenceClass.UNKNOWN)
    derive_unknowns(deployment)
    assert Unknown.objects.get().status == Unknown.Status.OPEN

    finding.evidence.update(classification=EvidenceClass.TECHNICALLY_VERIFIED)
    derive_unknowns(deployment)
    assert Unknown.objects.get().status == Unknown.Status.RESOLVED  # machine-resolved

    # Evidence downgrades again → the gap is live once more → re-opened.
    finding.evidence.update(classification=EvidenceClass.UNKNOWN)
    derive_unknowns(deployment)
    reopened = Unknown.objects.get()
    assert reopened.status == Unknown.Status.OPEN
    assert reopened.auto_resolved is False


def test_human_resolved_gap_is_never_reopened():
    """A gap a *human* resolved is left as they set it, even if the finding is still live."""
    deployment = _deployment()
    _finding(deployment, evidence_class=EvidenceClass.UNKNOWN)
    derive_unknowns(deployment)
    unknown = Unknown.objects.get()
    unknown.status = Unknown.Status.RESOLVED  # a human resolves it (auto_resolved stays False)
    unknown.save()

    derive_unknowns(deployment)  # the finding is still unverified/live
    unknown.refresh_from_db()
    assert unknown.status == Unknown.Status.RESOLVED  # human decision preserved


def test_completing_a_scan_populates_the_register(django_capture_on_commit_callbacks):
    user = _user()
    scan = PentestScan.objects.create(
        user=user,
        target_url="https://app.client.example/chat",
        consent=True,
        status=PentestScan.STATUS_PENDING,
        # An engine finding with no exploit confirmation → unverified evidence.
        engine_response={"findings": [
            {"type": "prompt_injection", "report_severity": "high",
             "evidence": {"endpoint": "/chat"}},
        ]},
    )

    with django_capture_on_commit_callbacks(execute=True):
        scan.mark_completed()

    unknown = Unknown.objects.get()
    assert unknown.source == Unknown.Source.DERIVED
    assert unknown.status == Unknown.Status.OPEN
    assert unknown.finding is not None
