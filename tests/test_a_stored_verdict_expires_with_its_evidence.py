"""SPINE #333, round 3: a stored verdict is not served as current once the evidence
it counted has expired.

``audit_current`` meant only "the stored audit's status is the claim's status".
Evidence that EXPIRES after the audit was taken leaves the status where it was,
so the stored verdict was served as current -- the expired item still marked
load-bearing -- although the audit taken now refuses it as expired and answers
differently (round-3 script E: ``pass`` served; the audit now reads
``incomplete``). Nothing re-audits on read or on expiry.

Now the stored audit records until when it holds (``valid_until``: the first
instant a counted item expires, or a refused one's reason lapses), and past it
every reader serves no verdict and marks the audit not current, with the reason.
"""

from __future__ import annotations

from datetime import timedelta
from itertools import count

import pytest
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient

from assurance import evidence_audit as ea
from assurance.claims import apply_claim_transition
from assurance.models import AssuranceClaim, ClaimVerdict, Deployment
from tests.test_spine_evidence_audit import _access_claim, _good

pytestmark = pytest.mark.django_db

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
V = ClaimVerdict
_names = count()


def _person(prefix="person"):
    return User.objects.create_user(username=f"{prefix}-exp-{next(_names)}", password=None, role=User.Roles.ADMIN)


def _supported(name):
    dep = Deployment.objects.create(name=name, owner=_person("owner"))
    claim = _access_claim(dep, principals=False)          # UNKNOWN; a person reads it SUPPORTED
    apply_claim_transition(claim, Status.SUPPORTED, actor=_person(), note="reviewed")
    claim.refresh_from_db()
    return claim


def _reads(claim):
    client = APIClient()
    client.force_authenticate(user=_person("reader"))
    detail = client.get(f"/api/assurance/claims/{claim.uuid}/").json()
    evidence = client.get(f"/api/assurance/claims/{claim.uuid}/evidence/").json()
    listed = client.get(f"/api/assurance/claims/?deployment={claim.deployment.uuid}").json()
    listed = listed["results"] if isinstance(listed, dict) else listed
    row = next(r for r in listed if r["uuid"] == str(claim.uuid))
    return detail, evidence, row


def test_a_verdict_whose_counted_evidence_has_expired_is_not_served_as_current():
    claim = _supported("expired")
    audited_at = timezone.now() - timedelta(hours=1)
    ea.record_claim_evidence(
        claim,
        **_good(
            claim, outcome=V.PASS.value, observed_at=audited_at - timedelta(minutes=2),
            state_checked_at=audited_at - timedelta(minutes=1), expires_at=audited_at + timedelta(minutes=5),
        ),
        now=audited_at,
    )
    claim.refresh_from_db()
    # As audited, the pass counted.
    assert claim.evidence_verdict == V.PASS
    assert claim.evidence_audit["admitted"]
    # The audit taken now refuses it as expired and answers differently.
    assert ea.audit_of(claim)["verdict"] != V.PASS

    detail, evidence, row = _reads(claim)
    for served in (detail, evidence, row):
        assert served["evidence_verdict"] is None
        assert served["evidence_audit"]["audit_current"] is False
        assert "expire" in served["evidence_audit"]["not_current_reason"]
    assert evidence["evidence"][0]["weighed"]["audit_current"] is False
    assert ea.current_verdict(claim) is None


def test_a_verdict_a_refused_items_lapsed_reason_would_change_is_not_served_as_current():
    """An item refused as observed in the future is admissible once its instant
    arrives: the stored audit no longer says what the audit taken now says."""
    claim = _supported("future")
    audited_at = timezone.now() - timedelta(hours=1)
    ea.record_claim_evidence(
        claim,
        **_good(
            claim, outcome=V.FAIL.value, observed_at=audited_at + timedelta(minutes=30),
            state_checked_at=audited_at + timedelta(minutes=31), expires_at=audited_at + timedelta(days=30),
        ),
        now=audited_at,
    )
    claim.refresh_from_db()
    assert ea.OBSERVED_IN_THE_FUTURE in claim.evidence_audit["refused"][0]["reasons"]
    assert ea.audit_of(claim)["verdict"] == V.FAIL

    detail, _evidence, _row = _reads(claim)
    assert detail["evidence_verdict"] is None
    assert detail["evidence_audit"]["audit_current"] is False


def test_a_verdict_whose_evidence_is_all_still_live_is_served_as_current():
    claim = _supported("live")
    ea.record_claim_evidence(claim, **_good(claim, outcome=V.PASS.value))
    claim.refresh_from_db()
    detail, evidence, row = _reads(claim)
    for served in (detail, evidence, row):
        assert served["evidence_verdict"] == V.PASS
        assert served["evidence_audit"]["audit_current"] is True
    assert ea.current_verdict(claim) == V.PASS
