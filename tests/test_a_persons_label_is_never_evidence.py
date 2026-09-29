"""SPINE #333, round 3: a person's own label is never evidence, and a contradiction
clears only by an attributed invalidation.

The audit reads a claim's own reading as pass-side evidence when it is an
observed pass -- SUPPORTED or VERIFIED on technically or configuration verified,
non-vendor evidence -- so a counted FAIL against it is CONTESTED (UNKNOWN), not
FAIL (CONTRADICTED). That is right for the deriver's reading: it is the
platform's own observation of the graph. It was also applied to a PERSON's
label. SUPPORTED and PARTIALLY_VERIFIED rank alike, so a person under a counted
FAIL could make the "lateral" move PARTIALLY_VERIFIED -> SUPPORTED, which the
round-2 rule accepts as "not above the reading" -- and their own label became the
pass side: verdict ``fail`` -> ``contested``, the claim CONTRADICTED -> UNKNOWN,
the deployment's cap ``needs_remediation`` -> ``needs_more_evidence``. No
invalidation, nobody resolving anything, and it toggled (round-3 script L).

Now only a derived reading stands on the pass side. A person's SUPPORTED or
VERIFIED is a reading, never an observation.
"""

from __future__ import annotations

from itertools import count

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from assurance import evidence_audit as ea
from assurance.claims import apply_claim_transition, derive_claims
from assurance.decision import claim_decision_signal
from assurance.models import AssuranceClaim, ClaimVerdict, Deployment
from tests.test_spine_evidence_audit import _access_claim, _current, _record

pytestmark = pytest.mark.django_db

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
V = ClaimVerdict
_names = count()


def _person(prefix="person"):
    return User.objects.create_user(username=f"{prefix}-lbl-{next(_names)}", password=None, role=User.Roles.ADMIN)


def _deployment(name):
    return Deployment.objects.create(name=name, owner=_person(f"owner-{name}"))


def _move(client, claim, to_status):
    response = client.post(
        f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": to_status, "note": "relabel"}, format="json"
    )
    claim.refresh_from_db()
    return response


def _cap(dep):
    dep.refresh_from_db()
    return claim_decision_signal(dep).get("cap")


def test_a_lateral_relabel_under_a_counted_failure_does_not_clear_the_contradiction():
    """Round-3 script L, as a test: the toggle no longer moves the claim, its
    verdict, or the deployment's cap."""
    client = APIClient()
    client.force_authenticate(user=_person("admin"))
    dep = _deployment("lateral")
    claim = _access_claim(dep)                            # the deriver's VERIFIED, configuration verified
    assert claim.status == Status.VERIFIED
    assert _move(client, claim, Status.PARTIALLY_VERIFIED).status_code == 200
    _record(claim, outcome=V.FAIL.value)
    assert (claim.status, claim.evidence_verdict) == (Status.CONTRADICTED, V.FAIL)
    cap = _cap(dep)

    for relabel in (Status.SUPPORTED, Status.PARTIALLY_VERIFIED, Status.SUPPORTED, Status.VERIFIED):
        response = _move(client, claim, relabel)
        if response.status_code == 200:
            assert (claim.status, claim.evidence_verdict) == (Status.CONTRADICTED, V.FAIL), relabel
        else:
            # Above the reading and held back at once: refused, and nothing moved.
            assert response.status_code == 400, response.content
            assert (claim.status, claim.evidence_verdict) == (Status.CONTRADICTED, V.FAIL), relabel
        assert _cap(dep) == cap
        assert claim.evidence_audit["held"] is True
        assert "the claim's own reading" not in " ".join(claim.evidence_audit["contradictions"])


@pytest.mark.parametrize("label", [Status.SUPPORTED, Status.VERIFIED])
def test_a_persons_pass_label_is_not_the_pass_side_of_a_contradiction(label):
    """A person reads the derived VERIFIED claim as SUPPORTED (or re-affirms
    VERIFIED); an independent, checked FAIL then counts. The person's label is not
    an observation: the verdict is FAIL and the claim CONTRADICTED -- not CONTESTED
    at UNKNOWN on the strength of the person's word."""
    dep = _deployment(f"label-{label}")
    claim = _access_claim(dep)
    if label == Status.VERIFIED:
        apply_claim_transition(claim, Status.SUPPORTED, actor=_person(), note="reviewed")
        claim.refresh_from_db()
    apply_claim_transition(claim, label, actor=_person(), note="reviewed")
    claim.refresh_from_db()
    assert claim.status == label

    fail = _record(claim, outcome=V.FAIL.value)

    assert claim.status == Status.CONTRADICTED
    assert claim.evidence_verdict == V.FAIL
    assert ea.reading_status(claim) == label
    # Only an attributed invalidation clears it, and the release lands on the reading.
    ea.invalidate_claim_evidence(fail, actor=_person("reviewer"), reason="probe hit staging")
    claim.refresh_from_db()
    assert claim.status == label


def test_the_derivers_observed_pass_is_still_the_pass_side_of_a_contradiction():
    """The control of the rule above: the deriver's own VERIFIED on configuration
    verified evidence is the platform's observation, so a counted FAIL against it
    is CONTESTED, held at UNKNOWN."""
    dep = _deployment("derived")
    claim = _access_claim(dep)
    _record(claim, outcome=V.FAIL.value)
    assert (claim.status, claim.evidence_verdict) == (Status.UNKNOWN, V.CONTESTED)
    assert "the claim's own reading" in claim.evidence_audit["contradictions"][0]


def test_a_re_derive_over_a_persons_label_under_a_counted_failure_keeps_it_contradicted():
    """The person's reading stands on the version through a re-derive, and is
    re-audited as a person's: the re-derive does not turn it into the pass side."""
    dep = _deployment("rederive")
    claim = _access_claim(dep)
    apply_claim_transition(claim, Status.SUPPORTED, actor=_person(), note="reviewed")
    claim.refresh_from_db()
    _record(claim, outcome=V.FAIL.value)
    assert claim.status == Status.CONTRADICTED

    derive_claims(dep)

    claim = _current(dep)
    assert (claim.status, claim.evidence_verdict) == (Status.CONTRADICTED, V.FAIL)
