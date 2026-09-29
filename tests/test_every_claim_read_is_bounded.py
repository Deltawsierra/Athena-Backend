"""SPINE #333, round 3: every claim read is bounded, and a stop's write does not
grow with the evidence.

The stored audit listed every item recorded against the claim -- one entry per
item in ``admitted`` / ``refused``, one line per refused adverse item in
``contradictions`` -- and every claim read embedded it whole: the claim detail
and the claim LIST at about 112 bytes per item (1.1 MB at 10,000), and the
evidence route, bounded to 100 items since round 1, still carried the whole
audit beside its page (round-3 script E3). A stop copies the stored audit to
take a hold down (``taken_down``), so its UPDATE statement grew the same way
(1.16 MB at 10,000; script E2).

Now the claim carries a bounded summary -- the verdict, the status, the hold,
counts, and the first few entries of each list -- and the per-item weighing is
stored beside it, in its own table (``ClaimAuditWeighing``), read only by the evidence route for
the items on its page. A stop writes the summary only.
"""

from __future__ import annotations

import json
from datetime import timedelta
from itertools import count

import pytest
from django.contrib.auth import get_user_model
from django.db import connection
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from rest_framework.test import APIClient

from assurance import evidence_audit as ea
from assurance.models import AssuranceClaim, ClaimEvidence, ClaimVerdict, Deployment
from tests.test_spine_evidence_audit import _access_claim, _good

pytestmark = pytest.mark.django_db

User = get_user_model()
Status = AssuranceClaim.ClaimStatus
V = ClaimVerdict
_names = count()


def _person(prefix="person"):
    return User.objects.create_user(username=f"{prefix}-bnd-{next(_names)}", password=None, role=User.Roles.ADMIN)


def _held_with(n, outcome=V.FAIL.value):
    """A VERIFIED claim with ``n`` counted items recorded against it, audited once:
    the hold a record leaves (contested, UNKNOWN)."""
    dep = Deployment.objects.create(name=f"bounded-{n}-{next(_names)}", owner=_person("owner"))
    claim = _access_claim(dep)
    base = _good(claim, outcome=outcome)
    now = timezone.now()
    ClaimEvidence.objects.bulk_create(
        [
            ClaimEvidence(
                deployment_id=claim.deployment_id, claim_fingerprint=claim.fingerprint, recorded_against=claim,
                expires_at=now + timedelta(days=30), created_at=now - timedelta(seconds=n - i), **base,
            )
            for i in range(n)
        ]
    )
    ea.audit_claim(claim)
    claim.refresh_from_db()
    assert claim.evidence_audit["held"] is True
    return claim


def _client():
    client = APIClient()
    client.force_authenticate(user=_person("admin"))
    return client


def _sizes(claim):
    client = _client()
    detail = client.get(f"/api/assurance/claims/{claim.uuid}/")
    listed = client.get(f"/api/assurance/claims/?deployment={claim.deployment.uuid}")
    evidence = client.get(f"/api/assurance/claims/{claim.uuid}/evidence/")
    assert detail.status_code == listed.status_code == evidence.status_code == 200
    return len(detail.content), len(listed.content), len(evidence.content), evidence.json()


def test_the_claim_detail_list_and_evidence_route_do_not_grow_with_the_evidence():
    small, large = _held_with(150), _held_with(400)
    s_detail, s_list, s_evidence, _ = _sizes(small)
    l_detail, l_list, l_evidence, served = _sizes(large)
    # A few digits of counts may differ; nothing per item.
    assert l_detail - s_detail < 200, (s_detail, l_detail)
    assert l_list - s_list < 200, (s_list, l_list)
    assert l_evidence - s_evidence < 200, (s_evidence, l_evidence)
    summary = served["evidence_audit"]
    assert summary["counts"]["admitted"] == 400
    assert len(summary["admitted"]) <= ea.AUDIT_LIST_LIMIT
    assert summary["lists_truncated"] is True
    assert served["evidence_count"] == 400 and served["returned"] == ea_page()


def ea_page():
    from assurance.views import ClaimViewSet

    return ClaimViewSet.EVIDENCE_PAGE_SIZE


def test_every_item_on_a_page_is_still_served_with_how_the_audit_weighed_it():
    claim = _held_with(260)
    client = _client()
    for offset in (0, 100, 200):
        served = client.get(f"/api/assurance/claims/{claim.uuid}/evidence/?offset={offset}").json()
        assert served["evidence"], offset
        for item in served["evidence"]:
            assert item["weighed"] == {"load_bearing": True, "reasons": []}, (offset, item["uuid"])


@pytest.mark.parametrize("stop", ["contradicted", "revoked"])
def test_a_stops_write_does_not_grow_with_the_evidence_under_a_hold(stop):
    def stop_statements(claim):
        with CaptureQueriesContext(connection) as queries:
            response = _client().post(
                f"/api/assurance/claims/{claim.uuid}/transition/", {"to_status": stop}, format="json"
            )
        assert response.status_code == 200, response.content
        claim.refresh_from_db()
        assert claim.status == stop
        statements = [q["sql"] for q in queries.captured_queries]
        # The whole weighing is neither written nor read: not by the stop, not by
        # the decision it brings current.
        assert not any("claimauditweighing" in s for s in statements)
        return len(statements), max(len(s) for s in statements)

    few_queries, few_largest = stop_statements(_held_with(20))
    many_queries, many_largest = stop_statements(_held_with(400))
    assert many_queries == few_queries
    assert many_largest - few_largest < 200, (few_largest, many_largest)


def test_the_stored_summary_is_bounded_and_counts_what_it_does_not_list():
    claim = _held_with(300)
    summary = claim.evidence_audit
    assert len(json.dumps(summary)) < 12_000
    for key in ("admitted", "refused", "contradictions", "supersessions", "residual_uncertainty"):
        assert len(summary[key]) <= ea.AUDIT_LIST_LIMIT, key
    assert summary["counts"]["admitted"] == 300
    assert len(ea.stored_weighing(claim)["admitted"]) == 300
