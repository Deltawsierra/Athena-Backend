"""Athena SPINE Phase 2 — the temporal / INVALIDATES backbone.

Proves that a detected system change invalidates the dependent claims and opens a
durable, attributed retest obligation, that the obligation is honest and
idempotent, and that only a rebinding re-derivation resolves it:

- a change (a moved system fingerprint) invalidates a current claim: it opens a
  RetestRequirement (attributed, with a reason) and moves the claim AWAY from a
  pass to STALE — never to an invented "invalid but passing" state;
- the engine is idempotent: re-running it opens no duplicate obligation for the
  same open drift;
- a fresh derive that rebinds the claim to the new state resolves the obligation,
  recording the new version as ``resolving_claim`` — a machine no longer flagging
  drift never resolves it, only an earned re-derivation does;
- a human REVOKED claim is never invalidated, marked, or given an obligation;
- invalidation never leaves a claim reading as a pass;
- cross-claim propagation: a supply-chain change (an AI_BOM input) also opens a
  retest on the dependent DATA_BOUNDARY claim — via the shared deployment
  fingerprint, the documented INVALIDATES seam (see ``assurance.invalidation``);
- the API endpoints return scoped reads and admin-gated mutations.

The migration applying is implicit: the test database is built from it.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.claims import derive_claims
from assurance.fingerprint import compute_system_fingerprint
from assurance.invalidation import check_invalidations, resolve_satisfied_requirements
from assurance.models import (
    Asset,
    AssuranceClaim,
    Deployment,
    EvidenceClass,
    Provider,
    ProviderAssertion,
    RetestRequirement,
)
from assurance.views import DeploymentViewSet, RetestRequirementViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()

Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType

_PASS_STATES = frozenset({Status.SUPPORTED, Status.VERIFIED, Status.PARTIALLY_VERIFIED})


# ---------------------------------------------------------------------------
# Fixtures — mirroring tests.test_assurance_claims
# ---------------------------------------------------------------------------


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _provider(name, *, kind=Provider.Kind.MODEL_PROVIDER, ev=EvidenceClass.VENDOR_ASSERTED, **assertions):
    p = Provider.objects.create(name=name, kind=kind)
    for field, value in assertions.items():
        ProviderAssertion.objects.create(provider=p, field=field, value=value, evidence_class=ev)
    return p


def _asset(dep, *, kind=Asset.Kind.MODEL, provider=None, classification=Asset.Classification.KNOWN, name="m", identifier=None, metadata=None):
    return Asset.objects.create(
        deployment=dep, provider=provider, kind=kind, classification=classification,
        name=name, identifier=identifier or name, metadata=metadata or {},
    )


def _claims_by_type(dep):
    return {
        c.claim_type: c
        for c in AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True)
    }


def _simple_deployment(owner=None):
    """A deployment with one provider-backed model asset — three current claims
    after a derive, all bound to one system fingerprint."""
    dep = Deployment.objects.create(name="d", owner=owner or _user())
    p = _provider("OpenAI", ev=EvidenceClass.CONFIGURATION_VERIFIED, region="eu-west-1")
    _asset(dep, provider=p, name="gpt", identifier="gpt", metadata={"region": "eu-west-1"})
    return dep


def _move_fingerprint(dep):
    """Change the deployment's stable state so its system fingerprint drifts."""
    before = compute_system_fingerprint(dep)
    _asset(dep, kind=Asset.Kind.VECTOR_DB, name="pinecone", identifier="pinecone")
    assert compute_system_fingerprint(dep) != before


# ---------------------------------------------------------------------------
# Invalidation opens an attributed, honest obligation
# ---------------------------------------------------------------------------


def test_change_opens_attributed_retest_requirement():
    dep = _simple_deployment()
    derive_claims(dep)
    _move_fingerprint(dep)

    counts = check_invalidations(dep)
    assert counts["invalidated"] == 3  # all three current claims drifted together
    assert counts["retests_opened"] == 3
    assert counts["retests_resolved"] == 0

    reqs = RetestRequirement.objects.filter(deployment=dep)
    assert reqs.count() == 3
    req = reqs.first()
    assert req.is_open and req.resolved_at is None
    assert req.reason  # a durable, non-empty reason
    assert req.actor is None  # machine-opened (no actor passed)
    assert req.triggering_system_fingerprint == compute_system_fingerprint(dep)

    # The obligation is attributed on the claim's own lifecycle.
    assert req.claim.events.filter(note__startswith="Retest required").exists()


def test_invalidation_moves_claim_off_a_pass_to_stale():
    """Invalidation must never read as a pass: a drifted SUPPORTED/VERIFIED claim
    is moved to STALE, never to an invented 'invalid but passing' state."""
    dep = _simple_deployment()
    derive_claims(dep)
    # The BOM claim derives SUPPORTED (a pass) for a provider-backed deployment.
    bom = _claims_by_type(dep)[ClaimType.AI_BOM]
    assert bom.status == Status.SUPPORTED

    _move_fingerprint(dep)
    check_invalidations(dep)

    for claim in _claims_by_type(dep).values():
        assert claim.status not in _PASS_STATES
    bom.refresh_from_db()
    assert bom.status == Status.STALE
    assert bom.events.filter(to_status=Status.STALE).exists()


def test_engine_is_idempotent_no_duplicate_obligation():
    dep = _simple_deployment()
    derive_claims(dep)
    _move_fingerprint(dep)

    first = check_invalidations(dep)
    assert first["retests_opened"] == 3
    # The drift persists, so the claims still read as invalidated...
    second = check_invalidations(dep)
    assert second["invalidated"] == 3
    # ...but no second obligation is opened for the same open drift.
    assert second["retests_opened"] == 0
    assert RetestRequirement.objects.filter(deployment=dep, resolved_at__isnull=True).count() == 3


# ---------------------------------------------------------------------------
# Resolution is earned by a rebinding re-derivation, and only then
# ---------------------------------------------------------------------------


def test_fresh_derive_resolves_obligation_with_resolving_claim():
    dep = _simple_deployment()
    derive_claims(dep)
    bom_before = _claims_by_type(dep)[ClaimType.AI_BOM]
    _move_fingerprint(dep)
    check_invalidations(dep)

    req = RetestRequirement.objects.get(claim=bom_before)
    assert req.is_open

    # A fresh derive rebinds each claim to the new system state and, in doing so,
    # resolves the obligation it answered.
    new_fp = compute_system_fingerprint(dep)
    derive_claims(dep)

    req.refresh_from_db()
    assert req.resolved_at is not None
    assert req.resolving_claim is not None
    # The resolver is the NEW current version, bound to the changed state.
    assert req.resolving_claim.valid_to is None
    assert req.resolving_claim.system_fingerprint == new_fp
    assert req.resolving_claim_id != bom_before.pk
    assert req.resolving_claim.fingerprint == bom_before.fingerprint  # same identity


def test_stale_claim_without_rebind_does_not_resolve():
    """A machine no longer flagging drift is not a retest. Without a rebinding
    re-derivation, an open obligation stays open."""
    dep = _simple_deployment()
    derive_claims(dep)
    _move_fingerprint(dep)
    check_invalidations(dep)

    # Re-running the check (no derive) resolves nothing — the current versions are
    # still the drifted ones, not freshly rebound.
    counts = check_invalidations(dep)
    assert counts["retests_resolved"] == 0
    assert resolve_satisfied_requirements(dep) == 0
    assert RetestRequirement.objects.filter(deployment=dep, resolved_at__isnull=True).count() == 3


# ---------------------------------------------------------------------------
# The human guard and honesty invariants
# ---------------------------------------------------------------------------


def test_revoked_claim_is_never_invalidated():
    dep = _simple_deployment()
    derive_claims(dep)
    bom = _claims_by_type(dep)[ClaimType.AI_BOM]
    # A human withdraws the claim.
    bom.status = Status.REVOKED
    bom.save(update_fields=["status"])

    _move_fingerprint(dep)
    counts = check_invalidations(dep)

    # The revoked claim is not counted, not marked, and given no obligation; the
    # other two claims still invalidate.
    assert counts["invalidated"] == 2
    bom.refresh_from_db()
    assert bom.status == Status.REVOKED
    assert not RetestRequirement.objects.filter(claim__fingerprint=bom.fingerprint).exists()


def test_cross_claim_change_opens_dependent_boundary_retest():
    """A supply-chain change (an AI_BOM input — a provider assertion) also opens a
    retest on the dependent DATA_BOUNDARY claim. With Phase 1's deployment-wide
    system fingerprint the dependent claims co-invalidate, which is the documented
    INVALIDATES seam (assurance.invalidation._CLAIM_DEPENDENCIES)."""
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("OpenAI", ev=EvidenceClass.CONFIGURATION_VERIFIED, region="eu-west-1", trains_on_data="No")
    _asset(dep, provider=p, name="gpt", identifier="gpt", metadata={"region": "eu-west-1"})
    derive_claims(dep)

    # Change an AI_BOM input: a provider's declared posture.
    assertion = p.assertions.get(field="region")
    assertion.value = "us-east-1"
    assertion.save(update_fields=["value"])

    check_invalidations(dep)
    boundary = _claims_by_type(dep)[ClaimType.DATA_BOUNDARY]
    assert RetestRequirement.objects.filter(
        claim__fingerprint=boundary.fingerprint, resolved_at__isnull=True
    ).exists()


# ---------------------------------------------------------------------------
# API — reads scoped, mutations admin-only
# ---------------------------------------------------------------------------


def test_check_invalidations_endpoint_admin_only_and_returns_counts():
    admin = _user("boss", role=User.Roles.ADMIN)
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = _simple_deployment(owner=admin)
    derive_claims(dep)
    _move_fingerprint(dep)

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"post": "check_invalidations"})

    denied = factory.post(f"/api/assurance/deployments/{dep.uuid}/check-invalidations/")
    force_authenticate(denied, user=analyst)
    assert view(denied, uuid=str(dep.uuid)).status_code == 403
    assert RetestRequirement.objects.filter(deployment=dep).count() == 0

    ok = factory.post(f"/api/assurance/deployments/{dep.uuid}/check-invalidations/")
    force_authenticate(ok, user=admin)
    resp = view(ok, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert set(resp.data.keys()) == {"invalidated", "retests_opened", "retests_resolved"}
    assert resp.data["retests_opened"] == 3
    # The endpoint attributes the obligations to the calling admin.
    assert RetestRequirement.objects.filter(deployment=dep, actor=admin).count() == 3


def test_retest_requirements_action_returns_open_and_all():
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = _simple_deployment(owner=admin)
    derive_claims(dep)
    _move_fingerprint(dep)
    check_invalidations(dep, actor=admin)

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "retest_requirements"})

    # Open by default.
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/retest-requirements/")
    force_authenticate(req, user=admin)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert len(resp.data) == 3
    keys = set(resp.data[0].keys())
    for expected in ("uuid", "claim_uuid", "claim_type", "reason", "is_open", "actor", "opened_at"):
        assert expected in keys

    # Resolve them via a rebinding derive, then ?all=true shows history while the
    # default open view is empty.
    derive_claims(dep)
    open_req = factory.get(f"/api/assurance/deployments/{dep.uuid}/retest-requirements/")
    force_authenticate(open_req, user=admin)
    assert len(view(open_req, uuid=str(dep.uuid)).data) == 0
    all_req = factory.get(f"/api/assurance/deployments/{dep.uuid}/retest-requirements/?all=true")
    force_authenticate(all_req, user=admin)
    all_resp = view(all_req, uuid=str(dep.uuid))
    assert len(all_resp.data) == 3
    assert all(r["is_open"] is False for r in all_resp.data)


def test_retest_requirement_list_is_scoped():
    owner = _user("owner", role=User.Roles.VIEWER)
    other = _user("other", role=User.Roles.VIEWER)
    dep = _simple_deployment(owner=owner)
    derive_claims(dep)
    _move_fingerprint(dep)
    check_invalidations(dep)

    factory = APIRequestFactory()
    list_view = RetestRequirementViewSet.as_view({"get": "list"})

    # The deployment owner sees their obligations.
    req = factory.get("/api/assurance/retest-requirements/")
    force_authenticate(req, user=owner)
    resp = list_view(req)
    assert resp.status_code == 200
    assert resp.data["count"] == 3

    # An unrelated non-privileged user sees none.
    req2 = factory.get("/api/assurance/retest-requirements/")
    force_authenticate(req2, user=other)
    assert list_view(req2).data["count"] == 0
