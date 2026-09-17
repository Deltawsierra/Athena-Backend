"""Athena SPINE Phase 1 — the Assurance Claims Engine.

Proves the engine turns the shipped assessments into version-bound, falsifiable
claims that keep the six honesty invariants, and that its lifecycle refuses to
coerce a claim into a dishonest state:

- the system fingerprint is deterministic and timestamp-free (same graph → same
  fingerprint; a config change moves it; the passage of time does not);
- each deriver maps to an honest status (a boundary violation → CONTRADICTED, an
  undeclared posture → UNKNOWN, a vendor-asserted boundary caps at SUPPORTED and
  never reads VERIFIED, a configuration-verified least-privilege reach can reach
  VERIFIED);
- ``confidence`` is None for UNKNOWN, never 0;
- a system_fingerprint change SUPERSEDES the old version (valid_to set, status
  SUPERSEDED, superseded_by linked) and leaves exactly one current version — the
  partial unique constraint holds;
- a re-derive preserves the human owner and never overwrites a human REVOKED;
- the lifecycle rejects the illegal, including hand-verifying an
  unknown/contradicted/vendor claim, and allows REVOKE from any live state, every
  move attributed;
- staleness moves a current claim to STALE after the TTL, never toward a pass;
- the three endpoints return 200 for an authorized reader and enforce admin on
  writes.

The migration applying is implicit: the test database is built from it.
"""

from __future__ import annotations

from datetime import timedelta

import pytest
from django.contrib.auth import get_user_model
from django.db.utils import IntegrityError
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance.change import EVIDENCE_TTL_DAYS
from assurance.claims import (
    IllegalClaimTransition,
    apply_claim_transition,
    can_transition,
    derive_claims,
)
from assurance.fingerprint import compute_system_fingerprint, policy_version
from assurance.models import (
    Asset,
    AssuranceClaim,
    ClaimEvent,
    DataBoundary,
    Deployment,
    EvidenceClass,
    Provider,
    ProviderAssertion,
)
from assurance.receipt import RECEIPT_VERSION
from assurance.views import ClaimViewSet, DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()

Status = AssuranceClaim.ClaimStatus
ClaimType = AssuranceClaim.ClaimType


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _provider(name, *, kind=Provider.Kind.MODEL_PROVIDER, ev=EvidenceClass.VENDOR_ASSERTED, **assertions):
    """Create a provider and one graded assertion per keyword (field=value), at the
    given evidence class — mirroring the boundary suite's fixture so `region=...`,
    `trains_on_data=...` etc. become real ProviderAssertion rows."""
    p = Provider.objects.create(name=name, kind=kind)
    for field, value in assertions.items():
        ProviderAssertion.objects.create(provider=p, field=field, value=value, evidence_class=ev)
    return p


def _asset(dep, *, kind=Asset.Kind.MODEL, provider=None, classification=Asset.Classification.KNOWN, name="m", identifier=None, metadata=None):
    return Asset.objects.create(
        deployment=dep, provider=provider, kind=kind, classification=classification,
        name=name, identifier=identifier or name, metadata=metadata or {},
    )


def _policy(dep, **kwargs):
    return DataBoundary.objects.create(deployment=dep, **kwargs)


def _claim(dep, *, fingerprint="fp", status=Status.SUPPORTED, evidence_class=EvidenceClass.CONFIGURATION_VERIFIED, vendor_asserted=False, **kwargs):
    """A claim built directly for lifecycle tests, mirroring how the remediation
    tests build findings directly to exercise the state machine in isolation."""
    now = timezone.now()
    defaults = dict(
        deployment=dep,
        claim_type=ClaimType.DATA_BOUNDARY,
        statement="s",
        fingerprint=fingerprint,
        system_fingerprint="sysfp",
        policy_version=RECEIPT_VERSION,
        environment=dep.environment,
        status=status,
        evidence_class=evidence_class,
        vendor_asserted=vendor_asserted,
        valid_from=now,
        first_seen=now,
        last_seen=now,
    )
    defaults.update(kwargs)
    return AssuranceClaim.objects.create(**defaults)


def _claims_by_type(dep):
    return {
        c.claim_type: c
        for c in AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True)
    }


# ---------------------------------------------------------------------------
# System fingerprint — deterministic and timestamp-free
# ---------------------------------------------------------------------------


def test_identical_graphs_produce_identical_fingerprints():
    """The fingerprint is over stable state only (not the deployment identity), so
    two deployments with an identical asset/provider/boundary graph and the same
    environment fingerprint identically."""
    a = Deployment.objects.create(name="a", owner=_user("u1"))
    b = Deployment.objects.create(name="b", owner=_user("u2"))
    # Providers are a global registry, so an identical graph shares the same
    # provider row; the fingerprint is over stable state, not the deployment id.
    p = _provider("OpenAI", ev=EvidenceClass.CONFIGURATION_VERIFIED, region="eu-west-1", trains_on_data="No")
    for dep in (a, b):
        _asset(dep, provider=p, name="gpt", identifier="gpt", metadata={"model": "gpt-x", "region": "eu-west-1"})
        _policy(dep, allowed_regions=["eu"], training_allowed=False)

    assert compute_system_fingerprint(a) == compute_system_fingerprint(b)
    assert len(compute_system_fingerprint(a)) == 64


def test_config_change_changes_the_fingerprint():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("OpenAI", ev=EvidenceClass.CONFIGURATION_VERIFIED, region="eu-west-1")
    asset = _asset(dep, provider=p, name="gpt", identifier="gpt", metadata={"region": "eu-west-1"})
    before = compute_system_fingerprint(dep)

    # A change to salient config moves the fingerprint.
    asset.metadata = {"region": "us-east-1"}
    asset.save()
    after = compute_system_fingerprint(dep)
    assert before != after

    # Adding a permission also moves it.
    asset.metadata = {"region": "us-east-1", "permissions": ["exec"]}
    asset.save()
    assert compute_system_fingerprint(dep) != after


def test_time_passing_does_not_change_the_fingerprint():
    """Timestamps are excluded, so re-observing the same state (moving last_seen,
    first_seen) never changes the fingerprint — 'free of any timestamp'."""
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("OpenAI", ev=EvidenceClass.CONFIGURATION_VERIFIED, region="eu-west-1")
    asset = _asset(dep, provider=p, name="gpt", identifier="gpt", metadata={"model": "gpt-x"})
    before = compute_system_fingerprint(dep)

    asset.first_seen = asset.first_seen - timedelta(days=30)
    asset.last_seen = timezone.now() + timedelta(days=5)
    asset.save()
    assert compute_system_fingerprint(dep) == before


def test_policy_version_is_the_receipt_version():
    dep = Deployment.objects.create(name="d", owner=_user())
    assert policy_version(dep) == RECEIPT_VERSION


# ---------------------------------------------------------------------------
# Derivers — honest status mapping
# ---------------------------------------------------------------------------


def test_boundary_violation_derives_contradicted():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("OpenAI", ev=EvidenceClass.CONFIGURATION_VERIFIED, region="us-east-1")
    _asset(dep, provider=p, name="gpt", identifier="gpt")
    _policy(dep, allowed_regions=["eu"], third_party_sharing_allowed=True)

    derive_claims(dep)
    claim = _claims_by_type(dep)[ClaimType.DATA_BOUNDARY]
    assert claim.status == Status.CONTRADICTED
    assert claim.confidence is None  # a false statement carries no supporting confidence
    assert "outside the boundary" in claim.contradicting_summary


def test_undeclared_boundary_derives_unknown_with_none_confidence():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("Silent")  # declares nothing
    _asset(dep, provider=p, name="gpt", identifier="gpt")
    _policy(dep, allowed_regions=["eu"], training_allowed=False)

    derive_claims(dep)
    claim = _claims_by_type(dep)[ClaimType.DATA_BOUNDARY]
    assert claim.status == Status.UNKNOWN
    # Invariant 2: confidence is None for UNKNOWN, NEVER 0.
    assert claim.confidence is None
    assert claim.evidence_class == EvidenceClass.UNKNOWN.value


def test_vendor_asserted_boundary_caps_at_supported_never_verified():
    """Invariant 4: a boundary that reconciles cleanly but rests on
    vendor-asserted provider claims caps at SUPPORTED — it never reads VERIFIED."""
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider(
        "OpenAI",
        ev=EvidenceClass.VENDOR_ASSERTED,
        region="eu-west-1",
        trains_on_data="No",
        subprocessors="none",
    )
    _asset(dep, provider=p, name="gpt", identifier="gpt")
    _policy(dep, allowed_regions=["eu"], training_allowed=False, third_party_sharing_allowed=False)

    derive_claims(dep)
    claim = _claims_by_type(dep)[ClaimType.DATA_BOUNDARY]
    assert claim.status == Status.SUPPORTED
    assert claim.vendor_asserted is True
    assert claim.confidence is not None and claim.confidence > 0


def test_configuration_verified_boundary_can_reach_verified():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider(
        "EU Model Co",
        ev=EvidenceClass.CONFIGURATION_VERIFIED,
        region="eu-west-1",
        trains_on_data="No",
        subprocessors="none",
    )
    _asset(dep, provider=p, classification=Asset.Classification.APPROVED, name="gpt", identifier="gpt")
    _policy(dep, allowed_regions=["eu"], training_allowed=False, third_party_sharing_allowed=False)

    derive_claims(dep)
    claim = _claims_by_type(dep)[ClaimType.DATA_BOUNDARY]
    assert claim.status == Status.VERIFIED
    assert claim.vendor_asserted is False
    assert claim.verified_at is not None
    assert claim.evidence_class == EvidenceClass.CONFIGURATION_VERIFIED.value


def test_effective_access_contradicted_on_privileged_reach():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           classification=Asset.Classification.APPROVED, metadata={"tools": ["shell-tool"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="shell", identifier="shell-tool",
           classification=Asset.Classification.APPROVED, metadata={"permissions": ["exec"]})

    derive_claims(dep)
    claim = _claims_by_type(dep)[ClaimType.EFFECTIVE_ACCESS]
    assert claim.status == Status.CONTRADICTED
    assert "privileged" in claim.contradicting_summary.lower()


def test_effective_access_verified_when_least_privilege_and_config_verified():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
           classification=Asset.Classification.APPROVED, metadata={"tools": ["reporter"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="reporter", identifier="reporter",
           classification=Asset.Classification.APPROVED, metadata={"permissions": ["query"]})

    derive_claims(dep)
    claim = _claims_by_type(dep)[ClaimType.EFFECTIVE_ACCESS]
    # An elevated but non-high reach to a managed target has no high-risk gap.
    assert claim.status == Status.VERIFIED
    assert claim.evidence_class == EvidenceClass.CONFIGURATION_VERIFIED.value
    assert claim.vendor_asserted is False


def test_effective_access_unknown_when_no_principals():
    dep = Deployment.objects.create(name="d", owner=_user())
    _asset(dep, kind=Asset.Kind.MODEL, name="gpt", identifier="gpt")  # no principals

    derive_claims(dep)
    claim = _claims_by_type(dep)[ClaimType.EFFECTIVE_ACCESS]
    assert claim.status == Status.UNKNOWN
    assert claim.confidence is None


def test_ai_bom_supported_capped_by_weakest_and_unknown_without_providers():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("OpenAI", ev=EvidenceClass.VENDOR_ASSERTED, region="eu-west-1", trains_on_data="No")
    _asset(dep, provider=p, name="gpt", identifier="gpt")

    derive_claims(dep)
    bom = _claims_by_type(dep)[ClaimType.AI_BOM]
    assert bom.status == Status.SUPPORTED
    assert bom.evidence_class == EvidenceClass.VENDOR_ASSERTED.value
    assert bom.vendor_asserted is True

    # A deployment with no providers cannot enumerate a supply chain → UNKNOWN.
    empty = Deployment.objects.create(name="e", owner=_user("u2"))
    derive_claims(empty)
    bom2 = _claims_by_type(empty)[ClaimType.AI_BOM]
    assert bom2.status == Status.UNKNOWN
    assert bom2.confidence is None


# ---------------------------------------------------------------------------
# Idempotence, version binding, and the human guards
# ---------------------------------------------------------------------------


def test_derive_is_idempotent_no_duplicates():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("OpenAI", ev=EvidenceClass.CONFIGURATION_VERIFIED, region="eu-west-1")
    _asset(dep, provider=p, name="gpt", identifier="gpt")

    first = derive_claims(dep)
    assert first["created"] == 3  # one per ClaimType
    second = derive_claims(dep)
    assert second["created"] == 0
    assert second["superseded"] == 0
    # Still exactly one current version per identity.
    assert AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True).count() == 3


def test_system_fingerprint_change_supersedes_and_leaves_one_current():
    dep = Deployment.objects.create(name="d", owner=_user())
    p = _provider("OpenAI", ev=EvidenceClass.CONFIGURATION_VERIFIED, region="eu-west-1")
    _asset(dep, provider=p, name="gpt", identifier="gpt")
    derive_claims(dep)

    bom_before = _claims_by_type(dep)[ClaimType.AI_BOM]
    fp = bom_before.fingerprint

    # A config change (a new component) moves the system fingerprint.
    _asset(dep, kind=Asset.Kind.VECTOR_DB, name="pinecone", identifier="pinecone")
    counts = derive_claims(dep)
    assert counts["superseded"] == 3

    old = AssuranceClaim.objects.get(pk=bom_before.pk)
    assert old.valid_to is not None
    assert old.status == Status.SUPERSEDED
    assert old.superseded_by is not None
    # Exactly one CURRENT version of that identity, and it is the new one.
    current = AssuranceClaim.objects.filter(deployment=dep, fingerprint=fp, valid_to__isnull=True)
    assert current.count() == 1
    assert current.get().pk == old.superseded_by_id
    # The seam is attributed on both sides.
    assert old.events.filter(to_status=Status.SUPERSEDED).exists()


def test_partial_unique_constraint_forbids_two_current_versions():
    dep = Deployment.objects.create(name="d", owner=_user())
    _claim(dep, fingerprint="dup")
    with pytest.raises(IntegrityError):
        _claim(dep, fingerprint="dup")


def test_redevive_preserves_human_owner_and_never_overwrites_revoked():
    dep = Deployment.objects.create(name="d", owner=_user())
    admin = _user("boss", role=User.Roles.ADMIN)
    p = _provider("OpenAI", ev=EvidenceClass.CONFIGURATION_VERIFIED, region="us-east-1")
    _asset(dep, provider=p, name="gpt", identifier="gpt")
    _policy(dep, allowed_regions=["eu"], third_party_sharing_allowed=True)  # a violation
    derive_claims(dep)

    boundary = _claims_by_type(dep)[ClaimType.DATA_BOUNDARY]
    assert boundary.status == Status.CONTRADICTED
    # A human takes ownership and revokes the claim.
    boundary.human_owner = admin
    boundary.save(update_fields=["human_owner"])
    apply_claim_transition(boundary, Status.REVOKED, actor=admin, note="withdrawn")

    # Re-deriving the SAME state must not resurrect or relabel a revoked claim, and
    # must preserve the human owner.
    derive_claims(dep)
    boundary.refresh_from_db()
    assert boundary.status == Status.REVOKED
    assert boundary.human_owner == admin

    # An owned but non-revoked claim keeps its owner across a machine refresh too.
    bom = _claims_by_type(dep)[ClaimType.AI_BOM]
    bom.human_owner = admin
    bom.save(update_fields=["human_owner"])
    derive_claims(dep)
    bom.refresh_from_db()
    assert bom.human_owner == admin


def test_staleness_moves_current_claim_to_stale_after_ttl():
    """A current, non-contradicted claim whose evidence has expired is moved to
    STALE — away from a pass, never toward one."""
    dep = Deployment.objects.create(name="d", owner=_user())
    # A claim about a specific asset that the deployment-level derivers do not
    # produce, so a derive run does not refresh its last_seen.
    stale = _claim(
        dep,
        fingerprint="stale-fp",
        status=Status.SUPPORTED,
        last_seen=timezone.now() - timedelta(days=EVIDENCE_TTL_DAYS + 5),
    )
    counts = derive_claims(dep)
    assert counts["stale"] >= 1
    stale.refresh_from_db()
    assert stale.status == Status.STALE
    assert stale.events.filter(to_status=Status.STALE).exists()


def test_stale_property_matches_ttl():
    dep = Deployment.objects.create(name="d", owner=_user())
    fresh = _claim(dep, fingerprint="a", last_seen=timezone.now())
    old = _claim(dep, fingerprint="b", last_seen=timezone.now() - timedelta(days=EVIDENCE_TTL_DAYS + 1))
    assert fresh.is_stale is False
    assert old.is_stale is True
    # A superseded version is history, never itself "stale".
    old.valid_to = timezone.now()
    old.save(update_fields=["valid_to"])
    assert old.is_stale is False


# ---------------------------------------------------------------------------
# Lifecycle transitions — legality, the verify gate, attribution
# ---------------------------------------------------------------------------


def test_can_verify_only_config_or_technically_verified_non_vendor():
    dep = Deployment.objects.create(name="d", owner=_user())
    admin = _user("boss", role=User.Roles.ADMIN)

    ok = _claim(dep, fingerprint="ok", status=Status.SUPPORTED,
                evidence_class=EvidenceClass.CONFIGURATION_VERIFIED, vendor_asserted=False)
    event = apply_claim_transition(ok, Status.VERIFIED, actor=admin, note="reviewed")
    ok.refresh_from_db()
    assert ok.status == Status.VERIFIED
    assert ok.verified_at is not None
    assert event.actor == admin and event.from_status == Status.SUPPORTED and event.to_status == Status.VERIFIED


def test_cannot_hand_verify_vendor_or_unknown_claim():
    dep = Deployment.objects.create(name="d", owner=_user())
    admin = _user("boss", role=User.Roles.ADMIN)

    vendor = _claim(dep, fingerprint="v", status=Status.SUPPORTED,
                    evidence_class=EvidenceClass.VENDOR_ASSERTED, vendor_asserted=True)
    with pytest.raises(IllegalClaimTransition):
        apply_claim_transition(vendor, Status.VERIFIED, actor=admin)
    vendor.refresh_from_db()
    assert vendor.status == Status.SUPPORTED  # unchanged

    unknown = _claim(dep, fingerprint="u", status=Status.UNKNOWN,
                     evidence_class=EvidenceClass.UNKNOWN, vendor_asserted=True)
    with pytest.raises(IllegalClaimTransition):
        apply_claim_transition(unknown, Status.VERIFIED, actor=admin)

    # A contradicted claim cannot even reach VERIFIED at the map level.
    assert not can_transition(Status.CONTRADICTED, Status.VERIFIED)


def test_revoke_reachable_from_any_live_state_and_attributed():
    dep = Deployment.objects.create(name="d", owner=_user())
    admin = _user("boss", role=User.Roles.ADMIN)
    for i, state in enumerate([Status.SUPPORTED, Status.VERIFIED, Status.CONTRADICTED, Status.UNKNOWN, Status.STALE]):
        c = _claim(dep, fingerprint=f"r{i}", status=state)
        event = apply_claim_transition(c, Status.REVOKED, actor=admin, note="withdraw")
        c.refresh_from_db()
        assert c.status == Status.REVOKED
        assert event.actor == admin and event.to_status == Status.REVOKED


def test_machine_only_targets_rejected_as_human_transitions():
    dep = Deployment.objects.create(name="d", owner=_user())
    admin = _user("boss", role=User.Roles.ADMIN)
    c = _claim(dep, fingerprint="m", status=Status.SUPPORTED)
    for target in (Status.STALE, Status.SUPERSEDED):
        with pytest.raises(IllegalClaimTransition):
            apply_claim_transition(c, target, actor=admin)
    c.refresh_from_db()
    assert c.status == Status.SUPPORTED


# ---------------------------------------------------------------------------
# API — reads open, writes admin-only
# ---------------------------------------------------------------------------


def test_assurance_claims_endpoint_returns_current_claims():
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    p = _provider("OpenAI", ev=EvidenceClass.CONFIGURATION_VERIFIED, region="eu-west-1")
    _asset(dep, provider=p, name="gpt", identifier="gpt")
    derive_claims(dep)

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "assurance_claims"})
    req = factory.get(f"/api/assurance/deployments/{dep.uuid}/assurance-claims/")
    force_authenticate(req, user=admin)
    resp = view(req, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert len(resp.data) == 3
    keys = set(resp.data[0].keys())
    for expected in ("status", "evidence_class", "confidence", "vendor_asserted", "is_stale", "system_fingerprint"):
        assert expected in keys


def test_recompute_claims_endpoint_is_admin_only_and_returns_counts():
    admin = _user("boss", role=User.Roles.ADMIN)
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=admin)
    p = _provider("OpenAI", ev=EvidenceClass.CONFIGURATION_VERIFIED, region="eu-west-1")
    _asset(dep, provider=p, name="gpt", identifier="gpt")

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"post": "recompute_claims"})

    denied = factory.post(f"/api/assurance/deployments/{dep.uuid}/recompute-claims/")
    force_authenticate(denied, user=analyst)
    assert view(denied, uuid=str(dep.uuid)).status_code == 403
    assert AssuranceClaim.objects.filter(deployment=dep).count() == 0

    ok = factory.post(f"/api/assurance/deployments/{dep.uuid}/recompute-claims/")
    force_authenticate(ok, user=admin)
    resp = view(ok, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["created"] == 3
    assert set(resp.data.keys()) == {"created", "updated", "superseded", "stale"}


def test_claim_transition_endpoint_admin_only_and_attributed():
    admin = _user("boss", role=User.Roles.ADMIN)
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=admin)
    claim = _claim(dep, fingerprint="t", status=Status.SUPPORTED,
                   evidence_class=EvidenceClass.CONFIGURATION_VERIFIED, vendor_asserted=False)

    factory = APIRequestFactory()
    view = ClaimViewSet.as_view({"post": "transition"})

    # Non-admin refused, nothing recorded.
    denied = factory.post("/x/", {"to_status": "verified"}, format="json")
    force_authenticate(denied, user=analyst)
    assert view(denied, uuid=str(claim.uuid)).status_code == 403
    claim.refresh_from_db()
    assert claim.status == Status.SUPPORTED
    assert claim.events.count() == 0

    # Unknown status → clean 400.
    bad = factory.post("/x/", {"to_status": "banana"}, format="json")
    force_authenticate(bad, user=admin)
    assert view(bad, uuid=str(claim.uuid)).status_code == 400

    # Admin verifies it (evidence permits).
    ok = factory.post("/x/", {"to_status": "verified", "note": "reviewed"}, format="json")
    force_authenticate(ok, user=admin)
    resp = view(ok, uuid=str(claim.uuid))
    assert resp.status_code == 200
    assert resp.data["status"] == "verified"
    claim.refresh_from_db()
    assert claim.status == Status.VERIFIED
    assert claim.events.get().actor == admin


def test_claim_list_and_events_are_scoped_reads():
    owner = _user("owner", role=User.Roles.VIEWER)
    other = _user("other", role=User.Roles.VIEWER)
    dep = Deployment.objects.create(name="d", owner=owner)
    claim = _claim(dep, fingerprint="s", status=Status.SUPPORTED)
    ClaimEvent.objects.create(claim=claim, from_status="", to_status=Status.SUPPORTED, actor=None, note="seed")

    factory = APIRequestFactory()
    list_view = ClaimViewSet.as_view({"get": "list"})

    # The deployment owner sees their claim.
    req = factory.get("/api/assurance/claims/")
    force_authenticate(req, user=owner)
    resp = list_view(req)
    assert resp.status_code == 200
    assert resp.data["count"] == 1

    # An unrelated non-privileged user sees none.
    req2 = factory.get("/api/assurance/claims/")
    force_authenticate(req2, user=other)
    assert list_view(req2).data["count"] == 0

    # The events read is open to the owner and returns the history.
    events_view = ClaimViewSet.as_view({"get": "events"})
    ev = factory.get("/x/")
    force_authenticate(ev, user=owner)
    ev_resp = events_view(ev, uuid=str(claim.uuid))
    assert ev_resp.status_code == 200
    assert len(ev_resp.data) == 1
