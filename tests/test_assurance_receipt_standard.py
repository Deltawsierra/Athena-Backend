"""Athena commercial spine — the Assurance Receipt as a versioned standard.

Proves :func:`assurance.receipt.build_assurance_receipt` is what the roadmap's
"assurance receipt as a standard" asks for: a versioned, documented,
machine-readable, deterministic, portable payload carrying the tuple *system,
version, policy, evidence, result, per-assessment digests*. It attests integrity
and provenance, never that the conclusions are true — an undeclared policy reads
as ``declared: false`` rather than an invented one, and a change to a finding's
evidence moves the top-level digest.

The bare ``receipt`` action is unchanged; the new ``assurance-receipt`` action is
an open, computed read of the full standard.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import receipt
from assurance.models import (
    Asset,
    DataBoundary,
    Deployment,
    EvidenceClass,
    Evidence,
    Finding,
    Provider,
    ProviderAssertion,
)
from assurance.views import DeploymentViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _finding(dep, fp="fp1", ftype="xss", severity="high"):
    return Finding.objects.create(
        deployment=dep, fingerprint=fp, finding_type=ftype, title="F", severity=severity,
    )


def _evidence(finding, classification, source, content_hash):
    return Evidence.objects.create(
        finding=finding, classification=classification, source=source, content_hash=content_hash,
    )


def _populated_deployment(owner, *, environment=Deployment.Environment.PRODUCTION):
    """A deployment with a finding+evidence, an asset+provider, so every
    assessment (compliance / capabilities / boundary / bom) has real input."""
    dep = Deployment.objects.create(
        name="checkout-assistant",
        owner=owner,
        environment=environment,
        decision=Deployment.Decision.NEEDS_MORE_EVIDENCE,
    )
    f = _finding(dep)
    _evidence(f, EvidenceClass.VENDOR_ASSERTED, "vendor_doc", "a" * 64)
    provider = Provider.objects.create(name="Acme Model Co", kind=Provider.Kind.MODEL_PROVIDER)
    ProviderAssertion.objects.create(
        provider=provider, field=ProviderAssertion.Field.REGION, value="us-east-1"
    )
    Asset.objects.create(
        deployment=dep, kind=Asset.Kind.MODEL, name="gpt-x", provider=provider,
        classification=Asset.Classification.APPROVED,
    )
    return dep, f


def test_receipt_carries_the_full_versioned_tuple():
    owner = _user()
    dep, _f = _populated_deployment(owner)

    r = receipt.build_assurance_receipt(dep)

    # Version — the standard is versioned and stamps which schema it is.
    # 2.0 since the receipt began carrying the served route and the coverage
    # manifest: both are new HASHED content, so every 1.1 digest differs from the
    # 2.0 digest of the same state. A minor bump would have told a consumer the
    # shapes were compatible when the digests are not.
    assert r["receipt_version"] == receipt.RECEIPT_VERSION == "mythos.assurance.receipt/2.0"
    assert receipt.RECEIPT_SCHEMA["$id"] == receipt.RECEIPT_VERSION

    # The pinned assurance-policy version the decision was made under — the rule
    # set, not just the declared boundary. Matches the policy module's pin.
    from assurance.policy import policy_pin

    assert r["policy_version"] == policy_pin(dep)
    assert r["policy_version"].startswith("mythos.assurance.policy/")

    # System X.
    assert r["system"]["name"] == "checkout-assistant"
    assert r["system"]["uuid"] == str(dep.uuid)
    assert r["system"]["environment"] == Deployment.Environment.PRODUCTION

    # Result R — the six-state decision, carried at its true strength (not inflated).
    assert r["result"]["decision"] == Deployment.Decision.NEEDS_MORE_EVIDENCE
    assert r["result"]["decision_label"] == "Requires additional evidence"

    # Evidence set E — the Merkle-style root over the finding/evidence hashes.
    assert r["evidence"]["algorithm"] == "sha256"
    assert r["evidence"]["root"] == receipt.deployment_receipt(dep)["digest"]
    assert r["evidence"]["finding_count"] == 1

    # Per-assessment digests — one per computed assessment.
    assert set(r["assessments"]) == {"compliance", "capabilities", "boundary", "bom"}
    assert all(len(d) == 64 for d in r["assessments"].values())

    # Top-level digest + metadata timestamp outside the hash.
    assert len(r["digest"]) == 64
    assert r["algorithm"] == "sha256"
    assert "computed_at" in r


def test_receipt_is_deterministic_ignoring_the_timestamp():
    owner = _user()
    dep, _f = _populated_deployment(owner)

    r1 = receipt.build_assurance_receipt(dep)
    r2 = receipt.build_assurance_receipt(dep)

    # The digest is reproducible for the same DB state…
    assert r1["digest"] == r2["digest"]
    # …and so is every stable field (only computed_at, outside the hash, may move).
    r1_stable = {k: v for k, v in r1.items() if k != "computed_at"}
    r2_stable = {k: v for k, v in r2.items() if k != "computed_at"}
    assert r1_stable == r2_stable


def test_a_change_to_a_finding_changes_the_top_level_digest():
    owner = _user()
    dep, f = _populated_deployment(owner)
    before = receipt.build_assurance_receipt(dep)["digest"]

    # Tamper with the evidence behind the finding — the evidence root, and so the
    # top-level digest, must move: the receipt is tamper-evident.
    e = f.evidence.first()
    e.content_hash = "9" * 64
    e.save()

    after = receipt.build_assurance_receipt(dep)["digest"]
    assert before != after


def test_an_undeclared_policy_reads_as_declared_false_not_invented():
    owner = _user()
    dep, _f = _populated_deployment(owner)  # no DataBoundary declared

    r = receipt.build_assurance_receipt(dep)
    assert r["policy"] == {"declared": False}
    # Honest: no fabricated regions or permissive flags when nothing was approved.
    assert "allowed_regions" not in r["policy"]
    assert "training_allowed" not in r["policy"]


def test_a_declared_policy_is_carried_faithfully():
    owner = _user()
    dep, _f = _populated_deployment(owner)
    DataBoundary.objects.create(
        deployment=dep,
        allowed_regions=["eu-west-1"],
        training_allowed=False,
        third_party_sharing_allowed=False,
    )

    r = receipt.build_assurance_receipt(dep)
    assert r["policy"]["declared"] is True
    assert r["policy"]["allowed_regions"] == ["eu-west-1"]
    assert r["policy"]["training_allowed"] is False
    assert r["policy"]["third_party_sharing_allowed"] is False


def test_declaring_a_policy_changes_the_digest():
    owner = _user()
    dep, _f = _populated_deployment(owner)
    before = receipt.build_assurance_receipt(dep)["digest"]
    DataBoundary.objects.create(deployment=dep, allowed_regions=["eu-west-1"])
    after = receipt.build_assurance_receipt(Deployment.objects.get(pk=dep.pk))["digest"]
    assert before != after


def test_assurance_receipt_endpoint_is_an_open_read():
    admin = _user("boss", role=User.Roles.ADMIN)
    dep, _f = _populated_deployment(admin)

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "assurance_receipt"})

    # A non-admin analyst may fetch it — a receipt an auditor cannot fetch cannot
    # be verified, so the standard is an open read like the other assessments.
    analyst = _user("ana", role=User.Roles.ANALYST)
    request = factory.get(f"/api/assurance/deployments/{dep.uuid}/assurance-receipt/")
    force_authenticate(request, user=analyst)
    resp = view(request, uuid=str(dep.uuid))

    assert resp.status_code == 200
    assert resp.data["receipt_version"] == receipt.RECEIPT_VERSION
    assert resp.data["system"]["uuid"] == str(dep.uuid)
    assert resp.data["digest"] == receipt.build_assurance_receipt(dep)["digest"]


def test_the_bare_receipt_action_still_works():
    admin = _user("boss", role=User.Roles.ADMIN)
    dep, f = _populated_deployment(admin)

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "receipt"})
    request = factory.get(f"/api/assurance/deployments/{dep.uuid}/receipt/")
    force_authenticate(request, user=admin)
    resp = view(request, uuid=str(dep.uuid))

    assert resp.status_code == 200
    # Unchanged shape: the bare deployment receipt, not the full standard.
    assert resp.data["digest"] == receipt.deployment_receipt(dep)["digest"]
    assert resp.data["finding_count"] == 1
    assert "receipt_version" not in resp.data
