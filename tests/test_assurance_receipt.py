"""Athena spine (EXPOSE) — Evidence API + Assurance Receipt.

Proves the assurance receipt is a deterministic, recomputable digest over the
evidence hashes that already exist: the same evidence always yields the same
digest, altering any evidence hash changes it (tamper-evident), the digest is
independent of the order evidence was recorded in, and a deployment's receipt is
a stable root over its findings. The receipt attests integrity, not that a
conclusion is true — a receipt over a vendor claim still hashes cleanly.
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.db.models import Prefetch
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import receipt
from assurance.models import Deployment, EvidenceClass, Evidence, Finding
from assurance.views import DeploymentViewSet, FindingViewSet

pytestmark = pytest.mark.django_db

User = get_user_model()


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _finding(dep, fp="fp1"):
    return Finding.objects.create(
        deployment=dep, fingerprint=fp, finding_type="xss", title="XSS", severity="high",
    )


def _evidence(finding, classification, source, content_hash):
    return Evidence.objects.create(
        finding=finding, classification=classification, source=source, content_hash=content_hash,
    )


def test_receipt_is_deterministic_and_ignores_the_timestamp():
    dep = Deployment.objects.create(name="d", owner=_user())
    f = _finding(dep)
    _evidence(f, EvidenceClass.PARTIALLY_VERIFIED, "engine_scan", "a" * 64)

    r1 = receipt.finding_receipt(f)
    r2 = receipt.finding_receipt(f)
    assert r1["digest"] == r2["digest"]  # same content → same digest
    assert r1["algorithm"] == "sha256"
    assert r1["evidence_count"] == 1
    # computed_at is metadata, never part of the hashed content.
    assert "computed_at" in r1


def test_altering_an_evidence_hash_changes_the_receipt():
    dep = Deployment.objects.create(name="d", owner=_user())
    f = _finding(dep)
    e = _evidence(f, EvidenceClass.PARTIALLY_VERIFIED, "engine_scan", "a" * 64)
    before = receipt.finding_receipt(f)["digest"]

    e.content_hash = "b" * 64  # tamper
    e.save()
    f.refresh_from_db()
    after = receipt.finding_receipt(f)["digest"]
    assert before != after


def test_receipt_is_independent_of_evidence_order():
    # The digest sorts the evidence rows, so the order they were recorded in — or
    # the order the ORM returns them — never changes it.
    dep = Deployment.objects.create(name="d", owner=_user())
    f = _finding(dep)
    _evidence(f, EvidenceClass.PARTIALLY_VERIFIED, "engine_scan", "1" * 64)
    _evidence(f, EvidenceClass.VENDOR_ASSERTED, "vendor_doc", "2" * 64)

    forward = Finding.objects.prefetch_related("evidence").get(pk=f.pk)
    # A queryset that yields the evidence in the reverse order must hash the same.
    reversed_ = Finding.objects.prefetch_related(
        Prefetch("evidence", queryset=Evidence.objects.order_by("-content_hash"))
    ).get(pk=f.pk)
    assert receipt.finding_receipt(forward)["digest"] == receipt.finding_receipt(reversed_)["digest"]


def test_receipt_over_a_vendor_claim_still_hashes_cleanly():
    # Integrity, not truth: a weak-evidence finding produces a valid receipt.
    dep = Deployment.objects.create(name="d", owner=_user())
    f = _finding(dep)
    _evidence(f, EvidenceClass.VENDOR_ASSERTED, "vendor_doc", "c" * 64)
    r = receipt.finding_receipt(f)
    assert len(r["digest"]) == 64 and r["evidence_count"] == 1


def test_deployment_receipt_is_a_stable_root_over_its_findings():
    dep = Deployment.objects.create(name="d", owner=_user())
    f1 = _finding(dep, fp="a")
    _evidence(f1, EvidenceClass.PARTIALLY_VERIFIED, "engine_scan", "1" * 64)
    f2 = _finding(dep, fp="b")
    _evidence(f2, EvidenceClass.CONFIGURATION_VERIFIED, "config", "2" * 64)

    root1 = receipt.deployment_receipt(dep)
    assert root1["finding_count"] == 2
    assert len(root1["digest"]) == 64
    # Stable when nothing changed…
    assert receipt.deployment_receipt(dep)["digest"] == root1["digest"]
    # …and moves when a finding's evidence is altered.
    e = f2.evidence.first()
    e.content_hash = "9" * 64
    e.save()
    assert receipt.deployment_receipt(dep)["digest"] != root1["digest"]


def test_finding_api_exposes_the_receipt():
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep)
    _evidence(f, EvidenceClass.PARTIALLY_VERIFIED, "engine_scan", "a" * 64)

    factory = APIRequestFactory()
    view = FindingViewSet.as_view({"get": "list"})
    request = factory.get("/api/assurance/findings/")
    force_authenticate(request, user=admin)
    resp = view(request)
    assert resp.status_code == 200
    rows = resp.data["results"] if isinstance(resp.data, dict) else resp.data
    r = rows[0]["receipt"]
    assert r["algorithm"] == "sha256" and r["evidence_count"] == 1
    assert r["digest"] == receipt.finding_receipt(f)["digest"]


def test_deployment_receipt_endpoint_is_an_open_read():
    admin = _user("boss", role=User.Roles.ADMIN)
    dep = Deployment.objects.create(name="d", owner=admin)
    f = _finding(dep)
    _evidence(f, EvidenceClass.PARTIALLY_VERIFIED, "engine_scan", "a" * 64)

    factory = APIRequestFactory()
    view = DeploymentViewSet.as_view({"get": "receipt"})

    # An analyst (privileged reader) may verify without being an admin — it is a
    # read, and a receipt an auditor cannot fetch cannot be verified.
    analyst = _user("ana", role=User.Roles.ANALYST)
    request = factory.get(f"/api/assurance/deployments/{dep.uuid}/receipt/")
    force_authenticate(request, user=analyst)
    resp = view(request, uuid=str(dep.uuid))
    assert resp.status_code == 200
    assert resp.data["digest"] == receipt.deployment_receipt(dep)["digest"]
    assert resp.data["finding_count"] == 1
