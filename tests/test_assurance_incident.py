"""Athena Phase 3.7 — AI Incident Evidence Pack.

Proves the incident pack is a deterministic, REUSE-ONLY assembler over the stored
assurance graph, anchored on a finding (a finding IS the incident in this model),
and that it keeps the honesty invariants the product's credibility rests on:

- it is deterministic — the same graph yields an identical pack digest, stable
  across re-runs;
- no timestamp is inside the hashed content — the digest is over the stable content
  only, and ``computed_at`` rides alongside, outside the hash (proven by
  construction: recomputing the digest over the pack minus its metadata reproduces
  it, and mutating ``computed_at`` never moves it);
- it attests **integrity and provenance**, never that the conclusion is true or the
  system secure — the ``attests`` string says so on the wire;
- ``vendor_asserted`` evidence stays ``vendor_asserted`` — never inflated to verified;
- the runtime transcript (which lives in the engine's evidence pack) is surfaced as
  an **explicit gap** with the engine-pack reference, never fabricated;
- it is None-safe — no owner, no decision, no evidence, no asset, no scan link read
  as honest ``None`` / empty / gap, never "ready"/"secure"/"passing";
- the ripple / blast-radius is included, reused from ``assurance.ripple``;
- the API read returns 200 with the expected top-level keys for an authorized user.
"""

from __future__ import annotations

import json

import pytest
from django.contrib.auth import get_user_model
from rest_framework.test import APIRequestFactory, force_authenticate

from assurance import incident
from assurance.incident import (
    ATTESTS,
    INCIDENT_PACK_SCHEMA,
    INCIDENT_PACK_VERSION,
    assemble_incident_pack,
)
from assurance.models import (
    Asset,
    Deployment,
    Evidence,
    EvidenceClass,
    Finding,
)
from assurance.views import FindingViewSet
from pentest.models import PentestScan

pytestmark = pytest.mark.django_db

User = get_user_model()

# The pack's stable content is everything but these three metadata fields.
_META_FIELDS = ("algorithm", "digest", "computed_at")

_TOP_LEVEL_KEYS = {
    "pack_version",
    "attests",
    "identity",
    "surface",
    "evidence",
    "receipt",
    "runtime_transcript",
    "ripple",
    "decision",
    "algorithm",
    "digest",
    "computed_at",
}


def _user(name="analyst", role=None):
    return User.objects.create_user(username=name, password="x", role=role or User.Roles.ANALYST)


def _asset(dep, *, kind, classification=Asset.Classification.KNOWN, name="c", identifier=None, metadata=None):
    return Asset.objects.create(
        deployment=dep, kind=kind, classification=classification,
        name=name, identifier=identifier or name, metadata=metadata or {},
    )


def _finding(dep, *, asset=None, fp="fp1", finding_type="excessive_agency", title="t",
             severity="high", status=Finding.Status.OPEN, scan=None, location="", control_mapping=None):
    return Finding.objects.create(
        deployment=dep, asset=asset, scan=scan, fingerprint=fp,
        finding_type=finding_type, title=title, severity=severity, status=status,
        location=location, control_mapping=control_mapping or {},
    )


def _evidence(finding, classification, source, content_hash):
    return Evidence.objects.create(
        finding=finding, classification=classification, source=source, content_hash=content_hash,
    )


def _stable(pack: dict) -> dict:
    return {k: v for k, v in pack.items() if k not in _META_FIELDS}


# ---------------------------------------------------------------------------
# Determinism & the timestamp-free digest
# ---------------------------------------------------------------------------


def test_pack_is_deterministic_same_graph_same_digest():
    dep = Deployment.objects.create(name="d", owner=_user())
    f = _finding(dep)
    _evidence(f, EvidenceClass.PARTIALLY_VERIFIED, "engine_scan", "a" * 64)

    p1 = assemble_incident_pack(f)
    p2 = assemble_incident_pack(f)
    assert p1["digest"] == p2["digest"]  # same content → same digest
    assert p1["algorithm"] == "sha256"
    assert len(p1["digest"]) == 64
    # Stable across a fresh fetch of the same finding, too.
    refetched = Finding.objects.prefetch_related("evidence").get(pk=f.pk)
    assert assemble_incident_pack(refetched)["digest"] == p1["digest"]


def test_digest_is_over_stable_content_with_no_timestamp_inside():
    dep = Deployment.objects.create(name="d", owner=_user())
    f = _finding(dep)
    _evidence(f, EvidenceClass.VENDOR_ASSERTED, "vendor_doc", "b" * 64)

    pack = assemble_incident_pack(f)
    stable = _stable(pack)
    # By construction the digest excludes the timestamp: no computed_at in the hashed
    # content, and recomputing over the stable content reproduces the digest exactly.
    assert "computed_at" not in stable
    assert pack["digest"] == incident._digest(stable)

    # Mutating the computed_at path can never move the digest.
    tampered = dict(pack)
    tampered["computed_at"] = "1999-01-01T00:00:00+00:00"
    assert incident._digest(_stable(tampered)) == pack["digest"]
    # computed_at is present as metadata, outside the hash.
    assert "computed_at" in pack


def test_top_level_shape_and_version_and_schema():
    dep = Deployment.objects.create(name="d", owner=_user())
    f = _finding(dep)
    pack = assemble_incident_pack(f)
    assert set(pack) == _TOP_LEVEL_KEYS
    assert pack["pack_version"] == INCIDENT_PACK_VERSION
    # The documented, machine-readable schema travels as data and is self-describing.
    assert INCIDENT_PACK_SCHEMA["$id"] == INCIDENT_PACK_VERSION
    assert set(INCIDENT_PACK_SCHEMA["required"]) == _TOP_LEVEL_KEYS


def test_altering_evidence_moves_the_pack_digest():
    # Tamper-evident: the reused receipt binds the evidence hashes, so altering one
    # changes the pack digest.
    dep = Deployment.objects.create(name="d", owner=_user())
    f = _finding(dep)
    e = _evidence(f, EvidenceClass.PARTIALLY_VERIFIED, "engine_scan", "a" * 64)
    before = assemble_incident_pack(f)["digest"]
    e.content_hash = "9" * 64
    e.save()
    after = assemble_incident_pack(Finding.objects.prefetch_related("evidence").get(pk=f.pk))["digest"]
    assert before != after


# ---------------------------------------------------------------------------
# Honesty: integrity-not-truth, vendor_asserted preserved
# ---------------------------------------------------------------------------


def test_pack_attests_integrity_not_truth():
    dep = Deployment.objects.create(name="d", owner=_user())
    f = _finding(dep)
    pack = assemble_incident_pack(f)
    # The integrity-not-truth wording is on the wire, not only in the docstring.
    assert pack["attests"] == ATTESTS
    lowered = pack["attests"].lower()
    assert "integrity and provenance" in lowered
    assert "does not attest" in lowered and "true" in lowered
    # Nowhere (outside the disclaimer itself, which legitimately negates them) does
    # the pack make an affirmative security/truth claim.
    without_disclaimer = {k: v for k, v in pack.items() if k != "attests"}
    blob = json.dumps(without_disclaimer).lower()
    for forbidden in ("is secure", "now secure", "is fixed", "conclusion is true", "proven true"):
        assert forbidden not in blob


def test_vendor_asserted_evidence_is_preserved_not_inflated():
    dep = Deployment.objects.create(name="d", owner=_user())
    f = _finding(dep)
    _evidence(f, EvidenceClass.VENDOR_ASSERTED, "vendor_doc", "c" * 64)

    pack = assemble_incident_pack(f)
    ev = pack["evidence"]
    # The class is carried verbatim in the rows and as the honest weakest class.
    assert ev["rows"] == [["vendor_asserted", "vendor_doc", "c" * 64]]
    assert ev["evidence_class"] == EvidenceClass.VENDOR_ASSERTED.value
    assert ev["count"] == 1
    # It is never rewritten to a stronger class.
    assert "technically_verified" not in json.dumps(ev)


def test_evidence_class_is_the_weakest_link_not_the_strongest():
    # A finding with a strong AND a vendor-asserted row reads at its weakest floor.
    dep = Deployment.objects.create(name="d", owner=_user())
    f = _finding(dep)
    _evidence(f, EvidenceClass.TECHNICALLY_VERIFIED, "engine_scan", "1" * 64)
    _evidence(f, EvidenceClass.VENDOR_ASSERTED, "vendor_doc", "2" * 64)

    ev = assemble_incident_pack(f)["evidence"]
    # Honest floor: the weakest class present, never the strongest.
    assert ev["evidence_class"] == EvidenceClass.VENDOR_ASSERTED.value
    # Rows are sorted and independent of insertion order.
    assert ev["rows"] == sorted(ev["rows"])


# ---------------------------------------------------------------------------
# The runtime transcript gap (never fabricated) + engine-pack reference
# ---------------------------------------------------------------------------


def test_runtime_transcript_is_an_explicit_gap_not_fabricated():
    dep = Deployment.objects.create(name="d", owner=_user())
    f = _finding(dep)  # no scan link
    transcript = assemble_incident_pack(f)["runtime_transcript"]

    assert transcript["in_assurance_record"] is False
    assert "engine" in transcript["see"].lower()
    # No invented turns/messages/requests: the gap is stated, not filled.
    for fabricated in ("turns", "messages", "request", "response", "logs", "actions"):
        assert fabricated not in transcript
    # The engine-pack reference is present but honestly unavailable with no scan link.
    ref = transcript["engine_pack_ref"]
    assert ref["available"] is False
    assert ref["scan_uuid"] is None
    assert ref["engine_run_id"] is None


def test_engine_pack_reference_is_carried_when_a_scan_links_the_finding():
    dep = Deployment.objects.create(name="d", owner=_user())
    scan = PentestScan.objects.create(
        target_url="https://example.com", status=PentestScan.STATUS_COMPLETED,
        engine_run_id="run-abc-123",
    )
    f = _finding(dep, scan=scan)

    ref = assemble_incident_pack(f)["runtime_transcript"]["engine_pack_ref"]
    # The linkage that genuinely exists (Finding.scan) is passed through so Achilles
    # can fetch/replay — the scan uuid and the engine's own run id, not invented data.
    assert ref["available"] is True
    assert ref["scan_uuid"] == str(scan.uuid)
    assert ref["engine_run_id"] == "run-abc-123"


# ---------------------------------------------------------------------------
# None-safety
# ---------------------------------------------------------------------------


def test_none_safe_owner_decision_asset_and_evidence():
    # An unowned, undecided deployment with a bare finding: everything reads honestly
    # as None / empty / a gap — never "ready", "secure" or a fabricated value.
    dep = Deployment.objects.create(name="d", owner=None, decision=None)
    f = _finding(dep, asset=None)  # no asset, no evidence, no scan

    pack = assemble_incident_pack(f)
    assert pack["identity"]["deployment"]["owner"] is None
    assert pack["decision"]["decision"] is None
    assert pack["decision"]["decision_label"] is None
    # Surface: no asset is an explicit gap, not a fabricated component.
    assert pack["surface"]["asset"] is None
    assert pack["surface"]["asset_present"] is False
    assert pack["surface"]["location"] is None
    # Evidence: an empty, honest set — class UNKNOWN, never a green default.
    assert pack["evidence"]["rows"] == []
    assert pack["evidence"]["count"] == 0
    assert pack["evidence"]["evidence_class"] == EvidenceClass.UNKNOWN.value
    # Nothing green-by-default anywhere on the wire.
    blob = json.dumps(pack).lower()
    for forbidden in ("passing", "ready\"", "all clear", "healthy"):
        assert forbidden not in blob


def test_decision_is_carried_when_present():
    dep = Deployment.objects.create(
        name="d", owner=_user(), decision=Deployment.Decision.NEEDS_REMEDIATION
    )
    f = _finding(dep)
    dec = assemble_incident_pack(f)["decision"]
    assert dec["decision"] == "needs_remediation"
    assert dec["decision_label"] == "Requires remediation"


# ---------------------------------------------------------------------------
# Surface & identity read straight from the graph
# ---------------------------------------------------------------------------


def test_surface_reads_the_finding_asset_and_identity_verbatim():
    dep = Deployment.objects.create(name="prod-assistant", owner=_user())
    asset = _asset(dep, kind=Asset.Kind.TOOL, name="query-tool", identifier="query-tool")
    f = _finding(
        dep, asset=asset, finding_type="excessive_agency", title="over-broad agent",
        severity="high", location="/v1/chat", control_mapping={"mitre": ["T1190"]},
    )
    pack = assemble_incident_pack(f)

    fid = pack["identity"]["finding"]
    assert fid["category"] == "excessive_agency"  # finding_type carried verbatim
    assert fid["title"] == "over-broad agent"
    assert fid["severity"] == "high"
    assert fid["status"] == "open"
    assert fid["uuid"] == str(f.uuid)
    assert fid["fingerprint"] == f.fingerprint

    surface = pack["surface"]
    assert surface["asset_present"] is True
    assert surface["asset"]["name"] == "query-tool"
    assert surface["asset"]["kind"] == "tool"
    assert surface["location"] == "/v1/chat"
    assert surface["control_mapping"] == {"mitre": ["T1190"]}


# ---------------------------------------------------------------------------
# Ripple / blast-radius is included (reused from assurance.ripple)
# ---------------------------------------------------------------------------


def test_ripple_is_included_for_a_traced_origin_finding():
    dep = Deployment.objects.create(name="d", owner=_user())
    agent = _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant",
                   metadata={"tools": ["query-tool"]})
    _asset(dep, kind=Asset.Kind.TOOL, name="query-tool", identifier="query-tool",
           metadata={"permissions": ["db:read"], "server": "warehouse"})
    _asset(dep, kind=Asset.Kind.DATA_STORE, name="warehouse", identifier="warehouse")
    # An active high finding tied to the agent → the agent is a traced ripple origin.
    f = _finding(dep, asset=agent, severity="high", title="over-broad agent")

    ripple = assemble_incident_pack(f)["ripple"]
    assert ripple["is_traced_origin"] is True
    assert ripple["origins"], "the incident's origin must be included"
    # The evidenced downstream consequence(s) are attributed to this incident.
    assert any(c["target"] == "warehouse" for c in ripple["consequences"])
    assert ripple["deployment_summary"]["origins"] >= 1
    assert ripple["note"] is None


def test_ripple_reads_honestly_when_the_finding_is_not_an_origin():
    # A low-severity finding with no asset is not a traced blast-radius origin. That
    # reads honestly — no invented reach — with the deployment summary as context.
    dep = Deployment.objects.create(name="d", owner=_user())
    f = _finding(dep, asset=None, severity="low", title="informational")

    ripple = assemble_incident_pack(f)["ripple"]
    assert ripple["is_traced_origin"] is False
    assert ripple["origins"] == []
    assert ripple["consequences"] == []
    assert ripple["note"] is not None
    assert "not itself a traced blast-radius origin" in ripple["note"]
    # No "safe"/"contained" verdict slips in on the honest-gap path.
    assert "safe" not in json.dumps(ripple).lower()
    assert "contained" not in json.dumps(ripple).lower()


# ---------------------------------------------------------------------------
# The API endpoint
# ---------------------------------------------------------------------------


def test_incident_pack_endpoint_is_an_open_read_returning_expected_keys():
    analyst = _user("ana", role=User.Roles.ANALYST)
    dep = Deployment.objects.create(name="d", owner=analyst)
    asset = _asset(dep, kind=Asset.Kind.AGENT, name="assistant", identifier="assistant")
    f = _finding(dep, asset=asset, severity="high", title="incident")
    _evidence(f, EvidenceClass.VENDOR_ASSERTED, "vendor_doc", "a" * 64)

    factory = APIRequestFactory()
    view = FindingViewSet.as_view({"get": "incident_pack"})
    req = factory.get(f"/api/assurance/findings/{f.uuid}/incident-pack/")
    force_authenticate(req, user=analyst)
    resp = view(req, uuid=str(f.uuid))

    assert resp.status_code == 200
    assert set(resp.data.keys()) == _TOP_LEVEL_KEYS
    assert resp.data["pack_version"] == INCIDENT_PACK_VERSION
    assert resp.data["identity"]["finding"]["uuid"] == str(f.uuid)
    # The endpoint's pack matches the direct assembly (a computed, unstored read).
    assert resp.data["digest"] == assemble_incident_pack(f)["digest"]


def test_incident_pack_endpoint_requires_authentication():
    dep = Deployment.objects.create(name="d", owner=_user())
    f = _finding(dep)
    factory = APIRequestFactory()
    view = FindingViewSet.as_view({"get": "incident_pack"})
    req = factory.get(f"/api/assurance/findings/{f.uuid}/incident-pack/")
    resp = view(req, uuid=str(f.uuid))
    assert resp.status_code in (401, 403)
