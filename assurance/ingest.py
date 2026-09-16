"""Ingest a completed scan's engine response into structured assurance rows.

The CyberEngine returns findings as a list of dicts inside
``PentestScan.engine_response``. This module is the one place that turns that raw
JSON into durable, queryable :class:`~assurance.models.Finding` rows (with graded
:class:`~assurance.models.Evidence`) under a :class:`~assurance.models.Deployment`
— making the control-plane the system of record.

It is **idempotent**: a finding is keyed within its deployment by a fingerprint
(type + location), so re-ingesting the same scan, or re-scanning the same system,
updates the finding and its ``last_seen`` rather than duplicating it. Human-set
fields (status, owner) are never clobbered by a re-ingest — that is what makes a
finding trackable across scans and is the basis for retest and change
intelligence. Nothing here reaches the network; it only reads a stored response.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

from django.utils import timezone

from .models import (
    SEVERITY_INFO,
    Deployment,
    Evidence,
    EvidenceClass,
    Finding,
    severity_rank,
)


def _finding_severity(f: dict) -> str:
    """Same precedence the report renderer and the scan verdict use, so a badge,
    a PDF, and a Finding row never disagree."""
    s = f.get("report_severity") or f.get("signature_severity") or f.get("severity") or "info"
    return str(s).strip().lower()


def _finding_location(f: dict) -> str:
    """A stable location string for dedup: the endpoint/parameter the finding was
    observed at, else the evidence's attack/step ids, else empty."""
    for key in ("location", "endpoint", "url", "path", "parameter", "param"):
        val = f.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    ev = f.get("evidence")
    if isinstance(ev, dict):
        for key in ("endpoint", "url", "location", "attack_id", "step_id"):
            val = ev.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()
    return ""


def _fingerprint(deployment: Deployment, finding_type: str, location: str) -> str:
    raw = f"{deployment.pk}|{finding_type.strip().lower()}|{location.strip().lower()}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _content_hash(f: dict) -> str:
    return hashlib.sha256(json.dumps(f, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _title(f: dict, finding_type: str) -> str:
    for key in ("title", "name", "summary"):
        val = f.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()[:512]
    # Humanise the type as a fallback title.
    return finding_type.replace("_", " ").strip().title()[:512] or "Finding"


def _control_mapping(f: dict) -> dict[str, Any]:
    mapping = f.get("control_mapping")
    if isinstance(mapping, dict):
        return mapping
    out: dict[str, Any] = {}
    for key in ("mitre", "mitre_attack", "cwe", "owasp"):
        val = f.get(key)
        if val:
            out[key.replace("_attack", "")] = val
    return out


def _classify_evidence(f: dict) -> str:
    """How strongly an engine finding is known.

    An exploit-like finding a scan actually confirmed against the live target is
    technically verified; a suspicious/low-strength one is only partially
    verified; a purely informational (non-exploit) observation is configuration
    verified. This is the evidence taxonomy as data, not a display string."""
    tier = str(f.get("tier") or "").strip().lower()
    exploit_like = bool(f.get("exploit_like"))
    if exploit_like and tier in ("confirmed", "likely"):
        return EvidenceClass.TECHNICALLY_VERIFIED
    if exploit_like:
        return EvidenceClass.PARTIALLY_VERIFIED
    if _finding_severity(f) == SEVERITY_INFO:
        return EvidenceClass.CONFIGURATION_VERIFIED
    return EvidenceClass.PARTIALLY_VERIFIED


def _findings_list(engine_response: Any) -> list[dict]:
    if not isinstance(engine_response, dict):
        return []
    findings = engine_response.get("findings")
    if findings is None:
        findings = engine_response.get("results")
    if not isinstance(findings, list):
        return []
    return [f for f in findings if isinstance(f, dict) and not f.get("internal")]


def deployment_for_scan(scan) -> Deployment:
    """Get or create the deployment a scan's findings belong to.

    Reuses the scan's engagement as the deployment identity when there is one (so
    every scan of the same engagement lands on the same deployment); otherwise
    keys a deployment by the scan's target URL. Idempotent."""
    if scan.engagement_id:
        name = (
            getattr(scan.engagement, "name", None)
            or getattr(scan.engagement, "client_name", None)
            or f"Engagement {scan.engagement_id}"
        )
        deployment, _ = Deployment.objects.get_or_create(
            engagement_id=scan.engagement_id,
            defaults={"name": name, "owner_id": getattr(scan, "user_id", None)},
        )
        return deployment
    deployment, _ = Deployment.objects.get_or_create(
        name=f"target:{scan.target_url}",
        engagement__isnull=True,
        defaults={"owner_id": getattr(scan, "user_id", None)},
    )
    return deployment


def ingest_scan(scan, *, deployment: Deployment | None = None) -> list[Finding]:
    """Ingest a completed scan into structured Finding + Evidence rows.

    Returns the findings created or updated. A scan with no dict response or no
    findings list yields an empty list (and never fabricates a clean bill). Safe
    to call more than once for the same scan."""
    raw_findings = _findings_list(scan.engine_response)
    if not raw_findings:
        return []

    deployment = deployment or deployment_for_scan(scan)
    now = timezone.now()
    results: list[Finding] = []

    for f in raw_findings:
        finding_type = str(f.get("type") or "finding").strip() or "finding"
        location = _finding_location(f)
        fingerprint = _fingerprint(deployment, finding_type, location)
        severity = _finding_severity(f)
        try:
            confidence = float(f.get("confidence", 0.5))
        except (TypeError, ValueError):
            confidence = 0.5

        # Fields refreshed on every ingest (the engine's current truth).
        engine_fields = {
            "scan": scan,
            "finding_type": finding_type,
            "title": _title(f, finding_type),
            "severity": severity,
            "confidence": confidence,
            "cvss_score": f.get("cvss_score"),
            "cvss_vector": str(f.get("cvss_vector") or "")[:128],
            "impact": str(f.get("impact") or ""),
            "recommendation": str(f.get("recommendation") or ""),
            "control_mapping": _control_mapping(f),
            "location": location[:1024],
            "retest_required": severity_rank(severity) >= severity_rank("medium"),
            "raw": f,
            "last_seen": now,
        }

        finding, created = Finding.objects.get_or_create(
            deployment=deployment,
            fingerprint=fingerprint,
            defaults={**engine_fields, "first_seen": now},
        )
        if not created:
            # Refresh the engine-owned fields; never touch human-set status/owner.
            for key, value in engine_fields.items():
                setattr(finding, key, value)
            finding.save(update_fields=[*engine_fields.keys()])

        # One graded evidence row per finding from the scan, kept in step.
        Evidence.objects.update_or_create(
            finding=finding,
            source="engine_scan",
            defaults={
                "classification": _classify_evidence(f),
                "summary": f"Observed by scan {scan.pk} ({finding_type}).",
                "content_hash": _content_hash(f),
                "raw": {"tier": f.get("tier"), "exploit_like": f.get("exploit_like")},
            },
        )
        results.append(finding)

    return results
