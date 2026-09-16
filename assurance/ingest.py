"""Ingest a completed scan's engine response into structured assurance rows.

The CyberEngine returns findings as a list of dicts inside
``PentestScan.engine_response``. This module is the one place that turns that raw
JSON into durable, queryable :class:`~assurance.models.Finding` rows (with graded
:class:`~assurance.models.Evidence`) under a :class:`~assurance.models.Deployment`
— making the control-plane the system of record.

It is **idempotent**: a finding is keyed within its deployment by a fingerprint —
the engine's stable ``signature_id`` when it carries one, else the finding's type
plus a hash of its descriptive text — so re-ingesting the same scan, or
re-scanning the same system, updates the finding and its ``last_seen`` rather
than duplicating it. Human-set fields (status, owner) are never clobbered by a
re-ingest — that is what makes a finding trackable across scans and is the basis
for retest and change intelligence. Nothing here reaches the network; it only
reads a stored response.

The field vocabulary this reads is the engine's own, the same keys the PDF
renderer (``pentest/report_mythos.py``) and the scan verdict read: findings under
``results`` (or ``findings``); ``report_severity``/``signature_severity``/
``severity``; ``signature_description``/``message``/``details`` for the human
title; ``signature_recommendation``/``autofix_summary`` for the fix;
``explanation`` for impact; ``signature_id`` for the stable identity; and
``cvss_score``/``cvss_vector``/``confidence``.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any
from urllib.parse import urlparse

from django.utils import timezone

from .models import (
    SEVERITY_INFO,
    SEVERITY_ORDER,
    Deployment,
    Evidence,
    EvidenceClass,
    Finding,
    severity_rank,
)

# Engine / renderer severity synonyms → the canonical vocabulary. Anything still
# unrecognised after this falls to ``info`` — matching the PDF renderer's own
# ``_sev_of`` — so an assurance row never holds a value outside SEVERITY_ORDER.
_SEVERITY_ALIASES = {
    "informational": SEVERITY_INFO,
    "information": SEVERITY_INFO,
    "none": SEVERITY_INFO,
    "unknown": SEVERITY_INFO,
    "moderate": "medium",
    "warning": "low",
    "warn": "low",
}


def _finding_severity(f: dict) -> str:
    """Same precedence the report renderer and the scan verdict use, so a badge,
    a PDF, and a Finding row never disagree — normalised into SEVERITY_ORDER so an
    unrecognised label can never be stored verbatim and silently rank as info."""
    s = f.get("report_severity") or f.get("signature_severity") or f.get("severity") or "info"
    s = str(s).strip().lower()
    if s in SEVERITY_ORDER:
        return s
    return _SEVERITY_ALIASES.get(s, SEVERITY_INFO)


def _signature_id(f: dict) -> str:
    val = f.get("signature_id")
    return str(val).strip() if val not in (None, "") else ""


def _descriptor(f: dict) -> str:
    """The engine's human-readable description, used both as a title and — when
    there is no ``signature_id`` — to keep two distinct findings of the same type
    from colliding on the dedup key."""
    for key in ("signature_description", "message", "details", "title", "name", "summary"):
        val = f.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _dedup_basis(f: dict, finding_type: str) -> str:
    """The stable per-finding identity within a deployment.

    Prefers the engine's ``signature_id`` (stable across re-scans and unique per
    signature). Absent that, falls back to the finding type plus its descriptor,
    so two findings of the same type but different substance (e.g. two distinct
    misconfigurations) do not collide onto one row and overwrite each other."""
    sig = _signature_id(f)
    if sig:
        return f"sig:{sig.lower()}"
    return f"type:{finding_type.strip().lower()}|{_descriptor(f).strip().lower()}"


def _fingerprint(deployment: Deployment, basis: str) -> str:
    return hashlib.sha256(f"{deployment.pk}|{basis}".encode("utf-8")).hexdigest()


def _content_hash(f: dict) -> str:
    return hashlib.sha256(json.dumps(f, sort_keys=True, default=str).encode("utf-8")).hexdigest()


def _title(f: dict, finding_type: str) -> str:
    desc = _descriptor(f)
    if desc:
        return desc[:512]
    # Humanise the type as a fallback title.
    return finding_type.replace("_", " ").strip().title()[:512] or "Finding"


def _finding_location(f: dict) -> str:
    """Where the finding was observed, when the engine names it. Signature scans
    today rarely carry a per-instance location (dedup leans on ``signature_id``
    instead), but the column is populated when a location *is* present so a future
    per-endpoint engine needs no ingest change."""
    for key in ("location", "endpoint", "url", "path", "parameter", "param"):
        val = f.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _recommendation(f: dict) -> str:
    """The fix, in the engine's own vocabulary."""
    for key in ("signature_recommendation", "autofix_summary", "recommendation", "message"):
        val = f.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _impact(f: dict) -> str:
    """The technical consequence — the engine carries it as ``explanation``."""
    for key in ("explanation", "impact"):
        val = f.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


def _cvss_score(f: dict) -> float | None:
    """Parse the CVSS score defensively. A non-numeric value ("N/A", a list) must
    not raise on ``.save()`` and abort ingestion of the whole scan — it is simply
    absent."""
    val = f.get("cvss_score")
    if val in (None, ""):
        return None
    try:
        return float(val)
    except (TypeError, ValueError):
        return None


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

    The engine is a signature scanner: it observes a signal, it does not prove an
    exploit. So a substantive (non-info) finding is **partially verified** — the
    scanner saw something, but "is it real, and how bad?" is still open — while a
    purely informational configuration observation is **configuration verified**.
    ``technically_verified`` is deliberately not reachable from a passive scan; it
    is reserved for a conclusion something actually confirmed (a live exploit, a
    human), and if the engine ever emits such a confirmation signal this is where
    it is promoted. This keeps the taxonomy honest rather than dressing a
    signature hit up as proof."""
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


def _host(target_url: str) -> str:
    """The host a scan's target names, or "" if it names none. Survives a bare
    hostname as well as a full URL — the same normalisation the scan-launch path
    uses — so a deployment's identity does not hinge on the scheme somebody typed."""
    raw = (target_url or "").strip()
    if not raw:
        return ""
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        return (parsed.hostname or "").lower()
    except ValueError:
        return ""


def deployment_for_scan(scan) -> Deployment:
    """Get or create the deployment a scan's findings belong to.

    A deployment is *one system in one environment*, so its identity is the
    engagement **and the target host** — not the engagement alone. An engagement's
    scope can authorise several distinct hosts, and collapsing them onto one
    Deployment would blend unrelated systems' findings, gaps, and the single
    six-state decision. Keying on (engagement, host) keeps ``api.example.com`` and
    ``admin.example.com`` separate while a re-scan of the same host lands on the
    same row. Idempotent."""
    host = _host(scan.target_url)
    owner_id = getattr(scan, "user_id", None)
    if scan.engagement_id:
        base = (
            getattr(scan.engagement, "name", None)
            or getattr(scan.engagement, "client_name", None)
            or f"Engagement {scan.engagement_id}"
        )
        name = f"{base} · {host}" if host else base
        deployment, _ = Deployment.objects.get_or_create(
            engagement_id=scan.engagement_id,
            name=name,
            defaults={"owner_id": owner_id},
        )
        return deployment
    deployment, _ = Deployment.objects.get_or_create(
        name=f"target:{host or scan.target_url}",
        engagement__isnull=True,
        defaults={"owner_id": owner_id},
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
        fingerprint = _fingerprint(deployment, _dedup_basis(f, finding_type))
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
            "cvss_score": _cvss_score(f),
            "cvss_vector": str(f.get("cvss_vector") or "")[:128],
            "impact": _impact(f),
            "recommendation": _recommendation(f),
            "control_mapping": _control_mapping(f),
            "location": _finding_location(f)[:1024],
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
                "raw": {
                    "signature_id": _signature_id(f) or None,
                    "confidence": f.get("confidence"),
                    "detector_measurement": f.get("detector_measurement"),
                },
            },
        )
        results.append(finding)

    # Turn every "we couldn't verify this" into a managed gap before we score the
    # deployment, so the Unknowns Register is current alongside the findings
    # (Phase 0.4).
    from .unknowns import derive_unknowns

    derive_unknowns(deployment)

    # A scan culminates in a decision, not just a finding list: refresh the
    # deployment's six-state decision from its now-current findings (Phase 0.5).
    # A deployment an operator has PAUSED via the failsafe is left paused — an
    # automated re-ingest must not silently clear a human's stop.
    if deployment.decision != Deployment.Decision.PAUSED:
        from .decision import recompute_decision

        recompute_decision(deployment)

    return results
