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

from . import observability as obs

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
    """The customer-facing findings in an engine response (internal rows dropped)."""
    return _findings_payload(engine_response)[0]


def _findings_payload(engine_response: Any) -> tuple[list[dict], bool]:
    """The findings, and whether the engine REPORTED a findings list at all.

    Two situations both arrive as an empty list and mean opposite things:

    - the engine reported ``findings: []`` -- it looked and found nothing, which
      is a real result and the best one a customer can get;
    - there is no response, or no findings list in it -- nothing was reported, so
      there is nothing to ingest and no basis to re-score anything.

    Collapsing them is how a clean scan and a missing scan became the same event.
    The flag is what lets the caller tell them apart; the same distinction
    ``PentestScan.derive_verdict`` already draws for the scan's own verdict.
    """
    if not isinstance(engine_response, dict):
        return [], False
    findings = engine_response.get("findings")
    if findings is None:
        findings = engine_response.get("results")
    if not isinstance(findings, list):
        return [], False
    return [f for f in findings if isinstance(f, dict) and not f.get("internal")], True


# The ``coverage`` key on an engine response carries TWO independent statements,
# and neither implies the other:
#
#   coverage.assessed   which COMPONENTS the engine says it assessed, read by
#                       `_reported_coverage` below and stamped onto assets
#   coverage.checks     which CHECKS the engine ran, read by `_reported_checks`
#                       and stored on the deployment
#
# An engine may report either, both or neither. Athena reports checks and not
# components (it has no component model of its own); an engine that enumerates
# components may report those and not checks. Both readers therefore tolerate the
# other's absence, and absence always means "did not say" -- never "all of it".
#
# Written down here because the two arrived years apart and a reader finding one
# of them would reasonably assume it was the whole contract.


def _reported_coverage(engine_response: Any) -> tuple[list[dict], str]:
    """The components an engine says it assessed, and what it calls itself.

    Read from ``coverage: {assessed: [...], engine: "..."}`` on the engine
    response. Absent or malformed means nothing was reported -- never "everything
    was assessed", which is the reading that would make the whole manifest
    decorative.
    """
    if not isinstance(engine_response, dict):
        return [], ""
    coverage = engine_response.get("coverage")
    if not isinstance(coverage, dict):
        return [], ""
    assessed = coverage.get("assessed")
    if not isinstance(assessed, list):
        return [], ""
    engine = str(coverage.get("engine") or "").strip()
    return [row for row in assessed if isinstance(row, dict)], engine


def _record_reported_coverage(scan, deployment) -> int:
    """Stamp the deployment's assets that this scan reported assessing."""
    from .coverage import _component_key, record_assessment

    reported, engine = _reported_coverage(scan.engine_response)
    if not reported:
        return 0
    wanted = {
        _component_key(row.get("kind", ""), row.get("name", ""), row.get("identifier", ""))
        for row in reported
    }
    matched = [
        asset
        for asset in deployment.assets.all()
        if _component_key(asset.kind, asset.name, asset.identifier) in wanted
    ]
    # An engine that does not name itself still assessed something, and recording
    # the coverage without the assessor is better than dropping it -- but the
    # placeholder says plainly that the assessor is unknown rather than guessing one.
    return record_assessment(matched, assessed_by=engine or "unnamed engine")


def _reported_checks(engine_response: Any) -> dict:
    """The engine's statement of which checks it ran, or ``{}``.

    Read from ``coverage.checks`` on the engine response -- a list of rows, each
    naming a check and its state. Validated only as far as "is this the shape the
    manifest promises": a payload that is not is discarded whole rather than
    half-read, because a partial coverage claim is worse than none.

    ``{}`` means the engine did not say. It never means every check ran.

    A row this side cannot interpret is KEPT, not dropped. The per-row filter that
    used to stand here was itself the half-read the docstring above warns against,
    and it failed in the worst available direction: a row spelling ``status``
    instead of ``state`` was deleted, and the denominator shrank with it, so two
    never-run checks became a manifest of two performed checks out of two and a
    receipt attesting ``checks_complete: true``. The engine is a separate
    deployable on its own release cycle; a key it renames must cap the decision,
    not clear it.
    """
    if not isinstance(engine_response, dict):
        return {}
    coverage = engine_response.get("coverage")
    if not isinstance(coverage, dict):
        return {}
    checks = coverage.get("checks")
    if not isinstance(checks, list) or not checks:
        return {}
    rows = []
    # Rows with nothing this side can even name. Counted, because a row that
    # arrived and could not be read is a check whose outcome is unknown, and
    # unknown must reach the denominator; not named, because there is no name.
    unreadable = 0
    for row in checks:
        if isinstance(row, dict) and row.get("check"):
            rows.append(row)
        else:
            unreadable += 1
    if not rows and not unreadable:
        return {}
    return {
        "checks": rows,
        "unreadable": unreadable,
        # Recomputed from the rows rather than trusted from the payload: the
        # engine's own summary lists are a convenience, and a manifest whose
        # summary disagreed with its rows would be read by the summary.
        "not_performed": sorted(
            {r["check"] for r in rows if r.get("state") == "not_performed"}
        ),
        "degraded": sorted({r["check"] for r in rows if r.get("state") == "degraded"}),
        "unmeasured": sorted({r["check"] for r in rows if r.get("state") == "unmeasured"}),
        "performed": sorted({r["check"] for r in rows if r.get("state") == "performed"}),
        "limitations": (
            coverage["limitations"]
            if isinstance(coverage.get("limitations"), dict) else {}
        ),
        "notes": [n for n in (coverage.get("notes") or []) if isinstance(n, str)],
    }


def _record_reported_checks(scan, deployment) -> bool:
    """Store the latest scan's check coverage on the deployment. True if stored.

    Latest wins, and only a scan that said something overwrites one that did. An
    engine that reports nothing must not erase what a previous engine reported,
    because the decision reads this and silence would quietly lift the cap.
    """
    reported = _reported_checks(scan.engine_response)
    if not reported:
        return False
    deployment.check_coverage = reported
    deployment.check_coverage_at = timezone.now()
    deployment.save(update_fields=["check_coverage", "check_coverage_at", "updated_at"])
    return True


def _scan_was_incomplete(scan) -> bool:
    """Did the engine stop this scan before it finished?

    Asks the scan model, which owns the marker's spelling, so the ingest and the
    scan's own verdict can never disagree about whether a run finished. A scan
    object without the classmethod (a stub in a caller's test) reads as complete,
    which is the pre-existing behaviour and never worse than it."""
    checker = getattr(type(scan), "scan_was_incomplete", None)
    if checker is None:
        return False
    return bool(checker(scan.engine_response))


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

    Returns the findings created or updated. A scan with no dict response and no
    findings list yields an empty list and changes nothing (it never fabricates a
    clean bill). A scan that REPORTED zero findings is a real result and is
    ingested in full -- assets, unknowns and the decision are all refreshed --
    because a clean scan that leaves the register and the decision untouched is
    indistinguishable from a scan that never arrived. Safe to call more than once
    for the same scan."""
    raw_findings, reported = _findings_payload(scan.engine_response)
    if not reported:
        return []

    deployment = deployment or deployment_for_scan(scan)

    # The parent of every span below, so an ingest reads as one tree rather than a
    # pile of timings. Entered after the nothing-reported return above, so an
    # ingest of a response that carried no result is not recorded as work: a
    # near-zero sample would drag the p50 down and make the pipeline look faster
    # than it is. A reported-zero scan DOES do the work below, and is timed.
    with obs.span(
        obs.INVOKE_WORKFLOW,
        component="ingest_scan",
        subject=str(deployment.pk),
        attributes={"mythos.raw_findings": len(raw_findings)},
    ):
        return _ingest_findings(scan, deployment, raw_findings)


def _ingest_findings(scan, deployment, raw_findings) -> list[Finding]:
    """The body of :func:`ingest_scan`, lifted out so the workflow span wraps it.

    Extracted rather than re-indented in place: a re-indent would have rewritten
    every line of a function that ingests customer findings, and a reviewer could
    not have told the tracing change from a logic change in that diff.
    """
    now = timezone.now()
    results: list[Finding] = []

    for f in raw_findings:
        finding_type = str(f.get("type") or "finding").strip() or "finding"
        fingerprint = _fingerprint(deployment, _dedup_basis(f, finding_type))
        severity = _finding_severity(f)
        # No default. An engine that reported no confidence, or something that is
        # not a number, has told us it does not know -- and 0.5 would put a figure
        # nobody computed into every report, indistinguishable from a real 0.5 a
        # detector measured. Null means not known.
        raw_confidence = f.get("confidence")
        if raw_confidence is None:
            confidence = None
        else:
            try:
                confidence = float(raw_confidence)
            except (TypeError, ValueError):
                confidence = None

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

    # Populate the assurance graph's nodes — the deployment's assets — from what
    # the scan honestly knows (host, scope, declared LLM target), and attach each
    # finding to the asset it concerns (Phase 1.1).
    from .assets import derive_assets

    with obs.span(
        obs.RETRIEVAL,
        component="derive_assets",
        subject=str(deployment.pk),
        attributes={obs.GEN_AI_TOOL_NAME: "derive_assets"},
    ):
        derive_assets(deployment, scan)

    # Record what this scan actually ASSESSED, from the engine's own report of it.
    # Only from that report: nothing here infers assessment from an asset existing,
    # from a scan having run, or from the absence of a finding, because each of
    # those would put a component in the Assessed column that nothing tested. An
    # engine that reports no coverage leaves every asset unassessed, which is the
    # honest reading and is what the Coverage Manifest then says out loud.
    _record_reported_coverage(scan, deployment)

    # And what it actually ASKED. The two are independent: an engine can assess
    # every component while never running whole checks against them, and the
    # asset column cannot show that.
    _record_reported_checks(scan, deployment)

    # Turn every "we couldn't verify this" into a managed gap before we score the
    # deployment, so the Unknowns Register is current alongside the findings
    # (Phase 0.4).
    from .unknowns import derive_unknowns

    with obs.span(obs.PLAN, component="derive_unknowns", subject=str(deployment.pk)):
        derive_unknowns(deployment)

    # Whether the evidence this decision will rest on is complete. The engine
    # marks a run it stopped early with an internal `scan_incomplete` row, and
    # every consumer here filters internal rows out -- so without this, a scan the
    # operator stopped and a scan that found nothing produce the same READY.
    # Recorded on the deployment (not passed to the call below) so a recompute
    # from anywhere else cannot quietly restore the clean answer, and cleared by
    # the first scan that runs to completion.
    incomplete = _scan_was_incomplete(scan)
    changed = []
    if deployment.evidence_incomplete != incomplete:
        deployment.evidence_incomplete = incomplete
        changed.append("evidence_incomplete")
    if not incomplete:
        # A scan that ran to completion is an assessment even with nothing to
        # report, and this is the fact that says so. Without it a deployment
        # scanned clean has no findings and therefore no decision -- the same
        # answer as a deployment nobody has scanned at all.
        deployment.last_complete_scan_at = now
        changed.append("last_complete_scan_at")
    if changed:
        deployment.save(update_fields=[*changed, "updated_at"])

    # A scan culminates in a decision, not just a finding list: refresh the
    # deployment's six-state decision from its now-current findings (Phase 0.5).
    # A deployment an operator has PAUSED via the failsafe is left paused — an
    # automated re-ingest must not silently clear a human's stop.
    if deployment.decision != Deployment.Decision.PAUSED:
        from .decision import recompute_decision

        with obs.span(
            obs.PLAN, component="recompute_decision", subject=str(deployment.pk)
        ) as active:
            recompute_decision(deployment)
            if active is not None:
                active.set_attribute(obs.MYTHOS_VERDICT, str(deployment.decision))

    return results
