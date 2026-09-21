"""Declared-vs-observed AI-BOM drift — SPINE Stage 3.

The AI-BOM (:func:`assurance.bom.build_ai_bom`) enumerates the **observed**
architecture: every component discovery actually found. A
:class:`~assurance.models.DeclaredComponent` is what the customer **declares** the
system is. This module compares the two and computes **drift** — the gap between
declared and observed — because that gap is exactly where assurance quietly rots:

    Declared: 3 tools, 1 provider, 1 MCP server.
    Observed: 5 tools, a fallback provider, 3 MCP servers.

Two honest outputs come from that comparison:

- :func:`assess_bom_drift` — a pure, read-only assessment: what was declared, what
  is observed, and every point they disagree (undeclared/shadow components and
  providers the customer never declared; declared components no longer observed).
- :func:`record_bom_drift_findings` — turns that drift into managed
  :class:`~assurance.models.Finding` rows, **idempotently** and non-destructively
  (the same discipline :func:`assurance.unknowns.derive_unknowns` keeps): a
  re-record refreshes the machine fields rather than duplicating, a drift that
  clears auto-closes its finding, and a drift that returns re-opens a
  machine-closed finding — while a human's disposition is never clobbered.

The drift also feeds the claims engine: the AI_BOM deriver
(:func:`assurance.claims._derive_ai_bom`) consults :func:`assess_bom_drift`, and an
undeclared component **contradicts** the "the BOM enumerates the full supply chain"
claim — the deferred CONTRADICTED path the Phase 1 deriver left for this stage.
That contradiction is the invalidation: via Stage 1C it lowers the deployment
decision, and via Stage 1D it lands in the revalidation plan.

Honesty is load-bearing: **without a declared baseline there is no drift to
compute** (``has_declared`` is False), and the assessment says so rather than
reading "no drift" as a pass — you cannot confirm a BOM is complete against a
declaration that does not exist. The declared architecture is a *separate axis*
from the observed system state, so it is deliberately NOT part of the system
fingerprint: declaring or amending the architecture is not itself a change to what
is running.
"""

from __future__ import annotations

import hashlib

from django.utils import timezone

from .models import RESOLVED_FINDING_STATUSES, Asset, Deployment, Finding

# The severity an UNDECLARED (shadow) observed component carries, by kind. A
# component the customer never declared is real supply chain nobody approved; the
# blast radius differs by what it is — a model, MCP server, gateway, service
# account, or agent can act or route on its own (high); a tool/skill/api/store is
# a capability surface (medium); anything else is low. An undeclared *provider*
# (a whole vendor nobody declared, e.g. a fallback) is always high.
_UNDECLARED_SEVERITY_BY_KIND = {
    Asset.Kind.MODEL.value: "high",
    Asset.Kind.MCP_SERVER.value: "high",
    Asset.Kind.GATEWAY.value: "high",
    Asset.Kind.SERVICE_ACCOUNT.value: "high",
    Asset.Kind.AGENT.value: "high",
    Asset.Kind.TOOL.value: "medium",
    Asset.Kind.SKILL.value: "medium",
    Asset.Kind.API.value: "medium",
    Asset.Kind.VECTOR_DB.value: "medium",
    Asset.Kind.DATA_STORE.value: "medium",
    Asset.Kind.OTHER.value: "low",
}
_UNDECLARED_PROVIDER_SEVERITY = "high"
# A declared component no longer observed is a softer signal (retired, renamed, or
# simply not discovered this pass) — surfaced, but low: it does not, by itself,
# mean the running system is unsafe.
_MISSING_SEVERITY = "low"

# The finding types this module owns. The stale-sweep and the claim deriver key
# off this prefix, so every machine-managed drift finding starts with it.
_FINDING_PREFIX = "bom_drift."
_UNDECLARED_COMPONENT = "bom_drift.undeclared_component"
_UNDECLARED_PROVIDER = "bom_drift.undeclared_provider"
_DECLARED_NOT_OBSERVED = "bom_drift.declared_not_observed"



def _norm(value: str) -> str:
    return (value or "").strip().lower()


def _match_key(kind: str, identifier: str, name: str) -> tuple[str, str]:
    """The identity a declared and an observed component match on: kind plus the
    normalized identifier, falling back to the normalized name when no identifier
    was given. The same rule for both sides, so they line up."""
    return (kind, _norm(identifier) or _norm(name))


def _fp(*parts: str) -> str:
    """A stable drift-finding fingerprint (deployment-scoped dedup key)."""
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# The pure assessment
# ---------------------------------------------------------------------------


def assess_bom_drift(deployment) -> dict:
    """Compare the deployment's declared architecture against its observed AI-BOM.

    Pure and read-only. Returns the declared and observed inventories, and every
    point they disagree:

    - ``undeclared`` — observed components with no matching declaration (shadow
      supply chain); each carries a severity by kind.
    - ``undeclared_providers`` — vendors behind observed components that the
      customer never declared (a fallback provider, an unexpected model host).
    - ``missing`` — declared components not observed this pass (low: retired,
      renamed, or undiscovered).

    ``has_declared`` is False when no declaration exists — there is then no drift
    to compute, and this is NOT a pass. ``drift_detected`` is True only when an
    undeclared component or provider exists (the signal that the BOM does not
    enumerate the full supply chain). Prefetch ``assets__provider`` on the caller
    side to keep it query-light.
    """
    declared = list(deployment.declared_components.all())
    assets = list(deployment.assets.all())

    declared_index = {_match_key(d.kind, d.identifier, d.name): d for d in declared}
    observed_index = {_match_key(a.kind, a.identifier, a.name): a for a in assets}

    # Observed components with no matching declaration — the shadow supply chain.
    undeclared = []
    for key, asset in observed_index.items():
        if key in declared_index:
            continue
        undeclared.append(
            {
                "asset_uuid": str(asset.uuid),
                "kind": asset.kind,
                "kind_label": asset.get_kind_display(),
                "name": asset.name,
                "identifier": asset.identifier,
                "provider_name": asset.provider.name if asset.provider else None,
                "severity": _UNDECLARED_SEVERITY_BY_KIND.get(asset.kind, "low"),
            }
        )
    undeclared.sort(key=lambda c: (c["kind"], c["name"]))

    # Declarations with no matching observed component.
    missing = []
    for key, comp in declared_index.items():
        if key in observed_index:
            continue
        missing.append(
            {
                "declared_uuid": str(comp.uuid),
                "kind": comp.kind,
                "kind_label": comp.get_kind_display(),
                "name": comp.name,
                "identifier": comp.identifier,
                "provider_name": comp.provider_name or None,
            }
        )
    missing.sort(key=lambda c: (c["kind"], c["name"]))

    # Provider-level drift: vendors behind observed components that were never
    # declared. Declared provider names come from the declarations' provider_name.
    declared_providers = {_norm(d.provider_name) for d in declared if d.provider_name}
    observed_providers: dict[str, str] = {}
    for asset in assets:
        if asset.provider is not None:
            observed_providers.setdefault(_norm(asset.provider.name), asset.provider.name)
    undeclared_providers = sorted(
        name for norm, name in observed_providers.items() if norm not in declared_providers
    )
    # If the customer declared no providers at all, we cannot single out a vendor
    # as "undeclared" — that is the whole-BOM UNKNOWN case, handled by has_declared.
    if not declared_providers:
        undeclared_providers = []

    matched_count = sum(1 for key in observed_index if key in declared_index)
    has_declared = bool(declared)
    drift_detected = has_declared and bool(undeclared or undeclared_providers)

    if not has_declared:
        note = (
            "No declared architecture: drift cannot be computed. Declare the expected "
            "components to assess whether the observed BOM matches — an absent declaration "
            "is not a clean bill of materials."
        )
    elif drift_detected:
        bits = []
        if undeclared:
            bits.append(f"{len(undeclared)} undeclared component(s)")
        if undeclared_providers:
            bits.append(f"{len(undeclared_providers)} undeclared provider(s)")
        note = (
            "Observed architecture drifts from the declaration: "
            + ", ".join(bits)
            + ". The declared bill of materials does not enumerate the full observed supply chain."
        )
    else:
        note = (
            f"Observed architecture matches the declaration ({matched_count} component(s)); "
            "no undeclared component or provider. Declared components not observed are listed "
            "separately and do not, by themselves, indicate an unsafe system."
        )

    return {
        "deployment_uuid": str(deployment.uuid),
        "has_declared": has_declared,
        "drift_detected": drift_detected,
        "summary": {
            "declared_count": len(declared),
            "observed_count": len(assets),
            "matched": matched_count,
            "undeclared": len(undeclared),
            "undeclared_providers": len(undeclared_providers),
            "missing": len(missing),
        },
        "undeclared": undeclared,
        "undeclared_providers": undeclared_providers,
        "missing": missing,
        "note": note,
    }


# ---------------------------------------------------------------------------
# Turning drift into managed findings (idempotent, non-destructive)
# ---------------------------------------------------------------------------


def _reconcile_finding(deployment, *, fingerprint, finding_type, title, severity, location, asset, drift, now) -> str:
    """Create or refresh one machine-managed drift finding. Returns
    ``"created"`` / ``"updated"`` / ``"reopened"``. Never clobbers a human
    disposition."""
    raw = {"machine_managed": True, "auto_resolved": False, "drift": drift}
    machine_fields = {
        "finding_type": finding_type,
        "title": title,
        "severity": severity,
        "location": location,
        "asset": asset,
        "last_seen": now,
        "raw": raw,
    }
    finding, created = Finding.objects.get_or_create(
        deployment=deployment,
        fingerprint=fingerprint,
        defaults={**machine_fields, "confidence": 0.9, "first_seen": now},
    )
    if created:
        return "created"

    # Read the prior state BEFORE the refresh overwrites ``raw``: a drift the
    # *machine* auto-closed (CLOSED with auto_resolved set) has returned and must
    # re-open. A human's disposition (accepted, false-positive, or a manual close
    # with no auto_resolved marker) is left untouched.
    was_auto_closed = finding.status == Finding.Status.CLOSED and bool(
        (finding.raw or {}).get("auto_resolved")
    )
    outcome = "updated"
    for key, value in machine_fields.items():
        setattr(finding, key, value)
    fields = [*machine_fields.keys(), "updated_at"]
    if was_auto_closed:
        finding.status = Finding.Status.OPEN
        fields.append("status")
        outcome = "reopened"
    finding.save(update_fields=fields)
    return outcome


def record_bom_drift_findings(deployment) -> dict:
    """Reconcile the deployment's BOM-drift findings with its current drift.

    For every undeclared component, undeclared provider, and declared-but-missing
    component, create or refresh a managed finding; auto-close the drift findings
    whose drift has cleared. Idempotent and non-destructive — a re-record opens no
    duplicates and never overrides a human's disposition. Returns
    ``{created, updated, reopened, resolved, drift_detected}``.

    When there is no declared architecture, nothing is recorded (there is no drift
    to record) — the absence is surfaced by :func:`assess_bom_drift`, not written
    as findings.
    """
    now = timezone.now()
    dep = Deployment.objects.prefetch_related("assets__provider", "declared_components").get(
        pk=deployment.pk
    )
    assessment = assess_bom_drift(dep)

    counts = {"created": 0, "updated": 0, "reopened": 0, "resolved": 0}
    live: set[str] = set()

    # Assets by uuid, so an undeclared-component finding can attach to the real row.
    assets_by_uuid = {str(a.uuid): a for a in dep.assets.all()}

    for comp in assessment["undeclared"]:
        fingerprint = _fp(_UNDECLARED_COMPONENT, comp["kind"], _norm(comp["identifier"]) or _norm(comp["name"]))
        live.add(fingerprint)
        outcome = _reconcile_finding(
            dep,
            fingerprint=fingerprint,
            finding_type=_UNDECLARED_COMPONENT,
            title=f"Undeclared {comp['kind_label'].lower()} in the AI-BOM: {comp['name']}",
            severity=comp["severity"],
            location=comp["identifier"] or comp["name"],
            asset=assets_by_uuid.get(comp["asset_uuid"]),
            drift={"undeclared_component": comp},
            now=now,
        )
        counts[outcome] += 1

    for provider_name in assessment["undeclared_providers"]:
        fingerprint = _fp(_UNDECLARED_PROVIDER, _norm(provider_name))
        live.add(fingerprint)
        outcome = _reconcile_finding(
            dep,
            fingerprint=fingerprint,
            finding_type=_UNDECLARED_PROVIDER,
            title=f"Undeclared provider in the AI supply chain: {provider_name}",
            severity=_UNDECLARED_PROVIDER_SEVERITY,
            location=provider_name,
            asset=None,
            drift={"undeclared_provider": provider_name},
            now=now,
        )
        counts[outcome] += 1

    for comp in assessment["missing"]:
        fingerprint = _fp(_DECLARED_NOT_OBSERVED, comp["kind"], _norm(comp["identifier"]) or _norm(comp["name"]))
        live.add(fingerprint)
        outcome = _reconcile_finding(
            dep,
            fingerprint=fingerprint,
            finding_type=_DECLARED_NOT_OBSERVED,
            title=f"Declared {comp['kind_label'].lower()} not observed: {comp['name']}",
            severity=_MISSING_SEVERITY,
            location=comp["identifier"] or comp["name"],
            asset=None,
            drift={"declared_not_observed": comp},
            now=now,
        )
        counts[outcome] += 1

    # Auto-close machine-managed drift findings whose drift has cleared. A human's
    # disposition (accepted / false-positive / manually closed) is left as set; only
    # a still-live machine finding is closed, and marked so a later re-record can
    # re-open it if the drift returns.
    stale = (
        dep.findings.filter(finding_type__startswith=_FINDING_PREFIX)
        .exclude(fingerprint__in=live)
        .exclude(status__in=RESOLVED_FINDING_STATUSES)
    )
    for finding in stale:
        finding.status = Finding.Status.CLOSED
        raw = dict(finding.raw or {})
        raw["auto_resolved"] = True
        finding.raw = raw
        finding.last_seen = now
        finding.save(update_fields=["status", "raw", "last_seen", "updated_at"])
        counts["resolved"] += 1

    counts["drift_detected"] = assessment["drift_detected"]
    return counts
