"""AI Data Boundary Assessment — approved data flows vs. actual ones (Phase 1.4).

The flagship differentiator, grounded in signals that already exist. Two sides:

- **Actual** — where the deployment's data can go: the providers and components
  it depends on (its assets that resolve to a provider, from asset discovery and
  the MCP/agent inventory), plus each provider's *declared* posture (region,
  retention, training, subprocessors — the Provider Assurance Profile).
- **Approved** — what the customer says is allowed: the :class:`DataBoundary`
  they declare (allowed regions, whether training / third-party sharing is
  permitted).

This module reconciles them and reports, per data flow, whether it is within the
approved boundary, a violation, or *not assessable* because the posture or the
boundary was never declared. It is honest about the difference between a
**violation** (a declared fact that breaks a declared rule) and an **unknown**
(a fact nobody declared) — an undeclared posture is a gap to close, not a pass,
and never a violation. It also surfaces **shadow destinations**: unmanaged data
sinks the deployment reaches but nobody approved — a data flow outside the
boundary by definition.

Nothing here observes the network or parses a model's traffic. It reconciles what
discovery recorded against what a human approved; a mechanical check is made only
where both sides are structured enough to be honest about it, and everything else
is surfaced for a human to read rather than guessed.
"""

from __future__ import annotations

from .models import Asset

# The asset kinds that are data destinations — a place the deployment's data can
# flow to. A shadow (unmanaged) one is a flow outside any approved boundary.
DATA_DESTINATION_KINDS = {
    Asset.Kind.MODEL,
    Asset.Kind.MCP_SERVER,
    Asset.Kind.VECTOR_DB,
    Asset.Kind.GATEWAY,
    Asset.Kind.TOOL,
    Asset.Kind.API,
    Asset.Kind.DATA_STORE,
}

# Values, normalised, that read as "yes, it trains on / shares data". Conservative
# on purpose: anything with a negation ("no", "opted out", "zero retention") is
# NOT treated as affirmative, so a boundary check never invents a violation from
# an ambiguous phrase.
_NEGATIONS = ("no", "not", "never", "opt", "zero", "false", "disabled", "off")


def _affirmative(value: str) -> bool:
    v = (value or "").strip().lower()
    if not v:
        return False
    if any(neg in v for neg in _NEGATIONS):
        return False
    return v.startswith(("yes", "true", "1")) or "train" in v or "share" in v


def _region_allowed(declared: str, allowed_regions: list[str]) -> bool:
    """A declared region is within boundary when it matches any approved region —
    a case-insensitive two-way substring match, so ``eu`` approves ``eu-west-1``
    and ``us-east-1`` approves the literal ``us-east-1``. A loose match by design:
    it errs toward *not* flagging a plausibly-matching region."""
    d = (declared or "").strip().lower()
    if not d:
        return False
    for region in allowed_regions:
        r = str(region).strip().lower()
        if r and (r in d or d in r):
            return True
    return False


def _assertion_map(provider) -> dict:
    """{field: {value, evidence_class}} for a provider's declared assertions,
    read from whatever is prefetched — no query per provider when the caller
    prefetches ``assets__provider__assertions``."""
    return {
        a.field: {"value": a.value, "evidence_class": a.evidence_class}
        for a in provider.assertions.all()
    }


def _assess_flow(provider, assets, policy) -> dict:
    """Reconcile one provider (a data destination) against the approved boundary.

    ``policy`` is the :class:`DataBoundary` or ``None``. Returns the flow with a
    ``status`` of ``approved`` / ``violation`` / ``unknown`` and the reasons."""
    assertions = _assertion_map(provider)
    region = assertions.get("region")
    training = assertions.get("trains_on_data")
    violations: list[str] = []
    unknowns: list[str] = []

    if policy is None:
        unknowns.append("no data boundary has been approved for this deployment")
    else:
        # Region: only assessable when a region boundary is declared.
        if policy.allowed_regions:
            if not region:
                unknowns.append("data region not declared for this provider")
            elif not _region_allowed(region["value"], policy.allowed_regions):
                violations.append(
                    f"declared region '{region['value']}' is not within the approved "
                    f"boundary {list(policy.allowed_regions)}"
                )
        # Training: forbidden unless the boundary approves it.
        if not policy.training_allowed:
            if not training:
                unknowns.append("training-on-data posture not declared")
            elif _affirmative(training["value"]):
                violations.append(
                    f"provider declares it trains on customer data ('{training['value']}'), "
                    "which the approved boundary forbids"
                )

    status = "violation" if violations else "unknown" if unknowns else "approved"
    return {
        "provider_uuid": str(provider.uuid),
        "provider_name": provider.name,
        "kind": provider.kind,
        "kind_label": provider.get_kind_display(),
        "assets": sorted({a.name for a in assets}),
        "region": region,
        "training": training,
        "status": status,
        "violations": violations,
        "unknowns": unknowns,
    }


def assess_boundary(deployment) -> dict:
    """The full data-boundary assessment for a deployment: the approved boundary,
    each actual data flow reconciled against it, and the shadow destinations that
    escape it entirely. Prefetch ``assets__provider__assertions`` on the caller
    side to keep this query-light."""
    policy = getattr(deployment, "data_boundary", None)

    # Actual data flows: group the deployment's data-destination assets by the
    # provider they resolve to. Assets with no provider are the deployment's own
    # surface, not a third-party flow, so they do not form a provider flow (but a
    # shadow one is still surfaced below).
    by_provider: dict[int, dict] = {}
    shadow: list[dict] = []
    for asset in deployment.assets.all():
        if asset.kind not in DATA_DESTINATION_KINDS:
            continue
        if asset.classification == Asset.Classification.UNMANAGED:
            shadow.append(
                {
                    "asset_name": asset.name,
                    "kind": asset.kind,
                    "kind_label": asset.get_kind_display(),
                    "identifier": asset.identifier,
                }
            )
        if asset.provider_id is None:
            continue
        entry = by_provider.setdefault(asset.provider_id, {"provider": asset.provider, "assets": []})
        entry["assets"].append(asset)

    flows = [
        _assess_flow(entry["provider"], entry["assets"], policy)
        for entry in by_provider.values()
    ]
    flows.sort(key=lambda f: (f["status"] != "violation", f["status"] != "unknown", f["provider_name"]))

    summary = {
        "approved": sum(1 for f in flows if f["status"] == "approved"),
        "violations": sum(1 for f in flows if f["status"] == "violation"),
        "unknowns": sum(1 for f in flows if f["status"] == "unknown"),
        "shadow_destinations": len(shadow),
    }
    return {
        "declared": policy is not None,
        "policy": _policy_dict(policy),
        "flows": flows,
        "shadow_destinations": shadow,
        "summary": summary,
    }


def _policy_dict(policy) -> dict | None:
    if policy is None:
        return None
    return {
        "allowed_regions": list(policy.allowed_regions or []),
        "training_allowed": policy.training_allowed,
        "third_party_sharing_allowed": policy.third_party_sharing_allowed,
        "notes": policy.notes,
        "updated_at": policy.updated_at.isoformat() if policy.updated_at else None,
    }
