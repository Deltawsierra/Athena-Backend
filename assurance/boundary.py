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

import re

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

_WORD_RE = re.compile(r"[a-z0-9]+")

# Whole-word negations. Matched as tokens (word boundaries), NEVER as substrings,
# so "now" is not read as "no" and "opt-in" is not read as an "opt-out". These
# suppress an affirmative reading so a boundary check never invents a violation
# from an ambiguous phrase.
_NEGATION_WORDS = frozenset({"no", "not", "never", "none", "zero", "false", "disabled", "off"})
# Negations a single token cannot capture (hyphenated / two-word "opt out").
_NEGATION_PHRASES = ("opt out", "opt-out", "opted out", "opted-out", "opts out")
# Affirmative phrases that must win over the "opt" family ("opt-in" ≠ "opt-out").
_AFFIRMATIVE_PHRASES = ("opt in", "opt-in", "opted in", "opted-in", "opts in")
# Tokens that affirmatively say "yes, it trains on / shares data".
_AFFIRMATIVE_WORDS = frozenset(
    {"yes", "true", "train", "trains", "training", "trained", "share", "shares", "sharing", "shared"}
)

# Internal-only sharing declarations. A ``subprocessors`` value that positively
# declares the data stays in-house ("internal only", "in-house", "first-party",
# "self-hosted") is NOT third-party sharing, even though it carries no negation
# token — so "internal only" must not read as a violation. Mirrors the training
# path's whole-word / phrase discipline (word boundaries, never substrings), and
# is deliberately CONSERVATIVE: an internal-only reading is accepted only when the
# value BOTH carries an internal-only indicator AND is composed entirely of the
# benign internal vocabulary below. Any token outside that vocabulary — a named
# subprocessor (a vendor), or the word "third" — is not benign and keeps the
# sharing reading, so a real sharing declaration is never suppressed (the
# dangerous direction).
_INTERNAL_ONLY_PHRASES = (
    "internal only",
    "internal-only",
    "internal use only",
    "internal use",
    "in house",
    "in-house",
    "on prem",
    "on-prem",
    "on premise",
    "on-premise",
    "on premises",
    "on-premises",
    "first party",
    "first-party",
    "1st party",
    "self hosted",
    "self-hosted",
    "kept internal",
    "stays internal",
    "our own",
    "own infrastructure",
    "company internal",
)
# Single tokens that on their own declare an internal-only posture.
_INTERNAL_ONLY_WORDS = frozenset(
    {"internal", "internally", "inhouse", "onprem", "onpremise", "onpremises", "selfhosted", "firstparty", "private"}
)
# The FULL vocabulary a value may be composed of and still read as internal-only.
# Notably absent: any vendor / subprocessor name, and the token "third" — so
# "third party" (tokens {third, party}) is never suppressed while "first party"
# (tokens {first, party}, with the phrase indicator) is.
_BENIGN_INTERNAL_TOKENS = _INTERNAL_ONLY_WORDS | frozenset(
    {
        "only", "use", "used", "in", "house", "on", "prem", "premise", "premises",
        "self", "hosted", "host", "first", "1st", "party",
        "no", "not", "never", "none", "zero",
        "kept", "stays", "stay", "remains", "remain",
        "our", "ours", "own", "owned",
        "company", "corporate", "org", "organization", "organisation",
        "team", "staff", "employee", "employees",
        "data", "all", "and", "within",
        "infrastructure", "systems", "system", "environment", "environments",
    }
)


def _declares_internal_only(v: str) -> bool:
    """Whether a (lower-cased, stripped) subprocessors value positively declares an
    internal-only posture — the data stays in-house, no third party is named. True
    only when the value BOTH carries an internal-only indicator (a phrase or a
    token) AND is composed entirely of the benign internal vocabulary, so a value
    that also names a vendor ("internal team and Stripe") or says "third party" is
    never mistaken for internal-only."""
    has_phrase = any(p in v for p in _INTERNAL_ONLY_PHRASES)
    tokens = set(_WORD_RE.findall(v))
    has_word = bool(tokens & _INTERNAL_ONLY_WORDS)
    if not (has_phrase or has_word):
        return False
    return bool(tokens) and tokens <= _BENIGN_INTERNAL_TOKENS


def _negated(value: str) -> bool:
    """Whether a declared value carries a whole-word negation ("No", "opted out",
    "zero retention", "disabled"). Word-boundary aware, so an incidental substring
    ("now", "opt-in") never counts as a negation."""
    v = (value or "").strip().lower()
    if not v:
        return False
    # An explicit affirmative "opt in" beats the "opt out" family.
    if any(p in v for p in _AFFIRMATIVE_PHRASES):
        return False
    if any(p in v for p in _NEGATION_PHRASES):
        return True
    return bool(set(_WORD_RE.findall(v)) & _NEGATION_WORDS)


def _affirmative(value: str) -> bool:
    """Does a declared value affirmatively say the provider trains on / shares
    customer data? A whole-word negation suppresses it, but an incidental
    substring ("now", "opt-in") does not — so a real training declaration is never
    silently lost (the dangerous direction), and a real negation never invents a
    violation."""
    v = (value or "").strip().lower()
    if not v or _negated(v):
        return False
    if any(p in v for p in _AFFIRMATIVE_PHRASES):
        return True
    return v.startswith(("yes", "true", "1")) or bool(set(_WORD_RE.findall(v)) & _AFFIRMATIVE_WORDS)


def _shares_with_third_parties(value: str) -> bool:
    """A provider's declared subprocessors posture read as a sharing signal: a
    non-empty declaration that is neither a negation ("none", "no subprocessors")
    nor a positive internal-only declaration ("internal only", "in-house",
    "first-party") names third parties the data reaches. An empty value is a gap
    the caller surfaces as an unknown, not sharing.

    The internal-only guard mirrors the training path's whole-word discipline so a
    benign in-house declaration that carries no negation token does not invent a
    false sharing violation, while a real sharing declaration — a named vendor, an
    affirmative "shares with third parties" — is never suppressed."""
    v = (value or "").strip().lower()
    if not v:
        return False
    if _negated(v):
        return False
    if _declares_internal_only(v):
        return False
    return True


def _region_allowed(declared: str, allowed_regions: list[str]) -> bool:
    """A declared region is within boundary when it exactly matches an approved
    region, or sits inside a coarser approved one as a delimited sub-region — so
    ``eu`` approves ``eu-west-1`` and ``us-east-1`` approves the literal
    ``us-east-1``, but ``us`` does NOT approve ``aus-east`` (no accidental
    substring match). Case-insensitive."""
    d = (declared or "").strip().lower()
    if not d:
        return False
    for region in allowed_regions:
        r = str(region).strip().lower()
        if not r:
            continue
        if d == r or d.startswith(f"{r}-") or d.startswith(f"{r}_"):
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
    sharing = assertions.get("subprocessors")
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
        # Third-party sharing: forbidden unless the boundary approves it. The
        # provider's declared subprocessors are the sharing signal — named
        # subprocessors are third parties the data reaches.
        if not policy.third_party_sharing_allowed:
            if not sharing:
                unknowns.append("third-party sharing (subprocessor) posture not declared")
            elif _shares_with_third_parties(sharing["value"]):
                violations.append(
                    f"provider declares third-party subprocessors ('{sharing['value']}'), "
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
        "sharing": sharing,
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
