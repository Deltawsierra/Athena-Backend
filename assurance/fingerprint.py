"""Deterministic, timestamp-free system fingerprint for a deployment (SPINE).

An :class:`~assurance.models.AssuranceClaim` is true *of a system state*. To
version a claim honestly — to know when the state it was observed of has changed
and the claim must be re-evaluated and superseded — the state needs a stable,
recomputable identity. This module computes it: a SHA-256 over the CANONICAL JSON
(the same discipline :func:`assurance.receipt._digest` uses: sorted keys, compact
separators) of the deployment's **stable, security-relevant descriptor only**.

What goes into the descriptor is exactly the configuration whose *change* should
force a claim to be re-verified: the asset graph (each component's kind,
identifier, classification, the provider it resolves to, and the salient config
in its metadata — model id, region, permissions, prompt/generation config, the
edges it declares), each provider's declared assurance assertions, and the
approved data boundary. What is deliberately EXCLUDED is anything that varies
without the security posture changing — every timestamp (``first_seen`` /
``last_seen`` / ``created_at`` / ``updated_at``), every row uuid, and any counter
— exactly the "free of any timestamp" discipline the finding fingerprint and the
receipt digest already keep. Identical state therefore yields an identical
fingerprint, and merely letting time pass never changes it.

Pure and side-effect-free: a computed view of the stored graph, no record, no
migration. Prefetch ``assets__provider__assertions`` and select_related
``data_boundary`` on the caller side to keep it query-light.
"""

from __future__ import annotations

from .receipt import _digest

# The Asset.metadata keys that identify a component's security-relevant
# configuration — the facts whose change should force a claim to be re-verified.
# Anything not listed here (and every timestamp / uuid / counter) is excluded, so
# incidental churn never moves the fingerprint. Sorted for a stable descriptor.
_SALIENT_METADATA_KEYS = (
    "adapter",
    "base_url",
    "generation_config",
    "identity",
    "model",
    "permissions",
    "prompt_config",
    "provenance",
    "region",
    "server",
    "subkind",
    "system_prompt",
    "temperature",
    "tools",
    "version",
)


def _salient_metadata(metadata) -> dict:
    """The salient, non-empty config facts for a component, from its metadata.
    Only the curated, security-relevant keys — never a timestamp, uuid, or
    counter — so the descriptor is stable under incidental churn."""
    if not isinstance(metadata, dict):
        return {}
    facts: dict = {}
    for key in _SALIENT_METADATA_KEYS:
        value = metadata.get(key)
        if value not in (None, "", [], {}):
            facts[key] = value
    return facts


def _asset_descriptor(asset) -> dict:
    """One asset reduced to its stable, security-relevant identity: what it is,
    how it is classified, the provider it resolves to (by name/kind, not the
    volatile pk/uuid), and its salient config. No timestamps, no row uuid."""
    provider = getattr(asset, "provider", None)
    return {
        "kind": asset.kind,
        "name": asset.name,
        "identifier": asset.identifier,
        "classification": asset.classification,
        "provider": provider.name if provider else None,
        "provider_kind": provider.kind if provider else None,
        "provider_region": provider.region if provider else None,
        "metadata": _salient_metadata(asset.metadata),
    }


def _provider_descriptor(provider) -> dict:
    """One provider reduced to its declared assurance posture: identity, region,
    and each graded assertion (field / value / evidence class), sorted. The
    evidence class is in the descriptor because a fact moving from vendor-asserted
    to verified is a state change that should re-open a claim."""
    assertions = sorted(
        (
            {
                "field": a.field,
                "value": a.value,
                "evidence_class": a.evidence_class,
            }
            for a in provider.assertions.all()
        ),
        key=lambda a: (a["field"], a["value"], a["evidence_class"]),
    )
    return {
        "name": provider.name,
        "kind": provider.kind,
        "region": provider.region,
        "evidence_class": provider.evidence_class,
        "assertions": assertions,
    }


def _boundary_descriptor(deployment) -> dict | None:
    """The approved data boundary, None-safe. An undeclared boundary is ``None``
    in the descriptor — the honest "nothing approved", never a fabricated policy —
    and declaring one is itself a state change that should re-open a claim."""
    policy = getattr(deployment, "data_boundary", None)
    if policy is None:
        return None
    return {
        "allowed_regions": sorted(str(r) for r in (policy.allowed_regions or [])),
        "training_allowed": policy.training_allowed,
        "third_party_sharing_allowed": policy.third_party_sharing_allowed,
    }


def compute_system_fingerprint(deployment) -> str:
    """A deterministic, timestamp-free SHA-256 (hex, 64 chars) over the
    deployment's stable, security-relevant descriptor — its asset graph, the
    providers behind it and their declared assertions, the approved data boundary,
    and the environment. Identical state yields an identical fingerprint; a config
    change (a new region, an added permission, a declared boundary, an upgraded
    evidence class) changes it, and the mere passage of time never does.

    Prefetch ``assets__provider__assertions`` and select_related ``data_boundary``
    on the caller side to keep it query-light."""
    assets = sorted(
        (_asset_descriptor(a) for a in deployment.assets.all()),
        key=lambda d: (d["kind"], d["identifier"], d["name"]),
    )

    # The distinct providers the deployment's assets resolve to, described once.
    providers_by_name: dict[str, dict] = {}
    for asset in deployment.assets.all():
        provider = getattr(asset, "provider", None)
        if provider is not None and provider.name not in providers_by_name:
            providers_by_name[provider.name] = _provider_descriptor(provider)
    providers = [providers_by_name[name] for name in sorted(providers_by_name)]

    descriptor = {
        "environment": deployment.environment,
        "assets": assets,
        "providers": providers,
        "data_boundary": _boundary_descriptor(deployment),
    }
    return _digest(descriptor)


def policy_version(deployment) -> str:
    """The pinned assurance-policy version a claim is assessed under — the rule set
    (six-state thresholds, required-evidence rules, claim caps) bound to the
    assessment at derivation time, so a later change to the *policy* (not the
    system) can tell whether the policy a decision was made under still holds.

    Delegates to :func:`assurance.policy.policy_pin`: a deterministic
    ``mythos.assurance.policy/<v>+<hex>`` string derived from the governing rules,
    which moves when any of them change. It embeds the Assurance Receipt standard
    version, so a claim's policy and the receipt that backs it never disagree about
    which evaluator ran. Imported lazily to keep the fingerprint module free of the
    decision/policy layer at import time."""
    from .policy import policy_pin

    return policy_pin(deployment)
