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
edges it declares), each provider's declared assurance assertions, the approved
data boundary, and the **served-route fingerprint** — what actually ran, field by
field, with every unobserved field carried explicitly as ``unknown`` rather than
omitted (see :mod:`assurance.served_route`). What is deliberately EXCLUDED is anything that varies
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
from .served_route import served_route_fingerprint

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
        # What actually served (Phase 2 item 2). Folded in as its own fingerprint
        # rather than expanded here, for two reasons. It is computed from the same
        # assets, so inlining it would hash the same facts twice and make the
        # descriptor read as though the route were independent evidence. And the
        # route carries every field it did NOT observe -- `_salient_metadata`
        # above carries only what it did -- so a route field moving from
        # `unknown` to a value moves this fingerprint even though no metadata key
        # the asset descriptor watches has changed. That is the point: a claim
        # bound to a system whose quantization was unknown was bound to the
        # not-knowing, and learning it is a state change that should re-open the
        # claim.
        "served_route": served_route_fingerprint(deployment),
    }
    return _digest(descriptor)


# ---------------------------------------------------------------------------
# Per-claim input fingerprints -- the INVALIDATES table
# ---------------------------------------------------------------------------
#
# The system fingerprint above is ONE digest per deployment, and every claim used
# to bind to it. That made invalidation a co-invalidation: any change anywhere
# moved every claim's bound state at once, so widening the data boundary staled
# the AI-BOM and effective-access claims too, though neither reads the boundary.
# Minotaur measured it as two false accusations on every run, and the key's
# `claim.effective_access_stale` case sat as a known gap because "a change touched
# THIS claim's inputs" could not be told apart from "something changed".
#
# So each claim type binds to a fingerprint of the inputs its deriver actually
# reads, and only those. Propagation between claims is no longer a separate edge
# table: two claims that rest on a shared input both move when it moves, and
# neither moves when an input only the other reads does. The table below IS the
# INVALIDATES relation, read in the other direction.
#
# What each family is, and which assessor reads it:
#
#   environment          the deployment's environment. Every claim is made in it.
#   boundary             the approved data boundary (assurance.boundary).
#   providers            each provider's identity, region, evidence class and
#                        graded assertions (boundary postures; the BOM's declared
#                        facts).
#   asset_identity       each component's kind, name, identifier, classification
#                        and the provider it resolves to. Every assessor walks it.
#   asset_bom_facts      the metadata the AI-BOM carries per component
#                        (assurance.bom._COMPONENT_FACT_KEYS).
#   asset_access         the metadata the effective-access graph follows:
#                        permissions, tools, server, identity (assurance.access).
#   declared_components  the customer's declared architecture (bom_drift).
#   served_route         what actually served (assurance.served_route).
#
# A family missing from a claim's list is a change that claim would NOT notice,
# which is the dangerous direction. It is pinned by a test that mutates every
# family and requires any change to a claim's derived reading to move that
# claim's fingerprint -- never the other way round.
_ACCESS_METADATA_KEYS = ("identity", "permissions", "server", "tools")
_BOM_FACT_METADATA_KEYS = (
    "adapter",
    "base_url",
    "model",
    "provenance",
    "server",
    "subkind",
    "version",
)

CLAIM_INPUTS: dict[str, tuple[str, ...]] = {
    "data_boundary": ("environment", "boundary", "providers", "asset_identity"),
    "ai_bom": (
        "environment",
        "providers",
        "asset_identity",
        "asset_bom_facts",
        "declared_components",
        "served_route",
    ),
    "effective_access": ("environment", "asset_identity", "asset_access"),
}


def _metadata_subset(metadata, keys) -> dict:
    if not isinstance(metadata, dict):
        return {}
    return {k: metadata[k] for k in keys if metadata.get(k) not in (None, "", [], {})}


def _asset_identity(asset) -> dict:
    descriptor = _asset_descriptor(asset)
    descriptor.pop("metadata")
    return descriptor


def _declared_component_descriptor(component) -> dict:
    """A declared component, by the fields bom_drift compares -- never its row
    uuid or timestamps."""
    return {
        "kind": component.kind,
        "name": component.name,
        "identifier": component.identifier,
        "provider_name": getattr(component, "provider_name", "") or "",
    }


def _families(deployment) -> dict:
    """Every input family, computed once over a (prefetched) deployment."""
    assets = list(deployment.assets.all())

    def by_asset(project) -> list:
        return sorted(
            (project(a) for a in assets),
            key=lambda d: (d["kind"], d["identifier"], d["name"]),
        )

    providers_by_name: dict[str, dict] = {}
    for asset in assets:
        provider = getattr(asset, "provider", None)
        if provider is not None and provider.name not in providers_by_name:
            providers_by_name[provider.name] = _provider_descriptor(provider)

    return {
        "environment": deployment.environment,
        "boundary": _boundary_descriptor(deployment),
        "providers": [providers_by_name[n] for n in sorted(providers_by_name)],
        "asset_identity": by_asset(_asset_identity),
        "asset_bom_facts": by_asset(
            lambda a: {
                **_asset_identity(a),
                "facts": _metadata_subset(a.metadata, _BOM_FACT_METADATA_KEYS),
            }
        ),
        "asset_access": by_asset(
            lambda a: {
                **_asset_identity(a),
                "access": _metadata_subset(a.metadata, _ACCESS_METADATA_KEYS),
            }
        ),
        "declared_components": sorted(
            (_declared_component_descriptor(c) for c in deployment.declared_components.all()),
            key=lambda d: (d["kind"], d["identifier"], d["name"], d["provider_name"]),
        ),
        "served_route": served_route_fingerprint(deployment),
    }


def claim_input_fingerprints(deployment) -> dict[str, str]:
    """The input fingerprint of every claim type, keyed by claim type.

    Each is a SHA-256 over the families :data:`CLAIM_INPUTS` names for that type,
    and only those, so a change moves exactly the claims that rest on it. Computed
    together because the families are shared; prefetch as for
    :func:`compute_system_fingerprint`, plus ``declared_components``.
    """
    families = _families(deployment)
    return {
        claim_type: _digest(
            {"claim_type": claim_type, **{name: families[name] for name in names}}
        )
        for claim_type, names in CLAIM_INPUTS.items()
    }


def claim_input_fingerprint(deployment, claim_type: str) -> str:
    """One claim type's input fingerprint. A claim type with no entry in
    :data:`CLAIM_INPUTS` rests on the whole system state: it gets the system
    fingerprint, so an unmapped type is invalidated by any change rather than by
    none."""
    if claim_type not in CLAIM_INPUTS:
        return compute_system_fingerprint(deployment)
    return claim_input_fingerprints(deployment)[claim_type]


def claim_state_moved(claim, *, system_fp: str, input_fps: dict[str, str]) -> bool:
    """Whether the state a claim version is bound to no longer holds.

    A claim bound to its own inputs is compared on those inputs alone. A row bound
    before per-claim fingerprints existed carries none, and is compared on the
    whole system fingerprint -- the conservative reading, which is how every claim
    used to be compared. The one predicate derive, invalidate and resolve all use,
    so the three can never disagree about whether a claim drifted."""
    if claim.input_fingerprint:
        expected = input_fps.get(claim.claim_type)
        if expected is None:
            # An unmapped type rests on the whole system (see claim_input_fingerprint).
            expected = system_fp
        return claim.input_fingerprint != expected
    return claim.system_fingerprint != system_fp


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
