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

from .graph_refs import in_graph, retired
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
    "tool_kinds",
    "tools",
    "version",
    # Which row each tool reference reaches, and every account a merged agent row
    # acts as: both decide an agent's reach, and the system fingerprint covers the
    # access family (``_SYSTEM_COVERED``) only while it reads them too.
    "merged_identities",
)


def _present(metadata, keys) -> dict:
    """The listed keys a component's metadata carries, with their values.

    Present means present: an empty string, list or mapping is kept, and only a
    missing key or ``None`` is left out. Readers act on empty values -- a
    ``tools`` of ``""`` or ``{}`` is reported as a malformed declaration, which
    lowers the effective-access reading -- so a descriptor that dropped them
    could not see a change the reading could."""
    if not isinstance(metadata, dict):
        return {}
    return {k: metadata[k] for k in keys if metadata.get(k) is not None}


def _salient_metadata(metadata) -> dict:
    """The salient config facts for a component, from its metadata. Only the
    curated, security-relevant keys — never a timestamp, uuid, or counter — so the
    descriptor is stable under incidental churn."""
    return _present(metadata, _SALIENT_METADATA_KEYS)


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


def _distinct_providers(assets, describe) -> list:
    """Each distinct provider the assets resolve to, described once, in a stable
    order.

    Keyed by ``(name, kind)``, which is what makes a provider distinct
    (``Provider`` is unique on the pair). Keying by name alone collapsed an
    ``openai`` LLM provider and an ``openai`` vector store into whichever came
    first, so the second one's posture was invisible: it could start training on
    customer data and no fingerprint moved, while the boundary assessment --
    which groups by provider row -- read the violation."""
    seen: dict[tuple[str, str], dict] = {}
    for asset in assets:
        provider = getattr(asset, "provider", None)
        if provider is None:
            continue
        key = (provider.name, provider.kind)
        if key not in seen:
            seen[key] = describe(provider)
    return [seen[key] for key in sorted(seen)]


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
        (_asset_descriptor(a) for a in in_graph(deployment.assets.all())),
        key=lambda d: (d["kind"], d["identifier"], d["name"]),
    ) + _retired_keys(deployment)

    providers = _distinct_providers(in_graph(deployment.assets.all()), _provider_descriptor)

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
#   deployment_name      the deployment's name. The effective-access graph names
#                        its base principal after it, so a rename changes that
#                        claim's reading (who holds the reach), not only its text.
#   boundary             the approved data boundary (assurance.boundary).
#   providers            each distinct provider (by name AND kind): region and
#                        graded assertions (boundary postures; the BOM's declared
#                        facts). Not the provider row's own evidence_class, which
#                        no deriver reads.
#   asset_identity       each component's kind, name, identifier and
#                        classification. Every assessor walks it.
#   asset_provider       which provider each component resolves to (the boundary
#                        groups by it; the BOM and its drift name it). Not read by
#                        the access graph, so a provider change is not an access
#                        change.
#   asset_bom_facts      the metadata the AI-BOM carries per component
#                        (assurance.bom._COMPONENT_FACT_KEYS).
#   asset_access         the metadata the effective-access graph follows:
#                        permissions, tools, server, identity (assurance.access).
#   declared_components  the customer's declared architecture (bom_drift).
#
# The served route is not a family: no claim deriver reads it. It stays in the
# system fingerprint, which is what a decision is fenced on.
#
# A family missing from a claim's list is a change that claim would NOT notice,
# which is the dangerous direction. It is pinned by a test that mutates every
# family and requires any change to a claim's derived reading to move that
# claim's fingerprint. The other direction -- a family listed that the deriver
# does not read -- costs a retest nobody needed, and is pinned too, per family.
#
# ``tool_kinds`` decides which row a tool reference reaches (a tool, not the MCP
# server or skill at its key), so it is an input: left out, a declaration that
# changed only the kind of a tool moved an agent's reach from ``read`` to ``shell``
# and the access claim's inputs read as unchanged. ``merged_identities`` likewise:
# every account a merged agent row acts as beyond its first, so a rescan that
# changed which account the old unnamed row acts as moves the reading.
_ACCESS_METADATA_KEYS = ("identity", "merged_identities", "permissions", "server", "tool_kinds", "tools")
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
    "data_boundary": (
        "environment",
        "boundary",
        "providers",
        "asset_identity",
        "asset_provider",
    ),
    "ai_bom": (
        "environment",
        "providers",
        "asset_identity",
        "asset_provider",
        "asset_bom_facts",
        "declared_components",
    ),
    "effective_access": (
        "environment",
        "deployment_name",
        "asset_identity",
        "asset_access",
    ),
}

#: The families the whole-system fingerprint covers, each as much or more than
#: the family itself does. A row bound before per-claim fingerprints can only be
#: shown unchanged on these. A claim that also reads a family outside this set
#: cannot be, and is treated as moved: the declared architecture is deliberately
#: not in the system fingerprint (see assurance.bom_drift), and neither is the
#: deployment's name.
_SYSTEM_COVERED = frozenset(
    {
        "environment",
        "boundary",
        "providers",
        "asset_identity",
        "asset_provider",
        "asset_bom_facts",
        "asset_access",
    }
)


def _metadata_subset(metadata, keys) -> dict:
    return _present(metadata, keys)


def _asset_identity(asset) -> dict:
    return {
        "kind": asset.kind,
        "name": asset.name,
        "identifier": asset.identifier,
        "classification": asset.classification,
    }


def _asset_provider(asset) -> dict:
    provider = getattr(asset, "provider", None)
    return {
        "kind": asset.kind,
        "name": asset.name,
        "identifier": asset.identifier,
        "provider": provider.name if provider else None,
        "provider_kind": provider.kind if provider else None,
    }


def _claim_provider_descriptor(provider) -> dict:
    """A provider as the claim derivers read it: the system descriptor without the
    provider row's own evidence class, which no deriver reads (the boundary and
    the BOM grade each ASSERTION's evidence class, and those stay)."""
    descriptor = _provider_descriptor(provider)
    descriptor.pop("evidence_class")
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


def _retired_keys(deployment) -> list:
    """The key and kind of every :func:`graph_refs.retired` row, and nothing else of
    it. A retired row is out of the graph, but its key still decides resolution: a
    reference only it carries names nothing, where without it the reference falls
    through to whatever is CALLED that (``graph_refs.resolve_reference``). Deleting
    one moved an agent's reach -- to another agent's ``admin`` -- and no fingerprint
    moved, so the claim went on saying what it said. Appended only where there is
    one, so a deployment with none keeps the fingerprint it had."""
    return sorted(
        (
            {"retired": True, "kind": a.kind, "identifier": a.identifier}
            for a in deployment.assets.all()
            if retired(a) and a.identifier
        ),
        key=lambda d: (d["kind"], d["identifier"]),
    )


def _families(deployment) -> dict:
    """Every input family, computed once over a (prefetched) deployment."""
    assets = in_graph(deployment.assets.all())

    def by_asset(project) -> list:
        return sorted(
            (project(a) for a in assets),
            key=lambda d: (d["kind"], d["identifier"], d["name"]),
        )

    return {
        "environment": deployment.environment,
        "deployment_name": deployment.name,
        "boundary": _boundary_descriptor(deployment),
        "providers": _distinct_providers(assets, _claim_provider_descriptor),
        "asset_identity": by_asset(_asset_identity),
        "asset_provider": by_asset(_asset_provider),
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
        )
        + _retired_keys(deployment),
        "declared_components": sorted(
            (_declared_component_descriptor(c) for c in deployment.declared_components.all()),
            key=lambda d: (d["kind"], d["identifier"], d["name"], d["provider_name"]),
        ),
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


def legacy_row_is_provable(claim_type: str) -> bool:
    """Whether a row with no input fingerprint can be shown unchanged at all: only
    when every family its claim type reads is inside the system fingerprint."""
    return set(CLAIM_INPUTS.get(claim_type, ())) <= _SYSTEM_COVERED


def claim_state_moved(claim, *, system_fp: str, input_fps: dict[str, str]) -> bool:
    """Whether the state a claim version is bound to no longer holds.

    A claim bound to its own inputs is compared on those inputs alone. A row bound
    before per-claim fingerprints carries none. It is compared on the whole system
    fingerprint when that covers everything its claim reads, and is otherwise
    moved: the system fingerprint cannot see a change to the declared architecture
    an AI-BOM reads, so an unchanged system fingerprint is no evidence that an
    AI-BOM row still holds. The one predicate derive, invalidate and resolve all
    use, so the three can never disagree about whether a claim drifted."""
    if claim.input_fingerprint:
        expected = input_fps.get(claim.claim_type)
        if expected is None:
            # An unmapped type rests on the whole system (see claim_input_fingerprint).
            expected = system_fp
        return claim.input_fingerprint != expected
    if not legacy_row_is_provable(claim.claim_type):
        return True
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
