"""AI-BOM — the AI supply-chain bill of materials (Phase 1.7).

A sellable, exportable artifact — for procurement, audit, M&A due diligence, and
security questionnaires — before any deep adversarial testing is needed. It is an
aggregation, not a new detection: it assembles what discovery already recorded
into one structured document, the way a software SBOM lists a program's
dependencies. It overlaps 1.1 (the component inventory) and 1.5 (the provider
assurance profiles) and puts them in one place:

- **Components** — every AI component the deployment is built from (models,
  agents, tools, MCP servers, vector DBs, gateways, data stores, service
  accounts), with its kind, identifier, classification, the provider behind it,
  and the salient facts discovery recorded (model id, version, region).
- **Providers** — the third-party vendors in the supply chain and, for each, the
  facts they declare (region, retention, training, subprocessors) with the
  **evidence class** on every fact, so a reader sees how strongly each is known.

It is honest by construction. Every provider fact carries its evidence grade and
the profile's weakest link, so the BOM never reads as stronger than its softest
claim; an unmanaged component is flagged as **shadow** supply chain nobody
approved. And it is **tamper-evident**: a deterministic SHA-256 digest over the
BOM's stable content (never a timestamp) rides alongside, so a recipient of the
exported document can recompute it and confirm nothing was altered in transit —
integrity, not proof the vendors' claims are true.

Computed on read (a pure function of the stored asset graph and provider
profiles), like the other assessments — no new record, no migration. Prefetch
``assets__provider__assertions`` on the caller side to keep it query-light.
"""

from __future__ import annotations

from django.utils import timezone

from .models import evidence_strength
from .receipt import ALGORITHM, _digest
from .governance import is_shadow

BOM_FORMAT = "athena-ai-bom"
BOM_VERSION = "1.0"

# The metadata keys worth carrying into the BOM for a component — the facts a
# procurement or audit reader needs, pulled from whatever discovery recorded.
_COMPONENT_FACT_KEYS = ("model", "version", "base_url", "adapter", "subkind", "server", "provenance")


def _component_facts(metadata) -> dict:
    """The salient, non-empty facts for a component, from its recorded metadata."""
    if not isinstance(metadata, dict):
        return {}
    facts = {}
    for key in _COMPONENT_FACT_KEYS:
        value = metadata.get(key)
        if value not in (None, "", [], {}):
            facts[key] = value
    return facts


def _component(asset) -> dict:
    provider = getattr(asset, "provider", None)
    return {
        "uuid": str(asset.uuid),
        "name": asset.name,
        "kind": asset.kind,
        "kind_label": asset.get_kind_display(),
        "identifier": asset.identifier,
        "classification": asset.classification,
        "classification_label": asset.get_classification_display(),
        # Shadow supply chain: a component nobody approved.
        # See assurance.governance: `== UNMANAGED` counted a high-risk or
        # retired component as a governed part of the supply chain, and read
        # any value it did not recognise as governed too.
        "shadow": is_shadow(asset.classification),
        "provider_uuid": str(provider.uuid) if provider else None,
        "provider_name": provider.name if provider else None,
        "facts": _component_facts(asset.metadata),
        "first_seen": asset.first_seen.isoformat() if asset.first_seen else None,
        "last_seen": asset.last_seen.isoformat() if asset.last_seen else None,
    }


def _provider_entry(provider) -> dict:
    """One supply-chain vendor and the facts it declares, each evidence-graded.
    The profile's weakest evidence is surfaced so it never reads as stronger than
    its softest claim."""
    assertions = list(provider.assertions.all())
    declared = [
        {
            "field": a.field,
            "field_label": a.get_field_display(),
            "value": a.value,
            "evidence_class": a.evidence_class,
            "evidence_class_label": a.get_evidence_class_display(),
            "source": a.source,
            "source_label": a.get_source_display(),
        }
        for a in assertions
    ]
    declared.sort(key=lambda d: d["field"])
    classes = [a.evidence_class for a in assertions]
    weakest = max(classes, key=evidence_strength) if classes else None
    return {
        "uuid": str(provider.uuid),
        "name": provider.name,
        "kind": provider.kind,
        "kind_label": provider.get_kind_display(),
        "region": provider.region,
        "declared_facts": declared,
        "declared_field_count": len(declared),
        "weakest_evidence": weakest,
    }


def _tally(pairs) -> dict:
    """A stable count of a categorical field: {value: count}, insertion order not
    relied on (the digest sorts keys)."""
    counts: dict[str, int] = {}
    for value in pairs:
        counts[value] = counts.get(value, 0) + 1
    return counts


def build_ai_bom(deployment) -> dict:
    """The full AI bill of materials for a deployment: its components, the supply
    chain behind them, an honest summary, and a tamper-evident digest. Prefetch
    ``assets__provider__assertions`` on the caller side. Pure and
    side-effect-free (the ``generated_at`` timestamp rides outside the digest)."""
    assets = list(deployment.assets.all())
    components = [_component(a) for a in assets]
    components.sort(key=lambda c: (c["kind"], c["name"]))

    # The distinct providers this deployment's components resolve to.
    providers_by_uuid = {}
    for asset in assets:
        provider = getattr(asset, "provider", None)
        if provider is not None and str(provider.uuid) not in providers_by_uuid:
            providers_by_uuid[str(provider.uuid)] = provider
    providers = [_provider_entry(p) for p in providers_by_uuid.values()]
    providers.sort(key=lambda p: (p["kind"], p["name"]))

    # The BOM's weakest link overall: the softest evidence among all provider facts.
    all_evidence = [f["evidence_class"] for p in providers for f in p["declared_facts"]]
    weakest_overall = max(all_evidence, key=evidence_strength) if all_evidence else None

    summary = {
        "component_count": len(components),
        "provider_count": len(providers),
        "shadow_components": sum(1 for c in components if c["shadow"]),
        "components_by_kind": _tally(c["kind"] for c in components),
        "components_by_classification": _tally(c["classification"] for c in components),
        "declared_fact_count": len(all_evidence),
        "weakest_evidence": weakest_overall,
    }

    # The tamper-evident digest is over stable content only — never the timestamp
    # — so the same DB state always produces the same digest and a recipient can
    # recompute it.
    digest = _digest(
        {
            "format": BOM_FORMAT,
            "version": BOM_VERSION,
            "deployment": str(deployment.uuid),
            "components": components,
            "providers": providers,
        }
    )

    return {
        "format": BOM_FORMAT,
        "version": BOM_VERSION,
        "deployment": {"uuid": str(deployment.uuid), "name": deployment.name},
        "components": components,
        "providers": providers,
        "summary": summary,
        "receipt": {"algorithm": ALGORITHM, "digest": digest},
        "generated_at": timezone.now().isoformat(),
    }
