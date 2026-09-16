"""Discover a deployment's assets from what a scan honestly knows.

Roadmap Phase 1.1 (AI Asset Discovery). An assurance graph needs *nodes* — the
components a deployment is made of — for findings and evidence to hang off. This
module populates the :class:`~assurance.models.Asset` precursor from the signals
that actually exist, and nothing it must invent:

  * the **scanned host** (always present on a scan) becomes an ``api`` asset,
    classified ``known`` when it is inside the engagement's authorised scope and
    ``unmanaged`` (a reachable-but-undeclared shadow asset) when it is not;
  * each **declared scope host** on the engagement becomes an ``approved`` asset
    (authorised inventory), even one no scan has reached yet;
  * a finding's **endpoint** becomes an ``api`` asset *when the finding carries a
    location* (sparse for today's signature engine, populated when present);
  * a **declared LLM target** (``scan.target_config``: adapter / base_url /
    model) becomes a ``model`` asset under a model :class:`Provider` — the one
    AI-component signal that exists today, and it is *declared*, not detected.

Every finding is attached to the asset it concerns (its endpoint if it has one,
else the deployment's host). What the engine cannot see — the target's model
providers, gateways, vector DBs, MCP servers — is deliberately not fabricated;
that is declared-inventory work for a later slice.

It is **idempotent** and **non-destructive**: an asset is keyed within its
deployment by ``(kind, identifier)``, so a re-scan refreshes ``last_seen`` and
metadata rather than duplicating it, and a human's re-classification of an asset
is never overwritten by a re-derive. Nothing here reaches the network.
"""

from __future__ import annotations

from urllib.parse import urlparse

from django.utils import timezone

from .ingest import _host
from .models import Asset, Deployment, Provider


def _endpoint_identifier(location: str) -> str:
    """A stable identifier for an endpoint asset from a finding location. A URL
    is reduced to host+path so the same endpoint dedupes across query strings; a
    bare path is used as-is."""
    loc = (location or "").strip()
    if not loc:
        return ""
    if "://" in loc:
        try:
            parsed = urlparse(loc)
            return f"{parsed.hostname or ''}{parsed.path or ''}".rstrip("/") or loc
        except ValueError:
            return loc
    return loc


def _get_or_refresh(
    deployment: Deployment,
    *,
    kind: str,
    identifier: str,
    name: str,
    classification: str,
    now,
    provider: Provider | None = None,
    metadata: dict | None = None,
) -> Asset | None:
    """Create the asset, or refresh the machine-owned fields of an existing one.

    Classification and name are set only on create — a human may reclassify or
    rename an asset, and a re-derive must not undo that. ``last_seen``, provider
    linkage, and metadata are refreshed as the current machine truth."""
    if not identifier:
        return None
    defaults = {
        "name": name[:255] or identifier[:255],
        "classification": classification,
        "provider": provider,
        "metadata": metadata or {},
        "first_seen": now,
        "last_seen": now,
    }
    asset, created = Asset.objects.get_or_create(
        deployment=deployment, kind=kind, identifier=identifier[:1024], defaults=defaults
    )
    if not created:
        asset.last_seen = now
        if provider is not None and asset.provider_id != provider.pk:
            asset.provider = provider
        if metadata:
            merged = {**(asset.metadata or {}), **metadata}
            asset.metadata = merged
        asset.save(update_fields=["last_seen", "provider", "metadata"])
    return asset


def _llm_provider_and_asset(deployment: Deployment, cfg: dict, now) -> Asset | None:
    """Register a declared LLM target as a model Provider + Asset.

    The facts are caller-declared (evidence class ``vendor_asserted``), never
    measured — this is honest about *how strongly it is known*."""
    base_url = str(cfg.get("base_url") or "").strip()
    model = str(cfg.get("model") or "").strip()
    if not base_url and not model:
        return None
    host = _host(base_url)
    provider_name = host or model or "LLM provider"
    # evidence_class defaults to VENDOR_ASSERTED on the model: a declared target
    # is a vendor assertion, not a measurement.
    provider, _ = Provider.objects.get_or_create(
        name=provider_name[:200],
        kind=Provider.Kind.MODEL_PROVIDER,
    )
    identifier = f"{base_url}|{model}".strip("|") or base_url or model
    name = model or host or "LLM model"
    return _get_or_refresh(
        deployment,
        kind=Asset.Kind.MODEL,
        identifier=identifier,
        name=name,
        classification=Asset.Classification.KNOWN,
        now=now,
        provider=provider,
        metadata={"adapter": cfg.get("adapter", ""), "base_url": base_url, "model": model},
    )


def derive_assets(deployment: Deployment, scan) -> list[Asset]:
    """Reconcile the deployment's assets from a scan, and attach its findings.

    Returns the assets touched. Safe to call repeatedly; preserves human
    classification and never fabricates a component the data does not attest."""
    now = timezone.now()
    touched: list[Asset] = []

    engagement = getattr(scan, "engagement", None)
    host = _host(getattr(scan, "target_url", "") or "")

    # 1. The scanned host: known if authorised by the engagement scope, else a
    #    reachable-but-undeclared shadow asset.
    host_asset = None
    if host:
        in_scope = engagement.covers(host) if engagement is not None else True
        host_asset = _get_or_refresh(
            deployment,
            kind=Asset.Kind.API,
            identifier=host,
            name=host,
            classification=Asset.Classification.KNOWN if in_scope else Asset.Classification.UNMANAGED,
            now=now,
            metadata={"source": "scan_target"},
        )
        if host_asset:
            touched.append(host_asset)

    # 2. Declared scope hosts: authorised inventory, even if unscanned.
    if engagement is not None and isinstance(getattr(engagement, "scope_hosts", None), list):
        for entry in engagement.scope_hosts:
            if not isinstance(entry, str) or not entry.strip():
                continue
            h = entry.strip().lower().lstrip("*.").strip(".")
            if not h or h == host:
                continue
            a = _get_or_refresh(
                deployment,
                kind=Asset.Kind.API,
                identifier=h,
                name=h,
                classification=Asset.Classification.APPROVED,
                now=now,
                metadata={"source": "engagement_scope"},
            )
            if a:
                touched.append(a)

    # 3. Declared LLM target → a model Provider + Asset (the one AI-component
    #    signal that exists today, and it is declared).
    cfg = getattr(scan, "target_config", None)
    llm_asset = None
    if isinstance(cfg, dict) and cfg.get("kind") == "llm":
        llm_asset = _llm_provider_and_asset(deployment, cfg, now)
        if llm_asset:
            touched.append(llm_asset)

    # 4. Endpoint assets from findings that carry a location, and attach every
    #    finding to the asset it concerns.
    for finding in deployment.findings.all():
        endpoint_id = _endpoint_identifier(finding.location)
        target_asset = None
        if endpoint_id:
            target_asset = _get_or_refresh(
                deployment,
                kind=Asset.Kind.API,
                identifier=endpoint_id,
                name=finding.location[:255],
                classification=Asset.Classification.KNOWN,
                now=now,
                metadata={"source": "finding_endpoint"},
            )
            if target_asset and target_asset not in touched:
                touched.append(target_asset)
        # An LLM finding belongs to the model asset; a located finding to its
        # endpoint; everything else to the deployment's host.
        target_asset = target_asset or (llm_asset if cfg and isinstance(cfg, dict) and cfg.get("kind") == "llm" else None) or host_asset
        if target_asset is not None and finding.asset_id != target_asset.pk:
            finding.asset = target_asset
            finding.save(update_fields=["asset"])

    return touched
