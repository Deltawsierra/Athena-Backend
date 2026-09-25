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
    model) becomes a ``model`` asset under a model :class:`Provider` — declared,
    not detected;
  * a **declared agent and its tools / MCP servers / skills**
    (``scan.target_config``: ``agent`` + ``tools[]``) become ``agent`` /
    ``tool`` / ``mcp_server`` / ``skill`` assets, each carrying its permission
    map and provenance, with the agent→tool edge recorded on the agent (roadmap
    1.2 — MCP & Agent-Skill Assurance). Declared inventory, not detected.

Every finding is attached to the asset it concerns (its endpoint if it has one,
else the LLM model, else the agent, else the deployment's host). What the engine
cannot see is deliberately not fabricated: a tool or MCP server that appears from
a signal but is absent from the declared inventory is a *shadow* asset and would
be classified ``unmanaged`` — the same observed-but-undeclared path the scanned
host already takes — never invented here.

It is **idempotent** and **non-destructive**: an asset is keyed within its
deployment by ``(kind, identifier)``, so a re-scan refreshes ``last_seen`` and
metadata rather than duplicating it, and a human's re-classification of an asset
is never overwritten by a re-derive. Nothing here reaches the network.
"""

from __future__ import annotations

from urllib.parse import urlparse

from django.utils import timezone

from .graph_refs import IDENTITY_RULES
from .ingest import _host
from .models import Asset, Deployment, Finding, Provider


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


#: The longest identifier an ``Asset`` row holds. Applied ONCE, where an identity
#: is formed, and never again downstream: the row used to be written under
#: ``identifier[:1024]`` while the merge that grouped declarations, and the
#: agent's ``tools`` edge, both kept the full string. Two tools that differed
#: only after character 1024 were two groups written to one row -- the second
#: replacing the first's permissions -- and the agent's edges named strings no
#: row carried, so a declared ``shell`` appeared nowhere.
IDENTIFIER_MAX = 1024


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

    ``name`` is set only on create — a human may rename an asset and a re-derive
    must not undo that. ``classification`` follows its *provenance*: a
    machine-derived classification is refreshed to the freshly computed value (so a
    host that leaves engagement scope is downgraded ``known`` → ``unmanaged`` and
    surfaces as a shadow destination, instead of staying "known" forever), while a
    human-set classification is authoritative and left untouched. ``last_seen``,
    provider linkage, and metadata are always refreshed as the current machine
    truth."""
    if not identifier:
        return None
    defaults = {
        "name": name[:255] or identifier[:255],
        "classification": classification,
        "classification_source": Asset.ClassificationSource.MACHINE,
        "provider": provider,
        "metadata": metadata or {},
        "first_seen": now,
        "last_seen": now,
    }
    asset, created = Asset.objects.get_or_create(
        deployment=deployment, kind=kind, identifier=identifier[:IDENTIFIER_MAX], defaults=defaults
    )
    if not created:
        fields = ["last_seen", "provider", "metadata"]
        asset.last_seen = now
        # A machine-derived classification tracks the current computed truth; a
        # human-set one is never overwritten by a re-derive.
        if (
            asset.classification_source == Asset.ClassificationSource.MACHINE
            and asset.classification != classification
        ):
            asset.classification = classification
            fields.append("classification")
        if provider is not None and asset.provider_id != provider.pk:
            asset.provider = provider
        if metadata:
            merged = {**(asset.metadata or {}), **metadata}
            asset.metadata = merged
        asset.save(update_fields=fields)
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


# Declared tool kinds → the graph's asset kinds. An unrecognised kind is still a
# tool the agent can call, so it registers as a plain TOOL rather than vanishing.
_TOOL_KINDS = {
    "tool": Asset.Kind.TOOL,
    "function": Asset.Kind.TOOL,
    "mcp": Asset.Kind.MCP_SERVER,
    "mcp_server": Asset.Kind.MCP_SERVER,
    "skill": Asset.Kind.SKILL,
}


def _agent_anchor(target: str) -> str:
    """Where an unnamed agent is: host, port and path of the scan's target.

    Not :func:`_endpoint_identifier`, which drops the port on purpose -- an
    endpoint found at two ports is one endpoint to a finding. Two agents are not:
    ``bots.example.com:8443/agent`` and ``:9443/agent`` are two services, and an
    anchor without the port wrote them to one row, the second scan replacing the
    first's tools and the first agent's powers falling to the deployment as
    powers nobody owned. The port is the effective one, so ``http://h/a`` (80)
    and ``https://h/a`` (443) are two anchors too; https's default is left
    unwritten, so the common anchor reads ``host/path``.

    Never the raw target: a URL carries credentials in its userinfo and tokens in
    its query, and an anchor is written as the agent's identifier AND its name.
    An IPv6 host keeps its brackets, or ``[2001:db8::1]:8443`` and
    ``[2001:db8::1:8443]`` are one anchor. A port the URL parser rejects is
    kept as written rather than letting the whole target through. A target with
    no host has nowhere to anchor an agent, and gets no agent node.
    """
    loc = (target or "").strip()
    if "://" not in loc:
        return _endpoint_identifier(loc)
    try:
        parsed = urlparse(loc)
    except ValueError:
        return ""
    host = (parsed.hostname or "").lower()
    if not host:
        return ""
    hostport = parsed.netloc.rsplit("@", 1)[-1]
    if hostport.startswith("["):
        port = hostport.partition("]")[2].lstrip(":")
    else:
        port = hostport.rpartition(":")[2] if ":" in hostport else ""
    if not port:
        port = {"http": "80", "https": "443"}.get((parsed.scheme or "").lower(), "")
    where = f"[{host}]" if ":" in host else host
    if port and port != "443":
        where = f"{where}:{port}"
    return f"{where}{parsed.path or ''}".rstrip("/")


def _clean_str_list(value) -> list[str]:
    """A list of non-empty strings from whatever a caller declared (a list, or a
    single string), so a permission map is never a half-typed value."""
    if isinstance(value, str):
        return [value.strip()] if value.strip() else []
    if isinstance(value, list):
        return [str(v).strip() for v in value if isinstance(v, (str, int, float)) and str(v).strip()]
    return []


def _tool_identifier(entry: dict, kind: str, name: str) -> str:
    """The identity a declared tool is written under.

    Its own identifier or endpoint when it gives one. Otherwise its name, and
    when it also names the server it runs on, its name AT that server. It used to
    fall back to the server alone, which is the host's identity and not the
    tool's: every tool on one MCP server became one row, carrying the permissions
    of whichever was declared last, and a tool named for its server resolved its
    own ``server`` reference to itself. An MCP server entry is the exception --
    the server it names is the server it is.
    """
    explicit = str(entry.get("identifier") or entry.get("endpoint") or "").strip()
    if explicit:
        return explicit
    server = str(entry.get("server") or "").strip()
    if kind == Asset.Kind.MCP_SERVER:
        return server or name
    if name and server:
        return f"{name}@{server}"
    return name or server


def _agent_and_tools(
    deployment: Deployment, cfg: dict, now, *, target: str = ""
) -> tuple[Asset | None, list[Asset]]:
    """Register a declared agent and the tools / MCP servers / skills it can call
    (roadmap 1.2 — MCP & Agent-Skill Assurance).

    These are **declared inventory**, not detected: the customer states what the
    agent is wired to, exactly as ``target_config`` already declares the LLM
    target. Each tool carries its own permission map and provenance, so the graph
    can show *what the agent can reach and under what authority*. A declared tool
    is ``approved`` when the caller says so, else ``known`` (we know it is there).
    A tool observed from a signal but absent from this declared set would be
    ``unmanaged`` — a shadow tool — which the endpoint/host path already handles;
    nothing here fabricates one.
    """
    touched: list[Asset] = []

    # The tools the agent is wired to — each a graph node with its permissions.
    #
    # Entries that name the same tool are ONE node carrying all of their
    # permissions. Each used to be written in turn, and a refresh replaces the
    # metadata, so the last entry's permissions were the tool's permissions:
    # declare a tool twice, once with ``shell``, and whether the agent could run
    # code depended on which line came second.
    declared: dict[tuple[str, str], dict] = {}
    raw_tools = cfg.get("tools")
    if isinstance(raw_tools, list):
        for entry in raw_tools:
            if not isinstance(entry, dict):
                continue
            name = str(entry.get("name") or "").strip()
            kind = _TOOL_KINDS.get(str(entry.get("kind") or "").strip().lower(), Asset.Kind.TOOL)
            identifier = _tool_identifier(entry, kind, name)[:IDENTIFIER_MAX]
            if not identifier:
                continue
            tool = declared.setdefault(
                (kind, identifier),
                {
                    "name": name or identifier,
                    "approved": True,
                    "permissions": [],
                    "provenance": str(entry.get("provenance") or "").strip(),
                    "server": str(entry.get("server") or "").strip(),
                    "subkind": str(entry.get("kind") or "").strip(),
                },
            )
            # Approved only if every entry for it says so: one line calling it
            # approved does not vouch for a line that did not.
            tool["approved"] = tool["approved"] and bool(entry.get("approved"))
            for perm in _clean_str_list(entry.get("permissions")):
                if perm not in tool["permissions"]:
                    tool["permissions"].append(perm)

    tool_identifiers: list[str] = []
    for (kind, identifier), tool in declared.items():
        asset = _get_or_refresh(
            deployment,
            kind=kind,
            identifier=identifier,
            name=tool["name"],
            classification=(
                Asset.Classification.APPROVED if tool["approved"] else Asset.Classification.KNOWN
            ),
            now=now,
            metadata={
                "source": "declared_inventory",
                "identity_rules": IDENTITY_RULES,
                "declared": True,
                "permissions": tool["permissions"],
                "provenance": tool["provenance"],
                "server": tool["server"],
                "subkind": tool["subkind"],
            },
        )
        if asset:
            touched.append(asset)
            if identifier not in tool_identifiers:
                tool_identifiers.append(identifier)

    # The agent identity itself — the node the tools hang off. It is declared
    # explicitly (an ``agent`` block) or implied by a scan that declares tools.
    raw_agent = cfg.get("agent")
    agent_asset = None
    agent_declared = isinstance(raw_agent, dict) or cfg.get("kind") == "agent"
    if agent_declared or tool_identifiers:
        agent = raw_agent if isinstance(raw_agent, dict) else {}
        identifier = str(agent.get("identifier") or agent.get("name") or "").strip()[:IDENTIFIER_MAX]
        if not identifier:
            # An agent the scan implies but does not name is the agent at the
            # scan's target, and is identified by it. It used to be the literal
            # "agent" -- one row per deployment -- so two scans of two different
            # agents wrote the same row, each replacing the other's tools, and the
            # first agent's tools fell to the deployment as powers nobody owned.
            # No target, no identity to give it: better no node than one
            # invented for every unnamed agent at once.
            anchor = _agent_anchor(target)
            identifier = f"agent@{anchor}"[:IDENTIFIER_MAX] if anchor else ""
        name = str(agent.get("name") or identifier).strip()
        agent_asset = _get_or_refresh(
            deployment,
            kind=Asset.Kind.AGENT,
            identifier=identifier,
            name=name,
            classification=Asset.Classification.KNOWN,
            now=now,
            metadata={
                "source": "declared_inventory",
                "identity_rules": IDENTITY_RULES,
                "declared": True,
                "identity": str(agent.get("identity") or "").strip(),
                # The agent→tool edge: what this identity is authorised to call.
                "tools": tool_identifiers,
            },
        )
        if agent_asset:
            touched.append(agent_asset)

    return agent_asset, touched


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

    # 3b. Declared agent + the tools / MCP servers / skills it can call (roadmap
    #     1.2). Declared inventory, not detected — the same discipline as the LLM
    #     target above.
    agent_asset = None
    if isinstance(cfg, dict):
        agent_asset, inventory_assets = _agent_and_tools(
            deployment, cfg, now, target=getattr(scan, "target_url", "") or ""
        )
        for a in inventory_assets:
            if a not in touched:
                touched.append(a)

    # 4. Endpoint assets from findings that carry a location, and attach every
    #    finding to the asset it concerns. Reconciled in bulk so ingest stays
    #    O(1) queries in the number of findings rather than a get_or_create plus
    #    a save per finding: one query loads the endpoints not already in hand,
    #    one bulk_create adds the new ones, one bulk_update refreshes the rest,
    #    and one bulk_update re-parents the findings. The per-endpoint semantics
    #    are identical to ``_get_or_refresh`` — create-only name, machine-owned
    #    classification refresh that never clobbers a human decision, last_seen
    #    and metadata refreshed — just amortised across the whole scan.
    findings = list(deployment.findings.all())

    # Distinct endpoint identifiers, each with the display name from the first
    # finding that introduces it (the create-time name of the per-finding path).
    endpoint_name: dict[str, str] = {}
    for finding in findings:
        endpoint_id = _endpoint_identifier(finding.location)
        if not endpoint_id:
            continue
        ident = endpoint_id[:1024]
        if ident not in endpoint_name:
            endpoint_name[ident] = finding.location[:255] or ident[:255]

    # API assets already reconciled this call (scanned host, declared scope
    # hosts) are reused rather than re-created — an endpoint that coincides with
    # one of them must not fork a second row.
    api_by_identifier: dict[str, Asset] = {
        a.identifier: a for a in touched if a.kind == Asset.Kind.API
    }
    to_load = [ident for ident in endpoint_name if ident not in api_by_identifier]
    if to_load:
        for asset in Asset.objects.filter(
            deployment=deployment, kind=Asset.Kind.API, identifier__in=to_load
        ):
            api_by_identifier[asset.identifier] = asset

    to_create: list[Asset] = []
    to_refresh: list[Asset] = []
    for ident, name in endpoint_name.items():
        existing = api_by_identifier.get(ident)
        if existing is None:
            asset = Asset(
                deployment=deployment,
                kind=Asset.Kind.API,
                identifier=ident,
                name=name,
                classification=Asset.Classification.KNOWN,
                classification_source=Asset.ClassificationSource.MACHINE,
                provider=None,
                metadata={"source": "finding_endpoint"},
                first_seen=now,
                last_seen=now,
            )
            api_by_identifier[ident] = asset
            to_create.append(asset)
        elif existing not in touched:
            # An endpoint the host/scope pass already refreshed keeps that
            # reconciliation; only endpoints new to this pass are refreshed here.
            existing.last_seen = now
            if (
                existing.classification_source == Asset.ClassificationSource.MACHINE
                and existing.classification != Asset.Classification.KNOWN
            ):
                existing.classification = Asset.Classification.KNOWN
            existing.metadata = {**(existing.metadata or {}), "source": "finding_endpoint"}
            to_refresh.append(existing)

    if to_create:
        Asset.objects.bulk_create(to_create)
    if to_refresh:
        Asset.objects.bulk_update(to_refresh, ["last_seen", "classification", "metadata"])

    for asset in to_create + to_refresh:
        if asset not in touched:
            touched.append(asset)

    # A located finding belongs to its endpoint; else an LLM finding to the
    # model, an agent finding to the agent; everything else to the host.
    changed: list[Finding] = []
    for finding in findings:
        endpoint_id = _endpoint_identifier(finding.location)
        target_asset = api_by_identifier.get(endpoint_id[:1024]) if endpoint_id else None
        target_asset = target_asset or llm_asset or agent_asset or host_asset
        if target_asset is not None and finding.asset_id != target_asset.pk:
            finding.asset = target_asset
            changed.append(finding)
    if changed:
        Finding.objects.bulk_update(changed, ["asset"])

    return touched
