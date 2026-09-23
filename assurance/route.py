"""System / Route Map — reconstruct app → gateway → model → data → tools → logs (Phase 1.6).

The data-flow diagram customers lack, and the piece that ties 1.1–1.5 together.
Discovery already recorded the *nodes* (Phase 1.1 assets), the *agent→tool edges*
(Phase 1.2, on the agent's ``metadata.tools``), the *provider* behind each
component (Phase 1.5), and each component's *layer* is implied by its kind. This
module assembles them into a layered, directed graph: the path a request and its
data take through the system.

It is honest about how strongly each edge is known:

- A **declared** edge is one the inventory actually attests — an agent that
  declares the tools it can call, a tool that declares the MCP server that hosts
  it. These are facts, not guesses.
- An **inferred** edge is the reference pipeline between populated layers (the
  app's surface routes to the model through a gateway; the orchestrator reads a
  data store; and so on). It is the shape an AI system of this composition takes,
  drawn only between layers that actually have nodes, and marked inferred so a
  reader never mistakes it for an observed flow.

It never invents a node, and it surfaces the gaps rather than papering over them:
a reference the inventory declares but discovery could not place is an
**unresolved edge** (a dangling reference to chase), an unmanaged node is a
**shadow** on the map, and an empty **logs** layer is the honest finding that
nobody can say where this system's logs go.

Declared references are resolved by :mod:`assurance.graph_refs`, which is also
what :func:`assurance.access.assess_effective_access` reads the graph with. That
module exists because these two readers used to resolve the same strings
differently, and so disagreed about which hops were real.

Computed on read (a pure function of the stored asset graph), like
:func:`assurance.boundary.assess_boundary` and
:func:`assurance.capability.assess_capabilities` — no new record, no migration.
Prefetch ``assets__provider`` on the caller side to keep it query-light. Nothing
here reaches the network.
"""

from __future__ import annotations

from .graph_refs import (
    MECHANISM_SERVER,
    MECHANISM_TOOLS,
    dangling_reference,
    resolve_reference,
)
from .models import Asset, Provider

# The canonical pipeline, front to back. The map lays nodes out in this order and
# draws the inferred spine along it.
LAYER_APP = "app"
LAYER_GATEWAY = "gateway"
LAYER_MODEL = "model"
LAYER_DATA = "data"
LAYER_TOOLS = "tools"
LAYER_LOGS = "logs"
LAYER_ORDER = [LAYER_APP, LAYER_GATEWAY, LAYER_MODEL, LAYER_DATA, LAYER_TOOLS, LAYER_LOGS]
LAYER_LABELS = {
    LAYER_APP: "Application",
    LAYER_GATEWAY: "Gateway",
    LAYER_MODEL: "Model",
    LAYER_DATA: "Data",
    LAYER_TOOLS: "Tools",
    LAYER_LOGS: "Logs",
}

# Which pipeline layer a component's kind sits in. The application layer holds the
# deployment's own surface, its orchestrating agent, and the identity it acts as.
_KIND_LAYER = {
    Asset.Kind.API: LAYER_APP,
    Asset.Kind.AGENT: LAYER_APP,
    Asset.Kind.SERVICE_ACCOUNT: LAYER_APP,
    Asset.Kind.GATEWAY: LAYER_GATEWAY,
    Asset.Kind.MODEL: LAYER_MODEL,
    Asset.Kind.VECTOR_DB: LAYER_DATA,
    Asset.Kind.DATA_STORE: LAYER_DATA,
    Asset.Kind.TOOL: LAYER_TOOLS,
    Asset.Kind.MCP_SERVER: LAYER_TOOLS,
    Asset.Kind.SKILL: LAYER_TOOLS,
    Asset.Kind.OTHER: LAYER_APP,
}


def _layer_of(asset) -> str:
    """The pipeline layer a component belongs to. A component whose provider is an
    observability/logging vendor is a logs sink regardless of its kind — that is
    the one signal that puts a node in the logs layer, which otherwise stays
    empty (and its emptiness is the finding)."""
    provider = getattr(asset, "provider", None)
    if provider is not None and provider.kind == Provider.Kind.OBSERVABILITY:
        return LAYER_LOGS
    return _KIND_LAYER.get(asset.kind, LAYER_APP)


def _node(asset, layer: str) -> dict:
    return {
        "uuid": str(asset.uuid),
        "name": asset.name,
        "kind": asset.kind,
        "kind_label": asset.get_kind_display(),
        "classification": asset.classification,
        "classification_label": asset.get_classification_display(),
        "layer": layer,
        "shadow": asset.classification == Asset.Classification.UNMANAGED,
        "provider_name": asset.provider.name if getattr(asset, "provider", None) else None,
    }


def _edge(source: str, target: str, kind: str, label: str, declared: bool) -> dict:
    return {
        "source": source,
        "target": target,
        "kind": kind,
        "label": label,
        # Declared: the inventory attests this edge. Inferred: the reference
        # pipeline shape between populated layers, never an observed flow.
        "declared": declared,
    }


def build_route_map(deployment) -> dict:
    """The full system/route map for a deployment: every component as a layered
    node, the edges between them (declared where the inventory attests one, the
    inferred pipeline spine otherwise), and an honest summary. Prefetch
    ``assets__provider`` on the caller side. Pure and side-effect-free."""
    assets = list(deployment.assets.all())

    nodes: list[dict] = []
    by_uuid: dict[str, dict] = {}
    by_identifier: dict[str, Asset] = {}
    by_name: dict[str, Asset] = {}
    layer_members: dict[str, list[Asset]] = {layer: [] for layer in LAYER_ORDER}

    for asset in assets:
        layer = _layer_of(asset)
        node = _node(asset, layer)
        nodes.append(node)
        by_uuid[str(asset.uuid)] = node
        layer_members[layer].append(asset)
        if asset.identifier:
            by_identifier.setdefault(asset.identifier, asset)
        by_name.setdefault(asset.name, asset)

    edges: list[dict] = []
    seen: set[tuple[str, str, str]] = set()
    unresolved: list[dict] = []

    def add_edge(src_asset, dst_asset, kind: str, label: str, declared: bool) -> None:
        if src_asset is None or dst_asset is None or src_asset.pk == dst_asset.pk:
            return
        key = (str(src_asset.uuid), str(dst_asset.uuid), kind)
        if key in seen:
            return
        seen.add(key)
        edges.append(_edge(str(src_asset.uuid), str(dst_asset.uuid), kind, label, declared))

    # ---- Declared edges: what the inventory actually attests. ----

    agent_assets = [a for a in assets if a.kind == Asset.Kind.AGENT]
    tool_assets = [a for a in assets if a.kind in (Asset.Kind.TOOL, Asset.Kind.MCP_SERVER, Asset.Kind.SKILL)]

    for agent in agent_assets:
        metadata = agent.metadata if isinstance(agent.metadata, dict) else {}
        for ident in metadata.get("tools") or []:
            if not str(ident or "").strip():
                continue
            target = resolve_reference(ident, by_identifier, by_name)
            if target is not None:
                add_edge(agent, target, "invokes", "invokes", declared=True)
            else:
                # A tool the agent names but discovery could not place: a dangling
                # reference to chase, surfaced rather than silently dropped.
                unresolved.append(dangling_reference(agent, ident, MECHANISM_TOOLS))

    # A component that declares the backend it is wired to → an edge to that node.
    # Every asset, not only the tool-layer ones: the `server` key is a declaration
    # wherever it appears, and this map used to read it on three kinds while
    # :mod:`assurance.access` read it on all of them — so an API naming its backend
    # was a proven hop to one reader and did not exist for the other.
    for source in assets:
        metadata = source.metadata if isinstance(source.metadata, dict) else {}
        server = str(metadata.get("server") or "").strip()
        if not server:
            continue
        host = resolve_reference(server, by_identifier, by_name)
        if host is None:
            # The reference names nothing in the inventory. This used to vanish:
            # no edge, and no unresolved row either, because only the agent→tool
            # mechanism had a channel for a miss.
            unresolved.append(dangling_reference(source, server, MECHANISM_SERVER))
        elif host.kind == Asset.Kind.MCP_SERVER:
            add_edge(source, host, "hosted_by", "hosted by", declared=True)
        else:
            # The reference resolves, but not to an MCP server — a tool wired to a
            # data store, say. That is still a declared edge, and dropping it was
            # the worse half of this defect: a hop the inventory attests, absent
            # from the map AND absent from the gaps, so the map read as complete.
            add_edge(source, host, "connects_to", "wired to", declared=True)

    # ---- Inferred spine: the reference pipeline between populated layers. ----

    # The application's front door: the scanned surface if we have it, else any
    # app-layer API, else the agent. The orchestrating brain: the agent.
    app_apis = [a for a in assets if a.kind == Asset.Kind.API]
    front = next((a for a in app_apis if (a.metadata or {}).get("source") == "scan_target"), None)
    front = front or (app_apis[0] if app_apis else None) or (agent_assets[0] if agent_assets else None)
    brain = agent_assets[0] if agent_assets else None

    models = [a for a in assets if a.kind == Asset.Kind.MODEL]
    gateways = [a for a in assets if a.kind == Asset.Kind.GATEWAY]
    data_nodes = [a for a in assets if a.kind in (Asset.Kind.VECTOR_DB, Asset.Kind.DATA_STORE)]

    # Front door → orchestrator.
    if front is not None and brain is not None:
        add_edge(front, brain, "entry", "request enters", declared=False)

    # Whoever drives the model call: the orchestrator if there is one, else the front.
    caller = brain or front

    if caller is not None:
        # caller → gateway → model, or caller → model directly.
        if gateways:
            for gw in gateways:
                add_edge(caller, gw, "routes", "routes through", declared=False)
                for model in models:
                    add_edge(gw, model, "routes", "routes to", declared=False)
        else:
            for model in models:
                add_edge(caller, model, "prompts", "prompts", declared=False)
        # caller → data (retrieval / persistence).
        for data in data_nodes:
            add_edge(caller, data, "reads", "reads/writes", declared=False)
        # If there is no agent to own the tools, the front still reaches them.
        if brain is None:
            for tool in tool_assets:
                add_edge(caller, tool, "invokes", "invokes", declared=False)

    # ---- Assemble. ----

    layers = [
        {
            "key": layer,
            "label": LAYER_LABELS[layer],
            "nodes": [by_uuid[str(a.uuid)] for a in layer_members[layer]],
        }
        for layer in LAYER_ORDER
    ]

    summary = {
        "node_count": len(nodes),
        "edge_count": len(edges),
        "declared_edges": sum(1 for e in edges if e["declared"]),
        "inferred_edges": sum(1 for e in edges if not e["declared"]),
        "shadow_nodes": sum(1 for n in nodes if n["shadow"]),
        "unresolved_edges": len(unresolved),
        "unresolved_tool_references": sum(1 for u in unresolved if u["mechanism"] == MECHANISM_TOOLS),
        "unresolved_server_references": sum(1 for u in unresolved if u["mechanism"] == MECHANISM_SERVER),
        "layers_present": [layer for layer in LAYER_ORDER if layer_members[layer]],
        # The honest gap: nobody discovered where this system's logs go.
        "logs_observed": bool(layer_members[LAYER_LOGS]),
    }

    return {
        "layers": layers,
        "nodes": nodes,
        "edges": edges,
        "unresolved": unresolved,
        "summary": summary,
    }
