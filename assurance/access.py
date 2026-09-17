"""Identity Assurance & Effective Access Discovery (Phase 3.1).

The honest inventory of **principals** — the identities that can act in a
deployment — and **what each can effectively reach**, by direct and *transitive*
paths through the asset graph. It is the input the Ripple Effect / blast-radius
assessment (Phase 2.5) consumes: before you can reason about how far a
compromise spreads, you need the ground truth of who can touch what.

Grounded in signals that already exist, nothing it must invent:

- **Principals** are the actors in the graph. A ``service_account`` asset is a
  machine identity the system acts as; an ``agent`` asset is an autonomous actor
  that chains steps and invokes tools; and the deployment's own app/model surface
  is the **base principal** when it directly wields capability-bearing tools no
  agent owns. Each principal is *managed/declared* or *shadow* (evidenced only by
  unmanaged/unknown assets), and carries a **privilege level** derived from the
  sensitive capabilities it holds (reusing :mod:`assurance.capability`:
  ``code_execution`` / ``privileged_control`` / ``financial_action`` are
  high-privilege; ``network_access`` / ``filesystem_access`` / ``data_query`` /
  ``messaging`` are elevated).

- **Effective reach** is what a principal can touch by following the graph, built
  honestly hop by hop. A principal reaches the tools it declares it invokes (an
  agent's ``metadata.tools``), each tool reaches the backend it declares it
  connects to (a tool's ``metadata.server`` — an MCP server, a data store), and a
  tool's declared permissions surface the *powers* it can exercise (execution,
  network, database, filesystem). A concrete target — an MCP server, a data
  store, a vector DB — is only reported when a **declared edge evidences every
  hop** to it; a capability-power is only reported when a declared permission
  attests it. No path is fabricated: if the graph lacks the hop, the reach is not
  claimed.

It is honest in the same way its siblings are, and enforces these invariants:

- It never claims least privilege is satisfied, and never calls an identity
  secure. There is no "pass" here — only powers, reach, and gaps.
- A **shadow** principal (evidenced only by unmanaged/unknown assets) reads as
  shadow, and its risk is raised one band (reusing ``_RISK_RAISED``), never
  hidden.
- **Privileged access** (execute code / move money / privileged control) is
  surfaced on its own at risk high; an **over-broad** principal whose reach spans
  data + execution + network is surfaced; an **orphaned** service account with no
  dependent use is surfaced; and **ungoverned reach** to an unmanaged/shadow
  target is surfaced. Concern is never smoothed away.

Computed on read (a pure function of the stored asset graph), like
:func:`assurance.capability.assess_capabilities`,
:func:`assurance.boundary.assess_boundary` and :func:`assurance.route.build_route_map`
— no new record, no migration, no timestamp in the assessment. Prefetch
``assets__provider`` on the caller side to keep it query-light. Nothing here
reaches the network.
"""

from __future__ import annotations

from collections import deque

from .capability import (
    _KIND_CAPABILITY,
    _MANAGED,
    _RISK_ORDER,
    _RISK_RAISED,
    RISK_BASELINE,
    RISK_ELEVATED,
    RISK_HIGH,
    _max_risk,
    _permission_specs,
)
from .models import Asset

# The kinds that are principals in their own right: an identity that can act.
_PRINCIPAL_KINDS = {Asset.Kind.AGENT, Asset.Kind.SERVICE_ACCOUNT}
# The kinds an agent (or the app) invokes — the reachable "action surface".
_TOOL_KINDS = {Asset.Kind.TOOL, Asset.Kind.MCP_SERVER, Asset.Kind.SKILL}
# The kinds that are data targets — a store a principal can reach and read/write.
_DATA_KINDS = {Asset.Kind.DATA_STORE, Asset.Kind.VECTOR_DB}

# Privilege bands, strongest first. Derived from the risk band of the sensitive
# capabilities a principal holds, so the vocabularies never disagree: a held
# RISK_HIGH power (code execution, money movement, privileged control) makes a
# principal high-privilege; a RISK_ELEVATED power (network, filesystem, database,
# messaging) makes it elevated; a principal with no sensitive power is standard.
PRIVILEGE_HIGH = "high"
PRIVILEGE_ELEVATED = "elevated"
PRIVILEGE_STANDARD = "standard"
_PRIVILEGE_ORDER = (PRIVILEGE_HIGH, PRIVILEGE_ELEVATED, PRIVILEGE_STANDARD)
_PRIVILEGE_BY_RISK = {
    RISK_HIGH: PRIVILEGE_HIGH,
    RISK_ELEVATED: PRIVILEGE_ELEVATED,
    RISK_BASELINE: PRIVILEGE_STANDARD,
}


def _risk_index(risk: str) -> int:
    return _RISK_ORDER.index(risk)


def _managed(asset) -> bool:
    return asset.classification in _MANAGED


def _kind_cap(kind: str) -> dict:
    """The capability a component's kind confers, or a neutral fallback so an
    unmapped kind is still surfaced as a reach rather than dropped."""
    return _KIND_CAPABILITY.get(kind) or {
        "key": "reaches",
        "label": "Reach a component",
        "category": "integration",
        "risk": RISK_BASELINE,
    }


def _asset_permission_specs(asset) -> list[tuple[str, dict]]:
    """Every ``(permission, sensitive-capability spec)`` a component declares. A
    permission that matches nothing sensitive contributes nothing here — the same
    declared permission map :mod:`assurance.capability` reads."""
    metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
    permissions = metadata.get("permissions")
    out: list[tuple[str, dict]] = []
    if isinstance(permissions, list):
        for raw in permissions:
            perm = str(raw).strip()
            if not perm:
                continue
            for spec in _permission_specs(perm):
                out.append((perm, spec))
    return out


def _resolve(ident, by_identifier: dict, by_name: dict):
    """Resolve a declared reference (a tool identifier, a server name) to the
    asset it names, or ``None`` when discovery could not place it — an
    unresolvable reference is a dangling edge, never a fabricated node."""
    key = str(ident or "").strip()
    if not key:
        return None
    return by_identifier.get(key) or by_name.get(key)


def _build_edges(assets: list, by_identifier: dict, by_name: dict) -> dict:
    """The declared asset→asset edges the inventory attests, as
    ``{source_pk: [(target_asset, hop_label, capability_key), ...]}``.

    Two declared mechanisms, both ground truth:

    - an ``agent`` invokes each asset named in its ``metadata.tools``;
    - any component connects to the backend named in its ``metadata.server``
      (an MCP server that hosts it, a data store it is wired to).

    Nothing inferred: an edge exists only where the inventory names the target and
    discovery placed it.
    """
    edges: dict[int, list[tuple]] = {}

    def add(src, tgt, hop: str, cap_key: str) -> None:
        if tgt is None or src.pk == tgt.pk:
            return
        row = edges.setdefault(src.pk, [])
        if any(existing.pk == tgt.pk for existing, _, _ in row):
            return
        row.append((tgt, hop, cap_key))

    for asset in assets:
        metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
        if asset.kind == Asset.Kind.AGENT:
            for ident in metadata.get("tools") or []:
                target = _resolve(ident, by_identifier, by_name)
                if target is not None:
                    add(asset, target, "invokes", _kind_cap(target.kind)["key"])
        server = metadata.get("server")
        if server and str(server).strip():
            target = _resolve(server, by_identifier, by_name)
            if target is not None:
                add(asset, target, "connects to", _kind_cap(target.kind)["key"])

    return edges


def _reach(first_hops: list, start_path: list, edges: dict, visited: set) -> list:
    """Breadth-first transitive closure over declared edges.

    ``first_hops`` seeds the frontier (the principal's own declared edges, or, for
    the base principal, the un-owned tools the app invokes). Returns
    ``[(asset, via_names, capability_key), ...]`` for every asset reached, each
    with the shortest declared path (``via_names``) that reaches it. ``visited``
    is threaded so a principal never reaches itself and a shared graph is walked
    once per principal."""
    out: list[tuple] = []
    queue: deque = deque()
    for target, _hop, cap in first_hops:
        if target.pk in visited:
            continue
        visited.add(target.pk)
        path = start_path + [target.name]
        out.append((target, path, cap))
        queue.append((target, path))
    while queue:
        node, path = queue.popleft()
        for target, _hop, cap in edges.get(node.pk, []):
            if target.pk in visited:
                continue
            visited.add(target.pk)
            npath = path + [target.name]
            out.append((target, npath, cap))
            queue.append((target, npath))
    return out


def _reach_entry(target, via: list, cap_key: str) -> dict:
    """One concrete-asset reach: a target the principal can touch, its declared
    via-path, the capability the last hop confers, and its risk (raised one band
    when the target itself is unmanaged — reaching an ungoverned component is
    worse than reaching a governed one)."""
    spec = _kind_cap(target.kind)
    base = spec["risk"]
    managed = _managed(target)
    risk = base if managed else _RISK_RAISED[base]
    return {
        "target": target.name,
        "target_kind": target.kind,
        "target_kind_label": target.get_kind_display(),
        "target_classification": target.classification,
        "target_managed": managed,
        "via": via,
        "capability": cap_key,
        "risk": risk,
    }


def _power_entry(asset, via_to_asset: list, perm: str, spec: dict) -> dict:
    """One capability-power reach: a sensitive power a principal can exercise via
    a declared permission on itself or a tool it reaches. Grounded in the declared
    permission string, never guessed; risk raised one band when the declaring
    component is unmanaged."""
    base = spec["risk"]
    managed = _managed(asset)
    risk = base if managed else _RISK_RAISED[base]
    return {
        "target": spec["label"],
        "target_kind": "capability",
        "target_kind_label": "Capability",
        "target_classification": None,
        "target_managed": managed,
        "via": via_to_asset + [f"permission '{perm}'"],
        "capability": spec["key"],
        "risk": risk,
    }


def _principal_dict(
    *,
    key: str,
    name: str,
    kind: str,
    kind_label: str,
    classification,
    classification_label,
    managed: bool,
    shadow: bool,
    own_asset,
    reaches_raw: list,
    is_service_account: bool,
    referenced_identities: set,
) -> dict:
    """Assemble one principal from its own asset and the assets it transitively
    reaches: its held sensitive capabilities, its effective reach (concrete
    targets + capability-powers), its identity-assurance gaps, and an honest risk
    band. Pure — reads only what was passed in."""

    # --- Held sensitive capabilities: the powers this identity wields, via its
    # own declared permissions and those of every tool it reaches. This is what
    # privilege is derived from. ---
    held: dict[str, dict] = {}

    def hold(asset, perm: str, spec: dict) -> None:
        entry = held.get(spec["key"])
        if entry is None:
            entry = {
                "key": spec["key"],
                "label": spec["label"],
                "category": spec["category"],
                "risk": spec["risk"],
                "sources": [],
            }
            held[spec["key"]] = entry
        entry["sources"].append({"asset_name": asset.name, "permission": perm})

    reach: list[dict] = []

    # The principal's own declared permissions (a service account may carry them
    # directly; an agent's own block usually does not, but is read the same way).
    if own_asset is not None:
        for perm, spec in _asset_permission_specs(own_asset):
            hold(own_asset, perm, spec)
            reach.append(_power_entry(own_asset, [name], perm, spec))

    # Concrete reaches + the powers each reached tool declares.
    for target, via, cap_key in reaches_raw:
        reach.append(_reach_entry(target, via, cap_key))
        for perm, spec in _asset_permission_specs(target):
            hold(target, perm, spec)
            reach.append(_power_entry(target, via, perm, spec))

    capabilities = sorted(
        held.values(), key=lambda c: (_risk_index(c["risk"]), c["key"])
    )
    for cap in capabilities:
        cap["sources"].sort(key=lambda s: (s["asset_name"], s["permission"]))

    # Privilege: the strongest band among the sensitive powers held.
    privilege_risk = RISK_BASELINE
    for cap in capabilities:
        privilege_risk = _max_risk(privilege_risk, cap["risk"])
    privilege_level = _PRIVILEGE_BY_RISK[privilege_risk]

    reach.sort(key=lambda r: (_risk_index(r["risk"]), r["target_kind"], r["target"]))

    # Base risk before gaps: the worst of what it can do and what it can reach.
    base_risk = privilege_risk
    for r in reach:
        base_risk = _max_risk(base_risk, r["risk"])

    held_categories = {c["category"] for c in capabilities}

    # --- Identity-assurance gaps: surfaced, never hidden. ---
    gaps: list[dict] = []

    # Privileged access: a power to execute code, move money, or exercise
    # privileged control — a RISK_HIGH sensitive capability, called out on its own.
    privileged_caps = [c["key"] for c in capabilities if c["risk"] == RISK_HIGH]
    is_privileged = bool(privileged_caps)
    if is_privileged:
        gaps.append(
            {
                "type": "privileged_access",
                "risk": RISK_HIGH,
                "detail": "Holds privileged capability: " + ", ".join(sorted(privileged_caps)),
                "capabilities": sorted(privileged_caps),
            }
        )

    # Over-broad: an effective reach spanning data + execution + network — an
    # over-broad blast surface, worse than any one power alone.
    is_over_broad = {"data", "execution", "network"} <= held_categories
    if is_over_broad:
        gaps.append(
            {
                "type": "over_broad",
                "risk": RISK_HIGH,
                "detail": "Effective reach spans data, execution and network — an over-broad "
                "blast surface.",
                "categories": sorted(held_categories),
            }
        )

    # Shadow identity: a principal evidenced only by unmanaged/unknown assets — a
    # power nobody approved. Its risk is raised one band above its base.
    if shadow:
        gaps.append(
            {
                "type": "shadow_identity",
                "risk": _RISK_RAISED[base_risk],
                "detail": "Identity is evidenced only by unmanaged/unknown assets — a power "
                "nobody approved.",
            }
        )

    # Ungoverned reach: a concrete target that is itself unmanaged/shadow.
    ungoverned = sorted(
        {r["target"] for r in reach if r["target_kind"] != "capability" and not r["target_managed"]}
    )
    if ungoverned:
        ungoverned_risk = RISK_BASELINE
        for r in reach:
            if r["target_kind"] != "capability" and not r["target_managed"]:
                ungoverned_risk = _max_risk(ungoverned_risk, r["risk"])
        gaps.append(
            {
                "type": "ungoverned_reach",
                "risk": ungoverned_risk,
                "detail": "Reaches unmanaged/shadow targets: " + ", ".join(ungoverned),
                "targets": ungoverned,
            }
        )

    # Orphaned: a service account with no dependent or declared use — no agent
    # acts under it, and it grants no reach or power. A standing credential nobody
    # uses is a gap, not a clean bill.
    is_orphaned = (
        is_service_account
        and not reach
        and not capabilities
        and name not in referenced_identities
        and (own_asset is None or own_asset.identifier not in referenced_identities)
    )
    if is_orphaned:
        gaps.append(
            {
                "type": "orphaned",
                "risk": RISK_ELEVATED,
                "detail": "Service account with no dependent or declared use — no principal acts "
                "under it.",
            }
        )

    # Principal risk: the worst of its base risk and any gap it carries.
    risk = base_risk
    for gap in gaps:
        risk = _max_risk(risk, gap["risk"])

    gaps.sort(key=lambda g: (_risk_index(g["risk"]), g["type"]))

    return {
        "key": key,
        "name": name,
        "kind": kind,
        "kind_label": kind_label,
        "classification": classification,
        "classification_label": classification_label,
        "managed": managed,
        "shadow": shadow,
        "privilege_level": privilege_level,
        "capabilities": capabilities,
        "effective_reach": reach,
        "gaps": gaps,
        "risk": risk,
        # Convenience flags the summary rolls up (not a "pass" — a concern signal).
        "privileged": is_privileged,
        "over_broad": is_over_broad,
        "orphaned": is_orphaned,
    }


def assess_effective_access(deployment) -> dict:
    """The full identity-assurance & effective-access assessment for a deployment:
    every principal, what each can effectively reach (direct and transitive), its
    identity-assurance gaps, and an honest roll-up.

    Prefetch ``assets__provider`` on the caller side. Pure and side-effect-free —
    a computed view of the stored asset graph, never a stored record."""
    assets = list(deployment.assets.all())

    by_identifier: dict[str, Asset] = {}
    by_name: dict[str, Asset] = {}
    for asset in assets:
        if asset.identifier:
            by_identifier.setdefault(asset.identifier, asset)
        by_name.setdefault(asset.name, asset)

    edges = _build_edges(assets, by_identifier, by_name)

    agents = [a for a in assets if a.kind == Asset.Kind.AGENT]
    service_accounts = [a for a in assets if a.kind == Asset.Kind.SERVICE_ACCOUNT]
    tools = [a for a in assets if a.kind in _TOOL_KINDS]

    # Identities that something acts under: an agent's declared ``identity``. Used
    # to tell an orphaned service account (nobody acts under it) from a used one.
    referenced_identities: set[str] = set()
    for agent in agents:
        metadata = agent.metadata if isinstance(agent.metadata, dict) else {}
        identity = str(metadata.get("identity") or "").strip()
        if identity:
            referenced_identities.add(identity)

    principals: list[dict] = []

    # Tools reached by some agent are "owned"; the base principal (the app itself)
    # only holds the tools no agent owns — the powers the deployment wields
    # directly.
    owned_tool_pks: set[int] = set()

    def reaches_of(start_asset) -> list:
        visited = {start_asset.pk}
        return _reach(edges.get(start_asset.pk, []), [start_asset.name], edges, visited)

    for agent in agents:
        reaches_raw = reaches_of(agent)
        for target, _via, _cap in reaches_raw:
            if target.kind in _TOOL_KINDS:
                owned_tool_pks.add(target.pk)
        principals.append(
            _principal_dict(
                key=f"asset:{agent.uuid}",
                name=agent.name,
                kind=agent.kind,
                kind_label=agent.get_kind_display(),
                classification=agent.classification,
                classification_label=agent.get_classification_display(),
                managed=_managed(agent),
                shadow=not _managed(agent),
                own_asset=agent,
                reaches_raw=reaches_raw,
                is_service_account=False,
                referenced_identities=referenced_identities,
            )
        )

    for sa in service_accounts:
        reaches_raw = reaches_of(sa)
        principals.append(
            _principal_dict(
                key=f"asset:{sa.uuid}",
                name=sa.name,
                kind=sa.kind,
                kind_label=sa.get_kind_display(),
                classification=sa.classification,
                classification_label=sa.get_classification_display(),
                managed=_managed(sa),
                shadow=not _managed(sa),
                own_asset=sa,
                reaches_raw=reaches_raw,
                is_service_account=True,
                referenced_identities=referenced_identities,
            )
        )

    # The base principal: the deployment's own app/model surface, present only
    # when it directly wields capability-bearing tools no agent owns.
    unowned_tools = [t for t in tools if t.pk not in owned_tool_pks]
    if unowned_tools:
        first_hops = [(t, "invokes", _kind_cap(t.kind)["key"]) for t in unowned_tools]
        base_reaches = _reach(first_hops, [deployment.name], edges, set())
        principals.append(
            _principal_dict(
                key=f"deployment:{deployment.uuid}",
                name=deployment.name,
                kind="deployment",
                kind_label="Deployment app/model",
                classification=None,
                classification_label=None,
                managed=True,
                shadow=False,
                own_asset=None,
                reaches_raw=base_reaches,
                is_service_account=False,
                referenced_identities=referenced_identities,
            )
        )

    # Most-concerning first: worst risk, then highest privilege, shadow before
    # managed, then name for a stable, deterministic order.
    principals.sort(
        key=lambda p: (
            _risk_index(p["risk"]),
            _PRIVILEGE_ORDER.index(p["privilege_level"]),
            not p["shadow"],
            p["name"],
        )
    )

    worst_risk = None
    for p in principals:
        worst_risk = p["risk"] if worst_risk is None else _max_risk(worst_risk, p["risk"])

    summary = {
        "principals": len(principals),
        "privileged": sum(1 for p in principals if p["privileged"]),
        "shadow": sum(1 for p in principals if p["shadow"]),
        "orphaned": sum(1 for p in principals if p["orphaned"]),
        "over_broad": sum(1 for p in principals if p["over_broad"]),
        "high_risk_reach": sum(
            1 for p in principals for r in p["effective_reach"] if r["risk"] == RISK_HIGH
        ),
        "worst_risk": worst_risk,
    }

    return {
        "principals": principals,
        "summary": summary,
    }
