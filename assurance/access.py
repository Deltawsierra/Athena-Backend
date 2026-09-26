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
from .graph_refs import (
    INVOKED_KINDS,
    MECHANISM_IDENTITY,
    MECHANISM_SERVER,
    PRINCIPAL_KINDS,
    MECHANISM_TOOLS,
    identity_index,
    identity_references,
    in_graph,
    legacy_unnamed_agent,
    resolve_identity,
    reference_index,
    resolve_reference,
    resolve_tool,
    superseded_identity,
    unresolved_row,
    sort_references,
    tool_references,
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




def _build_edges(assets: list, by_identifier: dict, by_name: dict) -> tuple[dict, list]:
    """The declared asset→asset edges the inventory attests, plus the references
    it could not place.

    Returns ``({source_pk: [(target_asset, hop_label, capability_key), ...]},
    [dangling reference, ...])``.

    Two declared mechanisms, both ground truth:

    - an ``agent`` invokes each asset named in its ``metadata.tools``;
    - an ``agent`` acts as the service account its ``metadata.identity`` names,
      and so holds every power that account holds. An agent acting as an
      account with admin rights has admin rights; the reach used to stop at
      the agent's own tools, so the account's powers were nobody's;
    - any component connects to the backend named in its ``metadata.server``
      (an MCP server that hosts it, a data store it is wired to).

    Nothing inferred: an edge exists only where the inventory names the target and
    discovery placed it. And nothing dropped: a reference that resolves to no
    asset is returned as a dangling reference rather than skipped. It used to be
    skipped, which made an inventory pointing at a component nobody can find
    indistinguishable from an inventory that pointed at nothing.
    """
    edges: dict[int, list[tuple]] = {}
    unresolved: list[dict] = []
    accounts = identity_index(assets)

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
            for ident in tool_references(metadata):
                if not str(ident or "").strip():
                    continue
                targets, why = resolve_tool(metadata, ident, by_identifier, by_name)
                for target in targets:
                    add(asset, target, "invokes", _kind_cap(target.kind)["key"])
                row = unresolved_row(asset, ident, MECHANISM_TOOLS, targets, why)
                if row is not None:
                    unresolved.append(row)
            for identity in identity_references(metadata):
                targets, why = resolve_identity(identity, accounts)
                for target in targets:
                    add(asset, target, "acts as", _kind_cap(target.kind)["key"])
                row = unresolved_row(asset, identity, MECHANISM_IDENTITY, targets, why)
                if row is not None:
                    unresolved.append(row)
        server = metadata.get("server")
        if server and str(server).strip():
            targets, why = resolve_reference(
                server, by_identifier, by_name, not_kinds=PRINCIPAL_KINDS, skip_kinds=INVOKED_KINDS
            )
            for target in targets:
                add(asset, target, "connects to", _kind_cap(target.kind)["key"])
            row = unresolved_row(asset, server, MECHANISM_SERVER, targets, why)
            if row is not None:
                unresolved.append(row)

    return edges, unresolved


def _reach(first_hops: list, start_path: list, start_keys: list, edges: dict, visited: set) -> list:
    """Breadth-first transitive closure over declared edges.

    ``first_hops`` seeds the frontier (the principal's own declared edges, or, for
    the base principal, the un-owned tools the app invokes). Returns
    ``[(asset, via_names, via_keys, capability_key), ...]`` for every asset
    reached, each with the shortest declared path that reaches it — ``via_names``
    for display and ``via_keys`` (the uuid of every hop, in parallel) as the stable
    per-node key, since asset names are not unique. ``start_path``/``start_keys``
    seed the path with the origin node (its name and uuid). ``visited`` is threaded
    so a principal never reaches itself and a shared graph is walked once per
    principal."""
    out: list[tuple] = []
    queue: deque = deque()
    for target, _hop, cap in first_hops:
        if target.pk in visited:
            continue
        visited.add(target.pk)
        path = start_path + [target.name]
        keys = start_keys + [str(target.uuid)]
        out.append((target, path, keys, cap))
        queue.append((target, path, keys))
    while queue:
        node, path, keys = queue.popleft()
        for target, _hop, cap in edges.get(node.pk, []):
            if target.pk in visited:
                continue
            visited.add(target.pk)
            npath = path + [target.name]
            nkeys = keys + [str(target.uuid)]
            out.append((target, npath, nkeys, cap))
            queue.append((target, npath, nkeys))
    return out


def _reach_entry(target, via: list, via_keys: list, cap_key: str) -> dict:
    """One concrete-asset reach: a target the principal can touch, its declared
    via-path, the capability the last hop confers, and its risk (raised one band
    when the target itself is unmanaged — reaching an ungoverned component is
    worse than reaching a governed one).

    ``target``/``via`` carry the human-readable names for display; ``target_uuid``
    and ``via_keys`` (parallel to ``via``) carry the stable per-node uuid keys so a
    consumer that slices or indexes a path does so by a unique key, never a
    non-unique name."""
    spec = _kind_cap(target.kind)
    base = spec["risk"]
    managed = _managed(target)
    risk = base if managed else _RISK_RAISED[base]
    return {
        "target": target.name,
        "target_uuid": str(target.uuid),
        "target_kind": target.kind,
        "target_kind_label": target.get_kind_display(),
        "target_classification": target.classification,
        "target_managed": managed,
        "via": via,
        "via_keys": via_keys,
        "capability": cap_key,
        "risk": risk,
    }


def _power_entry(asset, via_to_asset: list, via_keys_to_asset: list, perm: str, spec: dict) -> dict:
    """One capability-power reach: a sensitive power a principal can exercise via
    a declared permission on itself or a tool it reaches. Grounded in the declared
    permission string, never guessed; risk raised one band when the declaring
    component is unmanaged.

    The target is a capability, not an asset, so ``target_uuid`` is ``None``;
    ``via_keys`` stays parallel to ``via`` (the declaring component's uuid path plus
    the same permission marker) so a consumer can slice it by uuid."""
    base = spec["risk"]
    managed = _managed(asset)
    risk = base if managed else _RISK_RAISED[base]
    perm_marker = f"permission '{perm}'"
    return {
        "target": spec["label"],
        "target_uuid": None,
        "target_kind": "capability",
        "target_kind_label": "Capability",
        "target_classification": None,
        "target_managed": managed,
        "via": via_to_asset + [perm_marker],
        "via_keys": via_keys_to_asset + [perm_marker],
        "capability": spec["key"],
        "risk": risk,
    }


#: How an agent's declared identity names a service account it did not name
#: alone. See :func:`_identity_use`.
IDENTITY_PROVEN = "proven"
IDENTITY_AMBIGUOUS = "ambiguous"
#: Named by an agent row no scan has recorded under the current identity rules.
IDENTITY_UNRECORDED = "unrecorded"
#: Named only by the row the old rules wrote for every unnamed agent -- which,
#: unlike any other unrecorded row, a rescan does not re-record: it records each
#: unnamed agent under a row of its own.
IDENTITY_LEGACY = "legacy"
_USE_RANK = {IDENTITY_LEGACY: 0, IDENTITY_UNRECORDED: 1, IDENTITY_AMBIGUOUS: 2, IDENTITY_PROVEN: 3}


def _identity_use(agents, service_accounts) -> dict:
    """``{service_account_pk: IDENTITY_PROVEN | IDENTITY_AMBIGUOUS}`` for every
    service account some agent's declared ``identity`` resolves to.

    Resolved the way every other reference in the graph is
    (:func:`graph_refs.resolve_reference`): identifier first, then name, and an
    identifier that matches never falls through to a name. Only service accounts
    are candidates -- an identity is the account an agent acts as, so a tool or
    a store that happens to share the string is not one.

    One candidate is a proven use. More than one is ambiguous for each of them,
    unless another agent's identity names that account alone: a proven use is
    not undone by an ambiguous one.
    """
    accounts = identity_index(service_accounts)
    use: dict = {}

    def note(account, level: str) -> None:
        # The strongest use any agent makes of the account stands: proven over
        # ambiguous over unrecorded. Keeping the first one seen let the old unnamed
        # row -- first by name -- mark an account "unrecorded" and say no current
        # agent names it, while one did.
        if _USE_RANK[level] > _USE_RANK.get(use.get(account.pk), -1):
            use[account.pk] = level

    for agent in agents:
        metadata = agent.metadata if isinstance(agent.metadata, dict) else {}
        # An agent row no scan has recorded under the current identity rules --
        # the old unnamed "agent", standing for every unnamed agent at once --
        # does not prove anyone acts under the account it names. It kept an
        # orphaned account reading as used, with nothing anywhere to say why.
        unrecorded = superseded_identity(agent)
        for identity in identity_references(metadata):
            candidates, why = resolve_identity(identity, accounts)
            for account in candidates:
                if why is None and not unrecorded:
                    note(account, IDENTITY_PROVEN)
                elif why is None:
                    note(account, IDENTITY_LEGACY if legacy_unnamed_agent(agent) else IDENTITY_UNRECORDED)
                else:
                    note(account, IDENTITY_AMBIGUOUS)
    return use


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
    acted_under: str | None = None,
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
        own_keys = [str(own_asset.uuid)]
        for perm, spec in _asset_permission_specs(own_asset):
            hold(own_asset, perm, spec)
            reach.append(_power_entry(own_asset, [name], own_keys, perm, spec))

    # Concrete reaches + the powers each reached tool declares.
    for target, via, via_keys, cap_key in reaches_raw:
        reach.append(_reach_entry(target, via, via_keys, cap_key))
        for perm, spec in _asset_permission_specs(target):
            hold(target, perm, spec)
            reach.append(_power_entry(target, via, via_keys, perm, spec))

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
    #
    # ``acted_under`` is how an agent's declared identity resolved to THIS
    # account (see ``_identity_use``), never a string compared to its name: a
    # second account that merely shared the name used to count as used, so the
    # real orphan hid behind its namesake.
    unused = is_service_account and not reach and not capabilities
    is_orphaned = unused and acted_under is None
    if is_orphaned:
        gaps.append(
            {
                "type": "orphaned",
                "risk": RISK_ELEVATED,
                "detail": "Service account with no dependent or declared use — no principal acts "
                "under it.",
            }
        )
    elif unused and acted_under in (IDENTITY_AMBIGUOUS, IDENTITY_UNRECORDED, IDENTITY_LEGACY):
        # Neither orphaned nor used: an agent acts under an identity this account
        # and another both answer to, or an agent row no scan has re-recorded names
        # it. Calling it orphaned says nobody acts under it; calling it used says
        # someone does. The inventory says neither -- and says which of the two
        # it is, because they are fixed differently.
        if acted_under == IDENTITY_AMBIGUOUS:
            detail = (
                "An agent acts under an identity more than one service account answers "
                "to, and the inventory does not say which — no principal is proven to act "
                "under this one."
            )
        elif acted_under == IDENTITY_LEGACY:
            detail = (
                "The only agent naming this account is the row the old identity rules "
                "wrote for every unnamed agent at once, and a rescan records each unnamed "
                "agent under a row of its own, not that one — no principal is proven to act "
                "under this account."
            )
        else:
            detail = (
                "The only agent naming this account is recorded under identity rules no "
                "scan has re-recorded it under since — no principal is proven to act under "
                "it until that agent is scanned again."
            )
        gaps.append({"type": "use_unproven", "risk": RISK_ELEVATED, "detail": detail})

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
    assets = in_graph(deployment.assets.all())

    by_identifier, by_name = reference_index(assets)

    edges, unresolved = _build_edges(assets, by_identifier, by_name)
    unresolved = sort_references(unresolved)

    agents = [a for a in assets if a.kind == Asset.Kind.AGENT]
    service_accounts = [a for a in assets if a.kind == Asset.Kind.SERVICE_ACCOUNT]
    tools = [a for a in assets if a.kind in _TOOL_KINDS]

    identity_use = _identity_use(agents, service_accounts)

    principals: list[dict] = []

    # Tools reached by some agent are "owned"; the base principal (the app itself)
    # only holds the tools no agent owns — the powers the deployment wields
    # directly.
    owned_tool_pks: set[int] = set()

    def reaches_of(start_asset) -> list:
        visited = {start_asset.pk}
        return _reach(
            edges.get(start_asset.pk, []),
            [start_asset.name],
            [str(start_asset.uuid)],
            edges,
            visited,
        )

    for agent in agents:
        reaches_raw = reaches_of(agent)
        for target, _via, _keys, _cap in reaches_raw:
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
                acted_under=identity_use.get(sa.pk),
            )
        )

    # The base principal: the deployment's own app/model surface, present only
    # when it directly wields capability-bearing tools no agent owns.
    unowned_tools = [t for t in tools if t.pk not in owned_tool_pks]
    if unowned_tools:
        first_hops = [(t, "invokes", _kind_cap(t.kind)["key"]) for t in unowned_tools]
        base_reaches = _reach(first_hops, [deployment.name], [str(deployment.uuid)], edges, set())
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
        # How much of the graph this assessment could not resolve. A reach
        # computed over a graph with dangling references is a reach over an
        # incomplete graph, and a reader is entitled to know that before
        # treating "no high-risk reach" as reassurance.
        "unresolved_references": len(unresolved),
        "worst_risk": worst_risk,
    }

    return {
        "principals": principals,
        # References the inventory declares and discovery could not place. This
        # assessment had no channel for them at all: `_resolve` returned None and
        # the caller moved on, so an agent naming a tool that is not in the
        # inventory produced no edge, no gap and no count -- an absence of
        # evidence that read as evidence of absence.
        "unresolved": unresolved,
        "summary": summary,
    }
