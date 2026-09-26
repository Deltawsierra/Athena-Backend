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

from django.db import transaction
from django.utils import timezone

from .graph_refs import (
    IDENTITY_RULES,
    MERGED_IDENTITIES,
    RETIRED,
    TOOL_KINDS,
    identity_references,
    legacy_unnamed_agent,
    retired,
    superseded_identity,
    tool_references,
)
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
    renamed = False
    if not created and metadata and _keeps_what_it_stood_for(asset, metadata):
        metadata, classification = _merge_into_legacy_row(asset, metadata, classification, name=name)
    elif not created and metadata and metadata.get("identity_rules") == IDENTITY_RULES:
        # A declaration re-recording this key under the current rules replaces
        # whatever an older one left here: the snapshot of the old content, the
        # declaration kept beside it, the key's collision mark, a retirement --
        # and the old rules' name, if nobody has renamed the row since.
        held = asset.metadata if isinstance(asset.metadata, dict) else {}
        renamed = _takes_declared_name(asset, held.get(LEGACY_NAME), name)
        asset.metadata = {k: v for k, v in held.items() if k not in _LEGACY_BOOKKEEPING}
    if not created:
        fields = ["last_seen", "provider", "metadata"]
        if renamed:
            fields.append("name")
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


#: Set by migration 0034 on a row whose key more than one old declaration wrote:
#: read here rather than re-derived from the row, because what the row says about
#: its own server is whatever the LAST old writer said -- a plain tool written last
#: over a server-keyed one left no trace of the collapse in the row.
LEGACY_KEY = "legacy_key"
#: What an old-keyed row held under the old rules, frozen the first time a current
#: declaration lands on it; and that declaration, kept beside it. The row reads as
#: both while an old declaration may still mean it, and as the current one alone
#: once none can (:func:`_settle_legacy_rows`).
LEGACY_CONTENT = "legacy_content"
DECLARED_CONTENT = "declared_content"
#: The classification that declaration asked for, before a merge held it to the
#: old row's: what the row is again once it is that declaration alone.
DECLARED_CLASSIFICATION = "declared_classification"
#: The name the row had when a current declaration first landed on it, and the
#: name that declaration gives the key. The name is written once, at creation, so
#: a row settled to a declaration kept the old one -- a tool keyed ``github`` still
#: called ``create_issue``, a name another component really has -- and every view
#: that labels a path by name described the wrong tool. Renamed only while it still
#: carries the name the old rules gave it: a person's rename is theirs.
LEGACY_NAME = "legacy_name"
DECLARED_NAME = "declared_name"
#: Set by the admin when a person renames an asset (like ``classification_source``
#: for a classification): a name a person gave a row is theirs, and no settle or
#: re-declaration renames it. Not bookkeeping -- it stays for the row's life. The
#: legacy-name comparison alone could not tell: a person who renamed the row before
#: any declaration landed on it left their name as the one frozen at the merge.
NAMED_BY_HAND = "named_by_hand"
_LEGACY_BOOKKEEPING = frozenset(
    {LEGACY_KEY, LEGACY_CONTENT, DECLARED_CONTENT, DECLARED_CLASSIFICATION, DECLARED_NAME, LEGACY_NAME, RETIRED}
)
#: Set on every row the old rules wrote that a declaration has since settled, and
#: kept for good (it is not bookkeeping a current write clears). Such a row is
#: retired whenever nothing names it, current or not: settled first and dropped
#: after, it used to stay as a tool nobody owned, while the same declarations in
#: the other order retired it -- one set of declarations, two graphs.
LEGACY_ORIGIN = "legacy_origin"

#: What a retired row says about itself.
RETIRED_WHY = (
    "No declaration names this row any more: every agent that named its key has been "
    "recorded under the current identity rules, and none names it now. (The row the old "
    "rules wrote for every unnamed agent at once is not counted: a rescan records each "
    "unnamed agent under a row of its own.)"
)


def _legacy_key(asset: Asset) -> bool:
    """Whether ``asset``'s key is one the old identity rules gave to more than one
    declaration at once: the literal ``"agent"`` every unnamed agent was written
    to, a server's key every tool on that server was written to, or a key
    migration 0034 found more than one old declaration naming."""
    metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
    if metadata.get(LEGACY_KEY) is True:
        return True
    if asset.kind == Asset.Kind.AGENT:
        return asset.identifier == "agent"
    if asset.kind == Asset.Kind.MCP_SERVER:
        return False
    server = str(metadata.get("server") or "").strip()
    return bool(server) and asset.identifier == server[:IDENTIFIER_MAX]


def _keeps_what_it_stood_for(asset: Asset, metadata: dict) -> bool:
    """Whether a declaration landing on ``asset`` must merge into it rather than
    replace it: the row carries an older identity-rules stamp, its key is a
    :func:`_legacy_key`, and the declaration does not cover everything the row
    holds.

    A different agent's scan could declare a tool under a key an old collapsed
    row held, and the refresh replaced that row's permissions and stamped it
    current: the agent the old row served, not yet rescanned, lost its ``shell``
    with no reason left anywhere to say so.

    Covering is the test, not the row's name. The name is written once, when the
    row is created, and the old rules went on replacing the permissions under it
    -- so a row can carry the name of one declaration and the powers of another,
    and a name that matched let a scan stamp such a row and drop the powers it
    did not know about. A declaration that holds every permission and tool the
    row holds, and names the same identity and server where the row names one,
    replaces nothing anyone depended on; anything less merges, and the row stays
    reported until something that covers it is declared.
    """
    if not superseded_identity(asset) or not _legacy_key(asset) or retired(asset):
        return False
    if asset.kind in (Asset.Kind.TOOL, Asset.Kind.SKILL):
        # Settled after the declaration, not here. A covering write stamped the row
        # current on the spot, while another agent not yet rescanned still named its
        # key under the old rules -- and that agent then reached the new
        # declaration's powers with nothing reported. Whether an old declaration can
        # still mean the row is known once this one is recorded
        # (:func:`_settle_legacy_rows`).
        return True
    return not _covers(metadata, _legacy_content(asset))


def _legacy_content(asset: Asset) -> dict:
    """What ``asset`` held under the old rules: the frozen snapshot once a current
    declaration has merged into it, else the row as it stands."""
    metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
    frozen = metadata.get(LEGACY_CONTENT)
    return frozen if isinstance(frozen, dict) else metadata


def _covers(declared: dict, held: dict) -> bool:
    """Whether ``declared`` holds everything ``held`` does: every permission and
    tool, and the same identity and server wherever ``held`` names one. A row that
    already merged a second identity stands for two declarations, and no single
    declaration covers two."""
    for key in ("permissions", "tools"):
        have = {str(v) for v in held.get(key) or [] if isinstance(v, str)}
        if not have <= {str(v) for v in declared.get(key) or [] if isinstance(v, str)}:
            return False
    for key in ("identity", "server"):
        was = str(held.get(key) or "").strip()
        if was and was != str(declared.get(key) or "").strip():
            return False
    return not held.get(MERGED_IDENTITIES)


def _takes_declared_name(asset: Asset, legacy_name, declared_name) -> bool:
    """Rename ``asset`` to ``declared_name`` if it still carries ``legacy_name``,
    the name the old rules gave it; True if it was renamed."""
    wanted = str(declared_name or "").strip()[:255]
    held = asset.metadata if isinstance(asset.metadata, dict) else {}
    if held.get(NAMED_BY_HAND) is True:
        return False
    if not wanted or not isinstance(legacy_name, str) or asset.name != legacy_name or asset.name == wanted:
        return False
    asset.name = wanted
    return True


def _merge_into_legacy_row(
    asset: Asset, metadata: dict, classification: str, *, name: str = ""
) -> tuple[dict, str]:
    """``(metadata, classification)`` for a declaration merging into a legacy row:
    its permissions and tools added to the row's, its identity beside the row's
    own (:data:`graph_refs.MERGED_IDENTITIES`), its server only where the row had
    none, the row's older stamp kept -- so every reference to it is still
    reported until something that is the same declaration re-records it -- and
    approved only if the row already was.

    Merged over what the row held under the OLD rules (:data:`LEGACY_CONTENT`), not
    over the row as it stands: that already holds the last declaration to land
    here, so merging over it kept every power any declaration ever gave the key --
    a permission dropped from the declaration stayed on the row through every
    rescan. The old content is frozen the first time; the declaration is kept
    beside it (:data:`DECLARED_CONTENT`) for when nothing old can mean the row."""
    old = _legacy_content(asset)
    held = asset.metadata if isinstance(asset.metadata, dict) else {}
    merged = {k: v for k, v in metadata.items() if k != "identity_rules"}
    merged[LEGACY_CONTENT] = {
        k: v for k, v in old.items() if k not in _LEGACY_BOOKKEEPING and k not in (LEGACY_ORIGIN, NAMED_BY_HAND)
    }
    merged[DECLARED_CONTENT] = dict(metadata)
    merged[DECLARED_CLASSIFICATION] = classification
    merged[DECLARED_NAME] = str(name or "").strip()[:255]
    merged[LEGACY_NAME] = held.get(LEGACY_NAME) if isinstance(held.get(LEGACY_NAME), str) else asset.name
    merged[LEGACY_ORIGIN] = True
    for key in ("permissions", "tools"):
        if key in merged:
            union = [str(v) for v in old.get(key) or [] if isinstance(v, str)]
            union += [v for v in merged[key] if v not in union]
            merged[key] = union
    # What made the row a legacy key stays with it, or the next declaration to
    # land here would find an ordinary row and replace it after all.
    if str(old.get("server") or "").strip():
        merged.pop("server", None)
    # Every identity it was declared with stays. The literal "agent" row stood for
    # every unnamed agent, so the one landing now can name another account --
    # keeping only the first dropped that account's powers from the agent, and
    # keeping only the last dropped the first's. Both readers follow each one.
    identities = identity_references(old)
    arriving = str(merged.get("identity") or "").strip()
    if identities:
        merged["identity"] = identities[0]
        extra = [i for i in [*identities[1:], arriving] if i and i != identities[0]]
        merged[MERGED_IDENTITIES] = list(dict.fromkeys(extra))
        if not merged[MERGED_IDENTITIES]:
            merged.pop(MERGED_IDENTITIES)
    if classification == Asset.Classification.APPROVED and asset.classification != Asset.Classification.APPROVED:
        classification = Asset.Classification.KNOWN
    return merged, classification


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
    A target without a scheme is read as https, the way :func:`ingest._host`
    reads it, rather than passed through whole; a port is its number, so
    ``:0443`` is 443.
    An IPv6 host keeps its brackets, or ``[2001:db8::1]:8443`` and
    ``[2001:db8::1:8443]`` are one anchor. A port the URL parser rejects is
    kept as written rather than letting the whole target through. A target with
    no host has nowhere to anchor an agent, and gets no agent node.
    """
    loc = (target or "").strip()
    if not loc or loc.startswith("/"):
        return ""
    try:
        parsed = urlparse(loc if "://" in loc else f"https://{loc}")
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
    # ASCII digits only: `str.isdigit` accepts "²" and "①", which `int` refuses,
    # and the anchor raised out of the scan's derivation instead of keeping the
    # port as written.
    if port.isascii() and port.isdigit():
        port = str(int(port))
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
    if server:
        # A tool with no name, on a server: `@server`, never the server's bare
        # name. As the bare name it was the same key as a tool NAMED for that
        # server and declared without one -- two components, one row, and the
        # second agent's scan replaced the first one's `shell` on a fresh
        # deployment with nothing to say it had.
        return f"@{server}"
    return name


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
    tool_kinds: dict[str, list[str]] = {}
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
            if kind not in tool_kinds.setdefault(identifier, []):
                tool_kinds[identifier].append(kind)

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
                # And what kind each one was declared as, so the edge reaches what
                # this declaration wrote under the key and nothing else carrying it.
                TOOL_KINDS: {k: sorted(v) for k, v in tool_kinds.items()},
            },
        )
        if agent_asset:
            touched.append(agent_asset)

    if touched:
        _settle_legacy_rows(deployment, now)
    return agent_asset, touched


def _settle_legacy_rows(deployment: Deployment, now) -> None:
    """Re-read every old-keyed tool row now that a declaration has been recorded.

    A row the old rules keyed at a server stood for the old declarations that named
    that key. While any of them may still mean it -- an agent row not re-recorded
    since, or recorded before rows said what kind each tool was -- it stays as it
    is: followed, reported, its powers counted. Once none can, it stands for
    nothing old: a row a current declaration also landed on becomes that
    declaration alone, and a row nothing declares is retired, its powers cleared --
    then or later: a settled row whose last declaration drops the key is retired
    too, so the same declarations settle the same way in any order.

    It never used to settle. The current rules write a tool on a server as
    ``name@server``, so no rescan ever touched the old row again, and a permission
    the inventory had since removed -- a ``shell`` -- stayed in the agent's reach for
    good while the page asked for the rescan that had already happened.

    Rows are never deleted: findings and a human classification still point at
    them, and a retired row returns the moment a declaration writes its key.
    """
    rows = Asset.objects.filter(deployment=deployment, metadata__source="declared_inventory")
    if transaction.get_connection().in_atomic_block:
        # Locked for the read-decide-write below: two scans settling one deployment
        # at once each decided on a copy the other was about to change, and the
        # second save undid the first -- a retirement over a fresh declaration, or
        # the reverse.
        rows = rows.select_for_update()
    rows = list(rows)
    # Keys a declaration recorded under the OLD rules may still mean, and the keys
    # -- with the kinds -- a declaration recorded under the current rules names.
    old_references: set[str] = set()
    current_references: set[tuple[str, str]] = set()
    for agent in rows:
        if agent.kind != Asset.Kind.AGENT or retired(agent):
            continue
        if legacy_unnamed_agent(agent):
            # The row the old rules wrote for every unnamed agent at once holds
            # nothing in place. No rescan ever records it again -- the current rules
            # record each unnamed agent under a row of its own -- so counting what
            # it names kept every row it named merged for good: a named agent that
            # dropped ``shell`` from a tool it shared with it reached ``shell``
            # through every rescan, and the page asked for another. What it names
            # is read as the graph holds it now, and reported as its (see
            # ``graph_refs.UNRESOLVED_LEGACY_UNNAMED``).
            continue
        metadata = agent.metadata if isinstance(agent.metadata, dict) else {}
        kinds = metadata.get(TOOL_KINDS)
        if superseded_identity(agent) or not isinstance(kinds, dict):
            old_references.update(
                str(r).strip() for r in tool_references(metadata) if isinstance(r, str) and str(r).strip()
            )
        else:
            current_references.update(
                (str(key), kind) for key, listed in kinds.items() if isinstance(listed, list)
                for kind in listed if isinstance(kind, str)
            )

    for row in rows:
        if row.kind not in (Asset.Kind.TOOL, Asset.Kind.SKILL) or retired(row):
            continue
        metadata = row.metadata if isinstance(row.metadata, dict) else {}
        if superseded_identity(row):
            if not _legacy_key(row):
                continue
        elif metadata.get(LEGACY_ORIGIN) is not True:
            # A row only the current rules ever wrote is theirs to keep.
            continue
        if row.identifier in old_references:
            continue
        if not superseded_identity(row):
            # Settled before, and current: it stays while a current declaration
            # names it, and is retired the moment none does -- as it would have
            # been had its last declarer dropped the key before the row settled.
            if (row.identifier, row.kind) in current_references:
                continue
            declared = None
        else:
            declared = metadata.get(DECLARED_CONTENT)
        fields = ["metadata"]
        if (
            isinstance(declared, dict)
            and declared.get("identity_rules") == IDENTITY_RULES
            and (row.identifier, row.kind) in current_references
        ):
            # What a current declaration wrote under this key, and still names --
            # under the name it gives the key, unless a person renamed the row.
            if _takes_declared_name(row, metadata.get(LEGACY_NAME), metadata.get(DECLARED_NAME)):
                fields.append("name")
            row.metadata = {
                **declared,
                LEGACY_ORIGIN: True,
                **({NAMED_BY_HAND: True} if metadata.get(NAMED_BY_HAND) is True else {}),
            }
            wanted = metadata.get(DECLARED_CLASSIFICATION)
            if (
                row.classification_source == Asset.ClassificationSource.MACHINE
                and isinstance(wanted, str)
                and wanted != row.classification
            ):
                row.classification = wanted
                fields.append("classification")
        else:
            # Nothing names it: no old declaration, and no current one -- a current
            # declaration that once landed here and has since dropped the key is not
            # a reason to bring it back as a tool nobody owns.
            row.metadata = {
                **{k: v for k, v in metadata.items() if k not in (DECLARED_CONTENT, DECLARED_CLASSIFICATION)},
                "permissions": [],
                LEGACY_ORIGIN: True,
                # The name the old rules gave it, if nothing recorded one yet: a
                # declaration that writes the key again renames it (see above).
                LEGACY_NAME: metadata.get(LEGACY_NAME) if isinstance(metadata.get(LEGACY_NAME), str) else row.name,
                RETIRED: {"at": now.isoformat(), "why": RETIRED_WHY},
            }
        row.save(update_fields=fields)


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
