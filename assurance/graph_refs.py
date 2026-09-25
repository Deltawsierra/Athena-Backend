"""How a declared reference between two components is resolved, in one place.

Every edge in the assurance graph is a STRING inside ``Asset.metadata`` -- an
agent's ``tools`` list names tools, a component's ``server`` names the backend it
is wired to -- resolved at read time against the deployment's own inventory.
There are no foreign keys between assets, so this resolution IS the graph.

Two modules read that graph and they resolved it differently, which meant they
disagreed about what the graph was. Measured, on the same deployment:

    a tool the agent names by NAME rather than identifier
        assurance.access   a proven hop
        assurance.route    zero edges, one unresolved row

    a `server` pointing at a data store rather than an MCP server
        assurance.access   a proven hop
        assurance.route    zero edges, and NOTHING in unresolved -- it vanished

    a `server` naming something that does not exist
        assurance.access   nothing at all: no edge, no gap, no count
        assurance.route    nothing at all

The last one is the worst of the three and it is the reason this module exists.
An unresolvable reference is a fact: the inventory names a component that
discovery could not place. Dropping it silently is the platform's own governing
defect -- a gap that reads as an absence of gaps. Both readers now record it, in
one shape, so "the inventory points at something we cannot find" is a thing an
operator can be told rather than something only the code knew.

The resolution order is identifier first, then name. The identifier is the
dedup key (``UniqueConstraint(deployment, kind, identifier)``); the name is not
unique, so it is the fallback and never the first answer. A key that more than
one asset carries is followed to all of them and ALSO reported as ambiguous:
picking one would make the graph depend on the order rows come back in, and
following none would let a duplicate name hide a reach. A reference is matched
against the assets of ONE deployment; nothing here can reach across a boundary.
"""

from __future__ import annotations

# The two mechanisms by which the inventory declares an edge. Named so an
# unresolved row says which kind of reference failed -- an agent naming a tool it
# cannot reach is a different conversation from a component naming a backend that
# is not there.
MECHANISM_TOOLS = "tools"
MECHANISM_SERVER = "server"

#: The kinds that are principals: something that acts, not something acted on.
#: Spelled as the ``Asset.Kind`` values so this module stays free of the models.
PRINCIPAL_KINDS = frozenset({"agent", "service_account"})


#: Why a reference could not be placed. A reference that names nothing and one
#: that names two things are both unresolved, and they are different
#: conversations: the first is a component discovery never found, the second is
#: an inventory that does not say which of two components it means.
UNRESOLVED_NOT_FOUND = "not_found"
UNRESOLVED_AMBIGUOUS = "ambiguous"
#: A reference names something that exists but is a principal -- an agent, a
#: service account -- which is neither a backend anything can be wired to nor a
#: tool anything can invoke.
UNRESOLVED_NAMES_A_PRINCIPAL = "names_a_principal"


def reference_index(assets) -> tuple[dict, dict]:
    """``(by_identifier, by_name)`` over one deployment's assets, each mapping a key
    to EVERY asset that carries it.

    Every asset, not the first one seen. Both readers used to build these with
    ``setdefault``, so when two assets shared a name the reference resolved to
    whichever the database returned first -- a primary-key tie-break nothing
    else in the graph can see. Deleting a component and recreating it
    identically could turn a proven hop to a managed store into one to an
    unmanaged one, with no change anyone could point to, and on Postgres the
    same rows can come back in either order. A reference that could mean two
    components does not get to mean one of them by accident.
    """
    by_identifier: dict[str, list] = {}
    by_name: dict[str, list] = {}
    for asset in assets:
        if asset.identifier:
            by_identifier.setdefault(asset.identifier, []).append(asset)
        by_name.setdefault(asset.name, []).append(asset)
    return by_identifier, by_name


def resolve_reference(reference, by_identifier: dict, by_name: dict, *, not_kinds=frozenset()):
    """``(candidates, reason)``: every asset a declared reference could name, and
    why it did not name exactly one.

    Identifier first, then name. One match is ``([asset], None)``. No match is
    ``([], UNRESOLVED_NOT_FOUND)``. More than one -- a shared name, or an
    identifier two kinds both carry -- is every candidate with
    ``UNRESOLVED_AMBIGUOUS``: the reference is followed to ALL of them AND
    recorded as unresolved. Picking one made the graph depend on row order;
    following none let a second same-named component launder a verdict -- one
    unmanaged ``warehouse`` read as ungoverned reach, two of them read as nothing
    reached at all. Following every candidate means the reading is never milder
    than any way the reference could be resolved, and the unresolved row still
    says the inventory does not say which one it meant. A reference whose
    identifier matches does not fall through to a name.

    ``not_kinds`` are kinds this mechanism cannot mean. A ``server`` is a backend
    something is wired to; it is never an agent or a service account, and
    resolving it to one made that principal a hop -- so a data store that shared
    its name with an agent put the agent's tools inside another agent's reach and
    named an agent that gained no power as privileged. The same holds for an
    agent's ``tools``: every entry is a tool the declaration itself wrote as a
    tool row, so a principal carrying the same key is a collision, not a callee,
    and following it handed one agent every power of another. Candidates of those
    kinds are dropped before the rest are followed; a reference that names only
    such a thing is unresolved and says so.

    An empty list is not permission to invent a node, and it is not permission to
    say nothing either: the caller records the reason.
    """
    key = str(reference or "").strip()
    if not key:
        return [], UNRESOLVED_NOT_FOUND
    for index in (by_identifier, by_name):
        matches = index.get(key)
        if matches:
            usable = [m for m in matches if m.kind not in not_kinds]
            if not usable:
                return [], UNRESOLVED_NAMES_A_PRINCIPAL
            return usable, (UNRESOLVED_AMBIGUOUS if len(usable) > 1 else None)
    return [], UNRESOLVED_NOT_FOUND


#: What a malformed ``tools`` declaration is reported as, in place of the
#: references it does not contain.
MALFORMED_TOOLS = "tools (not a list)"


def tool_references(metadata: dict) -> list:
    """The tool references a ``tools`` declaration holds -- or one finding saying it
    is not a list.

    ``metadata["tools"]`` is meant to be a list of strings. A string is a plausible
    typo for a one-element list (``"reader"`` for ``["reader"]``) and iterating it
    yields its CHARACTERS: six manufactured gaps from one mistyped field, each
    counted in both readers' summaries, and -- since resolution falls back to a
    name -- a single character matching an asset's name becomes a declared hop.
    Manufacturing findings is the same defect as dropping them, pointed the other
    way, so a malformed declaration is reported as exactly that: one thing wrong,
    which is what it is.
    """
    raw = metadata.get("tools")
    if raw is None:
        return []
    if isinstance(raw, (list, tuple)):
        return list(raw)
    return [MALFORMED_TOOLS]


def sort_references(rows: list[dict]) -> list[dict]:
    """The unresolved rows in one order, whatever order they were found in.

    The two readers walk the inventory differently -- one interleaves an asset's
    ``tools`` and its ``server`` per asset, the other walks every agent's tools
    first and then every asset's server -- so the same two gaps came out as the
    same SET in a different LIST. Measured at roughly one in ten agent-heavy
    inventories. Both lists are returned verbatim from their own endpoint, so the
    same gaps appeared in two reports in two orders, and a caller comparing them
    for agreement (the parity tests do, with ``==``) was comparing find order.

    Sorted on the row's own content rather than on iteration, so the order is a
    property of the graph and not of the walk.
    """
    return sorted(rows, key=lambda r: (r["source"], r["mechanism"], r["reference"]))


def dangling_reference(source, reference, mechanism: str, reason: str = UNRESOLVED_NOT_FOUND) -> dict:
    """One unresolved reference, in the shape both readers report.

    Names what declared it as well as what it named: an operator chasing a
    dangling edge needs the source to know where to look, and the source's kind
    to know what kind of declaration to fix. ``reason`` says whether the
    reference named nothing or named more than one thing.
    """
    return {
        "source": source.name,
        "source_kind": source.kind,
        "reference": str(reference or "").strip(),
        "mechanism": mechanism,
        "reason": reason,
    }
