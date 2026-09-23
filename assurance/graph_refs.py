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
unique, so it is the fallback and never the first answer. A reference is matched
against the assets of ONE deployment; nothing here can reach across a boundary.
"""

from __future__ import annotations

# The two mechanisms by which the inventory declares an edge. Named so an
# unresolved row says which kind of reference failed -- an agent naming a tool it
# cannot reach is a different conversation from a component naming a backend that
# is not there.
MECHANISM_TOOLS = "tools"
MECHANISM_SERVER = "server"


def resolve_reference(reference, by_identifier: dict, by_name: dict):
    """The asset a declared reference names, or ``None``.

    Identifier first, then name. ``None`` for an empty reference and for one that
    matches nothing -- and the caller must record that, not drop it. Returning
    ``None`` is not permission to invent a node, and it is not permission to say
    nothing either.
    """
    key = str(reference or "").strip()
    if not key:
        return None
    return by_identifier.get(key) or by_name.get(key)


def dangling_reference(source, reference, mechanism: str) -> dict:
    """One unresolved reference, in the shape both readers report.

    Names what declared it as well as what it named: an operator chasing a
    dangling edge needs the source to know where to look, and the source's kind
    to know what kind of declaration to fix.
    """
    return {
        "source": source.name,
        "source_kind": source.kind,
        "reference": str(reference or "").strip(),
        "mechanism": mechanism,
    }
