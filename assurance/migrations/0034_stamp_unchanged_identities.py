from django.db import migrations

#: ``graph_refs.IDENTITY_RULES`` when this migration was written. Spelled here, not
#: imported: a migration records what it did, and the constant may move on.
IDENTITY_RULES = 2
IDENTIFIER_MAX = 1024


def _same_key_under_both_rules(asset) -> bool:
    """Whether the current identity rules would write this declared-inventory row
    under the key it already has.

    The old rules keyed a tool by its explicit identifier, else its server, else
    its name; an unnamed agent was the literal ``"agent"``. The current rules key a
    named tool on a server as ``name@server`` and an unnamed agent by where it is.
    A row the two rules key identically is the same component either way, and
    leaving it unstamped reported every reference to it as superseded until a
    rescan -- a gap with nothing behind it, holding the access claim off
    VERIFIED on every existing deployment.

    Left unstamped: a non-MCP tool row keyed by its own server, and the literal
    ``"agent"`` row. The current rules write neither key -- a named tool on a server
    is ``name@server`` and a nameless one ``@server``; an unnamed agent is keyed by
    where it is -- and each was where the old rules collapsed several declarations
    into one row, so what such a row stands for cannot be read off it. They stay
    reported until a declaration that covers everything they hold lands on them.
    """
    metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
    if asset.kind == "agent":
        return asset.identifier != "agent"
    if asset.kind == "mcp_server":
        return True
    server = str(metadata.get("server") or "").strip()
    return not server or asset.identifier != server[:IDENTIFIER_MAX]


#: ``assets.LEGACY_KEY``: a row whose key more than one old declaration wrote.
LEGACY_KEY = "legacy_key"


def _named_more_than_once(Asset) -> set:
    """``{(deployment_id, key)}`` every key the deployment's declared agents name
    more than once between them, counting a key one agent names twice.

    The old rules wrote a named tool on a server at the server's key, so a plain
    tool named ``github`` and a tool on the server ``github`` were one row, holding
    whichever was written last. When the plain tool was last, the row said nothing
    about a server and looked keyed the same way under both rules -- stamped, the
    collapse was reported or not depending only on which agent was scanned last.
    Every declaration that wrote a key also named it, so a key named twice is a key
    two declarations may share. A shared tool that was never collapsed is reported
    until a rescan re-records it, and then settles: over-reported for a while, never
    a collapse hidden.
    """
    counts: dict = {}
    for agent in Asset.objects.filter(metadata__source="declared_inventory", kind="agent").iterator():
        metadata = agent.metadata if isinstance(agent.metadata, dict) else {}
        tools = metadata.get("tools")
        if not isinstance(tools, (list, tuple)):
            continue
        for ref in tools:
            key = str(ref or "").strip()
            if key:
                counts[(agent.deployment_id, key)] = counts.get((agent.deployment_id, key), 0) + 1
    return {pair for pair, n in counts.items() if n > 1}


def stamp(apps, schema_editor):
    Asset = apps.get_model("assurance", "Asset")
    shared = _named_more_than_once(Asset)
    for asset in Asset.objects.filter(metadata__source="declared_inventory").iterator():
        metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
        if "identity_rules" in metadata:
            continue
        invoked = asset.kind in ("tool", "skill")
        collapsed = invoked and (asset.deployment_id, asset.identifier) in shared
        if collapsed or not _same_key_under_both_rules(asset):
            # Left for a rescan, and marked, so the row is read as an old collapse
            # whatever the last declaration to land on it said about its server.
            if invoked and metadata.get(LEGACY_KEY) is not True:
                asset.metadata = {**metadata, LEGACY_KEY: True}
                asset.save(update_fields=["metadata"])
            continue
        asset.metadata = {**metadata, "identity_rules": IDENTITY_RULES}
        asset.save(update_fields=["metadata"])


class Migration(migrations.Migration):
    """Record the identity rules a declared-inventory row was written under, for
    every row the current rules would write under the same key. See
    ``graph_refs.IDENTITY_RULES``."""

    dependencies = [
        ("assurance", "0033_deployment_decision_keyring"),
    ]

    operations = [
        migrations.RunPython(stamp, migrations.RunPython.noop),
    ]
