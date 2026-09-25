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

    Left unstamped: a non-MCP tool row keyed by its own server, which is either a
    nameless tool (the same key under both rules) or the collapse of every tool on
    that server (not), and the literal ``"agent"`` row. Those cannot be told apart
    from the row, so they stay reported until a scan that declares them says
    which they are.
    """
    metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
    if asset.kind == "agent":
        return asset.identifier != "agent"
    if asset.kind == "mcp_server":
        return True
    server = str(metadata.get("server") or "").strip()
    return not server or asset.identifier != server[:IDENTIFIER_MAX]


def stamp(apps, schema_editor):
    Asset = apps.get_model("assurance", "Asset")
    for asset in Asset.objects.filter(metadata__source="declared_inventory").iterator():
        metadata = asset.metadata if isinstance(asset.metadata, dict) else {}
        if "identity_rules" in metadata or not _same_key_under_both_rules(asset):
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
