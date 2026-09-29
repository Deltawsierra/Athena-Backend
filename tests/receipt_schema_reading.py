"""Reading a receipt's object members against the schema published for its version.

The backend publishes one schema per receipt version (``assurance.receipt.
receipt_schema``). A version emitted in two shapes -- 2.0's ``coverage`` -- is
published as one schema whose member is exactly one of them (``oneOf``, each branch
titled with who emitted it). This is the reading a consumer holding that schema
does, one level into each object member: the members it requires are present, the
members present are ones it defines, and a ``oneOf`` matches exactly one branch.
Written once, so the conformance suite and the back-reading tests ask the same
question of the same schema.
"""

from __future__ import annotations


def _branch_matches(branch: dict, members: set) -> bool:
    if not set(branch.get("required", ())) <= members:
        return False
    excluded = branch.get("not", {}).get("anyOf", ())
    return not any(set(rule.get("required", ())) <= members for rule in excluded)


def shapes_read(schema: dict, document: dict) -> tuple[str, ...] | None:
    """The titles of the ``oneOf`` branches ``document``'s object members matched, or
    ``None`` when a member is not a shape the schema describes: a member it requires
    is missing, one it does not define is present, or it matches no branch of a
    ``oneOf``, or more than one."""
    titles: list[str] = []
    for name, rule in schema["properties"].items():
        value = document.get(name)
        if not isinstance(value, dict) or "properties" not in rule:
            continue
        members = set(value)
        if not set(rule.get("required", ())) <= members or not members <= set(rule["properties"]):
            return None
        if "oneOf" in rule:
            matched = [branch for branch in rule["oneOf"] if _branch_matches(branch, members)]
            if len(matched) != 1:
                return None
            titles.append(matched[0]["title"])
    return tuple(titles)
