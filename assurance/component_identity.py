"""The identity a declared component and an observed asset are matched on -- one
rule, and one way of grouping by it, for every reader that pairs them.

Three places paired the customer's declaration with what discovery observed:
the drift assessment, the coverage manifest, and the ingest step that stamps
which assets a scan assessed. Each kept its own copy of the key, and the copies
disagreed. An identifier of only whitespace fell back to the component's name in
one and matched the empty string in the other, so the same declared component was
"observed" to one reader and "never observed" to the next.

Both of the first two also indexed with a dict comprehension, ``{key: record}``,
which keeps the LAST record per key and drops the rest without a word. The key
lowercases and strips, and ``Asset``'s unique constraint does neither, so
``Reader`` and ``reader`` are two rows under one identity. With one of them
assessed and the other not, whether the manifest called the declared component
assessed depended on which row the database returned last, and a manifest that
reads COMPLETE on one ordering and INCOMPLETE on another is holding the decision
on a coin. Every record under a key is kept here, and each reader decides what
more than one means for its own question.
"""

from __future__ import annotations


def _norm(value) -> str:
    return str(value or "").strip().lower()


def component_key(kind, *, identifier, name) -> tuple[str, str]:
    """``(kind, identity)``: the normalized identifier, or the normalized name when
    the identifier is blank or only whitespace. Keyword-only so a caller cannot
    pass the name where the identifier goes -- two of the old copies took them in
    opposite orders."""
    return (str(kind or ""), _norm(identifier) or _norm(name))


def by_identity(records) -> dict[tuple[str, str], list]:
    """Every record grouped under its :func:`component_key`, in the order given.
    Never one record per key: a key more than one record answers to keeps them
    all."""
    groups: dict[tuple[str, str], list] = {}
    for record in records:
        key = component_key(record.kind, identifier=record.identifier, name=record.name)
        groups.setdefault(key, []).append(record)
    return groups
