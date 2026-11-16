"""A fixed corpus of observed-effect documents and reconciliation receipts, for one question:
does this backend read a STORED record exactly as ``master`` read it?

Until Mythos-Core defined the record (``mythos_core.observed_effect``, Mythos-Core#83), this
backend read it with rules of its own, kept by hand. Those rules are gone; the core's are asked
instead. What must not change is how a record already stored reads: a version 1 to 4 document
and a version 1 receipt. So the corpus is built from the valid document of every conformance
vector of those versions, each altered one field at a time in every way a hand-kept rule and
the core's could disagree about (a wrong type, a trailing newline, a space, another case, an
instant no calendar has, a field dropped, a field added, a list doubled or reversed), and
``tests/fixtures/observed_effect_read_on_master.json`` records what ``master`` (892ce03, with
its own rules and its own pin of the core) answered for each: accepted, refused, or an
unhandled error.

The corpus is generated, never stored: :func:`corpus` yields the same labelled documents in the
same order wherever it runs, and :func:`fingerprint` says so. ``tests/vectors/`` holds the
bases, byte for byte the core's files.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

VECTORS = Path(__file__).resolve().parent / "vectors"
RECORDED = Path(__file__).resolve().parent / "fixtures" / "observed_effect_read_on_master.json"

#: The versions a stored record can be in: what ``master`` took in.
EVIDENCE_FILES = ("observed-effect-v1.json", "observed-effect-v2.json", "observed-effect-v3.json", "observed-effect-v4.json")
RECEIPT_FILE = "effect-reconciliation-v1.json"

ACCEPTED = "accepted"
REFUSED = "refused"

#: Put in every field's place, whatever the field holds.
_WRONG: tuple[Any, ...] = (
    None,
    True,
    0,
    1,
    -1,
    1.5,
    "",
    " ",
    "x",
    "x\n",
    " x",
    [],
    {},
    ["x"],
    {"x": 1},
    "A" * 201,
    "0" * 64,
    "sha256:" + "0" * 64,
    "hmac-sha256:" + "0" * 64,
    "0" * 32,
    "2026-02-30T00:00:00.000000Z",
    "é",
    "a\x00b",
    "tool",
    "bound",
    "unbound",
    "applied",
)


def load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def _paths(node: Any, at: tuple = ()) -> Iterator[tuple]:
    yield at
    if isinstance(node, dict):
        for key in sorted(node):
            yield from _paths(node[key], (*at, key))
    elif isinstance(node, list):
        for index, item in enumerate(node):
            yield from _paths(item, (*at, index))


def _get(document: Any, path: tuple) -> Any:
    for step in path:
        document = document[step]
    return document


def _put(document: dict, path: tuple, value: Any) -> dict:
    changed = copy.deepcopy(document)
    _get(changed, path[:-1])[path[-1]] = copy.deepcopy(value)
    return changed


def _drop(document: dict, path: tuple) -> dict:
    changed = copy.deepcopy(document)
    del _get(changed, path[:-1])[path[-1]]
    return changed


def variants(document: dict) -> Iterator[tuple[str, Any]]:
    """``(label, document)``: ``document`` itself, then every one-field alteration of it."""
    yield "as signed", copy.deepcopy(document)
    yield "with a field added", {**copy.deepcopy(document), "extra": None}
    for path in _paths(document):
        if not path:
            continue
        at = "/".join(str(step) for step in path)
        original = _get(document, path)
        values: list[Any] = list(_WRONG)
        if isinstance(original, str):
            values += [
                original + "\n",
                original + " ",
                "\n" + original,
                original.upper(),
                original[:-1],
                original + "0",
                original.replace("T", " "),
            ]
        elif type(original) is int:
            values += [original + 1, original - 1, str(original), float(original), 199, 300, 503]
        for number, value in enumerate(values):
            if type(value) is type(original) and value == original:
                continue
            yield f"{at} = wrong value {number}", _put(document, path, value)
        yield f"{at} dropped", _drop(document, path)
        if isinstance(original, dict):
            yield f"{at} with a field added", _put(document, (*path, "extra"), None)
        if isinstance(original, list) and original:
            yield f"{at} doubled", _put(document, path, [*original, *original])
            yield f"{at} reversed", _put(document, path, list(reversed(original)))
            yield f"{at} with a non-entry", _put(document, path, [*original, "x"])


def evidence_bases() -> dict[str, dict]:
    """The valid document of each version's vector, by file name."""
    return {name: load(name)["evidence"] for name in EVIDENCE_FILES}


def receipt_bases() -> dict[str, dict]:
    """Every valid version 1 receipt of the vector, by its case's name."""
    return {f"{RECEIPT_FILE}: {case['name']}": case["document"] for case in load(RECEIPT_FILE)["valid"]}


def corpus() -> Iterator[tuple[str, str, str, Any]]:
    """``(kind, base, label, document)`` for every document of the corpus, in a fixed order:
    ``kind`` is ``"evidence"`` or ``"receipt"``. The vectors' own invalid documents are in
    it too, under their base."""
    for name, document in evidence_bases().items():
        for label, changed in variants(document):
            yield "evidence", name, label, changed
        for number, case in enumerate(load(name)["invalid"]):
            yield "evidence", name, f"the vector's invalid document {number}", case["evidence"]
    for name, document in receipt_bases().items():
        for label, changed in variants(document):
            yield "receipt", name, label, changed
    for number, case in enumerate(load(RECEIPT_FILE)["invalid_documents"]):
        yield "receipt", RECEIPT_FILE, f"the vector's invalid document {number}", case["document"]


def fingerprint(entries) -> str:
    """One digest over the labels and documents of ``entries``: two runs that read the same
    corpus print the same one."""
    seen = hashlib.sha256()
    for kind, base, label, document in entries:
        seen.update(json.dumps([kind, base, label, document], sort_keys=True, ensure_ascii=True).encode())
        seen.update(b"\n")
    return seen.hexdigest()


def answer(read, document: Any, refused: type[BaseException]) -> str:
    """How ``read`` answers ``document``: :data:`ACCEPTED`, :data:`REFUSED` (it raised
    ``refused``), or ``error: <type>`` for anything else it raised."""
    try:
        read(copy.deepcopy(document))
    except refused:
        return REFUSED
    except Exception as exc:  # noqa: BLE001 - an unhandled error is one of the three answers recorded
        return f"error: {type(exc).__name__}"
    return ACCEPTED


def read_all(validate_evidence, evidence_refused, validate_receipt, receipt_refused) -> dict:
    """Every document of the corpus read by the given validators: per kind and base, how
    many there are, the labels accepted and the labels that raised an unhandled error (every
    other one was refused), and the corpus's fingerprint."""
    entries = list(corpus())
    found: dict[str, Any] = {"fingerprint": fingerprint(entries), "documents": len(entries), "bases": {}}
    for kind, base, label, document in entries:
        entry = found["bases"].setdefault(f"{kind}: {base}", {"documents": 0, "accepted": [], "errors": {}})
        entry["documents"] += 1
        if kind == "evidence":
            said = answer(validate_evidence, document, evidence_refused)
        else:
            said = answer(validate_receipt, document, receipt_refused)
        if said == ACCEPTED:
            entry["accepted"].append(label)
        elif said != REFUSED:
            entry["errors"][label] = said
    return found
