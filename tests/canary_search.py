"""Searching a sink for a canary, however it is carried.

The search of Athena-Engine's canary harness (#76,
tests/test_no_planted_secret_leaves_through_an_export.py there), carried over
unchanged -- as achilles-engine carries it -- so the engines' harnesses and this
service's mean the same thing by "absent": every
canary is looked for raw, JSON-escaped, URL-encoded, as hex, as base64 and
URL-safe base64 at all three alignments, cut short at either end, and inside
anything that decodes -- base64 and hex runs, gzip, zlib and raw deflate streams,
URL-encoded text, nested JSON strings -- recursively; and a digest of it (md5 to
sha512, sha3, blake2; hex or base64; 24 hex or 20 base64 characters of it).
"""

from __future__ import annotations

import base64
import binascii
import contextlib
import gzip
import hashlib
import json
import re
import zlib
from collections.abc import Iterator
from urllib.parse import quote, quote_plus, unquote, unquote_plus

_DIGEST_ALGORITHMS = (
    "md5",
    "sha1",
    "sha224",
    "sha256",
    "sha384",
    "sha512",
    "sha3_256",
    "sha3_512",
    "blake2b",
    "blake2s",
)
#: How much of a digest is enough to call it one: 96 bits of hex, 120 of base64.
_HEX_DIGEST_CHARS = 24
_B64_DIGEST_CHARS = 20


def encoded_forms(value: str) -> dict[str, str]:
    """Every spelling of `value` an export could carry it in, by name.

    Base64 is taken at all three alignments: where a value starts inside a
    longer buffer decides which characters encode it, so each alignment is
    encoded and cut to the characters that depend on the value alone.
    """
    raw = value.encode("utf-8")
    forms = {
        "raw": value,
        "json": json.dumps(value)[1:-1],
        "json-ascii": json.dumps(value, ensure_ascii=True)[1:-1],
        "url": quote(value, safe=""),
        "url+": quote_plus(value),
        "hex": raw.hex(),
        # Enough of either end to catch a value cut short by a length limit.
        "prefix": value[:16],
        "suffix": value[-16:],
    }
    for offset in range(3):
        for name, encode in (
            ("b64", base64.b64encode),
            ("b64url", base64.urlsafe_b64encode),
        ):
            text = encode(b"\0" * offset + raw).decode("ascii")
            first = 4 * -(-offset // 3)
            last = 4 * ((offset + len(raw)) // 3)
            forms[f"{name}@{offset}"] = text[first:last]
    return forms


def digest_forms(value: str) -> dict[str, str]:
    """The start of every digest of `value` this searches for, by name."""
    raw = value.encode("utf-8")
    forms = {}
    for algorithm in _DIGEST_ALGORITHMS:
        digest = hashlib.new(algorithm, raw).digest()
        forms[f"{algorithm}.hex"] = digest.hex()[:_HEX_DIGEST_CHARS]
        forms[f"{algorithm}.b64"] = base64.b64encode(digest).decode("ascii")[:_B64_DIGEST_CHARS]
        forms[f"{algorithm}.b64url"] = base64.urlsafe_b64encode(digest).decode("ascii")[
            :_B64_DIGEST_CHARS
        ]
    return forms


def _caseless(form: str) -> bool:
    return form == "hex" or form.endswith(".hex")


class Needles:
    """Every form of every canary, indexed for one pass over a text."""

    def __init__(self, canaries: dict[str, str], extra: dict[str, dict[str, str]] | None = None):
        self.plain: list[tuple[str, str, str, bool]] = []
        seen: set[tuple[str, str]] = set()
        for origin, value in canaries.items():
            forms = {**encoded_forms(value), **(extra or {}).get(origin, {})}
            for form, needle in forms.items():
                caseless = _caseless(form)
                key = (origin, needle.lower() if caseless else needle)
                if needle and key not in seen:
                    seen.add(key)
                    self.plain.append((origin, form, key[1], caseless))
        self.hex_digests: dict[str, tuple[str, str]] = {}
        self.b64_digests: dict[str, tuple[str, str]] = {}
        for origin, value in canaries.items():
            for form, needle in digest_forms(value).items():
                if form.endswith(".hex"):
                    self.hex_digests[needle] = (origin, form)
                else:
                    self.b64_digests.setdefault(needle, (origin, form))


_HEX_RUN = re.compile(rf"[0-9a-fA-F]{{{_HEX_DIGEST_CHARS},}}")
_B64_RUN = re.compile(rf"[A-Za-z0-9+/_-]{{{_B64_DIGEST_CHARS},}}")
_B64_BLOB = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}")
_HEX_BLOB = re.compile(r"(?:[0-9a-fA-F]{2}){12,}")
_PERCENT = re.compile(r"%[0-9A-Fa-f]{2}")
_MAX_DEPTH = 3


def _printable(data: bytes) -> str | None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if not text:
        return None
    good = sum(ch.isprintable() or ch in "\r\n\t" for ch in text)
    return text if good >= 0.9 * len(text) else None


def _inflated(data: bytes) -> Iterator[tuple[str, bytes]]:
    """`data` gunzipped, zlib-inflated or raw-inflated, wherever that works."""
    if data[:2] == b"\x1f\x8b":
        with contextlib.suppress(OSError, EOFError, zlib.error):
            yield "gzip", gzip.decompress(data)
    for name, window in (("zlib", zlib.MAX_WBITS), ("deflate", -zlib.MAX_WBITS)):
        with contextlib.suppress(zlib.error, ValueError):
            inflated = zlib.decompress(data, window)
            if inflated:
                yield name, inflated


def _decoded(blob: str, how: str) -> Iterator[tuple[str, str]]:
    """What a run of base64 or hex characters decodes to, where that is text."""
    candidates: list[tuple[str, bytes]] = []
    stripped = blob.rstrip("=")
    for name, altchars in (("b64", None), ("b64url", b"-_")):
        with contextlib.suppress(binascii.Error, ValueError):
            candidates.append(
                (
                    name,
                    base64.b64decode(stripped + "=" * (-len(stripped) % 4), altchars, True),
                )
            )
    if _HEX_BLOB.fullmatch(blob):
        with contextlib.suppress(ValueError):
            candidates.append(("unhex", bytes.fromhex(blob)))
    for name, data in candidates:
        label = f"{how}{name}>" if how else f"{name}>"
        for inflate, inflated in _inflated(data):
            text = _printable(inflated)
            if text is not None:
                yield f"{label}{inflate}>", text
        text = _printable(data)
        if text is not None:
            yield label, text


def _layers(text: str, how: str = "", depth: int = 0) -> Iterator[tuple[str, str]]:
    """The text, and every text that decodes out of it, recursively."""
    yield how, text
    if depth >= _MAX_DEPTH:
        return
    if _PERCENT.search(text):
        for name, decode in (("urldecoded", unquote), ("urldecoded+", unquote_plus)):
            with contextlib.suppress(Exception):
                plain = decode(text)
                if plain != text:
                    yield from _layers(plain, f"{how}{name}>", depth + 1)
    seen: set[str] = set()
    for pattern in (_B64_BLOB, _HEX_BLOB):
        for match in pattern.finditer(text):
            blob = match.group(0)
            if blob in seen:
                continue
            seen.add(blob)
            for label, inner in _decoded(blob, how):
                yield from _layers(inner, label, depth + 1)


def _strings(value) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(key)
            yield from _strings(item)
    elif isinstance(value, (list, tuple, set)):
        for item in value:
            yield from _strings(item)


def serialise(document) -> str:
    """One export document, whole, as text."""
    if isinstance(document, bytes):
        return document.decode("latin-1")
    if isinstance(document, str):
        return document
    return json.dumps(document, sort_keys=True, ensure_ascii=False, default=repr)


def _texts(document, how: str = "", depth: int = 0) -> Iterator[tuple[str, str]]:
    """The document serialised, then every JSON string inside it, re-parsed."""
    yield how, serialise(document)
    if isinstance(document, bytes):
        for name, inflated in _inflated(document):
            yield f"{how}{name}>", inflated.decode("latin-1")
    if depth >= _MAX_DEPTH or isinstance(document, (bytes, str)):
        if isinstance(document, str):
            stripped = document.strip()
            if stripped[:1] in ("{", "[") and depth < _MAX_DEPTH:
                with contextlib.suppress(ValueError):
                    yield from _texts(json.loads(stripped), f"{how}json>", depth + 1)
        return
    for text in _strings(document):
        stripped = text.strip()
        if len(stripped) > 1 and stripped[:1] in ("{", "["):
            with contextlib.suppress(ValueError):
                yield from _texts(json.loads(stripped), f"{how}json>", depth + 1)


def _context(text: str, at: int, width: int, needles: Needles) -> str:
    start = max(0, at - 40)
    window = text[start : at + width + 40]
    for origin, _form, needle, caseless in needles.plain:
        if not caseless and needle in window:
            window = window.replace(needle, f"<{origin}>")
    return window.replace("\n", " ")


def search(document, needles: Needles) -> list[tuple[str, str, bool, str]]:
    """(origin, form, digest, context) for every needle found in `document`."""
    found: dict[tuple[str, str, bool], str] = {}
    for how0, text in _texts(document):
        for how, layer in _layers(text, how0):
            lowered = layer.lower()
            for origin, form, needle, caseless in needles.plain:
                haystack = lowered if caseless else layer
                at = haystack.find(needle)
                if at >= 0:
                    found.setdefault(
                        (origin, how + form, False),
                        _context(layer, at, len(needle), needles),
                    )
            for match in _HEX_RUN.finditer(layer):
                run = match.group(0).lower()
                for i in range(len(run) - _HEX_DIGEST_CHARS + 1):
                    hit = needles.hex_digests.get(run[i : i + _HEX_DIGEST_CHARS])
                    if hit:
                        found.setdefault((hit[0], how + hit[1], True), match.group(0))
            for match in _B64_RUN.finditer(layer):
                run = match.group(0)
                for i in range(len(run) - _B64_DIGEST_CHARS + 1):
                    hit = needles.b64_digests.get(run[i : i + _B64_DIGEST_CHARS])
                    if hit:
                        found.setdefault((hit[0], how + hit[1], True), run)
    return [(origin, form, digest, ctx) for (origin, form, digest), ctx in found.items()]
