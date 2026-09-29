#!/usr/bin/env python3
"""Verify a Mythos Assurance Receipt offline, from its published specification.

    python verify_receipt.py RECEIPT.json --keyring KEYRING.json [--evidence EVIDENCE.json]
    python verify_receipt.py RECEIPT.json --public-key KEY.b64
    python verify_receipt.py RECEIPT.json          # an unsigned copy: checked, then refused

Written from ``docs/receipt-spec/v4.0.md``, not from this repository's code, and it
imports nothing from it: the Python standard library, plus ``cryptography`` for
Ed25519 -- the one crypto library athena-backend already depends on. Copy this file
anywhere and run it.

RECEIPT.json is one of these, saved as it was served:

* the answer of ``GET /api/assurance/deployments/<uuid>/signed-assurance-receipt/``
  -- the receipt with its DSSE envelope beside it;
* the answer of ``GET /api/assurance/deployments/<uuid>/assurance-receipt/`` -- the
  unsigned copy;
* a DSSE envelope on its own, as the engine returns one.

Keys come from you, never from the receipt. ``--keyring`` is the engine's published
keyring (``GET /api/assurance/keyring`` on the ENGINE; this backend does not serve
it). ``--public-key`` is a file holding one base64 Ed25519 public key you obtained
out of band. A key taken from the same place as the receipt proves only that the two
agree with each other.

``--evidence`` is optional: the evidence the receipt's evidence root covers, in the
form the specification gives (section 5.3). With it the root is recomputed from the
evidence; without it the root is bound by the digest and the signature but not
re-derived, and the output says so.

Exit status:
  0  VERIFIED.
  1  REFUSED. The first line names the reason, one of the specification's refusal
     list (``REFUSALS`` below); the lines after it say why.
  2  The verifier could not run: bad arguments, a file it cannot read, a keyring or
     evidence file that is not in the specified form, or a signed receipt with no
     key given to check it against.

VERIFIED establishes integrity and provenance: this is the assurance state
athena-backend recorded, unaltered since the holder of the named key signed it. It
does not establish that the assessment is correct or the system safe, and it does
not establish WHEN: a signed receipt carries no signing time (specification,
section 1).
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import json
import re
import sys
from dataclasses import dataclass

SPEC = "docs/receipt-spec/v4.0.md"

#: The DSSE payload type an assurance-receipt signature is bound to.
RECEIPT_TYPE = "application/vnd.mythos.assurance-receipt+json"
ENVELOPE_VERSION = 1
KEYRING_VERSION = 1

#: How deeply any JSON this verifier reads may nest (arrays and objects, strings
#: ignored), measured before it is parsed.
MAX_DEPTH = 64

#: The members of the top level of a receipt that its digest is taken over, per
#: version. Every other top-level member is outside the digest (``OUTSIDE_DIGEST``).
_BASE = (
    "receipt_version", "policy_version", "system", "result", "policy", "evidence", "assessments",
)
_V2 = (*_BASE, "served_route", "coverage")
HASHED: dict[str, frozenset[str]] = {
    "mythos.assurance.receipt/1.1": frozenset(_BASE),
    "mythos.assurance.receipt/2.0": frozenset(_V2),
    "mythos.assurance.receipt/3.0": frozenset(_V2),
    "mythos.assurance.receipt/3.1": frozenset(_V2),
    "mythos.assurance.receipt/4.0": frozenset((*_V2, "chains")),
}
CURRENT = "mythos.assurance.receipt/4.0"

#: The receipt's report on itself: present from 3.1, outside the digest and outside
#: the signature. A receipt cannot make itself signed; only an envelope can.
SELF_REPORT = ("signed", "signature", "unsigned_reason")
_SELF_REPORTING = frozenset({"mythos.assurance.receipt/3.1", "mythos.assurance.receipt/4.0"})

#: Top-level members no digest covers. ``algorithm`` and ``digest`` are covered by
#: the signature; the other four by nothing.
OUTSIDE_DIGEST = ("algorithm", "digest", "computed_at", *SELF_REPORT)
#: Left out of the signed copy, and so out of every envelope.
NOT_SIGNED = ("computed_at", *SELF_REPORT)

#: Key statuses in the engine's keyring. A retired key still verifies what it
#: signed; a revoked key verifies nothing.
_VERIFYING = ("active", "retired")
_STATUSES = ("active", "retired", "revoked")

#: The refusal list. The specification's table and the conformance vectors are
#: tested against these keys (tests/test_receipt_spec_conformance.py).
REFUSALS: dict[str, str] = {
    "depth_limit": "the receipt, or the payload inside its envelope, nests deeper than 64 levels",
    "malformed": "not a receipt this specification describes: unreadable JSON, a member "
    "missing or undefined for its version, or a receipt claiming a signature of its own",
    "not_an_envelope": "the envelope is not a DSSE envelope over an assurance receipt",
    "different_document": "the receipt served beside the envelope is not the one inside it",
    "unknown_version": "a receipt version this specification does not describe",
    "digest_mismatch": "the digest does not match the receipt's own content",
    "evidence_mismatch": "the evidence supplied does not reproduce the receipt's evidence root",
    "unsigned": "nothing signs this receipt",
    "wrong_key": "the signature is not by a key you gave the verifier",
    "revoked_key": "the signature is by a key the keyring has revoked",
    "bad_signature": "the signature does not check out over the payload",
}

_HEX64 = re.compile(r"[0-9a-f]{64}")
_STRUCTURE = re.compile(r'[\[\]{}"\\]')
_ENVELOPE_MEMBERS = frozenset({"envelope_version", "payloadType", "payload", "signatures"})


class Refused(Exception):
    """The receipt does not verify, for a reason in :data:`REFUSALS`."""

    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


class CannotRun(Exception):
    """The verifier could not do what it was asked (exit status 2)."""


@dataclass(frozen=True)
class Verdict:
    verified: bool
    reason: str | None
    lines: tuple[str, ...]

    def render(self) -> str:
        head = "VERIFIED" if self.verified else f"REFUSED {self.reason}"
        return "\n".join([head, *(f"  {line}" for line in self.lines)])


# --------------------------------------------------------------------- reading JSON


class _Unreadable(ValueError):
    def __init__(self, too_deep: bool, detail: str) -> None:
        super().__init__(detail)
        self.too_deep = too_deep


def _depth(text: str) -> int:
    """How deeply ``text`` nests arrays and objects, brackets inside strings not
    counted (a backslash in a string escapes the character after it). One linear
    pass that stops at the first bracket past :data:`MAX_DEPTH`, so a hostile input
    costs what a small one does."""
    depth = deepest = 0
    in_string = False
    escaped_until = -1
    for match in _STRUCTURE.finditer(text):
        at = match.start()
        if at < escaped_until:
            continue
        char = match.group()
        if in_string:
            if char == "\\":
                escaped_until = at + 2
            elif char == '"':
                in_string = False
        elif char == '"':
            in_string = True
        elif char in "[{":
            depth += 1
            if depth > deepest:
                deepest = depth
                if deepest > MAX_DEPTH:
                    return deepest
        elif char in "]}":
            depth -= 1
    return deepest


def _unique_members(pairs: list) -> dict:
    """Refuse an object that names one member twice. JSON parsers keep one of the
    two -- which one differs between parsers -- so such a document says one thing
    to this verifier and another to its reader."""
    seen: dict = {}
    for name, value in pairs:
        if name in seen:
            raise ValueError("an object names the same member twice")
        seen[name] = value
    return seen


def _no_constant(name: str) -> object:
    raise ValueError(f"{name} is not JSON")


def _parse(raw: bytes, what: str) -> object:
    """``raw`` as JSON, decoded the way ``json.loads`` decodes bytes (UTF-8, or
    UTF-16/32 by their byte-order marks), depth-bounded before parsing."""
    try:
        text = raw.decode(json.detect_encoding(raw), "surrogatepass")
    except UnicodeDecodeError as exc:
        raise _Unreadable(False, f"{what} is not text a JSON reader can decode") from exc
    if _depth(text) > MAX_DEPTH:
        raise _Unreadable(
            True,
            f"{what} nests deeper than {MAX_DEPTH} levels, so it is not read: a signature "
            "or a digest over something this verifier cannot read attests nothing",
        )
    try:
        return json.loads(text, object_pairs_hook=_unique_members, parse_constant=_no_constant)
    except (ValueError, RecursionError) as exc:
        raise _Unreadable(False, f"{what} is not JSON: {exc.__class__.__name__}") from exc


def _read_artifact(raw: bytes) -> object:
    try:
        return _parse(raw, "the receipt")
    except _Unreadable as exc:
        raise Refused("depth_limit" if exc.too_deep else "malformed", str(exc)) from exc


def _read_input(raw: bytes, what: str) -> object:
    try:
        return _parse(raw, what)
    except _Unreadable as exc:
        raise CannotRun(str(exc)) from exc


# ----------------------------------------------------------------- the digest form


def _canonical(value: object) -> bytes:
    """The digest's canonical form: sorted member names, no whitespace, every
    non-ASCII character escaped as ``\\uXXXX`` (specification, section 5.1)."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "ascii"
    )


def _sha256(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def _key_id(material: bytes) -> str:
    return "sha256:" + hashlib.sha256(material).hexdigest()[:32]


def _pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE's pre-authentication encoding: the bytes a signature is taken over."""
    kind = payload_type.encode("utf-8")
    return b" ".join(
        [b"DSSEv1", str(len(kind)).encode("ascii"), kind, str(len(payload)).encode("ascii"), payload]
    )


def _show(value: object) -> str:
    """A value from the receipt, printable safely (control characters escaped)."""
    shown = json.dumps(value, ensure_ascii=True)
    return shown if len(shown) <= 120 else shown[:117] + "..."


# ------------------------------------------------------------------------ the steps


def _classify(document: object) -> tuple[dict | None, dict, str, bool]:
    """Step 2: ``(envelope, receipt, form, served)``. ``receipt`` is the copy served
    beside an envelope when there is one; ``form`` is ``"full"`` for the unsigned
    copy and ``"signed"`` for the signed projection; ``served`` says whether a copy
    was served that the envelope must contain."""
    if not isinstance(document, dict):
        raise Refused("malformed", f"the receipt file holds a JSON {type(document).__name__}, not an object")
    if _ENVELOPE_MEMBERS & document.keys():
        return document, {}, "signed", False
    if "envelope" in document and "receipt" in document:
        served = document["receipt"]
        if not isinstance(served, dict):
            raise Refused("malformed", "the response's `receipt` is not an object")
        envelope = document["envelope"]
        if envelope is None:
            return None, served, "signed", False
        return envelope, served, "signed", True
    if "receipt_version" in document:
        return None, document, "full", False
    raise Refused(
        "malformed",
        "this is not an assurance receipt, a signed-receipt response or a DSSE envelope",
    )


def _open(envelope: object) -> tuple[bytes, dict]:
    """Step 3: the envelope's shape, then its payload's exact bytes and content."""
    if not isinstance(envelope, dict):
        raise Refused("not_an_envelope", f"the envelope is a JSON {type(envelope).__name__}, not an object")
    version = envelope.get("envelope_version")
    if type(version) is not int or version != ENVELOPE_VERSION:
        raise Refused("not_an_envelope", f"envelope_version is {_show(version)}, not {ENVELOPE_VERSION}")
    if envelope.get("payloadType") != RECEIPT_TYPE:
        raise Refused(
            "not_an_envelope",
            f"payloadType is {_show(envelope.get('payloadType'))}, not {RECEIPT_TYPE}: a signature "
            "is bound to its document kind, and one over another kind does not sign a receipt",
        )
    signatures = envelope.get("signatures")
    if not isinstance(signatures, list) or not signatures:
        raise Refused(
            "not_an_envelope",
            "the envelope carries no signatures: a receipt that looks signed and is not",
        )
    for index, entry in enumerate(signatures):
        if not (
            isinstance(entry, dict)
            and isinstance(entry.get("keyid"), str)
            and entry["keyid"]
            and isinstance(entry.get("sig"), str)
            and entry["sig"]
        ):
            raise Refused("not_an_envelope", f"signature {index} names no key or carries no signature bytes")
    raw = envelope.get("payload")
    if not isinstance(raw, str):
        raise Refused("not_an_envelope", "the envelope carries no base64 payload")
    try:
        payload = base64.b64decode(raw, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise Refused("not_an_envelope", "the envelope's payload is not base64") from exc
    try:
        receipt = _parse(payload, "the envelope's payload")
    except _Unreadable as exc:
        raise Refused("depth_limit" if exc.too_deep else "not_an_envelope", str(exc)) from exc
    if not isinstance(receipt, dict):
        raise Refused("not_an_envelope", "the envelope's payload is not a JSON object")
    return payload, receipt


def _has_non_integer_number(value: object) -> bool:
    if isinstance(value, float):
        return True
    if isinstance(value, dict):
        return any(_has_non_integer_number(v) for v in value.values())
    if isinstance(value, list):
        return any(_has_non_integer_number(v) for v in value)
    return False


def _check_structure(receipt: dict, form: str) -> str:
    """Steps 5 and 6: the version, then the members that version defines."""
    version = receipt.get("receipt_version")
    if not isinstance(version, str) or version not in HASHED:
        known = ", ".join(sorted(HASHED))
        raise Refused(
            "unknown_version",
            f"the receipt names version {_show(version)}; this verifier reads {known}. A "
            "version it does not know is refused, never read as one it does",
        )
    expected = set(HASHED[version]) | {"algorithm", "digest"}
    if form == "full":
        expected.add("computed_at")
        if version in _SELF_REPORTING:
            expected.update(SELF_REPORT)
    missing = sorted(expected - receipt.keys())
    extra = sorted(receipt.keys() - expected)
    if missing or extra:
        said = []
        if missing:
            said.append("missing " + ", ".join(missing))
        if extra:
            said.append(f"members {version} does not define: " + _show(extra))
        raise Refused("malformed", "; ".join(said))
    if receipt["algorithm"] != "sha256":
        raise Refused("malformed", f"algorithm is {_show(receipt['algorithm'])}; this specification defines sha256")
    if not (isinstance(receipt["digest"], str) and _HEX64.fullmatch(receipt["digest"])):
        raise Refused("malformed", "digest is not 64 lowercase hex characters")
    if form == "full" and version in _SELF_REPORTING and not (
        receipt["signed"] is False
        and receipt["signature"] is None
        and isinstance(receipt["unsigned_reason"], str)
        and receipt["unsigned_reason"].strip()
    ):
        raise Refused(
            "malformed",
            "the receipt reports a signature of its own. A receipt cannot sign itself -- "
            "only an envelope around it can -- so `signed` must be false, `signature` "
            "null and `unsigned_reason` said",
        )
    if _has_non_integer_number(receipt):
        raise Refused("malformed", "a receipt's numbers are integers; this one carries a fraction or an exponent")
    return version


def _check_digest(receipt: dict, version: str) -> None:
    """Step 7."""
    recomputed = _sha256({name: receipt[name] for name in HASHED[version]})
    if recomputed != receipt["digest"]:
        raise Refused(
            "digest_mismatch",
            f"the digest recomputed from the receipt's content is {recomputed}; the receipt "
            f"says {receipt['digest']}. Something in it was altered after it was computed",
        )


def _check_evidence(receipt: dict, evidence: tuple[str, list]) -> str:
    """Step 8: recompute the evidence root from the evidence itself."""
    deployment, findings = evidence
    system, block = receipt.get("system"), receipt.get("evidence")
    if not isinstance(system, dict) or not isinstance(block, dict):
        raise Refused("malformed", "the receipt's `system` or `evidence` is not an object")
    if deployment != system.get("uuid"):
        raise Refused(
            "evidence_mismatch",
            f"the evidence is for deployment {_show(deployment)}; the receipt is for "
            f"{_show(system.get('uuid'))}",
        )
    leaves = sorted(
        _sha256({"evidence": sorted(rows), "fingerprint": fingerprint, "uuid": uuid})
        for uuid, fingerprint, rows in findings
    )
    root = _sha256({"deployment": deployment, "findings": leaves})
    if root != block.get("root") or len(leaves) != block.get("finding_count"):
        raise Refused(
            "evidence_mismatch",
            f"{len(leaves)} finding(s) of evidence recompute to root {root}; the receipt says "
            f"{_show(block.get('finding_count'))} finding(s) and root {_show(block.get('root'))}. "
            "Evidence changed after the receipt was computed, or the file lacks (or adds) a finding",
        )
    return f"recomputed from {len(leaves)} finding(s); matches the receipt's evidence root"


def _check_signature(envelope: dict, payload: bytes, trusted: dict[str, tuple[bytes, str]]) -> tuple[str, str]:
    """Step 9. Verifies when any one signature checks out; otherwise the reason is
    the last signature's, as the engine's own verifier reports it."""
    public_key_type, invalid_signature = _ed25519()
    signed_bytes = _pae(RECEIPT_TYPE, payload)
    refusal = Refused("wrong_key", "no signature could be checked")
    for entry in envelope["signatures"]:
        key_id = entry["keyid"]
        known = trusted.get(key_id)
        if known is None:
            refusal = Refused(
                "wrong_key",
                f"the signature is by {_show(key_id)}, which is not a key you gave this "
                "verifier. An unknown signer is not a signer whose trust was withdrawn: "
                "check you hold the right keyring before concluding more",
            )
            continue
        material, status = known
        if status not in _VERIFYING:
            refusal = Refused(
                "revoked_key",
                f"the signature is by {key_id}, which the keyring has revoked; every receipt "
                "signed with it is invalid",
            )
            continue
        try:
            signature = base64.b64decode(entry["sig"], validate=True)
            public_key_type.from_public_bytes(material).verify(signature, signed_bytes)
        except (binascii.Error, ValueError, invalid_signature) as exc:
            refusal = Refused(
                "bad_signature",
                f"the signature by {key_id} does not check out over this payload "
                f"({exc.__class__.__name__}): the payload's bytes are not the bytes that were signed",
            )
            continue
        return key_id, status
    raise refusal


def _ed25519() -> tuple[type, type]:
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError as exc:
        raise CannotRun("checking a signature needs the `cryptography` package (Ed25519)") from exc
    return Ed25519PublicKey, InvalidSignature


# ---------------------------------------------------------------- the other inputs


def _trusted(keyring: bytes | None, public_key: bytes | None) -> dict[str, tuple[bytes, str]] | None:
    """The keys you trust, as ``{key id: (32-byte public key, status)}``."""
    if public_key is not None:
        try:
            material = base64.b64decode(public_key.strip(), validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CannotRun("the --public-key file does not hold a base64 key") from exc
        if len(material) != 32:
            raise CannotRun(f"an Ed25519 public key is 32 bytes; the --public-key file holds {len(material)}")
        return {_key_id(material): (material, "active")}
    if keyring is None:
        return None
    document = _read_input(keyring, "the keyring")
    if not isinstance(document, dict) or document.get("version") != KEYRING_VERSION or isinstance(
        document.get("version"), bool
    ):
        raise CannotRun(f"the keyring is not a version {KEYRING_VERSION} keyring object")
    keys = document.get("keys")
    if not isinstance(keys, dict) or not keys:
        raise CannotRun("the keyring holds no keys, so it can establish nothing")
    trusted: dict[str, tuple[bytes, str]] = {}
    seen: set[bytes] = set()
    for key_id, entry in keys.items():
        if not isinstance(entry, dict) or not isinstance(entry.get("public_key"), str):
            raise CannotRun(f"keyring entry {_show(key_id)} has no base64 public_key")
        try:
            material = base64.b64decode(entry["public_key"], validate=True)
        except (binascii.Error, ValueError) as exc:
            raise CannotRun(f"keyring entry {_show(key_id)}: public_key is not base64") from exc
        if len(material) != 32:
            raise CannotRun(f"keyring entry {_show(key_id)}: an Ed25519 public key is 32 bytes")
        # A key id IS its material's digest. Revocation is recorded against the id, so
        # a second name for one key is a second, unrevoked identity for it.
        if key_id != _key_id(material):
            raise CannotRun(
                f"keyring entry {_show(key_id)} is not the digest of its own public key "
                f"({_key_id(material)}); a key filed under another name is how a revoked key comes back"
            )
        if material in seen:
            raise CannotRun(f"keyring entry {_show(key_id)}: this public key is enrolled twice")
        seen.add(material)
        if entry.get("status") not in _STATUSES:
            raise CannotRun(f"keyring entry {_show(key_id)}: status is not one of {', '.join(_STATUSES)}")
        trusted[key_id] = (material, entry["status"])
    return trusted


def _evidence(raw: bytes) -> tuple[str, list]:
    """The evidence file: ``{"deployment": uuid, "findings": [{"uuid", "fingerprint",
    "evidence": [[classification, source, content_hash], ...]}, ...]}``."""
    document = _read_input(raw, "the evidence file")
    form = "the evidence file is not in the form the specification gives (section 5.3)"
    if not isinstance(document, dict) or not isinstance(document.get("deployment"), str):
        raise CannotRun(f"{form}: no `deployment` uuid")
    findings = document.get("findings")
    if not isinstance(findings, list):
        raise CannotRun(f"{form}: `findings` is not a list")
    read = []
    for index, finding in enumerate(findings):
        rows = finding.get("evidence") if isinstance(finding, dict) else None
        if not (
            isinstance(finding, dict)
            and isinstance(finding.get("uuid"), str)
            and isinstance(finding.get("fingerprint"), str)
            and isinstance(rows, list)
            and all(
                isinstance(row, list) and len(row) == 3 and all(isinstance(cell, str) for cell in row)
                for row in rows
            )
        ):
            raise CannotRun(
                f"{form}: finding {index} needs a `uuid`, a `fingerprint` and `evidence` rows "
                "of three strings"
            )
        read.append((finding["uuid"], finding["fingerprint"], rows))
    return document["deployment"], read


# -------------------------------------------------------------------------- verify


def verify(
    artifact: bytes,
    *,
    keyring: bytes | None = None,
    public_key: bytes | None = None,
    evidence: bytes | None = None,
) -> Verdict:
    """Run the specification's verification algorithm (section 7) over the bytes of
    a receipt file and, optionally, a keyring or public key and an evidence file.

    Raises :class:`CannotRun` for what exit status 2 means; every other outcome is a
    :class:`Verdict`."""
    if keyring is not None and public_key is not None:
        raise CannotRun("give a keyring or a public key, not both")
    trusted = _trusted(keyring, public_key)
    evidence_set = None if evidence is None else _evidence(evidence)
    try:
        return _verify(artifact, trusted, evidence_set)
    except Refused as refusal:
        return Verdict(False, refusal.reason, (refusal.detail,))


def _verify(artifact: bytes, trusted: dict | None, evidence_set: tuple[str, list] | None) -> Verdict:
    envelope, receipt, form, served = _classify(_read_artifact(artifact))
    payload = b""
    if envelope is not None:
        payload, inside = _open(envelope)
        if served and inside != receipt:
            raise Refused(
                "different_document",
                "the receipt served beside the envelope is not the document inside it, so the "
                "signature does not attest the copy you were shown",
            )
        receipt = inside
    version = _check_structure(receipt, form)
    _check_digest(receipt, version)
    evidence_line = (
        "not re-derived (no --evidence given); bound by the digest"
        if evidence_set is None
        else _check_evidence(receipt, evidence_set)
    )
    if envelope is None:
        raise Refused(
            "unsigned",
            "nothing signs this receipt. Its digest matches its content, which shows only "
            "that this copy is internally consistent: anyone can recompute a digest, so it "
            "says nothing about who produced the receipt. Fetch the signed copy "
            "(GET .../signed-assurance-receipt/) and verify that.",
        )
    if trusted is None:
        raise CannotRun(
            "this receipt is signed; give the key to check it against, out of band from the "
            "receipt (--keyring or --public-key)"
        )
    key_id, status = _check_signature(envelope, payload, trusted)
    system = receipt.get("system") if isinstance(receipt.get("system"), dict) else {}
    result = receipt.get("result") if isinstance(receipt.get("result"), dict) else {}
    lines = [
        f"receipt   {version}",
        f"system    {_show(system.get('name'))} ({_show(system.get('uuid'))}, {_show(system.get('environment'))})",
        f"decision  {_show(result.get('decision'))}",
        f"digest    {receipt['digest']}",
        f"signer    {key_id} ({status})",
        f"evidence  {evidence_line}",
        "This establishes integrity and provenance only: not that the assessment is "
        "correct or the system safe, and not when -- a signed receipt carries no "
        "signing time.",
    ]
    if status == "retired":
        lines.insert(5, "note      the key has since been rotated out; a retired key still verifies what it signed")
    return Verdict(True, None, tuple(lines))


# ------------------------------------------------------------------------------ CLI


def _read(path: str) -> bytes:
    try:
        with open(path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        raise CannotRun(f"cannot read {path}: {exc.strerror or exc.__class__.__name__}") from exc


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify a Mythos Assurance Receipt offline (specification: " + SPEC + ").",
        epilog="Exit status: 0 verified, 1 refused (the reason is on the first line), 2 could not run.",
    )
    parser.add_argument(
        "receipt", help="the receipt file: the signed route's answer, the unsigned copy, or an envelope"
    )
    keys = parser.add_mutually_exclusive_group()
    keys.add_argument("--keyring", help="the engine's published keyring (JSON), fetched out of band")
    keys.add_argument("--public-key", help="a file holding one base64 Ed25519 public key, obtained out of band")
    parser.add_argument("--evidence", help="the evidence the receipt's evidence root covers (spec section 5.3)")
    args = parser.parse_args(argv)
    try:
        verdict = verify(
            _read(args.receipt),
            keyring=_read(args.keyring) if args.keyring else None,
            public_key=_read(args.public_key) if args.public_key else None,
            evidence=_read(args.evidence) if args.evidence else None,
        )
    except CannotRun as exc:
        print(f"CANNOT RUN: {exc}", file=sys.stderr)
        return 2
    print(verdict.render())
    return 0 if verdict.verified else 1


if __name__ == "__main__":
    sys.exit(main())
