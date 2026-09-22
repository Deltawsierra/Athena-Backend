"""Verification helpers for the control plane, built on mythos_core.failsafe.

The control plane verifies operator signatures for two reasons: to tell an
operator immediately whether their signature is valid, and to know when enough
distinct operators have signed for a command to be `ready`. It uses the SAME
command-signing definition (mythos_core.failsafe.Command.signing_bytes) and the
SAME thresholds the engine uses, so the two never disagree about what a
signature covers or how many are needed. The engine remains the authoritative
verifier; this is a faithful mirror of its check, not a replacement.
"""

from __future__ import annotations

import uuid

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from django.conf import settings
from django.utils import timezone

from mythos_core.failsafe import Command
from mythos_core.failsafe.commands import DEFAULT_THRESHOLDS, Action


def operator_keyring() -> dict[str, Ed25519PublicKey]:
    """The enrolled operator public keys, key_id -> key. Must match the keys the
    engine is configured with, or a command this plane calls `ready` would be
    refused by the engine (and vice versa)."""
    ring: dict[str, Ed25519PublicKey] = {}
    for key_id, hexkey in getattr(settings, "FAILSAFE_OPERATOR_KEYS", {}).items():
        ring[str(key_id)] = Ed25519PublicKey.from_public_bytes(bytes.fromhex(hexkey))
    return ring


def required_signatures(action: str) -> int:
    """Distinct-signature threshold for an action. settings.FAILSAFE_THRESHOLDS
    (action name -> int) overrides per action; unset actions use the library
    default (pause/resume 1; stand_down/release/terminate 2 -- the two-person
    rule)."""
    overrides = getattr(settings, "FAILSAFE_THRESHOLDS", {}) or {}
    if action in overrides:
        return int(overrides[action])
    return DEFAULT_THRESHOLDS[Action(action)]


def make_draft(action: str, engine_id: str, reason: str, ttl_seconds: int) -> dict:
    """A fresh unsigned command: a server-issued single-use nonce and a bounded
    validity window. Operators sign these exact fields."""
    now = timezone.now()
    return {
        "action": action,
        "engine_id": engine_id,
        "nonce": uuid.uuid4().hex,
        "issued_at": now.isoformat(),
        "expires_at": (now + timezone.timedelta(seconds=ttl_seconds)).isoformat(),
        "reason": reason or "",
    }


def signing_bytes_hex(command_fields: dict) -> str:
    """The exact bytes an operator signs, hex-encoded, for display in the console
    and for the operator's CLI to reproduce."""
    return Command.from_dict({**command_fields, "signatures": []}).signing_bytes().hex()


def verify_signature(command_fields: dict, key_id: str, sig_hex: str, keyring) -> bool:
    """Whether sig_hex is a valid signature by key_id over this command's signing
    bytes. Unknown key_id or malformed/forged signature -> False."""
    public_key = keyring.get(key_id)
    if public_key is None:
        return False
    signing_bytes = Command.from_dict({**command_fields, "signatures": []}).signing_bytes()
    try:
        public_key.verify(bytes.fromhex(sig_hex), signing_bytes)
    except (InvalidSignature, ValueError):
        return False
    return True


def distinct_valid_signers(command_fields: dict, signatures: list, keyring) -> set[str]:
    """The key_ids whose signatures verify, counting one per distinct **key**.

    The two-person rule is the only thing standing between one operator and a
    stand-down, so what counts as "two people" has to be the same on both sides
    of the wire. It was not. The engine
    (``mythos_core.failsafe.commands.verify_command``) counts distinct public
    key *material*; this counted distinct ``key_id``. One private key enrolled
    under two ids -- an ordinary outcome of re-enrolling an operator's hardware
    token, or of one copy-paste in ``FAILSAFE_OPERATOR_KEYS`` -- satisfied the
    console's threshold and was refused by the engine.

    The engine fails safe, so nothing was ever wrongly stood down. The damage is
    the silence in between: the console marks the command READY and publishes
    it, the engine rejects it and does nothing, and the rejection is recorded
    only in the governor's in-memory history, which no route exposes. An
    operator sees "stand-down ready" and a scan that never stopped. The same
    divergence blocks RELEASE, so an engine that *was* stood down with a
    duplicated keyring cannot be released except by restarting it.

    So this counts what the engine counts. It still returns key_ids, because
    those are what the console displays and audits -- but two ids backed by one
    key now contribute one signer, and the id kept is the first that verified.
    """
    seen_keys: set[bytes] = set()
    valid: set[str] = set()
    for sig in signatures:
        key_id = sig.get("key_id")
        if not key_id or key_id in valid:
            continue
        if not verify_signature(command_fields, key_id, sig.get("sig", ""), keyring):
            continue
        material = _key_material(keyring.get(key_id))
        if material is None:
            # A key that verified but whose material cannot be read is not
            # something to count optimistically. Refusing it costs a signature
            # an operator would have to re-submit; counting it is how one key
            # becomes two.
            continue
        if material in seen_keys:
            continue
        seen_keys.add(material)
        valid.add(key_id)
    return valid


def _key_material(public_key) -> bytes | None:
    """The raw public key bytes, or None if they cannot be read.

    ``public_bytes_raw`` is what ``mythos_core.failsafe`` uses, so the two sides
    compare identical values rather than two encodings of the same key.
    """
    if public_key is None:
        return None
    try:
        return public_key.public_bytes_raw()
    except Exception:  # noqa: BLE001 - an unreadable key counts as no key
        return None
