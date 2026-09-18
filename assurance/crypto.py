"""Symmetric encryption for connector / posture credentials at rest.

The commercial spine binds a connector or a posture domain to a per-tenant
(per-deployment) endpoint and the credential that reaches it. That credential is a
secret — a Jira/ServiceNow/GitHub token, a Splunk HEC token, a cloud/secret-store
read token — and it is **never stored in plaintext and never logged**. It is
encrypted at rest with a symmetric key sourced from settings/env, and only ever
decrypted, in memory, at the moment a *configured* connector is actually pushed to
or a *configured* posture domain is actually fetched.

The one honesty rule this module exists to enforce:

- **No key configured → no secret can be stored, and any binding that needs a
  secret stays inert and says so.** ``ASSURANCE_CREDENTIAL_KEY`` (a Fernet key, or
  a comma-separated list of them for rotation — the first is the one new
  ciphertext is written with, the rest still decrypt old ciphertext) is *absent by
  default*, so an unconfigured environment behaves exactly as it does today:
  nothing can be encrypted, so nothing can be configured, so every connector and
  every posture domain is inert. This is deliberate — a missing key never silently
  falls back to plaintext, and it never fabricates a "configured" state.

The key is a `Fernet <https://cryptography.io/en/latest/fernet/>`_ key:
URL-safe base64 of 32 random bytes, e.g. from
``python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"``.
Fernet gives authenticated symmetric encryption (AES-128-CBC + HMAC), so a
tampered ciphertext fails to decrypt rather than yielding garbage.
"""

from __future__ import annotations

import logging

from django.conf import settings

logger = logging.getLogger(__name__)


class EncryptionUnavailable(RuntimeError):
    """Raised when a secret write is attempted with no credential key configured.

    Callers that store secrets check :func:`encryption_available` first and keep a
    binding inert rather than raising; this exists so a *direct* attempt to encrypt
    without a key fails loudly instead of silently persisting plaintext."""


def _key_material() -> list[bytes]:
    """The configured Fernet key(s), primary first, as bytes. Empty when none is
    configured. A comma-separated ``ASSURANCE_CREDENTIAL_KEY`` enables rotation:
    the first key writes new ciphertext, every key can decrypt old ciphertext."""
    raw = getattr(settings, "ASSURANCE_CREDENTIAL_KEY", "") or ""
    keys: list[bytes] = []
    for part in str(raw).split(","):
        part = part.strip()
        if part:
            keys.append(part.encode("utf-8"))
    return keys


def _fernet():
    """Build the (Multi)Fernet from the configured key(s), or ``None`` when no key
    is configured or the configured value is not a valid Fernet key. A malformed
    key is treated as *no key* (inert), never as a reason to store plaintext, and
    the reason is logged **without** the key material."""
    keys = _key_material()
    if not keys:
        return None
    try:
        from cryptography.fernet import Fernet, MultiFernet

        fernets = [Fernet(k) for k in keys]
        return MultiFernet(fernets) if len(fernets) > 1 else fernets[0]
    except Exception:  # noqa: BLE001 — a bad key is inert, and we never log the key
        logger.warning(
            "ASSURANCE_CREDENTIAL_KEY is set but is not a valid Fernet key; "
            "credential encryption is unavailable and connector/posture bindings "
            "that need a secret will stay inert."
        )
        return None


def encryption_available() -> bool:
    """Whether a usable credential key is configured. When ``False``, no secret can
    be stored and every binding that needs one is inert — the default posture of an
    unconfigured environment."""
    return _fernet() is not None


def encrypt_secret(plaintext: str) -> str:
    """Encrypt a secret for storage. Returns the Fernet token as ``str``. Raises
    :class:`EncryptionUnavailable` when no key is configured — the caller must
    guard on :func:`encryption_available` and keep the binding inert instead of
    ever persisting a plaintext credential."""
    fernet = _fernet()
    if fernet is None:
        raise EncryptionUnavailable(
            "No ASSURANCE_CREDENTIAL_KEY configured; refusing to store a credential."
        )
    if not isinstance(plaintext, str):
        raise TypeError("secret to encrypt must be a string")
    return fernet.encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(token: str | None) -> str | None:
    """Decrypt a stored secret back to plaintext, in memory, at point of use.

    Returns ``None`` when there is nothing to decrypt (empty token), when no key is
    configured, or when the ciphertext cannot be decrypted with any configured key
    (a tampered token, or one written under a key that has since been retired). A
    ``None`` here means *no usable credential*, so the binding is treated as inert
    — never a crash, and never a plaintext fallback. The failure reason is logged
    without the token or the key."""
    if not token:
        return None
    fernet = _fernet()
    if fernet is None:
        return None
    try:
        from cryptography.fernet import InvalidToken

        try:
            return fernet.decrypt(token.encode("utf-8")).decode("utf-8")
        except InvalidToken:
            logger.warning(
                "A stored credential could not be decrypted with any configured "
                "key; the binding will be treated as inert until it is re-entered."
            )
            return None
    except Exception:  # noqa: BLE001 — decryption must never raise out into a request
        logger.warning("Credential decryption failed; treating the binding as inert.")
        return None
