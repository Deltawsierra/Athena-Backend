"""3.3 Secrets / Crypto — the cryptographic and secret-handling posture.

The checks a secrets/crypto read would make once credentials are granted: whether
TLS certificates are valid and not expiring, whether KMS keys are rotated, whether
the secret store is hygienic (managed, rotated), whether there are committed-secret
*indicators*, and whether data at rest is encrypted. Evaluated against fetched (or
fixture) posture data — never a live scan here.

Honesty, per the framework: a check with no data reads ``unknown``, never
``pass``; observed configuration is ``configuration_verified``; a *measured* TLS
handshake result (validity/expiry the read actually observed) is
``technically_verified``; nothing is reported "secure".

**No secret value is ever emitted.** A committed-secret indicator is surfaced as a
count and a type/location fact only — never the credential itself — so the read
stays safe to expose even though it names a hygiene problem.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.conf import settings

from ..capability import RISK_ELEVATED, RISK_HIGH
from .base import (
    PostureAssessment,
    PostureCheck,
    PostureConfig,
    _as_dict,
    config_gap,
    config_pass,
    measured_gap,
    measured_pass,
    unknown,
)

# Days-to-expiry at or below which a certificate is a gap rather than merely aging.
_TLS_EXPIRY_WARN_DAYS = 21
# Age (days) at or above which an unrotated secret/key is a hygiene gap.
_SECRET_STALE_DAYS = 90


@dataclass(frozen=True)
class SecretsPostureConfig(PostureConfig):
    """What a live secrets/crypto read needs: the base URL of the posture source
    and a token. From settings/env only; no source default, so an unconfigured
    environment is inert."""

    base_url: str | None = None
    token: str | None = None

    def is_configured(self) -> bool:
        return bool(self.base_url and self.token)


# ---------------------------------------------------------------------------
# Evaluators
# ---------------------------------------------------------------------------


def _eval_tls_validity(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "certificates" not in d:
        return unknown("no TLS certificate data was read")
    certs = d.get("certificates") or []
    if not isinstance(certs, list):
        return unknown("TLS certificate data was malformed")
    measured = [c for c in certs if isinstance(c, dict) and c.get("measured")]
    if not measured:
        return unknown("certificates were listed but none carried a measured handshake result")
    invalid = [c.get("host", "?") for c in measured if c.get("valid") is False]
    if invalid:
        return measured_gap(f"{len(invalid)} certificate(s) failed validation when handshaken")
    return measured_pass("every handshaken certificate validated")


def _eval_tls_expiry(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "certificates" not in d:
        return unknown("no TLS certificate data was read")
    certs = d.get("certificates") or []
    if not isinstance(certs, list):
        return unknown("TLS certificate data was malformed")
    measured = [
        c for c in certs
        if isinstance(c, dict) and c.get("measured") and isinstance(c.get("days_to_expiry"), int)
    ]
    if not measured:
        return unknown("no certificate carried a measured days-to-expiry")
    expiring = [
        c.get("host", "?") for c in measured if c["days_to_expiry"] <= _TLS_EXPIRY_WARN_DAYS
    ]
    if expiring:
        return measured_gap(
            f"{len(expiring)} certificate(s) expire within {_TLS_EXPIRY_WARN_DAYS} days"
        )
    return measured_pass(
        f"no handshaken certificate expires within {_TLS_EXPIRY_WARN_DAYS} days"
    )


def _eval_kms_rotation(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "keys" not in d:
        return unknown("no KMS/key configuration was read")
    keys = d.get("keys") or []
    if not isinstance(keys, list):
        return unknown("KMS/key data was malformed")
    unrotated = [
        k.get("id", "?")
        for k in keys
        if isinstance(k, dict) and k.get("rotation_enabled") is False
    ]
    undeclared = [
        k.get("id", "?") for k in keys if isinstance(k, dict) and "rotation_enabled" not in k
    ]
    if unrotated:
        return config_gap(f"{len(unrotated)} KMS key(s) have automatic rotation disabled")
    if undeclared:
        return unknown(f"{len(undeclared)} KMS key(s) did not report a rotation state")
    return config_pass("every read KMS key reported automatic rotation enabled")


def _eval_secret_store_hygiene(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "secrets" not in d:
        return unknown("no secret-store inventory was read")
    secrets_ = d.get("secrets") or []
    if not isinstance(secrets_, list):
        return unknown("secret-store data was malformed")
    stale = [
        s.get("name", "?")
        for s in secrets_
        if isinstance(s, dict)
        and isinstance(s.get("last_rotated_days"), int)
        and s["last_rotated_days"] >= _SECRET_STALE_DAYS
    ]
    if stale:
        return config_gap(
            f"{len(stale)} secret(s) have not been rotated in {_SECRET_STALE_DAYS}+ days"
        )
    return config_pass(
        f"no read secret is older than {_SECRET_STALE_DAYS} days since last rotation"
    )


def _eval_unmanaged_secrets(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "secrets" not in d:
        return unknown("no secret-store inventory was read")
    secrets_ = d.get("secrets") or []
    if not isinstance(secrets_, list):
        return unknown("secret-store data was malformed")
    unmanaged = [
        s.get("name", "?")
        for s in secrets_
        if isinstance(s, dict) and s.get("managed") is False
    ]
    if unmanaged:
        return config_gap(
            f"{len(unmanaged)} secret(s) live outside a managed secret store"
        )
    return config_pass("every read secret is held in a managed secret store")


def _eval_committed_secret_indicators(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "indicators" not in d:
        return unknown("no source scan for committed-secret indicators was read")
    indicators = d.get("indicators") or []
    if not isinstance(indicators, list):
        return unknown("committed-secret indicator data was malformed")
    if indicators:
        # Count and kind only — the secret VALUE is never read or emitted.
        kinds = sorted({str(i.get("type", "unknown")) for i in indicators if isinstance(i, dict)})
        return config_gap(
            f"{len(indicators)} committed-secret indicator(s) present "
            f"(kinds: {', '.join(kinds)})"
        )
    return config_pass("no committed-secret indicator was found in the read scope")


def _eval_encryption_at_rest(data) -> "tuple[str, str, str]":
    d = _as_dict(data)
    if d is None or "stores" not in d:
        return unknown("no data-at-rest encryption configuration was read")
    stores = d.get("stores") or []
    if not isinstance(stores, list):
        return unknown("data-at-rest encryption data was malformed")
    unencrypted = [
        s.get("name", "?")
        for s in stores
        if isinstance(s, dict) and s.get("encrypted") is False
    ]
    undeclared = [
        s.get("name", "?") for s in stores if isinstance(s, dict) and "encrypted" not in s
    ]
    if unencrypted:
        return config_gap(f"{len(unencrypted)} data store(s) are not encrypted at rest")
    if undeclared:
        return unknown(f"{len(undeclared)} data store(s) did not report an encryption state")
    return config_pass("every read data store reported encryption at rest")


# ---------------------------------------------------------------------------
# The domain
# ---------------------------------------------------------------------------


class SecretsPosture(PostureAssessment):
    """3.3 Secrets / Crypto posture over the deployment's cryptographic hygiene."""

    name = "secrets"
    label = "Secrets / Crypto"
    config_class = SecretsPostureConfig

    CHECKS = (
        PostureCheck(
            key="secrets_tls_validity",
            title="TLS certificate validity",
            severity=RISK_HIGH,
            resource="tls",
            category="tls",
            description="Whether presented TLS certificates validate on handshake.",
            evaluate=_eval_tls_validity,
        ),
        PostureCheck(
            key="secrets_tls_expiry",
            title="TLS certificate expiry",
            severity=RISK_ELEVATED,
            resource="tls",
            category="tls",
            description="TLS certificates within the expiry warning window.",
            evaluate=_eval_tls_expiry,
        ),
        PostureCheck(
            key="secrets_kms_rotation",
            title="KMS key rotation",
            severity=RISK_ELEVATED,
            resource="kms",
            category="keys",
            description="KMS/managed keys without automatic rotation enabled.",
            evaluate=_eval_kms_rotation,
        ),
        PostureCheck(
            key="secrets_store_hygiene",
            title="Secret rotation hygiene",
            severity=RISK_ELEVATED,
            resource="secret_store",
            category="secrets",
            description="Secrets not rotated within the staleness window.",
            evaluate=_eval_secret_store_hygiene,
        ),
        PostureCheck(
            key="secrets_unmanaged_secrets",
            title="Unmanaged secrets",
            severity=RISK_HIGH,
            resource="secret_store",
            category="secrets",
            description="Secrets held outside a managed secret store.",
            evaluate=_eval_unmanaged_secrets,
        ),
        PostureCheck(
            key="secrets_committed_indicators",
            title="Committed-secret indicators",
            severity=RISK_HIGH,
            resource="committed_secrets",
            category="secrets",
            description="Indicators of secrets committed to source (presence only, never values).",
            evaluate=_eval_committed_secret_indicators,
        ),
        PostureCheck(
            key="secrets_encryption_at_rest",
            title="Encryption at rest",
            severity=RISK_ELEVATED,
            resource="encryption_at_rest",
            category="crypto",
            description="Data stores without encryption at rest enabled.",
            evaluate=_eval_encryption_at_rest,
        ),
    )

    @classmethod
    def config_from_settings(cls) -> SecretsPostureConfig:
        return SecretsPostureConfig(
            base_url=getattr(settings, "POSTURE_SECRETS_URL", None),
            token=getattr(settings, "POSTURE_SECRETS_TOKEN", None),
        )
