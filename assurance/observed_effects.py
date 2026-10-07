"""Observed effects: what proves an authority chain's ``produces`` hop, from production.

Until now nothing signed an ``observed_effect``. Achilles signed one kind of outcome
-- ``held`` when its gate's permit check passed, an AUTHORIZATION CHECK -- and the
caller carried the action out where no engine saw it. So the last hop of every
chain (``action --produces--> effect``) read unproven, and #134's tests could prove
it only by trusting a made-up "collector" key.

Achilles now carries a permitted action out itself, through the provider the
operator registered for its tool, and when the provider answers success to exactly
the permitted action it signs an outcome with its OBSERVED-EFFECT key: a key that
signs nothing else, under the observer name ``achilles-effect``
(``achilles/observed_effect.py``). This module is the receiving half.

THE KEY. The keyring (``ASSURANCE_OUTCOME_KEYRING``) files that public key under
``achilles-effect``, and :data:`assurance.composition.SIGNER_EVIDENCE` maps that name
to ``observed_effect`` and to nothing else. The keyring already refuses one key filed
under two engines, so the outcome key and the effect key can never be one key here.

THE DOCUMENT. The signed outcome names, as its evidence digest, a
``mythos.observed-effect/v1`` document (:func:`validate_evidence`), defined here and
in Achilles alike and held to the same conformance vectors
(``tests/vectors/observed-effect-v1.json`` in both repositories) -- no code is
shared, and nothing here imports Achilles:

- ``deployment``, ``workflow``: the outcome's own, repeated;
- ``tool``: ``{"kind", "identifier"}``, the tool the action went through;
- ``action``, ``action_digest``: the permitted action and the digest its permit covers;
- ``permit_digest``: ``sha256:`` over the permit as presented;
- ``dispatch_id``: the dispatch it was observed on, one observation per dispatch;
- ``gate_outcome_id``: the authorization check the same dispatch signed;
- ``observed``: ``{"provider", "status_code" (a 2xx), "receipt_id", "response_digest"}``;
- ``observed_at``: the outcome's own instant.

WHAT IS REFUSED, at the route (:func:`examine`, through
:func:`assurance.observed_outcomes.ingest`): every check a signed outcome already
meets (authenticity, the deployment, the clock, a reused outcome id, a stale
replay), and also an envelope signed by any key not mapped to ``observed_effect``;
an outcome that is not ``held``; evidence that is not the document the signature's
digest names, or that names another deployment, workflow or instant; and a second
observation of a dispatch already observed. An observed effect posted to the
generic signed-outcome route is refused there: it is recorded with its document or
not at all.

WHAT PROVES A HOP, at read time (:mod:`assurance.authority_chain`, ``produces``): the
document, re-read against the signed digest (:func:`evidence_in_force`), must name
the tool the chain's ``invokes`` hop names and the gate decision the chain cites, and
no other chain in force may cite the same outcome. An observation of another tool,
of another dispatch, or claimed by two chains does not prove the hop.

WHO MAY POST. Only the observed-effect service: a pre-shared credential,
``ASSURANCE_OBSERVED_EFFECT_TOKEN`` (at least :data:`MIN_TOKEN_LENGTH` characters),
in the :data:`HEADER` header, authenticating as the one account
``ASSURANCE_OBSERVED_EFFECT_USER`` names -- the closure-evidence route's pattern
(:mod:`assurance.closure_evidence`). Read from the environment, as the outcome
keyring is. With either unset, the token too short, or the account missing, the
route answers 401; an operator's session, an admin's included, is answered 403. The
credential is accepted on this route only. Nothing here reads or writes a stop.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
from typing import Any

from mythos_core import outcome as oc
from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import BasePermission

from . import composition

logger = logging.getLogger(__name__)

EVIDENCE_SCHEMA = "mythos.observed-effect/v1"
#: The tool kinds an ``invokes`` hop may name (``authority_chain.TOOL_NODE_KINDS``),
#: spelled out so the schema is this module's to read, and pinned equal by test.
TOOL_KINDS: frozenset[str] = frozenset({"tool", "mcp_server", "skill"})

EVIDENCE_FIELDS = frozenset(
    {
        "schema",
        "deployment",
        "workflow",
        "tool",
        "action",
        "action_digest",
        "permit_digest",
        "dispatch_id",
        "gate_outcome_id",
        "observed",
        "observed_at",
    }
)
TOOL_FIELDS = frozenset({"kind", "identifier"})
OBSERVED_FIELDS = frozenset({"provider", "status_code", "receipt_id", "response_digest"})
BODY_FIELDS = frozenset({"envelope", "evidence"})

_SLUG = re.compile(r"^[-a-zA-Z0-9_]{1,200}$")
_TOKEN = re.compile(r"^[-a-zA-Z0-9_.:+]{1,200}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_UUID4_HEX = re.compile(r"^[0-9a-f]{32}$")
_INSTANT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_MAX_TEXT = 200

HEADER = "X-Observed-Effect-Token"
_META = "HTTP_X_OBSERVED_EFFECT_TOKEN"
TOKEN_ENV = "ASSURANCE_OBSERVED_EFFECT_TOKEN"
USER_ENV = "ASSURANCE_OBSERVED_EFFECT_USER"
#: The shortest credential accepted. A shorter one is treated as unset.
MIN_TOKEN_LENGTH = 32
#: One envelope (bounded by mythos_core) and its document.
MAX_BODY_BYTES = oc.MAX_PAYLOAD_B64 + 16 * 1024


class EvidenceRefused(ValueError):
    """A document that is not a ``mythos.observed-effect/v1`` evidence document."""


# ----------------------------------------------------------------- the document


def _text(value: Any, name: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise EvidenceRefused(f"{name} is text, not {type(value).__name__}")
    if not value and allow_empty:
        return value
    if not value or value != value.strip():
        raise EvidenceRefused(f"{name} is non-empty text with no surrounding whitespace")
    if len(value) > _MAX_TEXT:
        raise EvidenceRefused(f"{name} is at most {_MAX_TEXT} characters")
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in value):
        raise EvidenceRefused(f"{name} contains a control character")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EvidenceRefused(f"{name} is not encodable as UTF-8") from exc
    return value


def _match(value: Any, pattern: re.Pattern[str], name: str, what: str) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        raise EvidenceRefused(f"{name} is {what}")
    return value


def validate_evidence(document: Any) -> dict[str, Any]:
    """``document`` if it is a ``mythos.observed-effect/v1`` evidence document, else
    :class:`EvidenceRefused` naming the first thing wrong. Exactly the fields, no
    more, at every level -- Achilles' own rules, checked against the same vectors."""
    if not isinstance(document, dict):
        raise EvidenceRefused("the evidence is an object")
    if set(document) != EVIDENCE_FIELDS:
        raise EvidenceRefused(
            f"the evidence has exactly the fields {sorted(EVIDENCE_FIELDS)}; missing "
            f"{sorted(EVIDENCE_FIELDS - set(document))}, unexpected "
            f"{sorted(str(k) for k in set(document) - EVIDENCE_FIELDS)}"
        )
    if document["schema"] != EVIDENCE_SCHEMA:
        raise EvidenceRefused(f"schema is {EVIDENCE_SCHEMA!r}")
    _match(document["deployment"], _TOKEN, "deployment", "a deployment token")
    _match(document["workflow"], _SLUG, "workflow", "a workflow slug")
    tool = document["tool"]
    if not isinstance(tool, dict) or set(tool) != TOOL_FIELDS:
        raise EvidenceRefused("tool has exactly the fields kind and identifier")
    if tool["kind"] not in TOOL_KINDS:
        raise EvidenceRefused(f"tool.kind is one of {sorted(TOOL_KINDS)}")
    _text(tool["identifier"], "tool.identifier")
    _text(document["action"], "action")
    _match(document["action_digest"], _HEX64, "action_digest", "64 lowercase hex characters")
    _match(document["permit_digest"], _DIGEST, "permit_digest", "'sha256:' and 64 hex characters")
    _match(document["dispatch_id"], _UUID4_HEX, "dispatch_id", "a 32-character hex uuid")
    _match(document["gate_outcome_id"], _UUID4_HEX, "gate_outcome_id", "a 32-character hex uuid")
    observed = document["observed"]
    if not isinstance(observed, dict) or set(observed) != OBSERVED_FIELDS:
        raise EvidenceRefused(f"observed has exactly the fields {sorted(OBSERVED_FIELDS)}")
    _match(observed["provider"], _TOKEN, "observed.provider", "a provider name token")
    code = observed["status_code"]
    if type(code) is not int or not 200 <= code <= 299:
        raise EvidenceRefused("observed.status_code is the provider's 2xx: only success is observed")
    _text(observed["receipt_id"], "observed.receipt_id", allow_empty=True)
    _match(observed["response_digest"], _DIGEST, "observed.response_digest", "a sha256 digest")
    _match(document["observed_at"], _INSTANT, "observed_at", "YYYY-MM-DDTHH:MM:SS.ffffffZ")
    return document


def examine(outcome: dict, document: Any) -> str:
    """Why an AUTHENTIC ``outcome`` and the ``document`` posted beside it may not be
    recorded as an observed effect, or ``""``. The signature's own checks (key,
    deployment, clock, replay) are :func:`assurance.observed_outcomes.ingest`'s."""
    engine = outcome["observer"]["engine"]
    kind = composition.evidence_kind(composition.BASIS_DEMONSTRATED, engine)
    if kind != composition.EVIDENCE_OBSERVED_EFFECT:
        return (
            f"the outcome is signed by {engine!r}'s key, which is mapped to {kind}, not "
            f"{composition.EVIDENCE_OBSERVED_EFFECT}: only an observed-effect key's outcome is "
            "recorded here"
        )
    if outcome["status"] != oc.HELD:
        return (
            f"an observed effect is signed held, for an effect the dispatch saw complete; this one "
            f"is {outcome['status']!r}"
        )
    try:
        validate_evidence(document)
    except EvidenceRefused as exc:
        return f"the evidence is not a {EVIDENCE_SCHEMA} document: {exc}"
    if oc.evidence_digest_of(document) != outcome["evidence_digest"]:
        return (
            "the evidence is not the document the signature names: its digest is "
            f"{oc.evidence_digest_of(document)}, the outcome signs {outcome['evidence_digest']}"
        )
    for name in ("deployment", "workflow", "observed_at"):
        if document[name] != outcome[name]:
            return f"the evidence's {name} is {document[name]!r}; the outcome signs {outcome[name]!r}"
    return ""


def evidence_in_force(row, deployment_uuid: str) -> dict | None:
    """``row``'s evidence document, if it is one and is exactly what the row's
    signed digest names, for this deployment, workflow and dispatch -- else None.
    Read on every read: the column is writable, the digest is signed (and checked
    against the envelope by :func:`assurance.observed_outcomes.basis_in_force`)."""
    document = getattr(row, "effect_evidence", None)
    if document is None:
        return None
    try:
        validate_evidence(document)
    except EvidenceRefused:
        return None
    if oc.evidence_digest_of(document) != row.evidence_digest:
        return None
    if (
        document["deployment"] != deployment_uuid
        or document["workflow"] != row.workflow
        or document["dispatch_id"] != row.effect_dispatch_id
    ):
        return None
    return document


# ---------------------------------------------------------------- the body


class BodyRefused(ValueError):
    """A body this route cannot read. ``errors`` maps each field to why."""

    def __init__(self, errors: dict):
        self.errors = dict(errors)
        super().__init__("; ".join(f"{k}: {v}" for k, v in self.errors.items()))


def read_body(data: Any) -> tuple[Any, dict]:
    """``(envelope, evidence)`` from ``{"envelope": {...}, "evidence": {...}}``: one
    observed effect per request, exactly those two fields. The envelope is checked
    by the ingest; the evidence's shape here."""
    if not isinstance(data, dict):
        raise BodyRefused({"body": "an object with envelope and evidence"})
    unknown = sorted(str(k) for k in set(data) - BODY_FIELDS)
    missing = sorted(BODY_FIELDS - set(data))
    if unknown or missing:
        raise BodyRefused(
            {**{k: "unknown field" for k in unknown}, **{k: "required" for k in missing}}
        )
    try:
        evidence = validate_evidence(data["evidence"])
    except EvidenceRefused as exc:
        raise BodyRefused({"evidence": str(exc)}) from None
    return data["envelope"], evidence


# ------------------------------------------------------- the service's identity

#: A per-process key for the digests: it only makes the two sides one length.
_DIGEST_KEY = secrets.token_bytes(32)


def _hmac(value) -> bytes:
    return hmac.new(_DIGEST_KEY, str(value).encode("utf-8", "surrogatepass"), hashlib.sha256).digest()


def configured_token() -> str | None:
    """The service credential, or None when it is unset or too short to be safe."""
    token = os.environ.get(TOKEN_ENV)
    if not isinstance(token, str) or len(token) < MIN_TOKEN_LENGTH:
        return None
    return token


def token_matches(request) -> bool:
    expected = configured_token()
    provided = request.META.get(_META)
    if expected is None or provided is None:
        return False
    return hmac.compare_digest(_hmac(provided), _hmac(expected))


class ObservedEffectServiceCredential:
    """``request.auth`` for a request the observed-effect credential authenticated."""

    def __repr__(self):
        return "<observed-effect service credential>"


class ObservedEffectServiceAuthentication(BaseAuthentication):
    """DRF authentication by the observed-effect credential, on that route only (it
    is in no other view's authentication classes). Returns None -- the next class
    decides -- when the credential is absent, does not match, or names no active
    account."""

    def authenticate(self, request):
        django_request = getattr(request, "_request", request)
        if not token_matches(django_request):
            return None
        username = os.environ.get(USER_ENV)
        if not username:
            logger.error("%s is set but %s is not", TOKEN_ENV, USER_ENV)
            return None
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User._default_manager.filter(**{User.USERNAME_FIELD: username}, is_active=True).first()
        if user is None:
            logger.error("%s %r is not an active account", USER_ENV, username)
            return None
        return user, ObservedEffectServiceCredential()

    def authenticate_header(self, request):
        return HEADER


class IsObservedEffectService(BasePermission):
    """Only a request the observed-effect credential authenticated. An operator's
    session -- an admin's, or the service account's own -- is not the service."""

    message = "only the observed-effect service records observed effects"

    def has_permission(self, request, view):
        return isinstance(getattr(request, "auth", None), ObservedEffectServiceCredential)


__all__ = [
    "EVIDENCE_SCHEMA",
    "HEADER",
    "MAX_BODY_BYTES",
    "TOKEN_ENV",
    "USER_ENV",
    "BodyRefused",
    "EvidenceRefused",
    "IsObservedEffectService",
    "ObservedEffectServiceAuthentication",
    "evidence_in_force",
    "examine",
    "read_body",
    "validate_evidence",
]
