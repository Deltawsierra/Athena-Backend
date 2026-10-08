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
``mythos.observed-effect/v3`` document (:func:`validate_evidence`) -- or a ``v2`` or
``v1`` one, which stay readable -- defined here and in Achilles alike and held to the
same conformance vectors (``tests/vectors/observed-effect-v1.json``, ``-v2.json`` and
``-v3.json`` in both repositories) -- no code is shared, and nothing here imports
Achilles:

- ``deployment``, ``workflow``: the outcome's own, repeated;
- ``tool``: ``{"kind", "identifier"}``, the tool the action went through;
- ``action``, ``action_digest``: the permitted action and the digest its permit covers;
- ``permit_digest``: ``sha256:`` over the permit as presented;
- ``dispatch_id``: the dispatch it was observed on, one observation per dispatch;
- ``gate_outcome_id``: the authorization check the same dispatch signed;
- ``observed``: ``{"provider", "status_code" (a 2xx), "receipt_id", "response_digest"}``;
- ``observed_at``: the outcome's own instant;
- v2 only, ``dispatch``: the state the dispatch ran under, bound at dispatch
  (:data:`DISPATCH_FIELDS`) -- from Achilles' service, the instant it left, its
  authority epoch and operator policy at the spend and the permit's; and
  ``presented``, this backend's approval digest, tool contract digests, served route
  and sign-in and grant digests the dispatch was made under, which Achilles signs as
  presented and this backend proves against its own history as of the dispatch
  instant (:mod:`assurance.authority_chain`). A v1 document records none of it, and
  the hops read as of dispatch read it as unrecorded.
- v3 only, ``dispatch.verified`` (:data:`VERIFIED_FIELDS`): what the gate verified
  ITSELF, never copied from what it was presented -- ``approvals_digest``, a digest
  of Achilles' own approvals the permit rested on (``null``: none); and
  ``workflow_approval``, this backend's approval of the workflow in force as the gate
  READ it from this backend's approval-in-force route at decide time
  (:mod:`assurance.gate_approval`): ``deployment``, ``workflow``, the approval
  version's id (``version``, an :class:`~assurance.models.ApprovalVersion` row), its
  digest and when the gate read it (``read_at``) -- ``null`` when the gate has no
  link to this backend. ``under_policy`` reads it as gate-attested
  (:mod:`assurance.authority_chain`); a v2 document, or a v3 one whose reading is
  null, is read exactly as before, as presented.

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

#: The document a dispatch signs now: v1 and the ``dispatch`` block -- the state the
#: dispatch ran under, bound at dispatch (part 5 of the 7 Oct decision). v1 stays
#: readable: it proves ``produces`` as before, and records no dispatch state, so the
#: hops read as of dispatch (``under_policy``, ``invokes``) read it as unrecorded.
#: v3 is v2 and ``dispatch.verified``: what the gate verified itself (authority chain
#: short 3) -- its own approvals' digest, and this backend's workflow approval as the
#: gate read it in force (:data:`VERIFIED_FIELDS`). v2 and v1 stay readable, exactly
#: as before.
EVIDENCE_SCHEMA = "mythos.observed-effect/v3"
EVIDENCE_SCHEMA_V2 = "mythos.observed-effect/v2"
EVIDENCE_SCHEMA_V1 = "mythos.observed-effect/v1"
EVIDENCE_SCHEMAS: tuple[str, ...] = (EVIDENCE_SCHEMA_V1, EVIDENCE_SCHEMA_V2, EVIDENCE_SCHEMA)
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
#: v2's ``dispatch`` block. From Achilles' service, never its caller: when the effect
#: left (``dispatched_at``), the gate's authority epoch at the spend and the one the
#: permit was issued under, and the operator policy the spend found in force and the
#: one the permit was decided under. ``presented``: this backend's authority the
#: dispatch was presented under, which Achilles cannot judge and signs as presented,
#: and which this backend proves against its own history as of ``dispatched_at``
#: (:mod:`assurance.authority_chain`).
DISPATCH_FIELDS = frozenset(
    {"dispatched_at", "epoch", "permit_epoch", "policy_id", "policy_digest", "permit_policy_digest", "presented"}
)
PRESENTED_FIELDS = frozenset({"approval_digest", "contracts", "route_fingerprint", "assertion_digest", "grant_digest"})
CONTRACT_FIELDS = frozenset({"kind", "identifier", "digest"})
#: v3's ``dispatch.verified``: what the gate verified itself, exactly these fields.
VERIFIED_FIELDS = frozenset({"approvals_digest", "workflow_approval"})
#: The gate's reading of this backend's workflow approval in force, exactly these.
READING_FIELDS = frozenset({"deployment", "workflow", "version", "digest", "read_at"})
_VERSION = re.compile(r"^[1-9][0-9]{0,18}$")
#: The most tool contracts one dispatch may present (``tool_contract.MAX_TOOLS_PER_WORKFLOW``).
MAX_PRESENTED_CONTRACTS = 100
_POLICY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

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
    """A document that is not a ``mythos.observed-effect`` evidence document (v1, v2 or v3)."""


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


def _optional(value: Any, pattern: re.Pattern[str], name: str, what: str) -> str | None:
    if value is None:
        return None
    return _match(value, pattern, name, f"null or {what}")


def _validate_presented(raw: Any) -> None:
    name = "dispatch.presented"
    if not isinstance(raw, dict) or set(raw) != PRESENTED_FIELDS:
        raise EvidenceRefused(f"{name} has exactly the fields {sorted(PRESENTED_FIELDS)}")
    _optional(raw["approval_digest"], _HEX64, f"{name}.approval_digest", "64 lowercase hex characters")
    _optional(raw["route_fingerprint"], _HEX64, f"{name}.route_fingerprint", "64 lowercase hex characters")
    _optional(raw["assertion_digest"], _DIGEST, f"{name}.assertion_digest", "a sha256 digest")
    _optional(raw["grant_digest"], _DIGEST, f"{name}.grant_digest", "a sha256 digest")
    contracts = raw["contracts"]
    if not isinstance(contracts, list) or len(contracts) > MAX_PRESENTED_CONTRACTS:
        raise EvidenceRefused(f"{name}.contracts is a list of at most {MAX_PRESENTED_CONTRACTS}")
    keys: list[tuple[str, str]] = []
    for i, entry in enumerate(contracts):
        where = f"{name}.contracts[{i}]"
        if not isinstance(entry, dict) or set(entry) != CONTRACT_FIELDS:
            raise EvidenceRefused(f"{where} has exactly the fields {sorted(CONTRACT_FIELDS)}")
        if entry["kind"] not in TOOL_KINDS:
            raise EvidenceRefused(f"{where}.kind is one of {sorted(TOOL_KINDS)}")
        _text(entry["identifier"], f"{where}.identifier")
        _match(entry["digest"], _HEX64, f"{where}.digest", "64 lowercase hex characters")
        keys.append((entry["kind"], entry["identifier"]))
    if keys != sorted(set(keys)):
        raise EvidenceRefused(f"{name}.contracts is sorted by kind and identifier, one entry per tool")


def _fullmatch(value: Any, pattern: re.Pattern[str], name: str, what: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise EvidenceRefused(f"{name} is {what}")
    return value


def _validate_verified(raw: Any) -> None:
    """v3's ``dispatch.verified``, exactly as Achilles spells it: ``approvals_digest``
    null or a ``sha256:`` digest; ``workflow_approval`` null or the gate's reading --
    its fields matched whole, so a trailing newline is not a digest."""
    name = "dispatch.verified"
    if not isinstance(raw, dict) or set(raw) != VERIFIED_FIELDS:
        raise EvidenceRefused(f"{name} has exactly the fields {sorted(VERIFIED_FIELDS)}")
    if raw["approvals_digest"] is not None:
        _fullmatch(raw["approvals_digest"], _DIGEST, f"{name}.approvals_digest", "null or a sha256 digest")
    reading = raw["workflow_approval"]
    if reading is None:
        return
    where = f"{name}.workflow_approval"
    if not isinstance(reading, dict) or set(reading) != READING_FIELDS:
        raise EvidenceRefused(f"{where} is null or has exactly the fields {sorted(READING_FIELDS)}")
    _fullmatch(reading["deployment"], _TOKEN, f"{where}.deployment", "a deployment token")
    _fullmatch(reading["workflow"], _SLUG, f"{where}.workflow", "a workflow slug")
    _fullmatch(reading["version"], _VERSION, f"{where}.version", "a positive decimal version id")
    _fullmatch(reading["digest"], _HEX64, f"{where}.digest", "64 lowercase hex characters")
    _fullmatch(reading["read_at"], _INSTANT, f"{where}.read_at", "YYYY-MM-DDTHH:MM:SS.ffffffZ")


def _validate_dispatch(block: Any, schema: str = EVIDENCE_SCHEMA_V2) -> None:
    fields = DISPATCH_FIELDS | {"verified"} if schema == EVIDENCE_SCHEMA else DISPATCH_FIELDS
    if not isinstance(block, dict) or set(block) != fields:
        raise EvidenceRefused(f"dispatch has exactly the fields {sorted(fields)}")
    _match(block["dispatched_at"], _INSTANT, "dispatch.dispatched_at", "YYYY-MM-DDTHH:MM:SS.ffffffZ")
    _text(block["epoch"], "dispatch.epoch", allow_empty=True)
    _text(block["permit_epoch"], "dispatch.permit_epoch", allow_empty=True)
    if block["policy_id"] != "":
        _match(block["policy_id"], _POLICY_ID, "dispatch.policy_id", "empty or a policy id")
    for name in ("policy_digest", "permit_policy_digest"):
        if block[name] != "":
            _match(block[name], _DIGEST, f"dispatch.{name}", "empty or a sha256 digest")
    _validate_presented(block["presented"])
    if schema == EVIDENCE_SCHEMA:
        _validate_verified(block["verified"])


def validate_evidence(document: Any) -> dict[str, Any]:
    """``document`` if it is a ``mythos.observed-effect/v3`` evidence document -- or a
    ``v2`` one, which is v3 without ``dispatch.verified``, or a ``v1`` one, which is v2
    without its ``dispatch`` block -- else :class:`EvidenceRefused` naming the first
    thing wrong. Exactly the fields, no more, at every level -- Achilles' own rules,
    checked against the same vectors."""
    if not isinstance(document, dict):
        raise EvidenceRefused("the evidence is an object")
    schema = document.get("schema")
    if schema not in EVIDENCE_SCHEMAS:
        raise EvidenceRefused(f"schema is one of {list(EVIDENCE_SCHEMAS)}")
    fields = EVIDENCE_FIELDS if schema == EVIDENCE_SCHEMA_V1 else EVIDENCE_FIELDS | {"dispatch"}
    if set(document) != fields:
        raise EvidenceRefused(
            f"a {schema} document has exactly the fields {sorted(fields)}; missing "
            f"{sorted(fields - set(document))}, unexpected "
            f"{sorted(str(k) for k in set(document) - fields)}"
        )
    if schema != EVIDENCE_SCHEMA_V1:
        _validate_dispatch(document["dispatch"], schema)
    _match(document["deployment"], _TOKEN, "deployment", "a deployment token")
    _match(document["workflow"], _SLUG, "workflow", "a workflow slug")
    if schema == EVIDENCE_SCHEMA:
        reading = document["dispatch"]["verified"]["workflow_approval"]
        if reading is not None and (
            reading["deployment"] != document["deployment"] or reading["workflow"] != document["workflow"]
        ):
            raise EvidenceRefused(
                "dispatch.verified.workflow_approval names another deployment or workflow than the document's"
            )
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
        return f"the evidence is not an observed-effect document ({' or '.join(EVIDENCE_SCHEMAS)}): {exc}"
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
