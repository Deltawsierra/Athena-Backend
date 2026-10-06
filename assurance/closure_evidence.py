"""The engine service's route for retest-closure evidence (Phase 6 item 3, A1).

``POST /api/assurance/findings/<uuid>/closure-evidence/`` is the one way a retest
run reaches the closure gate (:mod:`assurance.retest_closure`): it stores one
finding's evidence document through
:func:`~assurance.retest_closure.record_closure_evidence` and nothing else. It
closes nothing. A close is still an operator's PATCH, and the gate still decides
it on the latest record.

WHO MAY CALL IT. Only the engine's own service identity: a pre-shared credential,
``CLOSURE_EVIDENCE_SERVICE_TOKEN`` (at least :data:`MIN_TOKEN_LENGTH` characters;
``openssl rand -hex 32`` makes one), presented in the :data:`HEADER` header. It
authenticates as the one account ``CLOSURE_EVIDENCE_SERVICE_USER`` names, which the
record is attributed to (``recorded_by``). This is how the backend already lets a
service in without a password (``FAILSAFE_POLL_TOKEN``, ``FAILSAFE_SERVICE_TOKEN``,
:mod:`safety.service_token`): a header token compared as two HMAC digests of one
length in constant time, accepted on its own route only. With either setting unset,
the token too short, or the account missing or inactive, the route is off: every
request is answered 401. An operator's own session -- an admin's included -- is
answered 403: an operator cannot type in a retest result. The credential is
accepted nowhere else; on any other route the header is ignored.

WHAT IT TAKES, EXACTLY. ``{"document": {...}, "content_digest": "sha256:<hex>"}``.
The ``document`` is Minotaur-Backend's remediation replay row
(``minotaur_backend/remediation_outcomes.py``, ``POST /remediation-outcomes``), so
the same document can be sent on there unchanged:

- ``finding_type`` -- the finding's own type, as this backend stores it;
- ``finding_ref``  -- the finding's uuid, the one in the URL;
- ``engine``       -- the producer's name;
- ``origin``       -- one of :class:`~assurance.models.ClaimEvidence.Origin`; only
  ``independent`` can carry a closure;
- ``remediation``  -- ``{"kind", "control_changed"}``, what the repair changed;
- ``replay``       -- ``{"reached": bool, "original_effect", "variants", "utility"}``:
  ``original_effect`` and each variant's reading one of ``gone``/``present``/
  ``unknown``, ``utility`` one of ``retained``/``broken``/``unknown``. ``variants``
  names each adjacent path replayed (at most :data:`MAX_VARIANTS`). A PRODUCER MUST
  SUPPLY THEM: a replay of no variant is kept and is inconclusive, never closed;
- ``fixtures``     -- the gate's fixture document: ``vulnerable``, ``repaired``,
  ``benign`` and ``incomplete_repair`` (one run per named pattern), each run
  ``{"ran": bool, "outcome": "passed"|"failed"|"errored"}``, ``outcome`` null or
  absent when it did not run.

Every field is typed and every one is required, except a fixture class or pattern,
which may be left out (the gate then names it "not recorded"). A field nobody
defined is refused by name, at every level -- an ``outcome`` or ``result`` above
all: what a replay came to is computed (:func:`~assurance.retest_closure.classify`),
never taken. Text is non-empty, at most :data:`MAX_TEXT` characters, with no
surrounding whitespace and no control characters; the body is at most
:data:`MAX_BODY_BYTES` bytes, refused 413 before it is read.

THE DIGEST. ``content_digest`` is ``sha256:`` over the document's canonical JSON --
sorted keys, no spaces, UTF-8 (:func:`canonical_digest`), the digest
Minotaur-Backend computes for the same row. It is recomputed here and refused
unless the body's matches, and the recomputed one is what is stored: the record
names the exact document it was made from, and the dataset row made from the same
document carries the same digest.

WHAT IS STORED. Every document that can be read whole, whatever it came to: the
record's ``fixtures`` and ``origin`` are the document's, its ``document`` the whole
of it. A replay that did not show the effect gone is kept and closes nothing -- the
gate holds a record to the replay it carries (``retest_closure.replay_reasons``).
The answer says what it came to (``result``, ``reasons``) and the finding's closure
standing now. Nothing is stored for a request refused for any reason.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import secrets

from django.conf import settings
from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import BasePermission

from .retest_closure import (
    EFFECT_READINGS,
    FIXTURE_CLASSES,
    INCOMPLETE_REPAIR,
    INCOMPLETE_REPAIR_PATTERNS,
    OUTCOMES,
    UTILITY_READINGS,
)

logger = logging.getLogger(__name__)

HEADER = "X-Closure-Evidence-Token"
_META = "HTTP_X_CLOSURE_EVIDENCE_TOKEN"

#: The shortest credential accepted. A shorter one is treated as unset.
MIN_TOKEN_LENGTH = 32

#: The largest body the route reads -- Minotaur-Backend's own bound for a replay
#: row (``MAX_OUTCOME_BYTES``), so a document stored here is never one it refuses
#: for its size.
MAX_BODY_BYTES = 64 * 1024
#: The longest text field, and the most variants -- Minotaur-Backend's bounds.
MAX_TEXT = 500
MAX_VARIANTS = 32

BODY_FIELDS = frozenset({"document", "content_digest"})
DOCUMENT_FIELDS = frozenset(
    {"finding_type", "finding_ref", "engine", "origin", "remediation", "replay", "fixtures"}
)
REMEDIATION_FIELDS = frozenset({"kind", "control_changed"})
REPLAY_FIELDS = frozenset({"reached", "original_effect", "variants", "utility"})
RUN_FIELDS = frozenset({"ran", "outcome"})

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


# ---------------------------------------------------------------------------
# The engine service's identity
# ---------------------------------------------------------------------------

#: A per-process key for the digests: it only makes the two sides one length, so
#: it never needs to be shared or kept.
_DIGEST_KEY = secrets.token_bytes(32)


def _hmac(value) -> bytes:
    return hmac.new(_DIGEST_KEY, str(value).encode("utf-8", "surrogatepass"), hashlib.sha256).digest()


def configured_token():
    """The service credential, or None when it is unset or too short to be safe."""
    token = getattr(settings, "CLOSURE_EVIDENCE_SERVICE_TOKEN", None)
    if not isinstance(token, str) or len(token) < MIN_TOKEN_LENGTH:
        return None
    return token


def token_matches(request) -> bool:
    """Whether ``request`` (a Django ``HttpRequest``) carries the configured credential."""
    expected = configured_token()
    provided = request.META.get(_META)
    if expected is None or provided is None:
        return False
    return hmac.compare_digest(_hmac(provided), _hmac(expected))


class EngineServiceCredential:
    """``request.auth`` for a request the engine service's credential authenticated."""

    def __repr__(self):
        return "<closure evidence engine service credential>"


class EngineServiceAuthentication(BaseAuthentication):
    """DRF authentication by the engine service's credential, on the closure-evidence
    route only (it is in no other view's authentication classes). Returns None -- the
    next class decides -- when the credential is absent, does not match, or names no
    active account."""

    def authenticate(self, request):
        django_request = getattr(request, "_request", request)
        if not token_matches(django_request):
            return None
        username = getattr(settings, "CLOSURE_EVIDENCE_SERVICE_USER", None)
        if not isinstance(username, str) or not username:
            logger.error("CLOSURE_EVIDENCE_SERVICE_TOKEN is set but CLOSURE_EVIDENCE_SERVICE_USER is not")
            return None
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User._default_manager.filter(**{User.USERNAME_FIELD: username}, is_active=True).first()
        if user is None:
            logger.error("CLOSURE_EVIDENCE_SERVICE_USER %r is not an active account", username)
            return None
        return user, EngineServiceCredential()

    def authenticate_header(self, request):
        # The first class's header is the one DRF sends with a 401: without one a
        # request that authenticates no way at all is answered 403.
        return HEADER


class IsEngineService(BasePermission):
    """Only a request the engine service's credential authenticated. An operator's
    session -- an admin's, or the service account's own -- is not the service."""

    message = "only the engine service records closure evidence"

    def has_permission(self, request, view):
        return isinstance(getattr(request, "auth", None), EngineServiceCredential)


# ---------------------------------------------------------------------------
# The document
# ---------------------------------------------------------------------------


class DocumentRefused(ValueError):
    """A body that cannot be read whole. ``errors`` maps each field path to why."""

    def __init__(self, errors: dict):
        self.errors = dict(errors)
        super().__init__("; ".join(f"{k}: {v}" for k, v in self.errors.items()))


def canonical_digest(document) -> str:
    """``sha256:`` over ``document``'s canonical JSON: sorted keys, no spaces, UTF-8.
    Minotaur-Backend's ``remediation_outcomes.digest`` of the same row."""
    payload = json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _fields(value, path: str, allowed: frozenset, required: frozenset, errors: dict) -> bool:
    """Whether ``value`` is an object with only ``allowed`` and all ``required`` keys;
    every other key is named in ``errors``."""
    if not isinstance(value, dict):
        errors[path] = "must be an object"
        return False
    ok = True
    for key in sorted((str(k) for k in value if k not in allowed)):
        errors[f"{path}.{key}" if path else key] = "unknown field"
        ok = False
    for key in sorted(required - set(value)):
        errors[f"{path}.{key}" if path else key] = "required"
        ok = False
    return ok


def _text(value, path: str, errors: dict) -> None:
    if not isinstance(value, str):
        errors[path] = "must be text"
    elif not value.strip():
        errors[path] = "must not be blank"
    elif len(value) > MAX_TEXT:
        errors[path] = f"must be at most {MAX_TEXT} characters"
    elif value != value.strip():
        errors[path] = "must be sent with no surrounding whitespace"
    elif _CONTROL.search(value):
        errors[path] = "must hold no control characters"
    else:
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            errors[path] = "must be valid UTF-8 text"


def _word(value, path: str, vocabulary: frozenset, errors: dict) -> None:
    if not isinstance(value, str) or value not in vocabulary:
        errors[path] = f"must be one of {sorted(vocabulary)}"


def _run(value, path: str, errors: dict) -> None:
    if not _fields(value, path, RUN_FIELDS, frozenset({"ran"}), errors):
        return
    ran = value["ran"]
    if not isinstance(ran, bool):
        errors[f"{path}.ran"] = "must be true or false"
        return
    outcome = value.get("outcome")
    if ran:
        _word(outcome, f"{path}.outcome", OUTCOMES, errors)
    elif outcome is not None:
        errors[f"{path}.outcome"] = "must be null or absent for a run that did not run"


def _fixtures(value, errors: dict) -> None:
    path = "document.fixtures"
    if not _fields(value, path, frozenset(FIXTURE_CLASSES), frozenset(), errors):
        return
    for name in FIXTURE_CLASSES:
        if name not in value:
            continue
        if name != INCOMPLETE_REPAIR:
            _run(value[name], f"{path}.{name}", errors)
            continue
        patterns = value[name]
        if _fields(patterns, f"{path}.{name}", frozenset(INCOMPLETE_REPAIR_PATTERNS), frozenset(), errors):
            for pattern in INCOMPLETE_REPAIR_PATTERNS:
                if pattern in patterns:
                    _run(patterns[pattern], f"{path}.{name}.{pattern}", errors)


def _replay(value, errors: dict) -> None:
    path = "document.replay"
    if not _fields(value, path, REPLAY_FIELDS, REPLAY_FIELDS, errors):
        return
    if not isinstance(value["reached"], bool):
        errors[f"{path}.reached"] = "must be true or false"
    _word(value["original_effect"], f"{path}.original_effect", EFFECT_READINGS, errors)
    _word(value["utility"], f"{path}.utility", UTILITY_READINGS, errors)
    variants = value["variants"]
    if not isinstance(variants, dict):
        errors[f"{path}.variants"] = "must be an object naming each adjacent path replayed"
        return
    if len(variants) > MAX_VARIANTS:
        errors[f"{path}.variants"] = f"must name at most {MAX_VARIANTS} paths"
        return
    for name, reading in variants.items():
        name_errors: dict = {}
        _text(name, "name", name_errors)
        if name_errors:
            errors[f"{path}.variants"] = f"each variant's name {name_errors['name']}"
            return
        _word(reading, f"{path}.variants.{name}", EFFECT_READINGS, errors)


def read_body(data, *, finding) -> tuple[dict, str]:
    """``(document, content_digest)`` from a request body for ``finding``, or
    :class:`DocumentRefused` naming every field that cannot be read. The document
    is returned as sent: nothing is trimmed, defaulted or reordered, so its digest
    is the one the producer computed."""
    from .models import ClaimEvidence

    errors: dict = {}
    if not _fields(data, "", BODY_FIELDS, BODY_FIELDS, errors):
        raise DocumentRefused(errors or {"body": "must be an object"})
    document, claimed = data["document"], data["content_digest"]
    if not isinstance(claimed, str) or not _DIGEST.fullmatch(claimed):
        errors["content_digest"] = "must be sha256: and 64 lowercase hex digits"
    if _fields(document, "document", DOCUMENT_FIELDS, DOCUMENT_FIELDS, errors):
        for name in ("finding_type", "finding_ref", "engine"):
            _text(document[name], f"document.{name}", errors)
        _word(document["origin"], "document.origin", frozenset(ClaimEvidence.Origin.values), errors)
        remediation = document["remediation"]
        if _fields(remediation, "document.remediation", REMEDIATION_FIELDS, REMEDIATION_FIELDS, errors):
            for name in sorted(REMEDIATION_FIELDS):
                _text(remediation[name], f"document.remediation.{name}", errors)
        _replay(document["replay"], errors)
        _fixtures(document["fixtures"], errors)
        if "document.finding_ref" not in errors and document["finding_ref"] != str(finding.uuid):
            errors["document.finding_ref"] = "must be this finding's uuid"
        if "document.finding_type" not in errors and document["finding_type"] != finding.finding_type:
            errors["document.finding_type"] = "must be this finding's type"
    if errors:
        raise DocumentRefused(errors)
    digest = canonical_digest(document)
    if not hmac.compare_digest(digest, claimed):
        raise DocumentRefused(
            {"content_digest": "does not match the document: sha256 over its canonical JSON (sorted keys, no spaces, UTF-8)"}
        )
    return document, digest
