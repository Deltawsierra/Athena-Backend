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
``mythos.observed-effect`` document, version 1 to 5. Its fields, its rules, its refusal
codes and its largest size are defined ONCE, in Mythos-Core
(``mythos_core.observed_effect``), for the engine that signs it and for this backend
alike. This module keeps none of them: until the core defined it, a copy of those rules
was kept here by hand and another in Achilles, and the two had drifted. Every name below
that the rest of this backend calls (:func:`validate_evidence`, :class:`EvidenceRefused`,
the schema names, :data:`MAX_BODY_BYTES`) is the core's, read at its first use
(:func:`_core`): the URL conf loads this module for the route's credential, on whatever
request a worker serves first, a stop included, and the document's rules are not loaded
with it. The conformance vectors are the core's own files, carried byte for byte
(``tests/vectors/observed-effect-v1.json`` to ``-v5.json``).

What each version adds is the core's to say. In short: v2 adds ``dispatch``, the state
the dispatch ran under and what it was ``presented``; v3 adds ``dispatch.verified``, what
the gate verified itself; v4 adds the tool contract the gate verified and the permit's
approval recipients; v5 replaces the plain digests of the action and the answer with
keyed references (``action_ref``, ``observed.response_ref``, ``keyed_under``), says which
stage was witnessed (``execution``) and signs the tool binding the permit was decided
for (``dispatch.verified.tool_binding``). A v5 document holding a plain digest of an
action, an answer or a population is refused with the core's code (``plain_digest``).

WHAT THIS BACKEND CAN AND CANNOT CHECK OF A v5 DOCUMENT. A keyed reference is keyed
under the engine's chain key, which this backend does not hold. It checks the signature,
the exact fields, the links to the gate decision, the dispatch and the permit, that two
records of one dispatch under one key id carry the same reference (the core's
``compare_refs``, :mod:`assurance.authority_chain`), that the binding names the
document's tool and that its population is within its bound. It cannot test a guess at
the action, the answer or the targets, and says so (:func:`shown`: ``keyed: not
checkable here``). No route here takes a text and answers whether it matches.

WHAT A READER IS SHOWN (:func:`shown`, served by ``GET .../chain-outcomes/``), in the
core's words: of a v1 to v4 record, ``plain digests`` that are withheld from this reader,
``no tool binding recorded`` (never "within its bound") and ``accepted, from the recorded
2xx; this version has no execution field`` (never "committed"); of a v5 record, its keyed
references, its key id, its execution as signed and its tool binding. A record is JUDGED,
never refused, for what happened: a binding whose bound is larger than the bound of an
approval it rests on is taken in, because it is evidence of what was dispatched, and is
shown with a named finding (:data:`BINDING_BOUND_OVER_APPROVAL`).

WHAT IS REFUSED, at the route (:func:`examine`, through
:func:`assurance.observed_outcomes.ingest`): every check a signed outcome already
meets (authenticity, the deployment, the clock, a reused outcome id, a stale
replay), and also an envelope signed by any key not mapped to ``observed_effect``;
an outcome that is not ``held``; evidence that is not the document the signature's
digest names, or that names another deployment, workflow or instant (each the core's
``verify_observed_effect``, and each refusal says the core's code first); and a second
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
credential is accepted on this route and on the reconciliation-receipt route only (the same
service posts the readback answers its key signs, :mod:`assurance.effect_reconciliation`).
Nothing here reads or writes a stop.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from typing import Any

from mythos_core import outcome as oc
from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import BasePermission

from . import composition

logger = logging.getLogger(__name__)


def _core():
    """``mythos_core.observed_effect``: the one definition of the document.

    Read at first use, never with this module. The URL conf loads this module (the
    routes name its credential classes), and it loads on whatever request a worker serves
    first, a stop included; the document's rules are evidence's, and nothing a stop loads
    or waits on reads them."""
    from mythos_core import observed_effect

    return observed_effect


#: This module's own names for what the core defines, and how each is read from it.
#: Resolved by :func:`__getattr__` when a caller reads one, so each is the core's own
#: object and none is spelled here.
_FROM_THE_CORE = {
    "EVIDENCE_SCHEMA_V1": lambda core: core.EVIDENCE_SCHEMA_V1,
    "EVIDENCE_SCHEMA_V2": lambda core: core.EVIDENCE_SCHEMA_V2,
    "EVIDENCE_SCHEMA_V3": lambda core: core.EVIDENCE_SCHEMA_V3,
    "EVIDENCE_SCHEMA_V4": lambda core: core.EVIDENCE_SCHEMA_V4,
    "EVIDENCE_SCHEMA_V5": lambda core: core.EVIDENCE_SCHEMA_V5,
    # This name has said v3 since v3 was what a dispatch signed, and what reads it here
    # reads exactly what it did. It is NOT the core's ``EVIDENCE_SCHEMA``, which names the
    # newest version: which version an engine signs is the engine's to say, never this
    # backend's, which reads every one of them.
    "EVIDENCE_SCHEMA": lambda core: core.EVIDENCE_SCHEMA_V3,
    "EVIDENCE_SCHEMAS": lambda core: core.EVIDENCE_SCHEMAS,
    "TOOL_KINDS": lambda core: core.TOOL_KINDS,
    "MAX_PRESENTED_CONTRACTS": lambda core: core.MAX_PRESENTED_CONTRACTS,
    "MAX_APPROVAL_RECIPIENTS": lambda core: core.MAX_APPROVAL_RECIPIENTS,
    "RECIPIENT_BOUND": lambda core: core.RECIPIENT_BOUND,
    "RECIPIENT_UNBOUND": lambda core: core.RECIPIENT_UNBOUND,
    "RECIPIENT_ORDER": lambda core: core.RECIPIENT_ORDER,
    # The core exports no field sets. This one name is kept because the G6 test reads it
    # (tests/test_the_gate_verifies_the_tool_contract_it_dispatches_under.py); it is the
    # core's own set, read by its private name at the pinned commit, never typed in.
    "VERIFIED_FIELDS_V4": lambda core: core._VERIFIED_FIELDS_V4,
    "EvidenceRefused": lambda core: core.EvidenceRefused,
    # One envelope (bounded by the core) and one document of the largest size the core's
    # field rules allow a version 5 document: both numbers are the core's.
    "MAX_BODY_BYTES": lambda core: _body_bound(oc.MAX_PAYLOAD_B64, core.MAX_EVIDENCE_BYTES),
}

#: The intake's bound, one object for each pair of the core's two numbers. The route's 413
#: reads it, and the Defender gateway holds it (``audit.middleware.DECLARED_BODY_BOUNDS``):
#: the same object, never a second copy computed beside it. When the core's numbers move,
#: the bound is a new object, as it was.
_BODY_BOUNDS: dict[tuple[int, int], int] = {}


def _body_bound(envelope: int, evidence: int) -> int:
    return _BODY_BOUNDS.setdefault((envelope, evidence), envelope + evidence)


def __getattr__(name: str):
    read = _FROM_THE_CORE.get(name)
    if read is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    return read(_core())


BODY_FIELDS = frozenset({"envelope", "evidence"})

HEADER = "X-Observed-Effect-Token"
_META = "HTTP_X_OBSERVED_EFFECT_TOKEN"
TOKEN_ENV = "ASSURANCE_OBSERVED_EFFECT_TOKEN"
USER_ENV = "ASSURANCE_OBSERVED_EFFECT_USER"
#: The shortest credential accepted. A shorter one is treated as unset.
MIN_TOKEN_LENGTH = 32

#: The named finding of a v5 record whose tool binding's bound (``max_targets``) is
#: larger than the bound of an approval it rests on. The record is taken in and kept: it
#: is evidence of what was dispatched, and refusing it would lose that evidence for good
#: (a refused intake is terminal for the engine). It is judged where it is read.
BINDING_BOUND_OVER_APPROVAL = "binding_bound_over_approval"


# ----------------------------------------------------------------- the document


def validate_evidence(document: Any) -> dict[str, Any]:
    """``document`` if it is a ``mythos.observed-effect`` evidence document, version 1
    to 5, else the core's :class:`EvidenceRefused` with the code of the first rule it
    breaks. The core's ``validate_evidence``, as a reader calls it: nothing is checked
    here."""
    return _core().validate_evidence(document)


def refusal(code: str, reason: str) -> str:
    """How this backend says a refusal of the core's: the core's code, then its reason.
    The same form a signed outcome's verdict is already said in (``wrong_type: ...``)."""
    return f"{code}: {reason}"


def examine(outcome: dict, document: Any, *, envelope: Any, keyring) -> str:
    """Why an AUTHENTIC ``outcome`` and the ``document`` posted beside it may not be
    recorded as an observed effect, or ``""``.

    The core's ``verify_observed_effect`` decides, over the ``envelope`` itself and under
    the ``keyring`` it was verified with: the observer, ``held``, the document's rules
    for its version, the digest the signature names, and the deployment, workflow and
    instant. A refusal says the core's code first. Which signer's outcome is which kind
    of evidence is this backend's own mapping
    (:data:`assurance.composition.SIGNER_EVIDENCE`): it is said beside the core's refusal
    of another observer's outcome, and it is held on its own, so an outcome is recorded
    here only when both agree it is an observed effect. The signature's other checks
    (the deployment it is filed under, the clock, a replay) are
    :func:`assurance.observed_outcomes.ingest`'s."""
    verdict = _core().verify_observed_effect(envelope, document, keyring)
    engine = outcome["observer"]["engine"]
    kind = composition.evidence_kind(composition.BASIS_DEMONSTRATED, engine)
    unmapped = (
        ""
        if kind == composition.EVIDENCE_OBSERVED_EFFECT
        else (
            f"the outcome is signed by {engine!r}'s key, which is mapped to {kind}, not "
            f"{composition.EVIDENCE_OBSERVED_EFFECT}: only an observed-effect key's outcome is "
            "recorded here"
        )
    )
    if not verdict.authentic:
        said = refusal(verdict.code, verdict.reason)
        return f"{said}; {unmapped}" if unmapped and verdict.verdict == oc.WRONG_OBSERVER else said
    if unmapped:
        return unmapped
    if verdict.outcome != outcome:
        # Cannot happen while the caller hands in the envelope it examined. Refused,
        # never assumed: the outcome recorded is the one the core verified.
        return "the envelope is not the one whose outcome was examined"
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
    except _core().EvidenceRefused:
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


def _verified(document: dict) -> dict:
    """``dispatch.verified`` of a document in force, or ``{}`` for a version that has
    none. Read by what the document holds: the core has already held it to exactly the
    fields of its version, so no version is named here."""
    dispatch = document.get("dispatch")
    verified = dispatch.get("verified") if isinstance(dispatch, dict) else None
    return verified if isinstance(verified, dict) else {}


def approval_recipients(row, deployment_uuid: str) -> list[dict] | None:
    """The approval-recipient entries the permit of ``row``'s dispatch bound, exactly
    as a v4 or v5 document signs them (``dispatch.verified.approval_recipients``; ``[]``
    for a permit resting on no approval) -- read from the document its signed digest
    names (:func:`evidence_in_force`), never from a column of its own. ``None`` for every
    other row: a v1, v2 or v3 document records none, and a row with no document in
    force has nothing to say."""
    document = evidence_in_force(row, deployment_uuid)
    if document is None or "approval_recipients" not in _verified(document):
        return None
    return [dict(entry) for entry in _verified(document)["approval_recipients"]]


def binding_findings(document: dict) -> list[dict]:
    """What this backend finds in the tool binding of a document in force, each a named
    finding: today one, :data:`BINDING_BOUND_OVER_APPROVAL`, for each approval that
    names a bound (``max_targets``) smaller than the binding's own. The core holds a
    binding to its own bound and does not compare it with an approval's; by the gate's
    arithmetic the binding's is never the larger. A record where it is was still
    dispatched, so it is kept and judged here, never refused at the intake. ``[]`` for a
    record with no binding, v1 to v4 among them."""
    binding = _verified(document).get("tool_binding")
    if not isinstance(binding, dict):
        return []
    found = []
    for approval in binding["approvals"]:
        limit = approval["max_targets"]
        if limit is not None and binding["max_targets"] > limit:
            found.append(
                {
                    "code": BINDING_BOUND_OVER_APPROVAL,
                    "approval": approval["approval"],
                    "binding_max_targets": binding["max_targets"],
                    "approval_max_targets": limit,
                    "detail": (
                        f"the tool binding's bound is {binding['max_targets']} targets, larger than the bound "
                        f"of {limit} that approval {approval['approval']} names: the record is kept as evidence "
                        "of what was dispatched, and its binding is not within that approval's bound"
                    ),
                }
            )
    return found


def shown(row, deployment_uuid: str) -> dict | None:
    """What a reader of this backend is shown of ``row``'s observed effect, in the
    core's words -- or ``None`` when the row has no document in force.

    Read from the document the signed digest names, never from a column. No reader of
    this API is the key holder or the caller, so a v1 to v4 record's plain digests are
    withheld (the core's ``withhold_plain_digests``: a copy, the stored record
    untouched), and a v5 record's keyed references are shown as what they are: not
    checkable here. Of an older record the words are the core's too: no tool binding was
    recorded, and it was accepted, from the recorded 2xx."""
    document = evidence_in_force(row, deployment_uuid)
    if document is None:
        return None
    core = _core()
    served, told = core.withhold_plain_digests(document)
    execution = core.execution_reading(document)
    keyed = "action_ref" in served
    return {
        "schema": document["schema"],
        # What the record carries, and what this reader is told of it.
        "digests": core.digests_reading(document),
        "digests_served": told,
        "action_reference": served["action_ref" if keyed else "action_digest"],
        "response_reference": served["observed"]["response_ref" if keyed else "response_digest"],
        "keyed_under": served.get("keyed_under"),
        "execution": {
            "state": execution.execution.state,
            "basis": execution.execution.basis,
            "words": execution.words,
        },
        "tool_binding": _verified(served).get("tool_binding"),
        "tool_binding_reading": core.tool_binding_reading(document),
        "findings": binding_findings(document),
    }


# ---------------------------------------------------------------- the body


class BodyRefused(ValueError):
    """A body this route cannot read. ``errors`` maps each field to why."""

    def __init__(self, errors: dict):
        self.errors = dict(errors)
        super().__init__("; ".join(f"{k}: {v}" for k, v in self.errors.items()))


def read_body(data: Any) -> tuple[Any, dict]:
    """``(envelope, evidence)`` from ``{"envelope": {...}, "evidence": {...}}``: one
    observed effect per request, exactly those two fields. The envelope is checked
    by the ingest; the evidence's shape here, by the core, and a refusal of it says the
    core's code first."""
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
    except _core().EvidenceRefused as exc:
        raise BodyRefused({"evidence": refusal(exc.code, str(exc))}) from None
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
    """DRF authentication by the observed-effect credential, on that route and the
    effect-reconciliations route only (it is in no other view's authentication
    classes). Returns None -- the next class decides -- when the credential is absent,
    does not match, or names no active account."""

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


# The names read from the core at first use (``_FROM_THE_CORE``: the schema names,
# ``EvidenceRefused``, ``MAX_BODY_BYTES`` and the rest) are this module's too, and are
# not listed here: a name ``__all__`` lists is one a star import binds when the module
# is imported, which is exactly when the core is not to be loaded.
__all__ = [
    "BINDING_BOUND_OVER_APPROVAL",
    "HEADER",
    "TOKEN_ENV",
    "USER_ENV",
    "BodyRefused",
    "IsObservedEffectService",
    "ObservedEffectServiceAuthentication",
    "approval_recipients",
    "binding_findings",
    "evidence_in_force",
    "examine",
    "read_body",
    "shown",
    "validate_evidence",
]
