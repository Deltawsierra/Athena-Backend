"""Signed sign-in and delegation records: what proves a chain's first two hops.

Until now nothing on this platform recorded who signed in as whom, or which principal
delegated what to which agent. So an authority chain's ``authenticated_as`` hop
(person -> user) and its ``delegates_to`` hop (person, user or agent -> agent) read
``unproven`` always (``no_record``), and a chain that starts at a person could never
be fully proven. This module is the record (part 4 of the owner's 7 Oct decision),
built exactly as the observed effect that proves ``produces`` is
(:mod:`assurance.observed_effects`): a signed outcome, a key mapped to one kind and
nothing else, an evidence document the signed digest names, its own route and its
own credential, and the hop proven only by what the document says, re-read against
its signed digest on every read.

THE KEYS. Each kind has a signer of its own, named for what signs it:

- ``mythos-signin-collector`` signs ``authentication`` records: the Mythos-run
  collector that reads the customer's identity provider's sign-in log;
- ``mythos-grant-collector`` signs ``delegation`` records: the Mythos-run collector
  that reads the identity provider's delegation grants and their revocations.

:data:`assurance.composition.SIGNER_EVIDENCE` maps each to its kind and to nothing
else. The keyring refuses one key filed under two engines (and so under two kinds),
so a sign-in key never proves a delegation, and neither is an Achilles key.

WHO WITNESSED IT. Per the owner's 5 Oct scope call, a Mythos-run collector's evidence
is labelled Mythos-witnessed, with a customer-run or third-party collector planned.
Every document carries ``witness``, and it must be the witness its signer is
(:data:`SIGNER_WITNESS`): a Mythos key cannot sign a record that claims a customer
witnessed it. What proves a hop names the witness. It does not weaken the proof,
because no basis rule here reads Mythos-witnessed evidence as weaker: the observed
effect that proves ``produces`` is Mythos-witnessed too (v6.0 spec, limitation 10).

THE DOCUMENTS.

``mythos.authentication/v1`` (:data:`AUTHENTICATION_FIELDS`)
    ``deployment``; ``person`` (who signed in, as the identity provider names them);
    ``principal`` (the account they signed in as -- a chain's ``user`` node);
    ``identity_provider`` ``{issuer, protocol}``; ``assertion_digest`` (``sha256:``
    over the session token or assertion the provider issued -- one sign-in, one
    record); ``authenticated_at`` and ``expires_at`` (the session it opened);
    ``witness``; ``observed_at`` (the outcome's own instant).

``mythos.delegation/v1`` (:data:`DELEGATION_FIELDS`)
    ``deployment``; ``grant`` ``{grant_id, principal {kind, ref}, agent, scope
    {actions}, not_before, not_after}``; ``grant_digest`` -- ``sha256:`` over the
    grant and the deployment (:func:`grant_digest`), recomputed here, so every record
    of one grant names exactly that grant; ``revocation`` ``{state: active|revoked,
    revoked_at}``; ``witness``; ``observed_at``.

WHAT IS REFUSED, at the routes (:func:`ingest`), with nothing recorded: an envelope
that does not verify against the keyring; a signature by a key not mapped to the
route's kind (any other kind's key, an Achilles or Athena key, an unclassified or
untrusted one); an outcome for another deployment, or one not ``held``, or one whose
workflow is not the kind's own name; a document that is not the one the signed
digest names, or that names another deployment, instant or witness; a grant digest
that is not the grant's; an outcome id already recorded anywhere; a replayed
assertion digest; a grant state already recorded. A duplicate is a named 400 --
including two posts that race past the checks -- never a 500.

A REVOCATION IS NEVER DROPPED FOR WHEN IT ARRIVES. The safety rule is absolute:
nothing may block, delay or drop a revoke. A revocation is refused only for what
makes it not a revocation at all (a forged, misdirected or tampered record) or for
being one already recorded word for word -- in which case the revocation it repeats
stands. It is never refused for its age, for its order, or because the grant it
revokes was never recorded. The revoke itself happens at the identity provider; this
route records the evidence of it, and is classified in :mod:`safety.stops` as not a
stop -- it holds no stop back, and nothing on the stop path reads it.

WHO MAY POST. Each route takes only its own service's pre-shared credential, the
observed-effect route's pattern: :data:`AUTHENTICATION_SERVICE` and
:data:`DELEGATION_SERVICE` name the variables and header, read from the environment
(the settings file is untouched). A token shorter than :data:`MIN_TOKEN_LENGTH`, an
unset account, or a missing one reads as unset (401); an operator's session, an
admin's included, is refused (403). Neither credential works on the other's route.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
from dataclasses import dataclass
from datetime import datetime, timezone as dt_timezone
from typing import Any

from django.db import IntegrityError, transaction
from mythos_core import outcome as oc
from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import BasePermission

from . import authority_chain as rule
from . import composition
from . import observed_outcomes

logger = logging.getLogger(__name__)

AUTHENTICATION = composition.EVIDENCE_AUTHENTICATION
DELEGATION = composition.EVIDENCE_DELEGATION
KINDS: frozenset[str] = composition.IDENTITY_EVIDENCE_KINDS

AUTHENTICATION_SCHEMA = "mythos.authentication/v1"
DELEGATION_SCHEMA = "mythos.delegation/v1"
#: The document a grant's digest is taken over: the grant, and the deployment it is on.
GRANT_SCHEMA = "mythos.delegation-grant/v1"
SCHEMAS: dict[str, str] = {AUTHENTICATION: AUTHENTICATION_SCHEMA, DELEGATION: DELEGATION_SCHEMA}

#: Who witnessed a record. Today only ``mythos`` signs; the others are named so a
#: customer-run or third-party collector has a word waiting for it.
WITNESS_MYTHOS = "mythos"
WITNESS_CUSTOMER = "customer"
WITNESS_THIRD_PARTY = "third_party"
WITNESSES: frozenset[str] = frozenset({WITNESS_MYTHOS, WITNESS_CUSTOMER, WITNESS_THIRD_PARTY})
#: Who each identity signer is, as a witness. A signer of an identity kind missing
#: here witnesses nothing, and its records are refused.
SIGNER_WITNESS: dict[str, str] = {
    "mythos-signin-collector": WITNESS_MYTHOS,
    "mythos-grant-collector": WITNESS_MYTHOS,
}

AUTHENTICATION_FIELDS = frozenset(
    {
        "schema",
        "deployment",
        "person",
        "principal",
        "identity_provider",
        "assertion_digest",
        "authenticated_at",
        "expires_at",
        "witness",
        "observed_at",
    }
)
PROVIDER_FIELDS = frozenset({"issuer", "protocol"})
DELEGATION_FIELDS = frozenset(
    {"schema", "deployment", "grant", "grant_digest", "revocation", "witness", "observed_at"}
)
GRANT_FIELDS = frozenset({"grant_id", "principal", "agent", "scope", "not_before", "not_after"})
PRINCIPAL_FIELDS = frozenset({"kind", "ref"})
SCOPE_FIELDS = frozenset({"actions"})
REVOCATION_FIELDS = frozenset({"state", "revoked_at"})
ACTIVE = "active"
REVOKED = "revoked"
#: Who may delegate to an agent: the ``delegates_to`` hop's source kinds, spelled out
#: so the schema is this module's to read, and pinned equal by test.
PRINCIPAL_KINDS: frozenset[str] = frozenset({"person", "user", "agent"})
#: The most actions one grant may delegate.
MAX_ACTIONS = 50
BODY_FIELDS = frozenset({"envelope", "evidence"})

_TOKEN = re.compile(r"^[-a-zA-Z0-9_.:+]{1,200}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_INSTANT = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$")
_MAX_TEXT = 200

MIN_TOKEN_LENGTH = 32
#: One envelope (bounded by mythos_core) and its document.
MAX_BODY_BYTES = oc.MAX_PAYLOAD_B64 + 16 * 1024


class EvidenceRefused(ValueError):
    """A document that is not the identity evidence document it claims to be."""


# ----------------------------------------------------------------- the documents


def _text(value: Any, name: str) -> str:
    if not isinstance(value, str):
        raise EvidenceRefused(f"{name} is text, not {type(value).__name__}")
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


def _exactly(value: Any, fields: frozenset[str], name: str) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        got = sorted(str(k) for k in value) if isinstance(value, dict) else type(value).__name__
        raise EvidenceRefused(f"{name} has exactly the fields {sorted(fields)}, not {got}")
    return value


def instant(value: str) -> datetime:
    """A document's instant, in the one spelling mythos_core gives one."""
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=dt_timezone.utc)


def _instant(value: Any, name: str) -> datetime:
    _match(value, _INSTANT, name, "YYYY-MM-DDTHH:MM:SS.ffffffZ")
    try:
        return instant(value)
    except ValueError as exc:
        raise EvidenceRefused(f"{name} names no real instant") from exc


def grant_digest(deployment: str, grant: dict) -> str:
    """``sha256:`` over the grant and the deployment it is on: what every record of
    one grant -- its granting and its revocation -- names it by."""
    return oc.evidence_digest_of({"schema": GRANT_SCHEMA, "deployment": deployment, **grant})


def validate_authentication(document: Any) -> dict[str, Any]:
    """``document`` if it is a ``mythos.authentication/v1`` document, else
    :class:`EvidenceRefused` naming the first thing wrong. Exactly the fields, at
    every level."""
    _exactly(document, AUTHENTICATION_FIELDS, "the evidence")
    if document["schema"] != AUTHENTICATION_SCHEMA:
        raise EvidenceRefused(f"schema is {AUTHENTICATION_SCHEMA!r}")
    _match(document["deployment"], _TOKEN, "deployment", "a deployment token")
    _text(document["person"], "person")
    _text(document["principal"], "principal")
    provider = _exactly(document["identity_provider"], PROVIDER_FIELDS, "identity_provider")
    _text(provider["issuer"], "identity_provider.issuer")
    _match(provider["protocol"], _TOKEN, "identity_provider.protocol", "a protocol token (oidc, saml, ...)")
    _match(document["assertion_digest"], _DIGEST, "assertion_digest", "'sha256:' and 64 hex characters")
    signed_in = _instant(document["authenticated_at"], "authenticated_at")
    expires = _instant(document["expires_at"], "expires_at")
    if expires <= signed_in:
        raise EvidenceRefused("expires_at is after authenticated_at: a session ends after it opens")
    _witness(document)
    observed = _instant(document["observed_at"], "observed_at")
    if signed_in > observed + observed_outcomes.MAX_CLOCK_SKEW:
        raise EvidenceRefused("authenticated_at is after observed_at: a sign-in was recorded before it happened")
    return document


def validate_delegation(document: Any) -> dict[str, Any]:
    """``document`` if it is a ``mythos.delegation/v1`` document whose grant digest is
    its grant's, else :class:`EvidenceRefused`."""
    _exactly(document, DELEGATION_FIELDS, "the evidence")
    if document["schema"] != DELEGATION_SCHEMA:
        raise EvidenceRefused(f"schema is {DELEGATION_SCHEMA!r}")
    deployment = _match(document["deployment"], _TOKEN, "deployment", "a deployment token")
    grant = _exactly(document["grant"], GRANT_FIELDS, "grant")
    _match(grant["grant_id"], _TOKEN, "grant.grant_id", "a grant id token")
    principal = _exactly(grant["principal"], PRINCIPAL_FIELDS, "grant.principal")
    if principal["kind"] not in PRINCIPAL_KINDS:
        raise EvidenceRefused(f"grant.principal.kind is one of {sorted(PRINCIPAL_KINDS)}")
    _text(principal["ref"], "grant.principal.ref")
    _text(grant["agent"], "grant.agent")
    scope = _exactly(grant["scope"], SCOPE_FIELDS, "grant.scope")
    actions = scope["actions"]
    if not isinstance(actions, list) or not actions or len(actions) > MAX_ACTIONS:
        raise EvidenceRefused(f"grant.scope.actions is a list of 1 to {MAX_ACTIONS} actions")
    for n, action in enumerate(actions):
        _text(action, f"grant.scope.actions[{n}]")
    if actions != sorted(set(actions)):
        raise EvidenceRefused("grant.scope.actions is sorted, each action once: one scope has one spelling")
    opens = _instant(grant["not_before"], "grant.not_before")
    closes = _instant(grant["not_after"], "grant.not_after")
    if closes <= opens:
        raise EvidenceRefused("grant.not_after is after grant.not_before: a window closes after it opens")
    _match(document["grant_digest"], _DIGEST, "grant_digest", "'sha256:' and 64 hex characters")
    if document["grant_digest"] != grant_digest(deployment, grant):
        raise EvidenceRefused(
            f"grant_digest is not the grant's: the grant digests to {grant_digest(deployment, grant)}"
        )
    revocation = _exactly(document["revocation"], REVOCATION_FIELDS, "revocation")
    if revocation["state"] == ACTIVE:
        if revocation["revoked_at"] is not None:
            raise EvidenceRefused("an active grant's revocation.revoked_at is null")
    elif revocation["state"] == REVOKED:
        _instant(revocation["revoked_at"], "revocation.revoked_at")
    else:
        raise EvidenceRefused(f"revocation.state is {ACTIVE!r} or {REVOKED!r}")
    _witness(document)
    _instant(document["observed_at"], "observed_at")
    return document


def _witness(document: dict) -> None:
    if document["witness"] not in WITNESSES:
        raise EvidenceRefused(f"witness is one of {sorted(WITNESSES)}")


_VALIDATORS = {AUTHENTICATION: validate_authentication, DELEGATION: validate_delegation}


def validate(kind: str, document: Any) -> dict[str, Any]:
    return _VALIDATORS[kind](document)


def is_revocation(kind: str, document: Any) -> bool:
    """Whether ``document`` is a delegation record of a revocation -- read off the
    document alone, as the stop classification reads it."""
    if kind != DELEGATION or not isinstance(document, dict):
        return False
    revocation = document.get("revocation")
    return isinstance(revocation, dict) and revocation.get("state") == REVOKED


def replay_key(kind: str, document: dict) -> str:
    """What makes a record a replay, whatever its outcome id: one sign-in per
    assertion the identity provider issued; one record per grant, state and
    revocation instant (so a grant is granted once, and each distinct revocation of
    it is taken, the earliest deciding)."""
    if kind == AUTHENTICATION:
        return f"authentication:{document['assertion_digest']}"
    revocation = document["revocation"]
    return f"delegation:{document['grant_digest']}:{revocation['state']}:{revocation['revoked_at'] or ''}"


def principal_of(kind: str, document: dict) -> str:
    """The principal a record names -- the one a chain's hop names it by: the account
    signed in as, or the one that delegated."""
    return document["principal"] if kind == AUTHENTICATION else document["grant"]["principal"]["ref"]


# ----------------------------------------------------------------------- intake


def examine(kind: str, outcome: dict, document: Any) -> str:
    """Why an AUTHENTIC ``outcome`` and the ``document`` posted beside it may not be
    recorded as ``kind`` evidence, or ``""``."""
    engine = outcome["observer"]["engine"]
    mapped = composition.signer_evidence(engine)
    if mapped != kind:
        return (
            f"the outcome is signed by {engine!r}'s key, which is mapped to {mapped}, not {kind}: only "
            f"a key mapped to {kind} records {kind} evidence here"
        )
    if outcome["workflow"] != kind:
        return f"an {kind} record's outcome names {kind!r} as its workflow, not {outcome['workflow']!r}"
    if outcome["status"] != oc.HELD:
        return f"an {kind} record is signed held; this one is {outcome['status']!r}"
    try:
        validate(kind, document)
    except EvidenceRefused as exc:
        return f"the evidence is not a {SCHEMAS[kind]} document: {exc}"
    if oc.evidence_digest_of(document) != outcome["evidence_digest"]:
        return (
            "the evidence is not the document the signature names: its digest is "
            f"{oc.evidence_digest_of(document)}, the outcome signs {outcome['evidence_digest']}"
        )
    for name in ("deployment", "observed_at"):
        if document[name] != outcome[name]:
            return f"the evidence's {name} is {document[name]!r}; the outcome signs {outcome[name]!r}"
    witness = SIGNER_WITNESS.get(engine)
    if witness is None or document["witness"] != witness:
        return (
            f"the evidence says it was witnessed by {document['witness']!r}; its signer {engine!r} is "
            f"{witness or 'no witness this platform names'}"
        )
    return ""


@dataclass(frozen=True)
class Refusal:
    reason: str


def _verify(envelope: Any, deployment, keyring, now: datetime, kind: str, document: Any):
    """``(outcome, key_id, "")`` for an envelope that may be recorded, else
    ``(None, None, why)``: authenticity, the deployment, the clock -- except that a
    revocation is never refused for its age."""
    verdict = oc.verify_outcome(envelope, keyring)
    if verdict.verdict != oc.AUTHENTIC:
        return None, None, f"{verdict.verdict}: {verdict.reason}"
    outcome = verdict.outcome
    if outcome["deployment"] != str(deployment.uuid):
        return None, None, (
            f"the outcome is for deployment {outcome['deployment']!r}, not this one "
            f"({deployment.uuid}); a signature proves who observed it, not where"
        )
    observed = instant(outcome["observed_at"])
    if observed > now + observed_outcomes.MAX_CLOCK_SKEW:
        return None, None, f"observed_at {outcome['observed_at']} is in the future"
    if observed < now - observed_outcomes.MAX_AGE and not is_revocation(kind, document):
        return None, None, (
            f"observed_at {outcome['observed_at']} is older than the {observed_outcomes.MAX_AGE.days}-day "
            "window a record is accepted in (a revocation is accepted whatever its age)"
        )
    return outcome, verdict.key_id, ""


def ingest(deployment, kind: str, envelope: Any, document: Any, *, keyring=None, now: datetime | None = None):
    """Verify and record one ``kind`` record for ``deployment``: ``(row, None)``, or
    ``(None, Refusal)`` with nothing recorded. Raises
    :class:`assurance.observed_outcomes.KeyringUnavailable` when nothing can be
    verified. Runs inside the caller's transaction (the route's, which refreshes the
    decision beside it)."""
    from .models import AuthorityChain, IdentityEvidence, WorkflowChainOutcome

    keyring = keyring if keyring is not None else observed_outcomes.load_keyring()
    now = now or datetime.now(dt_timezone.utc)
    outcome, key_id, why = _verify(envelope, deployment, keyring, now, kind, document)
    if outcome is None:
        return None, Refusal(why)
    why = examine(kind, outcome, document)
    if why:
        return None, Refusal(why)
    outcome_id = outcome["outcome_id"]
    key = replay_key(kind, document)
    with transaction.atomic():
        if (
            WorkflowChainOutcome.objects.filter(outcome_id=outcome_id).exists()
            or AuthorityChain.objects.filter(outcome_id=outcome_id).exists()
            or IdentityEvidence.objects.filter(outcome_id=outcome_id).exists()
        ):
            return None, Refusal(f"outcome {outcome_id} was already recorded")
        if IdentityEvidence.objects.filter(replay_key=key).exists():
            if kind == AUTHENTICATION:
                return None, Refusal(f"assertion {document['assertion_digest']} was already recorded: a replay")
            state = document["revocation"]["state"]
            stands = " The revocation already recorded stands." if state == REVOKED else ""
            return None, Refusal(
                f"grant {document['grant_digest']} is already recorded {state}"
                f"{' at ' + document['revocation']['revoked_at'] if state == REVOKED else ''}: a replay.{stands}"
            )
        try:
            # A savepoint of its own: the unique columns (outcome id, replay key) are
            # the backstop for two posts racing past the checks above, and a race lost
            # there is a named refusal like any replay -- never a 500.
            with transaction.atomic():
                row = IdentityEvidence.objects.create(
                    deployment=deployment,
                    kind=kind,
                    outcome_id=outcome_id,
                    observer_engine=outcome["observer"]["engine"],
                    observer_key_id=key_id,
                    evidence_digest=outcome["evidence_digest"],
                    envelope=envelope,
                    document=document,
                    replay_key=key,
                    principal=principal_of(kind, document),
                    witness=document["witness"],
                    observed_at=instant(outcome["observed_at"]),
                    recorded_at=now,
                )
        except IntegrityError:
            return None, Refusal(
                "the record already holds this outcome, or this record of the same sign-in or grant: another "
                "post recorded it first"
            )
    return row, None


# ------------------------------------------------------------------ reading


def in_force(row, keyring, deployment_uuid: str) -> dict | None:
    """``row``'s document, if the row still rests on what was signed -- the envelope
    verifies against the keyring as it stands NOW, by a key still mapped to the row's
    kind and witness, saying what the row says -- and the document is exactly what
    the signed digest names, for this deployment. Else None. Read on every read: the
    columns are writable, the signature is not."""
    if not keyring or not isinstance(row.envelope, dict):
        return None
    verdict = observed_outcomes._verified(row.envelope, keyring)
    if verdict.verdict != oc.AUTHENTIC or verdict.outcome is None:
        return None
    signed = verdict.outcome
    try:
        observed = instant(signed["observed_at"])
    except (KeyError, TypeError, ValueError):
        return None
    engine = signed["observer"]["engine"]
    if not (
        signed["outcome_id"] == row.outcome_id
        and signed["deployment"] == deployment_uuid
        and signed["workflow"] == row.kind
        and signed["status"] == oc.HELD
        and observed == row.observed_at
        and engine == row.observer_engine
        and verdict.key_id == row.observer_key_id
        and signed["evidence_digest"] == row.evidence_digest
        and composition.signer_evidence(engine) == row.kind
    ):
        return None
    document = row.document
    try:
        validate(row.kind, document)
    except (EvidenceRefused, KeyError, TypeError):
        return None
    if (
        oc.evidence_digest_of(document) != row.evidence_digest
        or document["deployment"] != deployment_uuid
        or document["witness"] != SIGNER_WITNESS.get(engine)
    ):
        return None
    return document


def as_authentication(row, document: dict) -> rule.Authentication:
    provider = document["identity_provider"]
    return rule.Authentication(
        outcome_id=row.outcome_id,
        person=document["person"],
        principal=document["principal"],
        authenticated_at=instant(document["authenticated_at"]),
        expires_at=instant(document["expires_at"]),
        issuer=provider["issuer"],
        protocol=provider["protocol"],
        witness=document["witness"],
        assertion_digest=document["assertion_digest"],
    )


def as_delegation(row, document: dict) -> rule.Delegation:
    grant, revocation = document["grant"], document["revocation"]
    return rule.Delegation(
        outcome_id=row.outcome_id,
        grant_digest=document["grant_digest"],
        principal_kind=grant["principal"]["kind"],
        principal_ref=grant["principal"]["ref"],
        agent=grant["agent"],
        actions=frozenset(grant["scope"]["actions"]),
        not_before=instant(grant["not_before"]),
        not_after=instant(grant["not_after"]),
        revoked_at=instant(revocation["revoked_at"]) if revocation["state"] == REVOKED else None,
        witness=document["witness"],
    )


def records_for(deployment, principals, keyring) -> tuple[tuple[rule.Authentication, ...], tuple[rule.Delegation, ...]]:
    """The sign-in and delegation records in force on ``deployment`` that name one of
    ``principals``: one query, none when no chain names a principal."""
    from .models import IdentityEvidence

    principals = sorted({p for p in principals if p})
    if not principals:
        return (), ()
    deployment_uuid = str(deployment.uuid)
    authentications, delegations = [], []
    for row in IdentityEvidence.objects.filter(deployment=deployment, principal__in=principals).order_by("id"):
        document = in_force(row, keyring, deployment_uuid)
        if document is None:
            continue
        if row.kind == AUTHENTICATION:
            authentications.append(as_authentication(row, document))
        elif row.kind == DELEGATION:
            delegations.append(as_delegation(row, document))
    return tuple(authentications), tuple(delegations)


# ---------------------------------------------------------------- the body


class BodyRefused(ValueError):
    """A body a route cannot read. ``errors`` maps each field to why."""

    def __init__(self, errors: dict):
        self.errors = dict(errors)
        super().__init__("; ".join(f"{k}: {v}" for k, v in self.errors.items()))


def read_body(kind: str, data: Any) -> tuple[Any, dict]:
    """``(envelope, evidence)`` from ``{"envelope": {...}, "evidence": {...}}``: one
    record per request, exactly those two fields. The envelope is checked by
    :func:`ingest`; the evidence's shape here."""
    if not isinstance(data, dict):
        raise BodyRefused({"body": "an object with envelope and evidence"})
    unknown = sorted(str(k) for k in set(data) - BODY_FIELDS)
    missing = sorted(BODY_FIELDS - set(data))
    if unknown or missing:
        raise BodyRefused({**{k: "unknown field" for k in unknown}, **{k: "required" for k in missing}})
    try:
        evidence = validate(kind, data["evidence"])
    except EvidenceRefused as exc:
        raise BodyRefused({"evidence": str(exc)}) from None
    return data["envelope"], evidence


# ------------------------------------------------------- the services' identities

#: A per-process key for the digests: it only makes the two sides one length.
_DIGEST_KEY = secrets.token_bytes(32)


def _hmac(value) -> bytes:
    return hmac.new(_DIGEST_KEY, str(value).encode("utf-8", "surrogatepass"), hashlib.sha256).digest()


@dataclass(frozen=True)
class Service:
    """One identity-evidence service: the kind it records, the variables its
    credential and account are read from, and the header it presents."""

    kind: str
    token_env: str
    user_env: str
    header: str

    @property
    def meta(self) -> str:
        return "HTTP_" + self.header.upper().replace("-", "_")

    def configured_token(self) -> str | None:
        token = os.environ.get(self.token_env)
        if not isinstance(token, str) or len(token) < MIN_TOKEN_LENGTH:
            return None
        return token

    def token_matches(self, request) -> bool:
        expected = self.configured_token()
        provided = request.META.get(self.meta)
        if expected is None or provided is None:
            return False
        return hmac.compare_digest(_hmac(provided), _hmac(expected))


AUTHENTICATION_SERVICE = Service(
    AUTHENTICATION,
    "ASSURANCE_AUTHENTICATION_EVIDENCE_TOKEN",
    "ASSURANCE_AUTHENTICATION_EVIDENCE_USER",
    "X-Authentication-Evidence-Token",
)
DELEGATION_SERVICE = Service(
    DELEGATION,
    "ASSURANCE_DELEGATION_EVIDENCE_TOKEN",
    "ASSURANCE_DELEGATION_EVIDENCE_USER",
    "X-Delegation-Evidence-Token",
)


class ServiceCredential:
    """``request.auth`` for a request one identity-evidence credential authenticated."""

    def __init__(self, kind: str):
        self.kind = kind

    def __repr__(self):
        return f"<{self.kind} evidence service credential>"


class _ServiceAuthentication(BaseAuthentication):
    service: Service

    def authenticate(self, request):
        django_request = getattr(request, "_request", request)
        if not self.service.token_matches(django_request):
            return None
        username = os.environ.get(self.service.user_env)
        if not username:
            logger.error("%s is set but %s is not", self.service.token_env, self.service.user_env)
            return None
        from django.contrib.auth import get_user_model

        User = get_user_model()
        user = User._default_manager.filter(**{User.USERNAME_FIELD: username}, is_active=True).first()
        if user is None:
            logger.error("%s %r is not an active account", self.service.user_env, username)
            return None
        return user, ServiceCredential(self.service.kind)

    def authenticate_header(self, request):
        return self.service.header


class _IsService(BasePermission):
    kind: str

    def has_permission(self, request, view):
        auth = getattr(request, "auth", None)
        return isinstance(auth, ServiceCredential) and auth.kind == self.kind


class AuthenticationServiceAuthentication(_ServiceAuthentication):
    """The sign-in collector's credential, on the authentications route only."""

    service = AUTHENTICATION_SERVICE


class DelegationServiceAuthentication(_ServiceAuthentication):
    """The grant collector's credential, on the delegations route only."""

    service = DELEGATION_SERVICE


class IsAuthenticationService(_IsService):
    kind = AUTHENTICATION
    message = "only the sign-in collector records authentication evidence"


class IsDelegationService(_IsService):
    kind = DELEGATION
    message = "only the grant collector records delegation evidence"


__all__ = [
    "AUTHENTICATION",
    "AUTHENTICATION_SCHEMA",
    "AUTHENTICATION_SERVICE",
    "DELEGATION",
    "DELEGATION_SCHEMA",
    "DELEGATION_SERVICE",
    "SIGNER_WITNESS",
    "BodyRefused",
    "EvidenceRefused",
    "examine",
    "grant_digest",
    "in_force",
    "ingest",
    "read_body",
    "records_for",
    "validate",
]
