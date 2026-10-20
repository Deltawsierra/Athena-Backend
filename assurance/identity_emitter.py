"""This backend's own sign-in and role grants, emitted as signed identity records.

Authority chain short 2 (the owner's decision 10, 20 Oct). #138 taught the backend to
take in signed sign-in and delegation records (:mod:`assurance.identity_evidence`) and
to read an authority chain's person hops from them, but nothing in production emitted
one: every chain that starts at a person read ``authenticated_as`` unproven
(``no_authentication_record``). Until an identity provider is added as a second
source (Keycloak fixtures, then Entra ID), the identity provider of record is this
backend: an operator signs in here (:class:`safety.sign_in.SignInView`), and an
operator promotes another here (:meth:`accounts.models.RoleGrant.record`). This
module emits each as the record #138 already verifies -- the same documents, the same
signers, the same intake -- so nothing about how a record is read changes.

WHAT IS EMITTED.

* On each successful sign-in: a ``mythos.authentication/v1`` record. ``person`` and
  ``principal`` are both the account, as :func:`account_ref` names it --
  ``athena-backend:<username>``: this backend knows the person only by the account
  they proved they hold (an identity provider names them separately), and the
  issuer's prefix keeps an account here from ever being read as a same-named user
  of another identity provider. ``identity_provider`` is
  ``{issuer: athena-backend, protocol: password}``;
  ``authenticated_at`` and ``expires_at`` are the issued refresh token's ``iat`` and
  ``exp`` (the session the sign-in opened, before any refresh); ``assertion_digest``
  is :func:`assertion_digest` -- ``sha256:`` over the deployment and a digest of that
  refresh token -- so the token itself never enters a record.
* On each role promotion that names who granted it: a ``mythos.delegation/v1`` record
  of the grant -- ``principal`` the granter (kind ``user``), ``agent`` the promoted
  account (both by :func:`account_ref`), scope ``athena-backend:role:<role>`` (and
  ``athena-backend:role:superuser`` for a superuser: :func:`role_scope`, named for
  this backend so it is never read as an action a customer's tool performs), from
  the instant it was granted with no end (:data:`OPEN_ENDED`), state ``active``. A
  promotion that names nobody (``createsuperuser``, an account created through the
  API) is a grant no one delegated, and has no delegation record.
* Delegation records otherwise: none. This backend delegates nothing to any agent;
  a delegation to an agent is recorded by the grant collector (#138) where one exists.
* The token refresh emits nothing (below).

ON WHICH DEPLOYMENTS. A record names one deployment, and #138 refuses it anywhere
else. A sign-in to this backend is a sign-in to every deployment it hosts -- an
operator's session reaches each one -- so each event is emitted once per deployment,
each with its own outcome id and its own assertion or grant digest (both bind the
deployment, as #138's grant digest does), so no two are a replay of each other.

THE KEYS, AND HOW THE VERIFIER TRUSTS THEM. Two Ed25519 private keys, each a PEM
(PKCS#8) file named by a variable read from the environment, as the keyring's own
path is (the settings file is untouched):

* :data:`SIGN_IN_KEY_ENV` signs sign-in records as ``mythos-signin-collector``;
* :data:`GRANT_KEY_ENV` signs grant records as ``mythos-grant-collector``.

Those are #138's two identity signers (:data:`assurance.composition.SIGNER_EVIDENCE`
maps each to its one kind; :data:`assurance.identity_evidence.SIGNER_WITNESS` makes
each Mythos-witnessed), so no new signer, kind or rule is added. The verifier trusts
them the one way it trusts any signer: each public key is filed in the outcome keyring
(``ASSURANCE_OUTCOME_KEYRING``) under its engine name, and the keyring refuses one key
under two engines, so the sign-in key never signs a grant. Every record is taken in
through :func:`assurance.identity_evidence.ingest` -- the collectors' own intake -- so
a key the keyring does not trust, or a record that is not the one signed, is refused
here exactly as it is at the routes, and nothing is recorded.

FAIL-OPEN FOR THE ACT, FAIL-CLOSED FOR THE PROOF. #138's rule is that only a record
that verifies proves a hop, and that a missing one leaves it ``unproven`` -- never
proven -- holding the decision back. So a record this backend cannot sign or record
(no key configured, a key that cannot be read, no keyring, a refusal, a database
fault) changes nothing but the record: the sign-in is answered as before and the
promotion stands, the failure is logged, and a chain that needed the record reads
``no_authentication_record`` (or ``no_delegation_record``). Refusing the sign-in
instead would lock out an operator who signs in to press stop; nothing here refuses
anything. Every public function returns, never raises.

WHAT IS NEVER IN A RECORD. No password, no token and no key: the refresh and access
tokens appear only as a digest of a digest, the password is never read here, and the
private keys stay in this process (only their signatures and key ids leave).

WHAT THIS NEVER SITS ON. Nothing here runs on a stop, pause, revoke, deactivation or
token-revocation path. The sign-in is not a stop (``token_obtain_pair`` in
:data:`safety.stops.NOT_STOPS`), and a stop client presents the failsafe service token
on the stop itself without signing in (:mod:`safety.service_token`, untouched). A grant
record is emitted only for a promotion -- :meth:`RoleGrant.record` runs for nothing
else -- never for a demotion, a deactivation or a removal, which are revokes; so a
demotion emits no revocation record, and a role grant's record says what was granted
and when, not that it is still held. The token refresh is the route an operator keeps
the session they press stop from (:data:`safety.stops.STOP_ACCESS_ROUTES`), so it emits
nothing: a session refreshed past its first refresh token's expiry reads
``authentication_expired``, which is unproven. Each record is emitted once the act it
records has committed (``transaction.on_commit``), each deployment's in a transaction
of its own, so no stop waits on a signature.

What a stop can still meet is what any evidence write leaves behind: a record's insert,
and the decision refresh it schedules (:mod:`assurance.signals`), which recomputes the
deployment's decision under its row lock -- the lock a pause takes. So a successful
sign-in, which no attempt budget counts (:mod:`safety.sign_in` gives it back), must not
turn into a stream of them: an account's sign-in is recorded on a deployment at most
once in :data:`SIGN_IN_RECORD_INTERVAL_SECONDS`. A burst of sign-ins adds one record and
one refresh per deployment per account per interval, however long it lasts; a sign-in
inside the interval is logged and not recorded, so a dispatch that presents its
assertion reads unproven (``authentication_not_dispatched``) -- the safe direction. A
promotion needs an admin's request, which the per-user throttle already bounds.

Records are append-only: :class:`assurance.models.IdentityEvidence` refuses an update
and a delete, and each sign-in or promotion adds new rows beside the old.
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta, timezone as dt_timezone

from django.db import transaction
from mythos_core import outcome as oc

from . import identity_evidence, observed_outcomes

logger = logging.getLogger(__name__)

AUTHENTICATION = identity_evidence.AUTHENTICATION
DELEGATION = identity_evidence.DELEGATION

#: The variables naming each signing key's PEM file. Read from the environment, by
#: these literal names, on every emission (a rotated key is read at the next one).
SIGN_IN_KEY_ENV = "ATHENA_SIGNIN_RECORD_KEY_FILE"
GRANT_KEY_ENV = "ATHENA_GRANT_RECORD_KEY_FILE"

#: Which signer each kind is emitted as: #138's identity signers, mapped to that kind
#: and nothing else (pinned by test).
SIGNERS: dict[str, str] = {
    AUTHENTICATION: "mythos-signin-collector",
    DELEGATION: "mythos-grant-collector",
}

#: The identity provider a sign-in record names: this backend, by password.
ISSUER = "athena-backend"
PROTOCOL = "password"
#: The observer version the signed outcome carries.
SOURCE_VERSION = "athena-backend"
#: What :func:`assertion_digest` is taken over.
ASSERTION_SCHEMA = "athena-backend.sign-in-assertion/v1"
#: A role grant has no end; a demotion is a revoke, recorded nowhere here.
OPEN_ENDED = "9999-12-31T23:59:59.999999Z"
#: An account's sign-in is recorded on a deployment at most once in this many seconds
#: (see the module docstring): the bound on what a burst of sign-ins can add for a
#: stop to wait behind.
SIGN_IN_RECORD_INTERVAL_SECONDS = 60


class EmitterUnavailable(Exception):
    """A signing key is named but cannot be used. Its message never quotes the key."""


def _stamp(instant: datetime) -> str:
    """An instant in the one spelling mythos_core gives one."""
    return instant.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def _now() -> datetime:
    return datetime.now(dt_timezone.utc)


def signing_key(kind: str):
    """The Ed25519 private key ``kind`` is signed with, or None when its variable is
    unset (the emitter is off for that kind). Raises :class:`EmitterUnavailable` for a
    key that is named and cannot be used."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    if kind == AUTHENTICATION:
        name, path = SIGN_IN_KEY_ENV, os.environ.get("ATHENA_SIGNIN_RECORD_KEY_FILE")
    else:
        name, path = GRANT_KEY_ENV, os.environ.get("ATHENA_GRANT_RECORD_KEY_FILE")
    if not path:
        return None
    try:
        with open(path, "rb") as handle:
            key = serialization.load_pem_private_key(handle.read(), password=None)
    except OSError as exc:
        raise EmitterUnavailable(f"{name} names a file that cannot be read ({exc.strerror})") from None
    except (ValueError, TypeError) as exc:
        raise EmitterUnavailable(f"{name} names no PEM private key ({type(exc).__name__})") from None
    except Exception as exc:  # noqa: BLE001 - an unsupported key type, named by its class and never quoted
        raise EmitterUnavailable(f"{name} names a key that cannot be loaded ({type(exc).__name__})") from None
    if not isinstance(key, Ed25519PrivateKey):
        raise EmitterUnavailable(f"{name} names a {type(key).__name__}, not an Ed25519 private key")
    return key


# ----------------------------------------------------------------- the documents


def assertion_digest(deployment_uuid: str, refresh_token: str) -> str:
    """``sha256:`` over the deployment and a digest of the refresh token a sign-in
    issued: what a sign-in record on that deployment names its assertion by, and what
    a dispatch made in that session presents. One sign-in, one record per deployment;
    the token itself is never in what is digested and kept."""
    session = "sha256:" + hashlib.sha256(refresh_token.encode("utf-8")).hexdigest()
    return oc.evidence_digest_of({"schema": ASSERTION_SCHEMA, "deployment": deployment_uuid, "session": session})


def account_ref(username: str) -> str:
    """How a record names an account of this backend: ``athena-backend:<username>``."""
    return f"{ISSUER}:{username}"


def authentication_document(
    deployment_uuid: str,
    username: str,
    digest: str,
    authenticated_at: datetime,
    expires_at: datetime,
    observed_at: datetime,
) -> dict:
    """The ``mythos.authentication/v1`` document of one sign-in to this backend."""
    return {
        "schema": identity_evidence.AUTHENTICATION_SCHEMA,
        "deployment": deployment_uuid,
        "person": account_ref(username),
        "principal": account_ref(username),
        "identity_provider": {"issuer": ISSUER, "protocol": PROTOCOL},
        "assertion_digest": digest,
        "authenticated_at": _stamp(authenticated_at),
        "expires_at": _stamp(expires_at),
        "witness": identity_evidence.SIGNER_WITNESS[SIGNERS[AUTHENTICATION]],
        "observed_at": _stamp(observed_at),
    }


def role_scope(role: str, is_superuser: bool) -> list[str]:
    """The scope a role grant delegates: the role, and superuser where it was one --
    each named for this backend, ``athena-backend:role:<role>``."""
    roles = {role, *(["superuser"] if is_superuser else [])}
    return sorted(f"{ISSUER}:role:{r}" for r in roles)


def delegation_document(deployment_uuid: str, grant, observed_at: datetime) -> dict:
    """The ``mythos.delegation/v1`` document of one :class:`accounts.models.RoleGrant`:
    its granter delegated its role to the account, from when it was granted."""
    body = {
        "grant_id": f"role-grant-{grant.pk}",
        "principal": {"kind": "user", "ref": account_ref(grant.granted_by_username)},
        "agent": account_ref(grant.account_username),
        "scope": {"actions": role_scope(grant.role, grant.is_superuser)},
        "not_before": _stamp(grant.granted_at),
        "not_after": OPEN_ENDED,
    }
    return {
        "schema": identity_evidence.DELEGATION_SCHEMA,
        "deployment": deployment_uuid,
        "grant": body,
        "grant_digest": identity_evidence.grant_digest(deployment_uuid, body),
        "revocation": {"state": identity_evidence.ACTIVE, "revoked_at": None},
        "witness": identity_evidence.SIGNER_WITNESS[SIGNERS[DELEGATION]],
        "observed_at": _stamp(observed_at),
    }


def sign(kind: str, document: dict, key, run_id: str) -> dict:
    """The DSSE envelope of the outcome ``kind``'s signer signs over ``document``: held,
    for the document's deployment and instant, naming exactly its digest."""
    outcome = oc.build_outcome(
        deployment=document["deployment"],
        workflow=kind,
        status=oc.HELD,
        engine=SIGNERS[kind],
        engine_version=SOURCE_VERSION,
        run_id=run_id,
        evidence_digest=oc.evidence_digest_of(document),
        observed_at=identity_evidence.instant(document["observed_at"]),
    )
    return oc.sign_outcome(outcome, key)


# ----------------------------------------------------------------- emitting


def _key_or_none(kind: str, what: str):
    """``kind``'s signing key, or None -- logged -- when it is not set or cannot be used."""
    try:
        key = signing_key(kind)
    except EmitterUnavailable as exc:
        logger.error("no %s record of %s was emitted: %s", kind, what, exc)
        return None
    if key is None:
        logger.info(
            "no %s record of %s was emitted: %s is not set",
            kind, what, SIGN_IN_KEY_ENV if kind == AUTHENTICATION else GRANT_KEY_ENV,
        )
    return key


def _emit(
    kind: str,
    what: str,
    run_id: str,
    key,
    build: Callable[[str, datetime], dict],
    skip: Callable[[object, datetime], str] | None = None,
) -> int:
    """Sign ``build(deployment_uuid, now)`` with ``key`` as ``kind`` for every
    deployment ``skip`` gives no reason to pass over, and take each in through #138's
    intake, each deployment in a transaction of its own. How many were recorded. Never
    raises: a failure is logged and records nothing more."""
    from .models import Deployment

    try:
        keyring = observed_outcomes.load_keyring()
        deployments = list(Deployment.objects.only("id", "uuid").order_by("pk"))
    except Exception as exc:  # noqa: BLE001 - no keyring or no deployments read: nothing is recorded, nothing refused
        logger.error("no %s record of %s was emitted: %s", kind, what, exc)
        return 0
    recorded = 0
    now = _now()
    for deployment in deployments:
        try:
            why = skip(deployment, now) if skip is not None else ""
            if why:
                logger.info("the %s record of %s for deployment %s was not emitted: %s", kind, what, deployment.pk, why)
                continue
            document = build(str(deployment.uuid), now)
            envelope = sign(kind, document, key, run_id)
            with transaction.atomic():
                _row, refusal = identity_evidence.ingest(deployment, kind, envelope, document, keyring=keyring, now=now)
        except Exception:  # noqa: BLE001 - a record that cannot be made is a record missing, never a refused act
            logger.exception("the %s record of %s for deployment %s was not emitted", kind, what, deployment.pk)
            continue
        if refusal is not None:
            logger.error(
                "the %s record of %s for deployment %s was refused: %s", kind, what, deployment.pk, refusal.reason
            )
            continue
        recorded += 1
    return recorded


def emit_sign_in(refresh_token: str) -> int:
    """Emit the sign-in that issued ``refresh_token`` as a signed ``authentication``
    record on every deployment. How many were recorded; never raises."""
    key = _key_or_none(AUTHENTICATION, "a sign-in")
    if key is None:
        return 0
    try:
        from django.contrib.auth import get_user_model
        from rest_framework_simplejwt.settings import api_settings
        from rest_framework_simplejwt.tokens import RefreshToken

        # Issued by this process a moment ago: read, not re-verified.
        payload = RefreshToken(refresh_token, verify=False).payload
        user_id = payload.get(api_settings.USER_ID_CLAIM)
        issued, expires = payload.get("iat"), payload.get("exp")
        if user_id is None or not isinstance(issued, int) or not isinstance(expires, int):
            logger.error("no authentication record was emitted: the issued token names no account or no lifetime")
            return 0
        User = get_user_model()
        username = (
            User._default_manager.filter(**{api_settings.USER_ID_FIELD: user_id})
            .values_list(User.USERNAME_FIELD, flat=True)
            .first()
        )
        if not username:
            logger.error("no authentication record was emitted: the signed-in account %s cannot be read", user_id)
            return 0
        authenticated_at = datetime.fromtimestamp(issued, dt_timezone.utc)
        expires_at = datetime.fromtimestamp(expires, dt_timezone.utc)
    except Exception:  # noqa: BLE001 - the sign-in stands; only its record is missing
        logger.exception("no authentication record was emitted: the sign-in could not be read")
        return 0

    def build(deployment_uuid: str, now: datetime) -> dict:
        return authentication_document(
            deployment_uuid,
            str(username),
            assertion_digest(deployment_uuid, refresh_token),
            authenticated_at,
            expires_at,
            now,
        )

    principal = account_ref(str(username))

    def recently(deployment, now: datetime) -> str:
        from .models import IdentityEvidence

        since = now - timedelta(seconds=SIGN_IN_RECORD_INTERVAL_SECONDS)
        recorded = IdentityEvidence.objects.filter(
            deployment=deployment, principal=principal, kind=AUTHENTICATION, recorded_at__gt=since
        ).exists()
        return (
            f"this account's sign-in was recorded on it less than {SIGN_IN_RECORD_INTERVAL_SECONDS} s ago"
            if recorded
            else ""
        )

    return _emit(
        AUTHENTICATION, f"account {user_id}'s sign-in", f"sign-in-{uuid.uuid4().hex}", key, build, recently
    )


def emit_role_grant(grant_pk) -> int:
    """Emit :class:`accounts.models.RoleGrant` ``grant_pk`` as a signed ``delegation``
    record on every deployment, when it names who granted it. How many were recorded;
    never raises."""
    try:
        from accounts.models import RoleGrant

        grant = RoleGrant.objects.filter(pk=grant_pk).first()
    except Exception:  # noqa: BLE001 - the promotion stands; only its record is missing
        logger.exception("no delegation record of role grant %s was emitted: it could not be read", grant_pk)
        return 0
    if grant is None:
        logger.error("no delegation record of role grant %s was emitted: it is not recorded", grant_pk)
        return 0
    if grant.granted_by_pk is None or not grant.granted_by_username:
        # Nobody delegated it: there is no delegation to record.
        return 0
    what = f"role grant {grant.pk}"
    key = _key_or_none(DELEGATION, what)
    if key is None:
        return 0
    return _emit(
        DELEGATION,
        what,
        f"role-grant-{grant.pk}",
        key,
        lambda deployment_uuid, now: delegation_document(deployment_uuid, grant, now),
    )


def after_commit(emit: Callable[[], int]) -> None:
    """Run ``emit`` once the transaction the act it records belongs to commits (now,
    outside one), and never let it raise into that act."""
    try:
        transaction.on_commit(emit, robust=True)
    except Exception:  # noqa: BLE001 - the act stands; only its record is missing
        logger.exception("an identity record could not be scheduled; none was emitted")


__all__ = [
    "GRANT_KEY_ENV",
    "SIGNERS",
    "SIGN_IN_RECORD_INTERVAL_SECONDS",
    "SIGN_IN_KEY_ENV",
    "EmitterUnavailable",
    "account_ref",
    "after_commit",
    "assertion_digest",
    "authentication_document",
    "delegation_document",
    "emit_role_grant",
    "emit_sign_in",
    "role_scope",
    "sign",
    "signing_key",
]
