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
signers, the same intake. The one thing read differently is how long a role grant's
record proves: one lease (:mod:`assurance.role_grant_lease`).

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
  the instant it was granted for ONE LEASE
  (:data:`assurance.role_grant_lease.ROLE_GRANT_LEASE_SECONDS`, 24 h), state
  ``active``. A promotion that names nobody (``createsuperuser``, an account created
  through the API) is a grant no one delegated, and has no delegation record.
* While the role is still held -- the account exists, is active, and its latest
  promotion's role (and superuser flag) are ones it still has (:func:`held_grant`) --
  :func:`reconcile` re-asserts that grant before its lease ends: a new record, a new
  window ``[now, now + lease)``, a new grant digest. It runs as ``manage.py
  reconcile_role_grants``, on a schedule, in a process of its own: never on a request,
  so never on a stop.
* When a role is withdrawn -- a demotion, the superuser flag taken away, a
  deactivation, a removal (:data:`accounts.models.role_withdrawn`, and an account's
  ``post_delete``) -- a ``revoked`` record of every lease still running of every grant
  the account no longer holds, ``revoked_at`` the instant of the withdrawal
  (:func:`emit_revocations`). The reconcile signs the same for a withdrawal nothing
  announced (a role changed by a path that sends no signal), at the instant it sees it.
* Delegation records otherwise: none. This backend delegates nothing to any agent;
  a delegation to an agent is recorded by the grant collector (#138) where one exists.
* The token refresh emits nothing (below).

WHAT A ROLE GRANT'S RECORD PROVES, AND FOR HOW LONG. ``delegates_to`` reads a role
grant's record within its lease and before its revocation, and ``unproven`` otherwise
(``delegation_expired``, ``delegation_revoked``). So a record nothing re-asserted
lapses at the end of its lease, however the re-assertion failed: no key, a key that
cannot be read, no keyring, the database down, the reconcile never scheduled -- a
failure never extends a lease, and what is unknown is never read as held. The
open-ended records signed before leases were (``not_after`` 9999-12-31, append-only)
are read to one lease from the instant they opened
(:func:`assurance.role_grant_lease.lease_end`): a role still held is re-asserted by
the first reconcile, one long withdrawn proves nothing more.

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
token-revocation path before that stop is answered. The sign-in is not a stop
(``token_obtain_pair`` in :data:`safety.stops.NOT_STOPS`), and a stop client presents
the failsafe service token on the stop itself without signing in
(:mod:`safety.service_token`, untouched). A grant record is emitted for a promotion (a
:class:`accounts.models.RoleGrant` recorded, through its ``post_save``) and by the
reconcile; the module that serves a demotion or a removal (:mod:`accounts`) imports
nothing of this one -- it sends a signal, and what listens here only notes the work.
A withdrawal's revocation is signed AFTER the stop is answered: inside a request, once
the response has been sent and closed (Django's ``request_finished``, which a server
sends after the last byte -- :func:`after_the_answer`; under WSGI and under ASGI
alike, on the request's own worker thread, never on an event loop); outside one, once the
withdrawal commits. Its key, its signature, its read of the records and the decision
refresh its record schedules all come after the answer, and a failure of any of them
is logged and changes nothing the stop did. The token refresh is the route an operator
keeps the session they press stop from (:data:`safety.stops.STOP_ACCESS_ROUTES`), so it
emits nothing: a session refreshed past its first refresh token's expiry reads
``authentication_expired``, which is unproven. Each record is emitted once the act it
records has committed (``transaction.on_commit``), each in a transaction of its own,
so no stop waits on a signature.

What a stop can still meet is what any evidence write leaves behind: a record's insert,
and the decision refresh it schedules (:mod:`assurance.signals`), which recomputes the
deployment's decision under its row lock -- the lock a pause takes. So a successful
sign-in, which no attempt budget counts (:mod:`safety.sign_in` gives it back), must not
turn into a stream of them: an account's sign-in is recorded on a deployment at most
once in :data:`SIGN_IN_RECORD_INTERVAL_SECONDS`. A burst of sign-ins adds one record and
one refresh per deployment per account per interval, however long it lasts; a sign-in
inside the interval is logged and not recorded, so a dispatch that presents its
assertion reads unproven (``authentication_not_dispatched``) -- the safe direction. A
promotion needs an admin's request, which the per-user throttle already bounds; a
withdrawal's revocations are one record per lease still running; the reconcile
re-asserts a held role at most about twice a lease per deployment
(:data:`RENEW_WITHIN_SECONDS`).

Records are append-only: :class:`assurance.models.IdentityEvidence` refuses an update
and a delete, and each sign-in or promotion adds new rows beside the old.
"""

from __future__ import annotations

import hashlib
import logging
import os
import threading
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone as dt_timezone

from django.db import transaction
from mythos_core import outcome as oc

from . import identity_evidence, observed_outcomes, role_grant_lease

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
#: How a role grant's record names it: ``role-grant-<RoleGrant pk>``.
GRANT_ID_PREFIX = "role-grant-"
#: The reconcile re-asserts a held role's grant once the lease it is proven by has
#: less than this left: half a lease, so a run missed or failed -- the reconcile is
#: scheduled hourly -- never lets a held role lapse, and a held role adds about two
#: records a lease per deployment.
RENEW_WITHIN_SECONDS = 12 * 60 * 60
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


def grant_id(grant_pk) -> str:
    """How a role grant's record names :class:`accounts.models.RoleGrant` ``grant_pk``."""
    return f"{GRANT_ID_PREFIX}{grant_pk}"


def delegation_document(deployment_uuid: str, grant, observed_at: datetime, *, opens: datetime | None = None) -> dict:
    """The ``mythos.delegation/v1`` document of one :class:`accounts.models.RoleGrant`:
    its granter delegated its role to the account for ONE LEASE from ``opens`` -- by
    default when it was granted (never later than ``observed_at``: a window opens no
    later than it is signed, so its lease ends within one lease of its record)."""
    opens = min(opens or grant.granted_at, observed_at)
    body = {
        "grant_id": grant_id(grant.pk),
        "principal": {"kind": "user", "ref": account_ref(grant.granted_by_username)},
        "agent": account_ref(grant.account_username),
        "scope": {"actions": role_scope(grant.role, grant.is_superuser)},
        "not_before": _stamp(opens),
        "not_after": _stamp(opens + role_grant_lease.lease()),
    }
    return _grant_record(deployment_uuid, body, {"state": identity_evidence.ACTIVE, "revoked_at": None}, observed_at)


def revocation_document(deployment_uuid: str, body: dict, revoked_at: datetime, observed_at: datetime) -> dict:
    """The ``mythos.delegation/v1`` document revoking the grant ``body`` names -- the
    very body a lease was signed with, so the revocation names its digest -- at
    ``revoked_at``."""
    return _grant_record(
        deployment_uuid, body, {"state": identity_evidence.REVOKED, "revoked_at": _stamp(revoked_at)}, observed_at
    )


def _grant_record(deployment_uuid: str, body: dict, revocation: dict, observed_at: datetime) -> dict:
    return {
        "schema": identity_evidence.DELEGATION_SCHEMA,
        "deployment": deployment_uuid,
        "grant": body,
        "grant_digest": identity_evidence.grant_digest(deployment_uuid, body),
        "revocation": revocation,
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


def _emit_documents(
    kind: str,
    what: str,
    run_id: str,
    key,
    documents_for: Callable[[object, object, datetime], list[dict]],
    recorded_one: Callable[[dict], object] | None = None,
) -> int:
    """Sign each of ``documents_for(deployment, keyring, now)`` with ``key`` as ``kind``,
    for every deployment, and take each in through #138's intake in a transaction of
    its own (``recorded_one`` is told of each one recorded). How many were recorded.
    Never raises: a failure is logged and records nothing more."""
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
            # A savepoint of its own: a read that fails leaves the caller's transaction
            # as it was.
            with transaction.atomic():
                documents = documents_for(deployment, keyring, now)
        except Exception:  # noqa: BLE001 - a record that cannot be made is a record missing, never a refused act
            logger.exception("the %s record of %s for deployment %s was not emitted", kind, what, deployment.pk)
            continue
        for document in documents:
            try:
                envelope = sign(kind, document, key, run_id)
                with transaction.atomic():
                    _row, refusal = identity_evidence.ingest(
                        deployment, kind, envelope, document, keyring=keyring, now=now
                    )
            except Exception:  # noqa: BLE001 - a record that cannot be made is a record missing, never a refused act
                logger.exception("the %s record of %s for deployment %s was not emitted", kind, what, deployment.pk)
                continue
            if refusal is not None:
                logger.error(
                    "the %s record of %s for deployment %s was refused: %s", kind, what, deployment.pk, refusal.reason
                )
                continue
            recorded += 1
            if recorded_one is not None:
                recorded_one(document)
    return recorded


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

    def documents_for(deployment, _keyring, now: datetime) -> list[dict]:
        why = skip(deployment, now) if skip is not None else ""
        if why:
            logger.info("the %s record of %s for deployment %s was not emitted: %s", kind, what, deployment.pk, why)
            return []
        return [build(str(deployment.uuid), now)]

    return _emit_documents(kind, what, run_id, key, documents_for)


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
        grant_id(grant.pk),
        key,
        lambda deployment_uuid, now: delegation_document(deployment_uuid, grant, now),
    )


# ------------------------------------------------- leases: held, revoked, re-asserted


def renew_within() -> timedelta:
    """How close to its end a held role's lease is re-asserted (:data:`RENEW_WITHIN_SECONDS`)."""
    return timedelta(seconds=RENEW_WITHIN_SECONDS)


def held_grant(account_pk):
    """The :class:`accounts.models.RoleGrant` account ``account_pk`` still holds, or
    None: the account exists and is active, its LATEST promotion named who granted it,
    and that promotion's role (and superuser flag) are ones the account still has. An
    earlier promotion is never held -- a later one replaced it, or a withdrawal ended
    it -- so a role an account came back down to holds no grant until someone grants
    it again. Raises when the account or its grants cannot be read: the caller treats
    that as not held, never as held."""
    from django.contrib.auth import get_user_model

    from accounts.models import RoleGrant

    User = get_user_model()
    account = (
        User._default_manager.filter(pk=account_pk).values("role", "is_superuser", "is_active").first()
    )
    if account is None or account["is_active"] is not True:
        return None
    grant = RoleGrant.latest_for(account_pk)
    if grant is None or grant.granted_by_pk is None or not grant.granted_by_username:
        return None
    granted = set(role_scope(grant.role, grant.is_superuser))
    if not granted <= set(role_scope(account["role"], account["is_superuser"] is True)):
        return None
    return grant


@dataclass(frozen=True)
class Lease:
    """One role grant's record, in force and still proving at an instant."""

    grant_id: str
    body: dict
    grant_digest: str
    ends: datetime


def live_leases(deployment, keyring, at: datetime) -> list[Lease]:
    """The role grants' records signed here that are in force on ``deployment`` and
    still prove at ``at``: active, their lease not ended, no revocation in force at or
    before ``at``. A record that does not verify proves nothing and is not listed. A
    lease ends within one lease of its record (:func:`delegation_document`), so only
    the records of the last lease are read."""
    from .models import IdentityEvidence

    since = at - role_grant_lease.lease()
    rows = IdentityEvidence.objects.filter(
        deployment=deployment, kind=DELEGATION, observer_engine=SIGNERS[DELEGATION], observed_at__gt=since
    ).order_by("id")
    granted: dict[str, dict] = {}
    revoked: dict[str, datetime] = {}
    for row in rows:
        document = identity_evidence.in_force(row, keyring, str(deployment.uuid))
        if document is None:
            continue
        body = document["grant"]
        if not str(body["grant_id"]).startswith(GRANT_ID_PREFIX) or not role_grant_lease.is_role_grant(
            body["scope"]["actions"]
        ):
            continue
        digest = document["grant_digest"]
        revocation = document["revocation"]
        if revocation["state"] == identity_evidence.REVOKED:
            when = identity_evidence.instant(revocation["revoked_at"])
            revoked[digest] = min(when, revoked.get(digest, when))
        else:
            granted.setdefault(digest, body)
    live = []
    for digest, body in granted.items():
        ends = role_grant_lease.lease_end(
            body["scope"]["actions"],
            identity_evidence.instant(body["not_before"]),
            identity_evidence.instant(body["not_after"]),
        )
        if ends <= at or (digest in revoked and revoked[digest] <= at):
            continue
        live.append(Lease(body["grant_id"], body, digest, ends))
    return live


def emit_revocations(account_pk, at: datetime | None = None) -> int:
    """Sign a revocation, at ``at`` (the instant the role was withdrawn), of every lease
    still running of every grant account ``account_pk`` no longer holds, on every
    deployment. How many were recorded; never raises. Runs after the withdrawal is
    answered (:func:`after_the_answer`), never before."""
    at = at or _now()
    what = f"account {account_pk}'s withdrawn role"
    try:
        from accounts.models import RoleGrant

        with transaction.atomic():
            named = [
                grant_id(pk)
                for pk in RoleGrant.objects.filter(account_pk=account_pk)
                .exclude(granted_by_pk=None)
                .values_list("pk", flat=True)
            ]
    except Exception:  # noqa: BLE001 - nothing read, nothing revoked here: each lease still ends
        logger.exception("no revocation of %s was emitted: its grants could not be read", what)
        return 0
    if not named:
        # Nobody delegated it a role: no record of one was ever signed.
        return 0
    try:
        with transaction.atomic():
            held = held_grant(account_pk)
    except Exception:  # noqa: BLE001 - unknown is never held: every grant's lease is revoked
        logger.exception("%s: whether it still holds a role could not be read; revoking every lease", what)
        held = None
    withdrawn = set(named) - ({grant_id(held.pk)} if held is not None else set())
    if not withdrawn:
        return 0
    key = _key_or_none(DELEGATION, what)
    if key is None:
        return 0

    def documents_for(deployment, keyring, now: datetime) -> list[dict]:
        uuid_ = str(deployment.uuid)
        return [
            revocation_document(uuid_, lease.body, at, now)
            for lease in live_leases(deployment, keyring, at)
            if lease.grant_id in withdrawn
        ]

    recorded = _emit_documents(DELEGATION, what, f"role-revoke-{uuid.uuid4().hex}", key, documents_for)
    if recorded:
        logger.info("%s: %s revocation record(s) emitted", what, recorded)
    return recorded


@dataclass
class Reconciled:
    """What one run of :func:`reconcile` did. ``ran`` False: nothing was read or
    signed (``why``), and every lease runs out where it stands."""

    ran: bool
    why: str = ""
    #: The emitter is off (its key is not set): nothing was ever signed to reconcile.
    off: bool = False
    reasserted: int = 0
    revoked: int = 0
    unknown: int = 0


def reconcile(now: datetime | None = None) -> Reconciled:
    """Re-assert the grant of every role still held whose lease ends within
    :data:`RENEW_WITHIN_SECONDS` (or has ended), and revoke every lease still running of
    a grant no longer held -- a withdrawal nothing announced -- at ``now``. Off every
    request: ``manage.py reconcile_role_grants``. A failure never extends a lease: an
    account whose role cannot be read is neither re-asserted nor revoked, and with no
    key, no keyring or no database nothing is signed, so each lease ends where it
    stands. Never raises."""
    what = "the role-grant reconcile"
    key = _key_or_none(DELEGATION, what)
    if key is None:
        if not os.environ.get("ATHENA_GRANT_RECORD_KEY_FILE"):
            return Reconciled(False, f"{GRANT_KEY_ENV} is not set: the emitter is off", off=True)
        return Reconciled(False, f"{GRANT_KEY_ENV} names no usable key")
    try:
        observed_outcomes.load_keyring()
    except Exception as exc:  # noqa: BLE001 - nothing verified, nothing re-asserted: each lease runs out
        logger.error("%s could not run: %s", what, exc)
        return Reconciled(False, f"the outcome keyring cannot be read ({type(exc).__name__})")
    try:
        from accounts.models import RoleGrant

        with transaction.atomic():
            named = list(RoleGrant.objects.exclude(granted_by_pk=None).values_list("pk", "account_pk"))
    except Exception as exc:  # noqa: BLE001 - nothing read, nothing re-asserted: each lease runs out
        logger.exception("%s could not read the role grants", what)
        return Reconciled(False, f"the role grants could not be read ({type(exc).__name__})")
    held: dict[str, object] = {}
    unknown: set[str] = set()
    result = Reconciled(True)
    for account_pk in sorted({account for _pk, account in named}):
        try:
            with transaction.atomic():
                grant = held_grant(account_pk)
        except Exception:  # noqa: BLE001 - unknown is never held: nothing re-asserted, nothing revoked
            logger.exception("%s: whether account %s still holds a role could not be read", what, account_pk)
            unknown.update(grant_id(pk) for pk, account in named if account == account_pk)
            result.unknown += 1
            continue
        if grant is not None:
            held[grant_id(grant.pk)] = grant
    at = now or _now()

    def documents_for(deployment, keyring, signed_at: datetime) -> list[dict]:
        uuid_ = str(deployment.uuid)
        live = live_leases(deployment, keyring, at)
        ends: dict[str, datetime] = {}
        for lease in live:
            ends[lease.grant_id] = max(lease.ends, ends.get(lease.grant_id, lease.ends))
        documents = []
        for gid, grant in held.items():
            if gid not in ends or ends[gid] - at < renew_within():
                documents.append(delegation_document(uuid_, grant, signed_at, opens=at))
        for lease in live:
            if lease.grant_id not in held and lease.grant_id not in unknown:
                documents.append(revocation_document(uuid_, lease.body, at, signed_at))
        return documents

    def counted(document: dict) -> None:
        if document["revocation"]["state"] == identity_evidence.REVOKED:
            result.revoked += 1
        else:
            result.reasserted += 1

    _emit_documents(DELEGATION, what, f"role-reconcile-{uuid.uuid4().hex}", key, documents_for, counted)
    return result


# ------------------------------------------- after the answer: never before a stop's

#: The work noted while a request is served, run once its response is closed: kept per
#: THREAD, the one Django serves the request's database connection from (its
#: connections are thread-critical for this reason). Under WSGI that thread serves the
#: whole request. Under ASGI (``config.asgi``) Django's handler runs every synchronous
#: part of one request -- the ``request_started`` receivers, the view, and the
#: response's ``close()`` that sends ``request_finished`` -- on one worker thread of
#: that request's own, so it is that thread here too. A context-local would not do:
#: the handler sends ``request_started`` through ``Signal.asend``, which runs the
#: synchronous receivers inside ``asyncio.gather`` -- in a task of its own -- so a
#: context variable they set never reaches the view, which then read "no request"
#: and ran the revocation on its commit, before the answer (AB-ASGI-DEFER).
_after_answer = threading.local()


def after_the_answer(job: Callable[[], object]) -> None:
    """Run ``job`` once the request being served has been ANSWERED -- its response sent
    and closed (``request_finished``) -- or, outside a request, once the transaction
    the act belongs to commits. All it does now is note ``job``; never raises."""
    try:
        if getattr(_after_answer, "serving", False):
            jobs = getattr(_after_answer, "jobs", None)
            if jobs is None:
                jobs = _after_answer.jobs = []
            jobs.append(job)
            return
        transaction.on_commit(job, robust=True)
    except Exception:  # noqa: BLE001 - the act stands; only its record is missing (each lease still ends)
        logger.exception("an identity record could not be scheduled; none was emitted")


def _request_started(**_kwargs) -> None:
    """A request is being served: what it notes waits for its answer. Work a request
    before it noted and never had answered (its response never closed) is dropped with
    it -- run later it would read another request's state -- and said; each lease it
    would have revoked still ends."""
    try:
        stale = getattr(_after_answer, "jobs", None)
        _after_answer.jobs = []
        _after_answer.serving = True
    except Exception:  # noqa: BLE001 - a request is never held back for a record
        logger.exception("could not note that a request started")
        return
    if stale:
        logger.error("%s identity record(s) noted by a request never answered were not emitted", len(stale))


def _request_finished(**_kwargs) -> None:
    """The response has been sent and closed: run what the request noted, each job on
    its own, none of it able to reach the answer already given."""
    try:
        _after_answer.serving = False
        jobs = getattr(_after_answer, "jobs", None) or []
        _after_answer.jobs = []
    except Exception:  # noqa: BLE001 - the answer is already given; only records are missing
        logger.exception("the identity records a request noted could not be read")
        return
    for job in jobs:
        try:
            job()
        except Exception:  # noqa: BLE001 - the answer is already given; only a record is missing
            logger.exception("an identity record noted by a request was not emitted")


def _role_granted(sender, instance, created=False, raw=False, **_kwargs) -> None:
    """A :class:`accounts.models.RoleGrant` recorded: emit its record once it commits,
    when it names who granted it (nobody delegated one that does not)."""
    if raw or not created:
        return
    try:
        if instance.granted_by_pk is None or not instance.granted_by_username:
            return
        pk = instance.pk
        after_commit(lambda: emit_role_grant(pk))
    except Exception:  # noqa: BLE001 - the promotion stands; only its record is missing
        logger.exception("a role grant's record could not be scheduled")


def _role_withdrawn(sender, account_pk=None, **_kwargs) -> None:
    """An account's role withdrawn: revoke what it no longer holds, after the answer."""
    try:
        at = _now()
        after_the_answer(lambda: emit_revocations(account_pk, at))
    except Exception:  # noqa: BLE001 - the withdrawal stands; the leases still end
        logger.exception("account %s's revocation could not be scheduled", account_pk)


def _account_removed(sender, instance, **_kwargs) -> None:
    """An account removed: every role it held is withdrawn."""
    try:
        _role_withdrawn(sender, account_pk=instance.pk)
    except Exception:  # noqa: BLE001 - the removal stands; the leases still end
        logger.exception("a removed account's revocation could not be scheduled")


def connect() -> None:
    """Listen for what the emitter records (:meth:`assurance.apps.AssuranceConfig.ready`):
    a role grant recorded, a role withdrawn, an account removed, and when a request
    starts and has been answered."""
    from django.contrib.auth import get_user_model
    from django.core.signals import request_finished, request_started
    from django.db.models.signals import post_delete, post_save

    from accounts.models import RoleGrant, role_withdrawn

    post_save.connect(_role_granted, sender=RoleGrant, dispatch_uid="identity_emitter.role_granted")
    role_withdrawn.connect(_role_withdrawn, dispatch_uid="identity_emitter.role_withdrawn")
    post_delete.connect(_account_removed, sender=get_user_model(), dispatch_uid="identity_emitter.account_removed")
    request_started.connect(_request_started, dispatch_uid="identity_emitter.request_started")
    request_finished.connect(_request_finished, dispatch_uid="identity_emitter.request_finished")


def after_commit(emit: Callable[[], int]) -> None:
    """Run ``emit`` once the transaction the act it records belongs to commits (now,
    outside one), and never let it raise into that act."""
    try:
        transaction.on_commit(emit, robust=True)
    except Exception:  # noqa: BLE001 - the act stands; only its record is missing
        logger.exception("an identity record could not be scheduled; none was emitted")


__all__ = [
    "GRANT_ID_PREFIX",
    "GRANT_KEY_ENV",
    "RENEW_WITHIN_SECONDS",
    "SIGNERS",
    "SIGN_IN_RECORD_INTERVAL_SECONDS",
    "SIGN_IN_KEY_ENV",
    "EmitterUnavailable",
    "Lease",
    "Reconciled",
    "account_ref",
    "after_commit",
    "after_the_answer",
    "assertion_digest",
    "authentication_document",
    "connect",
    "delegation_document",
    "emit_revocations",
    "emit_role_grant",
    "emit_sign_in",
    "grant_id",
    "held_grant",
    "live_leases",
    "reconcile",
    "renew_within",
    "revocation_document",
    "role_scope",
    "sign",
    "signing_key",
]
