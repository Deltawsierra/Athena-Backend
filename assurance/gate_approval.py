"""The workflow approval in force, read by Achilles' gate itself (authority chain short 3).

Until now this backend learnt which approval an effect's dispatch ran under only from
what the DISPATCHER presented (``mythos.observed-effect/v2``'s ``presented``), which
Achilles signed "as presented" and this backend proved against its history. A caller
that presented none left ``under_policy`` unproven, and nothing the gate admitted the
action on vouched for the one it did present.

On the owner's 8 Oct decision (option b), Achilles' gate reads the approval in force
ITSELF, from this route, at decide time: the approval version's id -- the
:class:`~assurance.models.ApprovalVersion` row that records it -- and its digest
(:func:`assurance.authority_chain_records.approval_digest`). It binds both into its
permit and signs them into the observed effect (``mythos.observed-effect/v3``,
``dispatch.verified.workflow_approval``), and ``under_policy`` reads that reading as
gate-attested (:mod:`assurance.authority_chain`).

THE ROUTE. ``GET /api/assurance/deployments/<uuid>/workflows/<slug>/approval-in-force/``
(:func:`approval_in_force`) answers:

- ``200`` ``{"deployment", "workflow", "version", "digest", "in_force_from"}``: the
  approval as it stands now, and the newest history row, which records exactly that
  digest -- so the version the gate signs is one this backend has on record;
- ``404`` (``code: no_approval_in_force``): no such deployment, or no approval of that
  workflow in force (never approved, or withdrawn);
- ``409`` (``code: approval_history_not_level``): the approval moved and its history
  has not noted it yet (a write no signal saw; the next approval write or decision
  refresh notes it). Nothing is written here: the gate refuses, which fails closed.

WHO MAY READ. Only the gate: a pre-shared credential, ``ASSURANCE_GATE_APPROVAL_TOKEN``
(at least :data:`MIN_TOKEN_LENGTH` characters), in the :data:`HEADER` header,
authenticating as the one account ``ASSURANCE_GATE_APPROVAL_USER`` names -- the
observed-effect route's pattern. It is accepted on this route only, and it reads and
does nothing else. ROLE SEPARATION: a read credential that is also any other service
credential this backend accepts -- the observed-effect service's, the sign-in and grant
collectors', the closure-evidence service's, the failsafe's stop service token and its
poll token -- is treated as unset and logged, so the credential that posts
observations, or stops the platform, can never read an approval, nor the reverse. With
it unset, too short, or its account missing, the route answers 401; an operator's
session, an admin's included, is answered 403.

Nothing here reads or writes a stop: the route is a read (``safety.stops.NOT_STOPS``).
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
from datetime import timezone as dt_timezone

from rest_framework.authentication import BaseAuthentication
from rest_framework.permissions import BasePermission

logger = logging.getLogger(__name__)

HEADER = "X-Gate-Approval-Token"
_META = "HTTP_X_GATE_APPROVAL_TOKEN"
TOKEN_ENV = "ASSURANCE_GATE_APPROVAL_TOKEN"
USER_ENV = "ASSURANCE_GATE_APPROVAL_USER"
#: The shortest credential accepted. A shorter one is treated as unset.
MIN_TOKEN_LENGTH = 32
#: Every other service credential this backend accepts from the environment: the
#: read credential may be none of them (role separation).
OTHER_TOKEN_ENVS: tuple[str, ...] = (
    "ASSURANCE_OBSERVED_EFFECT_TOKEN",
    "ASSURANCE_AUTHENTICATION_EVIDENCE_TOKEN",
    "ASSURANCE_DELEGATION_EVIDENCE_TOKEN",
)
#: And every one it reads from its settings: the closure-evidence service's, and the
#: failsafe's -- the stop service token (``safety.service_token``) and the poll token
#: (``failsafe.views``). A read credential that could also stop the platform, or poll
#: its commands, is not one that only reads.
OTHER_TOKEN_SETTINGS: tuple[str, ...] = (
    "CLOSURE_EVIDENCE_SERVICE_TOKEN",
    "FAILSAFE_SERVICE_TOKEN",
    "FAILSAFE_POLL_TOKEN",
)
NO_APPROVAL_IN_FORCE = "no_approval_in_force"
HISTORY_NOT_LEVEL = "approval_history_not_level"

_DIGEST_KEY = secrets.token_bytes(32)


def _hmac(value) -> bytes:
    return hmac.new(_DIGEST_KEY, str(value).encode("utf-8", "surrogatepass"), hashlib.sha256).digest()


def _others() -> list[str]:
    values = [os.environ.get(name) or "" for name in OTHER_TOKEN_ENVS]
    from django.conf import settings

    values.extend(str(getattr(settings, name, "") or "") for name in OTHER_TOKEN_SETTINGS)
    return [v for v in values if v]


def configured_token() -> str | None:
    """The gate's read credential, or None when it is unset, too short to be safe, or
    also another service's credential (logged: that is not separation)."""
    token = os.environ.get(TOKEN_ENV)
    if not isinstance(token, str) or len(token) < MIN_TOKEN_LENGTH:
        return None
    if any(hmac.compare_digest(_hmac(token), _hmac(other)) for other in _others()):
        logger.error(
            "%s is also another service's credential; the gate's approval read is refused until it is a "
            "credential of its own",
            TOKEN_ENV,
        )
        return None
    return token


def token_matches(request) -> bool:
    expected = configured_token()
    provided = request.META.get(_META)
    if expected is None or provided is None:
        return False
    return hmac.compare_digest(_hmac(provided), _hmac(expected))


class GateApprovalCredential:
    """``request.auth`` for a request the gate's read credential authenticated."""

    def __repr__(self):
        return "<gate approval-read credential>"


class GateApprovalAuthentication(BaseAuthentication):
    """DRF authentication by the gate's read credential, on the approval-in-force route
    only (it is in no other view's authentication classes). Returns None -- the next
    class decides -- when the credential is absent, does not match, or names no active
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
        return user, GateApprovalCredential()

    def authenticate_header(self, request):
        return HEADER


class IsGateApprovalReader(BasePermission):
    """Only a request the gate's read credential authenticated. An operator's session --
    an admin's, or the service account's own -- is not the gate."""

    message = "only the Action Gate's approval-read credential reads the approval in force here"

    def has_permission(self, request, view):
        return isinstance(getattr(request, "auth", None), GateApprovalCredential)


def _stamp(instant) -> str:
    return instant.astimezone(dt_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def approval_in_force(deployment, workflow: str) -> tuple[int, dict]:
    """``(status, body)``: the approval of ``workflow`` in force for ``deployment`` --
    its newest history row's id and digest, which must be the digest of the approval
    as it stands now -- or why there is none (see the module). Reads only."""
    from .approval_history import approvals_now
    from .models import ApprovalVersion

    current = approvals_now(deployment).get(workflow)
    if current is None:
        return 404, {
            "error": f"no approval of workflow {workflow!r} is in force for this deployment",
            "code": NO_APPROVAL_IN_FORCE,
        }
    digest, _tools = current
    latest = (
        ApprovalVersion.objects.filter(deployment=deployment, workflow=workflow)
        .order_by("in_force_from", "id")
        .last()
    )
    if latest is None or latest.digest != digest:
        return 409, {
            "error": (
                f"the approval of workflow {workflow!r} is not yet noted in its history as it stands; the next "
                "approval write or decision refresh notes it"
            ),
            "code": HISTORY_NOT_LEVEL,
        }
    return 200, {
        "deployment": str(deployment.uuid),
        "workflow": workflow,
        "version": str(latest.id),
        "digest": latest.digest,
        "in_force_from": _stamp(latest.in_force_from),
    }


__all__ = [
    "HEADER",
    "HISTORY_NOT_LEVEL",
    "MIN_TOKEN_LENGTH",
    "NO_APPROVAL_IN_FORCE",
    "OTHER_TOKEN_ENVS",
    "TOKEN_ENV",
    "USER_ENV",
    "GateApprovalAuthentication",
    "GateApprovalCredential",
    "IsGateApprovalReader",
    "approval_in_force",
    "configured_token",
]
