"""The override revoke: a STOP (review round 1 of #169, H1; ``docs/economics/spec-v1.md``,
section 35.5).

``POST deployments/<uuid>/economics/overrides/<override uuid>/revoke/`` takes away the
approval a Financial Exposure Receipt would be signed on: from it on, the sensitive
override is not in force (``override_revoked``), and never again. It only ever takes
authority away, as a claim's revoke takes a claim down, so it is in the stop set
(``safety.stops.STOP_ROUTES``) and is held back by nothing:

- no gateway and no throttle: a revoke whose body is a remark at most (none, ``{}``,
  or a text ``note`` and/or ``reason``, JSON or URL-encoded, at most 64 KiB) is a stop
  and rides the stop exemption (``audit.middleware``, ``safety.throttling``), the
  failsafe service token included;
- no validation: the body is read as a stop is judged
  (:func:`safety.stops.canonical_body`), never by a parser, and no body is refused --
  not for a field, a type, a media type or its size. The ``reason`` (else the
  ``note``), where it is text, is kept, cut to :data:`REASON_MAX` characters; anything
  else is recorded with no reason;
- no rule, state or idempotency: a revocation is recorded for an override in any
  state -- pending, in force, expired or already revoked -- and every one is
  recorded (:class:`~assurance.economics.models.OverrideRevocation`, whose check
  reads nothing and refuses nothing);
- no lock it does not own: one indexed read of the override it names, then ONE
  insert in autocommit -- no transaction, no run slot, no economics service, no
  engine -- and the answer is made from what is in hand, reading nothing after it.

It refuses only what is authorisation, not a control: a viewer (403: only an admin or
an analyst writes economics records) and an override the caller cannot see on that
deployment (404). Where the database itself refuses the insert, the answer says so
(503, nothing recorded, send it again): a revoke is never reported that was not
recorded.

This module imports the economics MODELS only (which ``assurance.models`` loads with
Django) and ``safety.stops``: no economics route module, service, report or engine,
so a fault in any of them (the economics fault plugins, ``tests/economics_fault_cases.py``)
leaves the revoke served. ``assurance/urls.py`` imports it in a guard of its own.
"""

from __future__ import annotations

from django.db import DatabaseError
from django.urls import path
from rest_framework import permissions, status
from rest_framework.exceptions import NotFound, PermissionDenied
from rest_framework.response import Response
from rest_framework.views import APIView

from safety.stops import canonical_body

from .models import OverrideRevocation, SensitiveOverride

#: The longest reason a revocation keeps; a longer one is cut, never refused.
REASON_MAX = 2000
#: How long a caller waits before sending a revoke again that the database refused.
RETRY_AFTER_SECONDS = 1


def _privileged(user) -> bool:
    """Who writes economics records: an admin or an analyst (as
    ``assurance.economics.api._may_write``; spelled here so this module imports no
    economics route module)."""
    return bool(
        getattr(user, "is_superuser", False) or getattr(user, "is_admin", False) or getattr(user, "is_analyst", False)
    )


def remark(body) -> str:
    """The reason a revoke's body gives: its text ``reason``, else its text ``note``,
    cut to :data:`REASON_MAX` characters; ``""`` for anything else. Never raises."""
    if not isinstance(body, dict):
        return ""
    for name in ("reason", "note"):
        value = body.get(name)
        if isinstance(value, str):
            return value[:REASON_MAX]
    return ""


class OverrideRevokeView(APIView):
    """A revocation of a sensitive override: a stop, refused by no control."""

    permission_classes = [permissions.IsAuthenticated]
    # No parser: DRF never reads the body, so no body is refused (400, 413, 415).
    parser_classes: list = []

    def post(self, request, uuid, override):
        if not _privileged(request.user):
            raise PermissionDenied("Overrides are revoked by an admin or an analyst.")
        found = (
            SensitiveOverride._base_manager.filter(uuid=override, scenario__deployment__uuid=uuid)
            .values_list("pk", flat=True)
            .first()
        )
        if found is None:
            raise NotFound("No such override on this deployment.")
        reason = remark(canonical_body(request._request))
        revocation = OverrideRevocation(override_id=found, revoked_by=request.user, reason=reason)
        try:
            revocation.save()
        except DatabaseError:
            return Response(
                {"code": "economics_busy", "detail": "The database refused the write and nothing was recorded; "
                 "send the revoke again."},
                status=status.HTTP_503_SERVICE_UNAVAILABLE,
                headers={"Retry-After": str(RETRY_AFTER_SECONDS), "Cache-Control": "no-store"},
            )
        response = Response(
            {
                "override": {
                    "uuid": str(override),
                    "in_force": False,
                    "not_in_force_because": "override_revoked",
                },
                "revocation": {
                    "uuid": str(revocation.uuid),
                    "revoked_by": revocation.revoked_by_username or None,
                    "revoked_at": revocation.revoked_at.isoformat(),
                    "reason": revocation.reason,
                },
            }
        )
        response["Cache-Control"] = "no-store"
        return response


urlpatterns = [
    path(
        "deployments/<uuid:uuid>/economics/overrides/<uuid:override>/revoke/",
        OverrideRevokeView.as_view(),
        name="deployment-economics-override-revoke",
    ),
]
