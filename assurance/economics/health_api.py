"""The data-health route (MVP step 10; ``docs/economics/spec-v1.md``, section 28.6).

Mounted under ``/api/assurance/`` by :mod:`assurance.urls`, GUARDED, in a guard of
its own: a fault here leaves this route unserved and nothing else -- not the other
economics routes, not the URLconf, not a stop.

- ``GET deployments/<uuid>/economics/data-health/``: every feed source a run of the
  deployment can read (:func:`assurance.economics.feeds.data_health`), on today's
  date: its latest version, the version a run uses, its age, SLA and state
  (``fresh``, ``stale``, ``blocked`` or ``missing``), the last fetch that failed (its
  code only) and the Unknowns it causes -- the deployment's current parameters that
  name it, where it is blocked or missing.

Access is the parameter-set routes' (:mod:`assurance.economics.api`): a signed-in
account, and a deployment the caller cannot see is 404 whether or not it exists; a
viewer reads. It takes no query parameter (400 for any, never ignored), and answers
canonical JSON: the same stored rows on the same date give the same bytes. It reads
no currency table and writes nothing.

None of it is a stop, and it reads or writes nothing a stop or the decision reads:
it is in ``safety.stops.NOT_STOPS``. It does nothing at import but define its view, and imports the feed module
(and through it the outbound client) only inside it: nothing Django loads at start
imports it.
"""

from __future__ import annotations

import json

from django.http import HttpResponse
from django.urls import path
from rest_framework import permissions
from rest_framework.exceptions import ValidationError
from rest_framework.views import APIView

from .api import _deployment


def canonical_bytes(document) -> bytes:
    """One spelling of the answer: sorted keys, no whitespace, UTF-8."""
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


class DataHealthView(APIView):
    """Feed freshness, source failures and the Unknowns they cause, for one deployment."""

    permission_classes = [permissions.IsAuthenticated]

    def get(self, request, uuid):
        deployment = _deployment(request, uuid)
        if request.query_params:
            raise ValidationError(
                {"code": "field_malformed", "detail": "the data-health route takes no query parameter"}
            )
        from . import feeds

        return HttpResponse(canonical_bytes(feeds.data_health(deployment)), content_type="application/json")


urlpatterns = [
    path(
        "deployments/<uuid:uuid>/economics/data-health/",
        DataHealthView.as_view(),
        name="deployment-economics-data-health",
    ),
]
