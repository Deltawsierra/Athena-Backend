"""The stop set: every request that stops, pauses, stands down, terminates or revokes.

The rule this module serves is absolute. No control, read failure, stale read,
failed write, flood or kill switch may ever block or delay a stop.

This is the ONE place a request is judged to be a stop. Everything in front of a
view that could hold a request back reads it from here:

* ``audit.middleware.DefenderMiddleware`` never sends a stop to the engine's
  ``/defend`` and never refuses one. It asked about every request, so an engine
  that trickled its answer delayed every stop by 20 s, and in enforce mode its
  block or throttle answer refused them with 403 or 429.
* ``safety.throttling``, the project's default throttles, never refuses a stop
  and never counts one. A user past the per-user rate got 429 on a pause (#310),
  and the engines' poll, which is anonymous, hit the anonymous rate at exactly
  its own polling interval.

A route is named by its URL name (``ResolverMatch.view_name``), so a format
suffix such as ``.json`` is the same route. Each stop route maps its methods to
a predicate that says whether one request is a stop. A request on a stop route
whose body cannot be read the way the view will read it is a stop: a doubt about
the body must never be what holds a stop back.

``tests/test_no_control_holds_back_a_stop.py`` walks the URLconf and fails on a
route that is in neither :data:`STOP_ROUTES` nor :data:`NOT_STOPS`, so a new
route cannot be added without somebody deciding whether it stops something.
"""

from __future__ import annotations

import json
from collections.abc import Mapping

from django.conf import settings
from django.http import QueryDict
from django.urls import Resolver404, resolve

#: The body could not be read here the way the view's parser will read it.
UNREAD = object()


def always(request, read):
    """Every request on this route and method is a stop."""
    return True


def _pause_or_lift(request, read):
    # The view reads `paused`; absent (None) is a routine recompute that keeps
    # the paused state, and anything else pauses or lifts. A body that is not an
    # object is refused by the view with a 400 either way.
    data = read()
    return data is UNREAD or (isinstance(data, Mapping) and data.get("paused") is not None)


#: The claim moves an operator makes to take a claim down.
_TAKE_DOWN = frozenset({"revoked", "contradicted"})


def _revoke_or_contradict(request, read):
    data = read()
    return data is UNREAD or (isinstance(data, Mapping) and data.get("to_status") in _TAKE_DOWN)


def _dispatch_switch(request, read):
    # The per-deployment kill switch for automated dispatch: `enabled`. Turning
    # it back on is in the set too, as a lift is beside a pause.
    data = read()
    return data is UNREAD or (isinstance(data, Mapping) and "enabled" in data)


def _engagement_status(request, read):
    # An engagement is a scan's authority. Pausing or cancelling one is re-read
    # before a running scan's result is recorded (pentest.views.still_authorised),
    # so it is how the backend withdraws a scan it cannot otherwise stop.
    data = read()
    return data is UNREAD or (isinstance(data, Mapping) and "status" in data)


def _engine_poll(request, read):
    # Only a poll that carries the poll token is how a command reaches an engine.
    # One that does not is answered 401, and stays throttled so the token cannot
    # be guessed at speed. The view asks the same function.
    from failsafe.views import poll_token_ok

    return poll_token_ok(request)


#: URL name -> {method: predicate}. A method not listed is not a stop.
STOP_ROUTES = {
    # Pause (`paused` true) and lift (`paused` false) of a deployment.
    "deployment-recompute": {"POST": _pause_or_lift},
    # Revoke or contradict a claim.
    "claim-transition": {"POST": _revoke_or_contradict},
    # The failsafe control plane: pause, stand-down and terminate are drafted,
    # found, read for their signing bytes, signed and cancelled here.
    "failsafe:commands": {"GET": always, "POST": always},
    "failsafe:command-detail": {"GET": always},
    "failsafe:submit-signature": {"POST": always},
    "failsafe:cancel-command": {"POST": always},
    # The engine's poll: the only way a signed command reaches an engine.
    "failsafe:pending": {"GET": _engine_poll},
    # The automated-dispatch kill switch of one deployment.
    "deployment-dispatch-policy": {"PUT": _dispatch_switch},
    # A scan's authority: its engagement paused, cancelled or deleted.
    "pentest:engagement_detail": {"PATCH": _engagement_status, "DELETE": always},
    # An operator's access revoked: demoted, or removed.
    "accounts:user-set-role": {"PATCH": always},
    "accounts:user-detail": {"DELETE": always},
}

_READ = "a read: it changes no running work and no authority"
_CONFIG = "configuration of a deployment: it starts and stops nothing"
_EVIDENCE = "records evidence or a derived state: it starts and stops nothing"

#: URL name -> why no request on it is a stop. "admin:*" is Django's admin site
#: as a whole.
NOT_STOPS = {
    "admin:*": (
        "Django's admin site, served by Django's own views; every stop it could also "
        "make has an API route in STOP_ROUTES, which is what the console and engines call"
    ),
    "health": "the liveness probe: it is already unthrottled and answers at once",
    "token_obtain_pair": (
        "signs in; its anonymous throttle is what bounds credential guessing, "
        "and it stops nothing"
    ),
    "token_refresh": "renews a token; it stops nothing",
    "api-root": _READ,
    "accounts:api-root": _READ,
    "accounts:user-list": "lists or creates operator accounts: it grants, it stops nothing",
    "accounts:user-me": _READ,
    "audit_log_list": _READ,
    "export_pdf": "renders the audit log as a PDF: a read",
    "asset-detail": _READ,
    "asset-list": _READ,
    "claim-list": _READ,
    "claim-detail": _READ,
    "claim-events": _READ,
    "claim-declare-latent-condition": (
        "declares a watch that may mark the claim stale later; it adds a check "
        "and stops nothing now"
    ),
    "claim-withdraw-latent-condition": (
        "withdraws a watch, which can only relax the decision: the opposite of a stop"
    ),
    "deployment-list": _READ,
    "deployment-detail": _READ,
    "deployment-check": "every assurance stream in one consistent read; it writes nothing",
    "deployment-latency": _READ,
    "deployment-receipt": _READ,
    "deployment-assurance-receipt": _READ,
    "deployment-signed-assurance-receipt": _READ,
    "deployment-vendor-packet-candidates": _READ,
    "deployment-chain-birth": _EVIDENCE,
    "deployment-connectors": _READ,
    "deployment-connector-push": "pushes findings to a ticket system by hand: outbound work, not a stop",
    "deployment-connector-config": (
        "a ticket connector's credentials; turning automated dispatch off is the "
        "dispatch policy, which is a stop"
    ),
    "deployment-posture-config": _CONFIG,
    "deployment-dispatch-attempts": _READ,
    "deployment-data-boundary": _CONFIG,
    "deployment-capabilities": _READ,
    "deployment-route-map": _READ,
    "deployment-effective-access": _READ,
    "deployment-ripple-effect": _READ,
    "deployment-personal-context": _READ,
    "deployment-data-lifecycle": _READ,
    "deployment-training-reuse": _READ,
    "deployment-metadata-logging": _READ,
    "deployment-posture": _READ,
    "deployment-cloud-posture": _READ,
    "deployment-secrets-posture": _READ,
    "deployment-repo-posture": _READ,
    "deployment-approved-workflows": _CONFIG,
    "deployment-chain-outcomes": _EVIDENCE,
    "deployment-observed-chain-outcomes": _EVIDENCE,
    "deployment-ai-bom": _READ,
    "deployment-declared-architecture": _CONFIG,
    "deployment-bom-drift": _READ,
    "deployment-record-bom-drift": _EVIDENCE,
    "deployment-compliance": _READ,
    "deployment-business-impact": _READ,
    "deployment-vendor-assurance": _READ,
    "deployment-executive-summary": _READ,
    "deployment-operational-assurance": _READ,
    "deployment-operational-risk": _READ,
    "deployment-assurance-packs": _READ,
    "deployment-assurance-pack": _READ,
    "deployment-assurance-claims": _READ,
    "deployment-recompute-claims": "re-derives claims from the deployment's state: a refresh",
    "deployment-retest-requirements": _READ,
    "deployment-decision-support": _READ,
    "deployment-coverage-manifest-view": _READ,
    "deployment-revalidation-plan": _READ,
    "deployment-check-invalidations": (
        "re-runs the invalidation engine: a refresh; the operator's own take-down "
        "of a claim is the claim transition"
    ),
    "deployment-latent-conditions": _READ,
    "retest-requirement-list": _READ,
    "retest-requirement-detail": _READ,
    "finding-list": _READ,
    "finding-detail": "reads or edits a finding's fields: tracking, not a stop",
    "finding-remediation": _READ,
    "finding-incident-pack": _READ,
    "finding-vendor-packet": _READ,
    "finding-remediation-transition": "moves a finding's remediation state: tracking work, not stopping it",
    "finding-remediation-assign": "assigns a finding's owner: tracking, not a stop",
    "finding-assignable": _READ,
    "provider-list": _CONFIG,
    "provider-detail": _CONFIG,
    "provider-assertion-list": _EVIDENCE,
    "provider-assertion-detail": _EVIDENCE,
    "unknown-list": _READ,
    "unknown-detail": "records how an unknown asset was resolved: evidence",
    "detection:defender-text-scan": "log analysis: text an analyst submits for inspection",
    "detection:defender-file-scan": "log analysis: a file an analyst submits for inspection",
    "detection:defender-list": _READ,
    "detection:defender-detail": _READ,
    "detection:cve-classify": "asks the engine to classify a CVE: analysis, not a stop",
    "detection:cve-list": _READ,
    "detection:cve-detail": _READ,
    "detection:cve-pdf": "renders a CVE report as a PDF: a read",
    "detection:cve-email": "emails a CVE report: it stops nothing",
    "failsafe:state": (
        "reads the engine's live governor state to show whether a stop landed; "
        "it changes nothing"
    ),
    "failsafe:audit": _READ,
    "pentest:run_pentest_scan": "launches a scan: the work a stop would stop",
    "pentest:run_llm_pentest_scan": "launches a scan: the work a stop would stop",
    "pentest:list_pentest_scans": _READ,
    "pentest:detail_pentest_scan": _READ,
    "pentest:download_scan_pdf": "renders a scan report as a PDF: a read",
    "pentest:resend_scan_email": "re-sends a scan report: it stops nothing",
    "pentest:pentest_scan_status": _READ,
    "pentest:allowed_pentest_checks": _READ,
    "pentest:engagements": "lists or creates engagements: it grants authority, it withdraws none",
    "pentest:engagement_plan": "returns a suggested plan for an engagement; it writes nothing",
}


def view_name(request):
    """The URL name the handler will route ``request`` to, or None for no route."""
    match = getattr(request, "resolver_match", None)
    if match is None:
        try:
            match = resolve(request.path_info, getattr(request, "urlconf", None))
        except Resolver404:
            return None
    return match.view_name


def _body(request):
    """The body as the view's parser will read it (DRF's JSON and form parsers),
    or UNREAD. It reads the raw body, never ``request.data``: a parse failure
    there empties DRF's data for the view, which would turn a malformed pause
    into a routine recompute."""
    try:
        length = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        length = 0
    if length == 0:
        # DRF reads no body at all then, and gives the view empty data.
        return {}
    content_type = (request.META.get("CONTENT_TYPE") or "").split(";")[0].strip().lower()
    if content_type not in ("application/json", "application/x-www-form-urlencoded"):
        # Multipart, or a type DRF refuses with a 415: not read here.
        return UNREAD
    try:
        raw = request.body
    except Exception:  # noqa: BLE001 - a body that cannot be read here is read as a stop
        return UNREAD
    encoding = request.encoding or settings.DEFAULT_CHARSET
    if content_type == "application/json":
        try:
            return json.loads(raw.decode(encoding))
        except (ValueError, LookupError, RecursionError):
            return UNREAD
    if content_type == "application/x-www-form-urlencoded":
        try:
            return QueryDict(raw, encoding=encoding)
        except (ValueError, LookupError):
            return UNREAD
    return UNREAD


def is_stop(request):
    """Whether ``request`` (a Django ``HttpRequest``) is a stop.

    A request on no stop route is not one. On a stop route, anything that goes
    wrong while judging it makes it a stop: judging must never be what holds a
    stop back."""
    methods = STOP_ROUTES.get(view_name(request))
    if not methods:
        return False
    method = (request.method or "").upper()
    predicate = methods.get("GET" if method == "HEAD" else method)
    if predicate is None:
        return False
    cache = []

    def read():
        if not cache:
            cache.append(_body(request))
        return cache[0]

    try:
        return bool(predicate(request, read))
    except Exception:  # noqa: BLE001 - on a stop route, a request that cannot be judged is a stop
        return True
