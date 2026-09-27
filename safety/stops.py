"""The stop set: every request that stops, pauses, stands down, terminates or revokes.

The rule this module serves is absolute. No control, read failure, stale read,
failed write, flood or kill switch may ever block or delay a stop. And the
exemption is exactly the stop set: nothing that is not stop-direction rides it.

This is the ONE place a request is judged to be a stop. Everything in front of a
view that could hold a request back reads it from here:

* ``audit.middleware.DefenderMiddleware`` never sends a stop to the engine's
  ``/defend`` and never refuses one. It asked about every request, so an engine
  that trickled its answer delayed every stop by 20 s, and in enforce mode its
  block or throttle answer refused them with 403 or 429. The engine therefore
  no longer sees stops at all, including a stop that will fail authentication
  (an anonymous or forged-token request): the view still answers that one 401
  or 403, so no stop is made by it.
* ``safety.throttling``, the project's default throttles, never refuses a stop
  and never counts one. A user past the per-user rate got 429 on a pause (#310),
  and the engines' poll, which is anonymous, hit the anonymous rate at exactly
  its own polling interval.
* ``safety.service_token`` accepts the failsafe service token -- a stop client's
  credential that needs no password sign-in -- only on a request judged a stop
  here, so what the token can do is exactly the stop set.

A route is named by its URL name (``ResolverMatch.view_name``), so a format
suffix such as ``.json`` is the same route. Each stop route maps its methods to
a predicate that says whether one request is a stop.

A stop is recognised only in its canonical form, and judging it is cheap and
bounded, because it runs before authentication: a body of at most
:data:`STOP_BODY_LIMIT` bytes, JSON or a URL-encoded form, in UTF-8 or ASCII,
parsed strictly (no duplicate keys, no NaN), carrying only the fields its
predicate names plus an optional text ``note`` or ``reason``. Anything else on
a stop route is NOT a stop: it goes through the gateway and the throttles like
any other request, which bound it (the gateway by its deadline, failing open).
Every client that makes stops sends the canonical form; the test module
replays each one's exact request shape.

A predicate reads only what a request says. A field a stop route learns later
that also stops something (say ``{"halt": true}`` on the recompute) is not a
stop until a predicate here names it.

``tests/test_no_control_holds_back_a_stop.py`` walks the URLconf, the admin
site included, and fails on a route or a method that is in neither
:data:`STOP_ROUTES` nor :data:`NOT_STOPS`, so a new route or method cannot be
added without somebody deciding whether it stops something.
"""

from __future__ import annotations

import codecs
import json

from django.conf import settings
from django.http import QueryDict
from django.urls import Resolver404, resolve
from django.utils.http import parse_header_parameters

#: The largest body a stop is recognised in. Every stop body is a few hundred
#: bytes; judging runs before authentication, so it reads no more than this.
STOP_BODY_LIMIT = 64 * 1024

#: The body is not in the canonical form a stop is recognised in.
NOT_CANONICAL = object()

_CANONICAL_TYPES = frozenset({"application/json", "application/x-www-form-urlencoded"})
#: Linear codecs only. The gateway refuses punycode and idna for being slower
#: than linear (audit.middleware._SLOW_CHARSETS); here nothing but these two is
#: decoded at all.
CANONICAL_CODECS = frozenset({"utf-8", "ascii"})

#: Free text a stop body may carry beside its fields. No view reads either as
#: anything but text, and most ignore them.
_REMARKS = frozenset({"note", "reason"})

#: What the views parse as a boolean (assurance.views._parse_bool_field).
_TRUE_STRINGS = frozenset({"true", "1", "yes", "on"})
_FALSE_STRINGS = frozenset({"false", "0", "no", "off", ""})


def _as_bool(value):
    """``value`` as the views read a boolean field, or None if they refuse it."""
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        token = value.strip().lower()
        if token in _TRUE_STRINGS:
            return True
        if token in _FALSE_STRINGS:
            return False
    return None


def _fields(data, fields):
    """``data`` if it is an object carrying at least one of ``fields``, nothing
    else but a text note or reason; otherwise None."""
    if not isinstance(data, dict):
        return None
    if not any(name in data for name in fields):
        return None
    for name, value in data.items():
        if name in fields:
            continue
        if name in _REMARKS and isinstance(value, str):
            continue
        return None
    return data


def always(request, read):
    """Every request on this route and method is a stop. The body is not read."""
    return True


def _pause(request, read):
    # `paused` true pauses. False lifts a pause: that puts a deployment back to
    # work, as a resume does, so it is start-direction and not a stop. Absent is
    # a routine recompute, which keeps the paused state and is not a stop.
    data = _fields(read(), {"paused"})
    return data is not None and _as_bool(data["paused"]) is True


#: The claim moves an operator makes to take a claim down.
_TAKE_DOWN = frozenset({"revoked", "contradicted"})


def _revoke_or_contradict(request, read):
    data = _fields(read(), {"to_status"})
    return data is not None and isinstance(data.get("to_status"), str) and data["to_status"] in _TAKE_DOWN


#: The failsafe commands that stop an engine. Resume and release put one back
#: to work: drafting them is not a stop.
_STOP_ACTIONS = frozenset({"pause", "stand_down", "terminate"})


def _stop_draft(request, read):
    data = _fields(read(), {"action", "engine_id"})
    return data is not None and isinstance(data.get("action"), str) and data["action"] in _STOP_ACTIONS


def _dispatch_off(request, read):
    # The per-deployment kill switch for automated dispatch, switched OFF.
    # Switching it on, or changing what it dispatches, is not a stop.
    data = _fields(read(), {"enabled"})
    return data is not None and "enabled" in data and _as_bool(data["enabled"]) is False


def _demotion(request, read):
    """A role that takes access away or keeps it: never a promotion.

    `viewer` is the lowest role, so a move to it never grants anything. A move
    to `analyst` is a demotion from admin and a promotion from viewer, so the
    target's current role is read (one indexed row); a read that fails is a
    stop, because a failed read must never hold back a demotion. A move to
    `admin` is never a stop."""
    data = _fields(read(), {"role"})
    if data is None or not isinstance(data.get("role"), str):
        return False
    from django.contrib.auth import get_user_model

    roles = get_user_model().Roles
    if data["role"] == roles.VIEWER:
        return True
    if data["role"] != roles.ANALYST:
        return False
    pk = str(_match(request).kwargs.get("pk", ""))
    if not pk.isdigit():
        return False
    try:
        current = get_user_model().objects.filter(pk=int(pk)).values_list("role", flat=True).first()
    except Exception:  # noqa: BLE001 - a read that fails must not hold back a demotion
        return True
    return current != roles.VIEWER


#: The engagement fields a scan's authority is re-read from
#: (pentest.views.still_authorised: running, inside its window, host in scope).
_AUTHORITY_FIELDS = frozenset({"status", "scope_hosts", "testing_window_end"})


def _authority_withdrawn(request, read):
    """An edit that only withdraws a scan's authority: the status moved off
    running, the scope emptied, the window closed now or earlier. A widening,
    or any other field, is not a stop."""
    data = _fields(read(), _AUTHORITY_FIELDS)
    if data is None:
        return False
    if "status" in data:
        from pentest.models import Engagement

        choices = {value for value, _label in Engagement.STATUS_CHOICES}
        status = data["status"]
        if not isinstance(status, str) or status not in choices or status == "running":
            return False
    if "scope_hosts" in data and data["scope_hosts"] != []:
        return False
    if "testing_window_end" in data and not _closed_by(data["testing_window_end"]):
        return False
    return True


def _closed_by(value):
    """Whether ``value``, as the serializer reads a testing window's end, is
    now or earlier (or none, which closes the window too)."""
    if value is None:
        return True
    if not isinstance(value, str):
        return False
    from django.utils import timezone
    from rest_framework import serializers

    try:
        end = serializers.DateTimeField().to_internal_value(value)
    except Exception:  # noqa: BLE001 - a value the serializer refuses is not a stop; the view answers 400
        return False
    return end <= timezone.now()


def _engine_poll(request, read):
    # Only a poll that carries the poll token is how a command reaches an engine.
    # One that does not is answered 401, and stays throttled so the token cannot
    # be guessed at speed. The view asks the same function.
    from failsafe.views import poll_token_ok

    return poll_token_ok(request)


def _valid_refresh(request, read):
    # A refresh token that verifies: signature, expiry and type, and that it is
    # not on the blacklist -- one indexed read of its unique jti, because a
    # refresh spends the token it was given. An invalid, expired or spent one
    # is not exempt: it stays under the gateway and the anonymous throttle like
    # any other guess, and so does one whose blacklist cannot be read.
    data = read()
    if not isinstance(data, dict) or set(data) != {"refresh"} or not isinstance(data["refresh"], str):
        return False
    from rest_framework_simplejwt.tokens import RefreshToken

    try:
        RefreshToken(data["refresh"])
    except Exception:  # noqa: BLE001 - a token that does not verify, for any reason, is not exempt
        return False
    return True


#: URL name -> {method: predicate}. A method not listed is not a stop.
STOP_ROUTES = {
    # Pause (`paused` true) of a deployment. A lift is not a stop.
    "deployment-recompute": {"POST": _pause},
    # Revoke or contradict a claim.
    "claim-transition": {"POST": _revoke_or_contradict},
    # The failsafe control plane. A pause, stand-down or terminate is drafted,
    # found and read for its signing bytes, signed and cancelled here. The three
    # reads are the stop lane: failsafe:state is where the dashboard's second
    # operator finds the command awaiting their signature, the list is where a
    # client finds it by engine and status, and the detail carries the bytes to
    # sign. Each is bounded and changes no running work (failsafe.views).
    "failsafe:state": {"GET": always},
    "failsafe:commands": {"GET": always, "POST": _stop_draft},
    "failsafe:command-detail": {"GET": always},
    "failsafe:submit-signature": {"POST": always},
    "failsafe:cancel-command": {"POST": always},
    # The engine's poll: the only way a signed command reaches an engine.
    "failsafe:pending": {"GET": _engine_poll},
    # The automated-dispatch kill switch of one deployment, switched off.
    "deployment-dispatch-policy": {"PUT": _dispatch_off},
    # A scan's authority withdrawn: paused, cancelled or completed, its scope
    # emptied, its window closed, or the engagement deleted.
    "pentest:engagement_detail": {"PATCH": _authority_withdrawn, "DELETE": always},
    # An operator's access taken away: demoted, or removed.
    "accounts:user-set-role": {"PATCH": _demotion},
    "accounts:user-detail": {"DELETE": always},
}

#: Not stops, but what an operator needs in order to make one, exempt the same
#: way. An access token lives an hour; the refresh is how an operator signed in
#: to this project's own frontend keeps the session they press stop from. A
#: refresh token is spent by its refresh (the token blacklist, with rotation),
#: so a used one no longer verifies and is not exempt. A stop client that signs
#: in with a password -- the dashboard's server -- needs neither: it presents
#: the failsafe service token on the stop itself (safety.service_token).
STOP_ACCESS_ROUTES = {
    "token_refresh": {"POST": _valid_refresh},
}

_READ = "a read: it returns data and changes no running work and no authority"
_CONFIG = "configures a deployment's settings: it starts and stops nothing"
_EVIDENCE = "records evidence or a derived state: it starts and stops nothing"
_REFRESH = "re-derives state from what is stored: a refresh that starts and stops nothing"


def _get(reason=_READ):
    return {"GET": reason}


#: URL name -> {method: why it is not a stop}. Every method a route serves is
#: here or in STOP_ROUTES (a route can be in both, with different methods).
#: "ANY" is a plain Django view, which serves every method.
NOT_STOPS = {
    "health": {"GET": "the liveness probe: it answers at once and is already unthrottled"},
    "token_obtain_pair": {
        "POST": (
            "signs in with a password: it issues a token and stops nothing; no stop needs it "
            "(the failsafe service token is presented on the stop itself), and failed attempts "
            "are limited per address and username and per address (safety.sign_in)"
        )
    },
    "api-root": _get(),
    "accounts:api-root": _get(),
    "accounts:user-list": {
        "GET": _READ,
        "POST": "creates an operator account: it grants access and withdraws none",
    },
    "accounts:user-me": _get(),
    "accounts:user-detail": {
        "GET": _READ,
        "PUT": "edits an account, but every field of its serializer is read-only, so it changes nothing",
        "PATCH": "edits an account, but every field of its serializer is read-only, so it changes nothing",
    },
    "audit_log_list": _get(),
    "export_pdf": _get("renders the audit log as a PDF: a read that changes nothing"),
    "asset-detail": _get(),
    "asset-list": _get(),
    "claim-list": _get(),
    "claim-detail": _get(),
    "claim-events": _get(),
    "claim-declare-latent-condition": {
        "POST": (
            "declares a watch that may mark the claim stale later; it adds a check "
            "and stops nothing now"
        )
    },
    "claim-withdraw-latent-condition": {
        "POST": "withdraws a watch, which can only relax the decision: the opposite of a stop"
    },
    "deployment-list": _get(),
    "deployment-detail": _get(),
    "deployment-check": {"POST": "returns every assurance stream in one consistent read; it writes nothing"},
    "deployment-latency": _get(),
    "deployment-receipt": _get(),
    "deployment-assurance-receipt": _get(),
    "deployment-signed-assurance-receipt": _get(),
    "deployment-vendor-packet-candidates": _get(),
    "deployment-chain-birth": {"GET": _READ, "POST": _EVIDENCE},
    "deployment-connectors": _get(),
    "deployment-connector-push": {
        "POST": "pushes findings to a ticket system by hand: outbound work, which a stop would stop"
    },
    "deployment-connector-config": {
        "GET": _READ,
        "PUT": (
            "configures a ticket connector's credentials; switching automated dispatch off "
            "is the dispatch policy, which is a stop"
        ),
        "DELETE": (
            "removes a ticket connector's credentials; switching automated dispatch off "
            "is the dispatch policy, which is a stop"
        ),
    },
    "deployment-posture-config": {"GET": _READ, "PUT": _CONFIG, "DELETE": _CONFIG},
    "deployment-dispatch-attempts": _get(),
    "deployment-dispatch-policy": {"GET": _READ},
    "deployment-data-boundary": {"GET": _READ, "PUT": _CONFIG, "PATCH": _CONFIG},
    "deployment-capabilities": _get(),
    "deployment-route-map": _get(),
    "deployment-effective-access": _get(),
    "deployment-ripple-effect": _get(),
    "deployment-personal-context": _get(),
    "deployment-data-lifecycle": _get(),
    "deployment-training-reuse": _get(),
    "deployment-metadata-logging": _get(),
    "deployment-posture": _get(),
    "deployment-cloud-posture": _get(),
    "deployment-secrets-posture": _get(),
    "deployment-repo-posture": _get(),
    "deployment-approved-workflows": {"GET": _READ, "PUT": _CONFIG},
    "deployment-chain-outcomes": {"GET": _READ, "POST": _EVIDENCE},
    "deployment-observed-chain-outcomes": {"POST": _EVIDENCE},
    "deployment-ai-bom": _get(),
    "deployment-declared-architecture": {"GET": _READ, "PUT": _CONFIG},
    "deployment-bom-drift": _get(),
    "deployment-record-bom-drift": {"POST": _EVIDENCE},
    "deployment-compliance": _get(),
    "deployment-business-impact": _get(),
    "deployment-vendor-assurance": _get(),
    "deployment-executive-summary": _get(),
    "deployment-operational-assurance": _get(),
    "deployment-operational-risk": _get(),
    "deployment-assurance-packs": _get(),
    "deployment-assurance-pack": _get(),
    "deployment-assurance-claims": _get(),
    "deployment-recompute-claims": {"POST": _REFRESH},
    "deployment-retest-requirements": _get(),
    "deployment-decision-support": _get(),
    "deployment-coverage-manifest-view": _get(),
    "deployment-revalidation-plan": _get(),
    "deployment-check-invalidations": {
        "POST": (
            "re-runs the invalidation engine: a refresh; the operator's own take-down "
            "of a claim is the claim transition"
        )
    },
    "deployment-latent-conditions": _get(),
    "retest-requirement-list": _get(),
    "retest-requirement-detail": _get(),
    "finding-list": _get(),
    "finding-detail": {
        "GET": _READ,
        "PUT": "edits a finding's tracked fields: tracking work, not stopping it",
        "PATCH": "edits a finding's tracked fields: tracking work, not stopping it",
    },
    "finding-remediation": _get(),
    "finding-incident-pack": _get(),
    "finding-vendor-packet": _get(),
    "finding-remediation-transition": {
        "POST": "moves a finding's remediation state: tracking work, not stopping it"
    },
    "finding-remediation-assign": {"POST": "assigns a finding's owner: tracking work, not a stop"},
    "finding-assignable": _get(),
    "provider-list": {"GET": _READ, "POST": "creates a provider record: configuration that starts and stops nothing"},
    "provider-detail": {
        "GET": _READ,
        "PUT": "edits a provider record: configuration that starts and stops nothing",
        "PATCH": "edits a provider record: configuration that starts and stops nothing",
    },
    "provider-assertion-list": {"GET": _READ, "POST": _EVIDENCE},
    "provider-assertion-detail": {
        "GET": _READ,
        "PUT": _EVIDENCE,
        "PATCH": _EVIDENCE,
        "DELETE": "deletes a provider's assertion: evidence, which starts and stops nothing",
    },
    "unknown-list": _get(),
    "unknown-detail": {
        "GET": _READ,
        "PUT": "records how an unknown asset was resolved: evidence that stops nothing",
        "PATCH": "records how an unknown asset was resolved: evidence that stops nothing",
    },
    "detection:defender-text-scan": {"POST": "submits text an analyst wants inspected: log analysis, not a stop"},
    "detection:defender-file-scan": {"POST": "submits a file an analyst wants inspected: log analysis, not a stop"},
    "detection:defender-list": _get(),
    "detection:defender-detail": _get(),
    "detection:cve-classify": {"POST": "asks the engine to classify a CVE: analysis that stops nothing"},
    "detection:cve-list": _get(),
    "detection:cve-detail": _get(),
    "detection:cve-pdf": _get("renders a CVE report as a PDF: a read that changes nothing"),
    "detection:cve-email": {"POST": "emails a CVE report to its recipients: it stops nothing"},
    "failsafe:audit": _get(),
    "pentest:run_pentest_scan": {"POST": "launches a scan: the work a stop would stop"},
    "pentest:run_llm_pentest_scan": {"POST": "launches a scan: the work a stop would stop"},
    "pentest:list_pentest_scans": _get(),
    "pentest:detail_pentest_scan": _get(),
    "pentest:download_scan_pdf": _get("renders a scan report as a PDF: a read that changes nothing"),
    "pentest:resend_scan_email": {"POST": "sends a scan report again by email: it stops nothing"},
    "pentest:pentest_scan_status": _get(),
    "pentest:allowed_pentest_checks": _get(),
    "pentest:engagements": {
        "GET": _READ,
        "POST": "creates an engagement: it grants a scan's authority and withdraws none",
    },
    "pentest:engagement_detail": {"GET": _READ},
    "pentest:engagement_plan": {"POST": "returns a suggested plan for an engagement; it writes nothing"},
}

#: The admin site's own routes: every one serves any method.
_ADMIN_SITE = {
    "index": "shows the admin's home page: a read",
    "app_list": "lists one app's models in the admin: a read",
    "login": "signs a staff member in to the admin: it issues a session and stops nothing",
    "logout": "signs a staff member out of the admin: it ends a session and stops nothing",
    "password_change": "changes the signed-in staff member's own password: it stops nothing",
    "password_change_done": "shows that a password was changed: a read",
    "jsi18n": "returns the admin's translated JavaScript strings: a read",
    "autocomplete": "returns autocomplete choices for an admin form: a read",
    "view_on_site": "redirects to an object's public page: a read",
    "<catch-all>": "redirects a URL missing its slash, or answers 404: it changes nothing",
    "<redirect>": "redirects an old admin object URL to the object's edit form: it changes nothing",
}

#: Every model registered in the admin, and what its forms change. Each gets
#: the admin's five routes. A stop made here would go through the gateway: the
#: admin is not where stops are made, and the reason names the route that is.
_ADMIN_MODELS = {
    "accounts.customuser": (
        "operator accounts; demoting or removing one is accounts:user-set-role or "
        "accounts:user-detail DELETE, which are stops"
    ),
    "assurance.asset": "a deployment's inventoried assets: records that start and stop nothing",
    "assurance.connectorbinding": "ticket connector credentials: configuration that starts and stops nothing",
    "assurance.databoundary": "a deployment's data boundary: configuration that starts and stops nothing",
    "assurance.decisiondispatchdue": "the owed dispatch record: bookkeeping that starts and stops nothing",
    "assurance.deployment": (
        "deployments; pausing one is deployment-recompute with paused true, which is a stop"
    ),
    "assurance.dispatchattempt": "the dispatch attempt log: records that start and stop nothing",
    "assurance.dispatchpolicy": (
        "dispatch policies; switching automated dispatch off is deployment-dispatch-policy "
        "PUT, which is a stop"
    ),
    "assurance.finding": "findings: tracking records that start and stop nothing",
    "assurance.posturebinding": "posture connector credentials: configuration that starts and stops nothing",
    "assurance.provider": "providers: configuration that starts and stops nothing",
    "assurance.providerassertion": "provider assertions: evidence that starts and stops nothing",
    "assurance.remediationevent": "remediation history: records that start and stop nothing",
    "assurance.unknown": "unknown assets: records that start and stop nothing",
    "audit.auditlog": "the audit log: records that start and stop nothing",
    "auth.group": "permission groups: configuration that starts and stops nothing",
    "pentest.engagement": (
        "engagements; withdrawing a scan's authority is pentest:engagement_detail, which is a stop"
    ),
    "pentest.pentestscan": "scan records: results that start and stop nothing",
    "token_blacklist.blacklistedtoken": (
        "spent or revoked refresh tokens, which the refresh writes itself; taking an operator's "
        "access away is accounts:user-set-role or accounts:user-detail DELETE, which are stops"
    ),
    "token_blacklist.outstandingtoken": "issued refresh tokens: records that start and stop nothing",
}

#: A model admin's routes, and what each does.
_ADMIN_MODEL_ROUTES = {
    "changelist": "lists, filters or bulk-edits the admin's",
    "add": "creates one of the admin's",
    "change": "edits one of the admin's",
    "delete": "deletes one of the admin's",
    "history": "shows the change history of one of the admin's",
}


def _admin_routes():
    routes = {f"admin:{name}": {"ANY": reason} for name, reason in _ADMIN_SITE.items()}
    for label, what in _ADMIN_MODELS.items():
        app, model = label.split(".")
        for route, effect in _ADMIN_MODEL_ROUTES.items():
            routes[f"admin:{app}_{model}_{route}"] = {"ANY": f"{effect} {what}"}
    # The custom user admin's password form for another account.
    routes["admin:auth_user_password_change"] = {
        "ANY": "changes another account's password from the admin: it stops nothing",
    }
    return routes


NOT_STOPS.update(_admin_routes())


def _match(request):
    """The route the handler will send ``request`` to, or None for no route."""
    match = getattr(request, "resolver_match", None)
    if match is None:
        try:
            match = resolve(request.path_info, getattr(request, "urlconf", None))
        except Resolver404:
            return None
    return match


def view_name(request):
    """The URL name the handler will route ``request`` to, or None for no route."""
    match = _match(request)
    return None if match is None else match.view_name


def _codec(name):
    try:
        return codecs.lookup(name).name
    except LookupError:
        return None


def _no_duplicates(pairs):
    body = {}
    for key, value in pairs:
        if key in body:
            raise ValueError(f"duplicate key {key!r}")
        body[key] = value
    return body


def _no_constants(name):
    raise ValueError(f"{name} is not JSON")


def _body(request):
    """The body in canonical form, or NOT_CANONICAL.

    It reads the raw body, never ``request.data`` (a parse failure there empties
    DRF's data for the view), and at most STOP_BODY_LIMIT bytes of it. A body
    declared longer is not read at all."""
    try:
        length = int(request.META.get("CONTENT_LENGTH") or 0)
    except ValueError:
        # Django reads no body for a length it cannot parse, so the view gets none.
        length = 0
    if length <= 0:
        return {}
    if length > STOP_BODY_LIMIT:
        return NOT_CANONICAL
    content_type, params = parse_header_parameters(request.META.get("CONTENT_TYPE") or "")
    if content_type.lower() not in _CANONICAL_TYPES:
        return NOT_CANONICAL
    codec = _codec(params.get("charset") or settings.DEFAULT_CHARSET)
    if codec not in CANONICAL_CODECS:
        return NOT_CANONICAL
    try:
        raw = request.body
    except Exception:  # noqa: BLE001 - a body that cannot be read is not canonical, so not a stop
        return NOT_CANONICAL
    if len(raw) > STOP_BODY_LIMIT:
        return NOT_CANONICAL
    try:
        text = raw.decode(codec)
    except UnicodeError:
        return NOT_CANONICAL
    if content_type.lower() == "application/json":
        try:
            data = json.loads(text, object_pairs_hook=_no_duplicates, parse_constant=_no_constants)
        except (ValueError, RecursionError):
            return NOT_CANONICAL
        return data if isinstance(data, dict) else NOT_CANONICAL
    try:
        form = QueryDict(text, encoding=codec)
    except Exception:  # noqa: BLE001 - TooManyFieldsSent and the like: not canonical, so not a stop
        return NOT_CANONICAL
    fields = dict(form.lists())
    if any(len(values) != 1 for values in fields.values()):
        return NOT_CANONICAL
    return {key: values[0] for key, values in fields.items()}


#: Every exempt route: the stops and what keeps an operator able to make one.
EXEMPT_ROUTES = {**STOP_ROUTES, **STOP_ACCESS_ROUTES}

_JUDGED = "_safety_is_stop"


def is_stop(request):
    """Whether ``request`` (a Django ``HttpRequest``) is a stop, or the refresh
    an operator needs to make one; either way exempt from the gateway and the
    throttles.

    A request on no exempt route is not one. The answer is kept on the request,
    so the gateway and the throttles judge it once. A predicate that raises
    makes the request a stop: the predicates never raise on any body (the tests
    feed them every JSON type), so only a defect here can, and a defect here
    must not be what holds a stop back."""
    judged = getattr(request, _JUDGED, None)
    if judged is not None:
        return judged
    verdict = _judge(request)
    try:
        setattr(request, _JUDGED, verdict)
    except AttributeError:
        pass
    return verdict


def _judge(request):
    methods = EXEMPT_ROUTES.get(view_name(request))
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
    except Exception:  # noqa: BLE001 - a defect in judging must not hold back a stop
        return True

