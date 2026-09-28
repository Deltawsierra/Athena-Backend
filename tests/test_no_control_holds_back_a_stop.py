"""No control in front of a view may refuse or delay a stop (#321).

The rule is absolute: no control, read failure, stale read, failed write, flood
or kill switch may ever block or delay a stop, pause, stand-down, terminate,
revoke, or a scan's Stop. And the exemption is exactly the stop set: nothing
that is not stop-direction may ride it. On 7985460 three request-path controls
broke the first half:

* The gateway (``audit.middleware.DefenderMiddleware``) put an engine round trip
  in front of every request, stops included. ``requests``' timeout bounds each
  socket operation, not the call, so an engine that sent a byte every 0.3 s
  held every stop and the engines' own command poll for 20.5 s (30 s when it
  dripped its headers). In enforce mode its block or throttle answer refused
  pause, lift, revoke, contradict, the failsafe draft, sign and cancel, and the
  poll, with 403 or 429.
* ``/api/failsafe/pending/`` is anonymous, so the default anonymous throttle
  (30/min per address) applied to it. The engines poll every 2 s -- exactly
  30/min -- so one extra poll, or a second engine behind the same address, got
  429 with Retry-After 60 and every command waited.
* The per-user throttle answered a flooded operator's stops with 429 (#310).
  And the same anonymous bucket covered sign-in and the token refresh, so a
  flood from the operator's address locked them out of the session they press
  stop from.

``safety.stops`` is now the one place a request is judged a stop, and the
gateway and the default throttles both read it. The first section is the
tripwire: it walks the URLconf, the admin site included, and fails on any route
or method nobody has classified. The judging section pins the canonical form a
stop is recognised in, each predicate's direction, and that judging is cheap
enough to run before authentication. The gateway tests run a real misbehaving
engine on 127.0.0.1. The throttle tests drive the real views through the whole
middleware stack.

Round 3 (the adversary's round-2 findings): the dashboard's stops depended on a
password sign-in that the gateway judged and ten guesses locked (H1), so a stop
client now presents the failsafe service token on the stop itself; sign-in
failures are counted per username as authentication reads it and per address
(H2, M4); the state read the dashboard's co-signer uses is in the stop lane
(M1); a lift is start-direction (M3); a spent refresh token no longer verifies
(L2); a flood of drafts cannot hide a command awaiting a signature (L1); and
every limit saturated at once, the request path pinned, and initial() and the
other request hooks checked, catch a limit added any way (M2).

Round 4 (the adversary's round-3 findings): a stop draft is never refused --
the per-account cap refused a fleet pause past 20 and let 20 junk drafts through
the service token refuse the dashboard's stand-down -- and is idempotent
instead (H1); cancelling a pause, stand-down or terminate withdraws a stop, so
it is not one, and neither is a signature on a resume or release (H2); a refresh
token is spent exactly once however many refreshes race (M1); the state read's
work is bounded by its row limits, not by the number of commands (M2); every
limit is saturated however it is built -- any throttle class, any cache count,
the WSGI entry point -- and round 3's T2 mutant is caught (M3); sign-in attempts
are counted atomically in the database before the hash (M4); a service account
that cannot be read is a 503, not a 401 (L1); deleting an engagement is not a
stop (L2); a removed or deactivated operator's refresh is not exempt (L3); and
the service token reads only the stop commands in flight (L4).

Round 5 (the adversary's round-4 findings): what stop drafts cost is bounded
without refusing one -- a stop is never refused for its reason length (the bound
matches the dashboard's 2,000, and a longer stop reason is truncated, not 400'd,
while a non-stop past it is input validation), an account's unsigned stop drafts
past its limit supersede its oldest and never another account's, and each
stop-lane read is bounded in bytes and says what it left out (H1); reads that
differ only in what the view ignores share one computation (H2); a draft is
reused only for an identical reason (M1); two signatures at once both count
(M3); identical drafts at once are one row (L1); every stop, with every limit
saturated, is answered within a stated bound, so a control that delays a stop
without refusing it fails (L2); and removing an operator keeps their engagements.

Round 5 (the adversary's round-5 findings): every identical stop draft answered
200 names a row that stays live, and a taken-back draft is never visible to a
list read (F1); a superseded but unsigned real stop is revived when validly
signed, so a count never makes a pending stop unsignable (F2, SAFETY); a stop
the dashboard can send is never refused for its reason length (F3); and every
account's newest unsigned stop draft is ranked, so no flood hides another
account's stand-down from any read (F5).
"""

from __future__ import annotations

import base64
import http.server
import io
import json
import re
import threading
import time
import types
import uuid
from datetime import timedelta
from unittest import mock

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.core.cache.backends.base import DEFAULT_TIMEOUT
from django.core.cache.backends.locmem import LocMemCache
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from django.urls import URLPattern, URLResolver, get_resolver
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework.throttling import BaseThrottle, SimpleRateThrottle
from rest_framework.views import APIView

from audit import middleware as gateway_module
from audit.middleware import DefenderMiddleware
from safety import stops
from safety.throttling import StopsPass

# --- The classification, declared here as well ---------------------------------

#: The stop set, stated independently of safety.stops so that a route dropped
#: from it -- or moved to NOT_STOPS with a reason -- fails here.
EXPECTED_STOPS = {
    "deployment-recompute": {"POST"},
    "failsafe:state": {"GET"},
    "claim-transition": {"POST"},
    "failsafe:commands": {"GET", "POST"},
    "failsafe:command-detail": {"GET"},
    "failsafe:submit-signature": {"POST"},
    "failsafe:cancel-command": {"POST"},
    "failsafe:pending": {"GET"},
    "deployment-dispatch-policy": {"PUT"},
    "pentest:engagement_detail": {"PATCH"},
    "accounts:user-set-role": {"PATCH"},
    "accounts:user-detail": {"DELETE"},
}

#: Not stops, exempt the same way: how an operator stays able to make one.
EXPECTED_STOP_ACCESS = {"token_refresh": {"POST"}}

#: A route whose name says "stop" in any of these words is in the stop set,
#: unless it is listed below.
STOP_WORDS = re.compile(
    r"pause|lift|stop|halt|kill|terminat|stand|revok|abort|cancel|suspend|disabl|"
    r"contradict|failsafe|withdraw|dispatch|role|engagement|transition|freeze|block|"
    r"quarantin|lock|deactivat|shut|off|emergenc|panic|rollback|expire|evict"
)
NAMED_LIKE_A_STOP_BUT_NOT = {
    "claim-withdraw-latent-condition",
    "deployment-dispatch-attempts",
    "failsafe:audit",
    "finding-remediation-transition",
    "pentest:engagement_plan",
    "pentest:engagements",
}

U = "11111111-2222-4333-8444-555555555555"
POLL_TOKEN = "test-poll-token-321"
RECOMPUTE = f"/api/assurance/deployments/{U}/recompute/"
TRANSITION = f"/api/assurance/claims/{U}/transition/"
DISPATCH = f"/api/assurance/deployments/{U}/dispatch-policy/"
ENGAGEMENT = "/api/pentest/engagements/7/"
SET_ROLE = "/api/accounts/users/7/set_role/"
PAST = "2000-01-01T00:00:00Z"
FUTURE = "2999-01-01T00:00:00Z"


def _fresh_refresh():
    """A refresh token that verifies, for an account that exists and is active."""
    from rest_framework_simplejwt.tokens import RefreshToken

    return {"refresh": str(RefreshToken.for_user(_user("viewer")))}


def _command(action, engine_id="athena-1", initiator=None, **fields):
    """A failsafe command made directly, as a draft would make it."""
    from failsafe.models import FailsafeCommand
    from failsafe.signing import make_draft, required_signatures

    draft = make_draft(action, engine_id, "", 600)
    return FailsafeCommand.objects.create(
        **draft, required_signatures=required_signatures(action), initiator=initiator, **fields
    )


def _on(action, route):
    """A path on one command of ``action``, made when the request is: the
    signature and cancel routes are judged by the command's action."""
    return lambda: f"/api/failsafe/commands/{_command(action).uuid}/{route}/"


#: One request that is a stop for every exempt (route, method): (route, method,
#: path -- or a function making one --, JSON body -- or a function making one --
#: or None, extra headers).
STOP_REQUESTS = [
    ("deployment-recompute", "POST", RECOMPUTE, {"paused": True}, {}),
    ("failsafe:state", "GET", "/api/failsafe/state/?engine_id=e", None, {}),
    ("claim-transition", "POST", TRANSITION, {"to_status": "revoked"}, {}),
    ("claim-transition", "POST", TRANSITION, {"to_status": "contradicted", "note": "n"}, {}),
    ("failsafe:commands", "GET", "/api/failsafe/commands/", None, {}),
    ("failsafe:commands", "POST", "/api/failsafe/commands/", {"action": "stand_down", "engine_id": "e"}, {}),
    ("failsafe:command-detail", "GET", f"/api/failsafe/commands/{U}/", None, {}),
    ("failsafe:submit-signature", "POST", _on("stand_down", "signatures"), {"key_id": "a", "sig": "00"}, {}),
    ("failsafe:cancel-command", "POST", _on("resume", "cancel"), {}, {}),
    ("failsafe:pending", "GET", "/api/failsafe/pending/", None, {"HTTP_X_FAILSAFE_POLL_TOKEN": POLL_TOKEN}),
    ("deployment-dispatch-policy", "PUT", DISPATCH, {"enabled": False}, {}),
    ("pentest:engagement_detail", "PATCH", ENGAGEMENT, {"status": "paused"}, {}),
    ("pentest:engagement_detail", "PATCH", ENGAGEMENT, {"testing_window_end": PAST}, {}),
    ("pentest:engagement_detail", "PATCH", ENGAGEMENT, {"scope_hosts": []}, {}),
    ("accounts:user-set-role", "PATCH", SET_ROLE, {"role": "viewer"}, {}),
    ("accounts:user-detail", "DELETE", "/api/accounts/users/7/", None, {}),
    ("token_refresh", "POST", "/api/token/refresh/", _fresh_refresh, {}),
]

MULTIPART = "multipart/form-data; boundary=zz"


def _multipart(name, value):
    return f'--zz\r\nContent-Disposition: form-data; name="{name}"\r\n\r\n{value}\r\n--zz--\r\n'.encode()


#: The same routes carrying requests that are NOT stops: the gateway still asks
#: about them and still enforces its answer, so the exemption is no wider than
#: the stop set. (label, method, path, body, content type, extra headers); a
#: body in bytes is sent as it is.
NOT_STOP_REQUESTS = [
    ("routine recompute", "POST", RECOMPUTE, {}, "application/json", {}),
    ("lift", "POST", RECOMPUTE, {"paused": False}, "application/json", {}),
    ("lift as a string, with a note", "POST", RECOMPUTE, {"paused": "false", "note": "done"}, "application/json", {}),
    ("lift as a form", "POST", RECOMPUTE, b"paused=false", "application/x-www-form-urlencoded", {}),
    ("routine recompute, multipart", "POST", RECOMPUTE, _multipart("note", "x"), MULTIPART, {}),
    ("routine recompute, */*", "POST", RECOMPUTE, b"{}", "*/*", {}),
    ("routine recompute, application/*", "POST", RECOMPUTE, b"{}", "application/*", {}),
    ("routine recompute, charset=base64", "POST", RECOMPUTE, base64.b64encode(b"{}"), "application/json; charset=base64", {}),
    ("recompute padded past 64 KiB", "POST", RECOMPUTE, {"note": "a" * 70_000}, "application/json", {}),
    ("pause with a field no predicate names", "POST", RECOMPUTE, {"paused": True, "halt": False}, "application/json", {}),
    ("claim verified", "POST", TRANSITION, {"to_status": "verified"}, "application/json", {}),
    ("claim verified, multipart", "POST", TRANSITION, _multipart("to_status", "verified"), MULTIPART, {}),
    ("poll without the token", "GET", "/api/failsafe/pending/", None, "application/json", {}),
    ("poll with a guess", "GET", "/api/failsafe/pending/", None, "application/json", {"HTTP_X_FAILSAFE_POLL_TOKEN": "a-guess"}),
    ("draft of a resume", "POST", "/api/failsafe/commands/", {"action": "resume", "engine_id": "e"}, "application/json", {}),
    ("draft of a release", "POST", "/api/failsafe/commands/", {"action": "release", "engine_id": "e"}, "application/json", {}),
    ("dispatch policy severity only", "PUT", DISPATCH, {"min_severity": "high"}, "application/json", {}),
    ("dispatch switched on", "PUT", DISPATCH, {"enabled": True, "min_severity": "info", "on_blocking_decision": True}, "application/json", {}),
    ("dispatch off with a severity change", "PUT", DISPATCH, {"enabled": False, "min_severity": "info"}, "application/json", {}),
    ("engagement renamed", "PATCH", ENGAGEMENT, {"name": "renamed"}, "application/json", {}),
    ("engagement running and widened", "PATCH", ENGAGEMENT, {"status": "running", "scope_hosts": ["a.example", "b.example"]}, "application/json", {}),
    ("engagement paused and widened", "PATCH", ENGAGEMENT, {"status": "paused", "scope_hosts": ["b.example"]}, "application/json", {}),
    ("engagement window extended", "PATCH", ENGAGEMENT, {"testing_window_end": FUTURE}, "application/json", {}),
    ("engagement read", "GET", ENGAGEMENT, None, "application/json", {}),
    ("engagement deleted", "DELETE", ENGAGEMENT, None, "application/json", {}),
    ("promotion to admin", "PATCH", SET_ROLE, {"role": "admin"}, "application/json", {}),
    ("refresh with a token that does not verify", "POST", "/api/token/refresh/", {"refresh": "x.y.z"}, "application/json", {}),
    ("audit read", "GET", "/api/failsafe/audit/", None, "application/json", {}),
    ("a scan launched", "POST", "/api/pentest/scan/", {"url": "https://x.test"}, "application/json", {}),
]


def walk(patterns=None, namespaces=(), prefix=""):
    """{view name: {"methods": set, "callbacks": list}} for every route served.

    Refuses a route it cannot name, as the engine's walker refuses a mount it
    cannot see into: an unnamed route is exactly where an unclassified stop
    would hide. The one exception is the admin site's own catch-all, which is
    unnamed in Django and is ``admin:<catch-all>`` here, and its model pages
    redirects from old object URLs, which are ``admin:<redirect>``."""
    found = {}

    def add(name, methods, callback):
        entry = found.setdefault(name, {"methods": set(), "callbacks": []})
        entry["methods"] |= methods
        if callback is not None:
            entry["callbacks"].append(callback)

    for pattern in get_resolver().url_patterns if patterns is None else patterns:
        if isinstance(pattern, URLResolver):
            inner = namespaces + ((pattern.namespace,) if pattern.namespace else ())
            for name, entry in walk(pattern.url_patterns, inner, prefix + str(pattern.pattern)).items():
                add(name, entry["methods"], None)
                found[name]["callbacks"].extend(entry["callbacks"])
        elif isinstance(pattern, URLPattern):
            name = pattern.name
            if not name and namespaces[:1] == ("admin",):
                # Django leaves two admin routes unnamed: the site's catch-all,
                # and each model's redirect from an old object URL to its form.
                from django.views.generic import RedirectView

                if getattr(pattern.callback, "__name__", "") == "catch_all_view":
                    name = "<catch-all>"
                elif getattr(pattern.callback, "view_class", None) is RedirectView:
                    name = "<redirect>"
            if not name:
                raise AssertionError(
                    f"the route {prefix}{pattern.pattern} has no name, so it cannot be classified"
                )
            callback = pattern.callback
            actions = getattr(callback, "actions", None)
            cls = getattr(callback, "cls", None)
            if actions:
                # A viewset adds "head" to its own actions the first time it
                # serves a GET; HEAD is judged as GET, and OPTIONS is never a stop.
                methods = {method.upper() for method in actions if method not in ("options", "head")}
            elif cls is not None:
                methods = {
                    method.upper()
                    for method in cls.http_method_names
                    if method not in ("options", "head") and hasattr(cls, method)
                }
            else:
                methods = {"ANY"}
            add(":".join((*namespaces, name)), methods, callback)
        else:
            raise AssertionError(f"unrecognised URLconf entry {type(pattern).__name__}")
    return found


# --- The tripwire --------------------------------------------------------------


def classification_problems(served, exempt, not_stops):
    """Every way ``served`` ({name: methods}) and the two tables disagree."""
    problems = []
    for name in sorted(set(served) | set(exempt) | set(not_stops)):
        stop_methods = set(exempt.get(name, {}))
        other_methods = set(not_stops.get(name, {}))
        both = stop_methods & other_methods
        if both:
            problems.append(f"{name}: {sorted(both)} classified both as a stop and as not one")
        if name not in served:
            problems.append(f"{name}: classified, but no such route is served")
            continue
        unclassified = served[name] - stop_methods - other_methods
        if unclassified:
            problems.append(
                f"{name}: serves {sorted(unclassified)}, which is neither a stop nor declared not one; "
                "classify it in safety/stops.py"
            )
        gone = (stop_methods | other_methods) - served[name]
        if gone:
            problems.append(f"{name}: classifies {sorted(gone)}, which it does not serve")
    return problems


def test_every_route_and_method_is_classified_as_a_stop_or_not():
    served = {name: entry["methods"] for name, entry in walk().items()}
    problems = classification_problems(served, stops.EXEMPT_ROUTES, stops.NOT_STOPS)
    assert problems == [], problems


def test_a_method_added_to_any_route_fails_the_tripwire():
    """A POST added to a read, or a DELETE added to a stop route's detail: the
    route is classified, the method is not, so the tripwire fails."""
    served = {name: set(entry["methods"]) for name, entry in walk().items()}
    for name, method in (("failsafe:state", "POST"), ("failsafe:command-detail", "DELETE"),
                         ("claim-transition", "PATCH"), ("admin:index", "POST")):
        widened = {**served, name: served[name] | {method}}
        if "ANY" in served[name]:
            widened[name] = {"ANY", "POST"}
        problems = classification_problems(widened, stops.EXEMPT_ROUTES, stops.NOT_STOPS)
        assert any(problem.startswith(f"{name}: serves") for problem in problems), (name, problems)


def test_the_stop_set_is_the_one_declared_here():
    declared = {name: set(methods) for name, methods in stops.STOP_ROUTES.items()}
    assert declared == EXPECTED_STOPS
    access = {name: set(methods) for name, methods in stops.STOP_ACCESS_ROUTES.items()}
    assert access == EXPECTED_STOP_ACCESS
    assert stops.EXEMPT_ROUTES == {**stops.STOP_ROUTES, **stops.STOP_ACCESS_ROUTES}


def test_every_stop_method_is_one_the_route_serves():
    """A stop declared on a method the route does not serve is never recognised:
    PUT where the view takes PATCH would leave every real request unexempt."""
    served = walk()
    for name, methods in stops.EXEMPT_ROUTES.items():
        missing = set(methods) - served[name]["methods"]
        assert not missing, f"{name} declares stops on {sorted(missing)}, which it does not serve"


def test_a_route_named_like_a_stop_is_one_or_is_listed_as_not():
    """The admin site's routes are classified model by model (below), each with
    the API route that is the real stop named in its reason."""
    for name in walk():
        if name.startswith("admin:"):
            continue
        if STOP_WORDS.search(name) and name not in stops.EXEMPT_ROUTES:
            assert name in NAMED_LIKE_A_STOP_BUT_NOT, (
                f"{name} is named like a stop but is not in the stop set; add it to "
                "safety.stops.STOP_ROUTES, or to NAMED_LIKE_A_STOP_BUT_NOT here"
            )
    assert NAMED_LIKE_A_STOP_BUT_NOT <= set(stops.NOT_STOPS)


def test_the_admin_site_is_classified_model_by_model():
    """Every model registered in the admin is declared, with what its forms
    change; a model registered later fails here and in the tripwire. The admin
    can switch dispatch off, move an engagement's status or remove an account,
    so each of those names the API route that is the stop."""
    registered = {f"{model._meta.app_label}.{model._meta.model_name}" for model in admin.site._registry}
    assert registered == set(stops._ADMIN_MODELS)
    for label, stop_route in (
        ("assurance.dispatchpolicy", "deployment-dispatch-policy"),
        ("pentest.engagement", "pentest:engagement_detail"),
        ("accounts.customuser", "accounts:user-set-role"),
        ("assurance.deployment", "deployment-recompute"),
    ):
        assert stop_route in stops._ADMIN_MODELS[label] and stop_route in stops.STOP_ROUTES
    assert any(name.startswith("admin:") for name in walk())


#: A reason names what the route does: one of these, as a word.
EFFECT = re.compile(
    r"\b(reads?|returns?|lists?|shows?|renders?|creates?|edits?|records?|changes?|launch(es)?|"
    r"sends?|emails?|pushes|signs?|issues|renews?|re-derives|re-runs|declares?|withdraws?|"
    r"assigns?|moves?|configures?|deletes?|removes?|submits?|asks?|grants?|answers?|"
    r"redirects?|probe)\b"
)
BOILERPLATE = re.compile(r"\b(todo|tbd|fixme|xxx|same as|see above|etc|n/a|not a stop here|irrelevant)\b", re.I)
WRITES = {"POST", "PUT", "PATCH", "DELETE"}


def reason_problem(method, reason):
    """Why ``reason`` does not justify ``method`` as not a stop, or None."""
    words = re.findall(r"[a-z0-9'-]+", reason.lower())
    if len(words) < 6:
        return "fewer than six words"
    if BOILERPLATE.search(reason):
        return "boilerplate"
    if not EFFECT.search(reason.lower()):
        return "names no effect (reads, creates, edits, launches, ...)"
    if method in WRITES and reason.lower().startswith("a read"):
        return f"calls {method} a read"
    return None


def test_every_route_that_is_not_a_stop_says_what_it_does():
    for name, methods in stops.NOT_STOPS.items():
        for method, reason in methods.items():
            problem = reason_problem(method, reason)
            assert problem is None, f"{name} {method}: {problem}: {reason!r}"


def test_the_reason_check_refuses_boilerplate():
    assert reason_problem("GET", "not a stop here") is not None
    assert reason_problem("GET", "this one is not a stop here at all") == "boilerplate"
    assert reason_problem("POST", stops._READ) == "calls POST a read"
    assert reason_problem("GET", "nothing to see on this route at all") is not None
    assert reason_problem("POST", "launches a scan: the work a stop would stop") is None


#: Where a view can refuse a request before or around its handler. Round 2
#: looked at the first two only; a limit added in ``initial()`` throttled every
#: pause after the second in a minute and passed all 250 cases (M2).
_REQUEST_HOOKS = (
    "initial", "check_throttles", "get_throttles", "throttled", "dispatch",
    "get_permissions", "check_permissions", "permission_denied", "perform_authentication", "get_authenticators",
)


def _view_throttles(callback):
    """The throttle classes a served view applies: its throttle_classes, and
    the class of each throttle its get_throttles() builds."""
    cls = callback.cls
    classes = list(callback.initkwargs.get("throttle_classes", cls.throttle_classes))
    try:
        built = cls(**callback.initkwargs).get_throttles()
    except Exception:  # noqa: BLE001 - one that cannot be built here is judged by its classes
        built = []
    return classes + [type(throttle) for throttle in built]


def _unwrapped(function):
    """The code objects along ``function``'s ``__wrapped__`` chain."""
    chain = []
    while function is not None and len(chain) < 50:
        chain.append(getattr(function, "__code__", None))
        function = getattr(function, "__wrapped__", None)
    return chain


def _throttle_problems(callback):
    cls = callback.cls
    problems = []
    for method in _REQUEST_HOOKS:
        if getattr(cls, method) is not getattr(APIView, method):
            problems.append(f"overrides {method}()")
    scope = callback.initkwargs.get("throttle_scope", getattr(cls, "throttle_scope", None))
    if scope is not None:
        problems.append(f"sets throttle_scope {scope!r}")
    # A stop is let through only where StopsPass's allow_request is the one
    # called: a class that subclasses StopsPass but overrides allow_request
    # before it (round 3's T2) never asks whether the request is a stop.
    problems += [
        f"throttles with {t.__name__}, whose allow_request is not StopsPass's"
        for t in dict.fromkeys(_view_throttles(callback))
        if getattr(t, "allow_request", None) is not StopsPass.allow_request
    ]
    # A decorator wrapped round the view where it is routed keeps .cls (by
    # functools.wraps), so it hides from everything above: the routed
    # callback must be exactly what the view class builds.
    actions = getattr(callback, "actions", None)
    built = cls.as_view(actions, **callback.initkwargs) if actions else cls.as_view(**callback.initkwargs)
    if _unwrapped(callback) != _unwrapped(built):
        problems.append("is routed through a wrapper the view class does not build")
    return problems


def test_no_exempt_view_opts_out_of_the_stop_exemption():
    """A stop view's own throttle_classes, throttle_scope, or its own
    initial(), dispatch(), throttled(), check_throttles() or get_throttles(),
    or a wrapper where it is routed, would replace or bypass the defaults;
    every one must still let a stop through. This is the static half: the
    saturation below drives every stop through the whole stack with every
    limit it can reach refusing."""
    served = walk()
    for name in stops.EXEMPT_ROUTES:
        for callback in served[name]["callbacks"]:
            assert _throttle_problems(callback) == [], name


def test_the_opt_out_check_sees_an_overridden_get_throttles():
    from rest_framework.throttling import AnonRateThrottle

    class Sneaky(APIView):
        def get_throttles(self):
            return [AnonRateThrottle()]

    class Plain(APIView):
        throttle_classes = (AnonRateThrottle,)

    class Initial(APIView):
        def initial(self, request, *args, **kwargs):
            super().initial(request, *args, **kwargs)

    class Scoped(APIView):
        throttle_scope = "recompute"

    assert _throttle_problems(Sneaky.as_view()) == [
        "overrides get_throttles()", "throttles with AnonRateThrottle, whose allow_request is not StopsPass's"
    ]
    assert _throttle_problems(Plain.as_view()) == [
        "throttles with AnonRateThrottle, whose allow_request is not StopsPass's"
    ]
    assert _throttle_problems(Initial.as_view()) == ["overrides initial()"]
    assert _throttle_problems(Scoped.as_view()) == ["sets throttle_scope 'recompute'"]


#: The request path in front of every view, as reviewed for #321. A middleware
#: added after the gateway, or a throttle or authentication class added to the
#: defaults, could hold back a stop that nothing here judged: it fails here
#: until somebody reviews it against the stop set.
EXPECTED_MIDDLEWARE = [
    "corsheaders.middleware.CorsMiddleware",
    "django.middleware.security.SecurityMiddleware",
    "audit.middleware.RequestMetadataMiddleware",
    "audit.middleware.DefenderMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]
EXPECTED_THROTTLE_CLASSES = (
    "safety.throttling.StopExemptAnonRateThrottle",
    "safety.throttling.StopExemptUserRateThrottle",
)
EXPECTED_AUTHENTICATION_CLASSES = (
    "safety.service_token.FailsafeServiceTokenAuthentication",
    "rest_framework_simplejwt.authentication.JWTAuthentication",
)


EXPECTED_PERMISSION_CLASSES = ("rest_framework.permissions.IsAuthenticated",)
#: Each exempt route's permission classes, as reviewed. A permission can refuse
#: a request as surely as a throttle can: one added here fails until reviewed.
EXPECTED_STOP_PERMISSIONS = {
    "accounts:user-detail": {"accounts.permissions.IsAdmin", "rest_framework.permissions.IsAuthenticated"},
    "accounts:user-set-role": {"accounts.permissions.IsAdmin", "rest_framework.permissions.IsAuthenticated"},
    "claim-transition": {"rest_framework.permissions.IsAuthenticated"},
    "deployment-dispatch-policy": {"rest_framework.permissions.IsAuthenticated"},
    "deployment-recompute": {"rest_framework.permissions.IsAuthenticated"},
    "failsafe:cancel-command": {"accounts.permissions.IsAdminOrAnalyst"},
    "failsafe:command-detail": {"accounts.permissions.IsAdminOrAnalyst"},
    "failsafe:commands": {"accounts.permissions.IsAdminOrAnalyst"},
    "failsafe:pending": {"rest_framework.permissions.AllowAny"},
    "failsafe:state": {"accounts.permissions.IsAdminOrAnalyst"},
    "failsafe:submit-signature": {"accounts.permissions.IsAdminOrAnalyst"},
    "pentest:engagement_detail": {"accounts.permissions.IsAdminOrAnalyst"},
    "token_refresh": set(),
}
#: SHA-256 of the WSGI and ASGI entry points, as reviewed: each wraps Django's
#: handler to start the owed-dispatch sweeper (#303), and a limit added in
#: either would be in front of every stop. Change one, review it against the
#: stop set, and put its new digest here.
REVIEWED_ENTRY_POINTS = {
    "config/wsgi.py": "1baddd7cfccd4ad81f808351bab9d44d35d300dd1ea40de2d3db3138991002cb",
    "config/asgi.py": "e1ed66dc5a469fd49e73b5fa94fdbe732fe71ff3dc8412ce417a725a013e7625",
}


def test_the_request_path_in_front_of_every_view_is_the_one_reviewed():
    import hashlib
    import pathlib

    from django.conf import settings
    from rest_framework.settings import api_settings

    root = pathlib.Path(settings.BASE_DIR)
    assert {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest() for name in REVIEWED_ENTRY_POINTS
    } == REVIEWED_ENTRY_POINTS
    assert tuple(settings.REST_FRAMEWORK["DEFAULT_PERMISSION_CLASSES"]) == EXPECTED_PERMISSION_CLASSES
    served = walk()
    permissions = {
        name: {
            f"{c.__module__}.{c.__name__}"
            for callback in served[name]["callbacks"]
            for c in callback.initkwargs.get("permission_classes", callback.cls.permission_classes)
        }
        for name in stops.EXEMPT_ROUTES
    }
    assert permissions == EXPECTED_STOP_PERMISSIONS

    assert list(settings.MIDDLEWARE) == EXPECTED_MIDDLEWARE
    assert tuple(settings.REST_FRAMEWORK["DEFAULT_THROTTLE_CLASSES"]) == EXPECTED_THROTTLE_CLASSES
    assert tuple(settings.REST_FRAMEWORK["DEFAULT_AUTHENTICATION_CLASSES"]) == EXPECTED_AUTHENTICATION_CLASSES
    assert [f"{c.__module__}.{c.__name__}" for c in api_settings.DEFAULT_THROTTLE_CLASSES] == list(
        EXPECTED_THROTTLE_CLASSES
    )
    assert [f"{c.__module__}.{c.__name__}" for c in api_settings.DEFAULT_AUTHENTICATION_CLASSES] == list(
        EXPECTED_AUTHENTICATION_CLASSES
    )


def test_the_walker_refuses_what_it_cannot_name_and_sees_into_includes():
    from django.urls import include, path

    def view(request):  # pragma: no cover - never called
        return HttpResponse()

    inner = ([path("x/", view, name="inner")], "space")
    found = walk([path("a/", include(inner)), path("b/", view, name="outer")])
    assert set(found) == {"space:inner", "outer"}
    assert found["outer"]["methods"] == {"ANY"}
    with pytest.raises(AssertionError, match="has no name"):
        walk([path("c/", view)])


def test_every_exempt_route_and_method_has_a_sample_request_below():
    sampled = {(name, method) for name, method, *_ in STOP_REQUESTS}
    declared = {(name, method) for name, methods in stops.EXEMPT_ROUTES.items() for method in methods}
    assert sampled == declared


# --- Judging a request: the canonical form and each predicate's direction --------


def _raw(method, path, data=b"", content_type="application/json", **extra):
    return RequestFactory().generic(method, path, data=data, content_type=content_type, **extra)


def _json(method, path, body, **extra):
    return _raw(method, path, json.dumps(body).encode(), **extra)


@pytest.mark.parametrize(
    ("content_type", "data"),
    [
        ("application/json", b'{"paused": true}'),
        ("application/json", b'{"paused":true}'),
        ("application/json", b'{"\\u0070aused": true}'),
        ("application/json; charset=utf-8", b'{"paused": true}'),
        ("application/json; charset=UTF-8", b'{"paused": true}'),
        ("application/json; charset=us-ascii", b'{"paused": true}'),
        ("Application/JSON", b'{"paused": true}'),
        ("application/json", b'{"paused": "true", "note": "maintenance"}'),
        ("application/x-www-form-urlencoded", b"paused=true"),
        ("application/x-www-form-urlencoded; charset=utf-8", b"paused=on&reason=incident"),
    ],
    ids=["json", "json-compact", "escaped-key", "utf-8", "UTF-8", "us-ascii", "type-case",
         "string-with-note", "form", "form-on-with-reason"],
)
def test_a_pause_in_canonical_form_is_a_stop(content_type, data):
    assert stops.is_stop(_raw("POST", RECOMPUTE, data, content_type))


@pytest.mark.parametrize(
    ("content_type", "data"),
    [
        ("application/json", b'{"paused": false}'),
        ("application/json", b'{"paused":false}'),
        ("application/json", b'{"paused": "false", "note": "maintenance over"}'),
        ("application/json", b'{"paused": "0"}'),
        ("application/json", b'{"paused": "off"}'),
        ("application/json", b'{"paused": ""}'),
        ("application/x-www-form-urlencoded", b"paused=false"),
        ("application/x-www-form-urlencoded", b"paused=no&reason=done"),
    ],
)
def test_a_lift_is_not_a_stop(content_type, data):
    """Round 2 exempted the lift with the pause. A lift puts a paused deployment
    back to work, as a resume does: start-direction, so it goes through the
    gateway (bounded by its deadline) and the throttles like any other request."""
    assert not stops.is_stop(_raw("POST", RECOMPUTE, data, content_type))


@pytest.mark.parametrize(
    ("content_type", "data"),
    [
        (MULTIPART, _multipart("paused", "true")),
        ("application/json", b'{"paused": tru'),
        ("application/json; charset=utf-16", json.dumps({"paused": True}).encode("utf-16")),
        ("application/json; charset=utf-8-sig", b'\xef\xbb\xbf{"paused": true}'),
        ("application/json; charset=punycode", b'{"paused": true}'),
        ("application/json; charset=idna", b'{"paused": true}'),
        ("application/json; charset=base64", base64.b64encode(b'{"paused": true}')),
        ("application/json; charset=no-such-codec", b'{"paused": true}'),
        ("application/json; charset=us-ascii", '{"paused": true, "note": "é"}'.encode()),
        ("*/*", b'{"paused": true}'),
        ("application/*", b'{"paused": true}'),
        ("application/vnd.example+json", b'{"paused": true}'),
        ("text/plain", b'{"paused": true}'),
        ("application/json", b'{"paused": true, "paused": true}'),
        ("application/json", b'{"paused": true, "note": NaN}'),
        ("application/json", b'[{"paused": true}]'),
        ("application/json", b"[" * 40_000),
        ("application/json", b'{"paused": true, "note": "' + b"a" * 70_000 + b'"}'),
        ("application/x-www-form-urlencoded", b"paused=true&paused=true"),
        ("application/x-www-form-urlencoded", b"paused=true&halt=1"),
    ],
    ids=["multipart", "broken-json", "utf-16", "utf-8-sig", "punycode", "idna", "base64",
         "unknown-codec", "ascii-with-non-ascii", "star-star", "application-star", "vnd-json",
         "text-plain", "duplicate-key", "nan", "top-level-array", "deep-nesting", "over-64-KiB",
         "form-duplicate", "form-extra-field"],
)
def test_a_body_not_in_canonical_form_is_not_a_stop(content_type, data):
    """Round 1 read these as UNREAD and so as stops: any non-stop could dress
    as one by switching its content type (multipart, ``*/*``, base64, padding
    past 10 MB), and judging a punycode body cost minutes of CPU before
    authentication. Every client sends the canonical form; anything else goes
    through the gateway and the throttles, which bound it."""
    assert not stops.is_stop(_raw("POST", RECOMPUTE, data, content_type))


def test_a_routine_recompute_is_not_a_stop():
    for data in (b"", b"{}", b'{"paused": null}', b'{"paused": 1}', b'{"paused": "maybe"}', b'{"note": "x"}'):
        assert not stops.is_stop(_raw("POST", RECOMPUTE, data)), data


#: (method, path, body, is it a stop). Each predicate, both directions.
DIRECTION = [
    ("POST", RECOMPUTE, {"paused": True}, True),
    ("POST", RECOMPUTE, {"paused": False}, False),
    ("POST", RECOMPUTE, {"paused": "false"}, False),
    ("POST", TRANSITION, {"to_status": "revoked", "note": "compromised"}, True),
    ("POST", TRANSITION, {"to_status": "contradicted"}, True),
    ("POST", TRANSITION, {"to_status": "verified"}, False),
    ("POST", TRANSITION, {"to_status": "supported"}, False),
    ("POST", TRANSITION, {"to_status": "revoked", "valid_to": None}, False),
    ("POST", TRANSITION, {"to_status": ["revoked"]}, False),
    ("POST", "/api/failsafe/commands/", {"action": "pause", "engine_id": "e", "reason": "r"}, True),
    ("POST", "/api/failsafe/commands/", {"action": "stand_down", "engine_id": "e"}, True),
    ("POST", "/api/failsafe/commands/", {"action": "terminate", "engine_id": "e", "reason": ""}, True),
    ("POST", "/api/failsafe/commands/", {"action": "resume", "engine_id": "e"}, False),
    ("POST", "/api/failsafe/commands/", {"action": "release", "engine_id": "e"}, False),
    ("POST", "/api/failsafe/commands/", {"action": "pause", "engine_id": "e", "nonce": "n"}, False),
    ("PUT", DISPATCH, {"enabled": False}, True),
    ("PUT", DISPATCH, {"enabled": "false", "reason": "incident"}, True),
    ("PUT", DISPATCH, {"enabled": True}, False),
    ("PUT", DISPATCH, {"enabled": None}, False),
    ("PUT", DISPATCH, {"enabled": False, "on_blocking_decision": True}, False),
    ("PUT", DISPATCH, {"reason": "x"}, False),
    ("PATCH", ENGAGEMENT, {"status": "paused"}, True),
    ("PATCH", ENGAGEMENT, {"status": "cancelled"}, True),
    ("PATCH", ENGAGEMENT, {"status": "completed"}, True),
    ("PATCH", ENGAGEMENT, {"status": "planned"}, True),
    ("PATCH", ENGAGEMENT, {"scope_hosts": []}, True),
    ("PATCH", ENGAGEMENT, {"testing_window_end": PAST}, True),
    ("PATCH", ENGAGEMENT, {"testing_window_end": None}, True),
    ("PATCH", ENGAGEMENT, {"status": "cancelled", "scope_hosts": [], "testing_window_end": PAST}, True),
    ("PATCH", ENGAGEMENT, {"status": "running"}, False),
    ("PATCH", ENGAGEMENT, {"status": "archived"}, False),
    ("PATCH", ENGAGEMENT, {"scope_hosts": ["a.example"]}, False),
    ("PATCH", ENGAGEMENT, {"testing_window_end": FUTURE}, False),
    ("PATCH", ENGAGEMENT, {"testing_window_end": "not a date"}, False),
    ("PATCH", ENGAGEMENT, {"testing_window_start": PAST}, False),
    ("PATCH", ENGAGEMENT, {"status": "paused", "name": "x"}, False),
    ("PATCH", ENGAGEMENT, {}, False),
    ("PATCH", SET_ROLE, {"role": "viewer"}, True),
    ("PATCH", SET_ROLE, {"role": "admin"}, False),
    ("PATCH", SET_ROLE, {"role": "root"}, False),
    ("PATCH", SET_ROLE, {"role": "viewer", "is_superuser": True}, False),
]


@pytest.mark.parametrize(("method", "path", "body", "expected"), DIRECTION,
                         ids=[f"{m}-{p.split('/')[3]}-{i}" for i, (m, p, *_) in enumerate(DIRECTION)])
def test_each_predicate_is_exactly_stop_direction(method, path, body, expected):
    assert stops.is_stop(_json(method, path, body)) is expected


def test_an_engagement_window_closed_as_the_serializer_reads_it():
    """The end is read as the serializer reads it, so a naive time is in the
    project's zone and an offset is honoured."""
    now = timezone.now()
    for end, expected in (
        ((now - timedelta(minutes=1)).isoformat(), True),
        ((now + timedelta(minutes=5)).isoformat(), False),
        ((now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S+00:00"), True),
    ):
        assert stops.is_stop(_json("PATCH", ENGAGEMENT, {"testing_window_end": end})) is expected, end


User = get_user_model()
_n = [0]


def _user(role="admin"):
    _n[0] += 1
    return User.objects.create_user(username=f"stop321-{_n[0]}", password="x", role=role)


@pytest.mark.django_db
def test_a_move_to_analyst_is_a_stop_only_when_it_takes_access_away():
    """Analyst is below admin and above viewer: from admin it is a demotion,
    from viewer a promotion. The target's role is read to tell them apart."""
    for current, expected in (("admin", True), ("analyst", True), ("viewer", False)):
        target = _user(current)
        request = _json("PATCH", f"/api/accounts/users/{target.pk}/set_role/", {"role": "analyst"})
        assert stops.is_stop(request) is expected, current
    # No such account: the view answers 404 and nothing is granted.
    assert stops.is_stop(_json("PATCH", "/api/accounts/users/999999/set_role/", {"role": "analyst"}))


@pytest.mark.django_db
def test_a_demotion_whose_role_cannot_be_read_is_a_stop(monkeypatch):
    target = _user("admin")

    def broken(*args, **kwargs):
        raise RuntimeError("the database is gone")

    monkeypatch.setattr(User.objects, "filter", broken)
    request = _json("PATCH", f"/api/accounts/users/{target.pk}/set_role/", {"role": "analyst"})
    assert stops.is_stop(request)


#: Every JSON type, for the predicates' fields.
ODD_VALUES = [None, True, False, 0, 1, 1.5, "", "x", "true", [], [1], ["a"], {}, {"a": 1}, "admin"]


def test_no_predicate_raises_on_any_json_value():
    """is_stop makes a request whose judging raises a stop, so a predicate that
    raised on some value would let that value ride the exemption. None does."""
    fields = {
        ("deployment-recompute", "POST"): ["paused", "note", "reason"],
        ("claim-transition", "POST"): ["to_status", "note"],
        ("failsafe:commands", "POST"): ["action", "engine_id", "reason"],
        ("deployment-dispatch-policy", "PUT"): ["enabled", "reason"],
        ("pentest:engagement_detail", "PATCH"): ["status", "scope_hosts", "testing_window_end", "note"],
        ("accounts:user-set-role", "PATCH"): ["role"],
        ("token_refresh", "POST"): ["refresh"],
    }
    paths = {name: path for name, _m, path, *_ in STOP_REQUESTS}
    for (name, method), names in fields.items():
        predicate = stops.EXEMPT_ROUTES[name][method]
        request = _raw(method, paths[name])
        for field in names:
            for value in ODD_VALUES:
                for body in ({field: value}, {field: value, "extra": 1}, value):
                    predicate(request, lambda body=body: body)
        predicate(request, lambda: stops.NOT_CANONICAL)


def test_a_stop_route_request_that_cannot_be_judged_is_a_stop(monkeypatch):
    def broken(request, read):
        raise RuntimeError("the judge failed")

    monkeypatch.setitem(stops.EXEMPT_ROUTES, "deployment-recompute", {"POST": broken})
    request = RequestFactory().post(RECOMPUTE, data={}, content_type="application/json")
    assert stops.is_stop(request)
    # Off the stop set, nothing is a stop by accident.
    assert not stops.is_stop(RequestFactory().get("/api/failsafe/audit/"))
    assert not stops.is_stop(RequestFactory().get("/no/such/route/"))


def test_a_request_is_judged_once(monkeypatch):
    calls = []
    real = stops._judge
    monkeypatch.setattr(stops, "_judge", lambda request: calls.append(1) or real(request))
    request = _json("POST", RECOMPUTE, {"paused": True})
    assert stops.is_stop(request) and stops.is_stop(request)
    assert calls == [1]


def test_head_is_judged_as_get_and_options_is_not_a_stop():
    assert stops.is_stop(RequestFactory().head("/api/failsafe/commands/"))
    with override_settings(FAILSAFE_POLL_TOKEN=POLL_TOKEN):
        assert stops.is_stop(RequestFactory().head("/api/failsafe/pending/", HTTP_X_FAILSAFE_POLL_TOKEN=POLL_TOKEN))
    assert not stops.is_stop(RequestFactory().options("/api/failsafe/commands/"))


def test_a_length_that_is_not_a_number_is_read_as_no_body():
    """Django reads no body for it, and neither does this: a routine recompute.
    A stop that reads no body is a stop whatever its length says."""
    request = _raw("POST", RECOMPUTE, b'{"paused": true}')
    request.META["CONTENT_LENGTH"] = "sixteen"
    assert not stops.is_stop(request)
    request = _raw("GET", "/api/failsafe/commands/", b"{}")
    request.META["CONTENT_LENGTH"] = "sixteen"
    assert stops.is_stop(request)


def test_a_body_django_refuses_to_read_is_not_a_stop():
    with override_settings(DATA_UPLOAD_MAX_MEMORY_SIZE=8):
        assert not stops.is_stop(_raw("POST", RECOMPUTE, b'{"paused": true}'))
    with override_settings(DATA_UPLOAD_MAX_NUMBER_FIELDS=0):
        assert not stops.is_stop(_raw("POST", RECOMPUTE, b"paused=true", "application/x-www-form-urlencoded"))


def test_the_dispatch_and_engagement_predicates_refuse_bodies_not_in_canonical_form():
    for method, path, field, value in (("PUT", DISPATCH, "enabled", "false"), ("PATCH", ENGAGEMENT, "status", "paused")):
        assert stops.is_stop(_raw(method, path, f"{field}={value}".encode(), "application/x-www-form-urlencoded"))
        assert not stops.is_stop(_raw(method, path, _multipart(field, value), MULTIPART))
        assert not stops.is_stop(_raw(method, path, json.dumps({field: value}).encode(), "*/*"))
        assert not stops.is_stop(_raw(method, path, b"{" + b" " * 70_000 + b"}"))


# --- Judging is cheap and bounded: it runs before authentication ----------------


class _CountingStream(io.BytesIO):
    def __init__(self, data):
        super().__init__(data)
        self.taken = 0

    def read(self, size=-1):
        chunk = super().read(size)
        self.taken += len(chunk)
        return chunk

    def readline(self, size=-1):
        chunk = super().readline(size)
        self.taken += len(chunk)
        return chunk


def test_a_ten_megabyte_body_is_judged_in_ten_milliseconds_without_reading_it():
    """Round 1: judging a 1 MB punycode body took 57 s, before authentication,
    and a 10 MB one about an hour. A body declared larger than 64 KiB is not
    read at all now."""
    body = b'{"paused": true, "note": "' + b"a" * (10 * 1024 * 1024) + b'"}'
    for content_type in ("application/json", "application/json; charset=punycode"):
        request = _raw("POST", RECOMPUTE, body, content_type)
        stream = _CountingStream(body)
        request._stream = stream
        started = time.perf_counter()
        verdict = stops.is_stop(request)
        took = time.perf_counter() - started
        assert verdict is False
        assert took < 0.010, f"{took * 1000:.1f} ms"
        assert stream.taken == 0


def test_a_slow_codec_is_never_decoded():
    """Just under the limit, punycode is refused on its name, not decoded."""
    body = ('{"x": "' + "aé" * 12_000 + '"}').encode("punycode")
    assert len(body) < stops.STOP_BODY_LIMIT
    request = _raw("POST", RECOMPUTE, body, "application/json; charset=punycode")
    started = time.perf_counter()
    assert not stops.is_stop(request)
    assert time.perf_counter() - started < 0.010
    assert stops.CANONICAL_CODECS.isdisjoint(gateway_module._SLOW_CHARSETS)


def test_a_body_at_the_limit_is_read_once_and_no_further():
    body = b'{"paused": true, "note": "' + b"a" * (stops.STOP_BODY_LIMIT - 40) + b'"}'
    assert len(body) <= stops.STOP_BODY_LIMIT
    from django.core.handlers.wsgi import LimitedStream

    request = _raw("POST", RECOMPUTE, body)
    stream = _CountingStream(body + b"trailing bytes past the declared length")
    request._stream = LimitedStream(stream, len(body))
    assert stops.is_stop(request)
    assert stream.taken <= stops.STOP_BODY_LIMIT + 1


# --- The real clients: every stop they send is recognised ------------------------

BEARER = {"HTTP_AUTHORIZATION": "Bearer header.payload.signature"}


def _client_shape(method, path, body=None, content_type="application/json", **extra):
    """A request as its client puts it on the wire: JSON.stringify and Python's
    json.dumps both write compact or spaced JSON with no charset; a fetch with
    no body still sends the JSON content type, with a length of 0."""
    request = RequestFactory().generic(method, path, data=b"" if body is None else body, content_type=content_type, **extra)
    if body is None and content_type:
        request.META["CONTENT_TYPE"] = content_type
        request.META["CONTENT_LENGTH"] = "0"
    return request


def _stringify(value):
    """JavaScript's JSON.stringify: no spaces."""
    return json.dumps(value, separators=(",", ":")).encode()


REAL_CLIENTS = [
    # athena-dashboard server/assurance.ts recomputeDecision: call() sets
    # Content-Type application/json and a Bearer token; body JSON.stringify({paused}).
    ("dashboard pause", "POST", RECOMPUTE, _stringify({"paused": True}), {}),
    # server/assurance.ts transitionClaim: {to_status} plus note when given.
    ("dashboard revoke", "POST", TRANSITION, _stringify({"to_status": "revoked"}), {}),
    ("dashboard revoke with a note", "POST", TRANSITION, _stringify({"to_status": "revoked", "note": "key leaked"}), {}),
    ("dashboard contradict with a note", "POST", TRANSITION, _stringify({"to_status": "contradicted", "note": "é, unicode"}), {}),
    # server/failsafe.ts draftCommand: {action, engine_id, reason}.
    ("dashboard draft pause", "POST", "/api/failsafe/commands/", _stringify({"action": "pause", "engine_id": "athena-1", "reason": "incident 12"}), {}),
    ("dashboard draft stand-down", "POST", "/api/failsafe/commands/", _stringify({"action": "stand_down", "engine_id": "athena-1", "reason": ""}), {}),
    ("dashboard draft terminate", "POST", "/api/failsafe/commands/", _stringify({"action": "terminate", "engine_id": "athena-1", "reason": "x"}), {}),
    # server/failsafe.ts listCommands / getCommand: GET, JSON content type, no body.
    ("dashboard list", "GET", "/api/failsafe/commands/?engine_id=athena-1&status=awaiting_signatures", None, {}),
    ("dashboard command", "GET", f"/api/failsafe/commands/{U}/", None, {}),
    # server/failsafe.ts status() and the page's in-flight list: GET state, the
    # read a second operator finds the command awaiting their signature in.
    ("dashboard state", "GET", "/api/failsafe/state/?engine_id=athena-1", None, {}),
    ("dashboard state, no engine", "GET", "/api/failsafe/state/", None, {}),
]


@pytest.mark.parametrize(("label", "method", "path", "body", "extra"), REAL_CLIENTS, ids=[c[0] for c in REAL_CLIENTS])
def test_every_real_clients_stop_is_recognised(label, method, path, body, extra):
    assert stops.is_stop(_client_shape(method, path, body, **BEARER, **extra)), label


#: server/failsafe.ts submitSignature relays {key_id, sig} as mythos-failsafe
#: sign prints it (mythos_core/failsafe/sign.py sign_draft: json.dumps, spaced);
#: cancelCommand is a POST with the JSON content type and no body.
SIGNATURE_BODY = json.dumps({"key_id": "alice", "sig": "ab" * 64}).encode()


@pytest.mark.django_db
def test_a_signature_or_cancel_is_judged_by_its_commands_direction():
    """H2: every cancel was exempt, and cancelling a pause, stand-down or
    terminate that is awaiting signatures or ready withdraws the stop. A cancel
    of a resume or release keeps the engine stopped: that one is a stop. A
    signature is the other way round: on a stop command it brings the stop
    nearer, on a resume or release it starts the engine again. Each is judged
    by one read of the command's action; the body is not read."""
    for action, cancel_is_a_stop in (("pause", False), ("stand_down", False), ("terminate", False),
                                     ("resume", True), ("release", True)):
        for state in ("awaiting_signatures", "ready"):
            command = _command(action, status=state)
            cancel = _client_shape("POST", f"/api/failsafe/commands/{command.uuid}/cancel/", None, **BEARER)
            sign = _client_shape("POST", f"/api/failsafe/commands/{command.uuid}/signatures/", SIGNATURE_BODY, **BEARER)
            assert stops.is_stop(cancel) is cancel_is_a_stop, (action, state)
            assert stops.is_stop(sign) is not cancel_is_a_stop, (action, state)
    # No such command: the view answers 404, and neither is a stop.
    for route in ("cancel", "signatures"):
        assert not stops.is_stop(_client_shape("POST", f"/api/failsafe/commands/{U}/{route}/", SIGNATURE_BODY, **BEARER))


@pytest.mark.django_db
def test_a_command_that_cannot_be_read_falls_the_safe_way(monkeypatch):
    """A cancel whose command cannot be read may be withdrawing a stop: not a
    stop, so it goes through the gateway (bounded by its deadline) to the view.
    A signature whose command cannot be read may be a stop's: a stop."""
    from failsafe.models import FailsafeCommand

    command = _command("resume")

    def broken(*args, **kwargs):
        raise RuntimeError("the database is gone")

    monkeypatch.setattr(FailsafeCommand.objects, "filter", broken)
    assert not stops.is_stop(_client_shape("POST", f"/api/failsafe/commands/{command.uuid}/cancel/", None, **BEARER))
    assert stops.is_stop(_client_shape("POST", f"/api/failsafe/commands/{command.uuid}/signatures/", SIGNATURE_BODY, **BEARER))


@pytest.mark.django_db
def test_judging_a_signature_or_cancel_is_one_indexed_read():
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    from failsafe.models import FailsafeCommand

    command = _command("resume")
    with CaptureQueriesContext(connection) as queries:
        assert stops.is_stop(_client_shape("POST", f"/api/failsafe/commands/{command.uuid}/cancel/", None, **BEARER))
    assert len(queries) == 1 and "uuid" in queries[0]["sql"]
    assert FailsafeCommand._meta.get_field("uuid").unique


def test_the_engines_poll_is_recognised():
    """mythos_core/failsafe/channel.py PollingHTTPChannel.poll: a GET through
    safe_http.control_read with the X-Failsafe-Poll-Token header and engine_id
    as a query parameter, no body and no content type."""
    with override_settings(FAILSAFE_POLL_TOKEN=POLL_TOKEN):
        request = RequestFactory().get(
            "/api/failsafe/pending/", {"engine_id": "athena-1"}, HTTP_X_FAILSAFE_POLL_TOKEN=POLL_TOKEN
        )
        assert stops.is_stop(request)


def test_the_dashboards_resume_and_release_drafts_are_not_stops():
    for action in ("resume", "release"):
        body = _stringify({"action": action, "engine_id": "athena-1", "reason": ""})
        assert not stops.is_stop(_client_shape("POST", "/api/failsafe/commands/", body, **BEARER))


def test_the_dashboards_lift_is_not_a_stop():
    assert not stops.is_stop(_client_shape("POST", RECOMPUTE, _stringify({"paused": False}), **BEARER))


def test_the_poll_token_is_compared_as_two_digests_of_one_length(monkeypatch):
    from failsafe import views

    seen = []
    real = views.hmac.compare_digest

    def spy(a, b):
        seen.append((len(a), len(b)))
        return real(a, b)

    monkeypatch.setattr(views.hmac, "compare_digest", spy)
    with override_settings(FAILSAFE_POLL_TOKEN=POLL_TOKEN):
        for guess, expected in (("x", False), ("x" * 500, False), (POLL_TOKEN, True), (POLL_TOKEN + "x", False)):
            request = RequestFactory().get("/api/failsafe/pending/", HTTP_X_FAILSAFE_POLL_TOKEN=guess)
            assert views.poll_token_ok(request) is expected
    assert seen == [(32, 32)] * 4


# --- The gateway: a real engine on 127.0.0.1 that misbehaves -------------------


class _Engine(http.server.BaseHTTPRequestHandler):
    """/defend, answering block after ``mode``: at once, after a hang, with its
    body a byte at a time, or with its status line and headers a byte at a time.
    A drip is 0.15 s a byte, under any per-socket timeout used here."""

    def log_message(self, *args):
        pass

    def do_POST(self):
        self.rfile.read(int(self.headers.get("Content-Length") or 0))
        self.server.asked.append(self.path)
        raw = json.dumps({"allow": False, "action": "block", "reason": "stand-in"}).encode()
        head = f"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(raw)}\r\n\r\n"
        mode = self.server.mode
        try:
            if mode == "hang":
                time.sleep(3.0)
            if mode == "headers":
                for byte in head.encode():
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.15)
                self.wfile.write(raw)
                return
            self.wfile.write(head.encode())
            if mode == "body":
                for byte in raw[:16]:
                    self.wfile.write(bytes([byte]))
                    self.wfile.flush()
                    time.sleep(0.15)
                self.wfile.write(raw[16:])
            else:
                self.wfile.write(raw)
        except OSError:
            pass  # the caller stopped waiting, which is the point


class _EngineServer(http.server.ThreadingHTTPServer):
    daemon_threads = True
    block_on_close = False

    def handle_error(self, request, client_address):
        pass


@pytest.fixture()
def configure():
    """Settings for one test, put back after it."""
    active = []

    def apply(**values):
        override = override_settings(**values)
        override.enable()
        active.append(override)

    yield apply
    for override in reversed(active):
        override.disable()


@pytest.fixture()
def engine():
    server = _EngineServer(("127.0.0.1", 0), _Engine)
    server.mode, server.asked = "now", []
    threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05}, daemon=True).start()
    yield server
    server.shutdown()
    server.server_close()


@pytest.fixture()
def gateway(configure, engine):
    def build(mode="now", monitor_only=False, timeout=0.5, max_in_flight=32):
        engine.mode = mode
        configure(
            CYBERENGINE_URL=f"http://127.0.0.1:{engine.server_address[1]}",
            CYBERENGINE_OPERATOR_KEY="k",
            DEFENDER_MONITOR_ONLY=monitor_only,
            DEFENDER_TIMEOUT_SECONDS=timeout,
            DEFENDER_MAX_IN_FLIGHT=max_in_flight,
            FAILSAFE_POLL_TOKEN=POLL_TOKEN,
        )
        return DefenderMiddleware(lambda request: HttpResponse("the view ran"))

    return build


def _request(method, path, body, extra, content_type="application/json"):
    factory = RequestFactory()
    if callable(path):
        path = path()
    if callable(body):
        body = body()
    if isinstance(body, bytes):
        data = body
    else:
        data = "" if body is None else json.dumps(body)
    return factory.generic(method, path, data=data, content_type=content_type, **extra)


@pytest.mark.django_db
@pytest.mark.parametrize("mode", ["hang", "body", "headers"])
@pytest.mark.parametrize(
    "sample", STOP_REQUESTS, ids=[f"{name}-{method}-{i}" for i, (name, method, *_) in enumerate(STOP_REQUESTS)]
)
def test_a_slow_or_trickling_engine_never_delays_a_stop(gateway, engine, mode, sample):
    """Measured on 7985460: 0.5 s behind a hung engine, 20.5 s behind one that
    drips its body, 30 s behind one that drips its headers -- every stop, and
    the engines' own poll. A stop never reaches the engine now."""
    _name, method, path, body, extra = sample
    app = gateway(mode=mode, monitor_only=True)
    request = _request(method, path, body, extra)
    started = time.monotonic()
    response = app(request)
    took = time.monotonic() - started
    assert response.status_code == 200 and response.content == b"the view ran"
    assert took < 0.25, f"{method} {path} took {took:.3f}s behind an engine in mode {mode!r}"
    assert engine.asked == []


@pytest.mark.django_db
@pytest.mark.parametrize("answer", [
    {"allow": False, "action": "block", "reason": "x"},
    {"allow": True, "action": "throttle", "block_seconds": 30},
])
@pytest.mark.parametrize(
    "sample", STOP_REQUESTS, ids=[f"{name}-{method}-{i}" for i, (name, method, *_) in enumerate(STOP_REQUESTS)]
)
def test_enforce_mode_never_refuses_a_stop(configure, sample, answer):
    """On 7985460, with DEFENDER_MONITOR_ONLY=False, the engine's block answered
    every stop 403 and its throttle answered 429."""
    _name, method, path, body, extra = sample
    configure(DEFENDER_MONITOR_ONLY=False, FAILSAFE_POLL_TOKEN=POLL_TOKEN)
    post = mock.Mock(side_effect=AssertionError("a stop was sent to the engine"))
    with mock.patch("audit.middleware.requests.post", post):
        response = DefenderMiddleware(lambda request: HttpResponse("the view ran"))(
            _request(method, path, body, extra)
        )
    assert response.status_code == 200 and response.content == b"the view ran"
    post.assert_not_called()


def _engine_answers(payload=None, raw=None):
    import urllib3

    def answer(*args, **kwargs):
        response = requests.Response()
        response.status_code = 200
        body = raw if raw is not None else json.dumps(payload).encode()
        response.raw = urllib3.HTTPResponse(body=io.BytesIO(body), status=200, preload_content=False)
        return response

    return mock.Mock(side_effect=answer)


@pytest.mark.parametrize("sample", NOT_STOP_REQUESTS, ids=[s[0] for s in NOT_STOP_REQUESTS])
def test_the_same_routes_are_still_enforced_when_the_request_is_not_a_stop(configure, sample):
    """The exemption is the stop set and no wider. Round 1 let every one of the
    content-type, promotion, switch-on and widening cases here past the gateway
    to its view (A1-A7 of the adversary report)."""
    _label, method, path, body, content_type, extra = sample
    configure(DEFENDER_MONITOR_ONLY=False, FAILSAFE_POLL_TOKEN=POLL_TOKEN)
    post = _engine_answers({"allow": False, "action": "block", "reason": "x"})
    with mock.patch("audit.middleware.requests.post", post):
        response = DefenderMiddleware(lambda request: HttpResponse("the view ran"))(
            _request(method, path, body, extra, content_type)
        )
    assert response.status_code == 403
    post.assert_called_once()


@pytest.mark.parametrize("mode", ["hang", "body", "headers"])
def test_every_other_request_waits_no_longer_than_the_whole_deadline_and_is_allowed(gateway, engine, mode):
    """The deadline is on the whole call. requests' timeout was per socket
    operation, so a byte every 0.15 s never tripped it: the body drip held the
    request 2.4 s and the header drip 7 s. Past the deadline the request is
    allowed, as when the engine is down: the gateway fails open, even though the
    late answer here is a block in enforce mode."""
    app = gateway(mode=mode, monitor_only=False, timeout=0.3)
    started = time.monotonic()
    response = app(_request("GET", "/api/failsafe/audit/", None, {}))
    took = time.monotonic() - started
    assert response.status_code == 200 and response.content == b"the view ran"
    assert took < 0.3 + 0.25, f"took {took:.3f}s against a 0.3s deadline"
    assert engine.asked == ["/defend"]


def test_calls_left_running_are_bounded_and_the_next_request_still_meets_its_deadline(gateway, monkeypatch):
    """A call the request stopped waiting for can still be running -- an engine
    dripping its headers holds it. With every slot taken, the next request waits
    for one only until its own deadline, and is allowed."""
    app = gateway(mode="headers", monitor_only=False, timeout=0.3, max_in_flight=1)
    problems = []
    monkeypatch.setattr(app, "_record_failure", problems.append)
    for _ in range(2):
        started = time.monotonic()
        response = app(_request("GET", "/api/failsafe/audit/", None, {}))
        assert response.status_code == 200
        assert time.monotonic() - started < 0.3 + 0.25
    assert problems[0] == "engine gave no decision within 0.3s"
    assert problems[1] == "all 1 engine call slots are in use; not asking"


def test_the_call_stops_reading_a_trickling_answer_at_its_deadline(gateway, engine, monkeypatch):
    """The answer is read as a stream under the deadline, so a call left behind
    by its request gives its slot back within a byte of the deadline, not when
    the engine finishes dripping (2.4 s here). With one slot, a request 0.8 s
    later is asked about, not turned away as "all slots in use"."""
    app = gateway(mode="body", monitor_only=False, timeout=0.3, max_in_flight=1)
    problems = []
    monkeypatch.setattr(app, "_record_failure", problems.append)
    started = time.monotonic()
    app(_request("GET", "/api/failsafe/audit/", None, {}))
    time.sleep(max(0.0, 0.8 - (time.monotonic() - started)))
    app(_request("GET", "/api/failsafe/audit/", None, {}))
    assert len(engine.asked) == 2, problems
    assert "all 1 engine call slots are in use; not asking" not in problems


def test_a_prompt_answer_is_still_enforced(gateway):
    app = gateway(mode="now", monitor_only=False)
    response = app(_request("GET", "/api/failsafe/audit/", None, {}))
    assert response.status_code == 403


# --- The gateway's failure branches ---------------------------------------------


@pytest.fixture()
def enforcing(configure, monkeypatch):
    """A gateway in enforce mode with its failures captured."""
    configure(DEFENDER_MONITOR_ONLY=False, CYBERENGINE_OPERATOR_KEY="k", DEFENDER_TIMEOUT_SECONDS=0.5)
    app = DefenderMiddleware(lambda request: HttpResponse("the view ran"))
    problems = []
    monkeypatch.setattr(app, "_record_failure", problems.append)
    return app, problems


def test_an_answer_larger_than_the_limit_is_not_read_and_the_request_is_allowed(enforcing, monkeypatch):
    app, problems = enforcing
    oversized = b'{"allow": false, "action": "block", "pad": "' + b"a" * (70 * 1024) + b'"}'
    monkeypatch.setattr("audit.middleware.requests.post", _engine_answers(raw=oversized))
    response = app(_request("GET", "/api/failsafe/audit/", None, {}))
    assert response.status_code == 200
    assert problems == [f"engine answer is larger than {gateway_module._ANSWER_LIMIT} bytes"]


def test_an_answer_that_cannot_be_read_is_recorded_and_the_request_is_allowed(enforcing, monkeypatch):
    app, problems = enforcing

    class Broken(io.BufferedIOBase):
        def readable(self):
            return True

        def read(self, size=-1):
            raise OSError("connection reset")

        read1 = read

        def readinto(self, buffer):
            raise OSError("connection reset")

    import urllib3

    def answer(*args, **kwargs):
        response = requests.Response()
        response.status_code = 200
        response.raw = urllib3.HTTPResponse(body=Broken(), status=200, preload_content=False)
        return response

    monkeypatch.setattr("audit.middleware.requests.post", mock.Mock(side_effect=answer))
    response = app(_request("GET", "/api/failsafe/audit/", None, {}))
    assert response.status_code == 200
    assert len(problems) == 1 and problems[0].startswith("engine answer could not be read: ")


def test_a_call_that_cannot_start_gives_its_slot_back(enforcing, monkeypatch, configure):
    configure(DEFENDER_MAX_IN_FLIGHT=1)
    app = DefenderMiddleware(lambda request: HttpResponse("the view ran"))
    problems = []
    monkeypatch.setattr(app, "_record_failure", problems.append)

    def refuse(self):
        raise RuntimeError("can't start new thread")

    with mock.patch.object(threading.Thread, "start", refuse):
        for _ in range(2):
            assert app(_request("GET", "/api/failsafe/audit/", None, {})).status_code == 200
    assert problems == ["engine call could not start: RuntimeError"] * 2


def test_an_error_that_is_not_a_request_failure_is_raised_as_before(enforcing, monkeypatch):
    app, problems = enforcing
    monkeypatch.setattr("audit.middleware.requests.post", mock.Mock(side_effect=ValueError("a bug")))
    with pytest.raises(ValueError, match="a bug"):
        app(_request("GET", "/api/failsafe/audit/", None, {}))
    assert app._slots.acquire(timeout=0)
    app._slots.release()


# --- The throttles and sign-in, through the whole stack --------------------------

#: The shipped anonymous rate (config.settings). The engines poll every 2 s.
ANON_RATE = "30/min"


@pytest.fixture()
def rates(monkeypatch, configure):
    """Real rates for these tests. The test settings switch throttling off, and
    the throttle classes read their rates once, at import."""

    def apply(anon=ANON_RATE, user="300/min", sign_in="10/min", sign_in_address="60/min"):
        monkeypatch.setattr(
            SimpleRateThrottle,
            "THROTTLE_RATES",
            {"anon": anon, "user": user, "sign_in": sign_in, "sign_in_address": sign_in_address},
        )

    cache.clear()
    configure(DEFENDER_MONITOR_ONLY=True, FAILSAFE_POLL_TOKEN=POLL_TOKEN)
    # The gateway answers allow at once: these tests are about the throttles.
    monkeypatch.setattr("audit.middleware.requests.post", _engine_answers({"allow": True, "action": "allow"}))
    # The state view's engine read answers at once, whatever engine is configured.
    monkeypatch.setattr(
        "ai_engine.services.cyberengine_client.CyberEngineClient.from_settings",
        classmethod(lambda cls: _LiveState()),
    )
    apply()
    yield apply
    cache.clear()


class _LiveState:
    def failsafe_state(self):
        return {"enabled": True, "engine_id": "athena-1", "state": "running"}


def _poll(client=None, token=POLL_TOKEN, engine_id="athena-1", **extra):
    headers = {} if token is None else {"HTTP_X_FAILSAFE_POLL_TOKEN": token}
    return (client or APIClient()).get(f"/api/failsafe/pending/?engine_id={engine_id}", **headers, **extra)


@pytest.mark.django_db
def test_more_than_thirty_polls_a_minute_from_one_address_are_all_served(rates):
    """On 7985460 the 31st poll in a minute was 429 with Retry-After 60."""
    codes = [_poll().status_code for _ in range(45)]
    assert codes == [200] * 45


@pytest.mark.django_db
def test_two_engines_behind_one_address_are_never_throttled(rates):
    codes = {"athena-1": [], "athena-2": []}
    for _ in range(30):
        for engine_id in codes:
            codes[engine_id].append(_poll(engine_id=engine_id).status_code)
    assert codes == {"athena-1": [200] * 30, "athena-2": [200] * 30}


@pytest.mark.django_db
def test_a_flood_of_guesses_at_the_poll_token_is_still_limited(rates):
    """A poll without the token is not a stop: it is throttled like any other
    anonymous request, so the token cannot be guessed at speed."""
    codes = [_poll(token="a-guess").status_code for _ in range(31)]
    assert codes == [401] * 30 + [429]
    assert _poll(token=None).status_code == 429


@pytest.mark.django_db
def test_the_engine_is_served_from_an_address_whose_guesses_are_throttled(rates):
    for _ in range(31):
        _poll(token="a-guess")
    assert _poll(token="a-guess").status_code == 429
    assert _poll().status_code == 200


@pytest.mark.django_db
def test_a_poll_carrying_a_stale_bearer_header_is_served(rates):
    """The engine is not an operator and the poll reads no JWT; on 7985460 a
    stale bearer header on the engine's request was answered 401."""
    assert _poll(HTTP_AUTHORIZATION="Bearer stale").status_code == 200


def _admin():
    return _user("admin")


def _deployment():
    from assurance.claims import derive_claims
    from assurance.decision import recompute_decision
    from assurance.models import Asset, DataBoundary, Deployment

    dep = Deployment.objects.create(name=f"stop321-{uuid.uuid4()}", owner=_admin())
    Deployment.objects.filter(pk=dep.pk).update(last_complete_scan_at=timezone.now())
    DataBoundary.objects.create(
        deployment=dep, allowed_regions=["eu-west-1"], training_allowed=False, third_party_sharing_allowed=False
    )
    Asset.objects.bulk_create(
        [
            Asset(deployment=dep, kind=Asset.Kind.TOOL, name=f"tool-{i}", identifier=f"tool-{i}",
                  classification=Asset.Classification.KNOWN)
            for i in range(3)
        ]
    )
    derive_claims(Deployment.objects.get(pk=dep.pk))
    recompute_decision(Deployment.objects.get(pk=dep.pk))
    return Deployment.objects.get(pk=dep.pk)


def _claim(dep):
    from assurance.models import AssuranceClaim

    Status = AssuranceClaim.ClaimStatus
    return (
        AssuranceClaim.objects.filter(deployment=dep, valid_to__isnull=True)
        .exclude(status__in=[Status.REVOKED, Status.STALE, Status.SUPERSEDED])
        .order_by("pk")
        .first()
    )


@pytest.fixture()
def operator_key(configure):
    key = Ed25519PrivateKey.generate()
    configure(FAILSAFE_OPERATOR_KEYS={"alice": key.public_key().public_bytes_raw().hex()})
    return key


def _every_stop(client, operator, operator_key, anonymous=APIClient):
    """Every kind of stop an operator makes, each on its own row, the three
    stop-lane reads, the engine's poll, and the refresh that keeps an operator
    signed in. Returns {stop: status code}; EVERY_STOP says which route and
    method each one is, and a test below holds that to the exempt set. The
    failsafe commands are for an engine of their own, so a second call drafts
    afresh. ``anonymous`` makes the client the poll and the refresh are sent
    with."""
    from rest_framework_simplejwt.tokens import RefreshToken

    from pentest.models import Engagement

    to_pause, to_revoke, to_contradict, to_switch_off = (_deployment() for _ in range(4))
    engine_id = f"athena-{uuid.uuid4().hex[:8]}"
    # A pause to read and sign (a draft of a stop is a stop too), and a resume
    # to cancel: cancelling a resume keeps the engine stopped.
    pause = client.post("/api/failsafe/commands/", {"action": "pause", "engine_id": engine_id}, format="json").data
    sig = operator_key.sign(bytes.fromhex(pause["signing_bytes"])).hex()
    resume = _command("resume", engine_id, initiator=operator)
    engagements = [
        Engagement.objects.create(name=f"stop321-{i}", created_by=operator, status="running", scope_hosts=["client.example"])
        for i in range(3)
    ]
    colleague, deputy, leaver = _admin(), _admin(), _admin()
    past = (timezone.now() - timedelta(minutes=1)).isoformat()

    base = "/api/assurance"
    return {
        "pause": client.post(f"{base}/deployments/{to_pause.uuid}/recompute/", {"paused": True}, format="json").status_code,
        "revoke": client.post(f"{base}/claims/{_claim(to_revoke).uuid}/transition/", {"to_status": "revoked"}, format="json").status_code,
        "contradict": client.post(f"{base}/claims/{_claim(to_contradict).uuid}/transition/", {"to_status": "contradicted"}, format="json").status_code,
        "stand down": client.post("/api/failsafe/commands/", {"action": "stand_down", "engine_id": engine_id}, format="json").status_code,
        "terminate": client.post("/api/failsafe/commands/", {"action": "terminate", "engine_id": engine_id}, format="json").status_code,
        "state read": client.get(f"/api/failsafe/state/?engine_id={engine_id}").status_code,
        "list": client.get(f"/api/failsafe/commands/?engine_id={engine_id}&status=awaiting_signatures").status_code,
        "command read": client.get(f"/api/failsafe/commands/{pause['uuid']}/").status_code,
        "sign": client.post(f"/api/failsafe/commands/{pause['uuid']}/signatures/", {"key_id": "alice", "sig": sig}, format="json").status_code,
        "cancel": client.post(f"/api/failsafe/commands/{resume.uuid}/cancel/", {}, format="json").status_code,
        "dispatch off": client.put(f"{base}/deployments/{to_switch_off.uuid}/dispatch-policy/", {"enabled": False}, format="json").status_code,
        "engagement paused": client.patch(f"/api/pentest/engagements/{engagements[0].pk}/", {"status": "paused"}, format="json").status_code,
        "engagement window closed": client.patch(f"/api/pentest/engagements/{engagements[1].pk}/", {"testing_window_end": past}, format="json").status_code,
        "engagement scope emptied": client.patch(f"/api/pentest/engagements/{engagements[2].pk}/", {"scope_hosts": []}, format="json").status_code,
        "operator demoted": client.patch(f"/api/accounts/users/{colleague.pk}/set_role/", {"role": "viewer"}, format="json").status_code,
        "admin demoted to analyst": client.patch(f"/api/accounts/users/{deputy.pk}/set_role/", {"role": "analyst"}, format="json").status_code,
        "operator removed": client.delete(f"/api/accounts/users/{leaver.pk}/").status_code,
        "poll": _poll(anonymous()).status_code,
        "refresh": anonymous().post("/api/token/refresh/", {"refresh": str(RefreshToken.for_user(operator))}, format="json").status_code,
    }


#: Each of _every_stop's requests: the route and method it is, and its answer when served.
EVERY_STOP = {
    "pause": ("deployment-recompute", "POST", 200),
    "revoke": ("claim-transition", "POST", 200),
    "contradict": ("claim-transition", "POST", 200),
    "stand down": ("failsafe:commands", "POST", 201),
    "terminate": ("failsafe:commands", "POST", 201),
    "state read": ("failsafe:state", "GET", 200),
    "list": ("failsafe:commands", "GET", 200),
    "command read": ("failsafe:command-detail", "GET", 200),
    "sign": ("failsafe:submit-signature", "POST", 200),
    "cancel": ("failsafe:cancel-command", "POST", 200),
    "dispatch off": ("deployment-dispatch-policy", "PUT", 200),
    "engagement paused": ("pentest:engagement_detail", "PATCH", 200),
    "engagement window closed": ("pentest:engagement_detail", "PATCH", 200),
    "engagement scope emptied": ("pentest:engagement_detail", "PATCH", 200),
    "operator demoted": ("accounts:user-set-role", "PATCH", 200),
    "admin demoted to analyst": ("accounts:user-set-role", "PATCH", 200),
    "operator removed": ("accounts:user-detail", "DELETE", 204),
    "poll": ("failsafe:pending", "GET", 200),
    "refresh": ("token_refresh", "POST", 200),
}
SERVED = {name: code for name, (_route, _method, code) in EVERY_STOP.items()}
#: The same, made with the failsafe service token and nothing else. The token
#: is not accepted on the account routes, so those three are 401: demoting or
#: removing an operator is an admin's own act, with their own session.
SERVICE_SERVED = {
    **SERVED, "operator demoted": 401, "admin demoted to analyst": 401, "operator removed": 401,
}


def test_every_exempt_route_and_method_is_driven_through_the_whole_stack():
    driven = {(route, method) for route, method, _code in EVERY_STOP.values()}
    declared = {(name, method) for name, methods in stops.EXEMPT_ROUTES.items() for method in methods}
    assert driven == declared


def _client_for(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


def _bearer_client(user):
    """A client that authenticates as a real one does: a JWT bearer header."""
    from rest_framework_simplejwt.tokens import AccessToken

    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {AccessToken.for_user(user)}")
    return client


@pytest.mark.django_db
def test_a_flooded_operator_can_still_pause_stand_down_revoke_and_read_the_stop_lane(rates, operator_key):
    """#310: past the per-user rate every stop was 429. The rate is 20/min here
    so the flood is short; the mechanism is the same at 300/min."""
    rates(user="20/min")
    operator = _admin()
    client = _client_for(operator)
    flood = [client.get("/api/failsafe/audit/").status_code for _ in range(25)]
    assert flood == [200] * 20 + [429] * 5, "the flood did not reach the rate"
    assert _every_stop(client, operator, operator_key) == SERVED


@pytest.mark.django_db
def test_stops_do_not_spend_the_operators_budget(rates, operator_key):
    """A stop is never counted: an operator who has just made every kind of stop
    still has the whole of their rate for everything else."""
    rates(user="5/min")
    operator = _admin()
    client = _client_for(operator)
    assert _every_stop(client, operator, operator_key) == SERVED
    reads = [client.get("/api/failsafe/audit/").status_code for _ in range(6)]
    assert reads == [200] * 5 + [429]


@pytest.mark.django_db
def test_drafts_of_a_resume_and_list_reads_past_the_rate_are_limited(rates):
    """Round 1 exempted every draft, resume and release included: 1,742 rows in
    12 s from one analyst. A resume or release draft now spends the budget."""
    rates(user="5/min")
    operator = _admin()
    client = _client_for(operator)
    codes = [
        client.post("/api/failsafe/commands/", {"action": "resume", "engine_id": f"e{i}"}, format="json").status_code
        for i in range(6)
    ]
    assert codes == [201] * 5 + [429]
    assert client.post("/api/failsafe/commands/", {"action": "pause", "engine_id": "e"}, format="json").status_code == 201


@pytest.mark.django_db
def test_a_lift_past_the_rate_is_limited(rates):
    """A lift is start-direction (M3): it spends the budget like a resume."""
    rates(user="3/min")
    client = _client_for(_admin())
    dep = _deployment()
    codes = [
        client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": False}, format="json").status_code
        for _ in range(4)
    ]
    assert codes == [200] * 3 + [429]
    pause = client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json")
    assert pause.status_code == 200


@pytest.mark.django_db
def test_enforce_mode_never_refuses_a_stop_through_the_whole_stack(rates, configure, operator_key, monkeypatch):
    """The gateway as settings.MIDDLEWARE installs it, answering block to
    everything in enforce mode: every stop is served, and a read is refused."""
    configure(DEFENDER_MONITOR_ONLY=False)
    monkeypatch.setattr(
        "audit.middleware.requests.post", _engine_answers({"allow": False, "action": "block", "reason": "x"})
    )
    operator = _admin()
    client = _client_for(operator)
    assert _every_stop(client, operator, operator_key) == SERVED
    assert client.get("/api/failsafe/audit/").status_code == 403


@pytest.mark.django_db
def test_enforce_mode_still_refuses_what_is_not_a_stop_through_the_whole_stack(rates, configure, monkeypatch):
    """Round 1 served each of these past a gateway answering block: a viewer
    promoted to admin, dispatch switched on, an engagement set running and
    widened, a viewer made analyst. Round 2 served the lift."""
    from assurance.decision import recompute_decision
    from assurance.models import Deployment
    from pentest.models import Engagement

    configure(DEFENDER_MONITOR_ONLY=False)
    monkeypatch.setattr(
        "audit.middleware.requests.post", _engine_answers({"allow": False, "action": "block", "reason": "x"})
    )
    operator = _admin()
    client = _client_for(operator)
    viewer, other_viewer = _user("viewer"), _user("viewer")
    dep, paused = _deployment(), _deployment()
    recompute_decision(paused, paused=True)
    engagement = Engagement.objects.create(name="stop321-w", created_by=operator, status="paused", scope_hosts=["client.example"])
    answers = {
        "promotion": client.patch(f"/api/accounts/users/{viewer.pk}/set_role/", {"role": "admin"}, format="json"),
        "viewer to analyst": client.patch(f"/api/accounts/users/{other_viewer.pk}/set_role/", {"role": "analyst"}, format="json"),
        "dispatch on": client.put(f"/api/assurance/deployments/{dep.uuid}/dispatch-policy/", {"enabled": True, "min_severity": "info"}, format="json"),
        "widened": client.patch(f"/api/pentest/engagements/{engagement.pk}/", {"status": "running", "scope_hosts": ["client.example", "other.example"]}, format="json"),
        "resume drafted": client.post("/api/failsafe/commands/", {"action": "resume", "engine_id": "athena-1"}, format="json"),
        "lift": client.post(f"/api/assurance/deployments/{paused.uuid}/recompute/", {"paused": False}, format="json"),
    }
    assert {name: response.status_code for name, response in answers.items()} == {name: 403 for name in answers}
    viewer.refresh_from_db(), other_viewer.refresh_from_db(), engagement.refresh_from_db()
    assert (viewer.role, other_viewer.role) == ("viewer", "viewer")
    assert (engagement.status, engagement.scope_hosts) == ("paused", ["client.example"])
    assert Deployment.objects.get(pk=paused.pk).decision == Deployment.Decision.PAUSED


# --- Every limit saturated at once: the stops are still served (M2, M3) --------


class _EveryScope(dict):
    """Throttle rates with a rate for every scope, however it is looked up."""

    def __missing__(self, key):
        return "1/min"

    def get(self, key, default=None):
        return self[key]


#: What a count in the saturated cache reads as.
_FULL = 10**9
_ABSENT = object()


def _full(value):
    """``value`` as a count past any limit: a number at least _FULL, a list or
    tuple of ten thousand moments, now. Anything else is left as it is."""
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return max(value, _FULL)
    if isinstance(value, (list, tuple)):
        return type(value)([time.time()] * 10_000)
    return value


class SaturatedCache(LocMemCache):
    """A cache in which every count is already full. Whatever a limit keeps in
    it -- a number, a list of moments -- reads as past any limit, whether it is
    there or not; a key it adds is already there; an increment lands past any
    limit. The saturation installs it as the default cache, so a limit that
    counts in the cache refuses, however it is built and wherever it runs: a
    throttle, a permission, a middleware, a view."""

    def get(self, key, default=None, version=None):
        value = super().get(key, _ABSENT, version)
        return _full(default if value is _ABSENT else value)

    def get_many(self, keys, version=None):
        return {key: _full(value) for key, value in super().get_many(keys, version).items()}

    def add(self, key, value, timeout=DEFAULT_TIMEOUT, version=None):
        return False

    def incr(self, key, delta=1, version=None):
        return _FULL

    def has_key(self, key, version=None):
        return True


def _every_throttle_class():
    """Every throttle class there is: every subclass of BaseThrottle, however
    deep (StopsPass's included), and the class of every throttle a served view
    names or builds, whatever it subclasses."""
    found, todo = set(), [BaseThrottle]
    while todo:
        cls = todo.pop()
        if cls not in found:
            found.add(cls)
            todo.extend(cls.__subclasses__())
    for entry in walk().values():
        for callback in entry["callbacks"]:
            if getattr(callback, "cls", None) is not None:
                found.update(_view_throttles(callback))
    return found


def _saturate_every_throttle(monkeypatch):
    """Every throttle refuses, and asks for an hour. Every allow_request any
    throttle class defines or inherits is replaced by one that refuses --
    except StopsPass's, the one place a stop is let through before any limit is
    asked. So a throttle lets a stop through only if StopsPass's allow_request
    is the first one it calls."""

    def refuse(self, request, view):
        return False

    def an_hour(self):
        return 3600.0

    for cls in _every_throttle_class():
        for klass in cls.__mro__:
            if klass in (StopsPass, object):
                continue
            if "allow_request" in vars(klass):
                monkeypatch.setattr(klass, "allow_request", refuse)
            if "wait" in vars(klass):
                monkeypatch.setattr(klass, "wait", an_hour)


@pytest.fixture()
def saturated(rates, configure, monkeypatch):
    """Every limit refuses at once, however it is built. Returns a function to
    call once the test's own classes exist, with the gateway's answer:

    * every throttle refuses and waits an hour (_saturate_every_throttle);
    * every rate reads as zero, whatever its scope and however it is set, so
      the sign-in limits refuse every attempt;
    * the default cache is saturated (SaturatedCache), so a count kept there
      by anything else is full;
    * the gateway is in enforce mode, answering as the test says.

    The stops are sent through config.wsgi.application (_WsgiClient), the
    entry point a server calls, so its wrapper is in front of them too."""
    configure(CACHES={"default": {"BACKEND": f"{__name__}.SaturatedCache", "LOCATION": "saturated-321"}})
    monkeypatch.setattr(SimpleRateThrottle, "THROTTLE_RATES", _EveryScope())
    monkeypatch.setattr(SimpleRateThrottle, "parse_rate", lambda self, rate: (0, 60))
    configure(DEFENDER_MONITOR_ONLY=False)
    # The WSGI wrapper starts the owed-dispatch sweeper (#303) on a request; not
    # a thread to leave running in a test.
    monkeypatch.setattr("assurance.dispatch.ensure_owed_sweeper", lambda: None)

    def apply(payload):
        _saturate_every_throttle(monkeypatch)
        monkeypatch.setattr("audit.middleware.requests.post", _engine_answers(payload))

    return apply


def _wsgi_application():
    """config.wsgi.application, imported without configuring Django again."""
    import django

    with mock.patch.object(django, "setup"):
        from config import wsgi
    return wsgi.application


class _WsgiHandler:
    """Sends a test client's request through config.wsgi.application, as a
    server does, and turns what it answers back into a response."""

    def __call__(self, environ):
        from django.core import signals
        from django.db import close_old_connections

        application = _wsgi_application()
        answer = {}

        def start_response(status_line, headers, exc_info=None):
            answer["status"], answer["headers"] = status_line, headers

        # As Django's test client does: the request ending must not close the
        # connection the test's transaction is on.
        signals.request_started.disconnect(close_old_connections)
        signals.request_finished.disconnect(close_old_connections)
        try:
            result = application(environ, start_response)
            try:
                body = b"".join(result)
            finally:
                if hasattr(result, "close"):
                    result.close()
        finally:
            signals.request_started.connect(close_old_connections)
            signals.request_finished.connect(close_old_connections)
        response = HttpResponse(body, status=int(answer["status"].split(" ", 1)[0]))
        for name, value in answer["headers"]:
            response[name] = value
        response.wsgi_request = types.SimpleNamespace(urlconf=None)
        try:
            response.data = json.loads(body)
        except ValueError:
            response.data = None
        return response


class _WsgiClient(APIClient):
    """An APIClient whose requests go through config.wsgi.application."""

    def __init__(self, **defaults):
        super().__init__(**defaults)
        self.handler = _WsgiHandler()


def _wsgi_bearer_client(user):
    from rest_framework_simplejwt.tokens import AccessToken

    client = _WsgiClient()
    client.credentials(HTTP_AUTHORIZATION=f"Bearer {AccessToken.for_user(user)}")
    return client


def _wsgi_service_client(token=None):
    client = _WsgiClient()
    client.credentials(HTTP_X_FAILSAFE_SERVICE_TOKEN=token or SERVICE_TOKEN)
    return client


GATEWAY_ANSWERS = {
    "allow": ({"allow": True, "action": "allow"}, 429),
    "block": ({"allow": False, "action": "block", "reason": "x"}, 403),
    "throttle": ({"allow": True, "action": "throttle", "block_seconds": 30}, 429),
}


@pytest.mark.django_db
@pytest.mark.parametrize("gateway_answer", list(GATEWAY_ANSWERS))
def test_with_every_limit_saturated_every_stop_is_served(saturated, operator_key, gateway_answer):
    """Every throttle class refusing, every rate zero, every count in the cache
    full, the sign-in limits refusing, and the gateway answering allow, block
    or throttle in enforce mode: each stop route's request, sent through the
    WSGI entry point and the whole stack as installed, is served -- by an
    operator with a JWT, and by the failsafe service token. A read that is not
    a stop is refused, so the saturation is real. Round 2's T1 (a limit in
    initial()) and round 3's T2 (a StopsPass subclass counting in the cache)
    fail here, whatever their rate."""
    payload, refused = GATEWAY_ANSWERS[gateway_answer]
    saturated(payload)
    operator = _admin()
    assert _sign_in(operator.username, "x").status_code in (403, 429)
    bearer = _wsgi_bearer_client(operator)
    assert bearer.get("/api/failsafe/audit/").status_code == refused
    assert _every_stop(bearer, operator, operator_key, anonymous=_WsgiClient) == SERVED
    service = _service_account()
    with override_settings(FAILSAFE_SERVICE_TOKEN=SERVICE_TOKEN, FAILSAFE_SERVICE_USER=service.username):
        assert _every_stop(_wsgi_service_client(), service, operator_key, anonymous=_WsgiClient) == SERVICE_SERVED


@pytest.mark.django_db
def test_the_saturation_catches_a_limit_added_in_initial(saturated, monkeypatch):
    """Round 2's T1: a per-view limit in initial(), outside throttle_classes and
    get_throttles(). The static check names it, and saturation refuses the pause
    it would have refused -- even at a rate far above what any test sends."""
    from rest_framework.throttling import SimpleRateThrottle as Rate

    from assurance.views import DeploymentViewSet

    class Recompute(Rate):
        rate = "1000/min"

        def get_cache_key(self, request, view):
            return f"t1-{request.user.pk}"

    def initial(self, request, *args, **kwargs):
        APIView.initial(self, request, *args, **kwargs)
        if getattr(self, "action", None) == "recompute" and not Recompute().allow_request(request, self):
            self.throttled(request, 60)

    monkeypatch.setattr(DeploymentViewSet, "initial", initial, raising=False)
    saturated({"allow": True, "action": "allow"})
    served = walk()
    assert any("overrides initial()" in _throttle_problems(cb) for cb in served["deployment-recompute"]["callbacks"])
    dep = _deployment()
    pause = _wsgi_bearer_client(_admin()).post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json")
    assert pause.status_code == 429


class _RecomputeBurst(StopsPass, BaseThrottle):
    """Round 3's T2 mutant, as it was put in DeploymentViewSet.throttle_classes:
    a StopsPass subclass -- so ``issubclass(t, StopsPass)`` passed -- whose own
    allow_request never asks whether the request is a stop, counting in the
    cache rather than through SimpleRateThrottle. It refused the 26th pause in
    a minute, and all 297 round-3 cases passed."""

    LIMIT = 25

    def allow_request(self, request, view):
        if getattr(view, "action", None) != "recompute":
            return True
        key = f"t2-burst-{request.user.pk}"
        count = cache.get(key, 0) + 1
        cache.set(key, count, 60)
        return count <= self.LIMIT

    def wait(self):
        return 60


@pytest.mark.django_db
def test_the_saturation_catches_round_3s_t2_mutant(saturated, monkeypatch):
    """T2 in DeploymentViewSet.throttle_classes: the static check names it, and
    the saturation refuses the pause -- by its own allow_request, which the
    saturation replaces as it does every throttle's but StopsPass's, and by its
    count in the cache, which the saturated cache reads as full."""
    from assurance.views import DeploymentViewSet
    from safety.throttling import StopExemptAnonRateThrottle, StopExemptUserRateThrottle

    monkeypatch.setattr(
        DeploymentViewSet,
        "throttle_classes",
        (StopExemptAnonRateThrottle, StopExemptUserRateThrottle, _RecomputeBurst),
    )
    problems = [p for cb in walk()["deployment-recompute"]["callbacks"] for p in _throttle_problems(cb)]
    assert "throttles with _RecomputeBurst, whose allow_request is not StopsPass's" in problems
    saturated({"allow": True, "action": "allow"})
    dep = _deployment()
    pause = _wsgi_bearer_client(_admin()).post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json")
    assert pause.status_code == 429
    # Its count alone, with its own allow_request put back, is full in the
    # saturated cache: the first pause is refused.
    monkeypatch.setattr(_RecomputeBurst, "allow_request", _RecomputeBurst.__dict__["allow_request"])
    assert not _RecomputeBurst().allow_request(
        types.SimpleNamespace(user=types.SimpleNamespace(pk=1)), types.SimpleNamespace(action="recompute")
    )


@pytest.mark.django_db
def test_the_saturation_catches_a_limit_that_is_not_a_throttle(saturated, monkeypatch):
    """A counting permission on the recompute -- not a throttle at all, so no
    throttle patch reaches it -- that keeps its count in the cache: the
    saturated cache reads the count as full, and the pause is refused. And a
    wrapper round the routed view (functools.wraps keeps its .cls) is named by
    the static check."""
    import functools

    from rest_framework.permissions import BasePermission

    from assurance.views import DeploymentViewSet

    class Budget(BasePermission):
        def has_permission(self, request, view):
            if getattr(view, "action", None) != "recompute":
                return True
            if cache.add(f"budget-{request.user.pk}", 0, 60):
                return True
            return cache.incr(f"budget-{request.user.pk}") <= 1000

    monkeypatch.setattr(DeploymentViewSet, "permission_classes", [*DeploymentViewSet.permission_classes, Budget])
    saturated({"allow": True, "action": "allow"})
    dep = _deployment()
    pause = _wsgi_bearer_client(_admin()).post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json")
    assert pause.status_code == 403

    callback = walk()["deployment-recompute"]["callbacks"][0]

    @functools.wraps(callback)
    def wrapped(request, *args, **kwargs):
        return callback(request, *args, **kwargs)

    assert "is routed through a wrapper the view class does not build" in _throttle_problems(wrapped)


# --- The failsafe service token: stops without a password sign-in (H1) ---------

SERVICE_TOKEN = "svc-" + "0123456789abcdef" * 3


def _service_account(username=None, role="admin", active=True):
    _n[0] += 1
    user = User.objects.create_user(
        username=username or f"failsafe-svc-{_n[0]}", password="svc-password", role=role
    )
    if not active:
        User.objects.filter(pk=user.pk).update(is_active=False)
    return user


def _service_client(token=SERVICE_TOKEN, **extra):
    client = APIClient()
    client.credentials(HTTP_X_FAILSAFE_SERVICE_TOKEN=token, **extra)
    return client


@pytest.fixture()
def service(configure):
    user = _service_account()
    configure(FAILSAFE_SERVICE_TOKEN=SERVICE_TOKEN, FAILSAFE_SERVICE_USER=user.username)
    return user


@pytest.mark.django_db
def test_the_dashboards_stops_need_no_password_sign_in(rates, service, operator_key, configure, monkeypatch):
    """H1: the dashboard's server signed in with a password for every stop,
    hourly. Ten wrong guesses at its username from the shared address answered
    that sign-in 429, and a gateway answering block answered it 403: every
    dashboard stop was 503. With the service token no stop signs in."""
    guesses = [_sign_in(service.username, f"guess-{i}").status_code for i in range(10)]
    assert guesses == [401] * 10
    assert _sign_in(service.username, "svc-password").status_code == 429
    assert _every_stop(_service_client(), service, operator_key) == SERVICE_SERVED

    configure(DEFENDER_MONITOR_ONLY=False)
    monkeypatch.setattr(
        "audit.middleware.requests.post", _engine_answers({"allow": False, "action": "block", "reason": "x"})
    )
    cache.clear()
    assert _sign_in(service.username, "svc-password").status_code == 403
    # A stale bearer beside the token cannot refuse the stop: the token is tried first.
    client = _service_client(HTTP_AUTHORIZATION="Bearer stale.bearer.header")
    assert _every_stop(client, service, operator_key) == SERVICE_SERVED


@pytest.mark.django_db
def test_the_service_token_does_nothing_but_stop(rates, service):
    """Accepted only on a stop or a stop-lane read. Everywhere else the header
    is ignored, so with no other credential the answer is 401 -- still 401,
    with the bearer challenge, not 403. Round 3 let it cancel another
    operator's stand-down awaiting its second signature, and a pause already
    signed and ready (H2), and delete other tenants' engagements (L2)."""
    from failsafe.models import FailsafeCommand
    from pentest.models import Engagement

    client = _service_client()
    dep, other = _deployment(), _deployment()
    engagement = Engagement.objects.create(name="stop321-s", created_by=service, status="paused", scope_hosts=["a.example"])
    running = Engagement.objects.create(name="stop321-r", created_by=_admin(), status="running", scope_hosts=["b.example"])
    viewer = _user("viewer")
    operator = _admin()
    stand_down = _command("stand_down", initiator=operator, signed=True,
                          signatures=[{"key_id": "alice", "sig": "00", "submitted_by": operator.username}])
    ready = _command("pause", initiator=operator, status="ready", signed=True)
    resume = _command("resume", initiator=operator)
    refused = {
        "lift": client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": False}, format="json"),
        "routine recompute": client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {}, format="json"),
        "resume drafted": client.post("/api/failsafe/commands/", {"action": "resume", "engine_id": "e"}, format="json"),
        "release drafted": client.post("/api/failsafe/commands/", {"action": "release", "engine_id": "e"}, format="json"),
        "resume signed": client.post(f"/api/failsafe/commands/{resume.uuid}/signatures/", {"key_id": "alice", "sig": "00"}, format="json"),
        "stand-down cancelled": client.post(f"/api/failsafe/commands/{stand_down.uuid}/cancel/", {}, format="json"),
        "ready pause cancelled": client.post(f"/api/failsafe/commands/{ready.uuid}/cancel/", {}, format="json"),
        "claim verified": client.post(f"/api/assurance/claims/{_claim(other).uuid}/transition/", {"to_status": "verified"}, format="json"),
        "dispatch on": client.put(f"/api/assurance/deployments/{dep.uuid}/dispatch-policy/", {"enabled": True}, format="json"),
        "engagement running": client.patch(f"/api/pentest/engagements/{engagement.pk}/", {"status": "running"}, format="json"),
        "engagement deleted": client.delete(f"/api/pentest/engagements/{running.pk}/"),
        "promotion": client.patch(f"/api/accounts/users/{viewer.pk}/set_role/", {"role": "admin"}, format="json"),
        "audit read": client.get("/api/failsafe/audit/"),
        "user list": client.get("/api/accounts/users/"),
        "deployment read": client.get(f"/api/assurance/deployments/{dep.uuid}/"),
        "scan launched": client.post("/api/pentest/scan/", {"url": "https://x.test"}, format="json"),
    }
    assert {name: r.status_code for name, r in refused.items()} == {name: 401 for name in refused}
    assert all(r["WWW-Authenticate"].startswith("Bearer") for r in refused.values())
    viewer.refresh_from_db(), engagement.refresh_from_db()
    assert viewer.role == "viewer" and engagement.status == "paused"
    assert Engagement.objects.filter(pk=running.pk).exists()
    assert FailsafeCommand.objects.get(pk=stand_down.pk).status == "awaiting_signatures"
    assert FailsafeCommand.objects.get(pk=ready.pk).status == "ready"
    assert _poll(engine_id="athena-1").data[0]["nonce"] == ready.nonce
    pause = client.post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json")
    assert pause.status_code == 200
    # Cancelling a resume keeps the engine stopped: that one the token may do.
    assert client.post(f"/api/failsafe/commands/{resume.uuid}/cancel/", {}, format="json").status_code == 200


@pytest.mark.django_db
def test_a_cancel_of_a_stop_needs_its_initiator_or_an_admin_and_goes_through_the_gateway(rates, configure, monkeypatch):
    """H2: cancelling a pause, stand-down or terminate withdraws a stop, so it
    is judged like any other request that is not one: authenticated by an
    operator's own session, allowed only to the command's initiator or an
    admin, and asked about at the gateway, whose block refuses it."""
    from failsafe.models import FailsafeCommand

    initiator, colleague, admin_ = _user("analyst"), _user("analyst"), _admin()
    commands_ = [_command("stand_down", initiator=initiator) for _ in range(3)]
    assert _client_for(colleague).post(f"/api/failsafe/commands/{commands_[0].uuid}/cancel/", {}, format="json").status_code == 403
    assert _client_for(initiator).post(f"/api/failsafe/commands/{commands_[0].uuid}/cancel/", {}, format="json").status_code == 200
    assert _client_for(admin_).post(f"/api/failsafe/commands/{commands_[1].uuid}/cancel/", {}, format="json").status_code == 200
    configure(DEFENDER_MONITOR_ONLY=False)
    post = _engine_answers({"allow": False, "action": "block", "reason": "x"})
    monkeypatch.setattr("audit.middleware.requests.post", post)
    blocked = _client_for(admin_).post(f"/api/failsafe/commands/{commands_[2].uuid}/cancel/", {}, format="json")
    assert blocked.status_code == 403 and post.call_count == 1
    assert FailsafeCommand.objects.get(pk=commands_[2].pk).status == "awaiting_signatures"
    # Past the rate it is refused as well: it spends the caller's budget.
    rates(user="2/min")
    client = _client_for(initiator)
    configure(DEFENDER_MONITOR_ONLY=True)
    cache.clear()
    others = [_command("pause", initiator=initiator) for _ in range(3)]
    codes = [client.post(f"/api/failsafe/commands/{c.uuid}/cancel/", {}, format="json").status_code for c in others]
    assert codes == [200, 200, 429]


@pytest.mark.django_db
def test_a_service_account_that_cannot_be_read_is_a_503_not_a_401(rates, service, monkeypatch):
    """L1: a failed read of the service account answered the stop 401, and the
    dashboard answers a 401 by signing in again with a password -- the path the
    token exists to avoid. Now: 503, the reason, and Retry-After."""
    from django.db import OperationalError
    from django.db.models.query import QuerySet

    real_first = QuerySet.first

    def locked(self):
        if self.model is User and service.username in str(self.query):
            raise OperationalError("database is locked")
        return real_first(self)

    monkeypatch.setattr(QuerySet, "first", locked)
    dep = _deployment()
    answer = _service_client().post(f"/api/assurance/deployments/{dep.uuid}/recompute/", {"paused": True}, format="json")
    assert answer.status_code == 503
    assert "OperationalError: database is locked" in answer.data["detail"]
    assert answer["Retry-After"] == "1"


@pytest.mark.django_db
def test_the_service_token_reads_only_the_stop_commands_in_flight(rates, service):
    """L4: the token read the whole command history: resume and release
    commands with their signing bytes, reasons, signatures and initiators. It
    now reads what stopping needs: the pause, stand-down and terminate commands
    in flight, their signing bytes, and the engine's live state."""
    operator = _admin()
    awaiting_stop = _command("stand_down", "athena-7", initiator=operator)
    ready_stop = _command("pause", "athena-7", initiator=operator, status="ready", signed=True)
    history = [_command("terminate", "athena-7", initiator=operator, status=state) for state in ("consumed", "canceled", "expired")]
    starts = [_command(action, "athena-7", initiator=operator, status=state)
              for action in ("resume", "release") for state in ("awaiting_signatures", "ready", "consumed")]
    client = _service_client()
    listed = {row["uuid"] for row in client.get("/api/failsafe/commands/?engine_id=athena-7").data}
    assert listed == {str(awaiting_stop.uuid), str(ready_stop.uuid)}
    state = client.get("/api/failsafe/state/?engine_id=athena-7").data
    assert {row["uuid"] for row in state["awaiting_signatures"]} == {str(awaiting_stop.uuid)}
    assert {row["uuid"] for row in state["ready"]} == {str(ready_stop.uuid)}
    assert state["recent"] == [] and state["engine_state"] == "running"
    for command in (awaiting_stop, ready_stop):
        detail = client.get(f"/api/failsafe/commands/{command.uuid}/")
        assert detail.status_code == 200 and detail.data["signing_bytes"]
    for command in (*history, *starts):
        assert client.get(f"/api/failsafe/commands/{command.uuid}/").status_code == 404
    # An operator's own session reads everything, as before.
    reader = _client_for(operator)
    everything = {row["uuid"] for row in reader.get("/api/failsafe/commands/?engine_id=athena-7").data}
    assert everything == {str(c.uuid) for c in (awaiting_stop, ready_stop, *history, *starts)}
    assert reader.get(f"/api/failsafe/commands/{starts[0].uuid}/").status_code == 200


@pytest.mark.django_db
def test_a_token_that_does_not_match_takes_the_normal_path(rates, service):
    """Invalid, short, or for an account that is not there: the header is
    ignored. The request is judged and authenticated as if it were absent --
    a pause with no other credential is 401, and with a JWT it is served."""
    dep = _deployment()
    path = f"/api/assurance/deployments/{dep.uuid}/recompute/"
    assert _service_client("a-guess").post(path, {"paused": True}, format="json").status_code == 401
    assert _service_client(SERVICE_TOKEN + "x").post(path, {"paused": True}, format="json").status_code == 401
    operator = _admin()
    with_jwt = _bearer_client(operator)
    with_jwt.credentials(
        HTTP_AUTHORIZATION=with_jwt._credentials["HTTP_AUTHORIZATION"], HTTP_X_FAILSAFE_SERVICE_TOKEN="a-guess"
    )
    assert with_jwt.post(path, {"paused": True}, format="json").status_code == 200
    short = "s" * 31
    with override_settings(FAILSAFE_SERVICE_TOKEN=short):
        assert _service_client(short).post(path, {"paused": True}, format="json").status_code == 401
    with override_settings(FAILSAFE_SERVICE_USER="no-such-account"):
        assert _service_client().post(path, {"paused": True}, format="json").status_code == 401
    with override_settings(FAILSAFE_SERVICE_USER=None):
        assert _service_client().post(path, {"paused": True}, format="json").status_code == 401
    User.objects.filter(pk=service.pk).update(is_active=False)
    assert _service_client().post(path, {"paused": True}, format="json").status_code == 401


@pytest.mark.django_db
def test_the_service_token_is_checked_cheaply(service, monkeypatch):
    """Compared as two HMAC-SHA256 digests of one length in constant time; no
    database read unless it matches, and then one: the account by its unique
    username."""
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    from safety import service_token

    seen = []
    real = service_token.hmac.compare_digest

    def spy(a, b):
        seen.append((len(a), len(b)))
        return real(a, b)

    monkeypatch.setattr(service_token.hmac, "compare_digest", spy)
    pause = json.dumps({"paused": True}).encode()
    for guess, expected in (("x", False), ("x" * 5000, False), (SERVICE_TOKEN, True)):
        request = _raw("POST", RECOMPUTE, pause, HTTP_X_FAILSAFE_SERVICE_TOKEN=guess)
        with CaptureQueriesContext(connection) as queries:
            assert service_token.accepted(request) is expected
            auth = service_token.FailsafeServiceTokenAuthentication().authenticate(request)
        assert (auth is not None) is expected
        assert len(queries) == (1 if expected else 0), [q["sql"] for q in queries]
        if expected:
            assert auth[0] == service
    # Asked once to judge and once to authenticate; each time two digests of one length.
    assert seen == [(32, 32)] * 6
    # Not a stop, or not a service route: not even compared.
    seen.clear()
    for request in (
        _raw("POST", RECOMPUTE, json.dumps({"paused": False}).encode(), HTTP_X_FAILSAFE_SERVICE_TOKEN=SERVICE_TOKEN),
        RequestFactory().get("/api/failsafe/audit/", HTTP_X_FAILSAFE_SERVICE_TOKEN=SERVICE_TOKEN),
        RequestFactory().get("/api/failsafe/pending/", HTTP_X_FAILSAFE_SERVICE_TOKEN=SERVICE_TOKEN),
    ):
        assert service_token.accepted(request) is False
    assert seen == []


def test_every_service_route_authenticates_by_the_service_token_first():
    from safety import service_token

    assert service_token.SERVICE_ROUTES == set(EXPECTED_STOPS) - {
        "failsafe:pending", "accounts:user-set-role", "accounts:user-detail"
    }
    served = walk()
    for name in service_token.SERVICE_ROUTES:
        for callback in served[name]["callbacks"]:
            classes = callback.initkwargs.get("authentication_classes", callback.cls.authentication_classes)
            assert classes and classes[0] is service_token.FailsafeServiceTokenAuthentication, name


# --- Password sign-in: its own failures only, however the name is spelled -------


def _sign_in(username, password, address="10.0.0.1"):
    return APIClient().post("/api/token/", {"username": username, "password": password}, format="json", REMOTE_ADDR=address)


@pytest.mark.django_db
def test_no_flood_from_the_operators_address_stops_them_signing_in_or_refreshing(rates):
    """Round 1 (and master): 30 wrong-token polls from the operator's address,
    then the right password was 429 with Retry-After 60, and so was a valid
    refresh. Polls never count against sign-in, and failed sign-ins for other
    names count only toward the address's cap of 60 a minute."""
    from rest_framework_simplejwt.tokens import RefreshToken

    operator = User.objects.create_user(username="operator321", password="right-password", role="admin")
    refresh = str(RefreshToken.for_user(operator))
    polls = [_poll(token="wrong", REMOTE_ADDR="10.0.0.1").status_code for _ in range(30)]
    guesses = [_sign_in(f"someone-{i}", "guess").status_code for i in range(15)] + [
        _sign_in("someone-else", "guess").status_code for _ in range(15)
    ]
    assert set(polls) == {401} and set(guesses) <= {401, 429}
    assert _sign_in("operator321", "right-password").status_code == 200
    answer = APIClient().post("/api/token/refresh/", {"refresh": refresh}, format="json", REMOTE_ADDR="10.0.0.1")
    assert answer.status_code == 200
    assert _poll(REMOTE_ADDR="10.0.0.1").status_code == 200


@pytest.mark.django_db
def test_failed_sign_ins_lock_that_username_from_that_address_only(rates):
    User.objects.create_user(username="op321", password="right-password", role="admin")
    User.objects.create_user(username="other321", password="right-password", role="admin")
    failures = [_sign_in("op321", "wrong").status_code for _ in range(10)]
    assert failures == [401] * 10
    locked = _sign_in("op321", "right-password")
    assert locked.status_code == 429 and int(locked["Retry-After"]) >= 1
    assert _sign_in("op321", "right-password", address="10.0.0.2").status_code == 200
    assert _sign_in("other321", "right-password").status_code == 200


#: Spellings SimpleJWT trims to "op325" before it authenticates.
PADDED = [" op325", "op325\t", "  op325\t", " op325", "op325　", " op325 ", "\nop325 "]


@pytest.mark.parametrize("name", [*PADDED, "OP325", "ｏｐ325", 325])
def test_the_budget_is_named_by_the_username_authentication_looks_up(name):
    from rest_framework.request import Request
    from rest_framework.parsers import JSONParser
    from rest_framework_simplejwt.serializers import TokenObtainPairSerializer

    from safety.sign_in import normalised_username

    request = Request(_json("POST", "/api/token/", {"username": name, "password": "x"}), parsers=[JSONParser()])
    expected = "325" if name == 325 else "op325"
    assert normalised_username(TokenObtainPairSerializer, request) == expected


@pytest.mark.django_db
def test_padded_spellings_of_one_username_share_its_budget(rates, monkeypatch):
    """H2: round 2 keyed the budget on the name as sent, and SimpleJWT trims it
    before authenticating: 207 wrong guesses at operator1 from one address were
    207 x 401, and '  operator1\\t' with the right password signed in as
    operator1. Every spelling that authenticates as one account is one budget."""
    from rest_framework_simplejwt import serializers as jwt_serializers
    from rest_framework_simplejwt.tokens import AccessToken

    operator = User.objects.create_user(username="op325", password="right-password", role="admin")
    for spelling in PADDED:
        answer = _sign_in(spelling, "right-password", address="10.0.0.9")
        assert answer.status_code == 200, spelling
        assert str(AccessToken(answer.data["access"])["user_id"]) == str(operator.pk), spelling
    checked = []
    real = jwt_serializers.authenticate
    monkeypatch.setattr(jwt_serializers, "authenticate", lambda **kw: checked.append(kw["username"]) or real(**kw))
    guesses = [_sign_in(PADDED[i % len(PADDED)], f"guess-{i}").status_code for i in range(30)]
    assert guesses == [401] * 10 + [429] * 20
    assert len(checked) == 10
    assert _sign_in("  op325\t", "right-password").status_code == 429
    assert _sign_in("OP325", "right-password").status_code == 429
    assert len(checked) == 10


@pytest.mark.django_db
def test_an_address_past_its_failures_is_refused_before_any_password_is_checked(rates, monkeypatch):
    """M4: a flood of names cost a password hash each, with no cap per address.
    Past the address's failures (60 a minute; 12 here) every attempt from it
    is 429 without a hash -- a correct password too, which is the stated
    residual. Another address is unaffected."""
    from rest_framework_simplejwt import serializers as jwt_serializers

    rates(sign_in_address="12/min")
    User.objects.create_user(username="op326", password="right-password", role="admin")
    checked = []
    real = jwt_serializers.authenticate
    monkeypatch.setattr(jwt_serializers, "authenticate", lambda **kw: checked.append(kw["username"]) or real(**kw))
    codes = [_sign_in(f"name-{i}", "guess").status_code for i in range(20)]
    assert codes == [401] * 12 + [429] * 8
    assert len(checked) == 12
    refused = _sign_in("op326", "right-password")
    assert refused.status_code == 429 and int(refused["Retry-After"]) >= 1
    assert len(checked) == 12
    assert _sign_in("op326", "right-password", address="10.0.0.2").status_code == 200


@pytest.mark.django_db
def test_a_successful_sign_in_clears_only_its_own_count(rates):
    rates(sign_in="5/min", sign_in_address="100/min")
    User.objects.create_user(username="op327", password="right-password", role="admin")
    User.objects.create_user(username="op328", password="right-password", role="admin")
    assert [_sign_in("op327", "wrong").status_code for _ in range(4)] == [401] * 4
    assert [_sign_in("op328", "wrong").status_code for _ in range(4)] == [401] * 4
    assert _sign_in("op327", "right-password").status_code == 200
    assert [_sign_in("op327", "wrong").status_code for _ in range(4)] == [401] * 4
    assert [_sign_in("op328", "wrong").status_code for _ in range(2)] == [401, 429]


@pytest.mark.django_db
def test_the_address_count_is_not_cleared_by_a_success(rates):
    rates(sign_in="100/min", sign_in_address="6/min")
    User.objects.create_user(username="op329", password="right-password", role="admin")
    assert [_sign_in(f"n-{i}", "wrong").status_code for i in range(5)] == [401] * 5
    assert _sign_in("op329", "right-password").status_code == 200
    assert [_sign_in(f"m-{i}", "wrong").status_code for i in range(2)] == [401, 429]


def _burst(names, monkeypatch, size):
    """``size`` sign-ins in flight at once, as a burst is: each attempt that
    reaches a password hash starts every attempt not yet started before its
    own hash finishes. Returns (answers, attempts that reached a hash)."""
    from rest_framework_simplejwt import serializers as jwt_serializers

    started, answers, hashed = [0], [], []
    real = jwt_serializers.authenticate

    def attempt():
        started[0] += 1
        answers.append(_sign_in(names(started[0]), f"guess-{started[0]}").status_code)

    def authenticate(**kwargs):
        hashed.append(kwargs["username"])
        while started[0] < size:
            attempt()
        return real(**kwargs)

    monkeypatch.setattr(jwt_serializers, "authenticate", authenticate)
    while started[0] < size:
        attempt()
    return answers, hashed


@pytest.mark.django_db
def test_a_burst_of_guesses_is_counted_before_any_password_is_hashed(rates, monkeypatch):
    """M4: round 3 checked the count before the hash and added to it after, so
    every attempt of a burst passed the check before any was counted: 40
    simultaneous guesses at one account were 40 hashes against a limit of 10,
    and 80 names from one address 80 hashes against 60. Each attempt is
    counted before its hash now."""
    User.objects.create_user(username="op330", password="right-password", role="admin")
    answers, hashed = _burst(lambda k: "op330", monkeypatch, 40)
    assert len(hashed) == 10
    assert sorted(answers) == [401] * 10 + [429] * 30
    assert _sign_in("op330", "right-password").status_code == 429


@pytest.mark.django_db
def test_a_burst_of_names_from_one_address_is_counted_before_any_password_is_hashed(rates, monkeypatch):
    """The same for the address's limit (60 a minute; 12 here, so the burst
    nests no deeper than a test can)."""
    rates(sign_in_address="12/min")
    answers, hashed = _burst(lambda k: f"nobody-{k}", monkeypatch, 30)
    assert len(hashed) == 12
    assert sorted(answers) == [401] * 12 + [429] * 18


@pytest.mark.django_db
def test_the_count_is_kept_where_every_worker_reads_it(rates, configure):
    """Round 3 kept the count in the per-process cache, so each worker had
    limits of its own. It is in the database now: a worker with an empty
    cache of its own still refuses the eleventh guess, and the one row per
    window is incremented in place."""
    from safety.models import SignInCount

    User.objects.create_user(username="op331", password="right-password", role="admin")
    assert [_sign_in("op331", "wrong").status_code for _ in range(10)] == [401] * 10
    cache.clear()
    assert _sign_in("op331", "wrong").status_code == 429
    per_key = {}
    for key, count in SignInCount.objects.values_list("key", "count"):
        per_key[key] = per_key.get(key, 0) + count
    assert sorted(per_key.values()) == [10, 10]
    assert SignInCount._meta.get_field("count").get_internal_type() == "PositiveIntegerField"
    assert any(c.fields == ("key", "window") for c in SignInCount._meta.constraints)


@pytest.mark.django_db
def test_an_attempt_that_cannot_be_counted_is_refused_unhashed(rates, monkeypatch):
    """No password is hashed uncounted: a count that cannot be written is 503."""
    from rest_framework_simplejwt import serializers as jwt_serializers

    from safety.models import SignInCount

    User.objects.create_user(username="op332", password="right-password", role="admin")
    hashed = []
    real = jwt_serializers.authenticate
    monkeypatch.setattr(jwt_serializers, "authenticate", lambda **kw: hashed.append(1) or real(**kw))

    def broken(*args, **kwargs):
        raise RuntimeError("the database is gone")

    monkeypatch.setattr(SignInCount.objects, "bulk_create", broken)
    answer = _sign_in("op332", "right-password")
    assert answer.status_code == 503 and answer["Retry-After"] == "1"
    assert hashed == []


def test_the_deployment_check_warns_when_the_count_is_per_process(monkeypatch):
    """`check --deploy` names a sign-in count that each worker would have its
    own of: an in-memory SQLite database."""
    from django.core.checks import registry
    from django.db import connections

    from safety import checks

    assert checks.sign_in_limits_are_shared in registry.registry.get_checks(include_deployment_checks=True)
    assert checks.sign_in_limits_are_shared(None) == []
    for name in (":memory:", "file::memory:?cache=shared", "file:x?mode=memory"):
        assert checks.per_process_database({"ENGINE": "django.db.backends.sqlite3", "NAME": name})
    assert not checks.per_process_database({"ENGINE": "django.db.backends.sqlite3", "NAME": "/var/db/athena.sqlite3"})
    assert not checks.per_process_database({"ENGINE": "django.db.backends.postgresql", "NAME": "athena"})
    monkeypatch.setitem(connections["default"].settings_dict, "NAME", ":memory:")
    assert [w.id for w in checks.sign_in_limits_are_shared(None)] == ["safety.W001"]


@pytest.mark.django_db(transaction=True)
def test_simultaneous_sign_ins_on_threads_are_limited(rates, monkeypatch):
    """M4, as it happens: threads sending sign-ins at the same moment, each with
    its own database connection, as workers do. At most the limit are hashed."""
    from rest_framework_simplejwt import serializers as jwt_serializers

    rates(sign_in="5/min", sign_in_address="12/min")
    name = f"op333-{uuid.uuid4().hex[:6]}"
    User.objects.create_user(username=name, password="right-password", role="admin")
    hashed = []
    real = jwt_serializers.authenticate
    monkeypatch.setattr(jwt_serializers, "authenticate", lambda **kw: hashed.append(kw["username"]) or real(**kw))

    def burst(names, address):
        barrier = threading.Barrier(len(names))
        answers = [None] * len(names)

        def one(k):
            from django.db import connection

            try:
                barrier.wait()
                answers[k] = _sign_in(names[k], "guess", address=address).status_code
            finally:
                connection.close()

        threads = [threading.Thread(target=one, args=(k,)) for k in range(len(names))]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(120)
        return answers

    answers = burst([name] * 16, "10.0.3.1")
    assert len(hashed) <= 5 and answers.count(401) == len(hashed) and set(answers) <= {401, 429}
    hashed.clear()
    answers = burst([f"nobody-{k}" for k in range(24)], "10.0.3.2")
    assert len(hashed) <= 12 and answers.count(401) == len(hashed) and set(answers) <= {401, 429}


# --- The refresh: exempt only while its token is unspent (L2) -------------------


@pytest.mark.django_db
def test_a_valid_refresh_is_never_throttled_and_an_invalid_one_is(rates):
    from rest_framework_simplejwt.tokens import RefreshToken

    operator = User.objects.create_user(username="op323", password="x", role="admin")
    refresh = str(RefreshToken.for_user(operator))
    codes = []
    for _ in range(40):
        answer = APIClient().post("/api/token/refresh/", {"refresh": refresh}, format="json")
        codes.append(answer.status_code)
        refresh = answer.data["refresh"]
    assert codes == [200] * 40
    bad = [APIClient().post("/api/token/refresh/", {"refresh": "x.y.z"}, format="json").status_code for _ in range(31)]
    assert bad == [401] * 30 + [429]


@pytest.mark.django_db
def test_a_spent_refresh_token_no_longer_verifies_and_is_not_exempt(rates, configure, monkeypatch):
    """L2: token_blacklist was not installed, so ROTATE_REFRESH_TOKENS and
    BLACKLIST_AFTER_ROTATION did nothing: one viewer's refresh token was
    refreshed 200 times in 1.4 s, all 200, all past the gateway. Now a refresh
    spends its token; a spent one is judged like any other bad token."""
    from rest_framework_simplejwt.tokens import RefreshToken

    viewer = _user("viewer")
    first = str(RefreshToken.for_user(viewer))
    answer = APIClient().post("/api/token/refresh/", {"refresh": first}, format="json")
    assert answer.status_code == 200
    second = answer.data["refresh"]
    assert APIClient().post("/api/token/refresh/", {"refresh": first}, format="json").status_code == 401
    assert not stops.is_stop(_json("POST", "/api/token/refresh/", {"refresh": first}))
    assert stops.is_stop(_json("POST", "/api/token/refresh/", {"refresh": second}))

    configure(DEFENDER_MONITOR_ONLY=False)
    post = _engine_answers({"allow": False, "action": "block", "reason": "x"})
    monkeypatch.setattr("audit.middleware.requests.post", post)
    assert APIClient().post("/api/token/refresh/", {"refresh": first}, format="json").status_code == 403
    assert post.call_count == 1
    assert APIClient().post("/api/token/refresh/", {"refresh": second}, format="json").status_code == 200
    assert post.call_count == 1


@pytest.mark.django_db
def test_judging_a_refresh_is_one_indexed_read():
    """The account (by its primary key) and the blacklist (by the token's
    unique jti) in one statement."""
    from django.db import connection
    from django.test.utils import CaptureQueriesContext
    from rest_framework_simplejwt.token_blacklist.models import OutstandingToken
    from rest_framework_simplejwt.tokens import RefreshToken

    token = str(RefreshToken.for_user(_user("viewer")))
    with CaptureQueriesContext(connection) as queries:
        assert stops.is_stop(_json("POST", "/api/token/refresh/", {"refresh": token}))
    assert len(queries) == 1
    sql = queries[0]["sql"]
    assert "token_blacklist" in sql and "jti" in sql and User._meta.db_table in sql and "is_active" in sql
    assert OutstandingToken._meta.get_field("jti").unique


@pytest.mark.django_db
def test_a_removed_or_deactivated_operators_refresh_is_not_exempt_and_is_a_401(rates, configure, monkeypatch):
    """L3: the exemption checked the token but not its account. A removed
    operator's token rode it and was answered 500 (DoesNotExist, a traceback
    each time); a deactivated one's 401 -- both past the gateway and every
    throttle. Now neither is exempt, and both are 401."""
    from rest_framework_simplejwt.tokens import RefreshToken

    gone, off = _user("analyst"), _user("analyst")
    gone_token, off_token = str(RefreshToken.for_user(gone)), str(RefreshToken.for_user(off))
    gone.delete()
    User.objects.filter(pk=off.pk).update(is_active=False)
    for token in (gone_token, off_token):
        assert not stops.is_stop(_json("POST", "/api/token/refresh/", {"refresh": token}))
        answer = APIClient().post("/api/token/refresh/", {"refresh": token}, format="json")
        assert answer.status_code == 401, answer.content
    configure(DEFENDER_MONITOR_ONLY=False)
    post = _engine_answers({"allow": False, "action": "block", "reason": "x"})
    monkeypatch.setattr("audit.middleware.requests.post", post)
    for token in (gone_token, off_token):
        assert APIClient().post("/api/token/refresh/", {"refresh": token}, format="json").status_code == 403
    assert post.call_count == 2


@pytest.mark.django_db
def test_a_refresh_token_is_spent_once_even_when_its_check_is_raced(rates, monkeypatch):
    """M1: SimpleJWT reads the blacklist and then writes to it, so two
    refreshes that overlap both passed the read and both got a new token --
    8 at once forked into 8 live chains. The read is made to pass here for
    both, as it does in a race: the spend itself (a unique insert) still lets
    only the first through, and the second is 401 "refresh token already used"
    and is issued nothing."""
    from django.db.models.query import QuerySet
    from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken
    from rest_framework_simplejwt.tokens import RefreshToken

    operator = _user("analyst")
    token = str(RefreshToken.for_user(operator))
    real_exists = QuerySet.exists

    def blind(self):
        # Every read of the blacklist says "not spent", as it does for two
        # refreshes that both read it before either writes.
        return False if self.model is BlacklistedToken else real_exists(self)

    monkeypatch.setattr(QuerySet, "exists", blind)
    first = APIClient().post("/api/token/refresh/", {"refresh": token}, format="json")
    second = APIClient().post("/api/token/refresh/", {"refresh": token}, format="json")
    assert first.status_code == 200 and "refresh" in first.data
    assert second.status_code == 401
    assert second.data["detail"] == "refresh token already used" and "access" not in second.data
    # The one chain goes on.
    assert APIClient().post("/api/token/refresh/", {"refresh": first.data["refresh"]}, format="json").status_code == 200


@pytest.mark.django_db(transaction=True)
def test_eight_refreshes_of_one_token_at_once_leave_one_live_chain(rates):
    """M1, as it happens: eight threads refresh one token at the same moment.
    Exactly one gets a new token; the other seven are 401 "refresh token
    already used"; and the one new token refreshes."""
    from rest_framework_simplejwt.tokens import RefreshToken

    operator = User.objects.create_user(username=f"tabs-{uuid.uuid4().hex[:8]}", password="x", role="analyst")
    token = str(RefreshToken.for_user(operator))
    barrier = threading.Barrier(8)
    answers = [None] * 8

    def refresh(k):
        from django.db import connection

        try:
            barrier.wait()
            answers[k] = APIClient().post("/api/token/refresh/", {"refresh": token}, format="json")
        finally:
            connection.close()

    threads = [threading.Thread(target=refresh, args=(k,)) for k in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    codes = sorted(answer.status_code for answer in answers)
    assert codes == [200] + [401] * 7, codes
    assert all(a.data["detail"] == "refresh token already used" for a in answers if a.status_code == 401)
    new = next(a.data["refresh"] for a in answers if a.status_code == 200)
    assert APIClient().post("/api/token/refresh/", {"refresh": new}, format="json").status_code == 200


@pytest.mark.django_db
def test_enforce_mode_never_refuses_a_valid_refresh(rates, configure, monkeypatch):
    from rest_framework_simplejwt.tokens import RefreshToken

    configure(DEFENDER_MONITOR_ONLY=False)
    post = _engine_answers({"allow": False, "action": "block", "reason": "x"})
    monkeypatch.setattr("audit.middleware.requests.post", post)
    operator = User.objects.create_user(username="op324", password="x", role="admin")
    answer = APIClient().post("/api/token/refresh/", {"refresh": str(RefreshToken.for_user(operator))}, format="json")
    assert answer.status_code == 200
    post.assert_not_called()
    assert APIClient().post("/api/token/refresh/", {"refresh": "x.y.z"}, format="json").status_code == 403


# --- The stop lane: no draft refused, none hidden, every read bounded (H1, M2) --


def _draft(client, action="pause", engine_id="eng-1", reason=""):
    return client.post(
        "/api/failsafe/commands/", {"action": action, "engine_id": engine_id, "reason": reason}, format="json"
    )


@pytest.mark.django_db
def test_no_stop_draft_is_ever_refused(rates, service):
    """H1: round 3 capped the stop commands one account had awaiting
    signatures at 20. One admin pausing a fleet of 25 engines (draft first,
    sign after, as the CLI does) got 429 from the 21st, and a terminate after
    them 429; 20 junk drafts through the dashboard's one service account got
    the dashboard's real stand-down 429. A stop draft is never refused now."""
    fleet = _client_for(_admin())
    assert [_draft(fleet, "pause", f"eng-{i:02d}").status_code for i in range(25)] == [201] * 25
    assert _draft(fleet, "terminate", "eng-24").status_code == 201
    token = _service_client()
    assert [_draft(token, "pause", f"junk-{i}").status_code for i in range(20)] == [201] * 20
    assert _draft(token, "stand_down", "athena-1").status_code == 201
    assert [_draft(token, "pause", f"more-junk-{i}").status_code for i in range(40)] == [201] * 40
    assert _draft(token, "terminate", "athena-1").status_code == 201


@pytest.mark.django_db
def test_a_stop_draft_made_again_while_unsigned_returns_the_same_draft(rates, operator_key):
    """Idempotent, not refused: the same account's draft of the same action
    for the same engine, while it is unsigned and has at least half its window
    left, is answered 200 with that draft -- the same bytes, so a signature
    already made out of band still counts. Signed, cancelled, expired or past
    half its window, the next one is a new draft."""
    from failsafe.models import FailsafeCommand

    analyst = _user("analyst")
    client = _client_for(analyst)
    first = _draft(client, "pause", "athena-9")
    again = [_draft(client, "pause", "athena-9") for _ in range(30)]
    assert first.status_code == 201 and {a.status_code for a in again} == {200}
    assert {a.data["uuid"] for a in again} == {first.data["uuid"]}
    assert {a.data["signing_bytes"] for a in again} == {first.data["signing_bytes"]}
    assert FailsafeCommand.objects.filter(engine_id="athena-9").count() == 1
    # Another action, engine or account is a draft of its own.
    assert _draft(client, "stand_down", "athena-9").status_code == 201
    assert _draft(client, "pause", "athena-10").status_code == 201
    assert _draft(_client_for(_user("analyst")), "pause", "athena-9").status_code == 201
    # Signed: a stand-down with its first signature is awaiting its second.
    stand_down = FailsafeCommand.objects.get(engine_id="athena-9", action="stand_down")
    sig = operator_key.sign(bytes.fromhex(_draft(client, "stand_down", "athena-9").data["signing_bytes"])).hex()
    signed = client.post(f"/api/failsafe/commands/{stand_down.uuid}/signatures/", {"key_id": "alice", "sig": sig}, format="json")
    assert signed.status_code == 200 and signed.data["status"] == "awaiting_signatures"
    assert _draft(client, "stand_down", "athena-9").status_code == 201
    # Cancelled, expired, or with less than half its window left.
    pause = FailsafeCommand.objects.get(uuid=first.data["uuid"])
    assert client.post(f"/api/failsafe/commands/{pause.uuid}/cancel/", {}, format="json").status_code == 200
    renewed = _draft(client, "pause", "athena-9")
    assert renewed.status_code == 201
    FailsafeCommand.objects.filter(uuid=renewed.data["uuid"]).update(expires_at="2000-01-01T00:00:00+00:00")
    renewed = _draft(client, "pause", "athena-9")
    assert renewed.status_code == 201
    late = (timezone.now() + timedelta(seconds=200)).isoformat()
    FailsafeCommand.objects.filter(uuid=renewed.data["uuid"]).update(expires_at=late)
    assert _draft(client, "pause", "athena-9").status_code == 201
    # Resume and release are not stops: each draft is a new one, and the rate limits them.
    assert [_draft(client, "resume", "athena-9").status_code for _ in range(2)] == [201, 201]


@pytest.mark.django_db
def test_a_draft_whose_earlier_one_cannot_be_read_is_made_afresh(rates, monkeypatch):
    """The read for an identical draft fails: the draft is made anyway."""
    from failsafe.models import FailsafeCommand

    client = _client_for(_user("analyst"))
    assert _draft(client).status_code == 201
    real = FailsafeCommand.objects.filter

    def failing(*args, **kwargs):
        if "initiator" in kwargs:
            raise RuntimeError("the database is gone")
        return real(*args, **kwargs)

    monkeypatch.setattr(FailsafeCommand.objects, "filter", failing)
    assert [_draft(client).status_code for _ in range(3)] == [201] * 3


@pytest.mark.django_db
def test_a_flood_of_drafts_cannot_hide_a_stop_awaiting_a_signature(rates, operator_key, configure):
    """Round 2's L1 without round 3's cap: one analyst drafts 60 pauses of one
    engine and 60 more of sixty engines, after one admin's stand-down has its
    first signature and another admin's is unsigned; and there are many newer
    commands that are not stops awaiting a signature. No draft is refused; the
    60 of one engine are one row; the signed stand-down is listed first and the
    unsigned one within the first three -- in the list with each filter and in
    state, with the engine and without -- and the signed one is signed again,
    to ready."""
    from failsafe.models import FailsafeCommand
    from failsafe.views import COMMAND_LIST_LIMIT

    bob = Ed25519PrivateKey.generate()
    configure(FAILSAFE_OPERATOR_KEYS={
        "alice": operator_key.public_key().public_bytes_raw().hex(),
        "bob": bob.public_key().public_bytes_raw().hex(),
    })
    first_admin = _client_for(_admin())
    signed = _draft(first_admin, "stand_down").data
    sign = {"key_id": "alice", "sig": operator_key.sign(bytes.fromhex(signed["signing_bytes"])).hex()}
    assert first_admin.post(f"/api/failsafe/commands/{signed['uuid']}/signatures/", sign, format="json").status_code == 200
    unsigned = _draft(_client_for(_admin()), "stand_down").data
    analyst = _client_for(_user("analyst"))
    assert [_draft(analyst).status_code for _ in range(60)] == [201] + [200] * 59
    assert [_draft(analyst, "pause", f"eng-{i}").status_code for i in range(100, 160)] == [201] * 60
    assert FailsafeCommand.objects.filter(engine_id="eng-1", action="pause").count() == 1
    FailsafeCommand.objects.bulk_create(
        [
            FailsafeCommand(engine_id="eng-1", action=action, nonce=f"n-{uuid.uuid4()}", issued_at="t",
                            expires_at="2999-01-01T00:00:00+00:00", status=state)
            for action, state in [("resume", "awaiting_signatures"), ("pause", "consumed")] * (COMMAND_LIST_LIMIT + 5)
        ]
    )
    reader = _client_for(_admin())
    reads = {query: reader.get(f"/api/failsafe/commands/{query}").data
             for query in ("?engine_id=eng-1&status=awaiting_signatures", "?engine_id=eng-1", "")}
    reads.update({f"state{query}": reader.get(f"/api/failsafe/state/{query}").data["awaiting_signatures"]
                  for query in ("?engine_id=eng-1", "")})
    for label, rows in reads.items():
        order = [row["uuid"] for row in rows]
        assert order[0] == signed["uuid"], label
        assert unsigned["uuid"] in order[:3], label
    sign = {"key_id": "bob", "sig": bob.sign(bytes.fromhex(signed["signing_bytes"])).hex()}
    ready = reader.post(f"/api/failsafe/commands/{signed['uuid']}/signatures/", sign, format="json")
    assert ready.status_code == 200 and ready.data["status"] == "ready"


def _loads_and_statements(client, path, monkeypatch):
    """(rows loaded as commands, SELECTs of commands, UPDATEs of commands)
    for one read, and every SELECT of commands is by an index range with a
    LIMIT, or by primary keys."""
    from django.db import connection
    from django.test.utils import CaptureQueriesContext

    from failsafe.models import FailsafeCommand

    loaded = []
    real = FailsafeCommand.from_db.__func__
    monkeypatch.setattr(
        FailsafeCommand, "from_db", classmethod(lambda cls, db, names, values: loaded.append(1) or real(cls, db, names, values))
    )
    with CaptureQueriesContext(connection) as queries:
        answer = client.get(path)
    monkeypatch.setattr(FailsafeCommand, "from_db", classmethod(real))
    assert answer.status_code == 200
    table = FailsafeCommand._meta.db_table
    selects = [q["sql"] for q in queries if q["sql"].startswith("SELECT") and f'FROM "{table}"' in q["sql"]]
    unbounded = [sql for sql in selects if " LIMIT " not in sql and '"id" IN (' not in sql]
    assert unbounded == [], unbounded
    updates = [q["sql"] for q in queries if q["sql"].startswith("UPDATE") and table in q["sql"]]
    return len(loaded), len(selects), len(updates), answer.data


@pytest.mark.django_db
def test_a_stop_lane_read_does_bounded_work_however_many_commands_there_are(rates, monkeypatch):
    """M2: the state read expired every in-flight command of the engine (or of
    every engine) one by one: 3,000 resume drafts took a read from 0.011 s to
    0.07-0.13 s, and the first read after they expired took 3.8 s, a write per
    row. Now every list is an index read of its few newest rows and one read of
    the rows chosen: with 30 commands or 3,630, a read loads at most its row
    limits and runs the same statements; and it marks at most EXPIRE_PER_READ
    commands expired, in one write."""
    from failsafe.models import FailsafeCommand
    from failsafe.views import AWAITING_STOP_LIMIT, EXPIRE_PER_READ

    reader = _client_for(_admin())
    flooder = _user("analyst")

    def seed(resumes, pauses):
        FailsafeCommand.objects.bulk_create(
            [FailsafeCommand(engine_id="athena-1", action="resume", nonce=uuid.uuid4().hex, issued_at="t",
                             expires_at="2999-01-01T00:00:00+00:00", initiator=flooder) for _ in range(resumes)]
            + [FailsafeCommand(engine_id=f"flood-{uuid.uuid4().hex[:8]}", action="pause", nonce=uuid.uuid4().hex,
                               issued_at="t", expires_at="2999-01-01T00:00:00+00:00", initiator=flooder)
               for _ in range(pauses)],
            batch_size=500,
        )

    seed(20, 10)
    real = _command("stand_down", "athena-1", initiator=_admin())
    paths = ("/api/failsafe/state/?engine_id=athena-1", "/api/failsafe/state/", "/api/failsafe/commands/")
    small = {path: _loads_and_statements(reader, path, monkeypatch) for path in paths}
    seed(3000, 600)
    large = {path: _loads_and_statements(reader, path, monkeypatch) for path in paths}
    for path in paths:
        loaded, selects, updates, data = large[path]
        assert selects == small[path][1], path
        assert updates == 0, path
        assert loaded <= AWAITING_STOP_LIMIT + 20 + 20 + 10 + 50, (path, loaded)
    state = large["/api/failsafe/state/"][3]
    assert len(state["awaiting_signatures"]) == AWAITING_STOP_LIMIT + 20
    assert str(real.uuid) in [row["uuid"] for row in state["awaiting_signatures"][:2]]
    # Every one of them past its window: the next read marks what it came
    # across expired in one write, and shows none of them as in flight.
    FailsafeCommand.objects.update(expires_at="2000-01-01T00:00:00+00:00")
    loaded, _selects, updates, data = _loads_and_statements(reader, paths[0], monkeypatch)
    assert updates == 1 and loaded <= AWAITING_STOP_LIMIT + 20 + 20 + 10
    assert data["awaiting_signatures"] == [] and data["ready"] == []
    assert all(row["status"] == "expired" for row in data["recent"])
    first_read = FailsafeCommand.objects.filter(status="expired").count()
    assert first_read == EXPIRE_PER_READ, first_read
    # The backlog is marked a bounded few at a time, by the reads that follow.
    _loads_and_statements(reader, paths[1], monkeypatch)
    second_read = FailsafeCommand.objects.filter(status="expired").count()
    assert second_read == 2 * EXPIRE_PER_READ, second_read


def test_identical_reads_at_once_share_one_computation_never_an_older_one():
    """M2: eight threads of one analyst reading state each computed it, and a
    pause competed with all eight (0.013 s -> 0.231 s). Identical reads by one
    account now share one computation at a time: a read that arrives while one
    is running waits for it, then reuses a result only if that result's
    computation started after it arrived -- else it computes the next one. So
    no reader gets a result older than its own arrival."""
    from failsafe.views import _SharedReads

    shared = _SharedReads()
    started, release, computed = threading.Event(), threading.Event(), []

    def compute():
        computed.append(len(computed) + 1)
        n = len(computed)
        if n == 1:
            started.set()
            release.wait(5)
        return n

    answers = {}

    def reader(name):
        answers[name] = shared.read("kind", compute)

    first = threading.Thread(target=reader, args=("first",))
    first.start()
    assert started.wait(5)
    later = [threading.Thread(target=reader, args=(f"later-{i}",)) for i in range(5)]
    for thread in later:
        thread.start()
    waited = time.monotonic() + 5
    while shared._kinds["kind"]["users"] < 6 and time.monotonic() < waited:
        time.sleep(0.01)
    assert shared._kinds["kind"]["users"] == 6
    assert computed == [1]  # the five wait; none computes beside the first
    release.set()
    for thread in (first, *later):
        thread.join(5)
    # The first gets its own; the five arrived while it ran, so they share the
    # NEXT computation, which started after all of them arrived.
    assert answers == {"first": 1, **{f"later-{i}": 2 for i in range(5)}}
    assert computed == [1, 2]
    # Another kind (another account, credential or query) is never shared.
    assert shared.read("other", lambda: "other") == "other"
    assert shared._kinds == {}


def test_a_read_waits_for_an_identical_one_no_longer_than_its_bound(monkeypatch):
    from failsafe import views

    monkeypatch.setattr(views, "SHARED_READ_WAIT", 0.2)
    shared = views._SharedReads()
    started, release = threading.Event(), threading.Event()

    def slow():
        started.set()
        release.wait(5)
        return "slow"

    thread = threading.Thread(target=shared.read, args=("kind", slow))
    thread.start()
    assert started.wait(5)
    began = time.monotonic()
    assert shared.read("kind", lambda: "own") == "own"
    assert time.monotonic() - began < 0.2 + 0.2
    release.set()
    thread.join(5)


@pytest.mark.django_db
def test_the_stop_lane_reads_are_shared_per_account_credential_and_query(rates, service, monkeypatch):
    """H2 (round 4): the kind included the raw query string, so ``&n=<i>`` --
    which the view ignores -- made every read distinct and none was shared (a
    pause went from 0.05 s to 0.33 s under 8 threads of reads). The kind is the
    route, the account, the credential, and the parameters the view reads, as
    it reads them."""
    from failsafe import views

    kinds = []
    real = views._SHARED_READS.read
    monkeypatch.setattr(views._SHARED_READS, "read", lambda kind, compute: kinds.append(kind) or real(kind, compute))
    analyst = _user("analyst")
    _client_for(analyst).get("/api/failsafe/state/?engine_id=athena-1")
    _client_for(analyst).get("/api/failsafe/commands/?engine_id=athena-1")
    _service_client().get("/api/failsafe/state/?engine_id=athena-1")
    assert kinds == [
        ("state", analyst.pk, False, "athena-1", ""),
        ("commands", analyst.pk, False, "athena-1", ""),
        ("state", service.pk, True, "athena-1", ""),
    ]
    # What the view does not read is not part of the kind, in any order or
    # spelling; what it reads is, as it reads it.
    kinds.clear()
    client = _client_for(analyst)
    for path in ("/api/failsafe/state/?engine_id=athena-1&n=1", "/api/failsafe/state/?n=2&engine_id=athena-1",
                 "/api/failsafe/state/?engine_id=athena-1&status=ready", "/api/failsafe/state/?n=3",
                 "/api/failsafe/state/?engine_id=&n=4", "/api/failsafe/state/",
                 "/api/failsafe/commands/?status=ready&n=5", "/api/failsafe/commands/?n=6&status=ready",
                 "/api/failsafe/commands/?status=bogus", "/api/failsafe/commands/?status=other-bogus&n=7",
                 "/api/failsafe/commands/?engine_id=e2&status=ready"):
        assert client.get(path).status_code == 200, path
    assert kinds == [
        ("state", analyst.pk, False, "athena-1", ""),
        ("state", analyst.pk, False, "athena-1", ""),
        ("state", analyst.pk, False, "athena-1", ""),
        ("state", analyst.pk, False, "", ""),
        ("state", analyst.pk, False, "", ""),
        ("state", analyst.pk, False, "", ""),
        ("commands", analyst.pk, False, "", "ready"),
        ("commands", analyst.pk, False, "", "ready"),
        ("commands", analyst.pk, False, "", "(none)"),
        ("commands", analyst.pk, False, "", "(none)"),
        ("commands", analyst.pk, False, "e2", "ready"),
    ]


def test_reads_that_differ_only_in_what_the_view_ignores_share_one_computation(monkeypatch):
    """H2, as it happens: eight reads of every engine at once, each with a query
    parameter of its own that the view ignores, while one is computing -- the
    eight share the next computation instead of making eight."""
    from django.http import QueryDict

    from failsafe import views

    shared = views._SharedReads()
    monkeypatch.setattr(views, "_SHARED_READS", shared)
    started, release, computed = threading.Event(), threading.Event(), []

    def compute():
        computed.append(1)
        if len(computed) == 1:
            started.set()
            release.wait(5)
        return len(computed)

    def request(query):
        return types.SimpleNamespace(
            query_params=QueryDict(query), META={"QUERY_STRING": query}, user=types.SimpleNamespace(pk=7), auth=None,
        )

    answers = {}

    def reader(i):
        answers[i] = shared.read(views._read_kind(request(f"n={i}"), "state"), compute)

    first = threading.Thread(target=reader, args=(0,))
    first.start()
    assert started.wait(5)
    later = [threading.Thread(target=reader, args=(i,)) for i in range(1, 9)]
    for thread in later:
        thread.start()
    waited = time.monotonic() + 5
    while shared._kinds.get(views._read_kind(request(""), "state"), {}).get("users", 0) < 9 and time.monotonic() < waited:
        time.sleep(0.01)
    release.set()
    for thread in (first, *later):
        thread.join(5)
    assert len(computed) == 2 and answers == {0: 1, **{i: 2 for i in range(1, 9)}}


@pytest.mark.django_db
def test_a_list_read_returns_at_most_the_cap(rates):
    from failsafe.models import FailsafeCommand
    from failsafe.views import COMMAND_LIST_LIMIT

    FailsafeCommand.objects.bulk_create(
        [
            FailsafeCommand(engine_id="e", action="pause", nonce=f"n-{uuid.uuid4()}", issued_at="t", expires_at="t",
                            status="consumed")
            for _ in range(COMMAND_LIST_LIMIT + 10)
        ]
    )
    response = _client_for(_admin()).get("/api/failsafe/commands/")
    assert response.status_code == 200 and len(response.data) == COMMAND_LIST_LIMIT == 50


@pytest.mark.django_db
def test_the_state_read_waits_for_the_engine_no_longer_than_its_deadline(rates, configure, monkeypatch):
    """M1 makes the state view a stop-lane read, so it is bounded: the engine
    client allows 60 s a socket read, and the view waits for it 0.3 s here."""

    class Hung:
        def failsafe_state(self):
            time.sleep(2.0)
            return {"enabled": True, "state": "running"}

    configure(FAILSAFE_STATE_ENGINE_SECONDS=0.3)
    monkeypatch.setattr(
        "ai_engine.services.cyberengine_client.CyberEngineClient.from_settings", classmethod(lambda cls: Hung())
    )
    client = _client_for(_admin())
    started = time.monotonic()
    answer = client.get("/api/failsafe/state/?engine_id=athena-1")
    assert time.monotonic() - started < 0.3 + 0.5
    assert answer.status_code == 200
    assert answer.data["engine_state"] is None and answer.data["engine_state_available"] is False


# --- Round 5: what a stop draft costs, bounded without refusing one ------------

#: The header both stop-lane reads carry: whether the read left anything out.
MORE_HEADER = "X-Failsafe-More"


@pytest.mark.django_db
def test_a_stop_is_never_refused_for_its_reason_length(rates, operator_key):
    """F3 (round 5): the 1,000-character reason limit refused stops the
    dashboard can send -- its draftCommandSchema allows 2,000, its reason box
    has no maxLength, and it passed the backend's 400 through. A stop is judged
    a stop by safety.stops (any text up to the 64 KiB body) and must not then be
    400'd by the view. The bound now matches the dashboard (2,000); a stop
    reason within it is stored whole, a longer one is truncated and stored
    (never refused, and its signing bytes match what is stored); a non-stop past
    the bound is input validation (400)."""
    from failsafe.models import FailsafeCommand
    from failsafe.serializers import REASON_LIMIT

    assert REASON_LIMIT == 2000
    client = _client_for(_admin())
    reasons = {
        "1,001 ASCII": "r" * 1001,
        "2,000 ASCII (the dashboard's max)": "r" * 2000,
        "1,001 emoji (2,002 UTF-16 units)": "\U0001f6a8" * 1001,
        "600 Devanagari clusters (1,200 code points)": "क्" * 600,
    }
    for action in ("pause", "stand_down", "terminate"):
        for label, reason in reasons.items():
            answer = client.post(
                "/api/failsafe/commands/",
                {"action": action, "engine_id": f"e-{action}-{label[:6]}", "reason": reason},
                format="json",
            )
            assert answer.status_code == 201, (action, label, answer.status_code, answer.data)
            assert answer.data["reason"] == reason  # within the bound: stored whole
    # A stop reason past the bound is truncated and stored, never refused; the
    # signing bytes are for the stored reason, so a signature still verifies.
    huge = "z" * 5000
    stop = client.post(
        "/api/failsafe/commands/", {"action": "pause", "engine_id": "e-huge", "reason": huge}, format="json"
    )
    assert stop.status_code == 201 and stop.data["reason"] == huge[:REASON_LIMIT]
    row = FailsafeCommand.objects.get(uuid=stop.data["uuid"])
    from failsafe.signing import verify_signature

    keyring = {"alice": operator_key.public_key()}
    sig = operator_key.sign(bytes.fromhex(stop.data["signing_bytes"])).hex()
    assert verify_signature(row.as_command_dict(), "alice", sig, keyring)
    # A non-stop draft (resume/release) past the bound is 400 -- input validation.
    long_resume = client.post(
        "/api/failsafe/commands/", {"action": "resume", "engine_id": "e", "reason": "r" * 2001}, format="json"
    )
    assert long_resume.status_code == 400
    assert long_resume.data["reason"] == [f"A reason is at most {REASON_LIMIT:,} characters."]
    assert client.post(
        "/api/failsafe/commands/", {"action": "resume", "engine_id": "e-ok", "reason": "r" * 2000}, format="json"
    ).status_code == 201


@pytest.mark.django_db
def test_an_accounts_unsigned_stop_drafts_past_its_limit_supersede_its_oldest_and_only_its_own(rates, operator_key, configure):
    """H1 (round 4): one analyst drafted 1,200 pauses in 10 s to engines that do
    not exist, every one awaiting a signature. No stop draft is refused: past
    the account's limit of unsigned stop drafts, its OLDEST unsigned stop drafts
    are superseded -- recorded as such, with an audit event naming the draft
    that superseded each. Another account's drafts, and this account's draft
    that already carries a signature, are untouched. A superseded but unsigned
    stop is revived when validly signed (round 5, F2), and drafting it again
    while unsigned makes a new one."""
    from failsafe.models import FailsafeAuditEvent, FailsafeCommand

    configure(FAILSAFE_UNSIGNED_STOP_DRAFTS_PER_ACCOUNT=5)
    other = _client_for(_user("analyst"))
    theirs = _draft(other, "pause", "athena-2").data
    flooder = _user("analyst")
    client = _client_for(flooder)
    signed = _draft(client, "stand_down", "athena-3").data
    sig = {"key_id": "alice", "sig": operator_key.sign(bytes.fromhex(signed["signing_bytes"])).hex()}
    assert client.post(f"/api/failsafe/commands/{signed['uuid']}/signatures/", sig, format="json").status_code == 200
    drafts = [_draft(client, "pause", f"junk-{i}") for i in range(12)]
    assert [d.status_code for d in drafts] == [201] * 12
    mine = FailsafeCommand.objects.filter(initiator=flooder)
    awaiting = set(mine.filter(status="awaiting_signatures", signed=False).values_list("engine_id", flat=True))
    assert awaiting == {f"junk-{i}" for i in range(7, 12)}
    superseded = mine.filter(status="superseded")
    assert set(superseded.values_list("engine_id", flat=True)) == {f"junk-{i}" for i in range(7)}
    events = FailsafeAuditEvent.objects.filter(event="superseded", command__in=superseded)
    assert events.count() == 7 and all(e.detail["limit"] == 5 and e.detail["by"] for e in events)
    assert FailsafeCommand.objects.get(uuid=signed["uuid"]).status == "awaiting_signatures"
    assert FailsafeCommand.objects.get(uuid=theirs["uuid"]).status == "awaiting_signatures"
    # A superseded but unsigned stop is revived when validly signed (F2): a
    # count never makes a real pending stop unsignable. junk-0's pause needs
    # one signature, so signing it revives it straight to ready.
    old = drafts[0].data
    sig = {"key_id": "alice", "sig": operator_key.sign(bytes.fromhex(old["signing_bytes"])).hex()}
    revived = client.post(f"/api/failsafe/commands/{old['uuid']}/signatures/", sig, format="json")
    assert revived.status_code == 200 and revived.data["status"] == "ready"
    assert FailsafeCommand.objects.get(uuid=old["uuid"]).status == "ready"
    # Drafted again while unsigned, it is a new draft, never refused.
    again = _draft(client, "pause", "junk-0")
    assert again.status_code == 201 and again.data["uuid"] != old["uuid"]
    # The other account's flood never reaches this one's drafts either.
    assert [_draft(other, "pause", f"theirs-{i}").status_code for i in range(8)] == [201] * 8
    assert mine.filter(status="awaiting_signatures", signed=False).count() == 5
    assert FailsafeCommand.objects.get(engine_id="junk-11").status == "awaiting_signatures"


@pytest.mark.django_db
def test_a_stop_draft_with_another_reason_is_a_new_draft(rates, service):
    """M1 (round 4): a draft made again returned the first drafter's draft
    whatever its reason -- the service token drafted "DRILL - do not sign", and
    the dashboard's real pause a second later got that draft back, reason and
    all. The reason is in the signed bytes: only an identical one is reused."""
    from failsafe.models import FailsafeCommand

    ttl = 600
    for client in (_service_client(), _client_for(_user("analyst"))):
        drill = client.post("/api/failsafe/commands/", {"action": "pause", "engine_id": "athena-7", "reason": "DRILL - do not sign"}, format="json")
        real = client.post("/api/failsafe/commands/", {"action": "pause", "engine_id": "athena-7", "reason": "REAL: exfiltration in progress"}, format="json")
        assert (drill.status_code, real.status_code) == (201, 201)
        assert real.data["uuid"] != drill.data["uuid"] and real.data["reason"] == "REAL: exfiltration in progress"
        again = client.post("/api/failsafe/commands/", {"action": "pause", "engine_id": "athena-7", "reason": "REAL: exfiltration in progress"}, format="json")
        assert again.status_code == 200 and again.data["uuid"] == real.data["uuid"]
        assert again.data["signing_bytes"] == real.data["signing_bytes"]
        left = (timezone.datetime.fromisoformat(again.data["expires_at"]) - timezone.now()).total_seconds()
        assert left >= ttl / 2
        blank = client.post("/api/failsafe/commands/", {"action": "pause", "engine_id": "athena-7"}, format="json")
        assert blank.status_code == 201 and blank.data["reason"] == ""
        FailsafeCommand.objects.filter(engine_id="athena-7").update(status="canceled")


def _flood_of_long_reasons(count, reason_length, initiators):
    """Stop drafts with reasons as long as round 4 allowed, as rows drafted
    before the reason's limit are."""
    from failsafe.models import FailsafeCommand

    FailsafeCommand.objects.bulk_create(
        [
            FailsafeCommand(engine_id=f"long-{i}", action="pause", nonce=uuid.uuid4().hex, issued_at="t",
                            expires_at="2999-01-01T00:00:00+00:00", reason="x" * reason_length,
                            initiator=initiators[i % len(initiators)])
            for i in range(count)
        ],
        batch_size=100,
    )


@pytest.mark.django_db
def test_a_stop_lane_read_is_bounded_in_bytes_and_says_what_it_left_out(rates, configure):
    """H1 (round 4): the reads were bounded in rows, not bytes -- after 500
    drafts with 60,000-character reasons one read of every engine was 18.8 MB.
    Each read now returns at most FAILSAFE_STOP_LANE_READ_BYTES of commands,
    the stop commands awaiting a signature first (a signed one before them
    all), and says whether it left any out: X-Failsafe-More on both reads, and
    "more" in the state read."""
    limit = 64 * 1024
    configure(FAILSAFE_STOP_LANE_READ_BYTES=limit)
    reader = _client_for(_admin())
    quiet = reader.get("/api/failsafe/state/")
    assert quiet.data["more"] is False and quiet[MORE_HEADER] == "false"
    assert reader.get("/api/failsafe/commands/")[MORE_HEADER] == "false"
    signed = _command("stand_down", "athena-1", initiator=_admin(), signatures=[{"key_id": "alice", "sig": "ab"}], signed=True)
    _flood_of_long_reasons(40, 60_000, [_user("analyst"), _user("analyst")])
    for path in ("/api/failsafe/state/", "/api/failsafe/commands/", "/api/failsafe/commands/?status=awaiting_signatures"):
        answer = reader.get(path)
        assert answer.status_code == 200 and answer[MORE_HEADER] == "true", path
        assert len(answer.content) <= limit + 1024, (path, len(answer.content))
        rows = answer.data["awaiting_signatures"] if "state" in path else answer.data
        assert rows[0]["uuid"] == str(signed.uuid) and 1 < len(rows) < 41, (path, len(rows))
    assert reader.get("/api/failsafe/state/").data["more"] is True
    # The default: 600 such rows -- more than a read lists -- come to at most ~1 MB.
    configure(FAILSAFE_STOP_LANE_READ_BYTES=1_000_000)
    _flood_of_long_reasons(560, 60_000, [_user("analyst")])
    for path in ("/api/failsafe/state/", "/api/failsafe/commands/"):
        answer = reader.get(path)
        assert len(answer.content) <= 1_000_000 + 1024 and answer[MORE_HEADER] == "true", path


@pytest.mark.django_db
def test_a_read_that_lists_every_awaiting_stop_says_there_is_no_more(rates):
    """"more" is not always true: a read that left nothing out says so, and
    one cut by the row limit says it was."""
    from failsafe.views import AWAITING_STOP_LIMIT

    reader = _client_for(_admin())
    _flood_of_long_reasons(30, 10, [_user("analyst") for _ in range(3)])
    state = reader.get("/api/failsafe/state/")
    assert state.data["more"] is False and len(state.data["awaiting_signatures"]) == 30
    listed = reader.get("/api/failsafe/commands/?status=awaiting_signatures")
    assert listed[MORE_HEADER] == "false" and len(listed.data) == 30
    _flood_of_long_reasons(AWAITING_STOP_LIMIT, 10, [_user("analyst") for _ in range(3)])
    state = reader.get("/api/failsafe/state/")
    assert state.data["more"] is True and len(state.data["awaiting_signatures"]) == AWAITING_STOP_LIMIT


@pytest.mark.django_db(transaction=True)
def test_two_operators_signing_one_stand_down_at_once_both_count(rates, monkeypatch, configure):
    """M3 (round 4; on main too): the signature was read, appended to and saved
    with no lock, so two operators signing one stand-down at the same moment
    were both answered 200 and the stand-down stayed awaiting with one
    signature (6/20 on main). Here both requests reach the save together
    whenever nothing orders them; the append is to the row read again under
    the write lock, so both signatures count and the stand-down is ready."""
    from failsafe.models import FailsafeCommand

    alice, bob = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    configure(FAILSAFE_OPERATOR_KEYS={
        "alice": alice.public_key().public_bytes_raw().hex(),
        "bob": bob.public_key().public_bytes_raw().hex(),
    })
    first, second = (
        User.objects.create_user(username=f"sig-{uuid.uuid4().hex[:8]}", password="x", role="admin") for _ in range(2)
    )
    drafted = _client_for(first).post("/api/failsafe/commands/", {"action": "stand_down", "engine_id": f"sd-{uuid.uuid4().hex[:6]}"}, format="json").data
    raw = bytes.fromhex(drafted["signing_bytes"])
    together = threading.Barrier(2)
    real_save = FailsafeCommand.save

    def save(self, *args, **kwargs):
        if "signatures" in (kwargs.get("update_fields") or ()):
            try:
                together.wait(1.0)
            except threading.BrokenBarrierError:
                pass
        return real_save(self, *args, **kwargs)

    monkeypatch.setattr(FailsafeCommand, "save", save)
    answers = {}

    def sign(user, key_id, key):
        from django.db import connection

        try:
            answers[key_id] = _client_for(user).post(
                f"/api/failsafe/commands/{drafted['uuid']}/signatures/", {"key_id": key_id, "sig": key.sign(raw).hex()}, format="json"
            ).status_code
        finally:
            connection.close()

    threads = [threading.Thread(target=sign, args=args) for args in ((first, "alice", alice), (second, "bob", bob))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    command = FailsafeCommand.objects.get(uuid=drafted["uuid"])
    assert answers == {"alice": 200, "bob": 200}
    assert sorted(command.distinct_signers()) == ["alice", "bob"] and command.status == "ready"


@pytest.mark.django_db(transaction=True)
def test_identical_stop_drafts_sent_at_once_are_one_row(rates, monkeypatch):
    """L1 (round 4): identical drafts sent at once each looked for the other
    before either was written, and made up to four rows. Here both reach the
    insert together whenever nothing orders them; each then looks for an
    identical draft inserted before it, and the later one takes its own,
    unanswered row back -- one row, one 201 and one 200 with the same draft,
    and neither is refused."""
    from failsafe import views
    from failsafe.models import FailsafeCommand

    operator = User.objects.create_user(username=f"drafts-{uuid.uuid4().hex[:8]}", password="x", role="admin")
    engine_id = f"race-{uuid.uuid4().hex[:6]}"
    together = threading.Barrier(2)
    real_make = views.make_draft

    def make_draft(*args, **kwargs):
        try:
            together.wait(1.0)
        except threading.BrokenBarrierError:
            pass
        return real_make(*args, **kwargs)

    monkeypatch.setattr(views, "make_draft", make_draft)
    answers = []

    def draft():
        from django.db import connection

        try:
            answers.append(_draft(_client_for(operator), "pause", engine_id))
        finally:
            connection.close()

    threads = [threading.Thread(target=draft) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(60)
    assert sorted(a.status_code for a in answers) == [200, 201]
    assert len({a.data["uuid"] for a in answers}) == 1
    assert FailsafeCommand.objects.filter(engine_id=engine_id).count() == 1


@pytest.mark.django_db(transaction=True)
def test_a_stop_draft_holds_the_write_lock_only_across_its_dedupe(rates, configure):
    """A draft flood must not hold SQLite's write lock against a pause. A first
    fix for L1 looked up, inserted AND SUPERSEDED in one IMMEDIATE transaction;
    during a 4-thread draft flood a pause then took 2.9 s. The dedupe now runs
    in a short transaction -- the insert, one indexed look-up for an identical
    earlier draft, and the take-back if there is one -- so a taken-back row is
    never visible to a list read (round 5, F1/C4); but superseding, the reused-
    draft fast path and the audit all run OUTSIDE it, so the write lock is never
    held across the superseding (the 2.9 s cause) or anything but the dedupe."""
    from django.db import connection

    configure(FAILSAFE_UNSIGNED_STOP_DRAFTS_PER_ACCOUNT=2)
    operator = User.objects.create_user(username=f"lock-{uuid.uuid4().hex[:8]}", password="x", role="admin")
    client = _client_for(operator)
    seen = []

    def record(execute, sql, params, many, context):
        seen.append((sql.split(" ", 1)[0], connection.in_atomic_block))
        return execute(sql, params, many, context)

    with connection.execute_wrapper(record):
        codes = [_draft(client, "pause", f"lock-{i}").status_code for i in range(4)]
        codes.append(_draft(client, "pause", "lock-3").status_code)
    assert codes == [201, 201, 201, 201, 200]
    assert ("UPDATE", False) in seen  # the superseding UPDATE ran, outside any transaction
    assert ("UPDATE", True) not in seen  # never inside one -- the 2.9 s cause
    # Only the dedupe -- the command's insert, look-up and take-back -- is inside
    # a transaction; nothing else (no superseding, no audit) is.
    assert {kind for kind, in_transaction in seen if in_transaction} <= {"INSERT", "SELECT", "DELETE"}


@pytest.mark.django_db(transaction=True)
def test_every_answer_to_identical_drafts_names_a_live_row(rates):
    """F1 (round 5): the dedupe answered 200 with a uuid it had just deleted.
    Drafts X<Y<Z at once: Y found X and deleted itself; Z found Y (before Y's
    delete landed) and answered 200 with Y -- a row Y then deleted. At 8-16
    identical drafts at once, up to a third of the 200s named a row gone a
    moment later (GET and signature then 404). Every answer now names the OLDEST
    identical draft, which never takes itself back, so it stays live; and a list
    read made during the burst never shows a draft that is then taken back
    (C4), because a taken-back row is deleted in the transaction that inserted
    it and never becomes visible."""
    from failsafe.models import FailsafeCommand

    operator = User.objects.create_user(username=f"race-{uuid.uuid4().hex[:8]}", password="x", role="admin")
    for n in (8, 16):
        engine = f"race-{n}-{uuid.uuid4().hex[:6]}"
        barrier = threading.Barrier(n + 1)
        answered, listed, stop = [], set(), threading.Event()

        def draft():
            from django.db import connection

            try:
                barrier.wait(10)
                reply = _draft(_client_for(operator), "pause", engine)
                if reply.status_code in (200, 201):
                    answered.append(reply.data["uuid"])
            finally:
                connection.close()

        def lister():
            from django.db import connection

            try:
                barrier.wait(10)
                while not stop.is_set():
                    reply = _client_for(operator).get(f"/api/failsafe/commands/?engine_id={engine}")
                    if reply.status_code == 200:
                        listed.update(row["uuid"] for row in reply.data)
            finally:
                connection.close()

        threads = [threading.Thread(target=draft) for _ in range(n)] + [threading.Thread(target=lister)]
        for thread in threads:
            thread.start()
        for thread in threads[:n]:
            thread.join(60)
        stop.set()
        threads[n].join(60)
        live = {str(u) for u in FailsafeCommand.objects.filter(engine_id=engine).values_list("uuid", flat=True)}
        assert FailsafeCommand.objects.filter(engine_id=engine).count() == 1, n
        assert len(answered) == n, (n, len(answered))
        assert set(answered) <= live, (n, set(answered) - live)  # no answer names a deleted row
        assert listed <= live, (n, listed - live)  # a list read never showed a since-deleted draft


@pytest.mark.django_db
def test_a_signature_revives_a_superseded_stop(rates, operator_key, configure):
    """F2 (round 5, SAFETY): supersession bounds an account's UNSIGNED stop
    drafts, but a flood -- or a fleet pause past the limit -- must never turn a
    real pending stop's signature into 409. A superseded but unsigned stop,
    validly signed, is revived and takes the signature, so a count never makes a
    pending stop unsignable; once it carries a signature it is never superseded
    again. A superseded stop past its window is not revived."""
    from failsafe.models import FailsafeCommand

    configure(FAILSAFE_UNSIGNED_STOP_DRAFTS_PER_ACCOUNT=5)
    bob = Ed25519PrivateKey.generate()
    configure(FAILSAFE_OPERATOR_KEYS={
        "alice": operator_key.public_key().public_bytes_raw().hex(),
        "bob": bob.public_key().public_bytes_raw().hex(),
    })
    client = _client_for(_admin())
    # A real stand-down drafted first (the oldest), then a fleet pause past the
    # limit supersedes the account's oldest unsigned drafts -- the real one.
    real = _draft(client, "stand_down", "prod-1", reason="REAL: exfiltration in progress").data
    assert [_draft(client, "pause", f"fleet-{i}").status_code for i in range(10)] == [201] * 10
    assert FailsafeCommand.objects.get(uuid=real["uuid"]).status == "superseded"
    # alice signs its bytes out of band: the superseded stop is revived.
    a = {"key_id": "alice", "sig": operator_key.sign(bytes.fromhex(real["signing_bytes"])).hex()}
    signed = client.post(f"/api/failsafe/commands/{real['uuid']}/signatures/", a, format="json")
    assert signed.status_code == 200 and signed.data["status"] == "awaiting_signatures"  # needs its second
    revived = FailsafeCommand.objects.get(uuid=real["uuid"])
    assert revived.status == "awaiting_signatures" and revived.signed is True
    # Signed now, a later flood never supersedes it again.
    for i in range(10, 30):
        _draft(client, "pause", f"fleet-{i}")
    assert FailsafeCommand.objects.get(uuid=real["uuid"]).status == "awaiting_signatures"
    # The second signature makes it ready -- a real stop that a flood could not stop.
    b = {"key_id": "bob", "sig": bob.sign(bytes.fromhex(real["signing_bytes"])).hex()}
    ready = client.post(f"/api/failsafe/commands/{real['uuid']}/signatures/", b, format="json")
    assert ready.status_code == 200 and ready.data["status"] == "ready"
    # A superseded stop past its window is not revived: its nonce and window are spent.
    stale = _draft(client, "stand_down", "prod-2", reason="stale").data
    for i in range(30, 40):
        _draft(client, "pause", f"fleet-{i}")
    assert FailsafeCommand.objects.get(uuid=stale["uuid"]).status == "superseded"
    FailsafeCommand.objects.filter(uuid=stale["uuid"]).update(expires_at="2000-01-01T00:00:00+00:00")
    a2 = {"key_id": "alice", "sig": operator_key.sign(bytes.fromhex(stale["signing_bytes"])).hex()}
    refused = client.post(f"/api/failsafe/commands/{stale['uuid']}/signatures/", a2, format="json")
    assert refused.status_code == 409


@pytest.mark.django_db
def test_every_accounts_newest_stop_draft_is_ranked_however_many_accounts_flood(rates):
    """F5 (round 5): _awaiting_stops ranked only the newest UNSIGNED_STOP_SCAN
    unsigned drafts of each action before the per-account round robin, so ten
    accounts of a hundred distinct-reason drafts each pushed a real stand-down
    -- older than that many newer drafts -- out of every read (state, the
    engine-scoped state, and the awaiting list), and the second operator could
    not find it. Every account's newest unsigned stop draft is ranked now
    (Max(id) per account), so a real pending stop is always findable."""
    from failsafe.models import FailsafeCommand
    from failsafe.views import UNSIGNED_STOP_SCAN

    honest = _admin()
    real = _draft(_client_for(honest), "stand_down", "prod-1", reason="REAL: second operator please sign").data
    n_accounts, per = 11, 100
    assert n_accounts * per > UNSIGNED_STOP_SCAN  # the honest one is older than the newest scanned
    flooders = [_user("analyst") for _ in range(n_accounts)]
    FailsafeCommand.objects.bulk_create(
        [
            FailsafeCommand(engine_id="prod-1", action="stand_down", nonce=uuid.uuid4().hex, issued_at="t",
                            expires_at="2999-01-01T00:00:00+00:00", reason=f"junk {a}-{j}",
                            initiator=flooders[a], required_signatures=2)
            for a in range(n_accounts)
            for j in range(per)
        ],
        batch_size=500,
    )
    total = FailsafeCommand.objects.filter(action="stand_down", status="awaiting_signatures", signed=False).count()
    assert total == n_accounts * per + 1
    reader = _client_for(honest)
    for path in ("/api/failsafe/state/", "/api/failsafe/state/?engine_id=prod-1",
                 "/api/failsafe/commands/?engine_id=prod-1&status=awaiting_signatures"):
        answer = reader.get(path)
        rows = answer.data["awaiting_signatures"] if "state" in path else answer.data
        assert real["uuid"] in [row["uuid"] for row in rows], path


@pytest.mark.django_db
def test_removing_an_operator_keeps_their_engagements_and_unlinks_them(rates):
    """Removing an operator is a stop (the lead's decision), and its cascade
    deleted every engagement they had created -- the record of what had been
    authorised. The records are kept, with the creator unlinked; such an
    engagement is an admin's to see, and no longer the removed operator's."""
    from pentest.models import Engagement
    from pentest.views import engagements_visible_to

    leaver = _user("analyst")
    kept = [
        Engagement.objects.create(name=f"kept-{i}", created_by=leaver, status=state, scope_hosts=["client.example"])
        for i, state in enumerate(("running", "completed"))
    ]
    admin_user = _admin()
    assert _client_for(admin_user).delete(f"/api/accounts/users/{leaver.pk}/").status_code == 204
    assert not User.objects.filter(pk=leaver.pk).exists()
    rows = Engagement.objects.filter(pk__in=[e.pk for e in kept]).order_by("pk")
    assert [(e.name, e.status, e.created_by_id) for e in rows] == [("kept-0", "running", None), ("kept-1", "completed", None)]
    assert set(engagements_visible_to(admin_user).filter(pk__in=[e.pk for e in kept])) == set(rows)
    assert not engagements_visible_to(_user("analyst")).filter(pk__in=[e.pk for e in kept]).exists()


@pytest.mark.django_db
def test_removing_an_operator_a_protected_record_depends_on_deactivates_and_revokes(rates):
    """Removing an operator is a stop and must never be refused (lead decision,
    round 5). A MaterialityDecision keeps its decider (decided_by is PROTECT),
    so deleting an operator who made one raised ProtectedError -- a stop
    refused. The account is deactivated and its tokens revoked instead, and the
    answer says so; the record and its attribution are kept."""
    from datetime import date

    from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken, OutstandingToken
    from rest_framework_simplejwt.tokens import RefreshToken

    from assurance.models import AssuranceClaim, Deployment, LegalObligation, MaterialityDecision

    leaver = _user("analyst")
    dep = Deployment.objects.create(name=f"dep-{uuid.uuid4().hex[:6]}")
    claim = AssuranceClaim.objects.create(
        deployment=dep, claim_type="data_boundary", statement="s", fingerprint="f",
        system_fingerprint="sf", policy_version="p", environment="prod",
    )
    obligation = LegalObligation.objects.create(
        jurisdiction="eu", authority_tier="binding", source="src", source_version="1",
        operative_date=date(2024, 1, 1),
    )
    MaterialityDecision.objects.create(
        claim=claim, obligation=obligation, decided_by=leaver, material=True, rationale="because"
    )
    # A tracked (outstanding) refresh token for the operator, to be revoked.
    refresh = RefreshToken.for_user(leaver)
    outstanding, _ = OutstandingToken.objects.get_or_create(
        jti=refresh["jti"],
        defaults={"user": leaver, "token": str(refresh),
                  "created_at": timezone.now(), "expires_at": timezone.now() + timedelta(days=1)},
    )
    removed = _client_for(_admin()).delete(f"/api/accounts/users/{leaver.pk}/")
    assert removed.status_code == 200 and removed.data["deactivated"] is True
    leaver.refresh_from_db()
    assert leaver.is_active is False  # deactivated: its access and refresh no longer work
    assert BlacklistedToken.objects.filter(token=outstanding).exists()  # its token is revoked
    # The record and its attribution are kept -- the protected reference stands.
    assert User.objects.filter(pk=leaver.pk).exists()
    assert MaterialityDecision.objects.filter(decided_by=leaver).exists()
    # An operator nothing protects is still deleted outright (204).
    plain = _user("analyst")
    assert _client_for(_admin()).delete(f"/api/accounts/users/{plain.pk}/").status_code == 204
    assert not User.objects.filter(pk=plain.pk).exists()


#: The longest any stop may take through the whole stack with every limit
#: saturated. The slowest here takes about a tenth of this.
STOP_LATENCY_BOUND = 0.25


@pytest.mark.django_db
@pytest.mark.parametrize("gateway_answer", list(GATEWAY_ANSWERS))
def test_with_every_limit_saturated_every_stop_is_answered_within_its_bound(saturated, operator_key, gateway_answer, monkeypatch):
    """L2 (round 4): the saturation checked status codes only, so a control
    that DELAYS a stop without refusing it -- T4, a 0.3 s sleep in StopsPass
    for every stop -- passed it. Each stop through config.wsgi.application and
    the whole stack, with every limit saturated, is answered within
    STOP_LATENCY_BOUND, by an operator's JWT and by the service token."""
    payload, _refused = GATEWAY_ANSWERS[gateway_answer]
    saturated(payload)
    timings = []
    real = _WsgiHandler.__call__

    def timed(self, environ):
        began = time.perf_counter()
        try:
            return real(self, environ)
        finally:
            timings.append((time.perf_counter() - began, environ["REQUEST_METHOD"], environ["PATH_INFO"]))

    monkeypatch.setattr(_WsgiHandler, "__call__", timed)
    operator = _admin()
    bearer = _wsgi_bearer_client(operator)
    bearer.get("/api/failsafe/audit/")  # the first request through the entry point imports what it needs
    timings.clear()
    assert _every_stop(bearer, operator, operator_key, anonymous=_WsgiClient) == SERVED
    service = _service_account()
    with override_settings(FAILSAFE_SERVICE_TOKEN=SERVICE_TOKEN, FAILSAFE_SERVICE_USER=service.username):
        assert _every_stop(_wsgi_service_client(), service, operator_key, anonymous=_WsgiClient) == SERVICE_SERVED
    assert len(timings) >= 2 * len(EVERY_STOP)
    slow = [(round(t, 3), method, path) for t, method, path in timings if t > STOP_LATENCY_BOUND]
    assert slow == [], slow
