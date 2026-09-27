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
"""

from __future__ import annotations

import base64
import http.server
import io
import json
import re
import threading
import time
import uuid
from datetime import timedelta
from unittest import mock

import pytest
import requests
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from django.urls import URLPattern, URLResolver, get_resolver
from django.utils import timezone
from rest_framework.test import APIClient
from rest_framework.throttling import SimpleRateThrottle
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
    "claim-transition": {"POST"},
    "failsafe:commands": {"GET", "POST"},
    "failsafe:command-detail": {"GET"},
    "failsafe:submit-signature": {"POST"},
    "failsafe:cancel-command": {"POST"},
    "failsafe:pending": {"GET"},
    "deployment-dispatch-policy": {"PUT"},
    "pentest:engagement_detail": {"PATCH", "DELETE"},
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
    "failsafe:state",
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
    from rest_framework_simplejwt.tokens import RefreshToken

    return {"refresh": str(RefreshToken())}


#: One request that is a stop for every exempt (route, method):
#: (route, method, path, JSON body -- or a function making one -- or None, extra headers).
STOP_REQUESTS = [
    ("deployment-recompute", "POST", RECOMPUTE, {"paused": True}, {}),
    ("deployment-recompute", "POST", RECOMPUTE, {"paused": False}, {}),
    ("claim-transition", "POST", TRANSITION, {"to_status": "revoked"}, {}),
    ("claim-transition", "POST", TRANSITION, {"to_status": "contradicted", "note": "n"}, {}),
    ("failsafe:commands", "GET", "/api/failsafe/commands/", None, {}),
    ("failsafe:commands", "POST", "/api/failsafe/commands/", {"action": "stand_down", "engine_id": "e"}, {}),
    ("failsafe:command-detail", "GET", f"/api/failsafe/commands/{U}/", None, {}),
    ("failsafe:submit-signature", "POST", f"/api/failsafe/commands/{U}/signatures/", {"key_id": "a", "sig": "00"}, {}),
    ("failsafe:cancel-command", "POST", f"/api/failsafe/commands/{U}/cancel/", {}, {}),
    ("failsafe:pending", "GET", "/api/failsafe/pending/", None, {"HTTP_X_FAILSAFE_POLL_TOKEN": POLL_TOKEN}),
    ("deployment-dispatch-policy", "PUT", DISPATCH, {"enabled": False}, {}),
    ("pentest:engagement_detail", "PATCH", ENGAGEMENT, {"status": "paused"}, {}),
    ("pentest:engagement_detail", "PATCH", ENGAGEMENT, {"testing_window_end": PAST}, {}),
    ("pentest:engagement_detail", "PATCH", ENGAGEMENT, {"scope_hosts": []}, {}),
    ("pentest:engagement_detail", "DELETE", ENGAGEMENT, None, {}),
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
    ("promotion to admin", "PATCH", SET_ROLE, {"role": "admin"}, "application/json", {}),
    ("refresh with a token that does not verify", "POST", "/api/token/refresh/", {"refresh": "x.y.z"}, "application/json", {}),
    ("governor state read", "GET", "/api/failsafe/state/", None, "application/json", {}),
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


def _throttle_problems(callback):
    cls = callback.cls
    problems = []
    for method in ("get_throttles", "check_throttles"):
        if getattr(cls, method) is not getattr(APIView, method):
            problems.append(f"overrides {method}()")
    throttles = callback.initkwargs.get("throttle_classes", cls.throttle_classes)
    problems += [f"throttles with {t.__name__}" for t in throttles if not issubclass(t, StopsPass)]
    return problems


def test_no_exempt_view_opts_out_of_the_stop_exemption():
    """A stop view's own throttle_classes, or its own get_throttles(), would
    replace the defaults; every one must still let a stop through."""
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

    assert _throttle_problems(Sneaky.as_view()) == ["overrides get_throttles()"]
    assert _throttle_problems(Plain.as_view()) == ["throttles with AnonRateThrottle"]


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
        ("application/json", b'{"paused":false}'),
        ("application/json", b'{"\\u0070aused": true}'),
        ("application/json; charset=utf-8", b'{"paused": true}'),
        ("application/json; charset=UTF-8", b'{"paused": true}'),
        ("application/json; charset=us-ascii", b'{"paused": true}'),
        ("Application/JSON", b'{"paused": true}'),
        ("application/json", b'{"paused": "false", "note": "maintenance"}'),
        ("application/x-www-form-urlencoded", b"paused=true"),
        ("application/x-www-form-urlencoded; charset=utf-8", b"paused=false&reason=done"),
    ],
    ids=["json", "json-compact-lift", "escaped-key", "utf-8", "UTF-8", "us-ascii", "type-case",
         "string-lift-with-note", "form", "form-lift-with-reason"],
)
def test_a_pause_or_lift_in_canonical_form_is_a_stop(content_type, data):
    assert stops.is_stop(_raw("POST", RECOMPUTE, data, content_type))


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
    assert not stops.is_stop(RequestFactory().get("/api/failsafe/state/"))
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
    """Django reads no body for it, and neither does this: a routine recompute."""
    request = _raw("POST", RECOMPUTE, b'{"paused": true}')
    request.META["CONTENT_LENGTH"] = "sixteen"
    assert not stops.is_stop(request)
    request = _raw("POST", f"/api/failsafe/commands/{U}/cancel/", b"{}")
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
    ("dashboard lift", "POST", RECOMPUTE, _stringify({"paused": False}), {}),
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
    # server/failsafe.ts submitSignature: {key_id, sig} as mythos-failsafe sign
    # prints it (mythos_core/failsafe/sign.py sign_draft: json.dumps, spaced).
    ("signer CLI signature relayed", "POST", f"/api/failsafe/commands/{U}/signatures/", json.dumps({"key_id": "alice", "sig": "ab" * 64}).encode(), {}),
    # server/failsafe.ts cancelCommand: POST, JSON content type, no body.
    ("dashboard cancel", "POST", f"/api/failsafe/commands/{U}/cancel/", None, {}),
]


@pytest.mark.parametrize(("label", "method", "path", "body", "extra"), REAL_CLIENTS, ids=[c[0] for c in REAL_CLIENTS])
def test_every_real_clients_stop_is_recognised(label, method, path, body, extra):
    assert stops.is_stop(_client_shape(method, path, body, **BEARER, **extra)), label


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
    if callable(body):
        body = body()
    if isinstance(body, bytes):
        data = body
    else:
        data = "" if body is None else json.dumps(body)
    return factory.generic(method, path, data=data, content_type=content_type, **extra)


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
    started = time.monotonic()
    response = app(_request(method, path, body, extra))
    took = time.monotonic() - started
    assert response.status_code == 200 and response.content == b"the view ran"
    assert took < 0.25, f"{method} {path} took {took:.3f}s behind an engine in mode {mode!r}"
    assert engine.asked == []


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
    response = app(_request("GET", "/api/failsafe/state/", None, {}))
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
        response = app(_request("GET", "/api/failsafe/state/", None, {}))
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
    app(_request("GET", "/api/failsafe/state/", None, {}))
    time.sleep(max(0.0, 0.8 - (time.monotonic() - started)))
    app(_request("GET", "/api/failsafe/state/", None, {}))
    assert len(engine.asked) == 2, problems
    assert "all 1 engine call slots are in use; not asking" not in problems


def test_a_prompt_answer_is_still_enforced(gateway):
    app = gateway(mode="now", monitor_only=False)
    response = app(_request("GET", "/api/failsafe/state/", None, {}))
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
    response = app(_request("GET", "/api/failsafe/state/", None, {}))
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
    response = app(_request("GET", "/api/failsafe/state/", None, {}))
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
            assert app(_request("GET", "/api/failsafe/state/", None, {})).status_code == 200
    assert problems == ["engine call could not start: RuntimeError"] * 2


def test_an_error_that_is_not_a_request_failure_is_raised_as_before(enforcing, monkeypatch):
    app, problems = enforcing
    monkeypatch.setattr("audit.middleware.requests.post", mock.Mock(side_effect=ValueError("a bug")))
    with pytest.raises(ValueError, match="a bug"):
        app(_request("GET", "/api/failsafe/state/", None, {}))
    assert app._slots.acquire(timeout=0)
    app._slots.release()


# --- The throttles and sign-in, through the whole stack --------------------------

#: The shipped anonymous rate (config.settings). The engines poll every 2 s.
ANON_RATE = "30/min"


@pytest.fixture()
def rates(monkeypatch, configure):
    """Real rates for these tests. The test settings switch throttling off, and
    the throttle classes read their rates once, at import."""

    def apply(anon=ANON_RATE, user="300/min", sign_in="10/min"):
        monkeypatch.setattr(
            SimpleRateThrottle, "THROTTLE_RATES", {"anon": anon, "user": user, "sign_in": sign_in}
        )

    cache.clear()
    configure(DEFENDER_MONITOR_ONLY=True, FAILSAFE_POLL_TOKEN=POLL_TOKEN)
    # The gateway answers allow at once: these tests are about the throttles.
    monkeypatch.setattr("audit.middleware.requests.post", _engine_answers({"allow": True, "action": "allow"}))
    apply()
    yield apply
    cache.clear()


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


def _every_stop(client, operator, operator_key):
    """Every kind of stop an operator makes, each on its own row, the engine's
    poll, and the refresh that keeps the operator signed in. Returns {stop: status code}."""
    from rest_framework_simplejwt.tokens import RefreshToken

    from assurance.decision import recompute_decision
    from pentest.models import Engagement

    to_pause, to_lift, to_revoke, to_contradict, to_switch_off = (_deployment() for _ in range(5))
    recompute_decision(to_lift, paused=True)
    # Two drafts, one to sign and one to cancel. A draft of a stop is a stop too.
    drafts = [
        client.post("/api/failsafe/commands/", {"action": "pause", "engine_id": "athena-1"}, format="json").data
        for _ in range(2)
    ]
    sig = operator_key.sign(bytes.fromhex(drafts[0]["signing_bytes"])).hex()
    engagements = [
        Engagement.objects.create(name=f"stop321-{i}", created_by=operator, status="running", scope_hosts=["client.example"])
        for i in range(3)
    ]
    colleague, deputy = _admin(), _admin()
    past = (timezone.now() - timedelta(minutes=1)).isoformat()

    base = "/api/assurance"
    return {
        "pause": client.post(f"{base}/deployments/{to_pause.uuid}/recompute/", {"paused": True}, format="json").status_code,
        "lift": client.post(f"{base}/deployments/{to_lift.uuid}/recompute/", {"paused": False}, format="json").status_code,
        "revoke": client.post(f"{base}/claims/{_claim(to_revoke).uuid}/transition/", {"to_status": "revoked"}, format="json").status_code,
        "contradict": client.post(f"{base}/claims/{_claim(to_contradict).uuid}/transition/", {"to_status": "contradicted"}, format="json").status_code,
        "stand down": client.post("/api/failsafe/commands/", {"action": "stand_down", "engine_id": "athena-1"}, format="json").status_code,
        "terminate": client.post("/api/failsafe/commands/", {"action": "terminate", "engine_id": "athena-1"}, format="json").status_code,
        "sign": client.post(f"/api/failsafe/commands/{drafts[0]['uuid']}/signatures/", {"key_id": "alice", "sig": sig}, format="json").status_code,
        "cancel": client.post(f"/api/failsafe/commands/{drafts[1]['uuid']}/cancel/", {}, format="json").status_code,
        "dispatch off": client.put(f"{base}/deployments/{to_switch_off.uuid}/dispatch-policy/", {"enabled": False}, format="json").status_code,
        "engagement paused": client.patch(f"/api/pentest/engagements/{engagements[0].pk}/", {"status": "paused"}, format="json").status_code,
        "engagement window closed": client.patch(f"/api/pentest/engagements/{engagements[1].pk}/", {"testing_window_end": past}, format="json").status_code,
        "engagement scope emptied": client.patch(f"/api/pentest/engagements/{engagements[2].pk}/", {"scope_hosts": []}, format="json").status_code,
        "operator demoted": client.patch(f"/api/accounts/users/{colleague.pk}/set_role/", {"role": "viewer"}, format="json").status_code,
        "admin demoted to analyst": client.patch(f"/api/accounts/users/{deputy.pk}/set_role/", {"role": "analyst"}, format="json").status_code,
        "poll": _poll().status_code,
        "refresh": APIClient().post("/api/token/refresh/", {"refresh": str(RefreshToken.for_user(operator))}, format="json").status_code,
    }


SERVED = {
    "pause": 200, "lift": 200, "revoke": 200, "contradict": 200, "stand down": 201, "terminate": 201,
    "sign": 200, "cancel": 200, "dispatch off": 200, "engagement paused": 200, "engagement window closed": 200,
    "engagement scope emptied": 200, "operator demoted": 200, "admin demoted to analyst": 200, "poll": 200,
    "refresh": 200,
}


def _client_for(user):
    client = APIClient()
    client.force_authenticate(user=user)
    return client


@pytest.mark.django_db
def test_a_flooded_operator_can_still_pause_stand_down_revoke_and_lift(rates, operator_key):
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
def test_a_list_read_returns_at_most_the_cap(rates):
    from failsafe.models import FailsafeCommand
    from failsafe.views import COMMAND_LIST_LIMIT

    FailsafeCommand.objects.bulk_create(
        [
            FailsafeCommand(engine_id="e", action="pause", nonce=f"n-{uuid.uuid4()}", issued_at="t", expires_at="t")
            for _ in range(COMMAND_LIST_LIMIT + 10)
        ]
    )
    response = _client_for(_admin()).get("/api/failsafe/commands/")
    assert response.status_code == 200 and len(response.data) == COMMAND_LIST_LIMIT == 50


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
    widened, a viewer made analyst."""
    from pentest.models import Engagement

    configure(DEFENDER_MONITOR_ONLY=False)
    monkeypatch.setattr(
        "audit.middleware.requests.post", _engine_answers({"allow": False, "action": "block", "reason": "x"})
    )
    operator = _admin()
    client = _client_for(operator)
    viewer, other_viewer = _user("viewer"), _user("viewer")
    dep = _deployment()
    engagement = Engagement.objects.create(name="stop321-w", created_by=operator, status="paused", scope_hosts=["client.example"])
    answers = {
        "promotion": client.patch(f"/api/accounts/users/{viewer.pk}/set_role/", {"role": "admin"}, format="json"),
        "viewer to analyst": client.patch(f"/api/accounts/users/{other_viewer.pk}/set_role/", {"role": "analyst"}, format="json"),
        "dispatch on": client.put(f"/api/assurance/deployments/{dep.uuid}/dispatch-policy/", {"enabled": True, "min_severity": "info"}, format="json"),
        "widened": client.patch(f"/api/pentest/engagements/{engagement.pk}/", {"status": "running", "scope_hosts": ["client.example", "other.example"]}, format="json"),
        "resume drafted": client.post("/api/failsafe/commands/", {"action": "resume", "engine_id": "athena-1"}, format="json"),
    }
    assert {name: response.status_code for name, response in answers.items()} == {name: 403 for name in answers}
    viewer.refresh_from_db(), other_viewer.refresh_from_db(), engagement.refresh_from_db()
    assert (viewer.role, other_viewer.role) == ("viewer", "viewer")
    assert (engagement.status, engagement.scope_hosts) == ("paused", ["client.example"])


def _sign_in(username, password, address="10.0.0.1"):
    return APIClient().post("/api/token/", {"username": username, "password": password}, format="json", REMOTE_ADDR=address)


@pytest.mark.django_db
def test_no_flood_from_the_operators_address_stops_them_signing_in_or_refreshing(rates):
    """Round 1 (and master): 30 wrong-token polls from the operator's address,
    then the right password was 429 with Retry-After 60, and so was a valid
    refresh. Only the operator's own failed sign-ins count against them now."""
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


@pytest.mark.django_db
def test_a_successful_sign_in_clears_the_failures(rates):
    User.objects.create_user(username="op322", password="right-password", role="admin")
    for _ in range(2):
        assert [_sign_in("op322", "wrong").status_code for _ in range(9)] == [401] * 9
        assert _sign_in("op322", "right-password").status_code == 200


@pytest.mark.django_db
def test_a_valid_refresh_is_never_throttled_and_an_invalid_one_is(rates):
    from rest_framework_simplejwt.tokens import RefreshToken

    operator = User.objects.create_user(username="op323", password="x", role="admin")
    refresh = str(RefreshToken.for_user(operator))
    codes = [APIClient().post("/api/token/refresh/", {"refresh": refresh}, format="json").status_code for _ in range(40)]
    assert codes == [200] * 40
    bad = [APIClient().post("/api/token/refresh/", {"refresh": "x.y.z"}, format="json").status_code for _ in range(31)]
    assert bad == [401] * 30 + [429]


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
