"""A body within its route's own bound is not a failed inspection.

The Defender gateway (:mod:`audit.middleware`) sends the engine the first
``DEFENDER_MAX_BODY_BYTES`` (64 KiB) of a body and recorded every longer one as "truncated
for inspection": a failure, counted toward the gateway's one alert, the one an engine outage
raises ("Defender engine unavailable for N of the last 60s"). #234 raised the observed-effect
intake's bound to 456,634 bytes, read from the core, so every valid large version 5 record
counted toward an alert that means something is being kept from inspection.

The gateway now holds each route's own bound: a table built when it is loaded
(:data:`audit.middleware.DECLARED_BODY_BOUNDS`), from the route's URL name and method to the very
constant its own 413 compares against, imported by name. A body within it is recorded as
:data:`audit.middleware.INSPECTED_IN_PART`: named, counted and logged, never a failure. The
engine is sent the same first 64 KiB as before: its ``/defend`` states no bound of its own,
and sending more would put more work before authentication in front of a request allowed
today. This file holds:

* a valid version 5 record of 300 KB is taken in, inspected in part, and counts toward
  nothing; ten of them raise no alert, where ten on a route that declares no bound do;
* over the bound, on a route or a method that declares none, or with a bound that cannot be
  read, a body counts exactly as it did;
* each bound the gateway holds is the very object its route reads (never a copy, never a
  number), and every declared bound is the one its route refuses past;
* the gateway imports nothing and looks nothing up by a name built at runtime, and nothing is
  imported while a request is served;
* every other reason on the same body is still a failure, and the engine is sent what it was;
* no part of this runs on a stop, and nothing is refused or delayed.

On the base (#234 at 691ee0f) the first test fails: the 300 KB record is recorded as
``request body was truncated at 65536 bytes for inspection``.
"""

from __future__ import annotations

import ast
import copy
import io
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path
from unittest import mock

import pytest
import requests
import urllib3
from django.contrib.auth import get_user_model
from django.http import HttpResponse
from django.test import RequestFactory, override_settings
from mythos_core import observed_effect as core
from mythos_core import outcome as oc
from rest_framework.test import APIClient

from assurance import achilles_results, effect_reconciliation, identity_evidence, observed_effects, observed_outcomes
from assurance.models import Deployment, WorkflowChainOutcome
from audit import middleware as gateway
from audit.middleware import DefenderMiddleware
from tests.test_no_control_holds_back_a_stop import POLL_TOKEN, STOP_REQUESTS, _request
from tests.test_spine_authority_chain import _admin, _base, _client
from tests.test_the_observed_effect_is_mythos_cores import _instant, _key, _sign_effect, _vector

User = get_user_model()
REPO = Path(__file__).resolve().parent.parent
TOKEN = "observed-effect-service-token-for-tests-0123456789"  # pragma: allowlist secret
IDENTITY_TOKENS = {
    "authentication": "sign-in-collector-token-for-tests-0123456789",  # pragma: allowlist secret
    "delegation": "grant-collector-token-for-tests-0123456789abc",  # pragma: allowlist secret
}
U = "11111111-2222-4333-8444-555555555555"
EFFECTS = f"/api/assurance/deployments/{U}/observed-effects/"
SCAN_RESULTS = f"/api/assurance/deployments/{U}/achilles-scan-results/"
#: A route that takes a body and declares no bound of its own.
UNDECLARED = f"/api/assurance/deployments/{U}/chain-outcomes/"
TRUNCATED = "request body was truncated at 65536 bytes for inspection"

#: Every route that declares a bound, by URL name and method, and the constant its 413 reads.
DECLARED = {
    ("deployment-observed-chain-outcomes", "POST"): "assurance.observed_outcomes.MAX_BODY_BYTES",
    ("deployment-effect-reconciliations", "POST"): "assurance.effect_reconciliation.MAX_BODY_BYTES",
    ("deployment-observed-effects", "POST"): "assurance.observed_effects.MAX_BODY_BYTES",
    ("deployment-achilles-scan-results", "POST"): "assurance.achilles_results.MAX_BODY_BYTES",
    ("deployment-authentications", "POST"): "assurance.identity_evidence.MAX_BODY_BYTES",
    ("deployment-delegations", "POST"): "assurance.identity_evidence.MAX_BODY_BYTES",
}


def _engine_allows():
    """``outbound.post`` as an engine answering allow at once; each call's ctx is kept."""

    def answer(*args, **kwargs):
        response = requests.Response()
        response.status_code = 200
        response.raw = urllib3.HTTPResponse(
            body=io.BytesIO(json.dumps({"allow": True, "action": "allow"}).encode()), status=200, preload_content=False
        )
        return response

    return mock.Mock(side_effect=answer)


@pytest.fixture
def failures(monkeypatch):
    """Every reason the gateway records as a failure, from every instance, recorded as it was."""
    seen = []
    real = DefenderMiddleware._record_failure

    def recording(self, reason):
        seen.append(reason)
        return real(self, reason)

    monkeypatch.setattr(DefenderMiddleware, "_record_failure", recording)
    return seen


@pytest.fixture
def engine(monkeypatch):
    post = _engine_allows()
    monkeypatch.setattr("audit.middleware.outbound.post", post)
    return post


@pytest.fixture
def service(monkeypatch):
    User.objects.create_user(username="effect-service", password="x")
    monkeypatch.setenv(observed_effects.TOKEN_ENV, TOKEN)
    monkeypatch.setenv(observed_effects.USER_ENV, "effect-service")
    client = APIClient()
    client.credentials(HTTP_X_OBSERVED_EFFECT_TOKEN=TOKEN)
    return client


@pytest.fixture
def at(monkeypatch):
    def set_clock(now: datetime) -> None:
        class Clock(datetime):
            @classmethod
            def now(cls, tz=None):
                return now if tz is None else now.astimezone(tz)

        monkeypatch.setattr(observed_outcomes, "datetime", Clock)

    return set_clock


@pytest.fixture
def trust(tmp_path, monkeypatch):
    import base64

    def write(keys: dict[str, str]) -> None:
        path = tmp_path / "vector-keyring.json"
        path.write_text(
            json.dumps(
                [{"engine": e, "public_key": base64.b64encode(bytes.fromhex(k)).decode()} for e, k in keys.items()]
            )
        )
        monkeypatch.setenv(observed_outcomes.KEYRING_ENV, str(path))

    return write


def _record_of_300_kb(dep) -> tuple[bytes, dict]:
    """A valid version 5 record of about 300 KB, as posted: the core's largest document with 65
    of its 100 approval recipients, naming this deployment, signed by the vector's key."""
    v = _vector("observed-effect-v5.json")
    (largest,) = [c["evidence"] for c in v["also_valid"] if len(oc.canonical_bytes(c["evidence"])) == core.MAX_EVIDENCE_BYTES]
    document = copy.deepcopy(largest)
    document["deployment"] = str(dep.uuid)
    document["dispatch"]["verified"]["workflow_approval"]["deployment"] = str(dep.uuid)
    document["dispatch"]["verified"]["approval_recipients"] = document["dispatch"]["verified"]["approval_recipients"][:65]
    assert core.validate_evidence(copy.deepcopy(document)) == document
    envelope = _sign_effect(document, _key(v["effect_key_phrase"]))
    body = json.dumps({"envelope": envelope, "evidence": document}, separators=(",", ":"), ensure_ascii=False).encode()
    return body, document


def _gateway(**values):
    """The gateway in front of a view that answers at once."""
    with override_settings(**values):
        return DefenderMiddleware(lambda request: HttpResponse("the view ran"))


def _post(path, body, content_type="application/json", method="POST", **extra):
    return RequestFactory().generic(method, path, data=body, content_type=content_type, **extra)


def _json_of(size: int) -> bytes:
    """A JSON body of exactly ``size`` bytes, with nothing in it the redaction touches."""
    head, tail = b'{"note":"', b'"}'
    return head + b"a" * (size - len(head) - len(tail)) + tail


# ------------------------------------------------- a valid version 5 record, end to end


@pytest.mark.django_db
def test_a_valid_v5_record_of_300_kb_is_taken_in_and_counts_toward_no_alert(service, trust, at, engine, failures, caplog):
    """Through the whole request path: the gateway as settings.MIDDLEWARE installs it, then the
    route. On the base the gateway recorded it as a failure: ``request body was truncated at
    65536 bytes for inspection``."""
    v = _vector("observed-effect-v5.json")
    trust({v["effect_engine"]: v["effect_public_key_hex"]})
    dep = Deployment.objects.create(name="three-hundred-kb", owner=_admin())
    body, document = _record_of_300_kb(dep)
    assert 300_000 < len(body) < observed_effects.MAX_BODY_BYTES
    at(_instant(document["observed_at"]) + timedelta(minutes=1))

    with caplog.at_level(logging.INFO, logger="audit.middleware"):
        sent = service.post(_base(dep) + "observed-effects/", body, content_type="application/json")

    assert failures == [], "a valid record within its route's bound was counted as a failed inspection"
    assert sent.status_code == 201, sent.content[:300]
    assert WorkflowChainOutcome.objects.get(effect_dispatch_id=document["dispatch_id"]).effect_evidence == document
    # The engine was asked, once, with the first 64 KiB: what it was sent before.
    assert engine.call_count == 1
    assert len(engine.call_args.kwargs["json"]["body"]) == 64 * 1024
    said = [r.getMessage() for r in caplog.records if gateway.INSPECTED_IN_PART in r.getMessage()]
    assert said == [
        f"Defender request body {gateway.INSPECTED_IN_PART} (POST deployment-observed-effects, at most "
        f"{observed_effects.MAX_BODY_BYTES} bytes): {TRUNCATED}; 1 so far"
    ]
    assert all(r.levelno == logging.INFO for r in caplog.records if gateway.INSPECTED_IN_PART in r.getMessage())


@pytest.mark.django_db
def test_ten_records_in_a_minute_raise_no_alert_where_ten_undeclared_bodies_do(engine, failures, caplog):
    """The alert is ten failures in the window (DEFENDER_FAILURE_ALERT_AFTER). Ten bodies of
    300 KB on the intake are its traffic; the same ten on a route that declares no bound are ten
    failures, and the alert fires as it always did."""
    body = _json_of(300_000)
    app = _gateway(DEFENDER_FAILURE_ALERT_AFTER=10, DEFENDER_FAILURE_WINDOW_SECONDS=60)
    with caplog.at_level(logging.INFO, logger="audit.middleware"):
        for _ in range(10):
            assert app(_post(EFFECTS, body)).content == b"the view ran"
    assert failures == [] and app._recent_failures == [] and app.inspected_in_part == 10
    assert not [r for r in caplog.records if r.name == "audit.middleware" and r.levelno >= logging.WARNING]

    caplog.clear()
    with caplog.at_level(logging.INFO, logger="audit.middleware"):
        for _ in range(10):
            assert app(_post(UNDECLARED, body)).content == b"the view ran"
    assert failures == [TRUNCATED] * 10 and len(app._recent_failures) == 10 and app.inspected_in_part == 10
    alerts = [r.getMessage() for r in caplog.records if r.name == "audit.middleware" and r.levelno == logging.ERROR]
    assert alerts == [
        f"Defender engine unavailable for 10 of the last 60s: {TRUNCATED}. Requests are being allowed without a decision."
    ]


# ------------------------------------------- over the bound, or no bound: exactly as before


def test_a_body_over_its_routes_bound_counts_as_before(engine, failures, caplog):
    bound = observed_effects.MAX_BODY_BYTES
    app = _gateway()
    with caplog.at_level(logging.INFO, logger="audit.middleware"):
        assert app(_post(EFFECTS, _json_of(bound + 1))).content == b"the view ran"
    assert failures == [TRUNCATED] and app.inspected_in_part == 0
    assert not [r for r in caplog.records if gateway.INSPECTED_IN_PART in r.getMessage()]
    # At the bound exactly, it is within.
    assert app(_post(EFFECTS, _json_of(bound))).content == b"the view ran"
    assert failures == [TRUNCATED] and app.inspected_in_part == 1


def test_a_declared_length_or_a_read_over_the_bound_is_not_within_it(engine):
    """Both what the request declares (what the route's 413 reads) and what was read must be
    within the bound."""
    app = _gateway()
    bound = observed_effects.MAX_BODY_BYTES
    request = _post(EFFECTS, _json_of(70_000))
    assert app._unless_within_bound(request, TRUNCATED, bound + 1) == TRUNCATED
    for declared in (str(bound + 1), "not a number", "0", "-5"):
        request.META["CONTENT_LENGTH"] = declared
        assert app._unless_within_bound(request, TRUNCATED, 70_000) == TRUNCATED
    request.META["CONTENT_LENGTH"] = str(bound)
    assert app._unless_within_bound(request, TRUNCATED, None) is None
    assert app.inspected_in_part == 1


@pytest.mark.parametrize(
    "path, method",
    [
        (UNDECLARED, "POST"),  # a route that takes a body and declares no bound
        (SCAN_RESULTS, "GET"),  # a route that declares a bound for its POST only
        ("/api/thing/", "POST"),  # no route at all
    ],
)
def test_a_large_body_where_no_bound_is_declared_counts_as_before(engine, failures, path, method):
    app = _gateway()
    response = app(_post(path, _json_of(300_000), method=method))
    assert response.content == b"the view ran"
    assert failures == [TRUNCATED] and app.inspected_in_part == 0


def test_a_body_past_the_prefix_says_the_same_as_before_where_no_bound_is_declared(engine, failures):
    """A body whose redaction shrank under the limit is truncated at the prefix; the sentence is
    the one it always was."""
    body = b"password=" + b"s" * 300_000 + b"\nnote: n"
    app = _gateway()
    app(_post(UNDECLARED, body, content_type="text/plain"))
    assert failures == ["request body was truncated at 262144 bytes for inspection"]
    app(_post(EFFECTS, body, content_type="text/plain"))
    assert failures == ["request body was truncated at 262144 bytes for inspection"]
    assert app.inspected_in_part == 1


def test_a_bound_that_cannot_be_read_is_caution_and_says_so(engine, failures, monkeypatch):
    """Unreadable is never within: the body counts as uninspected, and the reason says why."""
    key = ("deployment-achilles-scan-results", "POST")
    monkeypatch.setitem(gateway.DECLARED_BODY_BOUNDS, key, "512 KiB")
    app = _gateway()
    response = app(_post(SCAN_RESULTS, _json_of(300_000)))
    assert response.content == b"the view ran"
    assert failures == [f"{TRUNCATED} (its route's declared bound could not be read: ValueError)"]
    for unreadable in (True, 0, -1, 1.5e6):
        monkeypatch.setitem(gateway.DECLARED_BODY_BOUNDS, key, unreadable)
        with pytest.raises(ValueError):
            gateway.declared_body_bound(_post(SCAN_RESULTS, b"{}"))
    assert app.inspected_in_part == 0


def test_an_outcome_that_cannot_be_recorded_counts_as_before_and_the_request_is_allowed(engine, failures, monkeypatch):
    """Within the bound, but the in-part record itself fails: never passed over in silence, and
    never a reason the request is not served."""

    def broken(self, request, trimmed, bound):
        raise RuntimeError("the log sink is gone")

    monkeypatch.setattr(DefenderMiddleware, "_record_in_part", broken)
    app = _gateway(DEFENDER_MONITOR_ONLY=False)
    assert app(_post(EFFECTS, _json_of(300_000))).content == b"the view ran"
    assert failures == [TRUNCATED]


def test_every_other_reason_on_a_body_within_its_bound_is_still_a_failure(engine, failures):
    """Only the truncation is the route's traffic. A charset the gateway does not read, or a
    value redacted to the end of its line, is the failure it always was."""
    app = _gateway()
    app(_post(EFFECTS, _json_of(100_000), content_type="application/json; charset=punycode"))
    assert failures == ["request body could not be fully inspected: its charset is not one read here"]
    doubtful = ("note: hi\npassword: [x] ' UNION SELECT username, pw FROM users --\n" + "a" * 100_000).encode()
    app(_post(EFFECTS, doubtful, content_type="text/plain"))
    assert failures[1:] == [f"request body {gateway.DOUBTFUL_VALUE}"]
    assert app.inspected_in_part == 2
    # And with no bound, the same body says what it said, in the order it said it.
    app(_post(UNDECLARED, doubtful, content_type="text/plain"))
    assert failures[2:] == [f"{TRUNCATED}; request body {gateway.DOUBTFUL_VALUE}"]


def test_the_engine_is_sent_what_it_was_sent(engine):
    """The same body, on a route that declares a bound and on one that does not: the engine
    sees the same first 64 KiB."""
    app = _gateway()
    body = b'{"q":"' + b"1 OR 1=1 " * 40_000 + b'"}'
    app(_post(EFFECTS, body))
    app(_post(UNDECLARED, body))
    within, undeclared = (call.kwargs["json"]["body"] for call in engine.call_args_list)
    assert within == undeclared and len(within) == 64 * 1024


# ---------------------------------------------- the bound is the route's, read, never typed


def test_each_bound_in_the_table_is_the_very_object_its_route_reads():
    """Never a second copy: each value is the route's own constant, the same object its 413
    compares against (``is``, not ``==``), and the route's 413 reads it by that name."""
    assert set(gateway.DECLARED_BODY_BOUNDS) == set(DECLARED)
    source = (REPO / "assurance" / "views.py").read_text(encoding="utf-8")
    for key, reference in DECLARED.items():
        module, name = reference.rsplit(".", 1)
        assert gateway.DECLARED_BODY_BOUNDS[key] is getattr(sys.modules[module], name), key
        # The route's own refusal reads that name.
        assert f"declared > {module.rsplit('.', 1)[1]}.{name}:" in source, reference
    # The observed-effect bound is the core's two numbers, and one object for them.
    assert observed_effects.MAX_BODY_BYTES is observed_effects.MAX_BODY_BYTES
    assert observed_effects.MAX_BODY_BYTES == oc.MAX_PAYLOAD_B64 + core.MAX_EVIDENCE_BYTES == 456_634
    assert gateway.declared_body_bound(_post(EFFECTS, b"{}")) is observed_effects.MAX_BODY_BYTES
    assert gateway.declared_body_bound(_post(SCAN_RESULTS, b"{}")) is achilles_results.MAX_BODY_BYTES
    assert gateway.declared_body_bound(_post(SCAN_RESULTS, b"{}", method="GET")) is None
    assert gateway.declared_body_bound(_post(UNDECLARED, b"{}")) is None


def test_the_table_holds_names_imported_from_each_route_and_no_number():
    """Read from the gateway's own source: every value of the table is a name, each imported
    by name from the route's module at the top of the file, and no value is a number."""
    tree = ast.parse((REPO / "audit" / "middleware.py").read_text(encoding="utf-8"))
    imported = {
        alias.asname or alias.name: f"{node.module}.{alias.name}"
        for node in tree.body
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    (table,) = [
        node.value
        for node in tree.body
        if isinstance(node, ast.Assign) and [t.id for t in node.targets if isinstance(t, ast.Name)] == ["DECLARED_BODY_BOUNDS"]
    ]
    assert isinstance(table, ast.Dict)
    named = {}
    for key, value in zip(table.keys, table.values):
        assert isinstance(value, ast.Name), ast.unparse(value)
        named[ast.literal_eval(key)] = imported[value.id]
    assert named == DECLARED


def test_the_gateway_reads_the_table_when_a_body_is_longer_than_it_sends(engine, failures, monkeypatch):
    """The bound a route holds is the one the gateway judges by: a smaller one, and the same
    body counts toward the alert."""
    app = _gateway()
    key = ("deployment-achilles-scan-results", "POST")
    app(_post(SCAN_RESULTS, _json_of(100_000)))
    assert failures == [] and app.inspected_in_part == 1
    monkeypatch.setitem(gateway.DECLARED_BODY_BOUNDS, key, 70_000)
    app(_post(SCAN_RESULTS, _json_of(100_000)))
    assert failures == [TRUNCATED] and app.inspected_in_part == 1


def test_the_gateway_imports_nothing_and_looks_nothing_up_by_a_runtime_name():
    """Read from its AST: no importlib, no __import__, and no getattr or hasattr whose name is
    not written in the call. An import inside a request can wait on the interpreter's import
    lock, and this gateway sits beside the stop judgement."""
    tree = ast.parse((REPO / "audit" / "middleware.py").read_text(encoding="utf-8"))
    wrong = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import) and any(alias.name.split(".")[0] == "importlib" for alias in node.names):
            wrong.append(f"{node.lineno}: import importlib")
        if isinstance(node, ast.ImportFrom) and (node.module or "").split(".")[0] == "importlib":
            wrong.append(f"{node.lineno}: from importlib")
        if isinstance(node, ast.Name) and node.id in ("importlib", "__import__", "import_module"):
            wrong.append(f"{node.lineno}: {node.id}")
        if isinstance(node, ast.Attribute) and node.attr in ("import_module", "__import__"):
            wrong.append(f"{node.lineno}: .{node.attr}")
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id in ("getattr", "hasattr", "setattr", "delattr")
            and len(node.args) >= 2
            and not (isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str))
        ):
            wrong.append(f"{node.lineno}: {ast.unparse(node)}")
    assert wrong == []


def _routes_clients(monkeypatch):
    """A client each declaring route takes a body from, and the path of that route."""
    dep = Deployment.objects.create(name="bounds", owner=_admin())
    admin = _client(_admin())
    User.objects.create_user(username="effect-service", password="x")
    monkeypatch.setenv(observed_effects.TOKEN_ENV, TOKEN)
    monkeypatch.setenv(observed_effects.USER_ENV, "effect-service")
    effect = APIClient()
    effect.credentials(HTTP_X_OBSERVED_EFFECT_TOKEN=TOKEN)
    clients = {
        "deployment-observed-chain-outcomes": (admin, "chain-outcomes/observed/"),
        "deployment-effect-reconciliations": (effect, "effect-reconciliations/"),
        "deployment-observed-effects": (effect, "observed-effects/"),
        "deployment-achilles-scan-results": (admin, "achilles-scan-results/"),
    }
    for kind, service in (
        ("authentication", identity_evidence.AUTHENTICATION_SERVICE),
        ("delegation", identity_evidence.DELEGATION_SERVICE),
    ):
        User.objects.create_user(username=f"{kind}-collector", password="x")
        monkeypatch.setenv(service.token_env, IDENTITY_TOKENS[kind])
        monkeypatch.setenv(service.user_env, f"{kind}-collector")
        client = APIClient()
        client.credentials(**{service.meta: IDENTITY_TOKENS[kind]})
        clients[f"deployment-{kind}s"] = (client, f"{kind}s/")
    return dep, clients


@pytest.mark.django_db
def test_every_declared_bound_is_the_one_its_route_refuses_past(engine, failures, monkeypatch):
    """A byte over the declared bound: the route's own 413, unchanged, and the gateway counts it
    as before. At the bound: past the 413 (the body is no record, so it is refused for that),
    and inspected in part."""
    dep, clients = _routes_clients(monkeypatch)
    for (name, method), reference in DECLARED.items():
        module, constant = reference.rsplit(".", 1)
        bound = getattr(sys.modules[module], constant)
        client, path = clients[name]
        del failures[:]
        over = client.post(_base(dep) + path, b"x" * (bound + 1), content_type="application/json")
        assert over.status_code == 413, (name, over.status_code)
        assert failures == [TRUNCATED], name
        at_bound = client.post(_base(dep) + path, b"x" * bound, content_type="application/json")
        assert at_bound.status_code in (400, 404), (name, at_bound.status_code, at_bound.content[:200])
        assert failures == [TRUNCATED], name
    assert not WorkflowChainOutcome.objects.filter(deployment=dep).exists()
    assert {m for (_n, m) in DECLARED} == {"POST"}
    assert effect_reconciliation.MAX_BODY_BYTES < identity_evidence.MAX_BODY_BYTES < observed_effects.MAX_BODY_BYTES


# --------------------------------------------------------- no stop, no refusal, no delay


@pytest.mark.django_db
@pytest.mark.parametrize(
    "sample", STOP_REQUESTS, ids=[f"{name}-{method}-{i}" for i, (name, method, *_) in enumerate(STOP_REQUESTS)]
)
def test_no_part_of_this_runs_on_a_stop(sample, monkeypatch):
    """A stop is judged first and goes to its view: the body is not read for the engine, no
    route's bound is read, nothing is counted, and the engine is not asked."""
    _name, method, path, body, extra = sample

    def never(*args, **kwargs):
        raise AssertionError("ran on a stop")

    monkeypatch.setattr(gateway, "declared_body_bound", never)
    monkeypatch.setattr(DefenderMiddleware, "_read_body", never)
    monkeypatch.setattr(DefenderMiddleware, "_unless_within_bound", never)
    monkeypatch.setattr(DefenderMiddleware, "_record_in_part", never)
    monkeypatch.setattr(DefenderMiddleware, "_record_failure", never)
    monkeypatch.setattr("audit.middleware.outbound.post", mock.Mock(side_effect=never))
    app = _gateway(DEFENDER_MONITOR_ONLY=False, FAILSAFE_POLL_TOKEN=POLL_TOKEN)
    with override_settings(FAILSAFE_POLL_TOKEN=POLL_TOKEN):
        response = app(_request(method, path, body, extra))
    assert response.status_code == 200 and response.content == b"the view ran"
    assert app.inspected_in_part == 0


@pytest.mark.parametrize("path", [EFFECTS, UNDECLARED])
@pytest.mark.parametrize("size", [1_000, 300_000, observed_effects.MAX_BODY_BYTES + 1])
def test_nothing_is_refused_that_was_allowed(path, size, monkeypatch):
    """Enforce mode, an engine that allows, and an engine that is down: every request reaches
    its view, within the bound, over it, or with no bound declared. The route refuses what is
    over its bound; the gateway never does."""
    app = _gateway(DEFENDER_MONITOR_ONLY=False)
    monkeypatch.setattr("audit.middleware.outbound.post", _engine_allows())
    assert app(_post(path, _json_of(size))).content == b"the view ran"
    monkeypatch.setattr("audit.middleware.outbound.post", mock.Mock(side_effect=requests.ConnectionError("down")))
    assert app(_post(path, _json_of(size))).content == b"the view ran"


def test_a_body_that_fits_reads_no_bound(engine, monkeypatch):
    """No route is resolved and no bound is read for a body the engine is sent whole: the
    ordinary request does exactly the work it did."""
    asked = []
    monkeypatch.setattr(gateway, "declared_body_bound", lambda request: asked.append(request) or None)
    app = _gateway()
    for path in (EFFECTS, UNDECLARED):
        app(_post(path, _json_of(64 * 1024)))
        app(_post(path, b"", method="GET"))
    assert asked == []


def test_nothing_is_imported_while_a_request_is_served():
    """The route's bounds are loaded with the gateway, never while a request is served: once the
    URL conf and the gateway are loaded, a stop, a body inspected in part, one over its bound and
    one on a route that declares none load no module at all, the first time or after."""
    probe = (
        "import sys, django; django.setup();"
        "from django.http import HttpResponse; from django.test import RequestFactory;"
        "import config.urls; from audit.middleware import DefenderMiddleware;"
        "app = DefenderMiddleware(lambda request: HttpResponse('ok'));"
        "app._ask_engine = lambda ctx: None;"
        f"stop = lambda: RequestFactory().post('/api/assurance/deployments/{U}/recompute/',"
        " data='{\"paused\": true}', content_type='application/json');"
        "body = lambda path, size: RequestFactory().post(path, data='x' * size, content_type='application/json');"
        f"effects, undeclared = '{EFFECTS}', '{UNDECLARED}';"
        "serve = lambda: [app(stop()), app(body(effects, 300000)), app(body(effects, 456635)), app(body(undeclared, 300000))];"
        "before = set(sys.modules); serve(); serve();"
        "loaded = set(sys.modules) - before;"
        "assert app.inspected_in_part == 2, app.inspected_in_part;"
        "print(sorted(loaded)); sys.exit(3 if loaded else 0)"
    )
    ran = subprocess.run([sys.executable, "-c", probe], cwd=REPO, env=dict(os.environ), capture_output=True, timeout=120)
    assert ran.returncode == 0, (ran.stdout.decode(errors="replace")[-600:], ran.stderr.decode(errors="replace")[-600:])


def test_the_routes_keep_their_operation_class_and_are_no_stop():
    """The SAFETY RULE: every declaring route is evidence and stops nothing, as it was."""
    from safety import degraded, stops

    for name, method in DECLARED:
        assert degraded.class_of(name, method) == degraded.EFFECT
        assert name not in stops.EXEMPT_ROUTES
        assert "stops nothing" in stops.NOT_STOPS[name][method]
